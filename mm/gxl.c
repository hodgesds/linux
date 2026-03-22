// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * gxl.c - GPU VRAM as CXL.mem-style memory tier (multi-GPU)
 *
 * gxl exposes GPU VRAM as a kernel-managed memory tier, allowing the
 * kernel to automatically demote cold pages from DRAM to GPU VRAM
 * under memory pressure.  This is conceptually identical to how CXL
 * Type 3 memory devices provide additional capacity at higher latency.
 *
 * GPU VRAM is accessed via the PCI BAR (resizable BAR / SAM) and
 * registered as a NUMA memory node through the memory hotplug and
 * memory tiering infrastructure.
 *
 * Multiple GPUs are supported (up to GXL_MAX_DEVICES).  Each GPU gets
 * its own NUMA node and memory_dev_type (with per-device configurable
 * abstract distance).  Per-device resize is available via:
 *   /sys/kernel/mm/gxl/<slot>/size_mb
 *
 * Pages are onlined to ZONE_MOVABLE so they can be migrated back
 * to DRAM when the VRAM region is shrunk (e.g., when the GPU driver
 * needs memory back).
 *
 * Architecture:
 *   Memory pressure -> NUMA demotion -> pages migrate DRAM -> GPU VRAM
 *   Access pattern  -> NUMA balancing -> pages promote GPU VRAM -> DRAM
 *   Shrink request  -> offline_and_remove_memory -> pages back to DRAM
 *
 * Initialization:
 *   Each gxl.device=SLOT on the command line automatically reserves a
 *   NUMA node via numa_extra_reserve_count during early boot, ensuring
 *   all per-node arrays (cpumasks, pgdat, workqueue node_nr_active) are
 *   properly sized.  A PCI bus notifier defers per-device setup until
 *   the GPU appears on the bus.
 *
 * Copyright (C) 2026
 */

#define pr_fmt(fmt) "gxl: " fmt

#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/memory.h>
#include <linux/memory-tiers.h>
#include <linux/memory_hotplug.h>
#include <linux/numa.h>
#include <linux/numa_memblks.h>
#include <linux/node.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/topology.h>
#include <linux/vmstat.h>

/*
 * Default abstract distance for GPU VRAM over PCIe.
 *
 * DRAM is MEMTIER_ADISTANCE_DRAM (576).  GPU VRAM over PCIe has
 * ~2-5x the latency of local DRAM, so the default is 2x DRAM
 * distance.  Tunable via gxl.adistance= kernel parameter.
 */
#define GXL_ADISTANCE_DEFAULT	(MEMTIER_ADISTANCE_DRAM * 2)

#define GXL_MAX_DEVICES	8

/* Memory resource name for add_memory_driver_managed() */
static const char *gxl_res_name = "System RAM (gxl)";

/*
 * Per-device state
 */
struct gxl_dev {
	char			slot[64];	/* PCI slot string */
	struct pci_dev		*pdev;
	int			bar_idx;
	int			mgid;
	int			numa_node;
	int			local_node;	/* closest DRAM NUMA node */
	unsigned int		adistance;
	unsigned int		pool_percent;
	struct memory_dev_type	*mtype;
	resource_size_t		bar_start;	/* raw BAR base */
	unsigned long		bar_size;	/* raw BAR size */
	resource_size_t		phys_start;
	unsigned long		max_size;
	unsigned long		online_size;
	bool			ready;
	struct kobject		*kobj;		/* /sys/kernel/mm/gxl/<slot>/ */
	struct mutex		lock;
};

static struct gxl_dev gxl_devs[GXL_MAX_DEVICES];
static int gxl_nr_devs;

/*
 * Parent kobject: /sys/kernel/mm/gxl/
 */
static struct kobject *gxl_kobj;

/*
 * PCI bus notifier for deferred device initialization.
 * gxl_init_mutex serializes gxl_init_one() calls from the notifier
 * and the gxl_init() scan loop so that gxl_claim_node() cannot hand
 * the same NUMA node to two devices.
 */
static DEFINE_MUTEX(gxl_init_mutex);
static struct notifier_block gxl_pci_nb;

/*
 * Parameters
 */
static unsigned int gxl_max_pool_percent = 80;
module_param_named(max_pool_percent, gxl_max_pool_percent, uint, 0644);
MODULE_PARM_DESC(max_pool_percent, "Percentage of VRAM to expose as system memory (default 80)");

static unsigned int gxl_adistance = GXL_ADISTANCE_DEFAULT;
module_param_named(adistance, gxl_adistance, uint, 0444);
MODULE_PARM_DESC(adistance, "Abstract distance for GPU VRAM tier (default: 2x DRAM)");

static bool gxl_auto_online = true;
module_param_named(auto_online, gxl_auto_online, bool, 0644);
MODULE_PARM_DESC(auto_online, "Auto-register all usable VRAM at init (default: true)");

/*
 * gxl.device=SLOT -- early_param, called once per GPU.
 * Each invocation appends to gxl_devs[] and reserves a NUMA node.
 */
static int __init gxl_setup_device(char *arg)
{
	if (gxl_nr_devs >= GXL_MAX_DEVICES) {
		pr_err("too many devices (max %d)\n", GXL_MAX_DEVICES);
		return 0;
	}

	strscpy(gxl_devs[gxl_nr_devs].slot, arg,
		sizeof(gxl_devs[gxl_nr_devs].slot));
	gxl_nr_devs++;

	/*
	 * Reserve a NUMA node for this device.  This increments the
	 * count used by numa_reserve_extra_nodes() during NUMA init
	 * (in numa_register_meminfo()), which runs after all early_params.
	 * The reserved nodes are added to node_possible_map before
	 * setup_nr_node_ids(), ensuring all per-node arrays are properly
	 * sized: node_to_cpumask_map, NODE_DATA, workqueue node_nr_active,
	 * memory tier node_demotion, etc.
	 */
	numa_extra_reserve_count++;

	return 0;
}
early_param("gxl.device", gxl_setup_device);

/*
 * BAR detection
 */
static int gxl_find_vram_bar(struct pci_dev *pdev, resource_size_t *bar_start,
			     unsigned long *bar_size, int *bar_idxp)
{
	resource_size_t best_start = 0;
	unsigned long best_size = 0;
	int bar, best_bar = -1;

	for (bar = 0; bar < PCI_STD_NUM_BARS; bar++) {
		unsigned long flags = pci_resource_flags(pdev, bar);
		resource_size_t start = pci_resource_start(pdev, bar);
		unsigned long size = pci_resource_len(pdev, bar);

		if (!(flags & IORESOURCE_MEM))
			continue;
		if (flags & IORESOURCE_IO)
			continue;
		if (!(flags & IORESOURCE_PREFETCH))
			continue;
		if (size > best_size) {
			best_start = start;
			best_size = size;
			best_bar = bar;
		}
	}

	if (!best_size)
		return -ENODEV;

	*bar_start = best_start;
	*bar_size = best_size;
	*bar_idxp = best_bar;
	return 0;
}

/*
 * Online callback -- online each memory block to ZONE_MOVABLE
 * so pages can be migrated back to DRAM on shrink.
 */
static int gxl_online_movable_cb(struct memory_block *mem, void *arg)
{
	if (mem->state == MEM_ONLINE) {
		pr_warn_once("blocks auto-onlined before ZONE_MOVABLE set; "
			     "add memhp_default_state=online_movable to cmdline\n");
		return 0;
	}

	if (mem->state != MEM_OFFLINE)
		return 0;

	mem->online_type = MMOP_ONLINE_MOVABLE;
	return device_online(&mem->dev);
}

/*
 * Dynamic resize -- operates on a single device.
 */
static int gxl_do_resize(struct gxl_dev *gdev, unsigned long new_size)
{
	unsigned long blk_size = memory_block_size_bytes();
	int rc = 0;

	new_size = ALIGN_DOWN(new_size, blk_size);
	if (new_size > gdev->max_size)
		new_size = gdev->max_size;

	mutex_lock(&gdev->lock);

	if (new_size == gdev->online_size)
		goto out;

	if (new_size < gdev->online_size) {
		unsigned long shrink = gdev->online_size - new_size;

		rc = offline_and_remove_memory(gdev->phys_start + new_size,
					       shrink);
		if (rc) {
			pr_warn("%s: shrink failed: %d (pages may be pinned)\n",
				gdev->slot, rc);
			goto out;
		}
		gdev->online_size = new_size;
		pr_info("%s: shrunk to %lu MB\n", gdev->slot, new_size >> 20);
	} else {
		unsigned long grow_start = gdev->phys_start + gdev->online_size;
		unsigned long grow = new_size - gdev->online_size;

		rc = add_memory_driver_managed(gdev->mgid, grow_start, grow,
					       gxl_res_name, MHP_NID_IS_MGID);
		if (rc == -EEXIST) {
			/*
			 * GPU driver's PCI BAR claim blocks the memory
			 * resource.  Release it and retry -- the driver
			 * keeps working through existing ioremap mappings.
			 */
			pr_info("%s: releasing GPU driver BAR claim\n",
				gdev->slot);
			pci_release_region(gdev->pdev, gdev->bar_idx);
			rc = add_memory_driver_managed(gdev->mgid, grow_start,
						       grow, gxl_res_name,
						       MHP_NID_IS_MGID);
			if (rc) {
				pr_warn("%s: grow failed after BAR release: %d, restoring\n",
					gdev->slot, rc);
				/* Best-effort restore; nothing to do if it fails */
				if (pci_request_region(gdev->pdev,
						       gdev->bar_idx,
						       dev_driver_string(&gdev->pdev->dev)))
					pr_warn("%s: could not restore GPU BAR claim\n",
						gdev->slot);
				goto out;
			}
		} else if (rc) {
			pr_warn("%s: grow failed: %d\n", gdev->slot, rc);
			goto out;
		}

		lock_device_hotplug();
		walk_memory_blocks(grow_start, grow, NULL,
				   gxl_online_movable_cb);
		unlock_device_hotplug();

		gdev->online_size = new_size;
		pr_info("%s: grown to %lu MB\n", gdev->slot, new_size >> 20);
	}

out:
	mutex_unlock(&gdev->lock);
	return rc;
}

/*
 * sysfs helpers -- map kobject back to gxl_dev.
 */
static struct gxl_dev *gxl_kobj_to_dev(struct kobject *kobj)
{
	int i;

	for (i = 0; i < gxl_nr_devs; i++) {
		if (gxl_devs[i].kobj == kobj)
			return &gxl_devs[i];
	}
	return NULL;
}

/*
 * Per-device sysfs: /sys/kernel/mm/gxl/<slot>/
 */
static ssize_t size_mb_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);

	if (!gdev)
		return -ENODEV;
	return sysfs_emit(buf, "%lu\n", gdev->online_size >> 20);
}

static ssize_t size_mb_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);
	unsigned long mb;
	int rc;

	if (!gdev || !gdev->ready)
		return -ENODEV;

	rc = kstrtoul(buf, 0, &mb);
	if (rc)
		return rc;

	if (mb > (gdev->max_size >> 20))
		mb = gdev->max_size >> 20;

	rc = gxl_do_resize(gdev, mb << 20);
	if (rc)
		return rc;

	return count;
}

static struct kobj_attribute gxl_size_mb_attr =
	__ATTR(size_mb, 0644, size_mb_show, size_mb_store);

static ssize_t max_size_mb_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);

	if (!gdev)
		return -ENODEV;
	return sysfs_emit(buf, "%lu\n", gdev->max_size >> 20);
}

static struct kobj_attribute gxl_max_size_mb_attr =
	__ATTR(max_size_mb, 0444, max_size_mb_show, NULL);

static ssize_t numa_node_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);

	if (!gdev)
		return -ENODEV;
	return sysfs_emit(buf, "%d\n", gdev->numa_node);
}

static struct kobj_attribute gxl_numa_node_attr =
	__ATTR(numa_node, 0444, numa_node_show, NULL);

static ssize_t local_node_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);

	if (!gdev)
		return -ENODEV;
	return sysfs_emit(buf, "%d\n", gdev->local_node);
}

static struct kobj_attribute gxl_local_node_attr =
	__ATTR(local_node, 0444, local_node_show, NULL);

static ssize_t nr_used_pages_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);
	unsigned long present, free;

	if (!gdev || !gdev->ready)
		return -ENODEV;

	present = node_present_pages(gdev->numa_node);
	free = sum_zone_node_page_state(gdev->numa_node, NR_FREE_PAGES);
	return sysfs_emit(buf, "%lu\n", present > free ? present - free : 0);
}

static struct kobj_attribute gxl_nr_used_pages_attr =
	__ATTR(nr_used_pages, 0444, nr_used_pages_show, NULL);

static ssize_t nr_free_pages_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);

	if (!gdev || !gdev->ready)
		return -ENODEV;

	return sysfs_emit(buf, "%lu\n",
		sum_zone_node_page_state(gdev->numa_node, NR_FREE_PAGES));
}

static struct kobj_attribute gxl_nr_free_pages_attr =
	__ATTR(nr_free_pages, 0444, nr_free_pages_show, NULL);

static ssize_t fill_percent_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);
	unsigned long present, free;

	if (!gdev || !gdev->ready)
		return -ENODEV;

	present = node_present_pages(gdev->numa_node);
	if (!present)
		return sysfs_emit(buf, "0\n");

	free = sum_zone_node_page_state(gdev->numa_node, NR_FREE_PAGES);
	return sysfs_emit(buf, "%lu\n", (present - free) * 100 / present);
}

static struct kobj_attribute gxl_fill_percent_attr =
	__ATTR(fill_percent, 0444, fill_percent_show, NULL);

static ssize_t adistance_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);

	if (!gdev)
		return -ENODEV;
	return sysfs_emit(buf, "%u\n", gdev->adistance);
}

static struct kobj_attribute gxl_adistance_attr =
	__ATTR(adistance, 0444, adistance_show, NULL);

/*
 * Recalculate max_size from the raw BAR and a new pool percent.
 * Rejects changes that would strand already-online memory.
 */
static ssize_t pool_percent_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);

	if (!gdev)
		return -ENODEV;
	return sysfs_emit(buf, "%u\n", gdev->pool_percent);
}

static ssize_t pool_percent_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	struct gxl_dev *gdev = gxl_kobj_to_dev(kobj);
	unsigned long blk_size;
	resource_size_t aligned_end;
	unsigned long new_max;
	unsigned int pct;
	int rc;

	if (!gdev || !gdev->ready)
		return -ENODEV;

	rc = kstrtouint(buf, 0, &pct);
	if (rc)
		return rc;
	if (pct > 100)
		pct = 100;

	blk_size = memory_block_size_bytes();
	aligned_end = ALIGN_DOWN(gdev->bar_start + gdev->bar_size * pct / 100,
				 blk_size);
	if (gdev->phys_start >= aligned_end)
		return -EINVAL;

	new_max = aligned_end - gdev->phys_start;

	mutex_lock(&gdev->lock);
	if (gdev->online_size > new_max) {
		mutex_unlock(&gdev->lock);
		return -EBUSY;
	}
	gdev->max_size = new_max;
	gdev->pool_percent = pct;
	mutex_unlock(&gdev->lock);

	pr_info("%s: pool_percent=%u%%, max_size=%lu MB\n",
		gdev->slot, pct, new_max >> 20);
	return count;
}

static struct kobj_attribute gxl_pool_percent_attr =
	__ATTR(pool_percent, 0644, pool_percent_show, pool_percent_store);

static struct attribute *gxl_dev_attrs[] = {
	&gxl_size_mb_attr.attr,
	&gxl_max_size_mb_attr.attr,
	&gxl_numa_node_attr.attr,
	&gxl_local_node_attr.attr,
	&gxl_nr_used_pages_attr.attr,
	&gxl_nr_free_pages_attr.attr,
	&gxl_fill_percent_attr.attr,
	&gxl_adistance_attr.attr,
	&gxl_pool_percent_attr.attr,
	NULL,
};

static const struct attribute_group gxl_dev_attr_group = {
	.attrs = gxl_dev_attrs,
};

/*
 * Claim a NUMA node for a device.
 * Scans for any offline-but-possible node reserved at early boot.
 */
static int gxl_claim_node(void)
{
	int i;

	for (i = 0; i < nr_node_ids; i++) {
		if (node_possible(i) && !node_online(i))
			return i;
	}

	return NUMA_NO_NODE;
}

/*
 * Set up NUMA distances for a synthetic GPU node.
 *
 * The GPU is modeled as "one PCIe hop past" its local DRAM node.
 * This gives the demotion target selector correct topology on
 * multi-socket systems so each DRAM node prefers demoting to
 * the physically closest GPU.
 */
#define GXL_PCIE_HOP	11

static void gxl_setup_distances(struct gxl_dev *gdev)
{
	int nid, gpu = gdev->numa_node;
	int local = gdev->local_node;
	int dist;

	numa_set_distance_runtime(gpu, gpu, LOCAL_DISTANCE);

	for_each_online_node(nid) {
		if (nid == gpu)
			continue;

		if (nid == local)
			dist = LOCAL_DISTANCE + GXL_PCIE_HOP;
		else
			dist = node_distance(local, nid) + GXL_PCIE_HOP;

		if (dist > 255)
			dist = 255;

		numa_set_distance_runtime(gpu, nid, dist);
		numa_set_distance_runtime(nid, gpu, dist);
	}
}

/*
 * Initialize a single device given an already-referenced PCI device.
 */
static int gxl_init_one(struct gxl_dev *gdev, struct pci_dev *pdev)
{
	resource_size_t bar_start, aligned_start, aligned_end;
	unsigned long bar_size, usable_size, blk_size;
	int rc;

	mutex_init(&gdev->lock);
	gdev->mgid = -1;
	gdev->numa_node = NUMA_NO_NODE;
	gdev->adistance = gxl_adistance;
	gdev->pool_percent = gxl_max_pool_percent;

	/* Determine which DRAM node this GPU is closest to */
	gdev->local_node = dev_to_node(&pdev->dev);
	if (gdev->local_node == NUMA_NO_NODE)
		gdev->local_node = first_online_node;

	rc = gxl_find_vram_bar(pdev, &bar_start, &bar_size, &gdev->bar_idx);
	if (rc) {
		pr_err("%s: no prefetchable VRAM BAR found\n", gdev->slot);
		goto err_put_pdev;
	}

	pr_info("%s: found VRAM BAR: base=%pa size=%lu MB (local node %d)\n",
		gdev->slot, &bar_start, bar_size >> 20, gdev->local_node);

	gdev->bar_start = bar_start;
	gdev->bar_size = bar_size;

	blk_size = memory_block_size_bytes();
	if (gdev->pool_percent > 100)
		gdev->pool_percent = 100;
	usable_size = bar_size * gdev->pool_percent / 100;
	aligned_start = ALIGN(bar_start, blk_size);
	aligned_end = ALIGN_DOWN(bar_start + usable_size, blk_size);

	if (aligned_start >= aligned_end) {
		pr_err("%s: VRAM region too small after alignment (%lu MB, block size %lu MB)\n",
		       gdev->slot, usable_size >> 20, blk_size >> 20);
		rc = -ENOSPC;
		goto err_put_pdev;
	}

	gdev->phys_start = aligned_start;
	gdev->max_size = aligned_end - aligned_start;

	pr_info("%s: usable: %lu MB of %lu MB VRAM (aligned to %lu MB blocks)\n",
		gdev->slot, gdev->max_size >> 20, bar_size >> 20,
		blk_size >> 20);

	/* Per-device memory type at this device's abstract distance */
	gdev->mtype = alloc_memory_type(gdev->adistance);
	if (IS_ERR(gdev->mtype)) {
		rc = PTR_ERR(gdev->mtype);
		pr_err("%s: failed to allocate memory type: %d\n",
		       gdev->slot, rc);
		gdev->mtype = NULL;
		goto err_put_pdev;
	}

	/* Claim a NUMA node */
	gdev->numa_node = gxl_claim_node();
	if (gdev->numa_node == NUMA_NO_NODE) {
		pr_err("%s: no offline-but-possible NUMA node available\n",
		       gdev->slot);
		rc = -ENOSPC;
		goto err_put_mtype;
	}

	rc = try_online_node(gdev->numa_node);
	if (rc < 0) {
		pr_err("%s: failed to online node %d: %d\n",
		       gdev->slot, gdev->numa_node, rc);
		goto err_put_mtype;
	}

	gxl_setup_distances(gdev);
	init_node_memory_type(gdev->numa_node, gdev->mtype);

	rc = memory_group_register_static(gdev->numa_node,
					  PFN_UP(gdev->max_size));
	if (rc < 0) {
		pr_err("%s: failed to register memory group: %d\n",
		       gdev->slot, rc);
		goto err_clear_type;
	}
	gdev->mgid = rc;

	/* Per-device sysfs kobject */
	gdev->kobj = kobject_create_and_add(gdev->slot, gxl_kobj);
	if (!gdev->kobj) {
		rc = -ENOMEM;
		goto err_unreg_group;
	}

	rc = sysfs_create_group(gdev->kobj, &gxl_dev_attr_group);
	if (rc)
		goto err_put_kobj;

	gdev->pdev = pdev;
	gdev->ready = true;

	pr_info("%s: ready: %lu MB GPU VRAM on node %d (adist %u, local node %d)\n",
		gdev->slot, gdev->max_size >> 20, gdev->numa_node,
		gdev->adistance, gdev->local_node);

	if (gxl_auto_online) {
		rc = gxl_do_resize(gdev, gdev->max_size);
		if (rc)
			pr_warn("%s: auto-online failed: %d\n",
				gdev->slot, rc);
	} else {
		pr_info("%s: write to /sys/kernel/mm/gxl/%s/size_mb to register VRAM\n",
			gdev->slot, gdev->slot);
	}

	return 0;

err_put_kobj:
	kobject_put(gdev->kobj);
	gdev->kobj = NULL;
err_unreg_group:
	memory_group_unregister(gdev->mgid);
	gdev->mgid = -1;
err_clear_type:
	clear_node_memory_type(gdev->numa_node, gdev->mtype);
	lock_device_hotplug();
	try_offline_node(gdev->numa_node);
	unlock_device_hotplug();
	gdev->numa_node = NUMA_NO_NODE;
err_put_mtype:
	put_memory_type(gdev->mtype);
	gdev->mtype = NULL;
err_put_pdev:
	pci_dev_put(pdev);
	return rc;
}

/*
 * Look up a PCI device from the slot string in a gxl_dev.
 * Returns a referenced pdev, or NULL if not found.
 */
static struct pci_dev *gxl_find_pdev(struct gxl_dev *gdev)
{
	unsigned int domain, bus, slot, func;

	if (sscanf(gdev->slot, "%x:%x:%x.%x",
		   &domain, &bus, &slot, &func) != 4) {
		pr_err("%s: invalid device format (expected DDDD:BB:DD.F)\n",
		       gdev->slot);
		return NULL;
	}

	return pci_get_domain_bus_and_slot(domain, bus, PCI_DEVFN(slot, func));
}

/*
 * PCI bus notifier -- attempt device init when a configured GPU appears.
 */
static int gxl_pci_bus_notify(struct notifier_block *nb,
			      unsigned long action, void *data)
{
	struct pci_dev *pdev = to_pci_dev(data);
	int i;

	if (action != BUS_NOTIFY_ADD_DEVICE)
		return NOTIFY_DONE;

	mutex_lock(&gxl_init_mutex);
	for (i = 0; i < gxl_nr_devs; i++) {
		if (gxl_devs[i].ready)
			continue;
		if (strcmp(gxl_devs[i].slot, pci_name(pdev)) != 0)
			continue;

		pci_dev_get(pdev);
		if (gxl_init_one(&gxl_devs[i], pdev))
			pr_info("%s: deferred init failed, will not retry\n",
				gxl_devs[i].slot);
		break;
	}
	mutex_unlock(&gxl_init_mutex);

	return NOTIFY_DONE;
}

/*
 * Main initialization
 */
static int __init gxl_init(void)
{
	struct pci_dev *pdev;
	int i, rc, ok = 0;

	if (!gxl_nr_devs)
		return 0;

	/* Parent sysfs directory */
	gxl_kobj = kobject_create_and_add("gxl", mm_kobj);
	if (!gxl_kobj)
		return -ENOMEM;

	/*
	 * Register notifier BEFORE scanning so that devices appearing
	 * between the scan and registration are not missed.
	 */
	gxl_pci_nb.notifier_call = gxl_pci_bus_notify;
	bus_register_notifier(&pci_bus_type, &gxl_pci_nb);

	/* Try to initialize devices already present on the PCI bus */
	mutex_lock(&gxl_init_mutex);
	for (i = 0; i < gxl_nr_devs; i++) {
		if (gxl_devs[i].ready)
			continue;
		pdev = gxl_find_pdev(&gxl_devs[i]);
		if (!pdev)
			continue;

		rc = gxl_init_one(&gxl_devs[i], pdev);
		if (rc)
			pr_err("%s: init failed: %d\n", gxl_devs[i].slot, rc);
		else
			ok++;
	}
	mutex_unlock(&gxl_init_mutex);

	if (!ok)
		pr_info("no devices found yet, waiting for PCI bus notifications\n");

	return 0;
}

late_initcall(gxl_init);
