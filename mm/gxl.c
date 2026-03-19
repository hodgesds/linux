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
 * its own NUMA node but all share a single memory_dev_type at the same
 * abstract distance.  Per-device resize is available via:
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
#include <linux/node.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <asm/numa.h>

/*
 * Abstract distance for GPU VRAM over PCIe.
 *
 * DRAM is MEMTIER_ADISTANCE_DRAM (576).  GPU VRAM over PCIe has
 * ~2-5x the latency of local DRAM, so we place it at 2x DRAM
 * distance.  This puts GPU VRAM in its own tier below DRAM,
 * making it a demotion target under memory pressure.
 */
#define GXL_ADISTANCE	(MEMTIER_ADISTANCE_DRAM * 2)

#define GXL_MAX_DEVICES	8

/* Memory resource name for add_memory_driver_managed() */
static const char *gxl_res_name = "System RAM (gxl)";

/*
 * Per-device state
 */
struct gxl_dev {
	char			slot[64];	/* PCI slot string */
	struct pci_dev		*pdev;
	struct resource		*res;
	int			mgid;
	int			numa_node;
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
 * Shared memory type -- all GPUs live at the same abstract distance.
 */
static struct memory_dev_type *gxl_mtype;

/*
 * Parent kobject: /sys/kernel/mm/gxl/
 */
static struct kobject *gxl_kobj;

/*
 * Parameters
 */
static unsigned int gxl_max_pool_percent = 80;
module_param_named(max_pool_percent, gxl_max_pool_percent, uint, 0644);
MODULE_PARM_DESC(max_pool_percent, "Percentage of VRAM to expose as system memory (default 80)");

/*
 * gxl.device=SLOT -- early_param, called once per GPU.
 * Each invocation appends to gxl_devs[].
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
	return 0;
}
early_param("gxl.device", gxl_setup_device);

/*
 * Early NUMA node reservation.
 *
 * Subsystems like workqueue size per-node arrays to nr_node_ids at boot.
 * If gxl needs to create a new NUMA node at late_initcall time, those
 * arrays are already too small.  To avoid this, the user passes
 * gxl.reserve_node[=N] on the kernel command line.  This runs during
 * parse_early_param() -- before NUMA init -- and reserves N node IDs
 * (default 1) by scanning numa_nodes_parsed from MAX_NUMNODES-1 downward,
 * avoiding collision with real hardware topology.
 */
static int gxl_reserved_nodes[GXL_MAX_DEVICES];
static int gxl_nr_reserved;

static int __init gxl_reserve_node(char *arg)
{
	int count = 1;
	int nid, i;

	if (arg && *arg)
		count = simple_strtol(arg, NULL, 0);
	if (count < 1)
		count = 1;
	if (count > GXL_MAX_DEVICES)
		count = GXL_MAX_DEVICES;

	for (i = 0; i < count; i++) {
		for (nid = MAX_NUMNODES - 1; nid >= 0; nid--) {
			if (!node_isset(nid, numa_nodes_parsed)) {
				node_set(nid, numa_nodes_parsed);
				gxl_reserved_nodes[gxl_nr_reserved++] = nid;
				pr_info("reserved NUMA node %d for GPU VRAM\n",
					nid);
				break;
			}
		}
		if (nid < 0) {
			pr_err("no free NUMA node ID to reserve (%d of %d done)\n",
			       i, count);
			break;
		}
	}

	return 0;
}
early_param("gxl.reserve_node", gxl_reserve_node);

/*
 * BAR detection
 */
static int gxl_find_vram_bar(struct pci_dev *pdev, resource_size_t *bar_start,
			     unsigned long *bar_size)
{
	resource_size_t best_start = 0;
	unsigned long best_size = 0;
	int bar;

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
		}
	}

	if (!best_size)
		return -ENODEV;

	*bar_start = best_start;
	*bar_size = best_size;
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
		if (rc) {
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

static struct attribute *gxl_dev_attrs[] = {
	&gxl_size_mb_attr.attr,
	&gxl_max_size_mb_attr.attr,
	&gxl_numa_node_attr.attr,
	NULL,
};

static const struct attribute_group gxl_dev_attr_group = {
	.attrs = gxl_dev_attrs,
};

/*
 * Claim a NUMA node for a device.
 * 1. Pop from gxl_reserved_nodes[] (reserved at early boot)
 * 2. Fallback: scan for any offline-but-possible node
 */
static int __init gxl_claim_node(void)
{
	int nid, i;

	/* Try reserved pool first */
	if (gxl_nr_reserved > 0) {
		nid = gxl_reserved_nodes[--gxl_nr_reserved];
		/*
		 * The reserved node will typically be online already --
		 * gxl_reserve_node() adds it to numa_nodes_parsed so that
		 * NUMA init sizes per-node arrays to include it.  That is
		 * expected.  Just verify it is a valid, memoryless node.
		 */
		if (node_possible(nid))
			return nid;
		pr_warn("reserved node %d is not possible, scanning\n", nid);
	}

	/* Fallback: any offline-but-possible node */
	for (i = 0; i < nr_node_ids; i++) {
		if (node_possible(i) && !node_online(i))
			return i;
	}

	return NUMA_NO_NODE;
}

/*
 * Initialize a single device.
 */
static int __init gxl_init_one(struct gxl_dev *gdev)
{
	unsigned int domain, bus, slot, func;
	resource_size_t bar_start, aligned_start, aligned_end;
	unsigned long bar_size, usable_size, blk_size;
	struct pci_dev *pdev;
	int rc;

	mutex_init(&gdev->lock);
	gdev->mgid = -1;
	gdev->numa_node = NUMA_NO_NODE;

	if (sscanf(gdev->slot, "%x:%x:%x.%x",
		   &domain, &bus, &slot, &func) != 4) {
		pr_err("%s: invalid device format (expected DDDD:BB:DD.F)\n",
		       gdev->slot);
		return -EINVAL;
	}

	pdev = pci_get_domain_bus_and_slot(domain, bus, PCI_DEVFN(slot, func));
	if (!pdev) {
		pr_err("%s: PCI device not found\n", gdev->slot);
		return -ENODEV;
	}

	rc = gxl_find_vram_bar(pdev, &bar_start, &bar_size);
	if (rc) {
		pr_err("%s: no prefetchable VRAM BAR found\n", gdev->slot);
		goto err_put_pdev;
	}

	pr_info("%s: found VRAM BAR: base=%pa size=%lu MB\n",
		gdev->slot, &bar_start, bar_size >> 20);

	blk_size = memory_block_size_bytes();
	if (gxl_max_pool_percent > 100)
		gxl_max_pool_percent = 100;
	usable_size = bar_size * gxl_max_pool_percent / 100;
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

	/* Claim a NUMA node */
	gdev->numa_node = gxl_claim_node();
	if (gdev->numa_node == NUMA_NO_NODE) {
		pr_err("%s: no offline-but-possible NUMA node available\n",
		       gdev->slot);
		pr_err("add gxl.reserve_node=N to kernel command line\n");
		rc = -ENOSPC;
		goto err_put_pdev;
	}

	rc = try_online_node(gdev->numa_node);
	if (rc < 0) {
		pr_err("%s: failed to online node %d: %d\n",
		       gdev->slot, gdev->numa_node, rc);
		goto err_put_pdev;
	}

	init_node_memory_type(gdev->numa_node, gxl_mtype);

	rc = memory_group_register_static(gdev->numa_node,
					  PFN_UP(gdev->max_size));
	if (rc < 0) {
		pr_err("%s: failed to register memory group: %d\n",
		       gdev->slot, rc);
		goto err_clear_type;
	}
	gdev->mgid = rc;

	gdev->res = request_mem_region(gdev->phys_start, gdev->max_size,
				       gxl_res_name);
	if (!gdev->res) {
		pr_err("%s: could not reserve VRAM region %pa+%lu (in use by GPU driver?)\n",
		       gdev->slot, &gdev->phys_start, gdev->max_size);
		rc = -EBUSY;
		goto err_unreg_group;
	}
	gdev->res->flags = IORESOURCE_SYSTEM_RAM;

	/* Per-device sysfs kobject */
	gdev->kobj = kobject_create_and_add(gdev->slot, gxl_kobj);
	if (!gdev->kobj) {
		rc = -ENOMEM;
		goto err_release_region;
	}

	rc = sysfs_create_group(gdev->kobj, &gxl_dev_attr_group);
	if (rc)
		goto err_put_kobj;

	gdev->pdev = pdev;
	gdev->ready = true;

	pr_info("%s: ready: %lu MB GPU VRAM on node %d (adist %ld)\n",
		gdev->slot, gdev->max_size >> 20, gdev->numa_node,
		(long)GXL_ADISTANCE);
	pr_info("%s: write to /sys/kernel/mm/gxl/%s/size_mb to register VRAM\n",
		gdev->slot, gdev->slot);

	return 0;

err_put_kobj:
	kobject_put(gdev->kobj);
	gdev->kobj = NULL;
err_release_region:
	remove_resource(gdev->res);
	kfree(gdev->res);
	gdev->res = NULL;
err_unreg_group:
	memory_group_unregister(gdev->mgid);
	gdev->mgid = -1;
err_clear_type:
	clear_node_memory_type(gdev->numa_node, gxl_mtype);
err_put_pdev:
	pci_dev_put(pdev);
	return rc;
}

/*
 * Main initialization
 */
static int __init gxl_init(void)
{
	int i, rc, ok = 0;

	if (!gxl_nr_devs)
		return 0;

	/* Shared memory type for all GPU devices */
	gxl_mtype = alloc_memory_type(GXL_ADISTANCE);
	if (IS_ERR(gxl_mtype)) {
		rc = PTR_ERR(gxl_mtype);
		pr_err("failed to allocate memory type: %d\n", rc);
		gxl_mtype = NULL;
		return rc;
	}

	/* Parent sysfs directory */
	gxl_kobj = kobject_create_and_add("gxl", mm_kobj);
	if (!gxl_kobj) {
		put_memory_type(gxl_mtype);
		gxl_mtype = NULL;
		return -ENOMEM;
	}

	for (i = 0; i < gxl_nr_devs; i++) {
		rc = gxl_init_one(&gxl_devs[i]);
		if (rc)
			pr_err("%s: init failed: %d\n", gxl_devs[i].slot, rc);
		else
			ok++;
	}

	if (!ok) {
		pr_err("no devices initialized successfully\n");
		kobject_put(gxl_kobj);
		gxl_kobj = NULL;
		put_memory_type(gxl_mtype);
		gxl_mtype = NULL;
		return -ENODEV;
	}

	return 0;
}

late_initcall(gxl_init);
