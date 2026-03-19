// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * gxl.c - GPU VRAM as CXL.mem-style memory tier
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
 * The registered VRAM size can be changed at runtime via:
 *   /sys/kernel/mm/gxl/size_mb
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
#include <linux/mmzone.h>
#include <linux/numa.h>
#include <linux/node.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/mutex.h>

/*
 * Abstract distance for GPU VRAM over PCIe.
 *
 * DRAM is MEMTIER_ADISTANCE_DRAM (576).  GPU VRAM over PCIe has
 * ~2-5x the latency of local DRAM, so we place it at 2x DRAM
 * distance.  This puts GPU VRAM in its own tier below DRAM,
 * making it a demotion target under memory pressure.
 */
#define GXL_ADISTANCE	(MEMTIER_ADISTANCE_DRAM * 2)

/* Memory resource name for add_memory_driver_managed() */
static const char *gxl_res_name = "System RAM (gxl)";

/*
 * Parameters
 */

static char gxl_device[64];
module_param_string(device, gxl_device, sizeof(gxl_device), 0444);
MODULE_PARM_DESC(device, "PCI slot of GPU device (e.g. 0000:03:00.0)");

static unsigned int gxl_max_pool_percent = 80;
module_param_named(max_pool_percent, gxl_max_pool_percent, uint, 0444);
MODULE_PARM_DESC(max_pool_percent, "Percentage of VRAM to expose as system memory (default 80)");

/*
 * State
 */

static DEFINE_MUTEX(gxl_lock);

static struct pci_dev *gxl_pdev;
static struct resource *gxl_res;
static struct memory_dev_type *gxl_mtype;
static int gxl_mgid = -1;
static int gxl_numa_node = NUMA_NO_NODE;

static resource_size_t gxl_phys_start;	/* aligned start of usable VRAM */
static unsigned long gxl_max_size;	/* max usable VRAM (aligned) */
static unsigned long gxl_online_size;	/* currently registered size */

static bool gxl_ready;			/* init completed successfully */

static struct kobject *gxl_kobj;

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
		/*
		 * Block was auto-onlined by add_memory_driver_managed()
		 * before we could set ZONE_MOVABLE.  Shrink operations
		 * may fail if kernel allocations land here.
		 */
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
 * Dynamic resize
 *
 * Grow: add_memory_driver_managed() then online to ZONE_MOVABLE
 * Shrink: offline_and_remove_memory() migrates pages back to DRAM
 */
static int gxl_do_resize(unsigned long new_size)
{
	unsigned long blk_size = memory_block_size_bytes();
	int rc = 0;

	new_size = ALIGN_DOWN(new_size, blk_size);
	if (new_size > gxl_max_size)
		new_size = gxl_max_size;

	mutex_lock(&gxl_lock);

	if (new_size == gxl_online_size)
		goto out;

	if (new_size < gxl_online_size) {
		/* Shrink: offline and remove memory from the end */
		unsigned long shrink = gxl_online_size - new_size;

		rc = offline_and_remove_memory(gxl_phys_start + new_size,
					       shrink);
		if (rc) {
			pr_warn("shrink failed: %d (pages may be pinned)\n",
				rc);
			goto out;
		}
		gxl_online_size = new_size;
		pr_info("shrunk to %lu MB\n", new_size >> 20);
	} else {
		/* Grow: add memory and online to ZONE_MOVABLE */
		unsigned long grow_start = gxl_phys_start + gxl_online_size;
		unsigned long grow = new_size - gxl_online_size;

		rc = add_memory_driver_managed(gxl_mgid, grow_start, grow,
					       gxl_res_name, MHP_NID_IS_MGID);
		if (rc) {
			pr_warn("grow failed: %d\n", rc);
			goto out;
		}

		/*
		 * Online the new blocks to ZONE_MOVABLE.
		 * lock_device_hotplug is needed for device_online().
		 */
		lock_device_hotplug();
		walk_memory_blocks(grow_start, grow, NULL,
				   gxl_online_movable_cb);
		unlock_device_hotplug();

		gxl_online_size = new_size;
		pr_info("grown to %lu MB\n", new_size >> 20);
	}

out:
	mutex_unlock(&gxl_lock);
	return rc;
}

/*
 * sysfs interface: /sys/kernel/gxl/
 */

static ssize_t size_mb_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", gxl_online_size >> 20);
}

static ssize_t size_mb_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned long mb;
	int rc;

	if (!gxl_ready)
		return -ENODEV;

	rc = kstrtoul(buf, 0, &mb);
	if (rc)
		return rc;

	if (mb > (gxl_max_size >> 20))
		mb = gxl_max_size >> 20;

	rc = gxl_do_resize(mb << 20);
	if (rc)
		return rc;

	return count;
}

static struct kobj_attribute gxl_size_mb_attr =
	__ATTR(size_mb, 0644, size_mb_show, size_mb_store);

static ssize_t max_size_mb_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", gxl_max_size >> 20);
}

static struct kobj_attribute gxl_max_size_mb_attr =
	__ATTR(max_size_mb, 0444, max_size_mb_show, NULL);

static ssize_t numa_node_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", gxl_numa_node);
}

static struct kobj_attribute gxl_numa_node_attr =
	__ATTR(numa_node, 0444, numa_node_show, NULL);

static struct attribute *gxl_attrs[] = {
	&gxl_size_mb_attr.attr,
	&gxl_max_size_mb_attr.attr,
	&gxl_numa_node_attr.attr,
	NULL,
};

static const struct attribute_group gxl_attr_group = {
	.attrs = gxl_attrs,
};

/*
 * Initialization
 */

static int __init gxl_init(void)
{
	unsigned int domain, bus, slot, func;
	resource_size_t bar_start, aligned_start, aligned_end;
	unsigned long bar_size, usable_size, blk_size;
	struct pci_dev *pdev;
	int rc;

	if (!gxl_device[0])
		return 0;

	if (sscanf(gxl_device, "%x:%x:%x.%x",
		   &domain, &bus, &slot, &func) != 4) {
		pr_err("invalid device format: %s (expected DDDD:BB:DD.F)\n",
		       gxl_device);
		return -EINVAL;
	}

	pdev = pci_get_domain_bus_and_slot(domain, bus, PCI_DEVFN(slot, func));
	if (!pdev) {
		pr_err("PCI device %s not found\n", gxl_device);
		return -ENODEV;
	}

	rc = gxl_find_vram_bar(pdev, &bar_start, &bar_size);
	if (rc) {
		pr_err("no prefetchable VRAM BAR found on %s\n", gxl_device);
		goto err_put_pdev;
	}

	pr_info("found VRAM BAR: base=%pa size=%lu MB on %s\n",
		&bar_start, bar_size >> 20, gxl_device);

	/* Calculate usable size and align to memory block size */
	blk_size = memory_block_size_bytes();
	if (gxl_max_pool_percent > 100)
		gxl_max_pool_percent = 100;
	usable_size = bar_size * gxl_max_pool_percent / 100;
	aligned_start = ALIGN(bar_start, blk_size);
	aligned_end = ALIGN_DOWN(bar_start + usable_size, blk_size);

	if (aligned_start >= aligned_end) {
		pr_err("VRAM region too small after alignment (%lu MB, block size %lu MB)\n",
		       usable_size >> 20, blk_size >> 20);
		rc = -ENOSPC;
		goto err_put_pdev;
	}

	gxl_phys_start = aligned_start;
	gxl_max_size = aligned_end - aligned_start;

	pr_info("usable: %lu MB of %lu MB VRAM (aligned to %lu MB blocks)\n",
		gxl_max_size >> 20, bar_size >> 20, blk_size >> 20);

	/*
	 * GPU VRAM needs its own NUMA node -- we cannot share with a
	 * DRAM node because init_node_memory_type() would reclassify
	 * all of that node's memory (including DRAM) as GPU VRAM tier.
	 *
	 * First try to find an offline-but-possible node.  If none
	 * exists (common on single-socket systems without SRAT), claim
	 * the first unused node ID and add it to the possible map so
	 * the memory hotplug path will accept it.
	 */
	gxl_numa_node = NUMA_NO_NODE;
	for (rc = 0; rc < MAX_NUMNODES; rc++) {
		if (node_possible(rc) && !node_online(rc)) {
			gxl_numa_node = rc;
			break;
		}
	}
	if (gxl_numa_node == NUMA_NO_NODE) {
		for (rc = 0; rc < MAX_NUMNODES; rc++) {
			if (!node_possible(rc)) {
				/*
				 * free_area_init() allocates NODE_DATA for
				 * every possible node at early boot.  We
				 * missed that window, so allocate pgdat now
				 * before making the node visible.
				 */
				node_data[rc] = kzalloc(sizeof(pg_data_t),
							GFP_KERNEL);
				if (!node_data[rc]) {
					rc = -ENOMEM;
					goto err_put_pdev;
				}
				/*
				 * hotadd_init_pgdat() reads pgdat->node_id
				 * for zone initialisation -- set it before
				 * try_online_node() is called.
				 */
				node_data[rc]->node_id = rc;
				node_set(rc, node_possible_map);
				if (rc >= nr_node_ids)
					nr_node_ids = rc + 1;
				/*
				 * node_demotion[] in memory-tiers.c was
				 * allocated with the old nr_node_ids.
				 * Grow it before the node can enter
				 * N_MEMORY and be visited by
				 * establish_demotion_targets().
				 */
				if (memory_tier_realloc_demotion()) {
					node_clear(rc, node_possible_map);
					kfree(node_data[rc]);
					node_data[rc] = NULL;
					rc = -ENOMEM;
					goto err_put_pdev;
				}
				gxl_numa_node = rc;
				pr_info("claimed NUMA node %d for GPU VRAM\n",
					rc);
				break;
			}
		}
	}
	if (gxl_numa_node == NUMA_NO_NODE) {
		pr_err("no available NUMA node for GPU VRAM\n");
		rc = -ENOSPC;
		goto err_put_pdev;
	}

	/*
	 * Bring the node online so pgdat zones and zonelists are
	 * initialised.  For nodes found in the first loop this is a
	 * no-cost re-init; for nodes we just claimed it is mandatory
	 * because hotadd_init_pgdat() sets up the empty zones that
	 * add_memory_driver_managed() will later populate.
	 */
	rc = try_online_node(gxl_numa_node);
	if (rc < 0) {
		pr_err("failed to online node %d: %d\n", gxl_numa_node, rc);
		goto err_put_pdev;
	}

	/* Allocate memory type and register with tiering framework */
	gxl_mtype = alloc_memory_type(GXL_ADISTANCE);
	if (IS_ERR(gxl_mtype)) {
		rc = PTR_ERR(gxl_mtype);
		pr_err("failed to allocate memory type: %d\n", rc);
		goto err_put_pdev;
	}

	init_node_memory_type(gxl_numa_node, gxl_mtype);

	/* Register memory group for coherent hotplug tracking */
	rc = memory_group_register_static(gxl_numa_node, PFN_UP(gxl_max_size));
	if (rc < 0) {
		pr_err("failed to register memory group: %d\n", rc);
		goto err_clear_type;
	}
	gxl_mgid = rc;

	/* Reserve the full VRAM region for our use */
	gxl_res = request_mem_region(gxl_phys_start, gxl_max_size,
				     gxl_res_name);
	if (!gxl_res) {
		pr_err("could not reserve VRAM region %pa+%lu (in use by GPU driver?)\n",
		       &gxl_phys_start, gxl_max_size);
		rc = -EBUSY;
		goto err_unreg_group;
	}
	gxl_res->flags = IORESOURCE_SYSTEM_RAM;

	/* Create sysfs interface */
	gxl_kobj = kobject_create_and_add("gxl", mm_kobj);
	if (!gxl_kobj) {
		rc = -ENOMEM;
		goto err_release_region;
	}

	rc = sysfs_create_group(gxl_kobj, &gxl_attr_group);
	if (rc)
		goto err_put_kobj;

	gxl_pdev = pdev;
	gxl_ready = true;

	pr_info("ready: %lu MB GPU VRAM available on node %d (adist %ld)\n",
		gxl_max_size >> 20, gxl_numa_node, GXL_ADISTANCE);
	pr_info("write to /sys/kernel/mm/gxl/size_mb to register VRAM\n");

	return 0;

err_put_kobj:
	kobject_put(gxl_kobj);
	gxl_kobj = NULL;
err_release_region:
	remove_resource(gxl_res);
	kfree(gxl_res);
	gxl_res = NULL;
err_unreg_group:
	memory_group_unregister(gxl_mgid);
	gxl_mgid = -1;
err_clear_type:
	clear_node_memory_type(gxl_numa_node, gxl_mtype);
	put_memory_type(gxl_mtype);
	gxl_mtype = NULL;
err_put_pdev:
	pci_dev_put(pdev);
	return rc;
}

late_initcall(gxl_init);
