// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * gxl.c - GPU VRAM as CXL.mem-style memory tier
 *
 * gxl exposes GPU VRAM as a kernel-managed memory tier, allowing the
 * kernel to automatically demote cold pages from DRAM to GPU VRAM
 * under memory pressure.  This is conceptually identical to how CXL
 * Type 3 memory devices provide additional capacity at higher latency.
 *
 * GPU VRAM is accessed via the PCI BAR (resizable BAR / SAM), mapped
 * with write-combining semantics, and registered as a NUMA memory node
 * through the memory hotplug and memory tiering infrastructure.
 *
 * Architecture:
 *   Memory pressure -> NUMA demotion -> pages migrate DRAM -> GPU VRAM
 *   Access pattern  -> NUMA balancing -> pages promote GPU VRAM -> DRAM
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

static struct pci_dev *gxl_pdev;
static struct resource *gxl_res;
static struct memory_dev_type *gxl_mtype;
static int gxl_mgid = -1;
static int gxl_numa_node = NUMA_NO_NODE;
static resource_size_t gxl_phys_start;
static unsigned long gxl_size;

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
	gxl_size = aligned_end - aligned_start;

	pr_info("using %lu MB of %lu MB VRAM (aligned to %lu MB blocks)\n",
		gxl_size >> 20, bar_size >> 20, blk_size >> 20);

	/* Determine NUMA node from PCI topology */
	gxl_numa_node = dev_to_node(&pdev->dev);
	if (gxl_numa_node < 0)
		gxl_numa_node = 0;

	/* Allocate memory type and register with tiering framework */
	gxl_mtype = alloc_memory_type(GXL_ADISTANCE);
	if (IS_ERR(gxl_mtype)) {
		rc = PTR_ERR(gxl_mtype);
		pr_err("failed to allocate memory type: %d\n", rc);
		goto err_put_pdev;
	}

	init_node_memory_type(gxl_numa_node, gxl_mtype);

	/* Register memory group for coherent hotplug tracking */
	rc = memory_group_register_static(gxl_numa_node, PFN_UP(gxl_size));
	if (rc < 0) {
		pr_err("failed to register memory group: %d\n", rc);
		goto err_clear_type;
	}
	gxl_mgid = rc;

	/* Reserve physical address region */
	gxl_res = request_mem_region(gxl_phys_start, gxl_size, gxl_res_name);
	if (!gxl_res) {
		pr_err("could not reserve VRAM region %pa+%lu (in use by GPU driver?)\n",
		       &gxl_phys_start, gxl_size);
		rc = -EBUSY;
		goto err_unreg_group;
	}
	gxl_res->flags = IORESOURCE_SYSTEM_RAM;

	/* Add VRAM as driver-managed system memory */
	rc = add_memory_driver_managed(gxl_mgid, gxl_phys_start, gxl_size,
				       gxl_res_name, MHP_NID_IS_MGID);
	if (rc) {
		pr_err("failed to add memory: %d\n", rc);
		goto err_release_region;
	}

	gxl_pdev = pdev;
	pr_info("registered %lu MB GPU VRAM as memory tier (node %d, adist %ld)\n",
		gxl_size >> 20, gxl_numa_node, GXL_ADISTANCE);

	return 0;

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
