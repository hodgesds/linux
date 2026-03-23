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
#include <linux/io.h>
#include <linux/swap.h>

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
static const char *gxl_res_name __used = "System RAM (gxl)";

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
	void __iomem		*wc_base;	/* ioremap_wc of the BAR */
	enum {
		GXL_STATE_INIT,		/* not yet initialized */
		GXL_STATE_READY,	/* ready, GPU driver holds BAR claim */
		GXL_STATE_BAR_FREE,	/* ready, BAR claim released by gxl */
	}			state;
	struct kobject		*kobj;		/* /sys/kernel/mm/gxl/<slot>/ */
	struct mutex		lock;
	atomic_long_t		nr_demotions;	/* DRAM->VRAM page copies */
	atomic_long_t		nr_promotions;	/* VRAM->DRAM page copies */
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

	/* WC mapping for fast MOVNTDQA reads and write-combining writes */
	gdev->wc_base = ioremap_wc(bar_start, bar_size);
	if (!gdev->wc_base) {
		pr_warn("%s: ioremap_wc failed, WC copy acceleration unavailable\n",
			gdev->slot);
		/* Non-fatal: fall through to normal memcpy path */
	}

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

	gdev->pdev = pdev;
	gdev->state = GXL_STATE_READY;

	pr_info("%s: ready: %lu MB GPU VRAM on node %d (adist %u, local node %d)\n",
		gdev->slot, gdev->max_size >> 20, gdev->numa_node,
		gdev->adistance, gdev->local_node);

	return 0;

err_clear_type:
	memory_group_unregister(gdev->mgid);
	gdev->mgid = -1;
	clear_node_memory_type(gdev->numa_node, gdev->mtype);
	lock_device_hotplug();
	try_offline_node(gdev->numa_node);
	unlock_device_hotplug();
	gdev->numa_node = NUMA_NO_NODE;
err_put_mtype:
	put_memory_type(gdev->mtype);
	gdev->mtype = NULL;
err_put_pdev:
	if (gdev->wc_base) {
		iounmap(gdev->wc_base);
		gdev->wc_base = NULL;
	}
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
		if (gxl_devs[i].state >= GXL_STATE_READY)
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
		if (gxl_devs[i].state >= GXL_STATE_READY)
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
