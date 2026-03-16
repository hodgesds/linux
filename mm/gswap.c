// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * gswap.c - GPU VRAM-backed compressed swap cache
 *
 * gswap is a swap cache that compresses pages and stores them in GPU VRAM
 * accessed via MMIO (io_mapping). It sits between zswap (RAM) and disk swap
 * in the swap hierarchy, providing ~2-5us latency while consuming zero
 * system RAM for data storage.
 *
 * Architecture:
 *   Page reclaim -> zswap (RAM) -> gswap (VRAM) -> disk swap
 *
 * The implementation follows zswap's interceptor pattern: hooks in
 * swap_writeout() and swap_read_folio() try gswap before falling through
 * to disk I/O.
 *
 * When CONFIG_DRM is enabled, VRAM is allocated through the GPU driver's
 * memory manager (via DRM client dumb buffers), ensuring safe coexistence.
 * Otherwise, VRAM is mapped directly from the PCI BAR. A fixed-slot bitmap
 * allocator manages VRAM space, with compressed pages stored in fixed-size
 * slots. Access uses iosys_map for portable iomem/system memory handling.
 *
 * Copyright (C) 2026
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/swap.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/acompress.h>
#include <crypto/scatterwalk.h>
#include <linux/gswap.h>
#include <linux/mm_types.h>
#include <linux/sched/mm.h>
#include <linux/page-flags.h>
#include <linux/swapops.h>
#include <linux/workqueue.h>
#include <linux/io.h>
#include <linux/bitmap.h>
#include <linux/debugfs.h>
#include <linux/pci.h>
#include <linux/iosys-map.h>
#include <linux/cpuhotplug.h>
#include <linux/local_lock.h>
#include <linux/bio.h>

#ifdef CONFIG_DRM
#include <drm/drm_client.h>
#include <drm/drm_dumb_buffers.h>
#include <drm/drm_file.h>
#include <drm/drm_gem.h>
#include <drm/drm_cache.h>
#endif
#include <linux/rcupdate.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/mempolicy.h>

#include "swap.h"
#include "internal.h"

/*********************************
* configuration
**********************************/

/*
 * Buddy allocator for VRAM.  Variable-size allocations let us accept
 * pages that compress to anything < PAGE_SIZE instead of rejecting
 * everything above a fixed 2 KB slot.
 *
 * Order 0 = 256 bytes, order 4 = 4096 bytes (PAGE_SIZE).
 */
#define GSWAP_MIN_ALLOC_SHIFT	8
#define GSWAP_MIN_ALLOC_SIZE	(1UL << GSWAP_MIN_ALLOC_SHIFT)
#define GSWAP_NR_ORDERS		5	/* 256, 512, 1024, 2048, 4096 */

/* Maximum readahead window (compile-time buffer size) */
#define GSWAP_RA_SIZE		32
#define GSWAP_RA_BUF_SIZE	(GSWAP_RA_SIZE * PAGE_SIZE)

/* Default compressor */
#define GSWAP_COMPRESSOR_DEFAULT "lz4"

/*********************************
* tunables
**********************************/

static bool gswap_enabled;
module_param_named(enabled, gswap_enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable/disable gswap");

static char *gswap_compressor = GSWAP_COMPRESSOR_DEFAULT;
module_param_named(compressor, gswap_compressor, charp, 0444);
MODULE_PARM_DESC(compressor, "Compression algorithm");

/* Readahead window: 0 disables, max GSWAP_RA_SIZE */
static unsigned int gswap_ra_size = GSWAP_RA_SIZE;
module_param_named(ra_size, gswap_ra_size, uint, 0644);
MODULE_PARM_DESC(ra_size, "VRAM readahead window (0 to disable, max 32)");

/* Maximum percentage of VRAM to use */
static unsigned int gswap_max_pool_percent = 50;
module_param_named(max_pool_percent, gswap_max_pool_percent, uint, 0644);
MODULE_PARM_DESC(max_pool_percent, "Max percentage of VRAM to use for swap");

/* VRAM BAR physical address and size -- set by user or auto-detected */
static unsigned long gswap_vram_base;
module_param_named(vram_base, gswap_vram_base, ulong, 0444);
MODULE_PARM_DESC(vram_base, "VRAM BAR physical base address");

static unsigned long gswap_vram_size;
module_param_named(vram_size, gswap_vram_size, ulong, 0444);
MODULE_PARM_DESC(vram_size, "VRAM BAR size in bytes");

/* Target a specific GPU by PCI slot (e.g. "0000:12:00.0") */
static char *gswap_device;
module_param_named(device, gswap_device, charp, 0444);
MODULE_PARM_DESC(device, "PCI slot of GPU to use (e.g. 0000:12:00.0)");

/*********************************
* statistics
**********************************/

static atomic_long_t gswap_stored_pages = ATOMIC_LONG_INIT(0);

static atomic_long_t gswap_stores = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_loads = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_reject_compress_fail = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_reject_compress_poor = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_reject_alloc_fail = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_reject_kmemcache_fail = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_decompress_fail = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_written_back_pages = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_pool_limit_hit = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_ra_hits = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_ra_misses = ATOMIC_LONG_INIT(0);
static atomic_long_t gswap_ra_skips = ATOMIC_LONG_INIT(0);

/*********************************
* data structures
**********************************/

struct gswap_ra_entry {
	pgoff_t			offset;
	int			swp_type;
	struct gswap_entry	*gentry;	/* xarray pointer at fill time */
	u32			length;
	u32			buf_offset;
};

struct gswap_ra_cache {
	struct gswap_ra_entry	entries[GSWAP_RA_SIZE];
	u8			*buf;		/* GSWAP_RA_BUF_SIZE bytes */
	int			count;
	pgoff_t			last_offset;	/* last loaded offset (sequentiality) */
	unsigned int		window;		/* adaptive window size */
	unsigned int		hits;		/* rolling hit count */
	unsigned int		accesses;	/* rolling access count */
};

struct gswap_crypto_ctx {
	struct crypto_acomp *acomp;
	struct acomp_req *req;
	struct crypto_wait wait;
	u8 *buffer;
	struct mutex mutex;
	struct gswap_ra_cache ra;
};

/*
 * gswap_entry: metadata for one compressed page stored in VRAM.
 *
 * Stored in a per-swap-type xarray keyed by swap offset.  The actual
 * compressed data lives in VRAM at the byte offset stored in vram_offset.
 */
struct gswap_entry {
	swp_entry_t swpentry;
	unsigned long vram_offset; /* byte offset in VRAM */
	u32 length;		/* compressed size in bytes */
	struct list_head lru;
};

/*
 * gswap_pool: manages a region of GPU VRAM for compressed swap storage.
 *
 * Uses a buddy allocator with power-of-2 block sizes from 256 bytes
 * (order 0) to 4096 bytes (order 4).  This lets us accept pages that
 * compress to anything under PAGE_SIZE, instead of rejecting all pages
 * above a fixed slot threshold.
 *
 * VRAM may be split across multiple DRM dumb buffers because the DRM
 * dumb-buffer interface uses u32 size arithmetic, limiting each buffer
 * to ~4 GB.  The maps[] array holds one iosys_map per buffer; byte
 * offsets span all buffers contiguously.
 */
#define GSWAP_MAX_BUFFERS	16

struct gswap_pool {
	struct iosys_map		maps[GSWAP_MAX_BUFFERS];
	unsigned int		nr_maps;	/* number of valid maps */
	unsigned long		buf_size;	/* size per buffer */
	unsigned long		total_size;	/* total VRAM region size */
	unsigned long		usable_size;	/* max_pool_percent of total */
	unsigned long		nr_blocks;	/* total min-size blocks */
	unsigned long		*free[GSWAP_NR_ORDERS]; /* buddy free bitmaps */
	unsigned long		nr_free[GSWAP_NR_ORDERS]; /* free block count */
	unsigned long		hint[GSWAP_NR_ORDERS];  /* bitmap scan start */
	spinlock_t		lock;		/* protects free bitmaps + hints */
	atomic_long_t		used_bytes;	/* bytes allocated */
};

static struct gswap_pool gswap_pool;
static struct gswap_crypto_ctx __percpu *gswap_comp_ctx;
static struct kmem_cache *gswap_entry_cache;

/* Per-swap-type xarray for entry tracking (mirrors zswap pattern) */
#define GSWAP_ADDRESS_SPACE_SHIFT 14
#define GSWAP_ADDRESS_SPACE_PAGES (1 << GSWAP_ADDRESS_SPACE_SHIFT)

static struct xarray *gswap_trees[MAX_SWAPFILES];
static unsigned int nr_gswap_trees[MAX_SWAPFILES];

/* LRU for writeback ordering */
static LIST_HEAD(gswap_lru_list);
static DEFINE_SPINLOCK(gswap_lru_lock);

/* Writeback workqueue */
static struct workqueue_struct *gswap_writeback_wq;
static struct delayed_work gswap_writeback_work;

static bool gswap_pool_reached_full;

static bool gswap_init_done;
static bool gswap_has_pool;

#ifdef CONFIG_DRM
static struct drm_client_dev gswap_drm_client;
static struct drm_gem_object *gswap_drm_gems[GSWAP_MAX_BUFFERS];
static unsigned int gswap_drm_nr_bufs;
static struct notifier_block gswap_pci_nb;
static struct work_struct gswap_drm_work;
static struct pci_dev *gswap_gpu_pdev;
#endif

/* CPU hotplug state for dynamic context management */
static enum cpuhp_state gswap_hp_state;

/*
 * Active users counter: prevents module teardown while store/load
 * operations are in-flight. Uses percpu_ref for minimal overhead
 * on the fast path.
 */
static struct percpu_ref gswap_active_ref;
static struct completion gswap_active_ref_done;

static void gswap_active_ref_release(struct percpu_ref *ref)
{
	complete(&gswap_active_ref_done);
}

/*********************************
* helpers
**********************************/

static inline struct xarray *swap_gswap_tree(swp_entry_t swp)
{
	return &gswap_trees[swp_type(swp)][swp_offset(swp)
		>> GSWAP_ADDRESS_SPACE_SHIFT];
}

static struct gswap_entry *gswap_entry_cache_alloc(gfp_t gfp, int nid)
{
	return kmem_cache_alloc_node(gswap_entry_cache, gfp, nid);
}

static void gswap_entry_cache_free(struct gswap_entry *entry)
{
	kmem_cache_free(gswap_entry_cache, entry);
}

static bool gswap_device_matches(struct pci_dev *pdev)
{
	if (!gswap_device || !*gswap_device)
		return true;
	return !strcmp(dev_name(&pdev->dev), gswap_device);
}

/*********************************

* entry management
**********************************/

static void gswap_entry_free(struct gswap_entry *entry)
{
	gswap_free_vram(entry->vram_offset, entry->length);

	spin_lock(&gswap_lru_lock);
	if (!list_empty(&entry->lru))
		list_del_init(&entry->lru);
	spin_unlock(&gswap_lru_lock);

	atomic_long_dec(&gswap_stored_pages);
	gswap_entry_cache_free(entry);
}

/*********************************

/*********************************
* main API (stubs, wired up by subsequent patches)
**********************************/

bool gswap_store(struct folio *folio) { return false; }
int gswap_load(struct folio *folio) { return -ENOENT; }
void gswap_invalidate(swp_entry_t swp) {}
int gswap_swapon(int type, unsigned long nr_pages, unsigned long flags) { return 0; }
void gswap_swapoff(int type) {}

static int __init gswap_init(void)
{
	gswap_entry_cache = KMEM_CACHE(gswap_entry, 0);
	if (!gswap_entry_cache)
		return -ENOMEM;
	gswap_init_done = true;
	return 0;
}
late_initcall(gswap_init);
