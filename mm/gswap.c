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
* VRAM buddy allocator
**********************************/

/*
 * Compute the buddy order needed for a given compressed size.
 * Returns the smallest order whose block size >= @size.
 */
static unsigned int gswap_size_to_order(unsigned int size)
{
	if (size <= GSWAP_MIN_ALLOC_SIZE)
		return 0;
	return order_base_2(size) - GSWAP_MIN_ALLOC_SHIFT;
}

/*
 * Per-CPU block cache to avoid global lock contention on the buddy
 * allocator hot path.  Each CPU keeps a small stash of pre-split
 * block offsets at each order.  Allocations drain the local cache
 * under a local_lock (RT-safe); on miss, a batch is refilled
 * from the global buddy under the pool lock.  Frees return blocks
 * to the local cache; overflow flushes half the cache back.
 */
#define GSWAP_PCPU_BATCH	16	/* blocks per order per CPU */

struct gswap_pcpu_cache {
	local_lock_t	lock;
	unsigned long	blocks[GSWAP_NR_ORDERS][GSWAP_PCPU_BATCH];
	unsigned int	count[GSWAP_NR_ORDERS];
};

static struct gswap_pcpu_cache __percpu *gswap_pcpu_alloc;

/*
 * Allocate a single block at @order from the global buddy.
 * Caller must hold gswap_pool.lock.
 * Returns block index or -1 on failure.
 */
static long __buddy_alloc_one(unsigned int order)
{
	unsigned int cur;
	unsigned long block_idx;
	unsigned long nr_at_order;

	for (cur = order; cur < GSWAP_NR_ORDERS; cur++) {
		unsigned long hint;

		if (!gswap_pool.nr_free[cur])
			continue;

		nr_at_order = gswap_pool.nr_blocks >> cur;
		hint = gswap_pool.hint[cur];
		if (hint >= nr_at_order)
			hint = 0;

		block_idx = find_next_bit(gswap_pool.free[cur], nr_at_order,
					  hint);
		if (block_idx < nr_at_order)
			goto found;

		if (hint) {
			block_idx = find_first_bit(gswap_pool.free[cur],
						   hint);
			if (block_idx < hint)
				goto found;
		}
	}

	return -1;

found:
	clear_bit(block_idx, gswap_pool.free[cur]);
	gswap_pool.nr_free[cur]--;
	gswap_pool.hint[cur] = block_idx + 1;

	while (cur > order) {
		cur--;
		set_bit(block_idx * 2 + 1, gswap_pool.free[cur]);
		gswap_pool.nr_free[cur]++;
		block_idx *= 2;
	}

	return (long)block_idx;
}

/*
 * Return a single block at @order to the global buddy with merging.
 * Caller must hold gswap_pool.lock.
 */
static void __buddy_free_one(unsigned long block_idx, unsigned int order)
{
	unsigned long buddy_idx;

	while (order < GSWAP_NR_ORDERS - 1) {
		buddy_idx = block_idx ^ 1;

		if (buddy_idx >= (gswap_pool.nr_blocks >> order) ||
		    !test_bit(buddy_idx, gswap_pool.free[order]))
			break;

		clear_bit(buddy_idx, gswap_pool.free[order]);
		gswap_pool.nr_free[order]--;
		block_idx >>= 1;
		order++;
	}

	set_bit(block_idx, gswap_pool.free[order]);
	gswap_pool.nr_free[order]++;

	if (block_idx < gswap_pool.hint[order])
		gswap_pool.hint[order] = block_idx;
}

/*
 * Refill the per-CPU cache for @order from the global buddy.
 * Called with per-CPU local_lock held, takes pool lock internally.
 */
static void gswap_pcpu_refill(struct gswap_pcpu_cache *cache,
			       unsigned int order)
{
	int i;

	spin_lock(&gswap_pool.lock);
	for (i = 0; i < GSWAP_PCPU_BATCH / 2; i++) {
		long idx = __buddy_alloc_one(order);

		if (idx < 0)
			break;
		cache->blocks[order][cache->count[order]++] = idx;
	}
	spin_unlock(&gswap_pool.lock);
}

/*
 * Flush half the per-CPU cache for @order back to the global buddy.
 * Called with per-CPU local_lock held, takes pool lock internally.
 */
static void gswap_pcpu_flush(struct gswap_pcpu_cache *cache,
			      unsigned int order)
{
	unsigned int nr_flush = cache->count[order] / 2;
	unsigned int i;

	spin_lock(&gswap_pool.lock);
	for (i = 0; i < nr_flush; i++) {
		cache->count[order]--;
		__buddy_free_one(cache->blocks[order][cache->count[order]],
				 order);
	}
	spin_unlock(&gswap_pool.lock);
}

/*
 * Allocate a VRAM region of the given order.
 * Returns the byte offset in VRAM, or -ENOMEM on failure.
 */
static long gswap_buddy_alloc(unsigned int order)
{
	struct gswap_pcpu_cache *cache;
	long block_idx;

	local_lock(&gswap_pcpu_alloc->lock);
	cache = this_cpu_ptr(gswap_pcpu_alloc);

	if (likely(cache->count[order])) {
		block_idx = cache->blocks[order][--cache->count[order]];
		local_unlock(&gswap_pcpu_alloc->lock);
		atomic_long_add(GSWAP_MIN_ALLOC_SIZE << order,
				&gswap_pool.used_bytes);
		return block_idx << (GSWAP_MIN_ALLOC_SHIFT + order);
	}

	/* Cache miss — refill from global buddy */
	gswap_pcpu_refill(cache, order);

	if (likely(cache->count[order])) {
		block_idx = cache->blocks[order][--cache->count[order]];
		local_unlock(&gswap_pcpu_alloc->lock);
		atomic_long_add(GSWAP_MIN_ALLOC_SIZE << order,
				&gswap_pool.used_bytes);
		return block_idx << (GSWAP_MIN_ALLOC_SHIFT + order);
	}

	local_unlock(&gswap_pcpu_alloc->lock);
	return -ENOMEM;
}

/*
 * Free a VRAM region, returning it to the per-CPU cache.
 * Overflows are flushed back to the global buddy with merging.
 */
static void gswap_buddy_free(unsigned long offset, unsigned int order)
{
	struct gswap_pcpu_cache *cache;
	unsigned long block_idx = offset >> (GSWAP_MIN_ALLOC_SHIFT + order);

	local_lock(&gswap_pcpu_alloc->lock);
	cache = this_cpu_ptr(gswap_pcpu_alloc);

	if (likely(cache->count[order] < GSWAP_PCPU_BATCH)) {
		cache->blocks[order][cache->count[order]++] = block_idx;
		local_unlock(&gswap_pcpu_alloc->lock);
		return;
	}

	/* Cache full — flush half, then add */
	gswap_pcpu_flush(cache, order);
	cache->blocks[order][cache->count[order]++] = block_idx;
	local_unlock(&gswap_pcpu_alloc->lock);
}

/*
 * Convenience wrappers that derive the order from compressed size.
 */
static long gswap_alloc_vram(unsigned int comp_len)
{
	unsigned int order = gswap_size_to_order(comp_len);

	if (order >= GSWAP_NR_ORDERS)
		return -ENOMEM;
	return gswap_buddy_alloc(order);
}

static void gswap_free_vram(unsigned long offset, unsigned int comp_len)
{
	unsigned int order = gswap_size_to_order(comp_len);

	gswap_buddy_free(offset, order);
	atomic_long_sub(GSWAP_MIN_ALLOC_SIZE << order, &gswap_pool.used_bytes);
}

/*
 * Translate a byte offset into a buffer index and offset within
 * that buffer.
 */
static void gswap_vram_location(unsigned long offset,
				unsigned int *buf_idx,
				unsigned long *buf_offset)
{
	*buf_idx    = offset / gswap_pool.buf_size;
	*buf_offset = offset % gswap_pool.buf_size;
}

/*
 * Check pool utilization and return:
 *   0 = below high watermark, store may proceed
 *   1 = above high watermark (90%), store proceeds but writeback triggered
 *   2 = at hard limit (100%), store rejected
 */
static int gswap_check_limits(void)
{
	unsigned long used = atomic_long_read(&gswap_pool.used_bytes);
	unsigned long max = gswap_pool.usable_size;

	if (used >= max) {
		atomic_long_inc(&gswap_pool_limit_hit);
		WRITE_ONCE(gswap_pool_reached_full, true);
		return 2;
	}

	if (READ_ONCE(gswap_pool_reached_full) && used <= max * 4 / 5)
		WRITE_ONCE(gswap_pool_reached_full, false);

	if (used >= max * 9 / 10)
		return 1;

	return 0;
}

/*********************************
* VRAM I/O helpers
**********************************/

static void gswap_write_to_vram(unsigned long vram_off,
				const void *src, unsigned int len)
{
	unsigned int buf_idx;
	unsigned long buf_off;

	gswap_vram_location(vram_off, &buf_idx, &buf_off);
	iosys_map_memcpy_to(&gswap_pool.maps[buf_idx], buf_off, src, len);
	/* Ensure write-combining buffers are flushed */
	wmb();
}

static void gswap_read_from_vram(unsigned long vram_off,
				 void *dst, unsigned int len)
{
	unsigned int buf_idx;
	unsigned long buf_off;

	gswap_vram_location(vram_off, &buf_idx, &buf_off);

#ifdef CONFIG_DRM
	{
		struct iosys_map src, dst_map = IOSYS_MAP_INIT_VADDR(dst);

		src = gswap_pool.maps[buf_idx];
		iosys_map_incr(&src, buf_off);
		/*
		 * Round up to 16 bytes for MOVNTDQA fast path in
		 * drm_memcpy_from_wc.  Callers' buffers are always
		 * large enough for the padding.
		 */
		drm_memcpy_from_wc(&dst_map, &src, ALIGN(len, 16));
	}
#else
	iosys_map_memcpy_from(dst, &gswap_pool.maps[buf_idx], buf_off, len);
#endif
}

/*********************************
* compression context management
**********************************/

static int gswap_cpu_comp_prepare(unsigned int cpu)
{
	struct gswap_crypto_ctx *ctx = per_cpu_ptr(gswap_comp_ctx, cpu);
	struct crypto_acomp *acomp;
	struct acomp_req *req;
	u8 *buffer;

	buffer = kmalloc_node(PAGE_SIZE, GFP_KERNEL, cpu_to_node(cpu));
	if (!buffer)
		return -ENOMEM;

	acomp = crypto_alloc_acomp_node(gswap_compressor, 0, 0,
					cpu_to_node(cpu));
	if (IS_ERR(acomp)) {
		pr_err("could not alloc crypto acomp %s: %pe\n",
		       gswap_compressor, acomp);
		kfree(buffer);
		return PTR_ERR(acomp);
	}

	req = acomp_request_alloc(acomp);
	if (!req) {
		pr_err("could not alloc crypto acomp_request %s\n",
		       gswap_compressor);
		crypto_free_acomp(acomp);
		kfree(buffer);
		return -ENOMEM;
	}

	if (!ctx->ra.buf) {
		ctx->ra.buf = kmalloc_node(GSWAP_RA_BUF_SIZE,
					   GFP_KERNEL, cpu_to_node(cpu));
		if (!ctx->ra.buf) {
			acomp_request_free(req);
			crypto_free_acomp(acomp);
			kfree(buffer);
			return -ENOMEM;
		}
		ctx->ra.count = 0;
		ctx->ra.last_offset = (pgoff_t)-1;
		ctx->ra.window = min_t(unsigned int,
				       gswap_ra_size, GSWAP_RA_SIZE);
		ctx->ra.hits = 0;
		ctx->ra.accesses = 0;
	}

	mutex_lock(&ctx->mutex);
	crypto_init_wait(&ctx->wait);
	acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &ctx->wait);
	ctx->buffer = buffer;
	ctx->acomp = acomp;
	ctx->req = req;
	mutex_unlock(&ctx->mutex);

	return 0;
}

static int gswap_cpu_comp_destroy(unsigned int cpu)
{
	struct gswap_crypto_ctx *ctx = per_cpu_ptr(gswap_comp_ctx, cpu);
	struct acomp_req *req;
	struct crypto_acomp *acomp;
	u8 *buffer;

	/* Drain per-CPU allocator cache back to global buddy */
	if (gswap_pcpu_alloc) {
		struct gswap_pcpu_cache *cache = per_cpu_ptr(gswap_pcpu_alloc,
							     cpu);
		int order;

		spin_lock(&gswap_pool.lock);
		for (order = 0; order < GSWAP_NR_ORDERS; order++) {
			while (cache->count[order]) {
				cache->count[order]--;
				__buddy_free_one(
					cache->blocks[order][cache->count[order]],
					order);
			}
		}
		spin_unlock(&gswap_pool.lock);
	}

	mutex_lock(&ctx->mutex);
	req = ctx->req;
	acomp = ctx->acomp;
	buffer = ctx->buffer;
	ctx->req = NULL;
	ctx->acomp = NULL;
	ctx->buffer = NULL;
	mutex_unlock(&ctx->mutex);

	if (req)
		acomp_request_free(req);
	if (acomp)
		crypto_free_acomp(acomp);
	kfree(buffer);
	kfree(ctx->ra.buf);
	ctx->ra.buf = NULL;
	ctx->ra.count = 0;
	ctx->ra.window = 0;
	return 0;
}

static struct gswap_crypto_ctx *gswap_comp_ctx_get(void)
{
	struct gswap_crypto_ctx *ctx;

	/*
	 * Retry loop handles the case where we get migrated to a CPU whose
	 * context was torn down by cpu_comp_dead(). The hotplug callback
	 * ensures a newly onlined CPU will always have a context prepared,
	 * so this loop will terminate.
	 */
	for (;;) {
		ctx = raw_cpu_ptr(gswap_comp_ctx);
		mutex_lock(&ctx->mutex);
		if (likely(ctx->req))
			return ctx;
		mutex_unlock(&ctx->mutex);
	}
}

static void gswap_comp_ctx_put(struct gswap_crypto_ctx *ctx)
{
	mutex_unlock(&ctx->mutex);
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
