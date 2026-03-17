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
* writeback (VRAM -> disk swap)
**********************************/

/*
 * gswap_writeback_entry() - write a single entry back to the swap device.
 *
 * Decompresses the data from VRAM, allocates a swap cache folio, and
 * writes it to the swap device so the data is preserved when we free
 * the VRAM slot. Follows the same pattern as zswap_writeback_entry().
 *
 * Returns 0 on success, negative error on failure.
 */
static int gswap_writeback_entry(struct gswap_entry *entry,
				 swp_entry_t swpentry)
{
	pgoff_t offset = swp_offset(swpentry);
	struct xarray *tree;
	struct gswap_crypto_ctx *ctx;
	struct scatterlist input, output;
	struct folio *folio;
	struct mempolicy *mpol;
	struct swap_info_struct *si;
	bool folio_was_allocated;
	int ret;
	unsigned int dlen;

	/*
	 * Allocate a swap cache folio. This either finds an existing
	 * folio (race with swapin) or creates a new one in the cache.
	 */
	si = get_swap_device(swpentry);
	if (!si)
		return -EAGAIN;

	mpol = get_task_policy(current);
	folio = swap_cache_alloc_folio(swpentry, GFP_KERNEL, mpol,
				       NO_INTERLEAVE_INDEX,
				       &folio_was_allocated);
	put_swap_device(si);
	if (!folio)
		return -EAGAIN;

	/*
	 * Folio already in swap cache -- it still contains the original
	 * page data that gswap_store() compressed.  Use it directly
	 * instead of allocating a new folio.  This avoids the livelock
	 * where writeback keeps failing with -EAGAIN because the
	 * original folio sits in the swap cache, and no VRAM slots are
	 * ever freed.
	 *
	 * folio_trylock avoids blocking against concurrent swapin which
	 * will handle the entry itself via gswap_load().
	 */
	if (!folio_was_allocated) {
		if (!folio_trylock(folio)) {
			folio_put(folio);
			return -EAGAIN;
		}

		/*
		 * Verify the folio is still in the swap cache -- it may
		 * have been reclaimed between swap_cache_get_folio and
		 * our trylock, invalidating the swap entry.
		 */
		if (!folio_test_swapcache(folio)) {
			folio_unlock(folio);
			folio_put(folio);
			return -EAGAIN;
		}

		/*
		 * Claim the gswap entry.  If a concurrent load/invalidate
		 * already erased it, the folio is being handled elsewhere.
		 */
		tree = swap_gswap_tree(swpentry);
		if (xa_cmpxchg(tree, offset, entry, NULL, GFP_KERNEL) != entry) {
			folio_unlock(folio);
			folio_put(folio);
			return -ENOMEM;
		}

		gswap_entry_free(entry);

		/* Folio already has correct data -- write it to disk */
		folio_mark_uptodate(folio);
		folio_set_reclaim(folio);
		__swap_writepage(folio, NULL);
		folio_put(folio);
		return 0;
	}

	/*
	 * Folio is locked and in the swap cache. Atomically claim the
	 * entry from the xarray using xa_cmpxchg. If the entry was
	 * already erased by a concurrent swapcache gswap_load() or
	 * gswap_invalidate(), the cmpxchg fails and we bail out.
	 *
	 * Only dereference entry after this check -- before this point,
	 * a concurrent load may have freed it. We use the stack copy
	 * of swpentry (passed by the caller) for all operations above.
	 */
	tree = swap_gswap_tree(swpentry);
	if (xa_cmpxchg(tree, offset, entry, NULL, GFP_KERNEL) != entry) {
		ret = -ENOMEM;
		goto out;
	}

	/* Entry is now exclusively ours -- decompress from VRAM */
	ctx = gswap_comp_ctx_get();
	gswap_read_from_vram(entry->vram_offset, ctx->buffer, entry->length);

	sg_init_one(&input, ctx->buffer, entry->length);
	sg_init_table(&output, 1);
	sg_set_folio(&output, folio, PAGE_SIZE, 0);
	acomp_request_set_params(ctx->req, &input, &output,
				 entry->length, PAGE_SIZE);

	ret = crypto_wait_req(crypto_acomp_decompress(ctx->req), &ctx->wait);
	dlen = ctx->req->dlen;
	gswap_comp_ctx_put(ctx);

	if (ret || dlen != PAGE_SIZE) {
		ret = -EIO;
		gswap_entry_free(entry);
		goto out;
	}

	gswap_entry_free(entry);

	folio_mark_uptodate(folio);
	folio_set_reclaim(folio);

	/* Write the decompressed page to the swap device */
	__swap_writepage(folio, NULL);

out:
	if (ret) {
		swap_cache_del_folio(folio);
		folio_unlock(folio);
	}
	folio_put(folio);
	return ret;
}

/* Backoff delay when writeback fails repeatedly (100ms) */
#define GSWAP_WRITEBACK_RETRY_DELAY	(HZ / 10)

static void gswap_writeback_worker(struct work_struct *work)
{
	struct gswap_entry *entry;
	struct xarray *tree;
	swp_entry_t swpentry;
	unsigned long nr_writeback = 0;
	unsigned long nr_failures = 0;
	unsigned long max_writeback = atomic_long_read(&gswap_pool.used_bytes) /
				     (4 * PAGE_SIZE);
	unsigned int nofs_flag;
	int ret;

	if (max_writeback < 16)
		max_writeback = 16;

	/*
	 * Prevent filesystem recursion: allocations inside (e.g.
	 * swap_cache_alloc_folio, xa_cmpxchg) can trigger direct
	 * reclaim, which can re-enter the swap path.  Stripping
	 * __GFP_FS prevents filesystem-level recursion.
	 *
	 * We allow __GFP_IO so reclaim can write dirty pages and
	 * swap pages to disk -- without this, folio allocation fails
	 * under memory pressure because reclaim has nothing clean to
	 * free, and VRAM never drains.  The recursive swap-out path
	 * is safe: gswap_store() rejects at the pool limit check and
	 * falls through to __swap_writepage(), and no gswap locks are
	 * held across that allocation.
	 */
	nofs_flag = memalloc_nofs_save();

	spin_lock(&gswap_lru_lock);
	while (!list_empty(&gswap_lru_list) && nr_writeback < max_writeback) {
		entry = list_last_entry(&gswap_lru_list,
					struct gswap_entry, lru);
		list_del_init(&entry->lru);

		/*
		 * Copy swpentry to the stack while under the LRU lock.
		 * Once we drop the lock, a concurrent gswap_load() can
		 * erase and free the entry at any time. We pass the
		 * stack copy to gswap_writeback_entry() so it can
		 * operate without dereferencing entry until the
		 * xa_cmpxchg validates the pointer.
		 */
		swpentry = entry->swpentry;
		spin_unlock(&gswap_lru_lock);

		ret = gswap_writeback_entry(entry, swpentry);

		if (ret == 0) {
			atomic_long_inc(&gswap_written_back_pages);
			nr_failures = 0;
		} else if (ret == -EAGAIN) {
			/*
			 * Writeback failed before xa_cmpxchg could claim
			 * the entry (folio alloc failure, swap device
			 * gone, or swapin race).  The entry may still be
			 * in the xarray consuming a VRAM slot.
			 *
			 * We cannot safely dereference entry here -- a
			 * concurrent gswap_load() may have freed it.
			 * Hold the xa_lock to prevent concurrent xa_erase
			 * while we validate and re-add to the LRU.
			 */
			tree = swap_gswap_tree(swpentry);
			xa_lock(tree);
			if (xa_load(tree, swp_offset(swpentry)) == entry) {
				spin_lock(&gswap_lru_lock);
				if (list_empty(&entry->lru))
					list_add(&entry->lru,
						 &gswap_lru_list);
				spin_unlock(&gswap_lru_lock);
			}
			xa_unlock(tree);

			if (++nr_failures >= 4) {
				cond_resched();
				nr_writeback++;
				spin_lock(&gswap_lru_lock);
				break;
			}
		}
		nr_writeback++;

		cond_resched();
		spin_lock(&gswap_lru_lock);
	}
	spin_unlock(&gswap_lru_lock);

	memalloc_nofs_restore(nofs_flag);

	/*
	 * If we bailed out due to consecutive failures but there are
	 * still entries to write back, reschedule with a delay to
	 * avoid busy-looping when folio allocation is persistently
	 * failing.  Without this, the worker never re-runs and VRAM
	 * never drains under sustained memory pressure.
	 */
	if (nr_failures >= 4 && !list_empty_careful(&gswap_lru_list))
		queue_delayed_work(gswap_writeback_wq,
				   &gswap_writeback_work,
				   GSWAP_WRITEBACK_RETRY_DELAY);
}

/*
 * gswap_drain_pool() - write back all stored pages to disk.
 *
 * Called during teardown (DRM unregister or module exit) to ensure no
 * pages are lost when the VRAM pool is released. New store operations
 * must already be prevented (gswap_has_pool = false, percpu_ref killed)
 * before calling this.
 */
static void gswap_drain_pool(void)
{
	struct gswap_entry *entry;
	swp_entry_t swpentry;
	unsigned long nr_drained = 0;
	unsigned long nr_orphaned = 0;
	int type;

	spin_lock(&gswap_lru_lock);
	while (!list_empty(&gswap_lru_list)) {
		entry = list_last_entry(&gswap_lru_list,
					struct gswap_entry, lru);
		list_del_init(&entry->lru);

		swpentry = entry->swpentry;
		spin_unlock(&gswap_lru_lock);

		gswap_writeback_entry(entry, swpentry);
		nr_drained++;

		cond_resched();
		spin_lock(&gswap_lru_lock);
	}
	spin_unlock(&gswap_lru_lock);

	/*
	 * Sweep xarrays for orphaned entries.  The writeback worker
	 * removes entries from the LRU before attempting writeback;
	 * if writeback fails (e.g. memory pressure), the entry stays
	 * in the xarray but is no longer on the LRU.  Free them here
	 * to prevent a use-after-free in gswap_free_vram()
	 * after gswap_pool_destroy() releases the buddy bitmaps.
	 */
	for (type = 0; type < MAX_SWAPFILES; type++) {
		struct xarray *trees = gswap_trees[type];
		unsigned int nr, i;
		unsigned long idx;

		if (!trees)
			continue;

		nr = nr_gswap_trees[type];
		for (i = 0; i < nr; i++) {
			xa_for_each(&trees[i], idx, entry) {
				entry = xa_erase(&trees[i], idx);
				if (entry) {
					gswap_entry_free(entry);
					nr_orphaned++;
				}
			}
		}
	}

	if (nr_drained || nr_orphaned)
		pr_info("drained %lu pages, freed %lu orphaned entries\n",
			nr_drained, nr_orphaned);
}

/*********************************
* main API
**********************************/

static bool gswap_store_page(struct page *page)
{
	swp_entry_t page_swpentry = page_swap_entry(page);
	struct gswap_crypto_ctx *ctx;
	struct gswap_entry *entry, *old;
	struct scatterlist input, output;
	unsigned int dlen = PAGE_SIZE;
	long slot;
	int comp_ret;

	entry = gswap_entry_cache_alloc(GFP_KERNEL, page_to_nid(page));
	if (!entry) {
		atomic_long_inc(&gswap_reject_kmemcache_fail);
		return false;
	}

	/* Compress the page */
	ctx = gswap_comp_ctx_get();

	sg_init_table(&input, 1);
	sg_set_page(&input, page, PAGE_SIZE, 0);
	sg_init_one(&output, ctx->buffer, PAGE_SIZE);
	acomp_request_set_params(ctx->req, &input, &output, PAGE_SIZE, dlen);

	comp_ret = crypto_wait_req(crypto_acomp_compress(ctx->req), &ctx->wait);
	dlen = ctx->req->dlen;

	if (comp_ret || !dlen) {
		atomic_long_inc(&gswap_reject_compress_fail);
		goto fail_unlock;
	}

	/* Reject pages that don't compress below page size */
	if (dlen >= PAGE_SIZE) {
		atomic_long_inc(&gswap_reject_compress_poor);
		goto fail_unlock;
	}

	/* Allocate VRAM space for the compressed data */
	slot = gswap_alloc_vram(dlen);
	if (slot < 0) {
		atomic_long_inc(&gswap_reject_alloc_fail);
		goto fail_unlock;
	}

	/* Write compressed data to VRAM */
	gswap_write_to_vram(slot, ctx->buffer, dlen);

	gswap_comp_ctx_put(ctx);

	/* Set up the entry */
	entry->swpentry = page_swpentry;
	entry->vram_offset = slot;
	entry->length = dlen;
	INIT_LIST_HEAD(&entry->lru);

	/* Insert into xarray */
	old = xa_store(swap_gswap_tree(page_swpentry),
		       swp_offset(page_swpentry),
		       entry, GFP_KERNEL);
	if (xa_is_err(old)) {
		atomic_long_inc(&gswap_reject_alloc_fail);
		gswap_free_vram(slot, dlen);
		gswap_entry_cache_free(entry);
		return false;
	}
	if (old)
		gswap_entry_free(old);

	/* Add to LRU */
	spin_lock(&gswap_lru_lock);
	list_add(&entry->lru, &gswap_lru_list);
	spin_unlock(&gswap_lru_lock);

	atomic_long_inc(&gswap_stored_pages);
	atomic_long_inc(&gswap_stores);

	return true;

fail_unlock:
	gswap_comp_ctx_put(ctx);
	gswap_entry_cache_free(entry);
	return false;
}

bool gswap_store(struct folio *folio)
{
	long nr_pages = folio_nr_pages(folio);
	swp_entry_t swp = folio->swap;
	long index;
	int limit;

	VM_WARN_ON_ONCE(!folio_test_locked(folio));
	VM_WARN_ON_ONCE(!folio_test_swapcache(folio));

	if (!gswap_enabled || !gswap_has_pool)
		goto check_old;

	if (!gswap_trees[swp_type(swp)])
		goto check_old;

	if (!percpu_ref_tryget(&gswap_active_ref))
		goto check_old;

	if (iosys_map_is_null(&gswap_pool.maps[0])) {
		percpu_ref_put(&gswap_active_ref);
		goto check_old;
	}

	limit = gswap_check_limits();
	if (limit == 2) {
		percpu_ref_put(&gswap_active_ref);
		goto check_old;
	}

	for (index = 0; index < nr_pages; ++index) {
		struct page *page = folio_page(folio, index);

		if (!gswap_store_page(page)) {
			percpu_ref_put(&gswap_active_ref);
			goto check_old;
		}
	}

	/* Above high watermark -- start draining to make room */
	if (limit == 1 && gswap_writeback_wq)
		mod_delayed_work(gswap_writeback_wq, &gswap_writeback_work, 0);

	percpu_ref_put(&gswap_active_ref);
	return true;

check_old:
	/*
	 * If store fails, invalidate any stale entries at these offsets
	 * to prevent stale data being returned on future loads.
	 */
	if (gswap_has_pool && gswap_trees[swp_type(swp)]) {
		unsigned int type = swp_type(swp);
		pgoff_t offset = swp_offset(swp);
		struct gswap_entry *entry;
		struct xarray *tree;

		for (index = 0; index < nr_pages; ++index) {
			tree = swap_gswap_tree(swp_entry(type, offset + index));
			entry = xa_erase(tree, offset + index);
			if (entry)
				gswap_entry_free(entry);
		}
	}

	if (READ_ONCE(gswap_pool_reached_full) && gswap_writeback_wq)
		mod_delayed_work(gswap_writeback_wq, &gswap_writeback_work, 0);

	return false;
}

/*********************************
* readahead cache
**********************************/

/**
 * gswap_ra_fill() - prefetch compressed data for upcoming offsets
 * @ra: per-CPU readahead cache
 * @type: swap type
 * @offset: current page offset (fills offset+1 .. offset+window)
 *
 * Reads compressed data from VRAM for the next several swap offsets
 * into the readahead buffer. Only entries present in the xarray are
 * cached; gaps are skipped.
 */
static void gswap_ra_fill(struct gswap_ra_cache *ra, int type, pgoff_t offset)
{
	unsigned int window = min_t(unsigned int, ra->window, GSWAP_RA_SIZE);
	unsigned int i;
	u32 buf_off = 0;

	ra->count = 0;

	if (!window)
		return;

	for (i = 0; i < window; i++) {
		pgoff_t ra_offset = offset + 1 + i;
		unsigned int tree_idx = ra_offset >> GSWAP_ADDRESS_SPACE_SHIFT;
		struct xarray *tree;
		struct gswap_entry *gentry;
		unsigned long vram_off;
		u32 length;

		if (tree_idx >= nr_gswap_trees[type])
			break;

		tree = &gswap_trees[type][tree_idx];

		/*
		 * Hold xa_lock while reading entry fields to prevent
		 * concurrent gswap_invalidate/writeback from freeing
		 * the entry between xa_load and field access.
		 */
		xa_lock(tree);
		gentry = xa_load(tree, ra_offset);
		if (!gentry) {
			xa_unlock(tree);
			continue;
		}
		vram_off = gentry->vram_offset;
		length = gentry->length;
		xa_unlock(tree);

		if (buf_off + ALIGN(length, 16) > GSWAP_RA_BUF_SIZE)
			break;

		gswap_read_from_vram(vram_off,
				     ra->buf + buf_off, length);

		ra->entries[ra->count].offset = ra_offset;
		ra->entries[ra->count].swp_type = type;
		ra->entries[ra->count].gentry = gentry;
		ra->entries[ra->count].length = length;
		ra->entries[ra->count].buf_offset = buf_off;

		buf_off += length;
		ra->count++;
	}
}

/**
 * gswap_ra_lookup() - check if a page's compressed data is in the RA cache
 * @ra: per-CPU readahead cache
 * @type: swap type
 * @offset: swap offset to look up
 * @dst: destination buffer for compressed data
 * @lenp: output — compressed data length
 *
 * Validates the cached pointer against the current xarray state to
 * handle races with writeback.
 *
 * Return: true if cache hit (data copied to dst), false on miss.
 */
static bool gswap_ra_lookup(struct gswap_ra_cache *ra, int type,
			     pgoff_t offset, void *dst, u32 *lenp)
{
	int i;

	for (i = 0; i < ra->count; i++) {
		struct gswap_ra_entry *rae = &ra->entries[i];
		struct xarray *tree;

		if (rae->swp_type != type || rae->offset != offset)
			continue;

		/* Validate: entry must still be in xarray (writeback race) */
		tree = &gswap_trees[type][offset >> GSWAP_ADDRESS_SPACE_SHIFT];
		if (xa_load(tree, offset) != rae->gentry)
			return false;

		memcpy(dst, ra->buf + rae->buf_offset, rae->length);
		*lenp = rae->length;
		return true;
	}

	return false;
}

/**
 * gswap_load_page() - decompress a single page from VRAM into the folio
 * @folio: target folio
 * @page_index: page index within the folio
 * @entry: gswap entry containing VRAM location and compressed length
 *
 * Uses the per-CPU readahead cache to avoid redundant VRAM reads for
 * sequential access patterns. On a cache miss, reads from VRAM and
 * prefetches the next several entries.
 *
 * Return: 0 on success, -EIO on decompression failure.
 */
static int gswap_load_page(struct folio *folio, long page_index,
			    struct gswap_entry *entry)
{
	struct gswap_crypto_ctx *ctx;
	struct scatterlist input, output;
	int ret;
	unsigned int dlen;
	u32 cached_len;
	int type = swp_type(entry->swpentry);
	pgoff_t offset = swp_offset(entry->swpentry);

	ctx = gswap_comp_ctx_get();

	if (gswap_ra_size &&
	    gswap_ra_lookup(&ctx->ra, type, offset, ctx->buffer, &cached_len)) {
		atomic_long_inc(&gswap_ra_hits);
		ctx->ra.hits++;
	} else {
		atomic_long_inc(&gswap_ra_misses);
		gswap_read_from_vram(entry->vram_offset, ctx->buffer,
				     entry->length);
		cached_len = entry->length;

		/*
		 * Only fill readahead when the access looks sequential --
		 * random loads would waste PCIe bandwidth reading entries
		 * that are never consumed.
		 */
		if (gswap_ra_size &&
		    offset == ctx->ra.last_offset + 1)
			gswap_ra_fill(&ctx->ra, type, offset);
		else if (gswap_ra_size)
			atomic_long_inc(&gswap_ra_skips);
	}

	ctx->ra.last_offset = offset;

	/*
	 * Adaptive window: every 64 accesses, adjust the window based
	 * on hit rate.  Shrink toward 1 when hits are rare, grow back
	 * toward gswap_ra_size when readahead is effective.
	 */
	if (gswap_ra_size && ++ctx->ra.accesses >= 64) {
		unsigned int max_win = min_t(unsigned int,
					     gswap_ra_size, GSWAP_RA_SIZE);

		if (ctx->ra.hits >= 48)
			ctx->ra.window = max_win;
		else if (ctx->ra.hits >= 32)
			ctx->ra.window = max(max_win / 2, 1U);
		else if (ctx->ra.hits >= 16)
			ctx->ra.window = max(max_win / 4, 1U);
		else
			ctx->ra.window = 1;

		ctx->ra.hits = 0;
		ctx->ra.accesses = 0;
	}

	sg_init_one(&input, ctx->buffer, cached_len);
	sg_init_table(&output, 1);
	sg_set_page(&output, folio_page(folio, page_index), PAGE_SIZE, 0);
	acomp_request_set_params(ctx->req, &input, &output,
				 cached_len, PAGE_SIZE);

	ret = crypto_wait_req(crypto_acomp_decompress(ctx->req), &ctx->wait);
	dlen = ctx->req->dlen;
	gswap_comp_ctx_put(ctx);

	if (ret || dlen != PAGE_SIZE) {
		atomic_long_inc(&gswap_decompress_fail);
		pr_alert_ratelimited(
			"Decompression error from gswap (%d:%lu %s %u->%u)\n",
			type, offset,
			gswap_compressor, cached_len, dlen);
		return -EIO;
	}

	return 0;
}

/**
 * gswap_read_swap_page() - read a single page from the swap device
 * @folio: target folio
 * @page_index: page index within the folio to read into
 * @swp: swap entry identifying the page on the swap device
 *
 * Reads a single page from the underlying swap block device.  Used to
 * fill in pages that the writeback worker already persisted to disk
 * when loading a large folio with partial gswap presence.
 *
 * Return: 0 on success, negative error on failure.
 */
static int gswap_read_swap_page(struct folio *folio, long page_index,
				swp_entry_t swp)
{
	struct swap_info_struct *sis;
	struct bio_vec bv;
	struct bio bio;
	int ret;

	sis = get_swap_device(swp);
	if (!sis)
		return -ENODEV;

	if (sis->flags & SWP_FS_OPS) {
		put_swap_device(sis);
		return -EOPNOTSUPP;
	}

	bio_init(&bio, sis->bdev, &bv, 1, REQ_OP_READ);
	bio.bi_iter.bi_sector = swap_entry_sector(swp);
	__bio_add_page(&bio, folio_page(folio, page_index), PAGE_SIZE, 0);
	ret = submit_bio_wait(&bio);
	bio_uninit(&bio);
	put_swap_device(sis);

	return ret;
}

/**
 * gswap_load() - load a folio from gswap VRAM cache
 * @folio: folio to load
 *
 * For large folios, each page is stored independently by gswap_store().
 * The writeback worker can evict individual pages to disk, creating a
 * partial set.  This function handles partial presence: pages still in
 * gswap are decompressed from VRAM, while pages already written back
 * are read directly from the swap device via bio.
 *
 * Only swapcache folios are handled.  The folio lock prevents
 * concurrent writeback from modifying entries between the presence
 * scan and the erase: writeback's swap_cache_alloc_folio() would
 * find this folio already in the cache and bail out with -EEXIST.
 * Non-swapcache loads (SWP_SYNCHRONOUS_IO) are rejected because
 * the writeback worker could concurrently free entries while we
 * read them.
 *
 * Return: 0 on success (folio unlocked, marked uptodate),
 *         -EIO on decompression/IO failure (folio unlocked, NOT uptodate),
 *         -ENOENT if not found in gswap (folio remains locked).
 */
int gswap_load(struct folio *folio)
{
	swp_entry_t swp = folio->swap;
	pgoff_t offset = swp_offset(swp);
	long nr_pages = folio_nr_pages(folio);
	struct xarray *tree;
	struct gswap_entry *entry;
	long index;
	long nr_present = 0;

	VM_WARN_ON_ONCE(!folio_test_locked(folio));

	if (!gswap_has_pool)
		return -ENOENT;

	/*
	 * Only handle swapcache loads.  For non-swapcache faults
	 * (SWP_SYNCHRONOUS_IO), the folio is not in the swap cache,
	 * so the writeback worker can concurrently xa_cmpxchg and
	 * free entries while we read them — use-after-free.
	 * Swapcache loads are safe because swap cache occupancy
	 * blocks the writeback worker's swap_cache_alloc_folio().
	 */
	if (!folio_test_swapcache(folio))
		return -ENOENT;

	if (!percpu_ref_tryget(&gswap_active_ref))
		return -ENOENT;

	if (!gswap_trees[swp_type(swp)]) {
		percpu_ref_put(&gswap_active_ref);
		return -ENOENT;
	}

	/*
	 * Phase 1: Count pages present in gswap.
	 *
	 * If none are present, return -ENOENT so the caller reads the
	 * entire folio from disk normally.  If some are present, we
	 * proceed to phase 2 where gswap pages are decompressed and
	 * missing pages are read from the swap device.
	 */
	for (index = 0; index < nr_pages; index++) {
		tree = swap_gswap_tree(swp_entry(swp_type(swp),
						  offset + index));
		if (xa_load(tree, offset + index))
			nr_present++;
	}

	if (nr_present == 0) {
		percpu_ref_put(&gswap_active_ref);
		return -ENOENT;
	}

	/*
	 * Phase 2: Load each page.
	 *
	 * Pages present in gswap are decompressed from VRAM.  Pages
	 * evicted by the writeback worker (missing from gswap) have
	 * already been persisted to the swap device, so we read them
	 * back via a synchronous bio.
	 *
	 * Use xa_load (not xa_erase) during decompression so that
	 * entries remain in the xarray.  If any page fails to load,
	 * the entries are still valid and the folio can be retried
	 * without data loss.  Entries are erased and freed only after
	 * all pages are successfully loaded.
	 */
	for (index = 0; index < nr_pages; index++) {
		swp_entry_t page_swp = swp_entry(swp_type(swp),
						  offset + index);

		tree = swap_gswap_tree(page_swp);
		entry = xa_load(tree, offset + index);

		if (entry) {
			if (gswap_load_page(folio, index, entry)) {
				percpu_ref_put(&gswap_active_ref);
				folio_unlock(folio);
				return -EIO;
			}
		} else {
			/*
			 * Page written back to disk -- read it via bio.
			 * This path is only reachable for large folios
			 * with partial gswap presence.
			 */
			if (gswap_read_swap_page(folio, index, page_swp)) {
				percpu_ref_put(&gswap_active_ref);
				folio_unlock(folio);
				return -EIO;
			}
		}
	}

	/*
	 * All pages loaded successfully.  Erase entries and free
	 * VRAM slots to transfer data ownership to the folio.
	 */
	for (index = 0; index < nr_pages; index++) {
		tree = swap_gswap_tree(swp_entry(swp_type(swp),
						  offset + index));
		entry = xa_erase(tree, offset + index);
		if (entry)
			gswap_entry_free(entry);
	}

	folio_mark_uptodate(folio);
	atomic_long_inc(&gswap_loads);
	folio_mark_dirty(folio);

	percpu_ref_put(&gswap_active_ref);
	folio_unlock(folio);
	return 0;
}

void gswap_invalidate(swp_entry_t swp)
{
	pgoff_t offset = swp_offset(swp);
	struct xarray *tree;
	struct gswap_entry *entry;

	if (!gswap_init_done || !gswap_trees[swp_type(swp)])
		return;

	tree = swap_gswap_tree(swp);
	if (xa_empty(tree))
		return;

	entry = xa_erase(tree, offset);
	if (entry)
		gswap_entry_free(entry);
}

int gswap_swapon(int type, unsigned long nr_pages, unsigned long flags)
{
	struct xarray *trees, *tree;
	unsigned int nr, i;

	if (!gswap_has_pool)
		return 0;

	/*
	 * gswap_read_swap_page() uses bio directly and cannot read
	 * from filesystem-backed swap.  Skip registration so partial
	 * writeback on swapfiles doesn't cause permanent load failures.
	 */
	if (flags & SWP_FS_OPS)
		return 0;

	nr = DIV_ROUND_UP(nr_pages, GSWAP_ADDRESS_SPACE_PAGES);
	trees = kvcalloc(nr, sizeof(*tree), GFP_KERNEL);
	if (!trees) {
		pr_err("alloc failed, gswap disabled for swap type %d\n", type);
		return -ENOMEM;
	}

	for (i = 0; i < nr; i++)
		xa_init(trees + i);

	nr_gswap_trees[type] = nr;
	gswap_trees[type] = trees;
	return 0;
}

void gswap_swapoff(int type)
{
	struct xarray *trees = gswap_trees[type];
	unsigned int i;

	if (!trees)
		return;

	for (i = 0; i < nr_gswap_trees[type]; i++)
		WARN_ON_ONCE(!xa_empty(trees + i));

	kvfree(trees);
	nr_gswap_trees[type] = 0;
	gswap_trees[type] = NULL;
}

/*********************************
* VRAM pool setup
**********************************/

/*
 * Set up buddy free bitmaps for @nr_blocks min-size blocks.
 * Marks all space as free, starting from the highest order.
 */
static int gswap_buddy_init(unsigned long nr_blocks)
{
	unsigned long bitmap_bits;
	unsigned long remaining, block_offset;
	int i, order;

	for (i = 0; i < GSWAP_NR_ORDERS; i++) {
		bitmap_bits = nr_blocks >> i;
		if (!bitmap_bits)
			bitmap_bits = 1;
		gswap_pool.free[i] = kvzalloc(
			BITS_TO_LONGS(bitmap_bits) * sizeof(unsigned long),
			GFP_KERNEL);
		if (!gswap_pool.free[i])
			goto err;
	}

	/*
	 * Mark all blocks as free.  Process from highest to lowest
	 * order so that the pool starts fully coalesced.  Works because
	 * the space is contiguous starting at offset 0.
	 */
	remaining = nr_blocks;
	block_offset = 0;
	for (order = GSWAP_NR_ORDERS - 1; order > 0; order--) {
		unsigned long order_blocks = 1UL << order;

		while (remaining >= order_blocks) {
			set_bit(block_offset >> order,
				gswap_pool.free[order]);
			gswap_pool.nr_free[order]++;
			block_offset += order_blocks;
			remaining -= order_blocks;
		}
	}
	while (remaining > 0) {
		set_bit(block_offset, gswap_pool.free[0]);
		gswap_pool.nr_free[0]++;
		block_offset++;
		remaining--;
	}

	return 0;

err:
	for (i--; i >= 0; i--)
		kvfree(gswap_pool.free[i]);
	return -ENOMEM;
}

/*
 * Drain all per-CPU caches back to the global buddy.
 * Called during pool teardown with no concurrent allocators.
 */
static void gswap_pcpu_drain_all(void)
{
	int cpu, order;

	if (!gswap_pcpu_alloc)
		return;

	for_each_possible_cpu(cpu) {
		struct gswap_pcpu_cache *cache = per_cpu_ptr(gswap_pcpu_alloc,
							     cpu);

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
}

static void gswap_buddy_destroy(void)
{
	int i;

	gswap_pcpu_drain_all();
	free_percpu(gswap_pcpu_alloc);
	gswap_pcpu_alloc = NULL;

	for (i = 0; i < GSWAP_NR_ORDERS; i++) {
		kvfree(gswap_pool.free[i]);
		gswap_pool.free[i] = NULL;
	}
}

/*
 * Initialize the pool from a single contiguous mapping.
 * Used by the direct-BAR path and single-buffer DRM allocations.
 */
static int gswap_pool_init(struct iosys_map *map, unsigned long size,
			   unsigned long usable_size)
{
	unsigned long nr_blocks;
	int ret;

	if (!size || size < GSWAP_MIN_ALLOC_SIZE) {
		pr_err("VRAM region too small: %lu bytes\n", size);
		return -EINVAL;
	}

	nr_blocks = size >> GSWAP_MIN_ALLOC_SHIFT;

	gswap_pool.maps[0] = *map;
	gswap_pool.nr_maps = 1;
	gswap_pool.buf_size = size;
	gswap_pool.total_size = size;
	gswap_pool.usable_size = usable_size;
	gswap_pool.nr_blocks = nr_blocks;
	spin_lock_init(&gswap_pool.lock);
	atomic_long_set(&gswap_pool.used_bytes, 0);

	ret = gswap_buddy_init(nr_blocks);
	if (ret)
		return ret;

	gswap_pcpu_alloc = alloc_percpu(struct gswap_pcpu_cache);
	if (!gswap_pcpu_alloc) {
		gswap_buddy_destroy();
		return -ENOMEM;
	}
	{
		int cpu;

		for_each_possible_cpu(cpu)
			local_lock_init(&per_cpu_ptr(gswap_pcpu_alloc, cpu)->lock);
	}

	pr_info("VRAM pool initialized: %lu MB (%lu blocks, %lu-%lu byte allocs)\n",
		size >> 20, nr_blocks,
		GSWAP_MIN_ALLOC_SIZE, GSWAP_MIN_ALLOC_SIZE << (GSWAP_NR_ORDERS - 1));
	pr_info("  usable: %lu MB (%lu%% of total)\n",
		usable_size >> 20, usable_size * 100 / size);

	return 0;
}

/*
 * Initialize the pool from multiple equal-sized mappings.
 * Each map covers buf_size bytes; the buddy spans all of them.
 */
static int gswap_pool_init_multi(struct iosys_map *maps, unsigned int nr_maps,
				 unsigned long buf_size,
				 unsigned long total_size,
				 unsigned long usable_size)
{
	unsigned long nr_blocks;
	unsigned int i;
	int ret;

	if (!total_size || total_size < GSWAP_MIN_ALLOC_SIZE) {
		pr_err("VRAM region too small: %lu bytes\n", total_size);
		return -EINVAL;
	}

	nr_blocks = total_size >> GSWAP_MIN_ALLOC_SHIFT;

	for (i = 0; i < nr_maps; i++)
		gswap_pool.maps[i] = maps[i];
	gswap_pool.nr_maps = nr_maps;
	gswap_pool.buf_size = buf_size;
	gswap_pool.total_size = total_size;
	gswap_pool.usable_size = usable_size;
	gswap_pool.nr_blocks = nr_blocks;
	spin_lock_init(&gswap_pool.lock);
	atomic_long_set(&gswap_pool.used_bytes, 0);

	ret = gswap_buddy_init(nr_blocks);
	if (ret)
		return ret;

	gswap_pcpu_alloc = alloc_percpu(struct gswap_pcpu_cache);
	if (!gswap_pcpu_alloc) {
		gswap_buddy_destroy();
		return -ENOMEM;
	}
	{
		int cpu;

		for_each_possible_cpu(cpu)
			local_lock_init(&per_cpu_ptr(gswap_pcpu_alloc, cpu)->lock);
	}

	pr_info("VRAM pool initialized: %lu MB (%lu blocks, %lu-%lu byte allocs, %u buffers)\n",
		total_size >> 20, nr_blocks,
		GSWAP_MIN_ALLOC_SIZE, GSWAP_MIN_ALLOC_SIZE << (GSWAP_NR_ORDERS - 1),
		nr_maps);
	pr_info("  usable: %lu MB (%lu%% of total)\n",
		usable_size >> 20, usable_size * 100 / total_size);

	return 0;
}

static void gswap_pool_destroy(void)
{
	unsigned int i;

#ifdef CONFIG_DRM
	if (gswap_drm_nr_bufs) {
		for (i = 0; i < gswap_drm_nr_bufs; i++) {
			drm_gem_vunmap(gswap_drm_gems[i],
				       &gswap_pool.maps[i]);
			drm_gem_object_put(gswap_drm_gems[i]);
			gswap_drm_gems[i] = NULL;
		}
		gswap_drm_nr_bufs = 0;
		drm_client_release(&gswap_drm_client);
	} else
#endif
	if (gswap_pool.maps[0].is_iomem && gswap_pool.maps[0].vaddr_iomem) {
		/* Direct BAR path: we own the ioremap */
		iounmap(gswap_pool.maps[0].vaddr_iomem);
	}
	for (i = 0; i < gswap_pool.nr_maps; i++)
		iosys_map_clear(&gswap_pool.maps[i]);
	gswap_pool.nr_maps = 0;
	gswap_buddy_destroy();
}

/*********************************
* GPU/VRAM discovery
**********************************/

/*
 * Scan PCI devices for GPUs with a usable VRAM BAR.
 * We look for VGA-compatible controllers (class 0x0300) or
 * 3D controllers (class 0x0302) and select the largest
 * prefetchable BAR. A warning is emitted if the BAR is < 256MB,
 * which may indicate ReBAR is not enabled.
 *
 * If gswap.device= is set, only that PCI slot is considered.
 * Returns a reference to the best PCI device via *pdev_out
 * (caller must pci_dev_put() when done).
 */
static int gswap_find_gpu_vram(resource_size_t *base, unsigned long *size,
			       struct pci_dev **pdev_out)
{
	struct pci_dev *pdev = NULL, *best_pdev = NULL;
	resource_size_t best_base = 0;
	unsigned long best_size = 0;
	int bar;

	while ((pdev = pci_get_class(PCI_CLASS_DISPLAY_VGA << 8, pdev)) != NULL) {
		if (!gswap_device_matches(pdev))
			continue;
		for (bar = 0; bar < PCI_STD_NUM_BARS; bar++) {
			unsigned long flags = pci_resource_flags(pdev, bar);
			resource_size_t bar_start = pci_resource_start(pdev, bar);
			unsigned long bar_size = pci_resource_len(pdev, bar);

			if (!(flags & IORESOURCE_MEM))
				continue;
			if (flags & IORESOURCE_IO)
				continue;
			/* Look for the largest prefetchable BAR (VRAM) */
			if (!(flags & IORESOURCE_PREFETCH))
				continue;
			if (bar_size > best_size) {
				best_base = bar_start;
				best_size = bar_size;
				if (best_pdev)
					pci_dev_put(best_pdev);
				best_pdev = pci_dev_get(pdev);
			}
		}
	}

	/* Also check 3D controllers (e.g. NVIDIA compute GPUs) */
	pdev = NULL;
	while ((pdev = pci_get_class(PCI_CLASS_DISPLAY_3D << 8, pdev)) != NULL) {
		if (!gswap_device_matches(pdev))
			continue;
		for (bar = 0; bar < PCI_STD_NUM_BARS; bar++) {
			unsigned long flags = pci_resource_flags(pdev, bar);
			resource_size_t bar_start = pci_resource_start(pdev, bar);
			unsigned long bar_size = pci_resource_len(pdev, bar);

			if (!(flags & IORESOURCE_MEM))
				continue;
			if (flags & IORESOURCE_IO)
				continue;
			if (!(flags & IORESOURCE_PREFETCH))
				continue;
			if (bar_size > best_size) {
				best_base = bar_start;
				best_size = bar_size;
				if (best_pdev)
					pci_dev_put(best_pdev);
				best_pdev = pci_dev_get(pdev);
			}
		}
	}

	if (!best_size) {
		pr_info("no GPU with usable VRAM BAR found\n");
		return -ENODEV;
	}

	*base = best_base;
	*size = best_size;
	*pdev_out = best_pdev;

	pr_info("found GPU VRAM BAR: base=%pa size=%lu MB on %s\n",
		&best_base, best_size >> 20, dev_name(&best_pdev->dev));

	if (best_size < (256UL << 20))
		pr_warn("VRAM BAR < 256MB, ReBAR may not be enabled\n");

	return 0;
}

/* Forward declarations for DRM client callbacks */
static int gswap_debugfs_init(void);
static void gswap_debugfs_exit(void);

/*********************************
* DRM client VRAM allocation
*
* When CONFIG_DRM is enabled, gswap allocates VRAM through the GPU
* driver's memory manager (via DRM client dumb buffers) instead of
* directly mapping the PCI BAR. This ensures gswap's VRAM region is
* reserved by the GPU driver's allocator (TTM) and won't be used for
* rendering, preventing data corruption from overlapping VRAM usage.
**********************************/

#ifdef CONFIG_DRM

/* Dumb buffer dimensions for VRAM allocation */
#define GSWAP_DRM_WIDTH		4096
#define GSWAP_DRM_BPP		8	/* bits per pixel */
#define GSWAP_DRM_STRIDE	(GSWAP_DRM_WIDTH * (GSWAP_DRM_BPP / 8))

/*
 * Maximum size per dumb buffer.  drm_mode_create_dumb() checks
 * height * stride <= U32_MAX, so cap each buffer accordingly.
 */
#define GSWAP_DRM_MAX_BUF	((unsigned long)(U32_MAX / GSWAP_DRM_STRIDE) * GSWAP_DRM_STRIDE)

static void gswap_drm_unregister(struct drm_client_dev *client)
{
	/*
	 * GPU driver is unloading -- disable gswap, drain the pool,
	 * and release VRAM back to the GPU driver.
	 */
	gswap_enabled = false;

	/*
	 * Unregister the PCI bus notifier first so a concurrent GPU
	 * driver bind cannot schedule gswap_drm_work and re-enable
	 * gswap_has_pool on dead infrastructure (percpu_ref exited,
	 * workqueue destroyed).
	 */
	bus_unregister_notifier(&pci_bus_type, &gswap_pci_nb);
	cancel_work_sync(&gswap_drm_work);

	if (!gswap_has_pool)
		return;

	gswap_has_pool = false;

	percpu_ref_kill(&gswap_active_ref);
	wait_for_completion(&gswap_active_ref_done);
	percpu_ref_exit(&gswap_active_ref);

	/*
	 * Drain all stored pages back to disk before releasing VRAM.
	 * gswap_store() returns true to swap_writeout() which skips
	 * disk I/O, so the only copy of page data lives in VRAM.
	 * Without a full drain, those pages would be silently lost.
	 */
	gswap_drain_pool();

	if (gswap_writeback_wq) {
		cancel_delayed_work_sync(&gswap_writeback_work);
		destroy_workqueue(gswap_writeback_wq);
		gswap_writeback_wq = NULL;
	}

	/*
	 * Don't call gswap_swapoff() here -- the normal swapoff syscall
	 * path handles xarray cleanup, and calling it from both paths
	 * without serialization would race on gswap_trees[].  The
	 * xarrays were drained above so entries are empty; swapoff
	 * will free the xarray memory when the swap device is removed.
	 */

	gswap_debugfs_exit();
	gswap_pool_destroy();

	pr_info("GPU driver unloaded, VRAM released\n");
}

static const struct drm_client_funcs gswap_drm_funcs = {
	.owner		= THIS_MODULE,
	.unregister	= gswap_drm_unregister,
};

/*
 * Find the DRM device associated with a PCI GPU device by scanning
 * the global drm_minors_xa xarray for a primary minor whose parent
 * device matches the PCI device.
 */
static struct drm_device *gswap_find_drm_for_pci(struct pci_dev *pdev)
{
	unsigned long index;
	struct drm_minor *minor;

	xa_for_each(&drm_minors_xa, index, minor) {
		if (minor->type == DRM_MINOR_PRIMARY &&
		    minor->dev->dev &&
		    minor->dev->dev == &pdev->dev)
			return minor->dev;
	}

	return NULL;
}

static int gswap_drm_alloc_vram(struct pci_dev *pdev)
{
	struct drm_device *drm;
	struct drm_gem_object *gems[GSWAP_MAX_BUFFERS];
	struct iosys_map maps[GSWAP_MAX_BUFFERS];
	unsigned long bar_size, alloc_size, buf_size, remaining;
	unsigned int nr_bufs = 0;
	int ret;

	drm = gswap_find_drm_for_pci(pdev);
	if (!drm)
		return -ENODEV;

	ret = drm_client_init(drm, &gswap_drm_client, "gswap",
			      &gswap_drm_funcs);
	if (ret) {
		pr_err("DRM client init failed: %d\n", ret);
		return ret;
	}

	/*
	 * Allocate a portion of VRAM through the DRM dumb buffer interface.
	 * The GPU driver's memory manager (TTM) reserves this region,
	 * preventing the GPU from using it for rendering.
	 *
	 * Find the largest prefetchable BAR (VRAM) rather than assuming
	 * BAR 0 -- this correctly picks up the full BAR size when ReBAR
	 * is enabled.
	 */
	bar_size = 0;
	for (int i = 0; i < PCI_STD_NUM_BARS; i++) {
		unsigned long flags = pci_resource_flags(pdev, i);
		unsigned long len = pci_resource_len(pdev, i);

		if ((flags & IORESOURCE_MEM) && (flags & IORESOURCE_PREFETCH) &&
		    !(flags & IORESOURCE_IO) && len > bar_size)
			bar_size = len;
	}
	if (!bar_size) {
		pr_err("no prefetchable VRAM BAR found on %s\n",
		       dev_name(&pdev->dev));
		ret = -ENODEV;
		goto fail_client;
	}
	alloc_size = bar_size * gswap_max_pool_percent / 100;
	if (alloc_size < (4UL << 20))
		alloc_size = 4UL << 20;

	/*
	 * drm_mode_create_dumb() uses u32 arithmetic (height * stride),
	 * limiting each buffer to ~4 GB.  Split the allocation across
	 * multiple dumb buffers when needed.
	 */
	buf_size = min(alloc_size, GSWAP_DRM_MAX_BUF);
	/* Align down to minimum allocation granularity */
	buf_size = rounddown(buf_size, GSWAP_MIN_ALLOC_SIZE);

	remaining = alloc_size;
	while (remaining && nr_bufs < GSWAP_MAX_BUFFERS) {
		struct drm_mode_create_dumb dumb_args = {};
		struct drm_gem_object *obj;
		unsigned long chunk = min(remaining, buf_size);
		u32 height;

		height = chunk / GSWAP_DRM_STRIDE;
		if (!height)
			break;
		chunk = (unsigned long)height * GSWAP_DRM_STRIDE;

		dumb_args.width = GSWAP_DRM_WIDTH;
		dumb_args.height = height;
		dumb_args.bpp = GSWAP_DRM_BPP;
		ret = drm_mode_create_dumb(drm, &dumb_args,
					   gswap_drm_client.file);
		if (ret) {
			pr_err("DRM dumb buffer %u creation failed: %d\n",
			       nr_bufs, ret);
			if (!nr_bufs)
				goto fail_client;
			break;
		}

		obj = drm_gem_object_lookup(gswap_drm_client.file,
					    dumb_args.handle);
		drm_mode_destroy_dumb(drm, dumb_args.handle,
				      gswap_drm_client.file);
		if (!obj) {
			pr_err("DRM buffer %u GEM lookup failed\n", nr_bufs);
			if (!nr_bufs) {
				ret = -ENOENT;
				goto fail_client;
			}
			break;
		}

		ret = drm_gem_vmap(obj, &maps[nr_bufs]);
		if (ret) {
			pr_err("DRM buffer %u vmap failed: %d\n", nr_bufs, ret);
			drm_gem_object_put(obj);
			if (!nr_bufs)
				goto fail_client;
			break;
		}

		gems[nr_bufs] = obj;
		nr_bufs++;
		remaining -= chunk;
	}

	alloc_size -= remaining;

	if (nr_bufs == 1) {
		gswap_drm_gems[0] = gems[0];
		gswap_drm_nr_bufs = 1;
		ret = gswap_pool_init(&maps[0], alloc_size, alloc_size);
	} else {
		unsigned int i;

		for (i = 0; i < nr_bufs; i++)
			gswap_drm_gems[i] = gems[i];
		gswap_drm_nr_bufs = nr_bufs;
		ret = gswap_pool_init_multi(maps, nr_bufs, buf_size,
					    alloc_size, alloc_size);
	}
	if (ret)
		goto fail_bufs;

	drm_client_register(&gswap_drm_client);

	pr_info("VRAM allocated via DRM client: %lu MB from %s (BAR: %lu MB, %u buffers)\n",
		alloc_size >> 20, dev_name(drm->dev), bar_size >> 20, nr_bufs);

	if (bar_size < (256UL << 20))
		pr_warn("VRAM BAR < 256MB, ReBAR may not be enabled\n");

	if (bar_size <= (256UL << 20) &&
	    !strstr(saved_command_line, "pci=realloc"))
		pr_warn("VRAM BAR only %lu MB, try pci=realloc"
			" if ReBAR is enabled in BIOS\n",
			bar_size >> 20);

	return 0;

fail_bufs:
	while (nr_bufs--) {
		drm_gem_vunmap(gems[nr_bufs], &maps[nr_bufs]);
		drm_gem_object_put(gems[nr_bufs]);
	}
	gswap_drm_nr_bufs = 0;
fail_client:
	drm_client_release(&gswap_drm_client);
	return ret;
}

/*
 * Deferred VRAM setup: called from a work item when the GPU driver
 * binds after gswap_init has already run.
 */
static void gswap_drm_setup_work_fn(struct work_struct *work)
{
	int ret;

	if (!gswap_gpu_pdev)
		return;

	/* Already DRM-backed -- nothing to do */
	if (gswap_has_pool && gswap_drm_nr_bufs)
		return;

	/*
	 * Transition from direct BAR to DRM: stop stores, drain all
	 * pages to disk, destroy the old pool, then allocate via DRM.
	 */
	if (gswap_has_pool) {
		pr_info("transitioning VRAM pool from direct BAR to DRM\n");
		gswap_has_pool = false;

		percpu_ref_kill(&gswap_active_ref);
		wait_for_completion(&gswap_active_ref_done);

		gswap_drain_pool();
		if (gswap_writeback_wq)
			cancel_delayed_work_sync(&gswap_writeback_work);
		gswap_pool_destroy();

		/* Reinitialize percpu_ref for the new pool */
		percpu_ref_exit(&gswap_active_ref);
		init_completion(&gswap_active_ref_done);
		ret = percpu_ref_init(&gswap_active_ref,
				      gswap_active_ref_release,
				      0, GFP_KERNEL);
		if (ret) {
			pr_err("percpu_ref reinit failed: %d, gswap disabled\n",
			       ret);
			return;
		}
	}

	ret = gswap_drm_alloc_vram(gswap_gpu_pdev);
	if (ret) {
		pr_err("DRM VRAM allocation failed: %d, gswap disabled\n",
		       ret);
		return;
	}

	gswap_has_pool = true;

	pr_info("initialized with compressor=%s buddy_alloc=%lu-%lu bytes (DRM, deferred)\n",
		gswap_compressor,
		GSWAP_MIN_ALLOC_SIZE, GSWAP_MIN_ALLOC_SIZE << (GSWAP_NR_ORDERS - 1));
}

/*
 * PCI bus notifier: watch for GPU PCI devices getting a driver bound.
 * When a VGA or 3D controller gets a driver, try DRM-based VRAM
 * allocation. This handles the case where the GPU driver loads as a
 * module after gswap's late_initcall.
 */
static int gswap_pci_notifier_fn(struct notifier_block *nb,
				 unsigned long action, void *data)
{
	struct device *dev = data;
	struct pci_dev *pdev;

	if (action != BUS_NOTIFY_BOUND_DRIVER)
		return NOTIFY_DONE;

	if (!dev_is_pci(dev))
		return NOTIFY_DONE;

	pdev = to_pci_dev(dev);
	if ((pdev->class >> 8) != PCI_CLASS_DISPLAY_VGA &&
	    (pdev->class >> 8) != PCI_CLASS_DISPLAY_3D)
		return NOTIFY_DONE;

	if (!gswap_device_matches(pdev))
		return NOTIFY_DONE;

	/* Already DRM-backed -- nothing to do */
	if (gswap_has_pool && gswap_drm_nr_bufs)
		return NOTIFY_DONE;

	gswap_gpu_pdev = pdev;
	schedule_work(&gswap_drm_work);

	return NOTIFY_OK;
}

#endif /* CONFIG_DRM */

/*********************************
* debugfs
**********************************/

#ifdef CONFIG_DEBUG_FS
static struct dentry *gswap_debugfs_root;

static int debugfs_get_stored_pages(void *data, u64 *val)
{
	*val = atomic_long_read(&gswap_stored_pages);
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(gswap_stored_pages_fops,
			 debugfs_get_stored_pages, NULL, "%llu\n");

static int debugfs_get_pool_total_size(void *data, u64 *val)
{
	*val = gswap_pool.total_size;
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(gswap_pool_total_fops,
			 debugfs_get_pool_total_size, NULL, "%llu\n");

static int debugfs_get_pool_used(void *data, u64 *val)
{
	*val = atomic_long_read(&gswap_pool.used_bytes);
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(gswap_pool_used_fops,
			 debugfs_get_pool_used, NULL, "%llu\n");

#define GSWAP_DEBUGFS_COUNTER(name)					\
static int debugfs_get_##name(void *data, u64 *val)			\
{									\
	*val = atomic_long_read(&gswap_##name);				\
	return 0;							\
}									\
DEFINE_DEBUGFS_ATTRIBUTE(gswap_##name##_fops,				\
			 debugfs_get_##name, NULL, "%llu\n")

GSWAP_DEBUGFS_COUNTER(stores);
GSWAP_DEBUGFS_COUNTER(loads);
GSWAP_DEBUGFS_COUNTER(reject_compress_fail);
GSWAP_DEBUGFS_COUNTER(reject_compress_poor);
GSWAP_DEBUGFS_COUNTER(reject_alloc_fail);
GSWAP_DEBUGFS_COUNTER(reject_kmemcache_fail);
GSWAP_DEBUGFS_COUNTER(decompress_fail);
GSWAP_DEBUGFS_COUNTER(pool_limit_hit);
GSWAP_DEBUGFS_COUNTER(written_back_pages);
GSWAP_DEBUGFS_COUNTER(ra_hits);
GSWAP_DEBUGFS_COUNTER(ra_misses);
GSWAP_DEBUGFS_COUNTER(ra_skips);

static int gswap_debugfs_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	gswap_debugfs_root = debugfs_create_dir("gswap", NULL);

	debugfs_create_file("stored_pages", 0444,
			    gswap_debugfs_root, NULL, &gswap_stored_pages_fops);
	debugfs_create_file("pool_total_size", 0444,
			    gswap_debugfs_root, NULL, &gswap_pool_total_fops);
	debugfs_create_file("pool_used_size", 0444,
			    gswap_debugfs_root, NULL, &gswap_pool_used_fops);
	debugfs_create_file("stores", 0444,
			    gswap_debugfs_root, NULL, &gswap_stores_fops);
	debugfs_create_file("loads", 0444,
			    gswap_debugfs_root, NULL, &gswap_loads_fops);
	debugfs_create_file("reject_compress_fail", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_reject_compress_fail_fops);
	debugfs_create_file("reject_compress_poor", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_reject_compress_poor_fops);
	debugfs_create_file("reject_alloc_fail", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_reject_alloc_fail_fops);
	debugfs_create_file("reject_kmemcache_fail", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_reject_kmemcache_fail_fops);
	debugfs_create_file("decompress_fail", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_decompress_fail_fops);
	debugfs_create_file("pool_limit_hit", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_pool_limit_hit_fops);
	debugfs_create_file("written_back_pages", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_written_back_pages_fops);
	debugfs_create_file("ra_hits", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_ra_hits_fops);
	debugfs_create_file("ra_misses", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_ra_misses_fops);
	debugfs_create_file("ra_skips", 0444,
			    gswap_debugfs_root, NULL,
			    &gswap_ra_skips_fops);

	return 0;
}

static void gswap_debugfs_exit(void)
{
	debugfs_remove_recursive(gswap_debugfs_root);
}
#else
static int gswap_debugfs_init(void) { return 0; }
static void gswap_debugfs_exit(void) {}
#endif

/*********************************
* module init and exit
**********************************/

/*
 * Try to ioremap a VRAM region directly and initialize the pool.
 * Used for user-specified VRAM addresses and (with CONFIG_DRM disabled)
 * for auto-detected PCI BARs.
 */
static int gswap_pool_init_bar(resource_size_t phys_base, unsigned long size)
{
	struct iosys_map map;
	void __iomem *vaddr;
	int ret;

	vaddr = ioremap_wc(phys_base, size);
	if (!vaddr) {
		pr_err("failed to ioremap VRAM at %pa size %lu\n",
		       &phys_base, size);
		return -ENOMEM;
	}

	iosys_map_set_vaddr_iomem(&map, vaddr);
	ret = gswap_pool_init(&map, size,
			      size * gswap_max_pool_percent / 100);
	if (ret) {
		iounmap(vaddr);
		return ret;
	}

	return 0;
}

static int __init gswap_init(void)
{
	bool pool_ready = false;
	int ret, cpu;

	pr_info("initializing gswap\n");

	/* Create entry cache */
	gswap_entry_cache = KMEM_CACHE(gswap_entry, 0);
	if (!gswap_entry_cache) {
		pr_err("entry cache creation failed\n");
		return -ENOMEM;
	}

	/* Set up per-CPU compression contexts */
	gswap_comp_ctx = alloc_percpu(struct gswap_crypto_ctx);
	if (!gswap_comp_ctx) {
		pr_err("percpu alloc failed\n");
		ret = -ENOMEM;
		goto fail_cache;
	}

	for_each_possible_cpu(cpu)
		mutex_init(&per_cpu_ptr(gswap_comp_ctx, cpu)->mutex);

	/*
	 * Register CPU hotplug callbacks to prepare/destroy compression
	 * contexts as CPUs come online/go offline. This also prepares
	 * contexts for all currently online CPUs via the startup callback.
	 */
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"mm/gswap:online",
				gswap_cpu_comp_prepare,
				gswap_cpu_comp_destroy);
	if (ret < 0) {
		pr_err("CPU hotplug registration failed: %d\n", ret);
		goto fail_percpu;
	}
	gswap_hp_state = ret;

	/* Writeback workqueue */
	gswap_writeback_wq = alloc_workqueue("gswap-writeback",
					     WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!gswap_writeback_wq) {
		ret = -ENOMEM;
		goto fail_hp;
	}
	INIT_DELAYED_WORK(&gswap_writeback_work, gswap_writeback_worker);

	/* Active reference for safe teardown */
	init_completion(&gswap_active_ref_done);
	ret = percpu_ref_init(&gswap_active_ref,
			      gswap_active_ref_release,
			      0, GFP_KERNEL);
	if (ret) {
		pr_err("percpu_ref_init failed: %d\n", ret);
		goto fail_wq;
	}

	if (gswap_debugfs_init())
		pr_warn("debugfs initialization failed\n");

	/*
	 * VRAM pool setup. Three methods are tried in order:
	 *
	 * 1. DRM client (CONFIG_DRM): Allocates VRAM through the GPU
	 *    driver's memory manager, ensuring safe coexistence. A PCI
	 *    bus notifier handles the case where the GPU driver loads
	 *    after gswap.
	 *
	 * 2. User-specified VRAM: Manual vram_base/vram_size params.
	 *    User is responsible for avoiding GPU driver conflicts.
	 *
	 * 3. Direct BAR scan (!CONFIG_DRM only): Auto-detects the GPU
	 *    VRAM BAR and maps it directly. WARNING: this does not
	 *    coordinate with the GPU driver and may cause data
	 *    corruption if both write to the same VRAM regions.
	 */

#ifdef CONFIG_DRM
	/* Method 1: DRM client -- safe coexistence with GPU driver */
	{
		resource_size_t bar_base;
		unsigned long bar_size;
		struct pci_dev *pdev = NULL;

		INIT_WORK(&gswap_drm_work, gswap_drm_setup_work_fn);

		ret = gswap_find_gpu_vram(&bar_base, &bar_size, &pdev);
		if (ret == 0 && pdev) {
			gswap_gpu_pdev = pdev;
			ret = gswap_drm_alloc_vram(pdev);
			if (ret == 0) {
				pool_ready = true;
			} else {
				/*
				 * GPU found but DRM not ready yet
				 * (driver may load later as module).
				 * Register bus notifier for deferred
				 * setup.
				 */
				gswap_pci_nb.notifier_call =
					gswap_pci_notifier_fn;
				bus_register_notifier(&pci_bus_type,
						      &gswap_pci_nb);
				pr_info("GPU found, waiting for DRM driver\n");
			}
			pci_dev_put(pdev);
		}
	}
#endif

	/* Method 2: User-specified VRAM address */
	if (!pool_ready && gswap_vram_base && gswap_vram_size) {
		ret = gswap_pool_init_bar(gswap_vram_base, gswap_vram_size);
		if (ret == 0) {
			pool_ready = true;
			pr_info("using user-specified VRAM: base=0x%lx size=%lu MB\n",
				gswap_vram_base, gswap_vram_size >> 20);
		}
	}

#ifndef CONFIG_DRM
	/* Method 3: Direct BAR scan (no GPU driver coordination!) */
	if (!pool_ready) {
		resource_size_t vram_base;
		unsigned long vram_size;
		struct pci_dev *pdev = NULL;

		ret = gswap_find_gpu_vram(&vram_base, &vram_size, &pdev);
		if (ret == 0) {
			pr_warn("using direct BAR mapping without GPU driver coordination\n");
			pr_warn("enable CONFIG_DRM for safe coexistence\n");
			ret = gswap_pool_init_bar(vram_base, vram_size);
			if (ret == 0)
				pool_ready = true;
			pci_dev_put(pdev);
		}
	}
#endif

	gswap_init_done = true;

	if (pool_ready) {
		gswap_has_pool = true;
		pr_info("initialized with compressor=%s buddy_alloc=%lu-%lu bytes\n",
			gswap_compressor,
			GSWAP_MIN_ALLOC_SIZE,
			GSWAP_MIN_ALLOC_SIZE << (GSWAP_NR_ORDERS - 1));
	} else {
		pr_info("no VRAM pool yet, gswap inactive\n");
	}

	return 0;

fail_wq:
	destroy_workqueue(gswap_writeback_wq);
	gswap_writeback_wq = NULL;
fail_hp:
	cpuhp_remove_state(gswap_hp_state);
fail_percpu:
	free_percpu(gswap_comp_ctx);
	gswap_comp_ctx = NULL;
fail_cache:
	kmem_cache_destroy(gswap_entry_cache);
	gswap_entry_cache = NULL;
	return ret;
}

late_initcall(gswap_init);
