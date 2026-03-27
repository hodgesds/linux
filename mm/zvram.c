// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * zvram.c - GPU VRAM-backed zpool driver
 *
 * zvram is a zpool backend that stores compressed swap pages in GPU VRAM
 * instead of system RAM.  When configured as zswap's zpool backend
 * (zswap.zpool=zvram), compressed pages are stored in VRAM over PCIe,
 * freeing system RAM while providing ~2-5us latency -- roughly 200x
 * faster than NVMe for random 4K access.
 *
 * Architecture:
 *   Page reclaim -> zswap (compress + store in VRAM) -> disk swap
 *
 * All compression, entry tracking, LRU management, and writeback are
 * handled by zswap.  zvram only provides the storage backend:
 *   - Buddy allocator for variable-size VRAM blocks (256B - 4KB)
 *   - VRAM I/O via iosys_map (portable iomem/system memory)
 *   - GPU PCI BAR discovery and DRM client VRAM allocation
 *
 * Multi-GPU support:
 *   zvram discovers all matching GPUs and allocates VRAM from each.
 *   Allocations prefer the GPU closest to the current CPU's NUMA node
 *   for lowest PCIe latency.  When the local GPU is full, allocations
 *   fall back to remote GPUs.  The GPU index is encoded in the handle.
 *
 * When CONFIG_DRM is enabled, VRAM is allocated through the GPU driver's
 * memory manager (via DRM client dumb buffers), ensuring safe coexistence.
 * Otherwise, VRAM is mapped directly from the PCI BAR.
 *
 * Copyright (C) 2026
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/io.h>
#include <linux/bitmap.h>
#include <linux/pci.h>
#include <linux/iosys-map.h>
#include <linux/local_lock.h>
#include <linux/rcupdate.h>
#include <linux/topology.h>
#include <linux/zpool.h>
#include <linux/debugfs.h>

#ifdef CONFIG_DRM
#include <drm/drm_drv.h>
#include <drm/drm_client.h>
#include <drm/drm_dumb_buffers.h>
#include <drm/drm_file.h>
#include <drm/drm_gem.h>
#include <drm/drm_cache.h>
#endif

/*********************************
* configuration
**********************************/

/*
 * Buddy allocator for VRAM.  Variable-size allocations let us accept
 * pages that compress to anything < PAGE_SIZE instead of rejecting
 * everything above a fixed slot.
 *
 * Order 0 = 256 bytes, order 4 = 4096 bytes (PAGE_SIZE).
 */
#define ZVRAM_MIN_ALLOC_SHIFT	8
#define ZVRAM_MIN_ALLOC_SIZE	(1UL << ZVRAM_MIN_ALLOC_SHIFT)
#define ZVRAM_NR_ORDERS		5	/* 256, 512, 1024, 2048, 4096 */

#define ZVRAM_MAX_GPUS		8
#define ZVRAM_GPU_IDX_BITS	3	/* log2(ZVRAM_MAX_GPUS) */
#define ZVRAM_GPU_IDX_SHIFT	(BITS_PER_LONG - ZVRAM_GPU_IDX_BITS)
#define ZVRAM_GPU_IDX_MASK	((1UL << ZVRAM_GPU_IDX_BITS) - 1)

/*********************************
* tunables
**********************************/

/* Maximum percentage of VRAM to use */
static unsigned int zvram_max_pool_percent = 50;
module_param_named(max_pool_percent, zvram_max_pool_percent, uint, 0644);
MODULE_PARM_DESC(max_pool_percent, "Max percentage of VRAM to use for swap");

/* VRAM BAR physical address and size -- set by user or auto-detected */
static unsigned long zvram_vram_base;
module_param_named(vram_base, zvram_vram_base, ulong, 0444);
MODULE_PARM_DESC(vram_base, "VRAM BAR physical base address");

static unsigned long zvram_vram_size;
module_param_named(vram_size, zvram_vram_size, ulong, 0444);
MODULE_PARM_DESC(vram_size, "VRAM BAR size in bytes");

/* Target a specific GPU by PCI slot (e.g. "0000:12:00.0") */
static char *zvram_device;
module_param_named(device, zvram_device, charp, 0444);
MODULE_PARM_DESC(device, "PCI slot of GPU to use (e.g. 0000:12:00.0)");

/*********************************
* data structures
**********************************/

/*
 * VRAM may be split across multiple DRM dumb buffers because the DRM
 * dumb-buffer interface uses u32 size arithmetic, limiting each buffer
 * to ~4 GB.  The maps[] array holds one iosys_map per buffer; byte
 * offsets span all buffers contiguously.
 */
#define ZVRAM_MAX_BUFFERS	16

/*
 * Per-CPU block cache to avoid global lock contention on the buddy
 * allocator hot path.
 */
#define ZVRAM_PCPU_BATCH	16	/* blocks per order per CPU */

struct zvram_pcpu_cache {
	local_lock_t	lock;
	unsigned long	blocks[ZVRAM_NR_ORDERS][ZVRAM_PCPU_BATCH];
	unsigned int	count[ZVRAM_NR_ORDERS];
};

/*
 * struct zvram_gpu - all state for one GPU's VRAM pool
 *
 * Uses a buddy allocator with power-of-2 block sizes from 256 bytes
 * (order 0) to 4096 bytes (order 4).
 */
struct zvram_gpu {
	struct iosys_map	maps[ZVRAM_MAX_BUFFERS];
	unsigned int		nr_maps;
	unsigned long		buf_size;	/* size per buffer */
	unsigned long		total_size;	/* total VRAM region size */
	unsigned long		nr_blocks;	/* total min-size blocks */
	unsigned long		*free[ZVRAM_NR_ORDERS]; /* buddy free bitmaps */
	unsigned long		nr_free[ZVRAM_NR_ORDERS]; /* free block count */
	unsigned long		hint[ZVRAM_NR_ORDERS];  /* bitmap scan start */
	spinlock_t		lock;		/* protects free bitmaps + hints */
	atomic_long_t		used_bytes;	/* bytes allocated */

	struct zvram_pcpu_cache __percpu *pcpu_alloc;

#ifdef CONFIG_DRM
	struct drm_client_dev	drm_client;
	struct drm_gem_object	*drm_gems[ZVRAM_MAX_BUFFERS];
	unsigned int		drm_nr_bufs;
	struct pci_dev		*pdev;		/* ref-counted */
	struct work_struct	drm_work;	/* deferred DRM setup */
#endif
	bool			ready;
	int			gpu_idx;	/* index in zvram_gpus[] */
	int			numa_node;

#ifdef CONFIG_DEBUG_FS
	struct dentry		*debugfs_dir;
#endif
};

/*
 * Handle encoding: we pack a GPU index, VRAM block index, and the
 * compressed length into a single unsigned long handle.
 *
 * Layout (MSB to LSB):
 *   [gpu_idx : 3 bits] [block_index : variable] [len : 13 bits]
 *
 * block_index = byte_offset / ZVRAM_MIN_ALLOC_SIZE, avoiding overflow
 * on 32-bit systems.  On 64-bit this gives 48 bits of block index
 * (~64 PB addressable).  On 32-bit: 16 bits (~16 MB per GPU).
 */
#define ZVRAM_HANDLE_LEN_BITS	13
#define ZVRAM_HANDLE_LEN_MASK	((1UL << ZVRAM_HANDLE_LEN_BITS) - 1)

static inline unsigned long zvram_make_handle(int gpu_idx,
					      unsigned long offset,
					      size_t len)
{
	unsigned long idx = offset >> ZVRAM_MIN_ALLOC_SHIFT;

	return ((unsigned long)gpu_idx << ZVRAM_GPU_IDX_SHIFT) |
		(idx << ZVRAM_HANDLE_LEN_BITS) |
		(len & ZVRAM_HANDLE_LEN_MASK);
}

static inline int zvram_handle_gpu(unsigned long handle)
{
	return (int)((handle >> ZVRAM_GPU_IDX_SHIFT) & ZVRAM_GPU_IDX_MASK);
}

static inline unsigned long zvram_handle_offset(unsigned long handle)
{
	unsigned long mask = (1UL << ZVRAM_GPU_IDX_SHIFT) - 1;

	return ((handle & mask) >> ZVRAM_HANDLE_LEN_BITS)
		<< ZVRAM_MIN_ALLOC_SHIFT;
}

static inline unsigned int zvram_handle_len(unsigned long handle)
{
	return handle & ZVRAM_HANDLE_LEN_MASK;
}

/*
 * Per-CPU map buffer: used to stage data between kernel memory and VRAM
 * during zpool map/unmap operations.  Avoids per-map allocation.
 */
struct zvram_map_ctx {
	local_lock_t	lock;
	u8		*buffer;	/* PAGE_SIZE staging buffer */
	unsigned long	mapped_handle;	/* currently mapped handle, or 0 */
	enum zpool_mapmode mapmode;
	struct zvram_gpu *gpu;		/* GPU for current mapping */
};

static struct zvram_map_ctx __percpu *zvram_map_ctx;

/*
 * Global GPU registry.
 */
static struct zvram_gpu		*zvram_gpus[ZVRAM_MAX_GPUS];
static unsigned int		zvram_nr_gpus;
static DEFINE_MUTEX(zvram_gpu_mutex);	/* protects gpus[] and nr_gpus */

/* Per-NUMA-node preferred GPU index (-1 = no preferred GPU) */
static int zvram_pref_gpu[MAX_NUMNODES] __read_mostly;

#ifdef CONFIG_DRM
static struct notifier_block zvram_pci_nb;
static bool zvram_pci_nb_registered;
#endif

/* Non-NULL token returned by zvram_zpool_create for the zpool API */
static int zvram_pool_token;

/*********************************
* helpers
**********************************/

static bool zvram_device_matches(struct pci_dev *pdev)
{
	if (!zvram_device || !*zvram_device)
		return true;
	return !strcmp(dev_name(&pdev->dev), zvram_device);
}

/*
 * Rebuild the per-NUMA-node preferred GPU map.  Called under
 * zvram_gpu_mutex whenever GPUs are added or removed.
 */
static void zvram_rebuild_pref_map(void)
{
	int node, i;

	for (node = 0; node < MAX_NUMNODES; node++) {
		int best = -1, best_dist = INT_MAX;

		for (i = 0; i < zvram_nr_gpus; i++) {
			struct zvram_gpu *gpu = zvram_gpus[i];
			int dist;

			if (!gpu || !READ_ONCE(gpu->ready))
				continue;
			dist = node_distance(node, gpu->numa_node);
			if (dist < best_dist) {
				best_dist = dist;
				best = i;
			}
		}
		WRITE_ONCE(zvram_pref_gpu[node], best);
	}
}

/*********************************
* VRAM buddy allocator
**********************************/

static unsigned int zvram_size_to_order(unsigned int size)
{
	if (size <= ZVRAM_MIN_ALLOC_SIZE)
		return 0;
	return order_base_2(size) - ZVRAM_MIN_ALLOC_SHIFT;
}

/*
 * Allocate a single block at @order from the buddy.
 * Caller must hold gpu->lock.
 */
static long __buddy_alloc_one(struct zvram_gpu *gpu, unsigned int order)
{
	unsigned int cur;
	unsigned long block_idx, nr_at_order;

	for (cur = order; cur < ZVRAM_NR_ORDERS; cur++) {
		unsigned long hint;

		if (!gpu->nr_free[cur])
			continue;

		nr_at_order = gpu->nr_blocks >> cur;
		hint = gpu->hint[cur];
		if (hint >= nr_at_order)
			hint = 0;

		block_idx = find_next_bit(gpu->free[cur], nr_at_order,
					  hint);
		if (block_idx < nr_at_order)
			goto found;

		if (hint) {
			block_idx = find_first_bit(gpu->free[cur], hint);
			if (block_idx < hint)
				goto found;
		}
	}

	return -1;

found:
	clear_bit(block_idx, gpu->free[cur]);
	gpu->nr_free[cur]--;
	gpu->hint[cur] = block_idx + 1;

	while (cur > order) {
		cur--;
		set_bit(block_idx * 2 + 1, gpu->free[cur]);
		gpu->nr_free[cur]++;
		block_idx *= 2;
	}

	return (long)block_idx;
}

/*
 * Return a single block at @order to the buddy with merging.
 * Caller must hold gpu->lock.
 */
static void __buddy_free_one(struct zvram_gpu *gpu,
			     unsigned long block_idx, unsigned int order)
{
	unsigned long buddy_idx;

	while (order < ZVRAM_NR_ORDERS - 1) {
		buddy_idx = block_idx ^ 1;

		if (buddy_idx >= (gpu->nr_blocks >> order) ||
		    !test_bit(buddy_idx, gpu->free[order]))
			break;

		clear_bit(buddy_idx, gpu->free[order]);
		gpu->nr_free[order]--;
		block_idx >>= 1;
		order++;
	}

	set_bit(block_idx, gpu->free[order]);
	gpu->nr_free[order]++;

	if (block_idx < gpu->hint[order])
		gpu->hint[order] = block_idx;
}

static void zvram_pcpu_refill(struct zvram_gpu *gpu,
			      struct zvram_pcpu_cache *cache,
			      unsigned int order)
{
	int i;

	spin_lock(&gpu->lock);
	for (i = 0; i < ZVRAM_PCPU_BATCH / 2; i++) {
		long idx = __buddy_alloc_one(gpu, order);

		if (idx < 0)
			break;
		cache->blocks[order][cache->count[order]++] = idx;
	}
	spin_unlock(&gpu->lock);
}

static void zvram_pcpu_flush(struct zvram_gpu *gpu,
			     struct zvram_pcpu_cache *cache,
			     unsigned int order)
{
	unsigned int nr_flush = cache->count[order] / 2;
	unsigned int i;

	spin_lock(&gpu->lock);
	for (i = 0; i < nr_flush; i++) {
		cache->count[order]--;
		__buddy_free_one(gpu,
				 cache->blocks[order][cache->count[order]],
				 order);
	}
	spin_unlock(&gpu->lock);
}

static long zvram_buddy_alloc(struct zvram_gpu *gpu, unsigned int order)
{
	struct zvram_pcpu_cache *cache;
	long block_idx;

	local_lock(&gpu->pcpu_alloc->lock);
	cache = this_cpu_ptr(gpu->pcpu_alloc);

	if (likely(cache->count[order])) {
		block_idx = cache->blocks[order][--cache->count[order]];
		local_unlock(&gpu->pcpu_alloc->lock);
		atomic_long_add(ZVRAM_MIN_ALLOC_SIZE << order,
				&gpu->used_bytes);
		return block_idx << (ZVRAM_MIN_ALLOC_SHIFT + order);
	}

	zvram_pcpu_refill(gpu, cache, order);

	if (likely(cache->count[order])) {
		block_idx = cache->blocks[order][--cache->count[order]];
		local_unlock(&gpu->pcpu_alloc->lock);
		atomic_long_add(ZVRAM_MIN_ALLOC_SIZE << order,
				&gpu->used_bytes);
		return block_idx << (ZVRAM_MIN_ALLOC_SHIFT + order);
	}

	local_unlock(&gpu->pcpu_alloc->lock);
	return -ENOMEM;
}

static void zvram_buddy_free(struct zvram_gpu *gpu,
			     unsigned long offset, unsigned int order)
{
	struct zvram_pcpu_cache *cache;
	unsigned long block_idx = offset >> (ZVRAM_MIN_ALLOC_SHIFT + order);

	local_lock(&gpu->pcpu_alloc->lock);
	cache = this_cpu_ptr(gpu->pcpu_alloc);

	if (likely(cache->count[order] < ZVRAM_PCPU_BATCH)) {
		cache->blocks[order][cache->count[order]++] = block_idx;
		local_unlock(&gpu->pcpu_alloc->lock);
		return;
	}

	/* Cache full — flush half, then add */
	zvram_pcpu_flush(gpu, cache, order);
	cache->blocks[order][cache->count[order]++] = block_idx;
	local_unlock(&gpu->pcpu_alloc->lock);
}

/*********************************
* VRAM I/O helpers
**********************************/

static void zvram_vram_location(struct zvram_gpu *gpu,
				unsigned long offset,
				unsigned int *buf_idx,
				unsigned long *buf_offset)
{
	*buf_idx    = offset / gpu->buf_size;
	*buf_offset = offset % gpu->buf_size;
}

static void zvram_write_to_vram(struct zvram_gpu *gpu,
				unsigned long vram_off,
				const void *src, unsigned int len)
{
	unsigned int buf_idx;
	unsigned long buf_off;

	zvram_vram_location(gpu, vram_off, &buf_idx, &buf_off);
	iosys_map_memcpy_to(&gpu->maps[buf_idx], buf_off, src, len);
	wmb();
}

static void zvram_read_from_vram(struct zvram_gpu *gpu,
				 unsigned long vram_off,
				 void *dst, unsigned int len)
{
	unsigned int buf_idx;
	unsigned long buf_off;

	zvram_vram_location(gpu, vram_off, &buf_idx, &buf_off);

#ifdef CONFIG_DRM
	{
		struct iosys_map src, dst_map = IOSYS_MAP_INIT_VADDR(dst);

		src = gpu->maps[buf_idx];
		iosys_map_incr(&src, buf_off);
		drm_memcpy_from_wc(&dst_map, &src, ALIGN(len, 16));
	}
#else
	iosys_map_memcpy_from(dst, &gpu->maps[buf_idx], buf_off, len);
#endif
}

/*********************************
* NUMA-aware GPU selection
**********************************/

/*
 * Select a GPU and allocate from it, preferring the GPU closest to the
 * current CPU's NUMA node.  Falls back to remote GPUs if the local one
 * is full or unavailable.
 *
 * Returns the GPU on success (with *offset_out set), or NULL on failure.
 */
static struct zvram_gpu *zvram_alloc_numa(unsigned int order,
					  long *offset_out)
{
	int node = numa_node_id();
	int pref, i;
	struct zvram_gpu *gpu;
	long offset;

	/* Fast path: try preferred (nearest) GPU */
	pref = READ_ONCE(zvram_pref_gpu[node]);
	if (pref >= 0) {
		gpu = zvram_gpus[pref];
		if (gpu && READ_ONCE(gpu->ready)) {
			offset = zvram_buddy_alloc(gpu, order);
			if (offset >= 0) {
				*offset_out = offset;
				return gpu;
			}
		}
	}

	/* Slow path: try all other GPUs */
	for (i = 0; i < zvram_nr_gpus; i++) {
		if (i == pref)
			continue;
		gpu = zvram_gpus[i];
		if (!gpu || !READ_ONCE(gpu->ready))
			continue;
		offset = zvram_buddy_alloc(gpu, order);
		if (offset >= 0) {
			*offset_out = offset;
			return gpu;
		}
	}

	return NULL;
}

/*********************************
* zpool operations
**********************************/

static void *zvram_zpool_create(const char *name, gfp_t gfp)
{
	unsigned int i;

	/* Succeed if any GPU is ready */
	for (i = 0; i < zvram_nr_gpus; i++)
		if (zvram_gpus[i] && smp_load_acquire(&zvram_gpus[i]->ready))
			return &zvram_pool_token;
	return NULL;
}

static void zvram_zpool_destroy(void *pool)
{
	/* GPU lifecycle is managed by module init/exit and DRM callbacks */
}

static int zvram_zpool_malloc(void *pool, size_t size, gfp_t gfp,
			      unsigned long *handle)
{
	struct zvram_gpu *gpu;
	unsigned int order;
	long offset;

	if (size > PAGE_SIZE || size == 0)
		return -EINVAL;

	order = zvram_size_to_order(size);
	if (order >= ZVRAM_NR_ORDERS)
		return -EINVAL;

	rcu_read_lock();
	gpu = zvram_alloc_numa(order, &offset);
	rcu_read_unlock();

	if (!gpu)
		return -ENOMEM;

	*handle = zvram_make_handle(gpu->gpu_idx, offset, size);
	return 0;
}

static void zvram_zpool_free(void *pool, unsigned long handle)
{
	int gpu_idx = zvram_handle_gpu(handle);
	unsigned long offset = zvram_handle_offset(handle);
	unsigned int len = zvram_handle_len(handle);
	unsigned int order = zvram_size_to_order(len);
	struct zvram_gpu *gpu;

	rcu_read_lock();
	if (gpu_idx >= zvram_nr_gpus)
		goto out;
	gpu = zvram_gpus[gpu_idx];
	if (unlikely(!gpu || !READ_ONCE(gpu->ready)))
		goto out;
	zvram_buddy_free(gpu, offset, order);
	atomic_long_sub(ZVRAM_MIN_ALLOC_SIZE << order, &gpu->used_bytes);
out:
	rcu_read_unlock();
}

/*
 * Map a handle for reading or writing.  Since VRAM is iomem and cannot
 * be accessed directly by the zswap compress/decompress code (which uses
 * memcpy), we use a per-CPU staging buffer.
 *
 * For MM_RO: copy data from VRAM into the staging buffer.
 * For MM_WO: return the staging buffer (caller writes, we flush on unmap).
 * For MM_RW: copy from VRAM, caller modifies, we flush on unmap.
 *
 * sleep_mapped is false because local_lock disables preemption.
 * zswap will copy from the staging buffer before unmapping.
 */
static void *zvram_zpool_map(void *pool, unsigned long handle,
			     enum zpool_mapmode mm)
{
	int gpu_idx = zvram_handle_gpu(handle);
	unsigned long offset = zvram_handle_offset(handle);
	unsigned int len = zvram_handle_len(handle);
	struct zvram_gpu *gpu = NULL;
	struct zvram_map_ctx *ctx;

	if (gpu_idx < zvram_nr_gpus)
		gpu = zvram_gpus[gpu_idx];

	rcu_read_lock();
	local_lock(&zvram_map_ctx->lock);
	ctx = this_cpu_ptr(zvram_map_ctx);
	ctx->mapped_handle = handle;
	ctx->mapmode = mm;
	ctx->gpu = gpu;

	if (gpu && likely(READ_ONCE(gpu->ready))) {
		if (mm == ZPOOL_MM_RO || mm == ZPOOL_MM_RW)
			zvram_read_from_vram(gpu, offset, ctx->buffer, len);
	}

	return ctx->buffer;
}

static void zvram_zpool_unmap(void *pool, unsigned long handle)
{
	struct zvram_map_ctx *ctx = this_cpu_ptr(zvram_map_ctx);
	unsigned long offset = zvram_handle_offset(handle);
	unsigned int len = zvram_handle_len(handle);
	struct zvram_gpu *gpu = ctx->gpu;

	if (gpu && likely(READ_ONCE(gpu->ready))) {
		if (ctx->mapmode == ZPOOL_MM_WO || ctx->mapmode == ZPOOL_MM_RW)
			zvram_write_to_vram(gpu, offset, ctx->buffer, len);
	}

	ctx->mapped_handle = 0;
	ctx->gpu = NULL;
	local_unlock(&zvram_map_ctx->lock);
	rcu_read_unlock();
}

static u64 zvram_zpool_total_size(void *pool)
{
	u64 total = 0;
	unsigned int i;

	for (i = 0; i < zvram_nr_gpus; i++) {
		struct zvram_gpu *gpu = zvram_gpus[i];

		if (gpu)
			total += atomic_long_read(&gpu->used_bytes);
	}
	return total;
}

static struct zpool_driver zvram_zpool_driver = {
	.type =			"zvram",
	.owner =		THIS_MODULE,
	.create =		zvram_zpool_create,
	.destroy =		zvram_zpool_destroy,
	.malloc =		zvram_zpool_malloc,
	.free =			zvram_zpool_free,
	.map =			zvram_zpool_map,
	.unmap =		zvram_zpool_unmap,
	.total_size =		zvram_zpool_total_size,
	.sleep_mapped =		false,
};

/*********************************
* VRAM pool setup
**********************************/

static int zvram_buddy_init(struct zvram_gpu *gpu, unsigned long nr_blocks)
{
	unsigned long bitmap_bits, remaining, block_offset;
	int i, order;

	for (i = 0; i < ZVRAM_NR_ORDERS; i++) {
		bitmap_bits = nr_blocks >> i;
		if (!bitmap_bits)
			bitmap_bits = 1;
		gpu->free[i] = kvzalloc(
			BITS_TO_LONGS(bitmap_bits) * sizeof(unsigned long),
			GFP_KERNEL);
		if (!gpu->free[i])
			goto err;
	}

	remaining = nr_blocks;
	block_offset = 0;
	for (order = ZVRAM_NR_ORDERS - 1; order > 0; order--) {
		unsigned long order_blocks = 1UL << order;

		while (remaining >= order_blocks) {
			set_bit(block_offset >> order,
				gpu->free[order]);
			gpu->nr_free[order]++;
			block_offset += order_blocks;
			remaining -= order_blocks;
		}
	}
	while (remaining > 0) {
		set_bit(block_offset, gpu->free[0]);
		gpu->nr_free[0]++;
		block_offset++;
		remaining--;
	}

	return 0;

err:
	for (i--; i >= 0; i--)
		kvfree(gpu->free[i]);
	return -ENOMEM;
}

static void zvram_pcpu_drain_all(struct zvram_gpu *gpu)
{
	int cpu, order;

	if (!gpu->pcpu_alloc)
		return;

	for_each_possible_cpu(cpu) {
		struct zvram_pcpu_cache *cache = per_cpu_ptr(gpu->pcpu_alloc,
							     cpu);

		spin_lock(&gpu->lock);
		for (order = 0; order < ZVRAM_NR_ORDERS; order++) {
			while (cache->count[order]) {
				cache->count[order]--;
				__buddy_free_one(gpu,
					cache->blocks[order][cache->count[order]],
					order);
			}
		}
		spin_unlock(&gpu->lock);
	}
}

static void zvram_buddy_destroy(struct zvram_gpu *gpu)
{
	int i;

	zvram_pcpu_drain_all(gpu);
	free_percpu(gpu->pcpu_alloc);
	gpu->pcpu_alloc = NULL;

	for (i = 0; i < ZVRAM_NR_ORDERS; i++) {
		kvfree(gpu->free[i]);
		gpu->free[i] = NULL;
	}
}

static int zvram_gpu_init_pool(struct zvram_gpu *gpu,
			       struct iosys_map *maps, unsigned int nr_maps,
			       unsigned long buf_size,
			       unsigned long total_size)
{
	unsigned long nr_blocks;
	unsigned int i;
	int cpu, ret;

	if (!total_size || total_size < ZVRAM_MIN_ALLOC_SIZE) {
		pr_err("GPU %d: VRAM region too small: %lu bytes\n",
		       gpu->gpu_idx, total_size);
		return -EINVAL;
	}

	nr_blocks = total_size >> ZVRAM_MIN_ALLOC_SHIFT;

	for (i = 0; i < nr_maps; i++)
		gpu->maps[i] = maps[i];
	gpu->nr_maps = nr_maps;
	gpu->buf_size = buf_size;
	gpu->total_size = total_size;
	gpu->nr_blocks = nr_blocks;
	spin_lock_init(&gpu->lock);
	atomic_long_set(&gpu->used_bytes, 0);

	ret = zvram_buddy_init(gpu, nr_blocks);
	if (ret)
		return ret;

	gpu->pcpu_alloc = alloc_percpu(struct zvram_pcpu_cache);
	if (!gpu->pcpu_alloc) {
		zvram_buddy_destroy(gpu);
		return -ENOMEM;
	}

	for_each_possible_cpu(cpu)
		local_lock_init(&per_cpu_ptr(gpu->pcpu_alloc, cpu)->lock);

	pr_info("GPU %d: VRAM pool %lu MB (%lu blocks, %u buffers)\n",
		gpu->gpu_idx, total_size >> 20, nr_blocks, nr_maps);

	return 0;
}

static void zvram_gpu_destroy_pool(struct zvram_gpu *gpu)
{
	unsigned int i;

#ifdef CONFIG_DRM
	if (gpu->drm_nr_bufs) {
		for (i = 0; i < gpu->drm_nr_bufs; i++) {
			drm_gem_vunmap_unlocked(gpu->drm_gems[i],
					       &gpu->maps[i]);
			drm_gem_object_put(gpu->drm_gems[i]);
			gpu->drm_gems[i] = NULL;
		}
		gpu->drm_nr_bufs = 0;
		drm_client_release(&gpu->drm_client);
	} else
#endif
	if (gpu->maps[0].is_iomem && gpu->maps[0].vaddr_iomem) {
		iounmap(gpu->maps[0].vaddr_iomem);
	}
	for (i = 0; i < gpu->nr_maps; i++)
		iosys_map_clear(&gpu->maps[i]);
	gpu->nr_maps = 0;
	zvram_buddy_destroy(gpu);
}

static struct zvram_gpu *zvram_gpu_alloc(int idx, int numa_node)
{
	struct zvram_gpu *gpu;

	gpu = kzalloc(sizeof(*gpu), GFP_KERNEL);
	if (!gpu)
		return NULL;

	gpu->gpu_idx = idx;
	gpu->numa_node = numa_node;
	return gpu;
}

/*********************************
* GPU/VRAM discovery
**********************************/

struct zvram_gpu_info {
	struct pci_dev		*pdev;
	resource_size_t		bar_base;
	unsigned long		bar_size;
};

static int zvram_find_all_gpus(struct zvram_gpu_info *out, int max_gpus)
{
	struct pci_dev *pdev = NULL;
	int nr_found = 0;
	int bar;

	while ((pdev = pci_get_class(PCI_CLASS_DISPLAY_VGA << 8, pdev)) != NULL) {
		resource_size_t best_base = 0;
		unsigned long best_size = 0;

		if (!zvram_device_matches(pdev))
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
			}
		}
		if (best_size && nr_found < max_gpus) {
			out[nr_found].pdev = pci_dev_get(pdev);
			out[nr_found].bar_base = best_base;
			out[nr_found].bar_size = best_size;
			nr_found++;
		}
	}

	/* Also check 3D controllers (e.g. NVIDIA compute GPUs) */
	pdev = NULL;
	while ((pdev = pci_get_class(PCI_CLASS_DISPLAY_3D << 8, pdev)) != NULL) {
		resource_size_t best_base = 0;
		unsigned long best_size = 0;

		if (!zvram_device_matches(pdev))
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
			}
		}
		if (best_size && nr_found < max_gpus) {
			out[nr_found].pdev = pci_dev_get(pdev);
			out[nr_found].bar_base = best_base;
			out[nr_found].bar_size = best_size;
			nr_found++;
		}
	}

	if (!nr_found)
		pr_info("no GPU with usable VRAM BAR found\n");

	return nr_found;
}

/*********************************
* DRM client VRAM allocation
**********************************/

#ifdef CONFIG_DRM

#define ZVRAM_DRM_WIDTH		4096
#define ZVRAM_DRM_BPP		8
#define ZVRAM_DRM_STRIDE	(ZVRAM_DRM_WIDTH * (ZVRAM_DRM_BPP / 8))
#define ZVRAM_DRM_MAX_BUF	((unsigned long)(U32_MAX / ZVRAM_DRM_STRIDE) * ZVRAM_DRM_STRIDE)

static void zvram_drm_unregister(struct drm_client_dev *client)
{
	struct zvram_gpu *gpu = container_of(client, struct zvram_gpu,
					     drm_client);

	WRITE_ONCE(gpu->ready, false);
	synchronize_rcu();
	zvram_gpu_destroy_pool(gpu);
	pr_info("GPU %d driver unloaded, VRAM released\n", gpu->gpu_idx);

	mutex_lock(&zvram_gpu_mutex);
	zvram_rebuild_pref_map();
	mutex_unlock(&zvram_gpu_mutex);

	module_put(THIS_MODULE);
}

static const struct drm_client_funcs zvram_drm_funcs = {
	.owner		= THIS_MODULE,
	.unregister	= zvram_drm_unregister,
};

static struct drm_device *zvram_find_drm_for_pci(struct pci_dev *pdev)
{
	return drm_find_device(&pdev->dev);
}

static int zvram_drm_alloc_vram(struct zvram_gpu *gpu)
{
	struct pci_dev *pdev = gpu->pdev;
	struct drm_device *drm;
	struct drm_gem_object *gems[ZVRAM_MAX_BUFFERS];
	struct iosys_map maps[ZVRAM_MAX_BUFFERS];
	unsigned long bar_size, alloc_size, buf_size, remaining;
	unsigned int nr_bufs = 0;
	int ret;

	drm = zvram_find_drm_for_pci(pdev);
	if (!drm)
		return -ENODEV;

	ret = drm_client_init(drm, &gpu->drm_client, "zvram",
			      &zvram_drm_funcs);
	if (ret) {
		pr_err("GPU %d: DRM client init failed: %d\n",
		       gpu->gpu_idx, ret);
		drm_dev_put(drm);
		return ret;
	}

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
	alloc_size = (unsigned long)((u64)bar_size *
		     min(zvram_max_pool_percent, 100U) / 100);
	if (alloc_size < (4UL << 20))
		alloc_size = 4UL << 20;

	buf_size = min(alloc_size, ZVRAM_DRM_MAX_BUF);
	buf_size = rounddown(buf_size, ZVRAM_MIN_ALLOC_SIZE);

	remaining = alloc_size;
	while (remaining && nr_bufs < ZVRAM_MAX_BUFFERS) {
		struct drm_mode_create_dumb dumb_args = {};
		struct drm_gem_object *obj;
		unsigned long chunk = min(remaining, buf_size);
		u32 height;

		height = chunk / ZVRAM_DRM_STRIDE;
		if (!height)
			break;
		chunk = (unsigned long)height * ZVRAM_DRM_STRIDE;

		dumb_args.width = ZVRAM_DRM_WIDTH;
		dumb_args.height = height;
		dumb_args.bpp = ZVRAM_DRM_BPP;
		ret = drm_mode_create_dumb(drm, &dumb_args,
					   gpu->drm_client.file);
		if (ret) {
			pr_err("GPU %d: DRM dumb buffer %u creation failed: %d\n",
			       gpu->gpu_idx, nr_bufs, ret);
			if (!nr_bufs)
				goto fail_client;
			break;
		}

		obj = drm_gem_object_lookup(gpu->drm_client.file,
					    dumb_args.handle);
		drm_mode_destroy_dumb(drm, dumb_args.handle,
				      gpu->drm_client.file);
		if (!obj) {
			pr_err("GPU %d: DRM buffer %u GEM lookup failed\n",
			       gpu->gpu_idx, nr_bufs);
			if (!nr_bufs) {
				ret = -ENOENT;
				goto fail_client;
			}
			break;
		}

		ret = drm_gem_vmap_unlocked(obj, &maps[nr_bufs]);
		if (ret) {
			pr_err("GPU %d: DRM buffer %u vmap failed: %d\n",
			       gpu->gpu_idx, nr_bufs, ret);
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

	mutex_lock(&zvram_gpu_mutex);
	if (smp_load_acquire(&gpu->ready)) {
		mutex_unlock(&zvram_gpu_mutex);
		ret = -EEXIST;
		goto fail_bufs;
	}

	{
		unsigned int i;

		for (i = 0; i < nr_bufs; i++)
			gpu->drm_gems[i] = gems[i];
		gpu->drm_nr_bufs = nr_bufs;
	}

	ret = zvram_gpu_init_pool(gpu, maps, nr_bufs, buf_size, alloc_size);
	if (ret) {
		gpu->drm_nr_bufs = 0;
		mutex_unlock(&zvram_gpu_mutex);
		goto fail_bufs;
	}

	if (!try_module_get(THIS_MODULE)) {
		zvram_gpu_destroy_pool(gpu);
		mutex_unlock(&zvram_gpu_mutex);
		ret = -ENODEV;
		goto fail_client;
	}
	smp_store_release(&gpu->ready, true);
	zvram_rebuild_pref_map();
	mutex_unlock(&zvram_gpu_mutex);

	drm_client_register(&gpu->drm_client);

	pr_info("GPU %d: VRAM via DRM: %lu MB from %s (BAR: %lu MB, "
		"%u buffers, NUMA node %d)\n",
		gpu->gpu_idx, alloc_size >> 20, dev_name(&pdev->dev),
		bar_size >> 20, nr_bufs, gpu->numa_node);

	if (bar_size < (256UL << 20))
		pr_warn("VRAM BAR < 256MB, ReBAR may not be enabled\n");

	drm_dev_put(drm);
	return 0;

fail_bufs:
	while (nr_bufs--) {
		drm_gem_vunmap_unlocked(gems[nr_bufs], &maps[nr_bufs]);
		drm_gem_object_put(gems[nr_bufs]);
	}
fail_client:
	drm_client_release(&gpu->drm_client);
	drm_dev_put(drm);
	return ret;
}

static void zvram_drm_setup_work_fn(struct work_struct *work)
{
	struct zvram_gpu *gpu = container_of(work, struct zvram_gpu, drm_work);
	int ret;

	if (READ_ONCE(gpu->ready))
		return;

	ret = zvram_drm_alloc_vram(gpu);
	if (ret)
		pr_err("GPU %d: DRM VRAM allocation failed: %d\n",
		       gpu->gpu_idx, ret);
	else
		pr_info("GPU %d: VRAM pool ready (DRM, deferred)\n",
			gpu->gpu_idx);
}

static int zvram_pci_notifier_fn(struct notifier_block *nb,
				 unsigned long action, void *data)
{
	struct device *dev = data;
	struct pci_dev *pdev;
	int i;

	if (action != BUS_NOTIFY_BOUND_DRIVER)
		return NOTIFY_DONE;

	if (!dev_is_pci(dev))
		return NOTIFY_DONE;

	pdev = to_pci_dev(dev);
	if ((pdev->class >> 8) != PCI_CLASS_DISPLAY_VGA &&
	    (pdev->class >> 8) != PCI_CLASS_DISPLAY_3D)
		return NOTIFY_DONE;

	if (!zvram_device_matches(pdev))
		return NOTIFY_DONE;

	/* Check if this GPU is already tracked and waiting for DRM */
	for (i = 0; i < zvram_nr_gpus; i++) {
		struct zvram_gpu *gpu = zvram_gpus[i];

		if (!gpu || !gpu->pdev)
			continue;
		if (gpu->pdev == pdev && !READ_ONCE(gpu->ready)) {
			schedule_work(&gpu->drm_work);
			return NOTIFY_OK;
		}
	}

	/* New GPU that wasn't discovered at init time */
	{
		struct zvram_gpu *gpu;
		int node = dev_to_node(&pdev->dev);

		if (node == NUMA_NO_NODE)
			node = 0;

		mutex_lock(&zvram_gpu_mutex);
		if (zvram_nr_gpus >= ZVRAM_MAX_GPUS) {
			mutex_unlock(&zvram_gpu_mutex);
			return NOTIFY_DONE;
		}
		gpu = zvram_gpu_alloc(zvram_nr_gpus, node);
		if (gpu) {
			gpu->pdev = pci_dev_get(pdev);
			INIT_WORK(&gpu->drm_work, zvram_drm_setup_work_fn);
			zvram_gpus[zvram_nr_gpus] = gpu;
			zvram_nr_gpus++;
			schedule_work(&gpu->drm_work);
		}
		mutex_unlock(&zvram_gpu_mutex);
	}

	return NOTIFY_OK;
}

#endif /* CONFIG_DRM */

/*********************************
* debugfs
**********************************/

#ifdef CONFIG_DEBUG_FS
static struct dentry *zvram_debugfs_root;

static int debugfs_get_gpu_total(void *data, u64 *val)
{
	struct zvram_gpu *gpu = data;

	*val = gpu->total_size;
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(zvram_gpu_total_fops,
			 debugfs_get_gpu_total, NULL, "%llu\n");

static int debugfs_get_gpu_used(void *data, u64 *val)
{
	struct zvram_gpu *gpu = data;

	*val = atomic_long_read(&gpu->used_bytes);
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(zvram_gpu_used_fops,
			 debugfs_get_gpu_used, NULL, "%llu\n");

static int debugfs_get_aggregate_total(void *data, u64 *val)
{
	unsigned int i;

	*val = 0;
	for (i = 0; i < zvram_nr_gpus; i++) {
		struct zvram_gpu *gpu = zvram_gpus[i];

		if (gpu)
			*val += gpu->total_size;
	}
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(zvram_agg_total_fops,
			 debugfs_get_aggregate_total, NULL, "%llu\n");

static int debugfs_get_aggregate_used(void *data, u64 *val)
{
	unsigned int i;

	*val = 0;
	for (i = 0; i < zvram_nr_gpus; i++) {
		struct zvram_gpu *gpu = zvram_gpus[i];

		if (gpu)
			*val += atomic_long_read(&gpu->used_bytes);
	}
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(zvram_agg_used_fops,
			 debugfs_get_aggregate_used, NULL, "%llu\n");

static void zvram_debugfs_add_gpu(struct zvram_gpu *gpu)
{
	char name[16];

	if (!zvram_debugfs_root)
		return;
	snprintf(name, sizeof(name), "gpu%d", gpu->gpu_idx);
	gpu->debugfs_dir = debugfs_create_dir(name, zvram_debugfs_root);
	debugfs_create_file("pool_total_size", 0444,
			    gpu->debugfs_dir, gpu, &zvram_gpu_total_fops);
	debugfs_create_file("pool_used_size", 0444,
			    gpu->debugfs_dir, gpu, &zvram_gpu_used_fops);
}

static int zvram_debugfs_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	zvram_debugfs_root = debugfs_create_dir("zvram", NULL);
	debugfs_create_file("pool_total_size", 0444,
			    zvram_debugfs_root, NULL, &zvram_agg_total_fops);
	debugfs_create_file("pool_used_size", 0444,
			    zvram_debugfs_root, NULL, &zvram_agg_used_fops);

	return 0;
}

static void zvram_debugfs_exit(void)
{
	debugfs_remove_recursive(zvram_debugfs_root);
}
#else
static int zvram_debugfs_init(void) { return 0; }
static void zvram_debugfs_exit(void) {}
static void zvram_debugfs_add_gpu(struct zvram_gpu *gpu) {}
#endif

/*********************************
* module init and exit
**********************************/

static int zvram_gpu_init_bar(struct zvram_gpu *gpu,
			      resource_size_t phys_base, unsigned long size)
{
	struct iosys_map map;
	void __iomem *vaddr;
	unsigned long alloc_size;
	int ret;

	alloc_size = (unsigned long)((u64)size *
		     min(zvram_max_pool_percent, 100U) / 100);
	if (alloc_size < ZVRAM_MIN_ALLOC_SIZE)
		alloc_size = ZVRAM_MIN_ALLOC_SIZE;

	vaddr = ioremap_wc(phys_base, alloc_size);
	if (!vaddr) {
		pr_err("GPU %d: failed to ioremap VRAM at %pa size %lu\n",
		       gpu->gpu_idx, &phys_base, alloc_size);
		return -ENOMEM;
	}

	iosys_map_set_vaddr_iomem(&map, vaddr);
	ret = zvram_gpu_init_pool(gpu, &map, 1, alloc_size, alloc_size);
	if (ret) {
		iounmap(vaddr);
		return ret;
	}

	return 0;
}

static int __init zvram_init(void)
{
	int cpu, ret, i;
	int any_ready = 0;

	pr_info("initializing zvram zpool backend\n");

	/* Initialize per-NUMA-node preferred GPU map */
	for (i = 0; i < MAX_NUMNODES; i++)
		zvram_pref_gpu[i] = -1;

	/* Allocate per-CPU map staging buffers */
	zvram_map_ctx = alloc_percpu(struct zvram_map_ctx);
	if (!zvram_map_ctx)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		struct zvram_map_ctx *ctx = per_cpu_ptr(zvram_map_ctx, cpu);

		local_lock_init(&ctx->lock);
		ctx->buffer = kmalloc_node(PAGE_SIZE, GFP_KERNEL,
					   cpu_to_node(cpu));
		if (!ctx->buffer) {
			ret = -ENOMEM;
			goto fail_map_ctx;
		}
	}

	if (zvram_debugfs_init())
		pr_warn("debugfs initialization failed\n");

	/*
	 * VRAM pool setup.  Three methods tried in order:
	 *
	 * 1. DRM client: safe coexistence with GPU driver (multi-GPU).
	 * 2. User-specified VRAM address (single GPU only).
	 * 3. Direct BAR scan (!CONFIG_DRM only, multi-GPU).
	 */

#ifdef CONFIG_DRM
	{
		struct zvram_gpu_info gpus_found[ZVRAM_MAX_GPUS];
		int nr_found;

		nr_found = zvram_find_all_gpus(gpus_found, ZVRAM_MAX_GPUS);

		for (i = 0; i < nr_found; i++) {
			struct zvram_gpu *gpu;
			int node;

			node = dev_to_node(&gpus_found[i].pdev->dev);
			if (node == NUMA_NO_NODE)
				node = 0;

			gpu = zvram_gpu_alloc(zvram_nr_gpus, node);
			if (!gpu) {
				pci_dev_put(gpus_found[i].pdev);
				continue;
			}

			gpu->pdev = gpus_found[i].pdev; /* transfer ref */
			INIT_WORK(&gpu->drm_work, zvram_drm_setup_work_fn);

			mutex_lock(&zvram_gpu_mutex);
			zvram_gpus[zvram_nr_gpus] = gpu;
			zvram_nr_gpus++;
			mutex_unlock(&zvram_gpu_mutex);

			ret = zvram_drm_alloc_vram(gpu);
			if (ret == 0) {
				any_ready++;
				zvram_debugfs_add_gpu(gpu);
			}

			if (gpus_found[i].bar_size < (256UL << 20))
				pr_warn("GPU %d: VRAM BAR < 256MB, "
					"ReBAR may not be enabled\n",
					gpu->gpu_idx);
		}

		/* Register PCI notifier for deferred GPU driver binding */
		if (nr_found > 0 || !zvram_device) {
			zvram_pci_nb.notifier_call = zvram_pci_notifier_fn;
			bus_register_notifier(&pci_bus_type, &zvram_pci_nb);
			zvram_pci_nb_registered = true;
		}
	}
#endif

	/* Method 2: User-specified VRAM address (single GPU) */
	if (!any_ready && zvram_vram_base && zvram_vram_size) {
		struct zvram_gpu *gpu = NULL;

		mutex_lock(&zvram_gpu_mutex);
		if (zvram_nr_gpus < ZVRAM_MAX_GPUS) {
			gpu = zvram_gpu_alloc(zvram_nr_gpus, 0);
			if (gpu) {
				zvram_gpus[zvram_nr_gpus] = gpu;
				zvram_nr_gpus++;

				ret = zvram_gpu_init_bar(gpu, zvram_vram_base,
							 zvram_vram_size);
				if (ret == 0) {
					smp_store_release(&gpu->ready, true);
					zvram_rebuild_pref_map();
					any_ready++;
					pr_info("GPU %d: using user-specified VRAM: "
						"base=0x%lx size=%lu MB\n",
						gpu->gpu_idx, zvram_vram_base,
						zvram_vram_size >> 20);
					zvram_debugfs_add_gpu(gpu);
				}
			}
		}
		mutex_unlock(&zvram_gpu_mutex);
	}

#ifndef CONFIG_DRM
	/* Method 3: Direct BAR scan (no GPU driver coordination) */
	if (!any_ready) {
		struct zvram_gpu_info gpus_found[ZVRAM_MAX_GPUS];
		int nr_found;

		nr_found = zvram_find_all_gpus(gpus_found, ZVRAM_MAX_GPUS);

		if (nr_found) {
			pr_warn("using direct BAR mapping without GPU driver coordination\n");
			pr_warn("enable CONFIG_DRM for safe coexistence\n");
		}

		for (i = 0; i < nr_found; i++) {
			struct zvram_gpu *gpu;
			int node;

			node = dev_to_node(&gpus_found[i].pdev->dev);
			if (node == NUMA_NO_NODE)
				node = 0;

			mutex_lock(&zvram_gpu_mutex);
			if (zvram_nr_gpus >= ZVRAM_MAX_GPUS) {
				mutex_unlock(&zvram_gpu_mutex);
				pci_dev_put(gpus_found[i].pdev);
				break;
			}

			gpu = zvram_gpu_alloc(zvram_nr_gpus, node);
			if (!gpu) {
				mutex_unlock(&zvram_gpu_mutex);
				pci_dev_put(gpus_found[i].pdev);
				continue;
			}

			zvram_gpus[zvram_nr_gpus] = gpu;
			zvram_nr_gpus++;

			ret = zvram_gpu_init_bar(gpu, gpus_found[i].bar_base,
						 gpus_found[i].bar_size);
			if (ret == 0) {
				smp_store_release(&gpu->ready, true);
				zvram_rebuild_pref_map();
				any_ready++;
				zvram_debugfs_add_gpu(gpu);
			}
			mutex_unlock(&zvram_gpu_mutex);

			pci_dev_put(gpus_found[i].pdev);
		}
	}
#endif

	/* Register with zpool framework */
	zpool_register_driver(&zvram_zpool_driver);

	if (any_ready)
		pr_info("ready, %d GPU(s), use zswap.zpool=zvram to enable\n",
			any_ready);
	else
		pr_info("no VRAM pool yet, waiting for GPU\n");

	return 0;

fail_map_ctx:
	for_each_possible_cpu(cpu) {
		struct zvram_map_ctx *ctx = per_cpu_ptr(zvram_map_ctx, cpu);

		kfree(ctx->buffer);
	}
	free_percpu(zvram_map_ctx);
	return ret;
}

static void __exit zvram_exit(void)
{
	int cpu, i;

#ifdef CONFIG_DRM
	if (zvram_pci_nb_registered)
		bus_unregister_notifier(&pci_bus_type, &zvram_pci_nb);

	/* Cancel all deferred DRM work before teardown */
	for (i = 0; i < zvram_nr_gpus; i++) {
		struct zvram_gpu *gpu = zvram_gpus[i];

		if (gpu)
			cancel_work_sync(&gpu->drm_work);
	}
#endif

	zpool_unregister_driver(&zvram_zpool_driver);

	/* Mark all GPUs not-ready, then single RCU barrier */
	for (i = 0; i < zvram_nr_gpus; i++) {
		struct zvram_gpu *gpu = zvram_gpus[i];

		if (gpu && READ_ONCE(gpu->ready))
			WRITE_ONCE(gpu->ready, false);
	}
	synchronize_rcu();

	/*
	 * Remove debugfs BEFORE freeing GPU structs -- debugfs files
	 * hold gpu pointers as their data parameter.
	 */
	zvram_debugfs_exit();

	/* Destroy all GPU pools (ready already cleared above) */
	for (i = 0; i < zvram_nr_gpus; i++) {
		struct zvram_gpu *gpu = zvram_gpus[i];

		if (!gpu)
			continue;
		if (gpu->pcpu_alloc)
			zvram_gpu_destroy_pool(gpu);
#ifdef CONFIG_DRM
		if (gpu->pdev) {
			pci_dev_put(gpu->pdev);
			gpu->pdev = NULL;
		}
#endif
		kfree(gpu);
		zvram_gpus[i] = NULL;
	}
	zvram_nr_gpus = 0;

	for_each_possible_cpu(cpu) {
		struct zvram_map_ctx *ctx = per_cpu_ptr(zvram_map_ctx, cpu);

		kfree(ctx->buffer);
	}
	free_percpu(zvram_map_ctx);
}

module_init(zvram_init);
module_exit(zvram_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Hodges <hodgesd@meta.com>");
MODULE_DESCRIPTION("GPU VRAM-backed zpool driver for zswap");
MODULE_ALIAS("zpool-zvram");
