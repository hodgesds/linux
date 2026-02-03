// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * zfcache.c - compressed file cache driver
 *
 * zfcache is a cache that takes clean file pages that are being evicted
 * from the page cache and attempts to compress and store them in a
 * RAM-based memory pool. This can result in significant I/O reduction
 * when pages are re-accessed, as they can be decompressed from RAM
 * instead of being read from disk.
 *
 * This is similar to zswap but for file-backed pages instead of swap pages.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/mempool.h>
#include <crypto/acompress.h>
#include <linux/zfcache.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/workqueue.h>
#include <linux/zsmalloc.h>
#include <linux/debugfs.h>
#include <linux/fs.h>

#include "internal.h"

/*********************************
 * statistics
 **********************************/
/* Number of pages currently stored in zfcache */
static atomic_long_t zfcache_stored_pages = ATOMIC_LONG_INIT(0);

/* Store failed due to compression algorithm failure */
static u64 zfcache_reject_compress_fail;
/* Compressed page was too big for the allocator to (optimally) store */
static u64 zfcache_reject_compress_poor;
/* Load failed due to decompression failure */
static u64 zfcache_decompress_fail;
/* Store failed because underlying allocator could not get memory */
static u64 zfcache_reject_alloc_fail;
/* Store failed because the entry metadata could not be allocated */
static u64 zfcache_reject_kmemcache_fail;
/* Pool limit was hit */
static u64 zfcache_pool_limit_hit;
/* Pages successfully loaded from cache */
static u64 zfcache_loads;
/* Pages successfully stored in cache */
static u64 zfcache_stores;

/*********************************
 * tunables
 **********************************/

/* Enable/disable zfcache */
static bool zfcache_enabled = IS_ENABLED(CONFIG_ZFCACHE_DEFAULT_ON);
module_param_named(enabled, zfcache_enabled, bool, 0644);

/* Crypto compressor to use */
static char *zfcache_compressor = CONFIG_ZFCACHE_COMPRESSOR_DEFAULT;
module_param_named(compressor, zfcache_compressor, charp, 0644);

/* The maximum percentage of memory that the compressed pool can occupy */
static unsigned int zfcache_max_pool_percent = 10;
module_param_named(max_pool_percent, zfcache_max_pool_percent, uint, 0644);

bool zfcache_is_enabled(void)
{
	return zfcache_enabled;
}

/*********************************
 * data structures
 **********************************/

struct crypto_acomp_ctx {
	struct crypto_acomp *acomp;
	struct acomp_req *req;
	struct crypto_wait wait;
	u8 *buffer;
	struct mutex mutex;
	bool is_sleepable;
};

/*
 * struct zfcache_pool - compressed storage pool
 */
struct zfcache_pool {
	struct zs_pool *zs_pool;
	struct crypto_acomp_ctx __percpu *acomp_ctx;
	char tfm_name[CRYPTO_MAX_ALG_NAME];
};

/*
 * struct zfcache_entry
 *
 * This structure contains the metadata for tracking a single compressed
 * page within zfcache.
 *
 * inode - the inode this page belongs to
 * index - page offset within the inode
 * length - the length in bytes of the compressed page data
 * pool - the zfcache_pool the entry's data is in
 * handle - zsmalloc allocation handle that stores the compressed page data
 */
struct zfcache_entry {
	struct inode *inode;
	pgoff_t index;
	unsigned int length;
	struct zfcache_pool *pool;
	unsigned long handle;
};

/* Per-inode tree for compressed pages: index -> zfcache_entry */
struct zfcache_tree {
	struct xarray entries;
	atomic_t count;
};

/* Global xarray mapping inode to zfcache_tree */
static DEFINE_XARRAY(zfcache_inodes);
static DEFINE_SPINLOCK(zfcache_inodes_lock);

/* The current zfcache pool */
static struct zfcache_pool *zfcache_pool_current_ptr;
static DEFINE_MUTEX(zfcache_pool_lock);

/* pool counter to provide unique names to zsmalloc */
static atomic_t zfcache_pools_count = ATOMIC_INIT(0);

enum zfcache_init_type {
	ZFCACHE_UNINIT,
	ZFCACHE_INIT_SUCCEED,
	ZFCACHE_INIT_FAILED
};

static enum zfcache_init_type zfcache_init_state;

/* used to ensure the integrity of initialization */
static DEFINE_MUTEX(zfcache_init_lock);

/* init completed, but couldn't create the initial pool */
static bool zfcache_has_pool;

/*********************************
 * helpers and fwd declarations
 **********************************/

static struct kmem_cache *zfcache_entry_cache;
static struct kmem_cache *zfcache_tree_cache;

#define zfcache_pool_debug(msg, p)			\
	pr_debug("%s pool %s\n", msg, (p)->tfm_name)

/*********************************
 * tree functions
 **********************************/

static struct zfcache_tree *zfcache_tree_alloc(gfp_t gfp)
{
	struct zfcache_tree *tree;

	tree = kmem_cache_alloc(zfcache_tree_cache, gfp);
	if (!tree)
		return NULL;

	xa_init(&tree->entries);
	atomic_set(&tree->count, 0);
	return tree;
}

static void zfcache_tree_free(struct zfcache_tree *tree)
{
	WARN_ON_ONCE(!xa_empty(&tree->entries));
	xa_destroy(&tree->entries);
	kmem_cache_free(zfcache_tree_cache, tree);
}

static struct zfcache_tree *zfcache_tree_get(struct inode *inode, gfp_t gfp)
{
	struct zfcache_tree *tree;
	unsigned long inode_key = (unsigned long)inode;

	tree = xa_load(&zfcache_inodes, inode_key);
	if (tree)
		return tree;

	/* Need to allocate a new tree */
	tree = zfcache_tree_alloc(gfp);
	if (!tree)
		return NULL;

	spin_lock(&zfcache_inodes_lock);
	/* Check if someone else created it while we were allocating */
	if (xa_load(&zfcache_inodes, inode_key)) {
		spin_unlock(&zfcache_inodes_lock);
		zfcache_tree_free(tree);
		return xa_load(&zfcache_inodes, inode_key);
	}

	if (xa_err(xa_store(&zfcache_inodes, inode_key, tree, gfp))) {
		spin_unlock(&zfcache_inodes_lock);
		zfcache_tree_free(tree);
		return NULL;
	}
	spin_unlock(&zfcache_inodes_lock);

	return tree;
}

/*********************************
 * pool functions
 **********************************/

static int zfcache_acomp_ctx_init(struct crypto_acomp_ctx *acomp_ctx,
				  const char *tfm_name, int cpu)
{
	struct crypto_acomp *acomp;
	struct acomp_req *req;
	u8 *buffer;

	buffer = kmalloc_node(PAGE_SIZE, GFP_KERNEL, cpu_to_node(cpu));
	if (!buffer)
		return -ENOMEM;

	acomp = crypto_alloc_acomp_node(tfm_name, 0, 0, cpu_to_node(cpu));
	if (IS_ERR(acomp)) {
		kfree(buffer);
		return PTR_ERR(acomp);
	}

	req = acomp_request_alloc(acomp);
	if (!req) {
		crypto_free_acomp(acomp);
		kfree(buffer);
		return -ENOMEM;
	}

	mutex_init(&acomp_ctx->mutex);
	crypto_init_wait(&acomp_ctx->wait);

	acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &acomp_ctx->wait);

	acomp_ctx->buffer = buffer;
	acomp_ctx->acomp = acomp;
	acomp_ctx->is_sleepable = acomp_is_async(acomp);
	acomp_ctx->req = req;

	return 0;
}

static void zfcache_acomp_ctx_destroy(struct crypto_acomp_ctx *acomp_ctx)
{
	if (!acomp_ctx)
		return;

	if (acomp_ctx->req)
		acomp_request_free(acomp_ctx->req);
	if (acomp_ctx->acomp)
		crypto_free_acomp(acomp_ctx->acomp);
	kfree(acomp_ctx->buffer);
}

static struct zfcache_pool *zfcache_pool_create(char *compressor)
{
	struct zfcache_pool *pool;
	char name[38]; /* 'zfcache' + 32 char (max) num + \0 */
	int ret, cpu;

	if (!compressor || !*compressor)
		return NULL;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;

	/* unique name for each pool specifically required by zsmalloc */
	snprintf(name, 38, "zfcache%x", atomic_inc_return(&zfcache_pools_count));
	pool->zs_pool = zs_create_pool(name);
	if (!pool->zs_pool)
		goto error;

	strscpy(pool->tfm_name, compressor, sizeof(pool->tfm_name));

	pool->acomp_ctx = alloc_percpu(*pool->acomp_ctx);
	if (!pool->acomp_ctx) {
		pr_err("percpu alloc failed\n");
		goto error;
	}

	/* Initialize compression context for each CPU */
	for_each_possible_cpu(cpu) {
		ret = zfcache_acomp_ctx_init(per_cpu_ptr(pool->acomp_ctx, cpu),
					     compressor, cpu);
		if (ret) {
			pr_err("failed to init acomp ctx for cpu %d: %d\n",
			       cpu, ret);
			goto error_ctx;
		}
	}

	zfcache_pool_debug("created", pool);

	return pool;

error_ctx:
	for_each_possible_cpu(cpu)
		zfcache_acomp_ctx_destroy(per_cpu_ptr(pool->acomp_ctx, cpu));
error:
	if (pool->acomp_ctx)
		free_percpu(pool->acomp_ctx);
	if (pool->zs_pool)
		zs_destroy_pool(pool->zs_pool);
	kfree(pool);
	return NULL;
}

static void __maybe_unused zfcache_pool_destroy(struct zfcache_pool *pool)
{
	int cpu;

	zfcache_pool_debug("destroying", pool);

	for_each_possible_cpu(cpu)
		zfcache_acomp_ctx_destroy(per_cpu_ptr(pool->acomp_ctx, cpu));
	free_percpu(pool->acomp_ctx);

	zs_destroy_pool(pool->zs_pool);
	kfree(pool);
}

static struct zfcache_pool *zfcache_pool_current(void)
{
	return zfcache_pool_current_ptr;
}

static unsigned long zfcache_max_pages(void)
{
	return totalram_pages() * zfcache_max_pool_percent / 100;
}

unsigned long zfcache_total_pages(void)
{
	struct zfcache_pool *pool = zfcache_pool_current();

	if (!pool)
		return 0;
	return zs_get_total_pages(pool->zs_pool);
}

static bool zfcache_check_limits(void)
{
	unsigned long cur_pages = zfcache_total_pages();
	unsigned long max_pages = zfcache_max_pages();

	if (cur_pages >= max_pages) {
		zfcache_pool_limit_hit++;
		return true;
	}
	return false;
}

/*********************************
 * entry functions
 **********************************/

static struct zfcache_entry *zfcache_entry_cache_alloc(gfp_t gfp, int nid)
{
	struct zfcache_entry *entry;

	entry = kmem_cache_alloc_node(zfcache_entry_cache, gfp, nid);
	if (!entry)
		return NULL;
	return entry;
}

static void zfcache_entry_cache_free(struct zfcache_entry *entry)
{
	kmem_cache_free(zfcache_entry_cache, entry);
}

static void zfcache_entry_free(struct zfcache_entry *entry)
{
	zs_free(entry->pool->zs_pool, entry->handle);
	zfcache_entry_cache_free(entry);
	atomic_long_dec(&zfcache_stored_pages);
}

/*********************************
 * compression/decompression
 **********************************/

static struct crypto_acomp_ctx *acomp_ctx_get_cpu_lock(struct zfcache_pool *pool)
{
	struct crypto_acomp_ctx *acomp_ctx;

	for (;;) {
		acomp_ctx = raw_cpu_ptr(pool->acomp_ctx);
		mutex_lock(&acomp_ctx->mutex);
		if (likely(acomp_ctx->req))
			return acomp_ctx;
		mutex_unlock(&acomp_ctx->mutex);
	}
}

static void acomp_ctx_put_unlock(struct crypto_acomp_ctx *acomp_ctx)
{
	mutex_unlock(&acomp_ctx->mutex);
}

static bool zfcache_compress(struct folio *folio, struct zfcache_entry *entry,
			     struct zfcache_pool *pool)
{
	struct crypto_acomp_ctx *acomp_ctx;
	struct scatterlist input, output;
	int comp_ret = 0, alloc_ret = 0;
	unsigned int dlen = PAGE_SIZE;
	unsigned long handle;
	gfp_t gfp;
	u8 *dst;

	acomp_ctx = acomp_ctx_get_cpu_lock(pool);
	dst = acomp_ctx->buffer;
	sg_init_table(&input, 1);
	sg_set_folio(&input, folio, PAGE_SIZE, 0);

	sg_init_one(&output, dst, PAGE_SIZE);
	acomp_request_set_params(acomp_ctx->req, &input, &output, PAGE_SIZE, dlen);

	comp_ret = crypto_wait_req(crypto_acomp_compress(acomp_ctx->req),
				   &acomp_ctx->wait);
	dlen = acomp_ctx->req->dlen;

	/*
	 * If a page cannot be compressed to a size smaller than PAGE_SIZE,
	 * we don't store it in zfcache - it wouldn't save any memory.
	 */
	if (comp_ret || !dlen || dlen >= PAGE_SIZE) {
		comp_ret = comp_ret ? comp_ret : -EINVAL;
		goto unlock;
	}

	gfp = GFP_NOWAIT | __GFP_NORETRY | __GFP_HIGHMEM | __GFP_MOVABLE;
	handle = zs_malloc(pool->zs_pool, dlen, gfp,
			   folio_nid(folio));
	if (IS_ERR_VALUE(handle)) {
		alloc_ret = PTR_ERR((void *)handle);
		goto unlock;
	}

	zs_obj_write(pool->zs_pool, handle, dst, dlen);
	entry->handle = handle;
	entry->length = dlen;

unlock:
	if (comp_ret == -ENOSPC || alloc_ret == -ENOSPC)
		zfcache_reject_compress_poor++;
	else if (comp_ret)
		zfcache_reject_compress_fail++;
	else if (alloc_ret)
		zfcache_reject_alloc_fail++;

	acomp_ctx_put_unlock(acomp_ctx);
	return comp_ret == 0 && alloc_ret == 0;
}

static bool zfcache_decompress(struct zfcache_entry *entry, struct folio *folio)
{
	struct zfcache_pool *pool = entry->pool;
	struct scatterlist input, output;
	struct crypto_acomp_ctx *acomp_ctx;
	int decomp_ret = 0, dlen = PAGE_SIZE;
	u8 *src, *obj;

	acomp_ctx = acomp_ctx_get_cpu_lock(pool);
	obj = zs_obj_read_begin(pool->zs_pool, entry->handle, acomp_ctx->buffer);

	/*
	 * zs_obj_read_begin() might return a kmap address of highmem when
	 * acomp_ctx->buffer is not used. However, sg_init_one() does not
	 * handle highmem addresses, so copy the object to acomp_ctx->buffer.
	 */
	if (virt_addr_valid(obj)) {
		src = obj;
	} else {
		WARN_ON_ONCE(obj == acomp_ctx->buffer);
		memcpy(acomp_ctx->buffer, obj, entry->length);
		src = acomp_ctx->buffer;
	}

	sg_init_one(&input, src, entry->length);
	sg_init_table(&output, 1);
	sg_set_folio(&output, folio, PAGE_SIZE, 0);
	acomp_request_set_params(acomp_ctx->req, &input, &output,
				 entry->length, PAGE_SIZE);
	decomp_ret = crypto_wait_req(crypto_acomp_decompress(acomp_ctx->req),
				     &acomp_ctx->wait);
	dlen = acomp_ctx->req->dlen;

	zs_obj_read_end(pool->zs_pool, entry->handle, obj);
	acomp_ctx_put_unlock(acomp_ctx);

	if (!decomp_ret && dlen == PAGE_SIZE)
		return true;

	zfcache_decompress_fail++;
	pr_alert_ratelimited("Decompression error from zfcache (%lu:%llu %s %u->%d)\n",
			     (unsigned long)entry->inode, (u64)entry->index,
			     entry->pool->tfm_name, entry->length, dlen);
	return false;
}

/*********************************
 * main API
 **********************************/

/**
 * zfcache_store - compress and store a clean file page
 * @folio: the folio to store
 * @mapping: the address_space the folio belongs to
 *
 * Returns true if the folio was successfully stored, false otherwise.
 * Only call this for clean file pages that are being evicted.
 */
bool zfcache_store(struct folio *folio, struct address_space *mapping)
{
	struct zfcache_pool *pool;
	struct zfcache_tree *tree;
	struct zfcache_entry *entry, *old;
	struct inode *inode;
	pgoff_t index;

	if (!zfcache_enabled)
		return false;

	if (!mapping || !mapping->host)
		return false;

	inode = mapping->host;
	index = folio->index;

	/* Only handle order-0 folios for now */
	if (folio_order(folio) != 0)
		return false;

	if (zfcache_check_limits())
		return false;

	pool = zfcache_pool_current();
	if (!pool)
		return false;

	/* Get or create the per-inode tree */
	tree = zfcache_tree_get(inode, GFP_NOWAIT);
	if (!tree)
		return false;

	/* Allocate entry */
	entry = zfcache_entry_cache_alloc(GFP_NOWAIT, folio_nid(folio));
	if (!entry) {
		zfcache_reject_kmemcache_fail++;
		return false;
	}

	entry->inode = inode;
	entry->index = index;
	entry->pool = pool;

	if (!zfcache_compress(folio, entry, pool)) {
		zfcache_entry_cache_free(entry);
		return false;
	}

	/* Store in tree, replacing any old entry */
	old = xa_store(&tree->entries, index, entry, GFP_NOWAIT);
	if (xa_is_err(old)) {
		zs_free(pool->zs_pool, entry->handle);
		zfcache_entry_cache_free(entry);
		zfcache_reject_alloc_fail++;
		return false;
	}

	if (old) {
		zfcache_entry_free(old);
	} else {
		atomic_inc(&tree->count);
	}

	atomic_long_inc(&zfcache_stored_pages);
	zfcache_stores++;

	return true;
}

/**
 * zfcache_load - load a compressed page from zfcache
 * @folio: the folio to load into
 * @mapping: the address_space the folio belongs to
 * @index: the page index within the inode
 *
 * Returns true if the page was found in zfcache and decompressed
 * successfully, false otherwise.
 */
bool zfcache_load(struct folio *folio, struct address_space *mapping,
		  pgoff_t index)
{
	struct zfcache_tree *tree;
	struct zfcache_entry *entry;
	struct inode *inode;
	unsigned long inode_key;

	if (!zfcache_enabled)
		return false;

	if (!mapping || !mapping->host)
		return false;

	inode = mapping->host;
	inode_key = (unsigned long)inode;

	/* Look up the per-inode tree */
	tree = xa_load(&zfcache_inodes, inode_key);
	if (!tree)
		return false;

	/* Look up the entry */
	entry = xa_load(&tree->entries, index);
	if (!entry)
		return false;

	/* Decompress into the folio */
	if (!zfcache_decompress(entry, folio))
		return false;

	/* Remove from cache after successful load */
	entry = xa_erase(&tree->entries, index);
	if (entry) {
		atomic_dec(&tree->count);
		zfcache_entry_free(entry);
	}

	zfcache_loads++;
	return true;
}

/**
 * zfcache_invalidate - invalidate compressed pages in a range
 * @mapping: the address_space to invalidate
 * @start: start page index
 * @end: end page index (inclusive)
 *
 * Called when file pages are truncated or invalidated.
 */
void zfcache_invalidate(struct address_space *mapping, pgoff_t start,
			pgoff_t end)
{
	struct zfcache_tree *tree;
	struct zfcache_entry *entry;
	struct inode *inode;
	unsigned long inode_key;
	pgoff_t index;

	if (!zfcache_enabled)
		return;

	if (!mapping || !mapping->host)
		return;

	inode = mapping->host;
	inode_key = (unsigned long)inode;

	tree = xa_load(&zfcache_inodes, inode_key);
	if (!tree)
		return;

	for (index = start; index <= end; index++) {
		entry = xa_erase(&tree->entries, index);
		if (entry) {
			atomic_dec(&tree->count);
			zfcache_entry_free(entry);
		}
	}
}

/**
 * zfcache_invalidate_inode - invalidate all compressed pages for an inode
 * @inode: the inode to invalidate
 *
 * Called when an inode is being evicted.
 */
void zfcache_invalidate_inode(struct inode *inode)
{
	struct zfcache_tree *tree;
	struct zfcache_entry *entry;
	unsigned long inode_key = (unsigned long)inode;
	unsigned long index;

	if (!zfcache_enabled)
		return;

	spin_lock(&zfcache_inodes_lock);
	tree = xa_erase(&zfcache_inodes, inode_key);
	spin_unlock(&zfcache_inodes_lock);

	if (!tree)
		return;

	/* Free all entries in the tree */
	xa_for_each(&tree->entries, index, entry) {
		xa_erase(&tree->entries, index);
		zfcache_entry_free(entry);
	}

	zfcache_tree_free(tree);
}

/*********************************
 * debugfs functions
 **********************************/
#ifdef CONFIG_DEBUG_FS
static struct dentry *zfcache_debugfs_root;

static int debugfs_get_total_size(void *data, u64 *val)
{
	*val = zfcache_total_pages() * PAGE_SIZE;
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(total_size_fops, debugfs_get_total_size, NULL, "%llu\n");

static int debugfs_get_stored_pages(void *data, u64 *val)
{
	*val = atomic_long_read(&zfcache_stored_pages);
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(stored_pages_fops, debugfs_get_stored_pages, NULL, "%llu\n");

static int zfcache_debugfs_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	zfcache_debugfs_root = debugfs_create_dir("zfcache", NULL);

	debugfs_create_u64("pool_limit_hit", 0444,
			   zfcache_debugfs_root, &zfcache_pool_limit_hit);
	debugfs_create_u64("reject_alloc_fail", 0444,
			   zfcache_debugfs_root, &zfcache_reject_alloc_fail);
	debugfs_create_u64("reject_kmemcache_fail", 0444,
			   zfcache_debugfs_root, &zfcache_reject_kmemcache_fail);
	debugfs_create_u64("reject_compress_fail", 0444,
			   zfcache_debugfs_root, &zfcache_reject_compress_fail);
	debugfs_create_u64("reject_compress_poor", 0444,
			   zfcache_debugfs_root, &zfcache_reject_compress_poor);
	debugfs_create_u64("decompress_fail", 0444,
			   zfcache_debugfs_root, &zfcache_decompress_fail);
	debugfs_create_u64("loads", 0444,
			   zfcache_debugfs_root, &zfcache_loads);
	debugfs_create_u64("stores", 0444,
			   zfcache_debugfs_root, &zfcache_stores);
	debugfs_create_file("pool_total_size", 0444,
			    zfcache_debugfs_root, NULL, &total_size_fops);
	debugfs_create_file("stored_pages", 0444,
			    zfcache_debugfs_root, NULL, &stored_pages_fops);

	return 0;
}
#else
static int zfcache_debugfs_init(void)
{
	return 0;
}
#endif

/*********************************
 * module init and exit
 **********************************/
static int zfcache_setup(void)
{
	struct zfcache_pool *pool;

	zfcache_entry_cache = KMEM_CACHE(zfcache_entry, 0);
	if (!zfcache_entry_cache) {
		pr_err("entry cache creation failed\n");
		goto cache_fail;
	}

	zfcache_tree_cache = KMEM_CACHE(zfcache_tree, 0);
	if (!zfcache_tree_cache) {
		pr_err("tree cache creation failed\n");
		goto tree_cache_fail;
	}

	if (!crypto_has_acomp(zfcache_compressor, 0, 0)) {
		pr_err("compressor %s not available\n", zfcache_compressor);
		goto comp_fail;
	}

	pool = zfcache_pool_create(zfcache_compressor);
	if (pool) {
		pr_info("loaded using pool %s\n", pool->tfm_name);
		zfcache_pool_current_ptr = pool;
		zfcache_has_pool = true;
	} else {
		pr_err("pool creation failed\n");
		zfcache_enabled = false;
	}

	if (zfcache_debugfs_init())
		pr_warn("debugfs initialization failed\n");

	zfcache_init_state = ZFCACHE_INIT_SUCCEED;
	return 0;

comp_fail:
	kmem_cache_destroy(zfcache_tree_cache);
tree_cache_fail:
	kmem_cache_destroy(zfcache_entry_cache);
cache_fail:
	zfcache_init_state = ZFCACHE_INIT_FAILED;
	zfcache_enabled = false;
	return -ENOMEM;
}

static int __init zfcache_init(void)
{
	if (!zfcache_enabled)
		return 0;
	return zfcache_setup();
}
/* must be late so crypto has time to come up */
late_initcall(zfcache_init);

MODULE_AUTHOR("Page Cache Compression");
MODULE_DESCRIPTION("Compressed cache for file pages");
