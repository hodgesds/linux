// SPDX-License-Identifier: GPL-2.0
/*
 * NUMA Page Replication
 *
 * Replicate read-only file-backed pages across NUMA nodes so each CPU
 * accesses a NUMA-local copy.  Replica folios live in a per-address_space
 * XArray keyed by (pgoff, nid), separate from the page cache.
 *
 * Mappings with replicas are tracked in a global XArray keyed by
 * address_space pointer, avoiding any growth of struct address_space.
 *
 * Replicas are NOT in the page cache's mapping->i_pages.  folio->mapping
 * is set to the canonical address_space OR'd with FOLIO_MAPPING_REPLICA
 * (bit 2), so folio_mapping() returns NULL for replicas — preserving the
 * invariant that folio_mapping() != NULL means "in the page cache."
 * rmap (try_to_unmap) uses folio_raw_mapping() to extract the real
 * address_space and find VMAs via i_mmap.
 *
 * Replicas are invalidated when the canonical page is truncated, reclaimed,
 * or dirtied.  This ensures coherency even when the underlying file is
 * modified by another process.
 *
 * XArray serialization:
 *  - xa_store() is only called from numa_replica_install() under PTL.
 *  - xa_erase() is called from the shrinker and invalidation paths.
 *    All erase paths check the return value: only the caller that
 *    receives a non-NULL folio owns it and may decrement counters and
 *    free the folio.  This prevents double folio_put() races.
 *  - The shrinker collects folios under replica_trees_lock, then
 *    unmaps/frees outside the lock.  Invalidation paths do not hold
 *    replica_trees_lock; they rely on xa_erase() atomicity.
 */

#include <linux/numa_replicate.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/shrinker.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/vmstat.h>
#include <linux/nodemask.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/rmap.h>
#include <linux/memcontrol.h>
#include <linux/swap.h>
#include <linux/workqueue.h>

#define CREATE_TRACE_POINTS
#include <trace/events/numa_replicate.h>

int sysctl_numa_replicate_enabled __read_mostly;
int sysctl_numa_replicate_pinned __read_mostly;
unsigned long sysctl_numa_replicate_max_per_node __read_mostly = 65536; /* 256MB */

/*
 * Static branch enabled when at least one mapping has a replica tree
 * registered.  Gates hot-path checks in shrink_folio_list(),
 * folio_mark_dirty(), and folio_check_dirty_writeback() so they
 * compile to nops when no replicas exist.
 */
DEFINE_STATIC_KEY_FALSE(numa_replicate_active);

static atomic_long_t node_nr_replicas[MAX_NUMNODES];

/* Global list of replica trees for shrinker iteration */
static LIST_HEAD(replica_trees_list);
static DEFINE_SPINLOCK(replica_trees_lock);

/*
 * Global XArray mapping address_space pointers to their numa_replica_tree.
 * This replaces the old mapping->numa_replicas pointer, keeping struct
 * address_space unchanged.
 */
static DEFINE_XARRAY(numa_replica_trees);

struct numa_replica_tree_entry {
	struct numa_replica_tree tree;
	struct list_head list;
};

/* Forward declarations for shrinker scan position (defined in shrinker section) */
static struct numa_replica_tree_entry *shrink_scan_entry;
static unsigned long shrink_scan_index;

static inline struct numa_replica_tree_entry *
tree_to_entry(struct numa_replica_tree *nrt)
{
	return container_of(nrt, struct numa_replica_tree_entry, tree);
}

/*
 * Look up the replica tree for a given address_space.
 * Returns NULL if no replicas exist for this mapping.
 */
struct numa_replica_tree *
numa_replica_tree_for_mapping(struct address_space *mapping)
{
	return xa_load(&numa_replica_trees, (unsigned long)mapping);
}

/*
 * Register a replica tree in the global XArray.
 * Returns 0 on success, -EEXIST if one is already registered.
 */
int numa_replica_tree_register(struct address_space *mapping,
			       struct numa_replica_tree *nrt)
{
	void *old;

	old = xa_cmpxchg(&numa_replica_trees, (unsigned long)mapping,
			 NULL, nrt, GFP_KERNEL | __GFP_ACCOUNT);
	if (xa_is_err(old))
		return xa_err(old);
	if (old)
		return -EEXIST;
	static_branch_inc(&numa_replicate_active);
	return 0;
}

/*
 * Unregister and return the replica tree for a mapping.
 */
struct numa_replica_tree *
numa_replica_tree_unregister(struct address_space *mapping)
{
	struct numa_replica_tree *nrt;

	nrt = xa_erase(&numa_replica_trees, (unsigned long)mapping);
	if (nrt)
		static_branch_dec(&numa_replicate_active);
	return nrt;
}

/*
 * Unmap and release a single replica folio.  Caller must have already
 * removed it from the XArray and decremented the counters.
 *
 * This acquires the replica folio lock.  Lock ordering:
 *   canonical folio lock -> replica folio lock
 * The shrinker acquires replica folio locks independently (without
 * holding any canonical folio lock), so ABBA deadlock is not possible.
 */
static void replica_unmap_and_free(struct folio *folio, int nid,
				   pgoff_t pgoff, const char *reason)
{
	folio_lock(folio);
	try_to_unmap(folio, 0);
	folio->mapping = NULL; /* clears FOLIO_MAPPING_REPLICA bit too */
	folio_unlock(folio);
	count_vm_event(NUMA_REPLICA_DROPPED);
	trace_numa_replica_drop(folio, nid, pgoff, reason);
	folio_put(folio);
}

/*
 * Deferred replica cleanup via workqueue.  Used by the dirty
 * invalidation path which cannot sleep (folio_mark_dirty may be
 * called under PTL).
 *
 * Uses a global list + static work item to avoid per-folio GFP_ATOMIC
 * allocation.  Replica folios are not on the LRU, so folio->lru is
 * available as a list node.  The folio keeps its mapping set so
 * try_to_unmap() can find and zap PTEs in the deferred worker.
 */
static LIST_HEAD(dirty_cleanup_list);
static DEFINE_SPINLOCK(dirty_cleanup_lock);

static void dirty_cleanup_worker(struct work_struct *work)
{
	LIST_HEAD(local);

	spin_lock(&dirty_cleanup_lock);
	list_splice_init(&dirty_cleanup_list, &local);
	spin_unlock(&dirty_cleanup_lock);

	while (!list_empty(&local)) {
		struct folio *folio = list_first_entry(&local,
						      struct folio, lru);
		list_del_init(&folio->lru);
		replica_unmap_and_free(folio, folio_nid(folio),
				      folio->index, "dirty");
	}
}

static DECLARE_WORK(dirty_cleanup_static_work, dirty_cleanup_worker);

static struct numa_replica_tree *
__numa_replica_tree_alloc(struct address_space *mapping, gfp_t gfp)
{
	struct numa_replica_tree_entry *entry;

	entry = kzalloc(sizeof(*entry), gfp | __GFP_ACCOUNT);
	if (!entry)
		return NULL;

	xa_init(&entry->tree.replicas);
	atomic_long_set(&entry->tree.nr_replicas, 0);
	entry->tree.mapping = mapping;

	spin_lock(&replica_trees_lock);
	list_add_tail(&entry->list, &replica_trees_list);
	spin_unlock(&replica_trees_lock);

	return &entry->tree;
}

struct numa_replica_tree *numa_replica_tree_alloc(struct address_space *mapping)
{
	return __numa_replica_tree_alloc(mapping, GFP_NOWAIT);
}

/*
 * Pre-allocate a replica tree from a sleepable context (madvise).
 * This avoids GFP_NOWAIT failures during the fault path.
 */
struct numa_replica_tree *numa_replica_tree_alloc_sleepable(
		struct address_space *mapping)
{
	return __numa_replica_tree_alloc(mapping, GFP_KERNEL);
}

void numa_replica_tree_free(struct numa_replica_tree *nrt)
{
	struct numa_replica_tree_entry *entry;
	struct folio *folio;
	unsigned long index;

	if (!nrt)
		return;

	/*
	 * Flush any deferred dirty cleanup work before tearing down
	 * the tree.  Queued replica folios reference this mapping's
	 * address_space via folio->mapping; if the inode is evicted
	 * before the worker runs, try_to_unmap() would dereference
	 * freed memory.
	 *
	 * flush_work() can sleep; all callers reach here from
	 * truncate_inode_pages_final() -> evict() which is in
	 * process context, so sleeping is safe.
	 */
	flush_work(&dirty_cleanup_static_work);

	entry = tree_to_entry(nrt);

	spin_lock(&replica_trees_lock);
	/* Invalidate shrinker position if it points at this entry */
	if (shrink_scan_entry == entry) {
		shrink_scan_entry = NULL;
		shrink_scan_index = 0;
	}
	list_del(&entry->list);
	spin_unlock(&replica_trees_lock);

	xa_for_each(&nrt->replicas, index, folio) {
		int nid = folio_nid(folio);

		xa_erase(&nrt->replicas, index);
		atomic_long_dec(&node_nr_replicas[nid]);
		atomic_long_dec(&nrt->nr_replicas);
		replica_unmap_and_free(folio, nid,
				      replica_key_pgoff(index), "destroy");
	}

	/*
	 * Only clear AS_NUMA_REPLICATED if this tree is still the registered
	 * one.  On the -EEXIST error path in madvise, the losing tree is
	 * freed but the winning tree's mapping flag must stay set.
	 */
	if (nrt->mapping) {
		struct numa_replica_tree *registered;

		registered = xa_load(&numa_replica_trees,
				     (unsigned long)nrt->mapping);
		if (registered == nrt)
			mapping_clear_numa_replicated(nrt->mapping);
	}

	xa_destroy(&nrt->replicas);
	kfree(entry);
}

/* Returns replica folio with a reference, or NULL. */
struct folio *numa_replica_lookup(struct numa_replica_tree *nrt,
				  pgoff_t pgoff, int nid)
{
	struct folio *folio;

	if (!nrt)
		return NULL;

	rcu_read_lock();
	folio = xa_load(&nrt->replicas, replica_key(pgoff, nid));
	if (folio && !folio_try_get(folio))
		folio = NULL;
	rcu_read_unlock();

	return folio;
}

long numa_replica_node_count(int nid)
{
	if (nid < 0 || nid >= MAX_NUMNODES)
		return 0;
	return atomic_long_read(&node_nr_replicas[nid]);
}
