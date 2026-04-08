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

static bool check_node_replica_limit(int nid)
{
	if (!sysctl_numa_replicate_max_per_node)
		return true;
	return atomic_long_read(&node_nr_replicas[nid]) <
	       (long)sysctl_numa_replicate_max_per_node;
}

/*
 * Skip replica creation when the target node is below the high watermark.
 * This prevents a thrash loop where the shrinker reclaims replicas that
 * are immediately re-created on the next fault.
 */
static bool node_has_memory_headroom(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	struct zone *zone;
	enum zone_type zidx = gfp_zone(GFP_NOWAIT);

	zone = &pgdat->node_zones[zidx];
	if (!managed_zone(zone))
		return true;

	return zone_watermark_ok(zone, 0, high_wmark_pages(zone), zidx, 0);
}

/*
 * Phase 1: Allocate and copy a replica folio (before PTL).
 *
 * Allocates a folio on the local NUMA node, copies data from the
 * canonical folio, sets FOLIO_MAPPING_REPLICA, and configures mapping/index for
 * rmap compatibility.  The folio is NOT inserted into the XArray yet.
 *
 * Returns the prepared folio with one reference, or NULL.
 * On failure, falls back gracefully to the canonical folio.
 *
 * Caller must later call either numa_replica_install() under PTL to
 * insert it, or numa_replica_discard_prepared() to discard it.
 */
struct folio *numa_replica_prepare(struct vm_area_struct *vma,
				   struct folio *canonical, pgoff_t pgoff)
{
	struct address_space *mapping;
	struct numa_replica_tree *nrt;
	struct folio *replica;
	void *src, *dst;
	int local_nid;

	if (!sysctl_numa_replicate_enabled || num_online_nodes() < 2)
		return NULL;

	/*
	 * Replicas are only created for order-0 folios.  If khugepaged
	 * later collapses small folios into a large folio via
	 * collapse_file(), stale replica XArray entries may persist
	 * until the shrinker walks the tree and frees them.  The data
	 * remains correct since the file content is unchanged.  After
	 * collapse, subsequent faults on the large folio will not
	 * create new replicas, so replication for that range is
	 * silently lost.
	 */
	if (folio_test_large(canonical) || folio_test_dirty(canonical))
		return NULL;

	local_nid = numa_node_id();

	if (folio_nid(canonical) == local_nid)
		return NULL;

	mapping = vma->vm_file->f_mapping;

	if (mapping_exiting(mapping))
		return NULL;

	nrt = numa_replica_tree_for_mapping(mapping);
	if (!nrt)
		return NULL;

	/*
	 * If a replica already exists, skip preparation.  Do not return
	 * the existing folio -- it could be concurrently invalidated
	 * (mapping cleared) between here and
	 * numa_replica_install(), creating a zombie folio.  The canonical
	 * folio is mapped for this fault; the existing replica serves
	 * future faults from this node.
	 */
	replica = numa_replica_lookup(nrt, pgoff, local_nid);
	if (replica) {
		count_vm_event(NUMA_REPLICA_HIT);
		trace_numa_replica_hit(pgoff, local_nid);
		folio_put(replica);
		return NULL;
	}
	count_vm_event(NUMA_REPLICA_MISS);

	if (!check_node_replica_limit(local_nid))
		return NULL;

	if (!node_has_memory_headroom(local_nid))
		return NULL;

	replica = __folio_alloc_node(GFP_NOWAIT | __GFP_NOWARN, 0, local_nid);
	if (!replica)
		return NULL;

	/* Charge replica to the current task's memcg */
	if (mem_cgroup_charge(replica, current->mm, GFP_NOWAIT)) {
		folio_put(replica);
		return NULL;
	}

	/*
	 * Re-check canonical->mapping: if the folio was truncated between
	 * the caller's lookup and here, mapping may be NULL.  A replica
	 * with NULL mapping cannot be unmapped via try_to_unmap() later.
	 */
	if (!canonical->mapping) {
		folio_put(replica);
		return NULL;
	}

	src = kmap_local_folio(canonical, 0);
	dst = kmap_local_folio(replica, 0);
	memcpy(dst, src, PAGE_SIZE);
	kunmap_local(dst);
	kunmap_local(src);

	/*
	 * Set replica's mapping/index so rmap (try_to_unmap) can find VMAs
	 * via i_mmap when the shrinker or invalidation path unmaps this folio.
	 *
	 * FOLIO_MAPPING_REPLICA (bit 2) is OR'd into the mapping pointer so
	 * folio_mapping() returns NULL for replicas, preserving the invariant
	 * that folio_mapping() != NULL means "in the page cache."  Code that
	 * needs the real address_space (e.g. rmap_walk) uses folio_raw_mapping()
	 * which strips the flag bits.
	 *
	 * Replicas are NOT added to the LRU.  Reclaim is handled exclusively
	 * through the custom shrinker.
	 */
	replica->mapping = (struct address_space *)
		((unsigned long)canonical->mapping | FOLIO_MAPPING_REPLICA);
	replica->index = pgoff;

	return replica;
}

/*
 * Phase 2: Install a prepared replica into the XArray (under PTL).
 *
 * This is the only path that calls xa_store() on the replica XArray.
 * Returns the replica folio on success (caller should map it), or NULL
 * on failure (caller should discard the prepared folio).
 *
 * @old_out: receives any replaced old replica for deferred cleanup.
 *           Caller MUST call numa_replica_cleanup_old() after releasing
 *           PTL -- replica_unmap_and_free() sleeps.
 */
struct folio *numa_replica_install(struct vm_area_struct *vma,
				   struct folio *prepared, pgoff_t pgoff,
				   struct folio **old_out)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct numa_replica_tree *nrt;
	unsigned long key;
	int nid;
	void *old;

	*old_out = NULL;

	nrt = numa_replica_tree_for_mapping(mapping);
	if (!nrt)
		return NULL;

	nid = folio_nid(prepared);
	key = replica_key(pgoff, nid);

	old = xa_store(&nrt->replicas, key, prepared, GFP_NOWAIT | __GFP_ACCOUNT);
	if (xa_is_err(old))
		return NULL;

	if (old && !xa_is_value(old)) {
		atomic_long_dec(&node_nr_replicas[folio_nid(old)]);
		atomic_long_dec(&nrt->nr_replicas);
		*old_out = old;
	}

	folio_get(prepared); /* XArray holds one ref, caller gets the other */
	atomic_long_inc(&node_nr_replicas[nid]);
	atomic_long_inc(&nrt->nr_replicas);

	count_vm_event(NUMA_REPLICA_CREATED);
	trace_numa_replica_create(prepared, nid, pgoff);

	return prepared;
}

/*
 * Erase and free a single replica for (@pgoff, @nid).
 * Called from memory_failure where we know exactly which replica is
 * affected and do not need to invalidate replicas on other nodes.
 *
 * Uses xa_erase() return value to avoid double-free races with the
 * shrinker: only the path that successfully erases owns the folio.
 */
void numa_replica_invalidate_one(struct numa_replica_tree *nrt,
				 pgoff_t pgoff, int nid)
{
	struct folio *folio;
	unsigned long key;

	if (!nrt)
		return;

	key = replica_key(pgoff, nid);
	folio = xa_erase(&nrt->replicas, key);
	if (!folio)
		return;

	atomic_long_dec(&node_nr_replicas[nid]);
	atomic_long_dec(&nrt->nr_replicas);
	replica_unmap_and_free(folio, nid, pgoff, "hwpoison");
}

/*
 * Unmap and drop all replicas for @pgoff.
 * Called on reclaim/truncate where sleeping is allowed.
 *
 * Uses xa_erase() return value to avoid double-free races with the
 * shrinker: only the path that successfully erases owns the folio.
 */
void numa_replica_invalidate(struct numa_replica_tree *nrt, pgoff_t pgoff)
{
	unsigned long start, end;
	struct folio *folio;
	unsigned long index;

	if (!nrt)
		return;

	start = replica_key(pgoff, 0);
	end = replica_key(pgoff, MAX_NUMNODES - 1);

	xa_for_each_range(&nrt->replicas, index, folio, start, end) {
		folio = xa_erase(&nrt->replicas, index);
		if (!folio)
			continue;
		atomic_long_dec(&node_nr_replicas[replica_key_nid(index)]);
		atomic_long_dec(&nrt->nr_replicas);
		replica_unmap_and_free(folio, replica_key_nid(index),
				      pgoff, "invalidate");
	}
}

/*
 * Unmap and drop all replicas in [start, end].
 * Called on truncation/hole punch and MADV_NUMA_NOREPLICATE.
 */
void numa_replica_invalidate_range(struct numa_replica_tree *nrt,
				   pgoff_t start, pgoff_t end)
{
	unsigned long key_start, key_end;
	struct folio *folio;
	unsigned long index;

	if (!nrt)
		return;

	key_start = replica_key(start, 0);
	key_end = replica_key(end, MAX_NUMNODES - 1);

	xa_for_each_range(&nrt->replicas, index, folio, key_start, key_end) {
		folio = xa_erase(&nrt->replicas, index);
		if (!folio)
			continue;
		atomic_long_dec(&node_nr_replicas[replica_key_nid(index)]);
		atomic_long_dec(&nrt->nr_replicas);
		replica_unmap_and_free(folio, replica_key_nid(index),
				      replica_key_pgoff(index), "truncate");
	}
}

/*
 * Invalidate replicas when a page is dirtied.  Called from
 * folio_mark_dirty() / set_page_dirty() paths which may execute
 * under PTL (e.g. zap_present_ptes -> folio_mark_dirty).
 *
 * This must be non-sleeping.  We remove replicas from the XArray
 * (atomic) and queue deferred unmap+free via a global list and static
 * work item.  The deferred worker calls folio_lock + try_to_unmap +
 * folio_put to ensure stale PTEs are removed and the replica is fully
 * freed.  Replica folios keep their mapping set on the list so
 * try_to_unmap() can find PTEs; this guarantees coherence even under
 * GFP_ATOMIC pressure.
 *
 * Uses xa_erase() return value to avoid double-free races.
 */
void numa_replica_invalidate_dirty(struct address_space *mapping,
				   pgoff_t pgoff)
{
	struct numa_replica_tree *nrt;
	unsigned long start, end;
	struct folio *folio;
	unsigned long index;
	bool queued = false;

	if (!mapping)
		return;

	nrt = numa_replica_tree_for_mapping(mapping);
	if (!nrt)
		return;

	start = replica_key(pgoff, 0);
	end = replica_key(pgoff, MAX_NUMNODES - 1);

	xa_for_each_range(&nrt->replicas, index, folio, start, end) {
		folio = xa_erase(&nrt->replicas, index);
		if (!folio)
			continue;
		atomic_long_dec(&node_nr_replicas[replica_key_nid(index)]);
		atomic_long_dec(&nrt->nr_replicas);

		/*
		 * Queue folio for deferred unmap+free.  The folio keeps
		 * its mapping set so try_to_unmap() can find PTEs.
		 * Replica folios are not on the LRU, so folio->lru is
		 * available as a list node.
		 */
		spin_lock(&dirty_cleanup_lock);
		list_add_tail(&folio->lru, &dirty_cleanup_list);
		queued = true;
		spin_unlock(&dirty_cleanup_lock);
	}
	if (queued)
		schedule_work(&dirty_cleanup_static_work);
}

/*
 * Discard an unused prepared replica folio.  Clears mapping (and the
 * FOLIO_MAPPING_REPLICA bit with it), then drops the reference.
 */
void numa_replica_discard_prepared(struct folio *prepared)
{
	if (!prepared)
		return;
	prepared->mapping = NULL;
	folio_put(prepared);
}

/*
 * Clean up a replaced replica folio after the caller has released PTL.
 * This is the deferred path for old replicas displaced by numa_replica_install().
 */
void numa_replica_cleanup_old(struct folio *old)
{
	if (!old)
		return;
	replica_unmap_and_free(old, folio_nid(old), old->index, "replace");
}

long numa_replica_node_count(int nid)
{
	if (nid < 0 || nid >= MAX_NUMNODES)
		return 0;
	return atomic_long_read(&node_nr_replicas[nid]);
}

/* --- Shrinker --- */

static struct shrinker *replica_shrinker;

static unsigned long
replica_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	unsigned long total = 0;
	int nid;

	if (sysctl_numa_replicate_pinned)
		return 0;

	if (sc->nid != NUMA_NO_NODE)
		return atomic_long_read(&node_nr_replicas[sc->nid]);

	for_each_node_state(nid, N_MEMORY)
		total += atomic_long_read(&node_nr_replicas[nid]);
	return total;
}

#define SHRINK_BATCH 16

/*
 * Collect replicas under the lock, then drop the lock and unmap/free them.
 * try_to_unmap() can sleep so it cannot be called under replica_trees_lock.
 *
 * The scan position (tree + XArray index) is saved between calls so that
 * each batch picks up where the previous one left off, avoiding O(n)
 * re-scan of already-visited entries under the global spinlock.
 *
 * The shrinker acquires replica folio locks independently, never while
 * holding a canonical folio lock.  This preserves the lock ordering
 * (canonical -> replica) documented in the file header.
 */
static unsigned long
replica_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	struct folio *batch[SHRINK_BATCH];
	struct numa_replica_tree_entry *entry;
	unsigned long freed = 0;
	unsigned long to_scan = sc->nr_to_scan;
	int target_nid = sc->nid;
	int nr_collected;
	int i;
	bool wrapped = false;

	if (sysctl_numa_replicate_pinned)
		return SHRINK_STOP;

	while (freed < to_scan) {
		nr_collected = 0;

		spin_lock(&replica_trees_lock);

		if (list_empty(&replica_trees_list)) {
			spin_unlock(&replica_trees_lock);
			break;
		}

		/* Resume from saved position or start from the head */
		if (!shrink_scan_entry ||
		    list_entry_is_head(shrink_scan_entry,
				      &replica_trees_list, list))
			shrink_scan_entry = list_first_entry(
				&replica_trees_list,
				struct numa_replica_tree_entry, list);

		entry = shrink_scan_entry;
		list_for_each_entry_from(entry, &replica_trees_list, list) {
			struct numa_replica_tree *nrt = &entry->tree;
			struct folio *folio;
			unsigned long index = (entry == shrink_scan_entry) ?
					      shrink_scan_index : 0;

			xa_for_each_start(&nrt->replicas, index, folio,
					  index) {
				struct folio *erased;

				if (nr_collected >= SHRINK_BATCH) {
					/* Save position for next call */
					shrink_scan_entry = entry;
					shrink_scan_index = index + 1;
					goto batch_full;
				}

				if (target_nid != NUMA_NO_NODE &&
				    folio_nid(folio) != target_nid)
					continue;

				/*
				 * xa_erase() inside xa_for_each_start() is safe:
				 * the iterator uses RCU for traversal while
				 * xa_erase() takes the xa_lock internally.
				 */
				erased = xa_erase(&nrt->replicas, index);
				if (!erased)
					continue;
				atomic_long_dec(&node_nr_replicas[folio_nid(erased)]);
				atomic_long_dec(&nrt->nr_replicas);
				batch[nr_collected++] = erased;
			}

			/*
			 * Finished scanning this tree.  If we collected any
			 * folios, save position at the next tree and break
			 * to free them outside the lock.  This bounds lock
			 * hold time to one tree's scan rather than all trees.
			 */
			if (nr_collected > 0) {
				struct list_head *next = entry->list.next;

				if (next != &replica_trees_list) {
					shrink_scan_entry = list_entry(next,
						struct numa_replica_tree_entry,
						list);
					shrink_scan_index = 0;
				} else {
					shrink_scan_entry = NULL;
					shrink_scan_index = 0;
				}
				goto batch_full;
			}
		}

		/*
		 * Reached the end of all trees.  Wrap around for the next
		 * scan call.  If we already wrapped in this invocation,
		 * there is nothing left to reclaim.
		 */
		shrink_scan_entry = NULL;
		shrink_scan_index = 0;
		if (!nr_collected && !wrapped) {
			wrapped = true;
			spin_unlock(&replica_trees_lock);
			continue;
		}
batch_full:
		spin_unlock(&replica_trees_lock);

		if (!nr_collected)
			break;

		for (i = 0; i < nr_collected; i++) {
			folio_lock(batch[i]);
			try_to_unmap(batch[i], 0);
			batch[i]->mapping = NULL;
			folio_unlock(batch[i]);
			count_vm_event(NUMA_REPLICA_DROPPED);
			folio_put(batch[i]);
		}
		freed += nr_collected;
	}

	return freed ? freed : SHRINK_STOP;
}

/* --- Sysctl --- */

#ifdef CONFIG_SYSCTL
static const struct ctl_table numa_replicate_sysctls[] = {
	{
		.procname	= "numa_replicate_enabled",
		.data		= &sysctl_numa_replicate_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "numa_replicate_pinned",
		.data		= &sysctl_numa_replicate_pinned,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "numa_replicate_max_per_node",
		.data		= &sysctl_numa_replicate_max_per_node,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
};
#endif

static int __init numa_replicate_init(void)
{
	int nid;

	for_each_node_state(nid, N_MEMORY)
		atomic_long_set(&node_nr_replicas[nid], 0);

	replica_shrinker = shrinker_alloc(SHRINKER_NUMA_AWARE,
					  "mm-numa-replicas");
	if (!replica_shrinker)
		return -ENOMEM;

	replica_shrinker->count_objects = replica_shrink_count;
	replica_shrinker->scan_objects = replica_shrink_scan;
	replica_shrinker->seeks = DEFAULT_SEEKS;
	shrinker_register(replica_shrinker);

#ifdef CONFIG_SYSCTL
	register_sysctl_init("vm", numa_replicate_sysctls);
#endif

	pr_info("NUMA page replication initialized\n");
	return 0;
}
late_initcall(numa_replicate_init);

#ifdef CONFIG_DEBUG_FS
static int numa_replicate_stats_show(struct seq_file *m, void *v)
{
	struct numa_replica_tree_entry *entry;
	int nid;
	unsigned long total = 0;

	seq_puts(m, "Per-node replica pages:\n");
	for_each_node_state(nid, N_MEMORY) {
		long count = atomic_long_read(&node_nr_replicas[nid]);

		seq_printf(m, "  Node %d: %ld pages (%ld KB)\n",
			   nid, count, count << (PAGE_SHIFT - 10));
		total += count;
	}
	seq_printf(m, "  Total:  %lu pages (%lu KB)\n\n", total, total << (PAGE_SHIFT - 10));

	seq_puts(m, "Per-mapping replica trees:\n");
	spin_lock(&replica_trees_lock);
	list_for_each_entry(entry, &replica_trees_list, list) {
		struct numa_replica_tree *nrt = &entry->tree;
		struct inode *inode = nrt->mapping ? nrt->mapping->host : NULL;
		long nr = atomic_long_read(&nrt->nr_replicas);

		if (inode)
			seq_printf(m, "  ino %lu dev %d:%d: %ld replicas\n",
				   inode->i_ino,
				   MAJOR(inode->i_sb->s_dev),
				   MINOR(inode->i_sb->s_dev),
				   nr);
		else
			seq_printf(m, "  (unknown): %ld replicas\n", nr);
	}
	spin_unlock(&replica_trees_lock);

	seq_printf(m, "\nConfig: enabled=%d pinned=%d max_per_node=%lu\n",
		   sysctl_numa_replicate_enabled,
		   sysctl_numa_replicate_pinned,
		   sysctl_numa_replicate_max_per_node);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(numa_replicate_stats);

static int __init numa_replicate_debugfs_init(void)
{
	debugfs_create_file("numa_replicate", 0444, NULL, NULL,
			    &numa_replicate_stats_fops);
	return 0;
}
late_initcall(numa_replicate_debugfs_init);
#endif
