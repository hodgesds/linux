// SPDX-License-Identifier: GPL-2.0
/*
 * NUMA Page Replication
 *
 * Replicate read-only file-backed pages across NUMA nodes so each CPU
 * accesses a NUMA-local copy.  Replica folios live in a per-address_space
 * XArray keyed by (pgoff, nid), separate from the page cache.
 *
 * Limitation: replicas are static copies.  If another process modifies the
 * underlying file (via a writable MAP_SHARED mapping), existing replicas
 * become stale.  This does not affect the intended use case (shared library
 * .text/.rodata which is never written at runtime).
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

#define CREATE_TRACE_POINTS
#include <trace/events/numa_replicate.h>

int sysctl_numa_replicate_enabled __read_mostly = 1;
int sysctl_numa_replicate_pinned __read_mostly;
unsigned long sysctl_numa_replicate_max_per_node __read_mostly;
int sysctl_numa_replicate_auto __read_mostly = 1;

static atomic_long_t node_nr_replicas[MAX_NUMNODES];

/* Global list of replica trees for shrinker iteration */
static LIST_HEAD(replica_trees_list);
static DEFINE_SPINLOCK(replica_trees_lock);

struct numa_replica_tree_entry {
	struct numa_replica_tree tree;
	struct list_head list;
};

static inline struct numa_replica_tree_entry *
tree_to_entry(struct numa_replica_tree *nrt)
{
	return container_of(nrt, struct numa_replica_tree_entry, tree);
}

static struct shrinker *replica_shrinker;

struct numa_replica_tree *numa_replica_tree_alloc(struct address_space *mapping)
{
	struct numa_replica_tree_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_NOWAIT);
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

void numa_replica_tree_free(struct numa_replica_tree *nrt)
{
	struct numa_replica_tree_entry *entry;
	struct folio *folio;
	unsigned long index;

	if (!nrt)
		return;

	entry = tree_to_entry(nrt);

	spin_lock(&replica_trees_lock);
	list_del(&entry->list);
	spin_unlock(&replica_trees_lock);

	xa_for_each(&nrt->replicas, index, folio) {
		int nid = folio_nid(folio);

		xa_erase(&nrt->replicas, index);
		atomic_long_dec(&node_nr_replicas[nid]);
		atomic_long_dec(&nrt->nr_replicas);
		count_vm_event(NUMA_REPLICA_DROPPED);
		trace_numa_replica_drop(folio, nid,
					replica_key_pgoff(index), "destroy");
		folio_put(folio);
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
 * Allocate a replica on @nid, copy from @canonical, insert into @nrt.
 * Returns replica folio with a reference, or NULL.  Best-effort: all
 * allocations use GFP_NOWAIT since callers hold PTL or rcu_read_lock.
 */
struct folio *numa_replica_create(struct numa_replica_tree *nrt,
				  struct folio *canonical, pgoff_t pgoff,
				  int nid)
{
	struct folio *replica;
	void *src, *dst;
	unsigned long key;
	void *old;

	if (!nrt || !sysctl_numa_replicate_enabled)
		return NULL;

	if (folio_nid(canonical) == nid)
		return NULL;

	if (!check_node_replica_limit(nid))
		return NULL;

	if (!node_has_memory_headroom(nid))
		return NULL;

	replica = __folio_alloc_node(GFP_NOWAIT | __GFP_NOWARN, 0, nid);
	if (!replica)
		return NULL;

	src = kmap_local_folio(canonical, 0);
	dst = kmap_local_folio(replica, 0);
	memcpy(dst, src, PAGE_SIZE);
	kunmap_local(dst);
	kunmap_local(src);

	/*
	 * Point replica's mapping/index at the canonical's address_space
	 * so rmap can find VMAs via i_mmap when unmapping this folio.
	 */
	replica->mapping = canonical->mapping;
	replica->index = pgoff;

	key = replica_key(pgoff, nid);
	old = xa_store(&nrt->replicas, key, replica, GFP_NOWAIT);
	if (xa_is_err(old)) {
		folio_put(replica);
		return NULL;
	}

	if (old && !xa_is_value(old)) {
		atomic_long_dec(&node_nr_replicas[folio_nid(old)]);
		atomic_long_dec(&nrt->nr_replicas);
		count_vm_event(NUMA_REPLICA_DROPPED);
		folio_put(old);
	}

	folio_get(replica); /* XArray holds one ref, caller gets the other */
	atomic_long_inc(&node_nr_replicas[nid]);
	atomic_long_inc(&nrt->nr_replicas);

	count_vm_event(NUMA_REPLICA_CREATED);
	trace_numa_replica_create(replica, nid, pgoff);

	return replica;
}

/* Drop all replicas for @pgoff (called on reclaim/truncate). */
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
		xa_erase(&nrt->replicas, index);
		atomic_long_dec(&node_nr_replicas[replica_key_nid(index)]);
		atomic_long_dec(&nrt->nr_replicas);
		count_vm_event(NUMA_REPLICA_DROPPED);
		trace_numa_replica_drop(folio, replica_key_nid(index),
					pgoff, "invalidate");
		folio_put(folio);
	}
}

/* Drop all replicas in [start, end] (called on truncation/hole punch). */
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
		xa_erase(&nrt->replicas, index);
		atomic_long_dec(&node_nr_replicas[replica_key_nid(index)]);
		atomic_long_dec(&nrt->nr_replicas);
		count_vm_event(NUMA_REPLICA_DROPPED);
		trace_numa_replica_drop(folio, replica_key_nid(index),
					replica_key_pgoff(index), "truncate");
		folio_put(folio);
	}
}

/*
 * Try to map a NUMA-local replica instead of the canonical folio.
 * Returns the replica folio (with ref) or NULL if not needed/available.
 *
 * Callers should check VM_NUMA_REPLICATE inline before calling this
 * to avoid function call overhead on non-replicated VMAs.
 */
struct folio *numa_replica_try_local(struct vm_area_struct *vma,
				     struct folio *folio, pgoff_t pgoff)
{
	struct address_space *mapping;
	struct numa_replica_tree *nrt;
	struct folio *replica;
	int local_nid;

	if (!sysctl_numa_replicate_enabled || num_online_nodes() < 2)
		return NULL;

	if (folio_test_large(folio) || folio_test_dirty(folio))
		return NULL;

	local_nid = numa_node_id();

	if (folio_nid(folio) == local_nid)
		return NULL;

	mapping = vma->vm_file->f_mapping;

	nrt = mapping->numa_replicas;
	if (!nrt) {
		nrt = numa_replica_tree_alloc(mapping);
		if (!nrt)
			return NULL;
		if (cmpxchg(&mapping->numa_replicas, NULL, nrt) != NULL) {
			numa_replica_tree_free(nrt);
			nrt = mapping->numa_replicas;
		}
	}

	replica = numa_replica_lookup(nrt, pgoff, local_nid);
	if (replica) {
		count_vm_event(NUMA_REPLICA_HIT);
		trace_numa_replica_hit(pgoff, local_nid);
		return replica;
	}

	replica = numa_replica_create(nrt, folio, pgoff, local_nid);
	if (replica)
		return replica;

	count_vm_event(NUMA_REPLICA_MISS);
	return NULL;
}

/* --- Shrinker --- */

static unsigned long
replica_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	if (sysctl_numa_replicate_pinned)
		return 0;

	if (sc->nid != NUMA_NO_NODE)
		return atomic_long_read(&node_nr_replicas[sc->nid]);

	{
		unsigned long total = 0;
		int nid;

		for_each_online_node(nid)
			total += atomic_long_read(&node_nr_replicas[nid]);
		return total;
	}
}

/*
 * Scan one replica tree at a time, dropping the global lock between
 * trees so fault-path tree allocation isn't blocked for the entire scan.
 */
static unsigned long
replica_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	struct numa_replica_tree_entry *entry;
	unsigned long freed = 0;
	unsigned long to_scan = sc->nr_to_scan;
	int target_nid = sc->nid;

	if (sysctl_numa_replicate_pinned)
		return SHRINK_STOP;

	spin_lock(&replica_trees_lock);
	list_for_each_entry(entry, &replica_trees_list, list) {
		struct numa_replica_tree *nrt = &entry->tree;
		struct folio *folio;
		unsigned long index;

		if (freed >= to_scan)
			break;

		xa_for_each(&nrt->replicas, index, folio) {
			if (freed >= to_scan)
				break;

			if (target_nid != NUMA_NO_NODE &&
			    folio_nid(folio) != target_nid)
				continue;

			xa_erase(&nrt->replicas, index);
			atomic_long_dec(&node_nr_replicas[folio_nid(folio)]);
			atomic_long_dec(&nrt->nr_replicas);
			count_vm_event(NUMA_REPLICA_DROPPED);
			trace_numa_replica_drop(folio, folio_nid(folio),
						replica_key_pgoff(index),
						"shrinker");
			folio_put(folio);
			freed++;
		}
	}
	spin_unlock(&replica_trees_lock);

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
	{
		.procname	= "numa_replicate_auto",
		.data		= &sysctl_numa_replicate_auto,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
};
#endif

int __init numa_replicate_init(void)
{
	int nid;

	for_each_node(nid)
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
subsys_initcall(numa_replicate_init);

long numa_replica_node_count(int nid)
{
	if (nid < 0 || nid >= MAX_NUMNODES)
		return 0;
	return atomic_long_read(&node_nr_replicas[nid]);
}

#ifdef CONFIG_DEBUG_FS
static int numa_replicate_stats_show(struct seq_file *m, void *v)
{
	struct numa_replica_tree_entry *entry;
	int nid;
	unsigned long total = 0;

	seq_puts(m, "Per-node replica pages:\n");
	for_each_online_node(nid) {
		long count = atomic_long_read(&node_nr_replicas[nid]);

		seq_printf(m, "  Node %d: %ld pages (%ld KB)\n",
			   nid, count, count * 4);
		total += count;
	}
	seq_printf(m, "  Total:  %lu pages (%lu KB)\n\n", total, total * 4);

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

	seq_printf(m, "\nConfig: enabled=%d pinned=%d auto=%d max_per_node=%lu\n",
		   sysctl_numa_replicate_enabled,
		   sysctl_numa_replicate_pinned,
		   sysctl_numa_replicate_auto,
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
