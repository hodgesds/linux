/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NUMA_REPLICATE_H
#define _LINUX_NUMA_REPLICATE_H

#include <linux/xarray.h>
#include <linux/nodemask_types.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/jump_label.h>

struct address_space;
struct folio;
struct vm_area_struct;

#ifdef CONFIG_NUMA_PAGE_REPLICATE

DECLARE_STATIC_KEY_FALSE(numa_replicate_active);

static inline bool numa_replicate_is_active(void)
{
	return static_branch_unlikely(&numa_replicate_active);
}

/*
 * Per-address_space replica tracking.  XArray keyed by composite key
 * encoding both pgoff and nid: key = (pgoff << NODES_SHIFT) | nid
 *
 * Mappings with replicas are registered in a global XArray keyed by
 * address_space pointer, avoiding any additions to struct address_space.
 *
 * Serialization of replica XArray mutations:
 *  - xa_store() is called only from numa_replica_install() under PTL.
 *  - xa_erase() is called from invalidation paths and the shrinker.
 *    All erase paths check the xa_erase() return value: only the path
 *    that gets a non-NULL return owns the folio and may free it.  This
 *    prevents double folio_put() when the shrinker races with
 *    invalidation.
 *  - Counter decrements (nr_replicas, node_nr_replicas) are performed
 *    only by the path that successfully erased the entry.
 */
struct numa_replica_tree {
	struct xarray		replicas;
	atomic_long_t		nr_replicas;
	struct address_space	*mapping;
};

static inline unsigned long replica_key(pgoff_t pgoff, int nid)
{
	BUILD_BUG_ON(NODES_SHIFT > BITS_PER_LONG / 2);
	return ((unsigned long)pgoff << NODES_SHIFT) | nid;
}

static inline pgoff_t replica_key_pgoff(unsigned long key)
{
	return key >> NODES_SHIFT;
}

static inline int replica_key_nid(unsigned long key)
{
	return key & (MAX_NUMNODES - 1);
}

struct numa_replica_tree *numa_replica_tree_for_mapping(
		struct address_space *mapping);
struct numa_replica_tree *numa_replica_tree_alloc(struct address_space *mapping);
struct numa_replica_tree *numa_replica_tree_alloc_sleepable(
		struct address_space *mapping);
void numa_replica_tree_free(struct numa_replica_tree *nrt);

int numa_replica_tree_register(struct address_space *mapping,
			       struct numa_replica_tree *nrt);
struct numa_replica_tree *numa_replica_tree_unregister(
		struct address_space *mapping);

struct folio *numa_replica_lookup(struct numa_replica_tree *nrt,
				  pgoff_t pgoff, int nid);

/*
 * Replica context for the two-phase create/install pattern used in
 * fault paths.  Bundles the prepared and old replica pointers so
 * callers do not need to thread two separate folio pointers through
 * the fault code.
 */
struct numa_replica_ctx {
	struct folio	*prepared;	/* phase 1 output, NULL if none */
	struct folio	*old;		/* replaced replica, cleanup after PTL */
};

static inline void numa_replica_ctx_init(struct numa_replica_ctx *ctx)
{
	ctx->prepared = NULL;
	ctx->old = NULL;
}

/*
 * Two-phase replica creation for use around PTL:
 *
 *  Phase 1 (before PTL): numa_replica_prepare() allocates a folio on
 *  the target NUMA node and copies data from the canonical folio.
 *  The prepared folio has FOLIO_MAPPING_REPLICA set in its mapping
 *  pointer and index configured, but is NOT yet in the XArray.
 *
 *  Phase 2 (under PTL): numa_replica_install() inserts the prepared
 *  folio into the XArray via xa_store(GFP_NOWAIT).  On failure or if
 *  no longer needed, the caller puts the prepared folio.
 */
struct folio *numa_replica_prepare(struct vm_area_struct *vma,
				   struct folio *canonical, pgoff_t pgoff);
struct folio *numa_replica_install(struct vm_area_struct *vma,
				   struct folio *prepared, pgoff_t pgoff,
				   struct folio **old_out);

void numa_replica_invalidate(struct numa_replica_tree *nrt, pgoff_t pgoff);
void numa_replica_invalidate_one(struct numa_replica_tree *nrt,
				 pgoff_t pgoff, int nid);
void numa_replica_invalidate_range(struct numa_replica_tree *nrt,
				   pgoff_t start, pgoff_t end);
void numa_replica_invalidate_dirty(struct address_space *mapping,
				   pgoff_t pgoff);

void numa_replica_cleanup_old(struct folio *old);
void numa_replica_discard_prepared(struct folio *prepared);

extern int sysctl_numa_replicate_enabled;
extern int sysctl_numa_replicate_pinned;
extern unsigned long sysctl_numa_replicate_max_per_node;

long numa_replica_node_count(int nid);

#else /* !CONFIG_NUMA_PAGE_REPLICATE */

static inline bool numa_replicate_is_active(void) { return false; }

struct numa_replica_tree;

static inline struct numa_replica_tree *
numa_replica_tree_for_mapping(struct address_space *mapping)
{
	return NULL;
}

static inline struct numa_replica_tree *
numa_replica_tree_alloc(struct address_space *mapping)
{
	return NULL;
}

static inline void numa_replica_tree_free(struct numa_replica_tree *nrt) {}

static inline struct folio *
numa_replica_lookup(struct numa_replica_tree *nrt, pgoff_t pgoff, int nid)
{
	return NULL;
}

static inline struct folio *
numa_replica_prepare(struct vm_area_struct *vma, struct folio *canonical,
		     pgoff_t pgoff)
{
	return NULL;
}

static inline struct folio *
numa_replica_install(struct vm_area_struct *vma, struct folio *prepared,
		     pgoff_t pgoff, struct folio **old_out)
{
	return NULL;
}

static inline void
numa_replica_invalidate(struct numa_replica_tree *nrt, pgoff_t pgoff) {}

static inline void
numa_replica_invalidate_one(struct numa_replica_tree *nrt,
			    pgoff_t pgoff, int nid) {}

static inline void
numa_replica_invalidate_range(struct numa_replica_tree *nrt,
			      pgoff_t start, pgoff_t end) {}

static inline void
numa_replica_invalidate_dirty(struct address_space *mapping, pgoff_t pgoff) {}

static inline void numa_replica_cleanup_old(struct folio *old) {}
static inline void numa_replica_discard_prepared(struct folio *prepared) {}

#endif /* CONFIG_NUMA_PAGE_REPLICATE */
#endif /* _LINUX_NUMA_REPLICATE_H */
