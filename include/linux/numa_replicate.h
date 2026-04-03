/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NUMA_REPLICATE_H
#define _LINUX_NUMA_REPLICATE_H

#include <linux/xarray.h>
#include <linux/nodemask_types.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>

struct address_space;
struct folio;
struct vm_area_struct;

#ifdef CONFIG_NUMA_PAGE_REPLICATE

/*
 * Per-address_space replica tracking.  XArray keyed by composite key
 * encoding both pgoff and nid: key = (pgoff << NODES_SHIFT) | nid
 */
struct numa_replica_tree {
	struct xarray		replicas;
	atomic_long_t		nr_replicas;
	struct address_space	*mapping;
};

static inline unsigned long replica_key(pgoff_t pgoff, int nid)
{
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

struct numa_replica_tree *numa_replica_tree_alloc(struct address_space *mapping);
void numa_replica_tree_free(struct numa_replica_tree *nrt);

struct folio *numa_replica_lookup(struct numa_replica_tree *nrt,
				  pgoff_t pgoff, int nid);
struct folio *numa_replica_create(struct numa_replica_tree *nrt,
				  struct folio *canonical, pgoff_t pgoff,
				  int nid);
void numa_replica_invalidate(struct numa_replica_tree *nrt, pgoff_t pgoff);
void numa_replica_invalidate_range(struct numa_replica_tree *nrt,
				   pgoff_t start, pgoff_t end);

struct folio *numa_replica_try_local(struct vm_area_struct *vma,
				     struct folio *folio, pgoff_t pgoff);

int __init numa_replicate_init(void);

extern int sysctl_numa_replicate_enabled;
extern int sysctl_numa_replicate_pinned;
extern unsigned long sysctl_numa_replicate_max_per_node;
extern int sysctl_numa_replicate_auto;

long numa_replica_node_count(int nid);

#else /* !CONFIG_NUMA_PAGE_REPLICATE */

struct numa_replica_tree;

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
numa_replica_create(struct numa_replica_tree *nrt, struct folio *canonical,
		    pgoff_t pgoff, int nid)
{
	return NULL;
}

static inline void
numa_replica_invalidate(struct numa_replica_tree *nrt, pgoff_t pgoff) {}

static inline void
numa_replica_invalidate_range(struct numa_replica_tree *nrt,
			      pgoff_t start, pgoff_t end) {}

static inline struct folio *
numa_replica_try_local(struct vm_area_struct *vma, struct folio *folio,
		       pgoff_t pgoff)
{
	return NULL;
}

#endif /* CONFIG_NUMA_PAGE_REPLICATE */
#endif /* _LINUX_NUMA_REPLICATE_H */
