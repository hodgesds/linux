/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ZSWAP_H
#define _LINUX_ZSWAP_H

#include <linux/types.h>
#include <linux/mm_types.h>

struct lruvec;
struct scatterlist;
struct module;

extern atomic_long_t zswap_stored_pages;

/*
 * Pluggable storage backend for compressed pages.  The default backend is
 * zsmalloc (host RAM).  An alternative (zvram) stores the compressed pages in
 * GPU VRAM over PCIe.  A backend is selected by name via the zswap.zpool=
 * parameter; the operations mirror exactly what the zswap store/load paths
 * need from zsmalloc, nothing more.
 */
struct zswap_backend {
	const char	*name;
	struct module	*owner;
	void		*(*create)(const char *name);
	void		(*destroy)(void *pool);
	unsigned long	(*malloc)(void *pool, size_t size, gfp_t gfp, int nid);
	void		(*free)(void *pool, unsigned long handle);
	void		(*write)(void *pool, unsigned long handle,
				 void *buf, size_t len);
	void		(*read_begin)(void *pool, unsigned long handle,
				      struct scatterlist *sg, size_t len);
	void		(*read_end)(void *pool, unsigned long handle);
	u64		(*total_pages)(void *pool);
};

int zswap_register_backend(struct zswap_backend *backend);
void zswap_unregister_backend(struct zswap_backend *backend);

#ifdef CONFIG_ZSWAP

struct zswap_lruvec_state {
	/*
	 * Number of swapped in pages from disk, i.e not found in the zswap pool.
	 *
	 * This is consumed and subtracted from the lru size in
	 * zswap_shrinker_count() to penalize past overshrinking that led to disk
	 * swapins. The idea is that had we considered this many more pages in the
	 * LRU active/protected and not written them back, we would not have had to
	 * swapped them in.
	 */
	atomic_long_t nr_disk_swapins;
};

unsigned long zswap_total_pages(void);
bool zswap_store(struct folio *folio);
int zswap_load(struct folio *folio);
void zswap_invalidate(swp_entry_t swp);
int zswap_swapon(int type, unsigned long nr_pages);
void zswap_swapoff(int type);
void zswap_memcg_offline_cleanup(struct mem_cgroup *memcg);
void zswap_lruvec_state_init(struct lruvec *lruvec);
void zswap_folio_swapin(struct folio *folio);
bool zswap_is_enabled(void);
bool zswap_never_enabled(void);
#else

struct zswap_lruvec_state {};

static inline bool zswap_store(struct folio *folio)
{
	return false;
}

static inline int zswap_load(struct folio *folio)
{
	return -ENOENT;
}

static inline void zswap_invalidate(swp_entry_t swp) {}
static inline int zswap_swapon(int type, unsigned long nr_pages)
{
	return 0;
}
static inline void zswap_swapoff(int type) {}
static inline void zswap_memcg_offline_cleanup(struct mem_cgroup *memcg) {}
static inline void zswap_lruvec_state_init(struct lruvec *lruvec) {}
static inline void zswap_folio_swapin(struct folio *folio) {}

static inline bool zswap_is_enabled(void)
{
	return false;
}

static inline bool zswap_never_enabled(void)
{
	return true;
}

#endif

#endif /* _LINUX_ZSWAP_H */
