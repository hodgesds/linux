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
 * GPU VRAM over PCIe.  A backend is selected by name via the zswap.backend=
 * parameter; the operations mirror exactly what the zswap store/load paths
 * need from zsmalloc, nothing more.
 */

/* caps bits */
#define ZSWAP_BE_BATCH	(1u << 0)	/* benefits from batched cluster loads */

/* Max folios handed to zswap_load_folios() / a backend ->load() in one call. */
#define ZSWAP_LOAD_BATCH	16

/* One element of a batched load: read object @handle (@len bytes) into @buf. */
struct zswap_io_req {
	unsigned long	handle;
	void		*buf;		/* backend fills; valid until load_done() */
	size_t		len;
	int		error;		/* per-request status (0 == ok) */
};

struct zswap_backend {
	const char	*name;
	struct module	*owner;
	unsigned int	caps;
	void		*(*create)(const char *name);
	void		(*destroy)(void *pool);
	unsigned long	(*malloc)(void *pool, size_t size, gfp_t gfp, int nid);
	void		(*free)(void *pool, unsigned long handle);
	void		(*write)(void *pool, unsigned long handle,
				 void *buf, size_t len);
	void		(*read_begin)(void *pool, unsigned long handle,
				      struct scatterlist *sg, size_t len);
	void		(*read_end)(void *pool, unsigned long handle,
				    struct scatterlist *sg);
	/*
	 * Batch-native load: pull N objects' compressed bytes into reqs[i].buf
	 * in one gather; zswap decompresses each individually, then calls
	 * load_done() to release the buffers.  Optional -- present when the
	 * backend sets ZSWAP_BE_BATCH.  Single page is just n == 1.
	 */
	void		(*load)(void *pool, struct zswap_io_req *reqs, int n);
	void		(*load_done)(void *pool, struct zswap_io_req *reqs, int n);
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
bool zswap_load_can_batch(void);
void zswap_load_folios(struct folio **folios, int n, bool *handled);
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

static inline bool zswap_load_can_batch(void)
{
	return false;
}
static inline void zswap_load_folios(struct folio **folios, int n,
				     bool *handled) {}
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
