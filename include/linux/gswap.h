/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_GSWAP_H
#define _LINUX_GSWAP_H

#include <linux/types.h>
#include <linux/mm_types.h>

#ifdef CONFIG_GSWAP

bool gswap_store(struct folio *folio);
int gswap_load(struct folio *folio);
void gswap_invalidate(swp_entry_t swp);
int gswap_swapon(int type, unsigned long nr_pages, unsigned long flags);
void gswap_swapoff(int type);

#else

static inline bool gswap_store(struct folio *folio)
{
	return false;
}

static inline int gswap_load(struct folio *folio)
{
	return -ENOENT;
}

static inline void gswap_invalidate(swp_entry_t swp) {}

static inline int gswap_swapon(int type, unsigned long nr_pages,
			      unsigned long flags)
{
	return 0;
}

static inline void gswap_swapoff(int type) {}

#endif /* CONFIG_GSWAP */

#endif /* _LINUX_GSWAP_H */
