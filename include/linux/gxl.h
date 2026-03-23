/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_GXL_H
#define _LINUX_GXL_H

#include <linux/types.h>

struct folio;
struct list_head;

#ifdef CONFIG_GXL
int gxl_copy_folio(struct folio *dst, struct folio *src);
void gxl_bulk_copy_folios(struct list_head *src_folios,
			  struct list_head *dst_folios);
void gxl_bulk_copy_done(void);
#else
static inline int gxl_copy_folio(struct folio *dst, struct folio *src)
{
	return -1;
}
static inline void gxl_bulk_copy_folios(struct list_head *src_folios,
					struct list_head *dst_folios) { }
static inline void gxl_bulk_copy_done(void) { }
#endif

#endif /* _LINUX_GXL_H */
