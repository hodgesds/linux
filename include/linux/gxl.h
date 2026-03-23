/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_GXL_H
#define _LINUX_GXL_H

#include <linux/types.h>

struct folio;

#ifdef CONFIG_GXL
int gxl_copy_folio(struct folio *dst, struct folio *src);
#else
static inline int gxl_copy_folio(struct folio *dst, struct folio *src)
{
	return -1;
}
#endif

#endif /* _LINUX_GXL_H */
