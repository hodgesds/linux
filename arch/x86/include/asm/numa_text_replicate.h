/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_NUMA_TEXT_REPLICATE_H
#define _ASM_X86_NUMA_TEXT_REPLICATE_H

#include <asm/pgtable_types.h>

#ifdef CONFIG_NUMA_PAGE_REPLICATE

extern int sysctl_numa_text_replicate;

void numa_replicate_kernel_text(void);
void numa_text_replicate_pgd_init(pgd_t *pgd);

#else

static inline void numa_replicate_kernel_text(void) {}
static inline void numa_text_replicate_pgd_init(pgd_t *pgd) {}

#endif /* CONFIG_NUMA_PAGE_REPLICATE */
#endif /* _ASM_X86_NUMA_TEXT_REPLICATE_H */
