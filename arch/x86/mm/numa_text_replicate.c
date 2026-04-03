// SPDX-License-Identifier: GPL-2.0
/*
 * NUMA Kernel Text Replication for x86_64
 *
 * Replicates kernel .text to each NUMA node at boot.  Each mm_struct
 * gets a per-node PGD entry pointing to node-local page copies.
 *
 * sync_global_pgds() is safe: it only fills NONE entries, ours are non-NONE.
 */

#include <linux/mm.h>
#include <linux/numa.h>
#include <linux/nodemask.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/sysctl.h>
#include <linux/init.h>
#include <linux/set_memory.h>
#include <asm-generic/sections.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/setup.h>
#include <asm/numa_text_replicate.h>

struct numa_text_node {
	pud_t		*pud;
	pmd_t		*text_pmd;
	pgd_t		pgd_entry;
	unsigned long	nr_pages;
};

static struct numa_text_node *node_text[MAX_NUMNODES];
static int text_home_node = NUMA_NO_NODE;
static bool numa_text_replicate_active;
int sysctl_numa_text_replicate __read_mostly = 1;

static int text_pgd_idx;
static int text_pud_idx;

static struct page **alloc_node_text_pages(int nid, unsigned long start,
					   unsigned long size,
					   unsigned long *nr_pages_out)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	struct page **pages;
	unsigned long i;

	pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return NULL;

	for (i = 0; i < nr_pages; i++) {
		pages[i] = alloc_pages_node(nid, GFP_KERNEL | __GFP_ZERO, 0);
		if (!pages[i])
			goto fail;

		memcpy(page_address(pages[i]),
		       (void *)(start + i * PAGE_SIZE), PAGE_SIZE);
	}

	*nr_pages_out = nr_pages;
	return pages;

fail:
	while (i--)
		__free_page(pages[i]);
	kvfree(pages);
	return NULL;
}

/*
 * Build a PMD table with per-node text pages.  Non-text entries are
 * copied from the original; text entries are split from 2MB to 4K PTEs
 * pointing to the replicated pages.
 */
static pmd_t *build_text_pmd(pmd_t *orig_pmd, struct page **text_pages,
			     unsigned long text_start, unsigned long text_size)
{
	pmd_t *new_pmd;
	unsigned long addr;
	unsigned long page_idx = 0;
	int i;

	new_pmd = (pmd_t *)get_zeroed_page(GFP_KERNEL);
	if (!new_pmd)
		return NULL;

	for (i = 0; i < PTRS_PER_PMD; i++)
		new_pmd[i] = orig_pmd[i];

	for (addr = text_start; addr < text_start + text_size;
	     addr += PMD_SIZE) {
		int pmd_idx = pmd_index(addr);
		pte_t *pte_page;
		unsigned long offset;

		pte_page = (pte_t *)get_zeroed_page(GFP_KERNEL);
		if (!pte_page)
			goto fail;

		for (offset = 0; offset < PMD_SIZE && page_idx < (text_size >> PAGE_SHIFT);
		     offset += PAGE_SIZE) {
			unsigned long pte_idx = pte_index(addr + offset);

			set_pte(&pte_page[pte_idx],
				pfn_pte(page_to_pfn(text_pages[page_idx]),
					PAGE_KERNEL_ROX));
			page_idx++;
		}

		set_pmd(&new_pmd[pmd_idx],
			__pmd(__pa(pte_page) | _PAGE_TABLE));
	}

	return new_pmd;

fail:
	for (addr = text_start; addr < text_start + text_size;
	     addr += PMD_SIZE) {
		int pmd_idx = pmd_index(addr);
		pmd_t entry = new_pmd[pmd_idx];

		if (!pmd_none(entry) && !pmd_leaf(entry)) {
			unsigned long pte_page_addr = pmd_page_vaddr(entry);
			free_page(pte_page_addr);
		}
	}
	free_page((unsigned long)new_pmd);
	return NULL;
}

static pud_t *build_node_pud(pud_t *orig_pud, pmd_t *text_pmd)
{
	pud_t *new_pud;
	int i;

	new_pud = (pud_t *)get_zeroed_page(GFP_KERNEL);
	if (!new_pud)
		return NULL;

	for (i = 0; i < PTRS_PER_PUD; i++)
		new_pud[i] = orig_pud[i];

	set_pud(&new_pud[text_pud_idx],
		__pud(__pa(text_pmd) | _PAGE_TABLE));

	return new_pud;
}

/* Called from mark_rodata_ro() after kernel text is made read-only. */
void __ref numa_replicate_kernel_text(void)
{
	unsigned long text_start = PFN_ALIGN((unsigned long)_text);
	unsigned long text_end = PFN_ALIGN((unsigned long)_etext);
	unsigned long text_size = text_end - text_start;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *orig_pud;
	pmd_t *orig_pmd;
	int nid;

	if (!sysctl_numa_text_replicate)
		return;

	if (num_online_nodes() < 2) {
		pr_info("NUMA text replicate: single node, skipping\n");
		return;
	}

	text_home_node = page_to_nid(virt_to_page(_text));

	text_pgd_idx = pgd_index((unsigned long)_text);
	text_pud_idx = pud_index((unsigned long)_text);

	pgd = pgd_offset_k((unsigned long)_text);
	p4d = p4d_offset(pgd, (unsigned long)_text);
	orig_pud = (pud_t *)p4d_pgtable(*p4d);
	orig_pmd = pmd_offset(&orig_pud[text_pud_idx], (unsigned long)_text);
	orig_pmd = (pmd_t *)((unsigned long)orig_pmd & PAGE_MASK);

	pr_info("NUMA text replicate: text=%lx-%lx (%lu KB) on node %d\n",
		text_start, text_end, text_size >> 10, text_home_node);
	pr_info("NUMA text replicate: PGD[%d] PUD[%d]\n",
		text_pgd_idx, text_pud_idx);

	for_each_online_node(nid) {
		struct numa_text_node *ntn;
		struct page **pages;
		unsigned long nr_pages;

		ntn = kzalloc(sizeof(*ntn), GFP_KERNEL);
		if (!ntn)
			continue;

		if (nid == text_home_node) {
			ntn->pud = orig_pud;
			ntn->text_pmd = orig_pmd;
			ntn->pgd_entry = *pgd;
			ntn->nr_pages = 0;
			node_text[nid] = ntn;
			continue;
		}

		pages = alloc_node_text_pages(nid, text_start, text_size,
					      &nr_pages);
		if (!pages) {
			pr_warn("NUMA text replicate: node %d alloc failed\n",
				nid);
			kfree(ntn);
			continue;
		}

		ntn->text_pmd = build_text_pmd(orig_pmd, pages, text_start,
					       text_size);
		if (!ntn->text_pmd) {
			unsigned long j;

			pr_warn("NUMA text replicate: node %d PMD failed\n",
				nid);
			for (j = 0; j < nr_pages; j++)
				__free_page(pages[j]);
			kvfree(pages);
			kfree(ntn);
			continue;
		}
		kvfree(pages);

		ntn->pud = build_node_pud(orig_pud, ntn->text_pmd);
		if (!ntn->pud) {
			unsigned long a;

			pr_warn("NUMA text replicate: node %d PUD failed\n",
				nid);
			for (a = text_start; a < text_start + text_size;
			     a += PMD_SIZE) {
				pmd_t entry = ntn->text_pmd[pmd_index(a)];

				if (!pmd_none(entry) && !pmd_leaf(entry))
					free_page(pmd_page_vaddr(entry));
			}
			free_page((unsigned long)ntn->text_pmd);
			kfree(ntn);
			continue;
		}

		ntn->pgd_entry = __pgd(__pa(ntn->pud) | _PAGE_TABLE);
		ntn->nr_pages = nr_pages;
		node_text[nid] = ntn;

		pr_info("NUMA text replicate: node %d: %lu pages replicated\n",
			nid, nr_pages);
	}

	numa_text_replicate_active = true;
	pr_info("NUMA text replicate: active\n");
}

/* Called from pgd_ctor() to install per-node kernel text mapping. */
void numa_text_replicate_pgd_init(pgd_t *pgd)
{
	int nid;

	if (!numa_text_replicate_active)
		return;

	nid = numa_node_id();
	if (!node_text[nid])
		return;

	set_pgd(&pgd[text_pgd_idx], node_text[nid]->pgd_entry);
}

#ifdef CONFIG_SYSCTL
static struct ctl_table numa_text_replicate_sysctls[] = {
	{
		.procname	= "numa_text_replicate",
		.data		= &sysctl_numa_text_replicate,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
};

static int __init numa_text_replicate_sysctl_init(void)
{
	register_sysctl_init("kernel", numa_text_replicate_sysctls);
	return 0;
}
late_initcall(numa_text_replicate_sysctl_init);
#endif

static int __init numa_text_replicate_setup(char *str)
{
	int val;

	if (get_option(&str, &val))
		sysctl_numa_text_replicate = val;
	return 1;
}
__setup("numa_text_replicate=", numa_text_replicate_setup);
