/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM numa_replicate

#if !defined(_TRACE_NUMA_REPLICATE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_NUMA_REPLICATE_H

#include <linux/tracepoint.h>

TRACE_EVENT(numa_replica_create,

	TP_PROTO(struct folio *folio, int nid, pgoff_t pgoff),

	TP_ARGS(folio, nid, pgoff),

	TP_STRUCT__entry(
		__field(unsigned long,	pfn)
		__field(int,		nid)
		__field(pgoff_t,	pgoff)
	),

	TP_fast_assign(
		__entry->pfn = folio_pfn(folio);
		__entry->nid = nid;
		__entry->pgoff = pgoff;
	),

	TP_printk("pfn=0x%lx nid=%d pgoff=%lu",
		__entry->pfn, __entry->nid, __entry->pgoff)
);

TRACE_EVENT(numa_replica_drop,

	TP_PROTO(struct folio *folio, int nid, pgoff_t pgoff,
		 const char *reason),

	TP_ARGS(folio, nid, pgoff, reason),

	TP_STRUCT__entry(
		__field(unsigned long,	pfn)
		__field(int,		nid)
		__field(pgoff_t,	pgoff)
		__string(reason,	reason)
	),

	TP_fast_assign(
		__entry->pfn = folio_pfn(folio);
		__entry->nid = nid;
		__entry->pgoff = pgoff;
		__assign_str(reason);
	),

	TP_printk("pfn=0x%lx nid=%d pgoff=%lu reason=%s",
		__entry->pfn, __entry->nid, __entry->pgoff,
		__get_str(reason))
);

TRACE_EVENT(numa_replica_hit,

	TP_PROTO(pgoff_t pgoff, int nid),

	TP_ARGS(pgoff, nid),

	TP_STRUCT__entry(
		__field(pgoff_t,	pgoff)
		__field(int,		nid)
	),

	TP_fast_assign(
		__entry->pgoff = pgoff;
		__entry->nid = nid;
	),

	TP_printk("pgoff=%lu nid=%d",
		__entry->pgoff, __entry->nid)
);

#endif /* _TRACE_NUMA_REPLICATE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
