/* SPDX-License-Identifier: GPL-2.0 */
/*
 * minlat scheduler class — shared inlines
 *
 * This header carries inlines that need to be visible to both
 * minlat.c and its PELT callers (pelt.c).  Do NOT include from
 * sched.h — these are minlat-internal and should not leak into the
 * rest of the scheduler.  Include after sched.h in files that need
 * them.
 */

#ifndef _KERNEL_SCHED_MINLAT_H
#define _KERNEL_SCHED_MINLAT_H

#ifdef CONFIG_SCHED_CLASS_MINLAT

/*
 * Effective runnable queue depth for picker and balance decisions:
 * total queued minlat entities minus those currently in
 * delayed-dequeue state (sleeping but kept on rq for O(1) re-wakeup).
 * Used by balance gates, the express-capacity calculation, and the
 * rq-level PELT runnable term so the same "delayed entities do not
 * count as runnable" rule applies everywhere.
 */
static __always_inline unsigned int minlat_eff(struct minlat_rq *mr)
{
	return mr->nr_running - min(mr->nr_running, mr->nr_delayed);
}

#endif /* CONFIG_SCHED_CLASS_MINLAT */

#endif /* _KERNEL_SCHED_MINLAT_H */
