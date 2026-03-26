// SPDX-License-Identifier: GPL-2.0
/*
 * Minimum Latency Scheduling Class (SCHED_MINLAT)
 *
 * General-purpose minimum latency scheduler using virtual runtime for fairness.
 * Takes over all fair tasks when CONFIG_SCHED_CLASS_MINLAT is enabled.
 *
 * Key design points:
 *  - vruntime-based proportional fairness (like classic CFS, no EEVDF)
 *  - LLC-aware placement: greedily pack a process's threads into the same
 *    LLC to minimize TLB flushes on context switch
 *  - Per-tgid NUMA + LLC soft affinity tracking
 *  - Load-aware balancing: idle pull + load-conscious task placement
 *  - 8 explicit priority levels for SCHED_MINLAT policy (0-7)
 *  - Taken-over SCHED_NORMAL tasks use nice-based weights
 */

#include "sched.h"
#include "pelt.h"
#include <linux/sched/cputime.h>
#include <linux/sched/signal.h>
#include <linux/task_work.h>

DEFINE_STATIC_KEY_TRUE(sched_minlat_enabled);

/* ---- weight math (private copy, fair.c's is static) ---- */

#define WMULT_CONST	(~0U)
#define WMULT_SHIFT	32

static void minlat_update_inv_weight(struct load_weight *lw)
{
	unsigned long w;

	if (likely(lw->inv_weight))
		return;

	w = scale_load_down(lw->weight);

	if (BITS_PER_LONG > 32 && unlikely(w >= WMULT_CONST))
		lw->inv_weight = 1;
	else if (unlikely(!w))
		lw->inv_weight = WMULT_CONST;
	else
		lw->inv_weight = WMULT_CONST / w;
}

static u64 minlat_calc_delta_weighted(u64 delta_exec, unsigned long weight,
				      struct load_weight *lw)
{
	u64 fact = scale_load_down(weight);
	u32 fact_hi = (u32)(fact >> 32);
	int shift = WMULT_SHIFT;
	int fs;

	minlat_update_inv_weight(lw);

	if (unlikely(fact_hi)) {
		fs = fls(fact_hi);
		shift -= fs;
		fact >>= fs;
	}

	fact = mul_u32_u32(fact, lw->inv_weight);

	fact_hi = (u32)(fact >> 32);
	if (fact_hi) {
		fs = fls(fact_hi);
		shift -= fs;
		fact >>= fs;
	}

	return mul_u64_u32_shr(delta_exec, fact, shift);
}

/* ---- tuning knobs (debugfs-tunable) ---- */

unsigned int minlat_latency_ns = 1500 * NSEC_PER_USEC;
unsigned int minlat_min_granularity_ns = 500 * NSEC_PER_USEC;
unsigned int minlat_cache_hot_ns = 500 * NSEC_PER_USEC;
unsigned int minlat_numa_imbalance_min = 2;
unsigned int minlat_migration_cooldown_ns = 4 * NSEC_PER_MSEC;
unsigned int minlat_numa_saturated_pct = 75;
unsigned int minlat_wake_affine = 1;
/*
 * Fork balancing imbalance thresholds (percentage).
 * A remote LLC is preferred over local when its per-CPU load
 * is lower by at least this percentage. Cross-NUMA requires
 * a larger imbalance to justify the migration cost.
 */
unsigned int minlat_fork_imbalance_pct = 25;
unsigned int minlat_fork_numa_imbalance_pct = 50;
/*
 * Wakeup preemption threshold (ns). Non-sync wakeups only preempt
 * if the vruntime advantage exceeds this value. Higher values
 * reduce context switches but increase latency for new wakeups.
 * 0 = preempt whenever wakee has lower vruntime (aggressive).
 */
unsigned int minlat_wakeup_preempt_thresh_ns = 1 * NSEC_PER_MSEC;
/*
 * Big-core preference for interactive and compute-bound tasks.
 * Controls placement on asymmetric capacity (big.LITTLE/hybrid) systems.
 *
 * interactive_big_prefer:
 *   0 = default: place interactive tasks on any idle CPU (cache-local)
 *   1 = prefer big cores for interactive tasks. On hybrid systems,
 *       latency-critical tasks (short burst, frequent sleep) are
 *       routed to high-capacity cores for lowest wake-to-run latency.
 *       Trades cache locality for raw single-thread performance.
 *
 * compute_big_prefer:
 *   0 = default: place compute-bound tasks on any available CPU
 *   1 = prefer big cores for compute-bound tasks. CPU-intensive
 *       tasks (high utilization, long run bursts) are routed to
 *       high-capacity cores for maximum throughput. Little cores
 *       are used as overflow when all big cores are busy.
 *
 * Both are no-ops on symmetric capacity systems.
 */
unsigned int minlat_interactive_big_prefer;
unsigned int minlat_compute_big_prefer;
/*
 * LLC stickiness: minimum number of times a task must run on its
 * current LLC before it becomes eligible for cross-LLC migration.
 * Prevents migration ping-pong that wastes cache warmth.
 * Inspired by p2dq's min_llc_runs concept.
 *
 * 0 = disabled (any task can be pulled immediately)
 * 1 = default (task must run 1 time before cross-LLC pull)
 */
unsigned int minlat_llc_stickiness = 1;

#define MINLAT_LATENCY_NS		minlat_latency_ns
#define MINLAT_MIN_GRANULARITY_NS	minlat_min_granularity_ns

/* ---- capacity helpers (big.LITTLE support) ---- */

/*
 * fits_capacity - check if utilization fits within capacity with margin.
 * Uses ~20% margin (same as CFS) to avoid premature misfit detection.
 */
#define minlat_fits_capacity(util, cap) ((util) * 1280 < (cap) * 1024)

static inline unsigned long minlat_capacity_of(int cpu)
{
	return cpu_rq(cpu)->cpu_capacity;
}

/*
 * PELT (Per-Entity Load Tracking) integration.
 *
 * Minlat uses the standard PELT infrastructure for two purposes:
 * 1. Per-entity tracking (sched_minlat_entity.avg): tracks each task's
 *    utilization for capacity-aware placement (big.LITTLE).
 * 2. Per-rq tracking (minlat_rq.avg): tracks aggregate CPU utilization
 *    from minlat tasks, driving CPU frequency scaling (schedutil).
 *
 * The per-entity PELT tracks:
 *   load_sum/load_avg  - weight-scaled running time
 *   runnable_sum/avg   - time spent runnable (waiting + running)
 *   util_sum/util_avg  - actual running time (CPU utilization, 0-1024)
 */

/*
 * Update per-entity PELT for a minlat task.
 * Called from enqueue, dequeue, tick, and context switch paths.
 *
 * Parameters mirror CFS's __update_load_avg_se():
 *   load    = !!on_rq (entity contributes to load when queued)
 *   runnable = !!on_rq (flat hierarchy, no group scheduling)
 *   running = is this entity the currently executing task?
 */
static int update_minlat_se_load_avg(u64 now, struct rq *rq,
				     struct sched_minlat_entity *me)
{
	/*
	 * After migration, last_update_time is 0. Sync to the
	 * current rq clock without accumulating a stale delta.
	 */
	if (!me->avg.last_update_time) {
		me->avg.last_update_time = now;
		return 0;
	}

	if (___update_load_sum(now, &me->avg,
			       !!me->on_rq,
			       !!me->on_rq,
			       rq->minlat.curr == me)) {
		___update_load_avg(&me->avg, scale_load_down(me->load.weight));
		return 1;
	}
	return 0;
}

/*
 * Combined PELT update: entity + rq + cpufreq notification.
 * Called from the hot scheduling paths (enqueue, dequeue, tick).
 */
static void update_minlat_load_avg(struct rq *rq, struct sched_minlat_entity *me)
{
	u64 now = rq_clock_pelt(rq);
	int entity_decayed, rq_decayed;

	entity_decayed = update_minlat_se_load_avg(now, rq, me);

	rq_decayed = update_minlat_rq_load_avg(now, rq,
				rq->minlat.curr != NULL);

	if (entity_decayed || rq_decayed)
		cpufreq_update_util(rq, 0);
}

/*
 * Check if a task fits on a given CPU based on utilization vs capacity,
 * honoring uclamp min/max constraints.
 *
 * Returns:
 *   1  — task fully fits (util and uclamp constraints satisfied)
 *   0  — task doesn't fit (util exceeds capacity)
 *  -1  — util fits but uclamp_min exceeds CPU capacity
 *         (task can run but won't get requested minimum performance)
 */
static inline int minlat_util_fits_cpu(struct task_struct *p, int cpu)
{
	unsigned long util = READ_ONCE(p->minlat.avg.util_avg);
	unsigned long capacity = arch_scale_cpu_capacity(cpu);
	bool fits;

	fits = minlat_fits_capacity(util, capacity);

#ifdef CONFIG_UCLAMP_TASK
	if (uclamp_is_used()) {
		unsigned long uclamp_min = uclamp_eff_value(p, UCLAMP_MIN);
		unsigned long uclamp_max = uclamp_eff_value(p, UCLAMP_MAX);

		/*
		 * uclamp_max caps the task — if the CPU's capacity
		 * is at least uclamp_max, the task fits regardless
		 * of its raw utilization.
		 */
		if (capacity >= uclamp_max)
			fits = true;

		/*
		 * uclamp_min boosts the task — if the task fits by
		 * utilization but the CPU can't provide uclamp_min
		 * performance, return -1 (partial fit).
		 */
		uclamp_min = min(uclamp_min, uclamp_max);
		if (fits && (util < uclamp_min) &&
		    (uclamp_min > capacity))
			return -1;
	}
#endif

	return fits ? 1 : 0;
}

/*
 * Simple boolean wrapper: does the task fully fit this CPU?
 */
static inline bool minlat_task_fits_cpu(struct task_struct *p, int cpu)
{
	if (!sched_asym_cpucap_active())
		return true;

	return (minlat_util_fits_cpu(p, cpu) > 0);
}

/*
 * Check if this task should prefer big (high-capacity) cores.
 *
 * Returns true if the task's placement policy calls for a big core:
 * - interactive_big_prefer=1 AND task is interactive (short bursts)
 * - compute_big_prefer=1 AND task is compute-bound (not interactive)
 *
 * When true, select_task_rq will prefer higher-capacity idle CPUs
 * even if a lower-capacity CPU in the same LLC is available.
 * This is a soft preference — if no big core is idle, little cores
 * are used as fallback.
 */
static inline bool minlat_prefers_big(struct task_struct *p)
{
	if (!sched_asym_cpucap_active())
		return false;

	if (minlat_interactive_big_prefer && p->minlat.interactive)
		return true;

	if (minlat_compute_big_prefer && !p->minlat.interactive)
		return true;

	return false;
}

/*
 * Check if a CPU is a "big" (high-capacity) core.
 * Returns true if this CPU's capacity equals the system maximum.
 */
static inline bool minlat_cpu_is_big(int cpu)
{
	return arch_scale_cpu_capacity(cpu) >= SCHED_CAPACITY_SCALE;
}

/*
 * Update misfit task status on the rq. Called from task_tick and
 * set_next_task to detect tasks that need higher-capacity CPUs.
 *
 * Mirrors CFS update_misfit_status() logic:
 * - No misfit if system has symmetric capacity
 * - No misfit if task is pinned to one CPU
 * - No misfit if task is already on biggest available CPU
 * - No misfit if task's utilization fits the CPU's capacity
 */
static void minlat_update_misfit_status(struct task_struct *p, struct rq *rq)
{
	int cpu;

	if (!sched_asym_cpucap_active())
		return;

	if (!p) {
		rq->misfit_task_load = 0;
		return;
	}

	cpu = cpu_of(rq);

	if (p->nr_cpus_allowed == 1 ||
	    arch_scale_cpu_capacity(cpu) == p->max_allowed_capacity ||
	    minlat_task_fits_cpu(p, cpu)) {
		rq->misfit_task_load = 0;
		return;
	}

	/*
	 * Task doesn't fit — set misfit load from PELT load_avg,
	 * falling back to task weight if PELT hasn't warmed up yet.
	 * Ensure non-zero so check_misfit_status() returns true.
	 */
	rq->misfit_task_load = max_t(unsigned long,
				     READ_ONCE(p->minlat.avg.load_avg), 1);
}

/* ==== NUMA balancing ==== */

#ifdef CONFIG_NUMA_BALANCING
/*
 * Trigger NUMA page scanning for minlat tasks.
 *
 * Mirrors CFS task_tick_numa() logic: periodically schedule
 * task_numa_work (set up by init_numa_balancing on fork) to scan
 * process pages and trigger NUMA faults. The MM layer handles
 * page migration; task_numa_placement sets numa_preferred_nid
 * based on fault data — both are scheduler-class agnostic.
 *
 * Uses sysctl_numa_balancing_scan_delay for initial period instead
 * of CFS's task_scan_start() which depends on numa_group internals.
 * After first scan, task_numa_placement() adapts the period.
 */
static void minlat_task_tick_numa(struct rq *rq, struct task_struct *curr)
{
	struct callback_head *work = &curr->numa_work;
	u64 period, now;

	if (!curr->mm || (curr->flags & (PF_EXITING | PF_KTHREAD)) ||
	    work->next != work)
		return;

	/*
	 * Use runtime rather than walltime so idle tasks don't
	 * trigger scanning, matching CFS behavior.
	 */
	now = curr->se.sum_exec_runtime;
	period = (u64)curr->numa_scan_period * NSEC_PER_MSEC;

	if (now > curr->node_stamp + period) {
		if (!curr->node_stamp)
			curr->numa_scan_period =
				sysctl_numa_balancing_scan_delay;
		curr->node_stamp += period;

		if (!time_before(jiffies, curr->mm->numa_next_scan))
			task_work_add(curr, work, TWA_RESUME);
	}
}
#else
static inline void minlat_task_tick_numa(struct rq *rq,
					 struct task_struct *curr)
{
}
#endif /* CONFIG_NUMA_BALANCING */

/*
 * Global count of overloaded CPUs (those with 2+ minlat tasks).
 * O(1) check replaces O(N_CPUs) scan — critical for idle-pull
 * fast-skip on large machines.
 */
static atomic_t minlat_nr_overloaded = ATOMIC_INIT(0);

static bool sched_minlat_any_overloaded(struct rq *this_rq)
{
	return atomic_read(&minlat_nr_overloaded) > 0;
}

/* ---- priority/weight tables ---- */

static const int minlat_prio_to_weight[MINLAT_MAX_PRIO] = {
	/* 0 */ 3121,  /* 1 */ 2501,  /* 2 */ 1991,  /* 3 */ 1586,
	/* 4 */ 1277,  /* 5 */ 1024,  /* 6 */  820,  /* 7 */  655,
};
static const u32 minlat_prio_to_wmult[MINLAT_MAX_PRIO] = {
	/* 0 */ 1376151, /* 1 */ 1717300, /* 2 */ 2157191, /* 3 */ 2708050,
	/* 4 */ 3363326, /* 5 */ 4194304, /* 6 */ 5237765, /* 7 */ 6557202,
};

static inline bool minlat_task_is_fair(struct task_struct *p)
{
	return !minlat_policy(p->policy);
}

static void minlat_set_load_weight(struct task_struct *p)
{
	struct sched_minlat_entity *me = &p->minlat;

	if (minlat_task_is_fair(p)) {
		int prio = p->static_prio - MAX_RT_PRIO;

		if (idle_policy(p->policy)) {
			me->load.weight = scale_load(WEIGHT_IDLEPRIO);
			me->load.inv_weight = WMULT_IDLEPRIO;
		} else if (prio >= 0 && prio < 40) {
			me->load.weight = scale_load(sched_prio_to_weight[prio]);
			me->load.inv_weight = sched_prio_to_wmult[prio];
		} else {
			me->load.weight = scale_load(1024);
			me->load.inv_weight = 4194304;
		}
	} else {
		unsigned int mp = min(me->minlat_prio,
				      (unsigned int)(MINLAT_MAX_PRIO - 1));
		me->load.weight = scale_load(minlat_prio_to_weight[mp]);
		me->load.inv_weight = minlat_prio_to_wmult[mp];
	}
}

static __always_inline u64
minlat_calc_delta(u64 delta, struct sched_minlat_entity *me)
{
	if (me->load.weight == scale_load(1024))
		return delta;
	return minlat_calc_delta_weighted(delta, NICE_0_LOAD, &me->load);
}

/* ==== per-tgid LLC/NUMA context ==== */

static struct minlat_tgid_ctx *minlat_tgid_ctx_alloc(int cpu)
{
	struct minlat_tgid_ctx *ctx;
	int llc_id = per_cpu(sd_llc_id, cpu);
	struct sched_domain *sd;

	ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return NULL;

	refcount_set(&ctx->refcount, 1);
	ctx->preferred_node = cpu_to_node(cpu);
	ctx->preferred_llc = llc_id;
	raw_spin_lock_init(&ctx->lock);
	atomic_set(&ctx->nr_tasks, 1);
	atomic_set(&ctx->nr_on_llc, 1);

	if (!zalloc_cpumask_var(&ctx->llc_cpus, GFP_ATOMIC)) {
		kfree(ctx);
		return NULL;
	}

	/* Populate LLC cpumask from the sched_domain */
	rcu_read_lock();
	sd = rcu_dereference(per_cpu(sd_llc, cpu));
	if (sd)
		cpumask_copy(ctx->llc_cpus, sched_domain_span(sd));
	else
		cpumask_set_cpu(cpu, ctx->llc_cpus);
	rcu_read_unlock();

	return ctx;
}

static void minlat_tgid_ctx_get(struct minlat_tgid_ctx *ctx)
{
	refcount_inc(&ctx->refcount);
}

static void minlat_tgid_ctx_put(struct minlat_tgid_ctx *ctx)
{
	if (ctx && refcount_dec_and_test(&ctx->refcount)) {
		free_cpumask_var(ctx->llc_cpus);
		kfree(ctx);
	}
}

static void minlat_ensure_tgid_ctx(struct task_struct *p)
{
	struct sched_minlat_entity *me = &p->minlat;
	struct task_struct *leader;

	if (me->tgid_ctx)
		return;

	/* Don't allocate during early boot before slab is up */
	if (unlikely(!slab_is_available()))
		return;

	/*
	 * Try to inherit from thread group leader.
	 * Only allocate for multi-threaded tasks — single-threaded
	 * processes (leader == self) skip allocation since they don't
	 * benefit from per-tgid LLC tracking. This avoids kmalloc+kfree
	 * overhead in fork-heavy workloads.
	 */
	leader = p->group_leader;
	if (leader && leader != p && leader->minlat.tgid_ctx) {
		struct minlat_tgid_ctx *ctx = leader->minlat.tgid_ctx;

		minlat_tgid_ctx_get(ctx);
		me->tgid_ctx = ctx;
		atomic_inc(&ctx->nr_tasks);
		return;
	}

	/* Only allocate for threads, not single-threaded fork children */
	if (leader && leader != p)
		me->tgid_ctx = minlat_tgid_ctx_alloc(task_cpu(p));
}

/*
 * Check if the process should migrate its LLC preference.
 * This happens when a majority of the process's tasks have moved
 * off the preferred LLC (e.g., due to load balancing).
 */
static void minlat_maybe_update_llc(struct task_struct *p)
{
	struct minlat_tgid_ctx *ctx = p->minlat.tgid_ctx;
	int cur_llc, nr_tasks, nr_on;
	struct sched_domain *sd;

	if (!ctx)
		return;

	cur_llc = per_cpu(sd_llc_id, task_cpu(p));

	/* Track whether this task is on the preferred LLC */
	if (cur_llc == ctx->preferred_llc) {
		if (p->minlat.prev_llc != cur_llc) {
			atomic_inc(&ctx->nr_on_llc);
			p->minlat.prev_llc = cur_llc;
		}
		return;
	}

	if (p->minlat.prev_llc == ctx->preferred_llc) {
		atomic_dec(&ctx->nr_on_llc);
		p->minlat.prev_llc = cur_llc;
	}

	/*
	 * If fewer than half the tasks are on the preferred LLC,
	 * consider switching preference to where we are now.
	 */
	nr_tasks = atomic_read(&ctx->nr_tasks);
	nr_on = atomic_read(&ctx->nr_on_llc);

	if (nr_tasks > 1 && nr_on * 2 < nr_tasks) {
		raw_spin_lock(&ctx->lock);
		/* Double-check under lock */
		nr_on = atomic_read(&ctx->nr_on_llc);
		nr_tasks = atomic_read(&ctx->nr_tasks);
		if (nr_on * 2 < nr_tasks) {
			ctx->preferred_llc = cur_llc;
			ctx->preferred_node = cpu_to_node(task_cpu(p));

			rcu_read_lock();
			sd = rcu_dereference(per_cpu(sd_llc, task_cpu(p)));
			if (sd)
				cpumask_copy(ctx->llc_cpus,
					     sched_domain_span(sd));
			rcu_read_unlock();

			/* Reset counters */
			atomic_set(&ctx->nr_on_llc, 1);
		}
		raw_spin_unlock(&ctx->lock);
	}
}

/* forward declarations */
static void minlat_update_interactivity(struct task_struct *p,
					struct rq *rq, int flags);
static void minlat_record_sleep(struct task_struct *p, struct rq *rq);
static void minlat_maybe_update_llc(struct task_struct *p);
static void pull_minlat_task(struct rq *this_rq);

/* ==== runqueue init ==== */

void init_minlat_rq(struct minlat_rq *minlat_rq)
{
	minlat_rq->tasks_timeline = RB_ROOT_CACHED;
	minlat_rq->curr = NULL;
	minlat_rq->next = NULL;
	minlat_rq->nr_running = 0;
	minlat_rq->nr_delayed = 0;
	minlat_rq->min_vruntime = 0;
	minlat_rq->load_weight = 0;
	memset(&minlat_rq->avg, 0, sizeof(minlat_rq->avg));
	minlat_rq->active_balance = 0;
	minlat_rq->push_cpu = 0;
	minlat_rq->next_balance = 0;
}

/* ==== rb-tree operations ==== */

static __always_inline bool __minlat_less(struct rb_node *a,
					  const struct rb_node *b)
{
	struct sched_minlat_entity *ea, *eb;

	ea = rb_entry(a, struct sched_minlat_entity, run_node);
	eb = rb_entry(b, struct sched_minlat_entity, run_node);
	return (s64)(ea->vruntime - eb->vruntime) < 0;
}

static __always_inline void
__enqueue_minlat_entity(struct minlat_rq *minlat_rq,
			struct sched_minlat_entity *me)
{
	rb_add_cached(&me->run_node, &minlat_rq->tasks_timeline,
		      __minlat_less);
}

static __always_inline void
__dequeue_minlat_entity(struct minlat_rq *minlat_rq,
			struct sched_minlat_entity *me)
{
	if (RB_EMPTY_NODE(&me->run_node))
		return;
	rb_erase_cached(&me->run_node, &minlat_rq->tasks_timeline);
	RB_CLEAR_NODE(&me->run_node);
}

static __always_inline struct sched_minlat_entity *
__pick_first_minlat_entity(struct minlat_rq *minlat_rq)
{
	struct rb_node *left = rb_first_cached(&minlat_rq->tasks_timeline);

	if (!left)
		return NULL;
	return rb_entry(left, struct sched_minlat_entity, run_node);
}

static __always_inline struct rq *rq_of_minlat_rq(struct minlat_rq *minlat_rq)
{
	return container_of(minlat_rq, struct rq, minlat);
}

/*
 * Update min_vruntime to track the minimum vruntime across all runnable
 * tasks. This must consider BOTH the currently running task and the
 * leftmost (next-to-run) task in the tree.
 *
 * Without considering the current task, min_vruntime can be pulled up
 * by high-weight tasks (high nice value = fast vruntime), causing
 * low-nice tasks to lose their vruntime advantage when they sleep
 * and wake up (place_minlat_entity uses min_vruntime for placement).
 */
static __always_inline void update_min_vruntime(struct minlat_rq *minlat_rq)
{
	struct sched_minlat_entity *leftmost;
	struct task_struct *curr = rq_of_minlat_rq(minlat_rq)->curr;
	u64 vruntime = minlat_rq->min_vruntime;

	if (curr && curr->sched_class == &minlat_sched_class)
		vruntime = curr->minlat.vruntime;

	leftmost = __pick_first_minlat_entity(minlat_rq);
	if (leftmost) {
		if (!curr || curr->sched_class != &minlat_sched_class)
			vruntime = leftmost->vruntime;
		else
			vruntime = min_t(u64, vruntime, leftmost->vruntime);
	}

	/* min_vruntime only moves forward */
	minlat_rq->min_vruntime = max_t(u64, minlat_rq->min_vruntime, vruntime);
}

static void place_minlat_entity(struct minlat_rq *minlat_rq,
				struct sched_minlat_entity *me, int flags)
{
	u64 vruntime = minlat_rq->min_vruntime;

	if (flags & ENQUEUE_WAKEUP) {
		/*
		 * Give waking tasks a half-latency credit so they run
		 * soon after wakeup. For weight 1024 (nice 0 / minlat
		 * prio 5), thresh == LATENCY/2 directly — skip the
		 * weighted calculation.
		 */
		u64 thresh;

		if (likely(me->load.weight == scale_load(1024)))
			thresh = MINLAT_LATENCY_NS / 2;
		else
			thresh = minlat_calc_delta(MINLAT_LATENCY_NS / 2, me);

		vruntime -= min(vruntime, thresh);
	}

	me->vruntime = max_t(s64, me->vruntime, vruntime);
}

/* ==== core scheduling callbacks ==== */

/*
 * Lightweight vruntime update — just accounting, no tree reposition.
 * Used on the wakeup preemption path where we need fresh vruntime
 * for comparison but don't need correct tree ordering yet.
 */
static __always_inline void update_curr_minlat_vruntime(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	struct sched_minlat_entity *me;
	u64 now, delta_exec;

	if (curr->sched_class != &minlat_sched_class)
		return;

	me = &curr->minlat;
	now = rq_clock_task(rq);
	delta_exec = now - curr->se.exec_start;

	if (unlikely((s64)delta_exec <= 0))
		return;

	curr->se.exec_start = now;
	curr->se.sum_exec_runtime += delta_exec;
	account_group_exec_runtime(curr, delta_exec);
	cgroup_account_cputime(curr, delta_exec);

	me->vruntime += minlat_calc_delta(delta_exec, me);
}

static void update_curr_minlat(struct rq *rq)
{
	struct minlat_rq *minlat_rq = &rq->minlat;

	update_curr_minlat_vruntime(rq);

	if (rq->curr->sched_class != &minlat_sched_class)
		return;

	/*
	 * Current entity is out-of-tree (removed by set_next_task).
	 * No tree repositioning needed — put_prev_task will re-insert
	 * it at the correct position when it stops running.
	 */
	update_min_vruntime(minlat_rq);
}

/*
 * Compute weight-proportional timeslice for a task.
 * Higher-weight (lower nice) tasks get longer slices.
 * Like CFS's sched_slice().
 */
static u64 minlat_sched_slice(struct minlat_rq *minlat_rq,
			      struct sched_minlat_entity *me)
{
	u64 slice = MINLAT_LATENCY_NS;

	if (minlat_rq->load_weight > 0) {
		slice *= scale_load_down(me->load.weight);
		slice = div_u64(slice, minlat_rq->load_weight);
	}

	return max_t(u64, slice, MINLAT_MIN_GRANULARITY_NS);
}

static void check_preempt_tick_minlat(struct rq *rq, struct task_struct *curr)
{
	struct sched_minlat_entity *curr_me = &curr->minlat;
	struct sched_minlat_entity *next_me;
	struct minlat_rq *minlat_rq = &rq->minlat;
	struct rb_node *next_node;
	u64 ideal_runtime, delta_exec;
	s64 delta;

	if (minlat_rq->nr_running <= 1)
		return;

	ideal_runtime = minlat_sched_slice(minlat_rq, curr_me);

	/*
	 * Minimum running time protection. Don't preempt until the
	 * task has run for at least min_granularity. This prevents
	 * thrashing from rapid preemption while keeping latency low.
	 */
	delta_exec = curr->se.sum_exec_runtime -
		     curr->se.prev_sum_exec_runtime;
	if (delta_exec < MINLAT_MIN_GRANULARITY_NS)
		return;

	/*
	 * Current entity is out of the tree — find the first
	 * non-delayed competitor. Delayed entities have stale
	 * vruntimes that would cause spurious preemption.
	 */
	for (next_node = rb_first_cached(&minlat_rq->tasks_timeline);
	     next_node; next_node = rb_next(next_node)) {
		struct task_struct *next_p;

		next_me = rb_entry(next_node, struct sched_minlat_entity,
				   run_node);
		next_p = container_of(next_me, struct task_struct, minlat);
		if (!next_p->se.sched_delayed)
			break;
	}
	if (!next_node)
		return;

	delta = (s64)(curr_me->vruntime - next_me->vruntime);
	if (delta > (s64)ideal_runtime)
		resched_curr(rq);
}

static void
enqueue_task_minlat(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_minlat_entity *me = &p->minlat;
	struct minlat_rq *minlat_rq = &rq->minlat;

	/*
	 * ENQUEUE_DELAYED: re-enable a delayed entity. The entity is
	 * already in the rb-tree with correct vruntime — just clear
	 * the delayed flag. No rb-tree operations needed.
	 *
	 * This is called from ttwu_runnable() when a task with
	 * p->se.sched_delayed wakes up on the same CPU. O(1) wakeup!
	 */
	if (flags & ENQUEUE_DELAYED) {
		WARN_ON_ONCE(!p->se.sched_delayed);
		p->se.sched_delayed = 0;
		minlat_rq->nr_delayed--;
		return;
	}

	if (!me->on_rq) {
		/*
		 * First enqueue or wakeup from sleep — weight may need
		 * recalculating (e.g., after fork or nice change while
		 * sleeping). Once set, weight stays valid until
		 * prio_changed/switched_to callbacks update it.
		 */
		minlat_set_load_weight(p);
		place_minlat_entity(minlat_rq, me, flags);
		me->on_rq = 1;
	}

	/*
	 * Don't insert into the tree if this entity is the currently
	 * running task (curr is kept out-of-tree while running).
	 */
	if (minlat_rq->curr != me)
		__enqueue_minlat_entity(minlat_rq, me);

	minlat_rq->nr_running++;
	minlat_rq->load_weight += scale_load_down(me->load.weight);
	add_nr_running(rq, 1);

	/*
	 * Track overloaded based on effective runnable count
	 * (excluding delayed sleepers). Delayed entities are sleeping
	 * tasks kept in the tree for O(1) wakeup — they don't need
	 * CPU time and shouldn't trigger migration pressure.
	 */
	if (minlat_rq->nr_running - minlat_rq->nr_delayed >= 2 &&
	    !minlat_rq->overloaded) {
		WRITE_ONCE(minlat_rq->overloaded, true);
		atomic_inc(&minlat_nr_overloaded);
	}

	update_minlat_load_avg(rq, me);
}

bool
dequeue_task_minlat(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_minlat_entity *me = &p->minlat;
	struct minlat_rq *minlat_rq = &rq->minlat;
	bool was_curr = (minlat_rq->curr == me);
	bool was_leftmost = false;

	if (minlat_rq->next == me)
		minlat_rq->next = NULL;

	/*
	 * Delayed dequeue: keep sleeping curr on the runqueue to avoid
	 * the full dequeue+enqueue cycle for brief sleep/wake patterns
	 * (pipes, futex, hackbench). Mirrors EEVDF's DELAY_DEQUEUE.
	 *
	 * When curr sleeps and there are other runnable tasks, mark it
	 * delayed and return false. block_task() skips __block_task(),
	 * leaving p->on_rq = TASK_ON_RQ_QUEUED. put_prev_task will
	 * re-insert the entity into the tree. If the task wakes before
	 * pick, ttwu_runnable() clears delayed via ENQUEUE_DELAYED — O(1).
	 *
	 * If still delayed at pick_task time, force-dequeue via
	 * DEQUEUE_DELAYED. Skip delay for DEQUEUE_SPECIAL (TASK_DEAD).
	 * Skip when nr_running == 1 (no other task to pick, force-dequeue
	 * would fire immediately anyway).
	 *
	 * Only delay when the task ran briefly before sleeping — this
	 * captures tight IPC loops (pipe, futex, message passing) while
	 * avoiding latency regression for compute-then-sleep patterns
	 * where migration to an idle CPU (via full ttwu) is beneficial.
	 */
	if ((flags & DEQUEUE_SLEEP) && was_curr &&
	    !(flags & (DEQUEUE_DELAYED | DEQUEUE_SPECIAL)) &&
	    me->on_rq && minlat_rq->nr_running > 1) {
		u64 run_ns = p->se.sum_exec_runtime -
			     p->se.prev_sum_exec_runtime;

		/*
		 * Only delay for short-running tasks (IPC pattern).
		 *
		 * Cap delayed entities to bound pick_task scan cost.
		 * At high oversubscription (75+ tasks/CPU), unbounded
		 * delayed entities cause O(n) scan or excessive
		 * force-dequeue overhead. Cap at nr_running/4 (min 2)
		 * to keep scan cost bounded while preserving
		 * ttwu_runnable benefits for the hottest IPC tasks.
		 *
		 * Also prevent all-delayed state (nr_running -
		 * nr_delayed > 1) so the CPU can become idle.
		 */
		if (run_ns < max_t(u64, MINLAT_MIN_GRANULARITY_NS,
				   sysctl_sched_base_slice) &&
		    minlat_rq->nr_running - minlat_rq->nr_delayed > 1 &&
		    minlat_rq->nr_delayed <
			    max_t(unsigned int, 2,
				  minlat_rq->nr_running >> 2)) {
			p->se.sched_delayed = 1;
			minlat_rq->nr_delayed++;
			return false;
		}
	}

	/* Clear delayed flag on force-dequeue */
	if (flags & DEQUEUE_DELAYED) {
		p->se.sched_delayed = 0;
		minlat_rq->nr_delayed--;
	}

	if (was_curr) {
		/*
		 * Currently running entity is already out of the tree
		 * (removed by set_next_task). Just clear curr.
		 */
		minlat_rq->curr = NULL;
	} else if (me->on_rq && !RB_EMPTY_NODE(&me->run_node)) {
		/* Check if this was leftmost before removing */
		was_leftmost = (rb_first_cached(&minlat_rq->tasks_timeline) ==
				&me->run_node);
		__dequeue_minlat_entity(minlat_rq, me);
	}

	minlat_rq->nr_running--;

	if (minlat_rq->nr_running - minlat_rq->nr_delayed < 2 &&
	    minlat_rq->overloaded) {
		WRITE_ONCE(minlat_rq->overloaded, false);
		atomic_dec(&minlat_nr_overloaded);
	}
	minlat_rq->load_weight -= scale_load_down(me->load.weight);
	sub_nr_running(rq, 1);

	if (flags & DEQUEUE_SLEEP) {
		me->on_rq = 0;
		minlat_record_sleep(p, rq);
	}

	update_minlat_load_avg(rq, me);

	/*
	 * Clear misfit status if no minlat tasks remain — the CPU
	 * will go idle or pick from another class.
	 */
	if (minlat_rq->nr_running == 0)
		rq->misfit_task_load = 0;

	/* Only update min_vruntime if the leftmost node changed */
	if (was_leftmost)
		update_min_vruntime(minlat_rq);

	/*
	 * Fix-up what block_task() skipped for delayed dequeue.
	 * Generic code (wait_task_inactive, etc.) calls dequeue_task()
	 * with DEQUEUE_DELAYED but never calls __block_task() itself.
	 * CFS handles this in dequeue_entities(); we must do the same.
	 *
	 * Must be last — p may not be valid after __block_task() since
	 * ttwu() can migrate the task once p->on_rq is cleared.
	 */
	if ((flags & DEQUEUE_DELAYED) && (flags & DEQUEUE_SLEEP))
		__block_task(rq, p);

	return true;
}

static void yield_task_minlat(struct rq *rq)
{
	struct task_struct *p = rq->donor;
	struct sched_minlat_entity *me = &p->minlat;
	struct minlat_rq *minlat_rq = &rq->minlat;
	struct sched_minlat_entity *next_me;
	struct rb_node *next;

	update_rq_clock(rq);
	update_curr_minlat(rq);

	/*
	 * Current is out of the tree — rb_first_cached returns the
	 * next competitor directly. Set our vruntime just past it
	 * so we'll be re-inserted behind it by put_prev_task.
	 */
	next = rb_first_cached(&minlat_rq->tasks_timeline);
	if (next) {
		next_me = rb_entry(next, struct sched_minlat_entity, run_node);
		me->vruntime = next_me->vruntime + 1;
		return;
	}
	/* Fallback: no other tasks, minor bump */
	me->vruntime = minlat_rq->min_vruntime +
		minlat_calc_delta(MINLAT_LATENCY_NS, me);
}

/*
 * Set the wakeup buddy — mirrors CFS set_next_buddy().
 *
 * The buddy is a hint to pick_task_minlat() to prefer this entity
 * at the next scheduling decision. Unlike CFS which walks cgroup
 * hierarchy, minlat is flat so we just set the per-rq pointer.
 *
 * Keep an existing buddy if it has a lower vruntime (more claim to
 * run). This mirrors CFS set_preempt_buddy() which keeps an existing
 * buddy with an earlier deadline.
 */
static __always_inline void
set_next_buddy_minlat(struct minlat_rq *minlat_rq,
		      struct sched_minlat_entity *me)
{
	if (minlat_rq->next &&
	    (s64)(me->vruntime - minlat_rq->next->vruntime) > 0)
		return;

	minlat_rq->next = me;
}

/*
 * Wakeup preemption — mirrors EEVDF's wakeup_preempt_fair() structure:
 *
 *  1. update_curr — freshen current's vruntime
 *  2. Skip if already rescheduling
 *  3. Skip WF_FORK (forked tasks unlikely to share data)
 *  4. Set wakee as next buddy (like CFS NEXT_BUDDY)
 *  5. WF_SYNC: preempt if wakee has vruntime advantage AND current
 *     ran >= cache_hot threshold (mirrors preempt_sync()).
 *     Also lazy-resched unconditionally since waker is about to block.
 *  6. Pick check: preempt if wakee has lower vruntime than current
 *     (analogous to __pick_eevdf() == pse)
 *  7. Use resched_curr_lazy() like EEVDF
 *
 * No min_granularity on the wakeup path — that's for tick preemption
 * only (task_tick). EEVDF similarly separates slice protection
 * (RUN_TO_PARITY) from wakeup preemption.
 */
static void
wakeup_preempt_minlat(struct rq *rq, struct task_struct *p, int flags)
{
	struct task_struct *curr = rq->curr;
	struct minlat_rq *minlat_rq = &rq->minlat;
	s64 delta;

	if (curr->sched_class != &minlat_sched_class) {
		resched_curr(rq);
		return;
	}

	if (test_tsk_need_resched(curr))
		return;

	/*
	 * Don't preempt for forked tasks — they are unlikely to
	 * share data with the parent. Mirrors EEVDF WF_FORK skip.
	 */
	if (flags & WF_FORK)
		return;

	/* Set the wakee as the preferred next task (NEXT_BUDDY) */
	set_next_buddy_minlat(minlat_rq, &p->minlat);

	/*
	 * WF_SYNC: waker expects to sleep soon.
	 *
	 * For same-CPU: no resched needed — the waker blocks soon,
	 * schedule() picks the buddy. Avoids extra switches in
	 * pipe/hackbench where the waker blocks immediately.
	 *
	 * For remote-CPU: the wakee is on a different CPU. If the
	 * wakee has significant vruntime advantage over that CPU's
	 * current task, use resched_curr for prompt scheduling.
	 * Small advantages don't justify the IPI cost (the tick
	 * will handle it). This gives hackbench throughput (senders
	 * complete all writes before being preempted) while keeping
	 * schbench latency low (computing workers get preempted).
	 */
	if (flags & WF_SYNC) {
		if (task_cpu(p) != smp_processor_id()) {
			update_curr_minlat_vruntime(rq);
			delta = (s64)(rq->curr->minlat.vruntime -
				      p->minlat.vruntime);
			if (delta > (s64)MINLAT_MIN_GRANULARITY_NS)
				resched_curr(rq);
		}
		return;
	}

	/*
	 * Non-sync: freshen current's vruntime for accurate comparison.
	 */
	update_curr_minlat_vruntime(rq);

	delta = (s64)(curr->minlat.vruntime - p->minlat.vruntime);

	/*
	 * Preempt if the wakee has a vruntime advantage.
	 *
	 * Very light load (at most 2 effective runnable tasks):
	 * preempt immediately unless curr just started running.
	 * Tasks that have run < min_granularity are protected from
	 * wakeup preemption — this prevents preempting tasks in
	 * tight syscall loops (like futex_wake batch waking pinned
	 * threads) while still allowing prompt scheduling for
	 * compute tasks that have been running for a while.
	 * The woken task's buddy status ensures it runs next when
	 * curr voluntarily sleeps (no tick wait needed).
	 *
	 * Heavier load: require a significant vruntime advantage
	 * (threshold) and use resched_curr_lazy to avoid IPI
	 * storms in IPC-heavy workloads like hackbench.
	 */
	if (delta > 0) {
		unsigned int eff = minlat_rq->nr_running -
				   minlat_rq->nr_delayed;

		if (eff <= 2) {
			u64 ran = curr->se.sum_exec_runtime -
				  curr->se.prev_sum_exec_runtime;

			if (ran >= MINLAT_MIN_GRANULARITY_NS)
				resched_curr(rq);
		} else if (delta > (s64)minlat_wakeup_preempt_thresh_ns)
			resched_curr_lazy(rq);
	}
}

/*
 * Check if an entity is eligible for buddy selection.
 *
 * The buddy's vruntime must not be too far ahead of min_vruntime
 * to prevent unfairness. Mirrors EEVDF's entity_eligible() which
 * checks vruntime <= avg_vruntime. Since minlat doesn't track
 * avg_vruntime, we use min_vruntime + latency_target as the bound.
 */
static __always_inline bool
minlat_buddy_eligible(struct minlat_rq *minlat_rq,
		      struct sched_minlat_entity *me)
{
	return (s64)(me->vruntime - minlat_rq->min_vruntime) <=
	       (s64)MINLAT_LATENCY_NS;
}

static struct task_struct *
pick_task_minlat(struct rq *rq, struct rq_flags *rf)
{
	struct minlat_rq *minlat_rq = &rq->minlat;
	struct sched_minlat_entity *me;
	struct task_struct *p;

	/*
	 * PICK_BUDDY: prefer the wakeup buddy if it's still queued,
	 * eligible, and not delayed. Mirrors EEVDF's PICK_BUDDY.
	 */
	if (minlat_rq->next &&
	    !RB_EMPTY_NODE(&minlat_rq->next->run_node) &&
	    minlat_buddy_eligible(minlat_rq, minlat_rq->next)) {
		p = container_of(minlat_rq->next, struct task_struct, minlat);
		if (!p->se.sched_delayed) {
			me = minlat_rq->next;
			minlat_rq->next = NULL;
			return container_of(me, struct task_struct, minlat);
		}
	}
	minlat_rq->next = NULL;

	/*
	 * Pick leftmost non-delayed entity. Force-dequeue any delayed
	 * entities at the head of the tree instead of scanning past
	 * them (O(n) scan degrades at high oversubscription).
	 *
	 * This mirrors CFS's pick_next_entity approach: pick the best
	 * candidate, and if it's delayed, force-dequeue it and retry.
	 * Force-dequeued entities go through full ttwu on wakeup,
	 * getting a chance to migrate to a less loaded CPU.
	 */
	while ((me = __pick_first_minlat_entity(minlat_rq))) {
		p = container_of(me, struct task_struct, minlat);
		if (!p->se.sched_delayed)
			return p;
		dequeue_task_minlat(rq, p, DEQUEUE_SLEEP | DEQUEUE_DELAYED);
	}

	/*
	 * Tree is empty but curr exists out-of-tree — return it.
	 * If curr is delayed, force-dequeue it.
	 */
	if (minlat_rq->curr && minlat_rq->curr->on_rq) {
		p = container_of(minlat_rq->curr, struct task_struct, minlat);
		if (!p->se.sched_delayed)
			return p;

		dequeue_task_minlat(rq, p, DEQUEUE_SLEEP | DEQUEUE_DELAYED);
	}

	/*
	 * No minlat tasks on this CPU. Try idle-pull from a busy CPU.
	 *
	 * prev_balance() only calls balance_minlat() when prev's class
	 * is at or above minlat. When prev is the idle task, balance_minlat
	 * is never reached, so we must pull here.
	 *
	 * Skip the pull if no CPU is overloaded — avoids expensive
	 * cross-CPU scanning when the system is balanced.
	 */
	if (rf && sched_minlat_any_overloaded(rq)) {
		rq_unpin_lock(rq, rf);
		pull_minlat_task(rq);
		rq_repin_lock(rq, rf);

		me = __pick_first_minlat_entity(&rq->minlat);
		if (me)
			return container_of(me, struct task_struct, minlat);
	}

	return NULL;
}

static void
put_prev_task_minlat(struct rq *rq, struct task_struct *p,
		     struct task_struct *next)
{
	struct sched_minlat_entity *me = &p->minlat;
	struct minlat_rq *minlat_rq = &rq->minlat;
	struct sched_minlat_entity *leftmost;
	u64 now, delta_exec, vruntime;

	if (unlikely(minlat_rq->curr != me))
		return;

	if (unlikely(!me->on_rq)) {
		minlat_rq->curr = NULL;
		return;
	}

	/*
	 * Combined vruntime + min_vruntime update.
	 * We know curr is minlat class — skip the class check that
	 * the standalone update_curr_minlat_vruntime() does.
	 * Inline min_vruntime update to avoid redundant rq lookup
	 * and second class check.
	 */
	now = rq_clock_task(rq);
	delta_exec = now - p->se.exec_start;

	if (likely((s64)delta_exec > 0)) {
		p->se.exec_start = now;
		p->se.sum_exec_runtime += delta_exec;
		account_group_exec_runtime(p, delta_exec);
		cgroup_account_cputime(p, delta_exec);
		me->vruntime += minlat_calc_delta(delta_exec, me);
	}

	/* Inline min_vruntime: curr vruntime is fresh, check leftmost */
	vruntime = me->vruntime;
	leftmost = __pick_first_minlat_entity(minlat_rq);
	if (leftmost)
		vruntime = min_t(u64, vruntime, leftmost->vruntime);
	minlat_rq->min_vruntime = max_t(u64, minlat_rq->min_vruntime,
					vruntime);

	__enqueue_minlat_entity(minlat_rq, me);
	minlat_rq->curr = NULL;

	/* Update PELT: entity stopped running */
	update_minlat_load_avg(rq, me);
}

static void
set_next_task_minlat(struct rq *rq, struct task_struct *p, bool first)
{
	struct sched_minlat_entity *me = &p->minlat;
	struct minlat_rq *minlat_rq = &rq->minlat;

	/*
	 * Remove the entity from the rb-tree. It stays out-of-tree
	 * while running, avoiding expensive conditional tree
	 * repositioning in update_curr_minlat(). put_prev_task will
	 * re-insert it when it stops running.
	 */
	if (likely(me->on_rq) && likely(!RB_EMPTY_NODE(&me->run_node)))
		__dequeue_minlat_entity(minlat_rq, me);

	/* Clear buddy — it's been picked or is no longer relevant */
	if (unlikely(minlat_rq->next == me))
		minlat_rq->next = NULL;

	minlat_rq->curr = me;

	p->se.exec_start = rq_clock_task(rq);
	p->se.prev_sum_exec_runtime = p->se.sum_exec_runtime;

	/* LLC stickiness: count runs on current LLC */
	me->llc_runs++;

	/* Update PELT: entity is now running */
	update_minlat_load_avg(rq, me);

	/* Update misfit status for the newly scheduled task */
	minlat_update_misfit_status(p, rq);
}

/* ==== SMT-aware interactivity tracking ==== */

/*
 * A task is "interactive" if its average run duration between sleeps
 * is short. This is used for SMT co-scheduling: pair an interactive
 * task with a throughput task on sibling hyperthreads for best utilization.
 */
#define MINLAT_INTERACTIVE_THRESH_NS	(2 * NSEC_PER_MSEC)
#define MINLAT_INTERACTIVITY_DECAY	8	/* exponential decay factor */

static void minlat_update_interactivity(struct task_struct *p,
					struct rq *rq, int flags)
{
	struct sched_minlat_entity *me = &p->minlat;

	if (flags & ENQUEUE_WAKEUP && me->last_sleep_duration) {
		u64 now = rq_clock(rq);
		u64 sleep_ns = now - me->last_sleep_duration;

		me->total_sleep_ns = (me->total_sleep_ns *
				      (MINLAT_INTERACTIVITY_DECAY - 1) +
				      sleep_ns) / MINLAT_INTERACTIVITY_DECAY;
	}
}

static void minlat_record_sleep(struct task_struct *p, struct rq *rq)
{
	struct sched_minlat_entity *me = &p->minlat;
	u64 run_ns = p->se.sum_exec_runtime - p->se.prev_sum_exec_runtime;

	me->total_run_ns = (me->total_run_ns *
			    (MINLAT_INTERACTIVITY_DECAY - 1) +
			    run_ns) / MINLAT_INTERACTIVITY_DECAY;

	me->interactive = (me->total_run_ns < MINLAT_INTERACTIVE_THRESH_NS);
	/* Use exec_start as sleep-start timestamp — already set by
	 * the last update_curr, avoids an extra rq_clock() read. */
	me->last_sleep_duration = p->se.exec_start;
}

/*
 * Check if a CPU's SMT sibling is running a task from the same tgid.
 * If so, prefer this core for cache/TLB sharing.
 */
#ifdef CONFIG_SCHED_SMT
static bool __maybe_unused
minlat_smt_sibling_has_tgid(int cpu, struct task_struct *p)
{
	const struct cpumask *smt_mask = cpu_smt_mask(cpu);
	int sibling;

	for_each_cpu(sibling, smt_mask) {
		struct task_struct *curr;

		if (sibling == cpu)
			continue;

		curr = cpu_curr(sibling);
		if (curr && curr->tgid == p->tgid)
			return true;
	}
	return false;
}

static bool __maybe_unused minlat_smt_has_interactive(int cpu)
{
	const struct cpumask *smt_mask = cpu_smt_mask(cpu);
	int sibling;

	for_each_cpu(sibling, smt_mask) {
		struct task_struct *curr;

		if (sibling == cpu)
			continue;

		curr = cpu_curr(sibling);
		if (curr && curr->sched_class == &minlat_sched_class &&
		    curr->minlat.interactive)
			return true;
	}
	return false;
}
#else
static bool __maybe_unused
minlat_smt_sibling_has_tgid(int cpu, struct task_struct *p)
{
	return false;
}
static bool __maybe_unused minlat_smt_has_interactive(int cpu)
{
	return false;
}
#endif

/*
 * Check if a CPU's entire physical core is idle (all SMT siblings idle).
 * Used for SMT-aware task placement: prefer fully idle cores over idle
 * SMT siblings to avoid sharing execution resources (~30-40% throughput
 * loss per task when two tasks share a physical core).
 */
#ifdef CONFIG_SCHED_SMT
static inline bool minlat_is_core_idle(int cpu)
{
	int sibling;

	for_each_cpu(sibling, cpu_smt_mask(cpu)) {
		if (sibling == cpu)
			continue;
		if (!idle_cpu(sibling))
			return false;
	}
	return true;
}
#else
static inline bool minlat_is_core_idle(int cpu)
{
	return true;
}
#endif

/* ==== LLC-aware CPU selection ==== */

/*
 * Track waker/wakee relationships for wake_wide() detection.
 * Same logic as CFS — decay flips once per second, increment
 * when the waker switches to a new wakee.
 */
static void minlat_record_wakee(struct task_struct *p)
{
	if (time_after(jiffies, current->wakee_flip_decay_ts + HZ)) {
		current->wakee_flips >>= 1;
		current->wakee_flip_decay_ts = jiffies;
	}

	if (current->last_wakee != p) {
		current->last_wakee = p;
		current->wakee_flips++;
	}
}

/*
 * Detect M:N waker/wakee relationships to avoid pulling many tasks
 * onto one CPU. Uses the same wakee_flips heuristic as CFS.
 *
 * Returns true if the relationship is "wide" (fan-out exceeds LLC size),
 * meaning we should NOT use wake affinity.
 */
static bool minlat_wake_wide(struct task_struct *p)
{
	unsigned int master = current->wakee_flips;
	unsigned int slave = p->wakee_flips;
	int factor = __this_cpu_read(sd_llc_size);

	if (master < slave)
		swap(master, slave);
	if (slave < factor || master < slave * factor)
		return false;
	return true;
}

/*
 * Check if a CPU is effectively idle for minlat task placement.
 * A CPU is effectively idle if:
 *  - It's truly idle (available_idle_cpu), OR
 *  - It only has delayed minlat entities (sleeping tasks kept
 *    in the tree for fast wakeup). These will be force-dequeued
 *    when the new task is picked, so the CPU is available.
 */
static inline bool minlat_cpu_effectively_idle(int cpu)
{
	struct minlat_rq *mrq = &cpu_rq(cpu)->minlat;

	if (available_idle_cpu(cpu))
		return true;

	/*
	 * CPU has only delayed entities — it will become idle once
	 * they're force-dequeued in pick_task_minlat.
	 */
	return mrq->nr_running > 0 &&
	       mrq->nr_running == mrq->nr_delayed &&
	       cpu_rq(cpu)->nr_running == mrq->nr_running;
}

/*
 * Wake affinity: try to place the wakee on the waker's CPU.
 *
 * For sync wakeups (WF_SYNC, e.g. futex_wake, pipe_write), the waker
 * is about to sleep, so its CPU will be free — placing the wakee there
 * gives it immediate access with warm cache and no contention.
 *
 * For non-sync wakeups from an idle waker CPU in the same LLC, we also
 * prefer the waker's CPU to keep tasks cache-local.
 *
 * Disabled for "wide" wakers (high fan-out) to avoid piling tasks
 * onto one CPU.
 *
 * Controlled by /sys/kernel/debug/sched/minlat/wake_affine.
 * Returns the target CPU, or -1 if wake affinity doesn't apply.
 */
static int minlat_wake_affine_cpu(struct task_struct *p, int prev_cpu,
				  int flags)
{
	int this_cpu = smp_processor_id();

	if (!minlat_wake_affine)
		return -1;

	/* Only on wakeup path, not fork/exec */
	if (!(flags & WF_TTWU))
		return -1;

	/* Must be allowed to run on the waker's CPU */
	if (!cpumask_test_cpu(this_cpu, p->cpus_ptr))
		return -1;

	/* Don't pull tasks from wide (fan-out) wakers */
	if (minlat_wake_wide(p))
		return -1;

	/*
	 * Don't pull a task to a CPU where it doesn't fit.
	 * A compute-bound task on a big core shouldn't be pulled
	 * to a little core just because the waker is there.
	 *
	 * Also respect big-core preference: if the task prefers big
	 * and this CPU is a little core, don't affine here.
	 */
	if (!minlat_task_fits_cpu(p, this_cpu))
		return -1;
	if (minlat_prefers_big(p) && !minlat_cpu_is_big(this_cpu))
		return -1;

	/*
	 * Sync wakeup: the waker is going to sleep right after this.
	 * Place the wakee on the waker's CPU if its effective load
	 * (after waker blocks) is no worse than the wakee's prev_cpu.
	 *
	 * This mirrors CFS wake_affine_weight(): since the waker is
	 * about to block, this_cpu's load drops by one. If that makes
	 * it equal or lighter than prev_cpu, the wakee benefits from
	 * the warm cache on this_cpu.
	 */
	if (flags & WF_SYNC) {
		unsigned int this_nr, prev_nr;

		/*
		 * Same CPU: the waker is about to sleep, freeing this
		 * CPU for the wakee. Always affine — no point scanning.
		 */
		if (this_cpu == prev_cpu)
			return this_cpu;

		/*
		 * After waker blocks, this_cpu has (this_nr - 1) tasks.
		 * Pull wakee here if that's no heavier than prev_cpu.
		 * Matches CFS wake_affine_weight() which subtracts the
		 * waker's load from this_cpu for sync wakeups.
		 */
		this_nr = cpu_rq(this_cpu)->minlat.nr_running -
			  cpu_rq(this_cpu)->minlat.nr_delayed;
		prev_nr = cpu_rq(prev_cpu)->minlat.nr_running -
			  cpu_rq(prev_cpu)->minlat.nr_delayed;
		if (this_nr <= prev_nr + 1)
			return this_cpu;
	}

	/*
	 * Non-sync: prefer an idle CPU for cache warmth.
	 * Mirrors CFS wake_affine_idle().
	 */
	if (minlat_cpu_effectively_idle(this_cpu))
		return this_cpu;

	if (this_cpu != prev_cpu &&
	    cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    minlat_cpu_effectively_idle(prev_cpu))
		return prev_cpu;

	return -1;
}

/*
 * CPU selection for wakeup. Optimized for low latency.
 *
 * O(1) checks (no scanning):
 *  0. Wake affinity: waker's CPU for sync wakeups (futex, pipe)
 *  1. prev_cpu if idle (cache warm, zero cost)
 *  2. recent_used_cpu if idle and same LLC (cache warm)
 *
 * Single scan (starting from prev_cpu for distribution):
 *  3. Any idle CPU in same LLC → immediate return
 *  4. First idle CPU outside LLC → remember as fallback
 *
 * Fully loaded fallback:
 *  5. Least-loaded CPU
 */
static int
select_task_rq_minlat(struct task_struct *p, int prev_cpu, int flags)
{
	const struct cpumask *allowed = p->cpus_ptr;
	int cpu, recent_used_cpu, best_cpu = -1;
	unsigned int best_nr;

	/*
	 * 0. Wake affinity — for sync wakeups (futex, pipe), place the
	 * wakee on the waker's CPU which is about to go idle.
	 * Check wake affine BEFORE recording wakee, so last_wakee
	 * reflects the previous wakeup target (not the current one).
	 */
	cpu = minlat_wake_affine_cpu(p, prev_cpu, flags);

	if (flags & WF_TTWU)
		minlat_record_wakee(p);
	if (cpu >= 0)
		return cpu;

	/*
	 * Fork balancing: spread new tasks across the LLC.
	 *
	 * CFS uses SD_BALANCE_FORK → sched_balance_find_dst_cpu() to
	 * find the idlest CPU within the LLC domain. We do the same:
	 * scan the LLC for the least-loaded CPU, with a randomized
	 * start to prevent thundering-herd pileup when many children
	 * are forked from the same parent CPU.
	 */
	if (flags & WF_FORK) {
		struct sched_domain *sd, *numa_sd;
		int best_cpu_local = -1, best_cpu_remote = -1;
		unsigned int best_nr_local = UINT_MAX;
		unsigned int best_nr_remote = UINT_MAX;
		int local_llc_load = 0, remote_llc_load = 0;
		int local_llc_cpus = 0;
		bool asym = sched_asym_cpucap_active();

		/*
		 * Fork balancing with pick-2 LLC selection:
		 *
		 * 1. Scan current LLC for idle or least-loaded CPU
		 * 2. Pick a random LLC in same NUMA, compare load
		 * 3. Use the less-loaded LLC
		 * 4. If NUMA node is saturated, try cross-NUMA
		 *
		 * On asymmetric capacity systems, prefer the highest-
		 * capacity idle CPU since forked tasks have no
		 * utilization history to guide placement.
		 */
		rcu_read_lock();
		sd = rcu_dereference(per_cpu(sd_llc, prev_cpu));
		if (sd) {
			const struct cpumask *llc_span = sched_domain_span(sd);
			int idle_big_cpu = -1;
			unsigned long idle_big_cap = 0;

			for_each_cpu_wrap(cpu, llc_span, prev_cpu + 1) {
				unsigned int nr;

				if (!cpumask_test_cpu(cpu, allowed))
					continue;
				local_llc_cpus++;
				nr = cpu_rq(cpu)->minlat.nr_running;
				local_llc_load += nr;
				if (nr == 0) {
					/*
					 * On symmetric systems, return the
					 * first idle CPU immediately.
					 * On asymmetric, track the highest-
					 * capacity idle CPU.
					 */
					if (!asym) {
						rcu_read_unlock();
						return cpu;
					}
					if (arch_scale_cpu_capacity(cpu) >
					    idle_big_cap) {
						idle_big_cap =
						    arch_scale_cpu_capacity(cpu);
						idle_big_cpu = cpu;
					}
				}
				if (nr < best_nr_local) {
					best_nr_local = nr;
					best_cpu_local = cpu;
				}
			}
			if (idle_big_cpu >= 0) {
				rcu_read_unlock();
				return idle_big_cpu;
			}
		}

		/*
		 * Pick-2: sample a random LLC in the same NUMA node.
		 * If it's less loaded, place the fork there instead.
		 */
		for_each_domain(prev_cpu, numa_sd) {
			const struct cpumask *numa_span;
			int rand_cpu, rand_llc;
			struct sched_domain *rand_sd;
			int rcpus = 0, rload = 0;

			if (numa_sd == sd)
				continue;

			numa_span = sched_domain_span(numa_sd);
			rand_cpu = cpumask_any_and_distribute(
					numa_span, cpu_online_mask);
			if (rand_cpu >= nr_cpu_ids ||
			    rand_cpu == prev_cpu)
				continue;

			rand_llc = per_cpu(sd_llc_id, rand_cpu);
			if (rand_llc == per_cpu(sd_llc_id, prev_cpu))
				continue;

			rand_sd = rcu_dereference(
					per_cpu(sd_llc, rand_cpu));
			if (!rand_sd)
				continue;

			{
			int remote_idle_big = -1;
			unsigned long remote_big_cap = 0;

			for_each_cpu(cpu, sched_domain_span(rand_sd)) {
				unsigned int nr;

				if (!cpumask_test_cpu(cpu, allowed))
					continue;
				rcpus++;
				nr = cpu_rq(cpu)->minlat.nr_running;
				rload += nr;
				if (nr == 0) {
					if (!asym) {
						rcu_read_unlock();
						return cpu;
					}
					if (arch_scale_cpu_capacity(cpu) >
					    remote_big_cap) {
						remote_big_cap =
						    arch_scale_cpu_capacity(cpu);
						remote_idle_big = cpu;
					}
				}
				if (nr < best_nr_remote) {
					best_nr_remote = nr;
					best_cpu_remote = cpu;
				}
			}
			if (remote_idle_big >= 0) {
				rcu_read_unlock();
				return remote_idle_big;
			}
			}
			remote_llc_load = rcpus ? rload : INT_MAX;

			/*
			 * Compare per-CPU average load between LLCs.
			 * Use the less-loaded LLC if the imbalance exceeds
			 * the tunable threshold percentage.
			 *
			 * Cross-NUMA requires a larger imbalance to justify
			 * remote memory access cost.
			 *
			 * Formula: remote_avg * 100 + threshold * local_avg
			 *          <= local_avg * 100
			 * i.e.: remote is at least threshold% less loaded.
			 */
			if (best_cpu_remote >= 0 && rcpus > 0 &&
			    local_llc_cpus > 0) {
				bool cross_numa = numa_sd->flags & SD_NUMA;
				unsigned int thresh = cross_numa ?
					minlat_fork_numa_imbalance_pct :
					minlat_fork_imbalance_pct;
				unsigned int local_avg =
					local_llc_load * 100 / local_llc_cpus;
				unsigned int remote_avg =
					rload * 100 / rcpus;

				if (local_avg > 0 &&
				    remote_avg * 100 <=
				    local_avg * (100 - thresh)) {
					rcu_read_unlock();
					return best_cpu_remote;
				}
			}

			/*
			 * For same-NUMA domains, only try one random LLC
			 * (pick-2). For cross-NUMA, also try one.
			 */
			break;
		}

		rcu_read_unlock();

		/* Local LLC least-loaded is our fallback */
		if (best_cpu_local >= 0)
			return best_cpu_local;

		/* No valid CPUs found — fall through to general path */
	}

	/*
	 * Check if this task has a big-core preference. If so, O(1)
	 * fast paths on little cores are skipped — we want the scan
	 * to find a big core instead. The scan has a little-core
	 * fallback so we never starve.
	 */
	{
	bool wants_big = minlat_prefers_big(p);

	/* 1. prev_cpu if idle — fast path, no scanning */
	if (cpu_active(prev_cpu) && cpumask_test_cpu(prev_cpu, allowed) &&
	    minlat_cpu_effectively_idle(prev_cpu) &&
	    minlat_task_fits_cpu(p, prev_cpu) &&
	    !(wants_big && !minlat_cpu_is_big(prev_cpu)))
		return prev_cpu;

	/*
	 * 2. recent_used_cpu — O(1) check of a CPU this task recently
	 * ran on. CFS maintains p->recent_used_cpu; we piggyback on it.
	 * Only useful if it's in the same LLC (cache warm) and idle.
	 */
	recent_used_cpu = p->recent_used_cpu;
	p->recent_used_cpu = prev_cpu;

	if (recent_used_cpu != prev_cpu &&
	    recent_used_cpu >= 0 &&
	    cpu_active(recent_used_cpu) &&
	    cpumask_test_cpu(recent_used_cpu, allowed) &&
	    cpus_share_cache(recent_used_cpu, prev_cpu) &&
	    minlat_cpu_effectively_idle(recent_used_cpu) &&
	    minlat_task_fits_cpu(p, recent_used_cpu) &&
	    !(wants_big && !minlat_cpu_is_big(recent_used_cpu)))
		return recent_used_cpu;

	/*
	 * 3-4. Single scan for idle CPU, starting from prev_cpu so
	 * each task scans a different order and spreads evenly.
	 * Prefer same-LLC idle CPUs (cheaper migration).
	 *
	 * On asymmetric capacity systems, skip CPUs where the task
	 * doesn't fit (little cores for compute-bound tasks). Track
	 * a fallback for the case where no fitting CPU is idle — a
	 * little core is better than staying on an overloaded big.
	 *
	 * When the task prefers big cores (interactive_big_prefer or
	 * compute_big_prefer), additionally skip little cores even
	 * if the task fits on them. The fallback catches the case
	 * where no big core is idle.
	 *
	 * SIS_UTIL-style scan depth limiting: on large machines,
	 * scanning all CPUs for an idle one is expensive. Use
	 * per-LLC idle tracking (sd_llc_shared->nr_busy_cpus,
	 * maintained by the NOHZ subsystem) to decide:
	 *
	 * 1. If our LLC has idle CPUs, skip off-LLC scan — cheap
	 *    local migration is available.
	 * 2. If our LLC is fully busy, compute off-LLC scan depth
	 *    from global utilization (quadratic curve like CFS).
	 *
	 * In-LLC CPUs are always fully scanned (cache-local,
	 * small scan space) — the limit applies only to off-LLC.
	 */
	{
		int fallback_cpu = -1;
		int nr_scanned = 0;
		int scan_limit;
		unsigned int nr_cpus;
		struct sched_domain_shared *sds;
#ifdef CONFIG_SCHED_SMT
		int idle_smt_cpu = -1;
		bool smt = sched_smt_active();
#endif
#ifdef CONFIG_NUMA_BALANCING
		int preferred_nid = READ_ONCE(p->numa_preferred_nid);
#endif

		nr_cpus = num_online_cpus();

		/*
		 * Per-LLC idle detection: sd_llc_shared->nr_busy_cpus
		 * tracks how many CPUs in this LLC have exited NOHZ
		 * idle. llc_size - nr_busy_cpus = idle CPUs in LLC.
		 *
		 * If idle CPUs exist in our LLC, focus the scan
		 * there (scan_limit=0 skips off-LLC CPUs). If the
		 * LLC is fully busy, fall through to compute an
		 * off-LLC scan limit from global utilization.
		 */
		sds = rcu_dereference_all(per_cpu(sd_llc_shared, prev_cpu));
		if (sds) {
			int llc_sz = per_cpu(sd_llc_size, prev_cpu);
			int llc_busy = atomic_read(&sds->nr_busy_cpus);
			int llc_idle = llc_sz - llc_busy;

			if (llc_idle > 0) {
				/*
				 * LLC has idle CPUs — stay local.
				 * The in-LLC scan below will find them.
				 */
				scan_limit = 0;
				goto do_scan;
			}
		}

		/*
		 * LLC fully busy (or no LLC domain). Compute off-LLC
		 * scan depth from global utilization.
		 *
		 * busy_pct = nr_overloaded / nr_online
		 * scan_frac = 1 - (busy_pct / 0.85)^2
		 * scan_limit = nr_online * scan_frac
		 *
		 * Quadratic curve: at 0% busy → scan all off-LLC,
		 * at 85% busy → scan 0. Minimum of 4 ensures we
		 * check at least a few off-LLC CPUs under moderate
		 * load. Small machines (<=16 CPUs) always scan all.
		 */
		{
			unsigned int nr_busy = atomic_read(&minlat_nr_overloaded);

			if (nr_busy * 100 >= nr_cpus * 85) {
				scan_limit = 0;
			} else if (nr_cpus <= 16) {
				scan_limit = nr_cpus;
			} else {
				unsigned int x = nr_busy * 100;
				unsigned int thresh = nr_cpus * 85;

				scan_limit = nr_cpus -
					(u64)x * x * nr_cpus /
					((u64)thresh * thresh);
				scan_limit = max(scan_limit, 4);
			}
		}
do_scan:

		for_each_cpu_wrap(cpu, cpu_active_mask, prev_cpu) {
			if (!cpumask_test_cpu(cpu, allowed))
				continue;

			/*
			 * In-LLC CPUs are always checked (cheap
			 * migration, small scan space). Off-LLC
			 * CPUs count against the scan limit.
			 */
			if (!cpus_share_cache(cpu, prev_cpu) &&
			    ++nr_scanned > scan_limit)
				break;

			if (!minlat_cpu_effectively_idle(cpu))
				continue;

			if (!minlat_task_fits_cpu(p, cpu)) {
				if (fallback_cpu < 0)
					fallback_cpu = cpu;
				continue;
			}

			/* Soft big-core preference: skip little cores */
			if (wants_big && !minlat_cpu_is_big(cpu)) {
				if (fallback_cpu < 0)
					fallback_cpu = cpu;
				continue;
			}

			if (cpus_share_cache(cpu, prev_cpu)) {
#ifdef CONFIG_SCHED_SMT
				/*
				 * SMT-aware: prefer idle cores (all
				 * siblings idle) over idle SMT siblings
				 * to avoid sharing execution resources.
				 * Two tasks on the same physical core
				 * lose ~30-40% throughput each.
				 */
				if (smt && !minlat_is_core_idle(cpu)) {
					if (idle_smt_cpu < 0)
						idle_smt_cpu = cpu;
					continue;
				}
#endif
				return cpu;
			}

			/* Off-LLC idle CPU */
			if (best_cpu < 0) {
				best_cpu = cpu;
			}
#ifdef CONFIG_NUMA_BALANCING
			/*
			 * NUMA preference: among off-LLC idle CPUs,
			 * prefer one on the task's preferred NUMA
			 * node for memory locality.
			 */
			else if (preferred_nid != NUMA_NO_NODE &&
				 cpu_to_node(cpu) == preferred_nid &&
				 cpu_to_node(best_cpu) != preferred_nid) {
				best_cpu = cpu;
			}
#endif
		}
#ifdef CONFIG_SCHED_SMT
		/* In-LLC SMT sibling > off-LLC idle core */
		if (idle_smt_cpu >= 0)
			return idle_smt_cpu;
#endif
		if (best_cpu >= 0)
			return best_cpu;

		/* No preferred idle CPU — use fallback (little core) */
		if (fallback_cpu >= 0)
			return fallback_cpu;
	}
	} /* end wants_big scope */

	/*
	 * 5. No idle CPU found.
	 *
	 * For fork: find least-loaded CPU globally to spread children.
	 * For wakeup: stay on prev_cpu — the idle-pull mechanism and
	 * wake affinity handle redistribution without the O(N) scan
	 * cost on every wakeup.
	 */
	if (!(flags & WF_FORK))
		return prev_cpu;

	best_cpu = prev_cpu;
	best_nr = cpu_rq(prev_cpu)->minlat.nr_running;

	for_each_cpu_wrap(cpu, cpu_active_mask, prev_cpu) {
		unsigned int nr;

		if (!cpumask_test_cpu(cpu, allowed))
			continue;
		nr = cpu_rq(cpu)->minlat.nr_running;
		if (nr < best_nr) {
			best_nr = nr;
			best_cpu = cpu;
			if (nr == 0)
				break;
		}
	}

	return best_cpu;
}

/* ==== idle-pull load balancing ==== */

/* Thresholds defined as debugfs-tunable variables above */

static bool minlat_task_cache_hot(struct task_struct *p, struct rq *src_rq)
{
	if (unlikely(p->sched_class != &minlat_sched_class))
		return false;

	if (p->se.exec_start == 0)
		return false;

	return (rq_clock_task(src_rq) - p->se.exec_start) < minlat_cache_hot_ns;
}

/*
 * Check if a NUMA node is saturated: most CPUs have at least one
 * minlat task. When saturated, cross-NUMA migration cooldowns apply
 * to prevent tasks bouncing back and forth across nodes.
 */
static bool minlat_numa_saturated(int node)
{
	int cpu, busy = 0, total = 0;

	for_each_online_cpu(cpu) {
		if (cpu_to_node(cpu) != node)
			continue;
		total++;
		if (cpu_rq(cpu)->minlat.nr_running > 0)
			busy++;
	}

	/* Saturated when busy CPUs exceed the tunable percentage */
	return total > 0 && busy * 100 > total * minlat_numa_saturated_pct;
}

/*
 * Check cross-NUMA migration cooldown.
 * Only applies when:
 *  1. This is a cross-NUMA pull, AND
 *  2. The source NUMA node is saturated
 *
 * When the source node is saturated, pulling tasks away just
 * creates churn — the task will likely get pulled back soon.
 * The cooldown prevents this ping-pong.
 */
static bool minlat_migration_cooldown(struct task_struct *p,
				      struct rq *src_rq)
{
	u64 now;

	if (!p->minlat.last_migrate_ts)
		return false;

	now = rq_clock_task(src_rq);
	if ((now - p->minlat.last_migrate_ts) >= minlat_migration_cooldown_ns)
		return false;

	/* Cooldown active only when source NUMA is saturated */
	return minlat_numa_saturated(cpu_to_node(src_rq->cpu));
}

/*
 * Find the best candidate task to pull from @src_rq to @this_cpu.
 * Walk the rb-tree from the right (highest vruntime = most starved)
 * to find a migratable task.
 *
 * NUMA-aware: among migratable candidates, prefer tasks whose
 * numa_preferred_nid matches the destination node. This pulls tasks
 * toward their memory, complementing page-fault-based NUMA migration.
 *
 * @cross_numa: true if this is a cross-NUMA pull (enables cooldown checks)
 */
static struct task_struct *
minlat_pick_pullable_task(struct rq *src_rq, int this_cpu, bool cross_numa)
{
	struct rb_node *node;
	struct sched_minlat_entity *me;
	struct task_struct *p, *fallback = NULL;
	int scanned = 0;
	bool cross_llc = !cpus_share_cache(src_rq->cpu, this_cpu);
#ifdef CONFIG_NUMA_BALANCING
	int dst_nid = cpu_to_node(this_cpu);
#endif

	for (node = rb_last(&src_rq->minlat.tasks_timeline.rb_root);
	     node && scanned < 4; node = rb_prev(node), scanned++) {
		me = rb_entry(node, struct sched_minlat_entity, run_node);
		p = container_of(me, struct task_struct, minlat);

		if (task_current(src_rq, p))
			continue;

		/* Skip delayed sleepers — not actually runnable */
		if (p->se.sched_delayed)
			continue;

		if (is_migration_disabled(p))
			continue;

		if (!cpumask_test_cpu(this_cpu, p->cpus_ptr))
			continue;

		if (minlat_task_cache_hot(p, src_rq))
			continue;

		/* Cross-NUMA cooldown only when source node is saturated */
		if (cross_numa && minlat_migration_cooldown(p, src_rq))
			continue;

		/*
		 * LLC stickiness: don't pull tasks across LLCs until
		 * they've run enough times on their current LLC.
		 * This prevents migration ping-pong that wastes cache.
		 * Inspired by p2dq's min_llc_runs concept.
		 */
		if (cross_llc && minlat_llc_stickiness &&
		    me->llc_runs < minlat_llc_stickiness)
			continue;

#ifdef CONFIG_NUMA_BALANCING
		/*
		 * Prefer tasks whose preferred NUMA node matches dst.
		 * Remember first fallback in case no NUMA match is found.
		 */
		if (p->numa_preferred_nid == dst_nid)
			return p;
		if (!fallback)
			fallback = p;
#else
		return p;
#endif
	}

	return fallback;
}

/*
 * Try to pull a task from @src_rq to @this_rq.
 * Both rq locks must be held (via double_lock_balance).
 * @cross_numa: whether src and dst are on different NUMA nodes.
 */
static bool minlat_pull_from(struct rq *this_rq, struct rq *src_rq,
			     bool cross_numa)
{
	struct task_struct *p;

	if (src_rq->minlat.nr_running <= 1)
		return false;

	p = minlat_pick_pullable_task(src_rq, this_rq->cpu, cross_numa);
	if (!p)
		return false;

	/* Stamp migration time — used for cross-NUMA cooldown */
	if (cross_numa)
		p->minlat.last_migrate_ts = rq_clock_task(src_rq);

	/* Reset LLC stickiness counter on cross-LLC migration */
	if (!cpus_share_cache(src_rq->cpu, this_rq->cpu))
		p->minlat.llc_runs = 0;

	move_queued_task_locked(src_rq, this_rq, p);
	return true;
}

/*
 * Find the busiest CPU within @mask that has minlat tasks.
 * Returns the rq of the busiest CPU, or NULL if none is overloaded.
 * @min_nr: minimum nr_running to consider (caller sets threshold).
 */
static struct rq *
minlat_find_busiest_rq(struct rq *this_rq, const struct cpumask *mask,
		       unsigned int min_nr)
{
	struct rq *best_rq = NULL;
	unsigned int best_nr = min_nr;
	int cpu;

	for_each_cpu(cpu, mask) {
		struct rq *rq;

		if (cpu == this_rq->cpu)
			continue;

		rq = cpu_rq(cpu);
		if (rq->minlat.nr_running > best_nr) {
			best_nr = rq->minlat.nr_running;
			best_rq = rq;
		}
	}

	return best_rq;
}

/*
 * Find a CPU with a misfit task that we can help.
 * Returns the rq of a lower-capacity CPU with a misfit task, or NULL.
 * Only useful when this_cpu has higher capacity than the source.
 */
static struct rq *
minlat_find_misfit_rq(struct rq *this_rq, const struct cpumask *mask)
{
	struct rq *best_rq = NULL;
	unsigned long best_misfit = 0;
	unsigned long this_cap = arch_scale_cpu_capacity(this_rq->cpu);
	int cpu;

	for_each_cpu(cpu, mask) {
		struct rq *rq;

		if (cpu == this_rq->cpu)
			continue;

		rq = cpu_rq(cpu);

		/* Only pull from CPUs with lower capacity than ours */
		if (arch_scale_cpu_capacity(cpu) >= this_cap)
			continue;

		if (rq->misfit_task_load > best_misfit) {
			best_misfit = rq->misfit_task_load;
			best_rq = rq;
		}
	}

	return best_rq;
}

/*
 * Try to pull a task from @src_rq with double-lock.
 * Returns true if a task was successfully migrated.
 */
static bool minlat_try_pull(struct rq *this_rq, struct rq *src_rq,
			    bool cross_numa)
{
	bool pulled;

	double_lock_balance(this_rq, src_rq);
	update_rq_clock(this_rq);
	update_rq_clock(src_rq);
	pulled = minlat_pull_from(this_rq, src_rq, cross_numa);
	double_unlock_balance(this_rq, src_rq);
	return pulled;
}

/*
 * Pick a random LLC within @numa_span and return its busiest CPU's rq.
 * Used for pick-2 load balancing: sample two random LLCs in the same
 * NUMA node and steal from the busier one.
 */
static struct rq *
minlat_pick_random_llc_rq(struct rq *this_rq, const struct cpumask *numa_span)
{
	int rand_cpu;

	rand_cpu = cpumask_any_and_distribute(numa_span, cpu_online_mask);
	if (rand_cpu >= nr_cpu_ids || rand_cpu == this_rq->cpu)
		return NULL;

	/*
	 * Find the busiest CPU in the same LLC as rand_cpu.
	 * This gives us an LLC-level pick-2 rather than CPU-level.
	 */
	{
		struct sched_domain *rand_sd;
		struct rq *best = NULL;
		unsigned int best_nr = 1;
		int cpu;

		rand_sd = rcu_dereference(per_cpu(sd_llc, rand_cpu));
		if (!rand_sd)
			return cpu_rq(rand_cpu)->minlat.nr_running > 1 ?
				cpu_rq(rand_cpu) : NULL;

		for_each_cpu(cpu, sched_domain_span(rand_sd)) {
			struct rq *rq = cpu_rq(cpu);

			if (cpu == this_rq->cpu)
				continue;
			if (rq->minlat.nr_running > best_nr) {
				best_nr = rq->minlat.nr_running;
				best = rq;
			}
		}
		return best;
	}
}

/*
 * Topology-adaptive idle-pull balancing.
 *
 * Uses the sched_domain hierarchy for correct topology awareness.
 * The search escalates from cheap to expensive migration domains:
 *
 * Single-LLC: simple busiest-CPU scan, no topology overhead.
 * Multi-LLC:  LLC-level pick-2 within NUMA node, then cross-NUMA.
 *
 * Balancing is a noop when:
 *  - No CPU in the domain has >1 minlat task (nothing to pull)
 *  - Load is roughly balanced (within 1 task per CPU average)
 *  - System is fully saturated (everyone busy, pulling just churns)
 */
static void pull_minlat_task(struct rq *this_rq)
{
	int this_cpu = this_rq->cpu;
	struct sched_domain *sd;
	struct rq *src_rq;

	rcu_read_lock();

	/*
	 * Misfit pull: on asymmetric capacity systems, prioritize
	 * pulling misfit tasks from lower-capacity CPUs. This runs
	 * before the normal overloaded pull so that big cores rescue
	 * compute-bound tasks stuck on little cores even when those
	 * little cores only have a single task (not overloaded).
	 */
	if (sched_asym_cpucap_active()) {
		sd = rcu_dereference(per_cpu(sd_asym_cpucapacity, this_cpu));
		if (sd) {
			src_rq = minlat_find_misfit_rq(this_rq,
						sched_domain_span(sd));
			if (src_rq) {
				bool cross = sd->flags & SD_NUMA;

				if (minlat_try_pull(this_rq, src_rq, cross)) {
					rcu_read_unlock();
					return;
				}
			}
		}
	}

	for_each_domain(this_cpu, sd) {
		const struct cpumask *span = sched_domain_span(sd);
		bool cross_numa = sd->flags & SD_NUMA;

		/* Find the busiest CPU with >1 task in this domain */
		src_rq = minlat_find_busiest_rq(this_rq, span, 1);
		if (!src_rq)
			continue;

		/*
		 * For NUMA-crossing domains, require significant imbalance.
		 * Cross-NUMA migration involves remote memory access.
		 */
		if (cross_numa &&
		    src_rq->minlat.nr_running < minlat_numa_imbalance_min + 1)
			continue;

		/*
		 * LLC-level pick-2 within this domain.
		 * Sample a random LLC and compare its busiest CPU with
		 * the one we found. Pull from whichever is busier.
		 * This distributes pull pressure and avoids thundering
		 * herd on the single busiest CPU.
		 */
		if (sd->span_weight > per_cpu(sd_llc_size, this_cpu)) {
			struct rq *rand_rq;

			rand_rq = minlat_pick_random_llc_rq(this_rq, span);
			if (rand_rq &&
			    rand_rq->minlat.nr_running >
			    src_rq->minlat.nr_running)
				src_rq = rand_rq;
		}

		if (minlat_try_pull(this_rq, src_rq, cross_numa))
			break;
	}

	rcu_read_unlock();
}

static int
balance_minlat(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	struct minlat_rq *minlat_rq = &rq->minlat;

	/* Have actual runnable (non-delayed) tasks — no pull needed */
	if (minlat_rq->nr_running > minlat_rq->nr_delayed)
		return 1;

	/*
	 * All tasks are delayed or none exist. Try to pull real
	 * work before pick_task has to scan/force-dequeue.
	 */
	if (sched_minlat_any_overloaded(rq)) {
		rq_unpin_lock(rq, rf);
		pull_minlat_task(rq);
		rq_repin_lock(rq, rf);

		if (minlat_rq->nr_running > minlat_rq->nr_delayed)
			return 1;
	}

	/* Delayed entities still need pick_task to handle them */
	return minlat_rq->nr_running > 0;
}

/* ==== active balancing (push from overloaded CPUs) ==== */

/*
 * Pick a task from @src_rq that can be pushed to @target_cpu.
 * Walks the rb-tree from the right (highest vruntime = most starved)
 * to find a migratable task. Active balance is a last resort, so
 * we skip cache-hot and LLC stickiness checks — the imbalance is
 * more important than cache warmth.
 */
static struct task_struct *
minlat_pick_pushable_task(struct rq *src_rq, int target_cpu)
{
	struct rb_node *node;
	struct sched_minlat_entity *me;
	struct task_struct *p;
	int scanned = 0;

	for (node = rb_last(&src_rq->minlat.tasks_timeline.rb_root);
	     node && scanned < 4; node = rb_prev(node), scanned++) {
		me = rb_entry(node, struct sched_minlat_entity, run_node);
		p = container_of(me, struct task_struct, minlat);

		if (p->se.sched_delayed)
			continue;

		if (is_migration_disabled(p))
			continue;

		if (!cpumask_test_cpu(target_cpu, p->cpus_ptr))
			continue;

		return p;
	}
	return NULL;
}

/*
 * CPU stopper callback: push a task from this (overloaded) CPU
 * to the target CPU recorded in push_cpu.
 *
 * Runs on the overloaded CPU via stop_one_cpu_nowait(). The stopper
 * preempts the current task, allowing us to pick and migrate a
 * queued task. Mirrors CFS's active_load_balance_cpu_stop().
 */
/*
 * CPU stopper callback: runs on the TARGET (idle) CPU, pulls a task
 * from the overloaded source CPU.
 *
 * We run the stopper on the target instead of the source to avoid a
 * deadlock: task_tick_minlat holds the source rq lock, and calling
 * stop_one_cpu_nowait on the same CPU would try to wake the stopper
 * thread, which needs the rq lock → deadlock. Running on the target
 * (different CPU) avoids this.
 */
static int minlat_active_balance_cpu_stop(void *data)
{
	struct rq *src_rq = data;
	struct minlat_rq *src_mrq = &src_rq->minlat;
	int src_cpu = cpu_of(src_rq);
	int target_cpu = smp_processor_id();
	struct rq *target_rq = cpu_rq(target_cpu);
	struct task_struct *p = NULL;
	struct rq_flags rf;

	/* Lock the source rq to pick and detach a task */
	rq_lock_irq(src_rq, &rf);

	if (!cpu_active(src_cpu) || !cpu_active(target_cpu))
		goto out_unlock;

	if (!src_mrq->active_balance)
		goto out_unlock;

	/* Source needs at least 2 effective tasks to give one away */
	if (src_mrq->nr_running <= src_mrq->nr_delayed ||
	    src_mrq->nr_running - src_mrq->nr_delayed < 2)
		goto out_unlock;

	p = minlat_pick_pushable_task(src_rq, target_cpu);
	if (!p)
		goto out_unlock;

	/* Detach: dequeue from source rq, set new CPU */
	update_rq_clock(src_rq);
	deactivate_task(src_rq, p, DEQUEUE_NOCLOCK);
	set_task_cpu(p, target_cpu);

	/* Reset LLC stickiness on cross-LLC migration */
	if (!cpus_share_cache(src_cpu, target_cpu))
		p->minlat.llc_runs = 0;

out_unlock:
	src_mrq->active_balance = 0;
	rq_unlock(src_rq, &rf);

	if (p) {
		/* Attach: enqueue on target (this) rq */
		rq_lock(target_rq, &rf);
		update_rq_clock(target_rq);
		activate_task(target_rq, p, 0);
		wakeup_preempt(target_rq, p, 0);
		rq_unlock(target_rq, &rf);
	}

	local_irq_enable();
	return 0;
}

/*
 * Tick-driven active balance check. Called from task_tick_minlat.
 *
 * Handles the case where idle-pull failed: this CPU has 2+ tasks
 * but some CPUs are idle. This can happen when all pushable tasks
 * are cache-hot, migration-disabled, or have restrictive affinity.
 *
 * Only targets IDLE CPUs. If all CPUs are busy, wakeup balancing
 * and natural placement distribute work without the overhead of
 * CPU stopper migrations (which disrupt producer-consumer locality).
 *
 * Rate-limited to once per ~32ms to keep tick overhead low.
 */
static void minlat_check_balance(struct rq *rq)
{
	struct minlat_rq *mrq = &rq->minlat;
	int this_cpu = cpu_of(rq);
	unsigned int this_eff;
	struct sched_domain *sd;
	int target_cpu = -1;

	if (mrq->nr_running <= mrq->nr_delayed)
		return;

	this_eff = mrq->nr_running - mrq->nr_delayed;

	if (this_eff < 2)
		return;

	if (mrq->active_balance)
		return;

	if (time_before(jiffies, mrq->next_balance))
		return;
	mrq->next_balance = jiffies + msecs_to_jiffies(32);

	rcu_read_lock();
	for_each_domain(this_cpu, sd) {
		int cpu;

		for_each_cpu(cpu, sched_domain_span(sd)) {
			if (cpu == this_cpu)
				continue;

			if (!idle_cpu(cpu))
				continue;

			target_cpu = cpu;
			break;
		}
		if (target_cpu >= 0)
			break;
	}
	rcu_read_unlock();

	if (target_cpu < 0)
		return;

	mrq->active_balance = 1;
	mrq->push_cpu = target_cpu;
	stop_one_cpu_nowait(target_cpu,
			    minlat_active_balance_cpu_stop,
			    rq, &mrq->active_balance_work);
}

/* ==== tick / lifecycle ==== */

static void task_tick_minlat(struct rq *rq, struct task_struct *p, int queued)
{
	update_curr_minlat(rq);
	check_preempt_tick_minlat(rq, p);

	/* Deferred tgid_ctx allocation — keep wakeup path fast */
	if (unlikely(!p->minlat.tgid_ctx))
		minlat_ensure_tgid_ctx(p);
	else
		minlat_maybe_update_llc(p);

	/* Deferred interactivity update — keep enqueue path fast */
	minlat_update_interactivity(p, rq, ENQUEUE_WAKEUP);

	/* Update PELT and misfit status */
	update_minlat_load_avg(rq, &p->minlat);
	minlat_update_misfit_status(p, rq);

	/* Drive NUMA page scanning */
	if (static_branch_unlikely(&sched_numa_balancing))
		minlat_task_tick_numa(rq, p);

	/* Active balance: push tasks from overloaded CPUs */
	minlat_check_balance(rq);
}

static void task_dead_minlat(struct task_struct *p)
{
	struct minlat_tgid_ctx *ctx = p->minlat.tgid_ctx;

	if (ctx) {
		if (p->minlat.prev_llc == ctx->preferred_llc)
			atomic_dec(&ctx->nr_on_llc);
		atomic_dec(&ctx->nr_tasks);
		minlat_tgid_ctx_put(ctx);
		p->minlat.tgid_ctx = NULL;
	}
}

/*
 * Called when a task is migrated to a new CPU. Reset PELT
 * last_update_time so the entity avg will be re-synced to
 * the new rq's clock on the next update_minlat_load_avg().
 */
static void migrate_task_rq_minlat(struct task_struct *p, int new_cpu)
{
	p->minlat.avg.last_update_time = 0;
}

static void switched_to_minlat(struct rq *rq, struct task_struct *p)
{
	if (task_on_rq_queued(p)) {
		minlat_set_load_weight(p);
		if (rq->curr != p)
			wakeup_preempt_minlat(rq, p, 0);
	}
}

static void prio_changed_minlat(struct rq *rq, struct task_struct *p,
				u64 oldprio)
{
	struct sched_minlat_entity *me = &p->minlat;
	struct minlat_rq *minlat_rq = &rq->minlat;
	unsigned long old_weight;

	if (!task_on_rq_queued(p)) {
		minlat_set_load_weight(p);
		return;
	}

	/* Update rq aggregate load: remove old weight, add new */
	old_weight = scale_load_down(me->load.weight);
	minlat_set_load_weight(p);
	minlat_rq->load_weight += scale_load_down(me->load.weight) - old_weight;

	/*
	 * Requeue: dequeue from rb-tree and re-insert with updated weight.
	 * Skip if this is the currently running task — it's out of tree.
	 */
	if (minlat_rq->curr != me && !RB_EMPTY_NODE(&me->run_node)) {
		__dequeue_minlat_entity(minlat_rq, me);
		__enqueue_minlat_entity(minlat_rq, me);
	}

	if (rq->curr == p)
		check_preempt_tick_minlat(rq, p);
	else
		wakeup_preempt_minlat(rq, p, 0);
}

/*
 * switching_from_minlat - called while task is still on the old class
 * but about to switch away.  Clear the delayed flag so the entity is
 * treated as a normal queued task by sched_change_begin()'s dequeue.
 *
 * We must NOT call dequeue_task() here because that triggers
 * __block_task() which publishes p->on_rq = 0, allowing ttwu to
 * migrate the task while sched_change_begin/end still reference it.
 * Phase 1 of minlat_switch_all() only holds rq_lock (not pi_lock),
 * so ttwu can proceed unblocked.  Instead, just clear the flag and
 * let sched_change_begin()'s own dequeue (DEQUEUE_SAVE, no
 * DEQUEUE_SLEEP) handle the rb-tree removal without __block_task.
 */
static void switching_from_minlat(struct rq *rq, struct task_struct *p)
{
	if (p->se.sched_delayed) {
		p->se.sched_delayed = 0;
		rq->minlat.nr_delayed--;
	}
}

/*
 * switched_from_minlat - called after the class pointer has changed.
 * Clean up minlat-specific state (buddy, curr, on_rq).
 *
 * Clearing on_rq ensures that if the task is later switched back to
 * minlat, enqueue_task_minlat will properly reinitialize weight and
 * vruntime placement instead of using stale values.
 */
static void switched_from_minlat(struct rq *rq, struct task_struct *p)
{
	struct minlat_rq *minlat_rq = &rq->minlat;

	if (minlat_rq->next == &p->minlat)
		minlat_rq->next = NULL;
	if (minlat_rq->curr == &p->minlat)
		minlat_rq->curr = NULL;
	p->minlat.on_rq = 0;
}

/* ==== runtime toggle ==== */

/*
 * Migrate all eligible tasks between minlat and fair in two phases:
 *
 * Phase 1: Per-CPU batch migration of queued/running tasks.
 *   Lock each CPU's rq once and drain all tasks of the source class.
 *   This is O(nr_cpus * tasks_per_cpu) with one lock per CPU.
 *
 * Phase 2: Sweep sleeping tasks.
 *   Sleeping tasks aren't on any runqueue so just swap the class pointer.
 *   The enqueue path on wakeup handles weight/load initialization.
 */
static void minlat_switch_all(bool to_minlat)
{
	int cpu;
	struct task_struct *g, *p;

	/* Phase 1: drain runqueues per-CPU */
	for_each_online_cpu(cpu) {
		struct rq *rq = cpu_rq(cpu);
		struct rq_flags rf;

		rq_lock_irqsave(rq, &rf);
		update_rq_clock(rq);

		if (!to_minlat) {
			/* minlat→CFS: drain minlat runqueue */
			while (rq->minlat.nr_running > 0) {
				struct sched_minlat_entity *me;
				struct sched_change_ctx *ctx;

				if (rq->minlat.curr)
					me = rq->minlat.curr;
				else {
					struct rb_node *nd;

					nd = rb_first_cached(
						&rq->minlat.tasks_timeline);
					if (!nd)
						break;
					me = rb_entry(nd,
						struct sched_minlat_entity,
						run_node);
				}
				p = container_of(me, struct task_struct,
						 minlat);

				ctx = sched_change_begin(p,
					DEQUEUE_SAVE | DEQUEUE_NOCLOCK |
					DEQUEUE_CLASS | ENQUEUE_CLASS);
				p->sched_class = &fair_sched_class;
				sched_change_end(ctx);
			}
		} else {
			/* CFS→minlat: drain CFS tasks on this rq */
			struct sched_entity *se, *se_tmp;

			list_for_each_entry_safe(se, se_tmp,
					&rq->cfs_tasks, group_node) {
				struct sched_change_ctx *ctx;

				p = container_of(se, struct task_struct, se);

				if (p->sched_class != &fair_sched_class)
					break;

				/*
				 * Skip delayed entities — switching_from_fair()
				 * calls dequeue_task(DEQUEUE_DELAYED) which
				 * triggers __block_task().  Phase 1 only holds
				 * rq_lock (not pi_lock), so ttwu could migrate
				 * the task out from under us.  Phase 2 handles
				 * these safely with task_rq_lock.
				 */
				if (p->se.sched_delayed)
					continue;

				ctx = sched_change_begin(p,
					DEQUEUE_SAVE | DEQUEUE_NOCLOCK |
					DEQUEUE_CLASS | ENQUEUE_CLASS);
				p->sched_class = &minlat_sched_class;
				sched_change_end(ctx);
			}
		}

		rq_unlock_irqrestore(rq, &rf);
	}

	/*
	 * Phase 2: migrate remaining tasks (sleeping + any that woke up
	 * between Phase 1 completing their CPU and now).
	 *
	 * For each task still on the old class, take task_rq_lock and
	 * use sched_change_begin/end if queued, or just swap the class
	 * pointer if sleeping.  This avoids the race where a task wakes
	 * up after Phase 1 processed its CPU and gets enqueued on the
	 * old class's runqueue — Phase 2 must properly dequeue/enqueue
	 * such tasks rather than just changing the class pointer.
	 */
	read_lock(&tasklist_lock);
	for_each_process_thread(g, p) {
		const struct sched_class *from_class = to_minlat ?
			&fair_sched_class : &minlat_sched_class;
		const struct sched_class *to_class = to_minlat ?
			&minlat_sched_class : &fair_sched_class;

		if (p->sched_class != from_class)
			continue;
		if (rt_prio(p->prio) || dl_prio(p->prio))
			continue;

		get_task_struct(p);
		read_unlock(&tasklist_lock);

		{
			struct rq_flags rf;
			struct rq *rq;

			rq = task_rq_lock(p, &rf);

			if (p->sched_class == from_class) {
				if (task_on_rq_queued(p)) {
					struct sched_change_ctx *ctx;

					ctx = sched_change_begin(p,
						DEQUEUE_SAVE |
						DEQUEUE_CLASS |
						ENQUEUE_CLASS);
					p->sched_class = to_class;
					sched_change_end(ctx);
				} else {
					p->sched_class = to_class;
				}
			}

			task_rq_unlock(rq, p, &rf);
		}

		read_lock(&tasklist_lock);
		put_task_struct(p);
	}
	read_unlock(&tasklist_lock);
}

static ssize_t minlat_enabled_write(struct file *file,
				     const char __user *ubuf,
				     size_t cnt, loff_t *ppos)
{
	bool enable;
	int ret;

	ret = kstrtobool_from_user(ubuf, cnt, &enable);
	if (ret)
		return ret;

	if (enable == static_key_enabled(&sched_minlat_enabled.key))
		return cnt;

	if (enable) {
		static_branch_enable(&sched_minlat_enabled);
		minlat_switch_all(true);
		pr_info("minlat: scheduler enabled, migrated all fair tasks\n");
	} else {
		minlat_switch_all(false);
		static_branch_disable(&sched_minlat_enabled);
		pr_info("minlat: scheduler disabled, migrated all tasks to CFS\n");
	}

	*ppos += cnt;
	return cnt;
}

static ssize_t minlat_enabled_read(struct file *file, char __user *ubuf,
				    size_t cnt, loff_t *ppos)
{
	char buf[4];
	int len;

	len = snprintf(buf, sizeof(buf), "%d\n",
		       static_key_enabled(&sched_minlat_enabled.key));
	return simple_read_from_buffer(ubuf, cnt, ppos, buf, len);
}

const struct file_operations minlat_enabled_fops = {
	.read	= minlat_enabled_read,
	.write	= minlat_enabled_write,
};

/* ==== init ==== */

__init void init_sched_minlat_class(void)
{
	pr_info("minlat: scheduler class initialized\n");
}

/* ==== class definition ==== */

DEFINE_SCHED_CLASS(minlat) = {
	.enqueue_task		= enqueue_task_minlat,
	.dequeue_task		= dequeue_task_minlat,
	.yield_task		= yield_task_minlat,

	.wakeup_preempt		= wakeup_preempt_minlat,

	.pick_task		= pick_task_minlat,
	.put_prev_task		= put_prev_task_minlat,
	.set_next_task		= set_next_task_minlat,

	.balance		= balance_minlat,
	.select_task_rq		= select_task_rq_minlat,
	.migrate_task_rq	= migrate_task_rq_minlat,
	.set_cpus_allowed	= set_cpus_allowed_common,

	.task_tick		= task_tick_minlat,
	.task_dead		= task_dead_minlat,

	.switching_from		= switching_from_minlat,
	.switched_from		= switched_from_minlat,
	.switched_to		= switched_to_minlat,
	.prio_changed		= prio_changed_minlat,

	.update_curr		= update_curr_minlat,
};
