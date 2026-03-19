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

unsigned int minlat_latency_ns = 4 * NSEC_PER_MSEC;
unsigned int minlat_min_granularity_ns = 500 * NSEC_PER_USEC;
unsigned int minlat_cache_hot_ns = 500 * NSEC_PER_USEC;
unsigned int minlat_numa_imbalance_min = 2;
unsigned int minlat_migration_cooldown_ns = 4 * NSEC_PER_MSEC;
unsigned int minlat_numa_saturated_pct = 75;
unsigned int minlat_wake_affine = 1;

#define MINLAT_LATENCY_NS		minlat_latency_ns
#define MINLAT_MIN_GRANULARITY_NS	minlat_min_granularity_ns

/*
 * Track how many CPUs have >1 minlat task (overloaded).
 * Used to fast-skip idle-pull when no CPU has tasks to donate.
 */
/*
 * Check if any online CPU has 2+ minlat tasks. Uses per-rq overloaded
 * flags — cheap READ_ONCE reads, no atomics on the enqueue/dequeue path.
 * Tolerates stale values: worst case is one missed or unnecessary pull.
 */
static bool sched_minlat_any_overloaded(struct rq *this_rq)
{
	int cpu;

	for_each_online_cpu(cpu) {
		if (cpu == this_rq->cpu)
			continue;
		if (READ_ONCE(cpu_rq(cpu)->minlat.overloaded))
			return true;
	}
	return false;
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

static u64 minlat_calc_delta(u64 delta, struct sched_minlat_entity *me)
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
	minlat_rq->nr_running = 0;
	minlat_rq->min_vruntime = 0;
	minlat_rq->load_weight = 0;
}

/* ==== rb-tree operations ==== */

static inline bool __minlat_less(struct rb_node *a, const struct rb_node *b)
{
	struct sched_minlat_entity *ea, *eb;

	ea = rb_entry(a, struct sched_minlat_entity, run_node);
	eb = rb_entry(b, struct sched_minlat_entity, run_node);
	return (s64)(ea->vruntime - eb->vruntime) < 0;
}

static void __enqueue_minlat_entity(struct minlat_rq *minlat_rq,
				    struct sched_minlat_entity *me)
{
	rb_add_cached(&me->run_node, &minlat_rq->tasks_timeline,
		      __minlat_less);
}

static void __dequeue_minlat_entity(struct minlat_rq *minlat_rq,
				    struct sched_minlat_entity *me)
{
	if (RB_EMPTY_NODE(&me->run_node))
		return;
	rb_erase_cached(&me->run_node, &minlat_rq->tasks_timeline);
	RB_CLEAR_NODE(&me->run_node);
}

static struct sched_minlat_entity *
__pick_first_minlat_entity(struct minlat_rq *minlat_rq)
{
	struct rb_node *left = rb_first_cached(&minlat_rq->tasks_timeline);

	if (!left)
		return NULL;
	return rb_entry(left, struct sched_minlat_entity, run_node);
}

static inline struct rq *rq_of_minlat_rq(struct minlat_rq *minlat_rq)
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
static void update_min_vruntime(struct minlat_rq *minlat_rq)
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
static void update_curr_minlat_vruntime(struct rq *rq)
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
	u64 ideal_runtime;
	s64 delta;

	if (minlat_rq->nr_running <= 1)
		return;

	ideal_runtime = minlat_sched_slice(minlat_rq, curr_me);

	/*
	 * Current entity is out of the tree — rb_first_cached always
	 * returns the next competitor, no skip logic needed.
	 */
	next_node = rb_first_cached(&minlat_rq->tasks_timeline);
	if (!next_node)
		return;
	next_me = rb_entry(next_node, struct sched_minlat_entity, run_node);

	delta = (s64)(curr_me->vruntime - next_me->vruntime);
	if (delta > (s64)ideal_runtime)
		resched_curr(rq);
}

static void
enqueue_task_minlat(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_minlat_entity *me = &p->minlat;
	struct minlat_rq *minlat_rq = &rq->minlat;

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

	if (minlat_rq->nr_running >= 2)
		WRITE_ONCE(minlat_rq->overloaded, true);
}

static bool
dequeue_task_minlat(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_minlat_entity *me = &p->minlat;
	struct minlat_rq *minlat_rq = &rq->minlat;
	bool was_curr = (minlat_rq->curr == me);
	bool was_leftmost = false;

	if (was_curr) {
		/*
		 * Currently running entity is already out of the tree
		 * (removed by set_next_task). Just clear curr.
		 */
		minlat_rq->curr = NULL;
	} else {
		/* Check if this was leftmost before removing */
		was_leftmost = (rb_first_cached(&minlat_rq->tasks_timeline) ==
				&me->run_node);
		__dequeue_minlat_entity(minlat_rq, me);
	}

	minlat_rq->nr_running--;

	if (minlat_rq->nr_running < 2)
		WRITE_ONCE(minlat_rq->overloaded, false);
	minlat_rq->load_weight -= scale_load_down(me->load.weight);
	sub_nr_running(rq, 1);

	if (flags & DEQUEUE_SLEEP) {
		me->on_rq = 0;
		minlat_record_sleep(p, rq);
	}

	/* Only update min_vruntime if the leftmost node changed */
	if (was_leftmost)
		update_min_vruntime(minlat_rq);
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

static void
wakeup_preempt_minlat(struct rq *rq, struct task_struct *p, int flags)
{
	struct task_struct *curr = rq->curr;
	s64 delta;

	if (curr->sched_class != &minlat_sched_class) {
		resched_curr(rq);
		return;
	}

	/*
	 * Lightweight vruntime update — just accounting, no tree
	 * reposition. We need fresh vruntime for a correct preemption
	 * comparison, but tree ordering can wait until put_prev_task.
	 */
	update_curr_minlat_vruntime(rq);

	/*
	 * Sync wakeups (pipe, futex): the waker is about to block.
	 *
	 * Only preempt if the current task has been running for at
	 * least CACHE_HOT_NS (~500µs). This lets batch producers
	 * (like hackbench senders doing 100 pipe writes) complete
	 * their burst before yielding to the reader, avoiding
	 * per-message context switch overhead.
	 *
	 * For true ping-pong (one write then block), the waker will
	 * block on its next read() and the scheduler naturally picks
	 * the wakee — no forced preemption needed.
	 *
	 * Matches CFS's preempt_sync() which uses migration_cost as
	 * the threshold and returns NONE (no preempt) when not met.
	 */
	if (flags & WF_SYNC) {
		u64 delta = rq_clock_task(rq) - curr->se.exec_start;

		if ((s64)delta >= (s64)minlat_cache_hot_ns)
			resched_curr(rq);
		return;
	}

	delta = (s64)(curr->minlat.vruntime - p->minlat.vruntime);
	if (delta > (s64)MINLAT_MIN_GRANULARITY_NS)
		resched_curr(rq);
}

static struct task_struct *
pick_task_minlat(struct rq *rq, struct rq_flags *rf)
{
	struct minlat_rq *minlat_rq = &rq->minlat;
	struct sched_minlat_entity *me;

	me = __pick_first_minlat_entity(minlat_rq);
	if (me)
		return container_of(me, struct task_struct, minlat);

	/*
	 * Tree is empty but curr exists out-of-tree — return it.
	 * This happens when the only minlat task is the currently
	 * running one (removed from tree by set_next_task).
	 */
	if (minlat_rq->curr && minlat_rq->curr->on_rq)
		return container_of(minlat_rq->curr, struct task_struct, minlat);

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

	/*
	 * Only re-insert if this entity is the current out-of-tree task.
	 * If minlat_rq->curr != me, the entity was already handled by
	 * dequeue_task_minlat (e.g., DEQUEUE_SAVE class-change path)
	 * and may already be in the tree or will be re-enqueued separately.
	 */
	if (minlat_rq->curr != me) {
		/* Not curr — nothing to re-insert */
		return;
	}

	if (!me->on_rq) {
		minlat_rq->curr = NULL;
		return;
	}

	update_curr_minlat_vruntime(rq);
	update_min_vruntime(minlat_rq);

	/* Re-insert into the rb-tree at the correct position. */
	__enqueue_minlat_entity(minlat_rq, me);
	minlat_rq->curr = NULL;
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
	if (me->on_rq && !RB_EMPTY_NODE(&me->run_node))
		__dequeue_minlat_entity(minlat_rq, me);

	minlat_rq->curr = me;

	p->se.exec_start = rq_clock_task(rq);
	p->se.prev_sum_exec_runtime = p->se.sum_exec_runtime;
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
	 * Sync wakeup: the waker is going to sleep right after this.
	 * Its CPU will be free — put the wakee there. This is the
	 * critical path for futex ping-pong, pipe read/write, etc.
	 *
	 * Guards:
	 *  - 1:1 pair only (last_wakee == p): prevents fan-out piling
	 *  - Waker's CPU has only the waker: it'll truly be idle
	 *  - wake_wide check: disables for high fan-out wakers
	 */
	if (!(flags & WF_SYNC))
		return -1;

	if (current->last_wakee != p)
		return -1;

	{
		struct rq *rq = cpu_rq(this_cpu);

		if (rq->nr_running <= 1)
			return this_cpu;
	}

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
		struct sched_domain *sd;
		int best_llc_cpu = -1;
		unsigned int best_llc_nr = UINT_MAX;

		rcu_read_lock();
		sd = rcu_dereference(per_cpu(sd_llc, prev_cpu));
		if (sd) {
			const struct cpumask *llc_span = sched_domain_span(sd);

			for_each_cpu_wrap(cpu, llc_span, prev_cpu + 1) {
				unsigned int nr;

				if (!cpumask_test_cpu(cpu, allowed))
					continue;
				nr = cpu_rq(cpu)->minlat.nr_running;
				if (nr == 0) {
					rcu_read_unlock();
					return cpu;
				}
				if (nr < best_llc_nr) {
					best_llc_nr = nr;
					best_llc_cpu = cpu;
				}
			}
		}
		rcu_read_unlock();

		if (best_llc_cpu >= 0)
			return best_llc_cpu;

		/* LLC had no valid CPUs — fall through to general path */
	}

	/* 1. prev_cpu if idle — fast path, no scanning */
	if (cpu_active(prev_cpu) && cpumask_test_cpu(prev_cpu, allowed) &&
	    available_idle_cpu(prev_cpu))
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
	    available_idle_cpu(recent_used_cpu))
		return recent_used_cpu;

	/*
	 * 3-4. Single scan for idle CPU, starting from prev_cpu so
	 * each task scans a different order and spreads evenly.
	 * Prefer same-LLC idle CPUs (cheaper migration).
	 */
	for_each_cpu_wrap(cpu, cpu_active_mask, prev_cpu) {
		if (!cpumask_test_cpu(cpu, allowed))
			continue;
		if (!available_idle_cpu(cpu))
			continue;

		if (cpus_share_cache(cpu, prev_cpu))
			return cpu;

		if (best_cpu < 0)
			best_cpu = cpu;
	}
	if (best_cpu >= 0)
		return best_cpu;

	/*
	 * 5. No idle CPU — least-loaded, scan from prev_cpu for
	 * distribution. Early exit if we find an empty CPU.
	 */
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
 * @cross_numa: true if this is a cross-NUMA pull (enables cooldown checks)
 */
static struct task_struct *
minlat_pick_pullable_task(struct rq *src_rq, int this_cpu, bool cross_numa)
{
	struct rb_node *node;
	struct sched_minlat_entity *me;
	struct task_struct *p;
	int scanned = 0;

	for (node = rb_last(&src_rq->minlat.tasks_timeline.rb_root);
	     node && scanned < 4; node = rb_prev(node), scanned++) {
		me = rb_entry(node, struct sched_minlat_entity, run_node);
		p = container_of(me, struct task_struct, minlat);

		if (task_current(src_rq, p))
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

		return p;
	}

	return NULL;
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
	if (rq->minlat.nr_running > 0)
		return 1;

	if (!sched_minlat_any_overloaded(rq))
		return 0;

	/*
	 * This CPU has no minlat tasks. Try to pull from busy CPUs.
	 *
	 * Follow the RT pattern: unpin the rq lock so that
	 * double_lock_balance can safely reorder locks, then repin.
	 * This is safe because current is on_cpu (can't be picked
	 * for load balance) and IRQs are disabled.
	 */
	rq_unpin_lock(rq, rf);
	pull_minlat_task(rq);
	rq_repin_lock(rq, rf);

	return rq->minlat.nr_running > 0;
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
	.set_cpus_allowed	= set_cpus_allowed_common,

	.task_tick		= task_tick_minlat,
	.task_dead		= task_dead_minlat,

	.switched_to		= switched_to_minlat,
	.prio_changed		= prio_changed_minlat,

	.update_curr		= update_curr_minlat,
};
