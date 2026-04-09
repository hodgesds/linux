================================================
SCHED_MINLAT Colony / Phase-Aware Picker (Design)
================================================

Status
======

This is a **design proposal**, not a description of currently merged code.
It describes the intended next architectural direction for the
SCHED_MINLAT scheduling class. The current SCHED_MINLAT picker uses
vruntime-based proportional fairness inherited from classic CFS (see
``kernel/sched/minlat.c``); this document describes a planned successor
that takes a fundamentally different approach to picking and placement.

The motivation, scope, and acceptance criteria below should be read
critically — none of the design has been measured yet, and several open
design questions remain. The intent is that this document is the input
to a prototype branch (``minlat-colony``), not a description of code
that already exists.

.. contents::
   :local:
   :depth: 2

Glossary
========

Some terms are used throughout this document with specific meanings:

**eff**
    The number of *effective* runnable tasks on a runqueue, defined as
    ``nr_running - nr_delayed``. Delayed tasks (sleepers kept on the
    rb-tree for fast re-wakeup) do not count.

**regime**
    A per-CPU classification of how loaded the runqueue is, in terms of
    ``eff``. Regimes are *empty* (eff=0), *single* (eff=1), *balanced*
    (eff=2), and *saturated* (eff≥3).

**lane**
    A per-rq queue: tasks are in either the *express* lane (recently
    woken) or the *regular* lane (everyone else). Distinct from a
    Linux runqueue, which holds tasks across both lanes.

**wait_start**
    The wall-clock timestamp at which a task became runnable. This is
    the colony picker's primary state, replacing vruntime.

**colony**
    An implicit set of tasks that wake each other frequently, revealed
    by the per-task pheromone graph. Colonies are not materialized as
    data structures.

**pheromone**
    A per-task array of (waker_id, strength) pairs, decaying over
    time, that records who has been waking this task. The placement
    layer uses pheromones to find a wakee's colony footprint.

**WHERE / WHEN**
    Two orthogonal questions every wake event must answer: WHERE
    should the wakee run (placement, cross-CPU, global), and WHEN
    should it run on that CPU vs the others queued there (picking,
    per-CPU, local).

Motivation
==========

The current SCHED_MINLAT picker inherits its core machinery from
classic CFS:

* a single per-entity ``vruntime`` ledger,
* leftmost-vruntime as the pick rule,
* a per-rq ``next`` buddy slot for sync wakeups,
* sleeper credit on wake to keep wakees competitive.

Empirical investigation of this picker against EEVDF on a 32-CPU AMD
Ryzen 9 7940HX (one LLC, single NUMA node) at the schbench overload
working point ``-m 2 -t 32`` revealed three regressions relative to
CFS, all traceable to a common architectural concern:

============================================ ===============================
regression                                   magnitude vs CFS
============================================ ===============================
``schbench req p99`` at ``-m 2 -t 16``       +28%
``schbench req p99.9`` at ``-m 2 -t 16``     +46%
``hackbench -g 16`` wall time                +8 to +9%
``schbench`` per-task max wait at            24-80 ms vs CFS's 12-18 ms
``-m 2 -t 32`` (perf sched latency)
``schbench wake p99`` at ``-m 2 -t 16``      −49% (a *win*, preserved)
``schbench wake p99.9``                      −46% (a *win*, preserved)
``perf bench sched pipe`` ops/sec            +29% (a *win*, preserved)
============================================ ===============================

The wins (wake tail latency, pipe throughput) are real and substantial.
The losses (request tail latency, fan-out throughput, max wait under
oversubscription) are also real and have a common root cause.

The architectural problem
-------------------------

The picker conflates three orthogonal concepts into the single
``vruntime`` scalar, and uses ad-hoc side-channel mechanisms (the buddy
slot, sleeper credit, wake-burst spread, weighted sched_period) to
bolt the missing concepts back on:

#. **Resource debt** — "you owe me CPU time" (the fairness ledger).
#. **Urgency** — "I need to run soon to meet my latency target".
#. **Readiness** — "I am able to run productively right now".

Vruntime cleanly captures #1. It captures #2 only by accident (a
long-sleeper has low vruntime, which proxies for "should run soon").
It captures #3 not at all (readiness is implicit in being on the
rb-tree).

The buddy slot in classic CFS was a hack to bolt #2 onto a #1-only
system: "this task just woke, prefer it" was an urgency signal stuffed
into the picker via a side channel. EEVDF fixed this by making
urgency a first-class signal (the deadline). Vruntime stayed as the
ledger; deadline became the picker's primary input. Eligibility
(``vruntime ≤ avg_vruntime``) became the anti-starvation guarantee.

SCHED_MINLAT's design comment (``5cce8ef153ac sched/minlat: Add
minimum-latency scheduling class``) explicitly rejected EEVDF in
favour of "pure vruntime-based proportional fairness like classic CFS,
before EEVDF" plus "topology-aware placement optimized for minimum
wake-to-run latency". The empirical regressions show that the rejection
was incomplete: the picker still needs *something* to encode urgency,
and the buddy slot cannot do that job at saturation without breaking
fairness.

Three options exist:

a. **Re-introduce EEVDF eligibility and virtual deadlines** — i.e.
   become EEVDF, abandoning the simplicity argument that justified
   SCHED_MINLAT's existence in the first place.
b. **Add a sequence of incremental fixes on top of the buddy
   mechanism** — eligibility checks, wake-preempt floors, burst-spread
   admission control. Band-aids that grow without bound and never
   fully close the gap.
c. **Replace the picker and placement layers with a fundamentally
   different design** that is *not* a CFS or EEVDF derivative.

This document describes option (c), referred to here as the
**colony / phase-aware** design.

Core thesis
===========

The picker is not solving one problem. It is solving qualitatively
different problems at different load regimes, and a single mechanism
that handles all of them well does not exist.

============= ====================================== ==========================
regime        what the picker is solving             what mechanism fits
============= ====================================== ==========================
empty         placement, not picking                 route to this CPU
single        nothing — only one runnable task       trivial (return curr)
balanced      round-robin alternation of two tasks   tick-driven slice swap
saturated     fairness against multi-task contention real picker logic needed
============= ====================================== ==========================

Three of the four regimes need essentially no picker logic at all.
CFS and EEVDF run their full machinery in every regime, paying the
cost in all four to serve only the fourth. **Phase awareness is the
recognition that the picker should switch mechanisms based on the
observable per-CPU regime, running expensive logic only when the
regime requires it.**

A second observation: **fairness only matters at saturation**. Below
saturation, every runnable task can run somewhere — the picker has
nothing to choose between. At saturation, choosing X displaces Y,
and only here does fairness become a binding constraint. The picker's
expensive fairness machinery is dead weight in three of four regimes.

A third observation: every wake event has *two* questions to answer,
and current schedulers conflate them.

#. **WHERE** should the wakee run? — placement, cross-CPU, global.
#. **WHEN** should it run on that CPU vs the others queued there? —
   picking, per-CPU, local.

These questions have different natural solutions. The colony design
splits them cleanly. The picker is local and uses a traffic-flow
model. The placement layer is global and uses an ant-colony pheromone
model. The two layers share **no** state and use **different**
primitives.

============== ============================= =========================================
problem        natural analogy               new mechanism
============== ============================= =========================================
WHERE          ant pheromone trails          per-task pheromone array;
                                             dynamic colony-tracked relationship graph
WHEN           highway traffic flow          express+FIFO with regime detection
============== ============================= =========================================

Picker layer (traffic flow, local, per-CPU)
===========================================

Each CPU is a single-lane road. Tasks are vehicles. A CPU's runqueue
goes through phase transitions as ``eff = nr_running - nr_delayed``
crosses thresholds.

Regime classification
---------------------

============= ============== =====================================================
regime        eff            picker behavior
============= ============== =====================================================
empty         0              No pick. A wake is a placement event.
single        1              Pick the one runnable task. Trivial.
balanced      2              Tick-driven alternation, min_gran floor on preempt.
saturated     ≥ 3            Express + regular FIFO (see below).
============= ============== =====================================================

The regime is checked at pick time, requiring no extra state. The
picker dispatches into one of four hot paths based on the integer
``eff``. The branch is predictable in steady state (a workload running
in regime 2 mostly stays there).

Per-regime behavior in detail
-----------------------------

**Empty (eff = 0)**

There is nothing on the rq. The picker returns NULL or kicks an
idle-pull from a busy peer. This is the regime the CPU spends most
of its time in for typical desktop / server workloads. The picker
hot path here costs only a single load and branch::

    if (READ_ONCE(minlat_rq->eff) == 0)
        return NULL;     /* let __schedule() handle idle-pull */

**Single (eff = 1)**

Exactly one task is runnable. The picker returns it. There is no
choice to make and no fairness question to answer::

    if (eff == 1) {
        /* the one runnable task is in either express or regular */
        if (!list_empty(&minlat_rq->express_q))
            return list_first_entry(&minlat_rq->express_q, ...);
        return list_first_entry(&minlat_rq->regular_q, ...);
    }

**Balanced (eff = 2)**

Two tasks alternate. There is no fairness question — strict
alternation is automatically fair. The picker just picks the task
that is *not* curr. Lane membership doesn't matter; both tasks get
equal slices.

The interesting machinery in this regime lives in the *preemption*
path, not the pick path. Tick preemption fires after curr has run
for at least ``min_gran`` to enforce the alternation cycle. Wake
preemption fires only if the wakee has a vruntime advantage greater
than ``min_gran`` (this is the existing v3a/v3b min_gran floor). In
the colony design vruntime is gone; we replace this check with a
``wait_start`` comparison or simply with a fixed window of "if curr
has run < min_gran, don't preempt".

**Saturated (eff ≥ 3)**

Real contention. The picker has a real choice. This is where the
express+FIFO machinery (see below) lives.

Express + regular FIFO
----------------------

State per task::

    u64  wait_start_ns      /* when this task became runnable */
    enum { LANE_EXPRESS, LANE_REGULAR } lane

State per rq::

    struct list_head express_q     /* FIFO, oldest first (head) */
    struct list_head regular_q     /* FIFO, oldest first (head) */
    unsigned int express_count
    unsigned int express_capacity  /* = max(1, eff / 2) */

The picker (saturated regime)::

    static struct task_struct *pick_task_minlat_saturated(struct rq *rq)
    {
        struct minlat_rq *mr = &rq->minlat;

        /* graduate any over-aged express heads (lazy demote) */
        minlat_graduate_express_head(mr);

        if (!list_empty(&mr->express_q))
            return list_first_entry(&mr->express_q,
                                    struct task_struct, minlat.lane_node);
        return list_first_entry(&mr->regular_q,
                                struct task_struct, minlat.lane_node);
    }

Lane state machine
------------------

Tasks transition between lanes via these events::

                                          (graduation_interval expired,
                  (wake)                    or express_count > capacity)
       ┌────────────────────┐                   │
       │                    │                   ▼
   sleeping ──────────► EXPRESS ─────────────► REGULAR
       ▲                  │                       │
       │                  │  (slice start)        │  (slice start)
       │                  ▼                       ▼
       │              running ◄──────────────── running
       │                  │                       │
       │                  │  (slice end)          │  (slice end)
       │                  ▼                       ▼
       │              EXPRESS                  REGULAR
       │                  │                       │
       └─── (block) ──────┴───────────────────────┘

The key invariant: **a task always re-enters the lane it was in
before being picked.** Running does not change lane membership.
Lane transitions only happen on wake (always to express),
graduation (express → regular), and overflow (express → regular).

Lane transition rules
---------------------

* **Wake**: Enter ``express_q``. Set ``wait_start_ns = sched_clock()``,
  ``lane = LANE_EXPRESS``. Increment ``express_count``. If
  ``express_count > express_capacity``, demote the *oldest* express
  task to ``regular_q``.

* **Picked**: Remove from whichever lane the task was in. The task is
  running, out-of-lane.

* **Slice end (put_prev)**: Re-insert at the *back* of the same lane
  the task was in. ``wait_start_ns`` is *not* reset — the task picks
  up its wait clock where it left off. This is intentional: a task
  that was waiting and was just briefly served should not have its
  wait time reset to zero.

* **Graduation**: A task that has been ``LANE_EXPRESS`` for longer
  than its graduation interval ``G(latency_nice)`` is demoted to
  ``LANE_REGULAR``. Implemented lazily: at the start of each pick,
  walk the express head and demote any over-aged entries before
  picking. Also swept periodically at ``task_tick`` for tasks that
  are running and accumulating express age in the background.

* **Express overflow**: When ``express_count > express_capacity`` on
  enqueue, the *oldest* express task is demoted to regular. This
  bounds express size structurally — wakes cannot grow express
  indefinitely.

* **Block**: Remove from whichever lane. ``wait_start_ns`` is
  irrelevant while sleeping; will be reset on next wake.

Picker algorithm (pseudocode)
-----------------------------

The full picker, including all four regimes::

    static struct task_struct *pick_task_minlat(struct rq *rq)
    {
        struct minlat_rq *mr = &rq->minlat;
        unsigned int eff = mr->nr_running - mr->nr_delayed;

        switch (eff) {
        case 0:
            /* idle CPU; let __schedule() pull from a busy peer */
            return NULL;

        case 1:
            /* one task; return whichever lane it's in */
            if (!list_empty(&mr->express_q))
                return list_first_entry(&mr->express_q,
                                        struct task_struct,
                                        minlat.lane_node);
            return list_first_entry(&mr->regular_q,
                                    struct task_struct,
                                    minlat.lane_node);

        case 2:
            /* alternation; pick the non-curr task */
            return pick_other_in_balanced(mr);

        default:
            /* saturated: graduate then express-then-regular */
            graduate_express_head(mr);
            if (!list_empty(&mr->express_q))
                return list_first_entry(&mr->express_q,
                                        struct task_struct,
                                        minlat.lane_node);
            return list_first_entry(&mr->regular_q,
                                    struct task_struct,
                                    minlat.lane_node);
        }
    }

The eff=2 case can be folded into the default if measurement shows
that special-casing it doesn't help; both produce the same answer
(the only non-curr task ends up at the head of one of the two lanes).

Bounded wait analysis
---------------------

Worst-case wait time per task in the saturated regime::

    wait_max ≤ G(latency_nice) + (regular_size - 1) × slice

where:

* ``G(latency_nice)`` is the graduation interval — how long a task
  can sit in express before demoting. Default ``G(0) = latency_ns =
  1.5 ms``. Adjustable per-task via ``latency_nice`` weight scaling.
* ``regular_size`` is the steady-state number of tasks in regular
  on this rq.
* ``slice`` is the per-task slice = ``period / eff``, where
  ``period = max(latency_ns, eff × min_gran)``.

For a typical schbench overload (``-m 2 -t 32``, eff = 2 per rq,
slice = 750 µs, regular_size = 1):

* ``wait_max ≤ 1.5 ms + 0 × 750 µs = 1.5 ms``

This is a 16× improvement over the current SCHED_MINLAT v7 measured
``perf sched latency`` p50 of 24 ms.

For a 3× oversubscribed schbench (``-t 48``, eff = 3, slice = 500 µs,
regular_size = 2):

* ``wait_max ≤ 1.5 ms + 1 × 500 µs = 2 ms``

vs current SCHED_MINLAT v7 measured p50 of 44.6 ms — a 22× improvement.

Compare to CFS's bound::

    wait_max_CFS ≤ sched_period = max(sched_min_granularity,
                                       sched_min_granularity × eff)

For eff = 2, ``wait_max_CFS = 6 ms`` (sched_period default). The
colony bound at the same load is 1.5 ms — 4× tighter.

These bounds are theoretical. The prototype must measure the actual
distribution to validate them; in particular, the express graduation
interval interacts with wake bursts in ways that are hard to predict
without running the workload.

A note on the bound's tightness: the analysis assumes a *single*
graduation event per worst-case wait. A pathological wakee that
repeatedly enters and graduates from express can extend its own wait
indefinitely — but this is exactly the gaming case the express
capacity bound and structural overflow defend against.

Placement layer (ant colony, global, cross-CPU)
================================================

When a wake event arrives at the placement layer
(``select_task_rq_minlat``), the current logic is mostly static
topology + heuristics: LLC affinity, ``wake_affine``, ``recent_used_cpu``,
load balance fallbacks. The colony approach makes placement dynamic
and learned from observed wake patterns.

Pheromone state
---------------

Each task carries a small per-task pheromone array::

    #define MINLAT_PHEROMONE_FANIN 8

    struct minlat_pheromone {
        pid_t  waker_tgid;        /* tgid of the waker (not pid) */
        u32    strength;          /* exponentially decayed counter */
    };

    /* in struct sched_minlat_entity: */
    struct minlat_pheromone pheromone[MINLAT_PHEROMONE_FANIN];
    u64                     pheromone_last_decay_ns;

The array is sorted by ``strength`` (strongest first). On overflow,
the weakest entry is evicted. ``MINLAT_PHEROMONE_FANIN = 8`` is a
starting point; this is a tunable.

Pheromones are keyed by **tgid**, not pid, so all threads of the
same waker process accumulate trail weight together. This matches
how schbench, hackbench, and most fan-out workloads structure their
worker pools.

There is **no** explicit colony struct or membership list. A "colony"
is whatever the pheromone graph reveals as a dense subgraph; the
scheduler does not need to materialize colonies as data structures.
This keeps state O(N_tasks × FANIN) and avoids any global colony
registry.

Pheromone update on wake
------------------------

Pseudocode::

    static void minlat_record_pheromone(struct task_struct *wakee,
                                        struct task_struct *waker)
    {
        struct sched_minlat_entity *me = &wakee->minlat;
        pid_t tgid = task_tgid_nr(waker);
        u64 now = sched_clock();
        int i, slot;

        /* lazy decay since last update on this entity */
        minlat_pheromone_decay(me, now);

        /* find existing entry for this waker tgid */
        for (i = 0; i < MINLAT_PHEROMONE_FANIN; i++) {
            if (me->pheromone[i].waker_tgid == tgid) {
                me->pheromone[i].strength += PHEROMONE_INCREMENT;
                minlat_pheromone_resort(me, i);
                return;
            }
        }

        /* new waker — replace the weakest entry */
        slot = MINLAT_PHEROMONE_FANIN - 1;
        if (me->pheromone[slot].strength > PHEROMONE_REPLACE_THRESHOLD)
            return;  /* weakest is still strong; don't evict */
        me->pheromone[slot].waker_tgid = tgid;
        me->pheromone[slot].strength = PHEROMONE_INCREMENT;
        minlat_pheromone_resort(me, slot);
    }

Decay is lazy: only computed on access. ``minlat_pheromone_decay``
applies a multiplicative decay based on elapsed wall clock time::

    static void minlat_pheromone_decay(struct sched_minlat_entity *me,
                                       u64 now)
    {
        u64 elapsed = now - me->pheromone_last_decay_ns;
        unsigned int half_lives = elapsed / PHEROMONE_HALF_LIFE_NS;
        int i;

        if (half_lives == 0)
            return;
        if (half_lives > 16) {
            /* very stale — clear everything */
            memset(me->pheromone, 0, sizeof(me->pheromone));
        } else {
            for (i = 0; i < MINLAT_PHEROMONE_FANIN; i++)
                me->pheromone[i].strength >>= half_lives;
        }
        me->pheromone_last_decay_ns = now;
    }

``PHEROMONE_HALF_LIFE_NS`` is a tunable; a starting point is
``500 ms``. This is long enough to capture stable workloads but
short enough that workload transitions are detected within a few
seconds.

Colony location query
---------------------

Given a wakee with a pheromone array, where is its colony running
right now?

::

    static int minlat_find_colony_cpu(struct task_struct *wakee,
                                      int prev_cpu)
    {
        struct sched_minlat_entity *me = &wakee->minlat;
        int colony_cpus[MINLAT_PHEROMONE_FANIN];
        int i, n = 0;

        /* gather the CPUs of the strongest pheromone sources */
        for (i = 0; i < MINLAT_PHEROMONE_FANIN; i++) {
            struct task_struct *waker;
            pid_t tgid = me->pheromone[i].waker_tgid;
            int wake_cpu;

            if (me->pheromone[i].strength < PHEROMONE_USE_THRESHOLD)
                break;  /* sorted, so we're done */
            rcu_read_lock();
            waker = find_task_by_pid_ns(tgid, &init_pid_ns);
            wake_cpu = waker ? task_cpu(waker) : -1;
            rcu_read_unlock();
            if (wake_cpu >= 0)
                colony_cpus[n++] = wake_cpu;
        }

        if (n == 0)
            return -1;  /* no colony; fall back to topology */

        /* find a non-saturated CPU in the colony's LLC footprint */
        return minlat_pick_in_llc_set(colony_cpus, n, wakee);
    }

``minlat_pick_in_llc_set`` enumerates the LLCs touched by the colony
CPUs, then picks an underutilized CPU within those LLCs (preferring
CPUs in the *empty* or *single* regime over *balanced* or
*saturated*). This is the wake-burst-spread mechanism applied to the
colony footprint instead of raw topology.

If the colony is itself in saturation (all colony CPUs in
saturated regime), the placement falls through to off-colony spread,
the same way the current ``select_task_rq_minlat_wakeup`` falls
through to ``minlat_select_idle_cpu`` then to a global spread.

Burst handling
--------------

When the same waker dispatches multiple wakes in a tight loop, the
placement layer detects the burst via the ``wake_target_streak``
mechanism (already present from the v7 wake-burst-spread fix). The
spread is now guided by colony state instead of by raw LLC topology:

* The first wake in a burst goes to the colony's preferred CPU
* Subsequent wakes (within the burst window) rotate within the
  colony's CPU footprint, not just any LLC CPU
* This preserves cache locality (you stay within the colony's working
  set) while preventing pile-up

Cold start fallback
-------------------

A fresh task has no pheromones. Placement falls back to topology-based
selection — ``wake_affine``, ``recent_used_cpu``, the existing
``select_task_rq_minlat_wakeup`` path. As pheromones build up over
the first few wakes, the placement smoothly transitions to colony
mode. This ensures that the design has no cold-start latency cliff
relative to current behavior.

Placement algorithm (pseudocode)
--------------------------------

::

    static int select_task_rq_minlat(struct task_struct *p,
                                     int prev_cpu, int flags)
    {
        int cpu;

        if (!(flags & WF_TTWU))
            return select_task_rq_minlat_fork(p, prev_cpu);

        /* update pheromones from current waker */
        minlat_record_pheromone(p, current);

        /* try colony placement */
        cpu = minlat_find_colony_cpu(p, prev_cpu);
        if (cpu >= 0)
            return cpu;

        /* cold start fallback to topology-based selection */
        return select_task_rq_minlat_wakeup_topology(p, prev_cpu);
    }

How the two layers combine
==========================

A single wake event flows through the system in two stages, with no
shared state between them::

                            WAKE event
                                │
                                ▼
                ┌───────────────────────────────┐
                │  PLACEMENT (ant colony)       │
                │  - update pheromones          │
                │  - find colony footprint      │
                │  - pick CPU within footprint  │
                │    avoiding saturated CPUs    │
                └───────────────┬───────────────┘
                                │ → CPU N
                                ▼
                ┌───────────────────────────────┐
                │  PICKING on CPU N (traffic)   │
                │  - enqueue into express lane  │
                │  - if express overflows,      │
                │    demote oldest to regular   │
                │  - schedule() picks express   │
                │    head, then regular head    │
                └───────────────────────────────┘

Two completely separate decisions, two completely separate mechanisms.
The picker does not consult the colony graph. The placement layer
does not run any pick logic. **Each layer has one job.**

Compare this to current SCHED_MINLAT, where ``select_task_rq``,
``wakeup_preempt``, ``set_next_buddy``, ``pick_task``, ``place_entity``,
and ``update_curr`` all share the vruntime ledger and occasionally
update each other's state. The colony design replaces a tangled mesh
with two cleanly separated layers.

Worked examples
===============

Five canonical workloads, traced through both layers.

Example 1: pipe ping-pong (eff = 1, low load)
---------------------------------------------

Two tasks A and B alternate via ``write()`` and ``read()``. At any
moment, one is running and one is sleeping in ``read()``. The CPU
they share is in regime 1 (eff = 1) most of the time.

The placement layer:

* On the first few wakes, A and B's pheromone arrays both record each
  other's tgid. After a few iterations, ``A.pheromone[0] = (B, high)``
  and ``B.pheromone[0] = (A, high)``.
* The colony footprint contains both A and B's CPUs — but they're
  the same CPU (waker's CPU = A, wakee = B's prev_cpu = same CPU
  because they alternate there). The placement is a no-op: the wakee
  goes to the only CPU in its colony.
* Result: identical to ``wake_affine`` for this case.

The picker layer:

* When B wakes, it enters express on this CPU. Eff is 1 (A is curr
  running, but A is *out of lane* while running). Picker sees eff = 1,
  picks B from express in O(1).
* B runs, blocks in read(). A is woken, enters express.
* Repeat.

Pipe ops/sec should be at least as fast as current SCHED_MINLAT.

Example 2: schbench at the key load (``-m 2 -t 16``)
----------------------------------------------------

Two message threads, 16 worker threads each, on a 32-CPU system.
Total 34 tasks, ~half busy at any moment (workers do ~7 ms of compute
per request). Per-CPU state is mostly regime 1 with occasional
regime 2.

The placement layer:

* Each worker has ``pheromone[0] = (its_message_thread, very_strong)``.
  All 16 workers of message thread M share the same strongest pheromone.
* The colony footprint of message thread M contains M's CPU plus the
  16 workers' last CPUs — typically all on the same LLC.
* When M wakes worker_i, the placement looks at M's CPU + the
  workers' CPUs, and picks an underutilized CPU within that footprint.
* Crucially: this is *not* the same as wake_affine. wake_affine would
  put all 16 wakees on M's CPU. Colony placement spreads them across
  the colony's natural LLC footprint.

The picker layer:

* Most wakes land on rqs where the previous worker on that CPU is
  sleeping. Eff = 1 → trivial pick.
* Occasionally two workers land on the same rq → eff = 2 → alternation.
* Saturated regime is rare.

Wake p99 should remain ~1 ms (current SCHED_MINLAT v7 baseline).
Request p99 should approach CFS's ~13 ms (current SCHED_MINLAT v7
is at 17 ms).

Example 3: schbench at oversubscription (``-m 2 -t 32``)
--------------------------------------------------------

64 workers + 2 message threads on 32 CPUs. Average eff per CPU = 2.
Bursts of wakes from message threads land 8-15 deep on individual
CPUs.

The placement layer:

* Pheromones are the same as example 2 (workers all point to their
  message thread).
* The colony footprint is wide — 17 CPUs per colony. Burst spread
  rotates wakes across this footprint.
* Most CPUs end up with 2 workers each, evenly distributed.

The picker layer:

* eff = 2 most of the time → regime 2 alternation.
* Occasionally a wake burst lands eff = 3-5 on one CPU before the
  spread mechanism redirects later wakes elsewhere → regime 3-5 →
  saturated path.
* In saturated regime: express has the most-recently-woken workers,
  capacity = 1-2; regular has older waiters. Every pick alternates
  between the express head (~750 µs slice) and the regular head
  (~750 µs slice).
* The bounded-wait analysis predicts a max wait of ~1.5 ms + slice
  in this case — a 16× improvement over current v7's measured 24 ms.

Per-task max wait (perf sched latency) should approach CFS's
12-14 ms ceiling. Wake p99 should remain better than CFS.

Example 4: hackbench -g16 (heavy fan-out)
-----------------------------------------

16 groups × 20 senders × 20 receivers = 320 tasks. Each sender wakes
its 20 receivers via pipes. Heavy wake activity.

The placement layer:

* Each receiver has strong pheromones to its sender + the other 19
  receivers in its group (because senders also receive replies).
* The colony for each group is naturally bounded to ~40 tasks.
* 16 colonies emerge, one per group.
* Colony placement spreads each group across an LLC if possible. On
  a 32-CPU one-LLC system, all 16 colonies share the LLC, so cross-
  colony interference is unavoidable — the placement layer's job is
  to *minimize* it, not eliminate it.

The picker layer:

* eff is high (~10 per CPU). Regime 4 (saturated) most of the time.
* Express has the most recently woken senders/receivers.
* Express capacity = ~5 per rq. Beyond that, demote.
* Bounded wait: ~1.5 ms graduation + ~5 × 500 µs slice = 4 ms.

Hackbench wall time should improve relative to current v7.
Throughput regression vs CFS should largely close.

Example 5: producer-consumer pipeline
-------------------------------------

Stage A produces data, sends to stage B, which produces, sends to
stage C, etc. 4 stages × 8 tasks per stage = 32 tasks.

The placement layer:

* Stage B's tasks have strong pheromones to stage A's tasks.
* Stage C's tasks have strong pheromones to stage B's tasks.
* The colony graph is a layered structure: A→B→C→D.
* Colony placement co-locates each stage on its own LLC region (if
  possible) and routes wakes from A to a CPU near B.
* This is much smarter than ``wake_affine`` (which would just put
  every B-wake on A's CPU).

The picker layer:

* Stages have natural backpressure — A waits for B to consume, B waits
  for A to produce. eff per CPU is bounded.
* Express + regular handles the rest cleanly.

Workload classification falls out: the pheromone graph reveals the
4-stage structure without minlat knowing anything about the
application.

Comparison
==========

vs current SCHED_MINLAT
-----------------------

============================ ===================== =====================
property                     current minlat-v7     colony design
============================ ===================== =====================
Picker pick-time complexity  O(1) leftmost+buddy   O(1) lane head
Picker state per task        rb_node + vruntime    list_node + wait_start
                             + buddy slot
Picker fairness mechanism    leftmost-vruntime     express overflow +
                             + buddy eligibility   regular FIFO
Picker urgency mechanism     buddy slot            express lane membership
Wake placement               wake_affine + LLC     pheromone-driven
                             topology              colony footprint
Wake placement state         per-task prev_cpu     per-task pheromone[8]
                             + recent_used_cpu
Burst handling               wake_burst_spread     colony-aware burst
                             (LLC mask walk)       spread
Workload-aware               no                    yes (pheromones)
Code lines (estimate)        ~5600 (current)       ~5400 (estimate)
============================ ===================== =====================

vs CFS
------

============================ ===================== =====================
property                     CFS                   colony design
============================ ===================== =====================
Picker primary signal        vruntime              wait_start
Pick-time complexity         O(log n) rb-tree      O(1) lane head
Fairness model               proportional share    bounded max wait
Urgency model                sleeper credit        express lane
Wake placement               wake_affine + topo    pheromone colony
Adaptive workload-awareness  no                    yes
Latency target               sched_latency_ns      latency_nice (per-task)
============================ ===================== =====================

vs EEVDF
--------

============================= ============================== =========================
EEVDF                         colony design                  notes
============================= ============================== =========================
``vruntime ≤ avg_vruntime``   express overflow               anti-starvation
earliest deadline first       oldest wait_start in lane      pick rule
``latency_nice`` → slice →    ``latency_nice`` → graduation  urgency knob
deadline                      interval scaling
O(log n) per pick             O(1) per pick                  hot path
per-entity virtual deadline   per-entity wait_start          per-task state
anti-starv via eligibility    anti-starv via lane overflow   different mechanism,
math                                                         same property
no built-in placement         pheromone-driven placement     orthogonal layer
============================= ============================== =========================

Both solve the same problem (bounded latency + fairness). **EEVDF
computes its way to the answer; the colony design arranges its data
so the answer is the head of a queue.** EEVDF is a calculation; the
colony picker is a structure. The structural approach is dramatically
simpler on the pick hot path because it pushes the work to enqueue
and graduation time, both of which can be lazy.

vs MLFQ (Solaris TS, classic Windows)
-------------------------------------

The MLFQ family tunes priorities by *time consumed*: long-running
tasks demote, short-running tasks stay high. It is vulnerable to
gaming via voluntary yields.

The colony design tunes priority by *time waiting*: time waiting
promotes (express FIFO order is by wait time); time elapsed in
express demotes. It is vulnerable to gaming via repeated wakes, but
the express capacity bound caps the gaming rate structurally.

The wait-time framing is also more honest about what the user cares
about: tail latency is a function of wait time, not consumed time.

vs SCX (sched_ext, scx_lavd, scx_rusty)
---------------------------------------

SCX provides a programmable scheduler class via BPF. Schedulers can
be written in userspace and loaded at runtime. ``scx_lavd`` in
particular implements latency-aware virtual deadlines.

The colony design and SCX are not directly comparable: SCX is a
*mechanism* for shipping schedulers, not a scheduler itself. The
colony design could in principle be implemented as an SCX BPF
scheduler, with two caveats:

* SCX BPF schedulers cannot replace the per-rq lock, so the picker
  hot path costs are the same as a native scheduler.
* SCX BPF cannot deeply integrate with PELT, EAS, and the existing
  topology infrastructure that SCHED_MINLAT relies on for placement.

The colony design is intended as a native SCHED_MINLAT successor.
A SCX prototype is plausible as an early proof-of-concept, but the
full design needs native integration.

vs O(1) scheduler (historical, pre-CFS)
---------------------------------------

The O(1) scheduler had two priority arrays (active and expired) and
moved tasks between them as they used their time slices. The colony
picker's express and regular lanes superficially resemble this, but
the transition rules are different:

* O(1): tasks move from active → expired when their slice expires.
* Colony: tasks move from express → regular when their *graduation
  interval* expires (a wall-clock measure, not a CPU time measure).

The O(1) scheduler had well-known fairness problems on interactive
workloads, which CFS was designed to fix. The colony design avoids
those problems by using wait-time (not consumed time) as the
primary signal — interactive workloads stay in express because they
keep waking, not because they consume little CPU.

Hot-path cost analysis
======================

A coarse cycle estimate of the pick and wake hot paths, compared to
current SCHED_MINLAT and to CFS. Estimates are *gross* and assume
warm caches.

Pick path (``__schedule()`` → ``pick_next_task()`` → ``pick_task_minlat()``)
----------------------------------------------------------------------------

============================== =================== ====================
operation                      current minlat      colony design
============================== =================== ====================
read minlat_rq fields          1 cache line        1 cache line
buddy fast path                 5-10 cycles         (deleted)
leftmost rb_first_cached        3-5 cycles          (replaced)
list_first_entry on lane head   N/A                 2-3 cycles
graduation check (lazy)         N/A                 ~10 cycles
return target task              5 cycles            5 cycles
============================== =================== ====================
**estimated total**            **~25 cycles**      **~20 cycles**

The colony picker should be slightly faster than current SCHED_MINLAT
on the pick hot path because it skips the rb-tree leftmost lookup
and the buddy eligibility check.

Wake path (``try_to_wake_up()`` → ``select_task_rq_minlat()`` → enqueue)
------------------------------------------------------------------------

============================== =================== ====================
operation                      current minlat      colony design
============================== =================== ====================
wake_affine_cpu                 ~30 cycles          (deleted)
recent_used_cpu fast path       ~10 cycles          (cold-start fallback)
minlat_select_idle_cpu          ~50-200 cycles      (cold-start fallback)
pheromone update                N/A                 ~30 cycles (8 entries)
colony location query           N/A                 ~50-100 cycles
                                                    (8 task lookups)
wake_burst_spread               ~50 cycles          ~50 cycles
enqueue                          ~20 cycles          ~15 cycles
                                                    (no rb_insert)
============================== =================== ====================
**estimated total (warm)**      **~150 cycles**     **~165 cycles**

The colony wake path is slightly more expensive in steady state due
to the pheromone update and colony query, offset by the simpler
enqueue (list_add vs rb_add). Cold-start (no pheromones) costs more
because it falls back to the topology path.

Cache-line analysis
-------------------

Each pick touches:

* ``minlat_rq`` head: 1 cache line
* Picked task's lane node: 1 cache line
* Picked task's wait_start_ns: same cache line as lane node

Total: 2 cache lines per pick (vs current minlat's 3-4: rb_root, leftmost
node, vruntime, buddy slot).

Each wake touches:

* Wakee's pheromone array: 1-2 cache lines (depending on FANIN)
* Waker tgids' task_struct (for colony query): 1 cache line per
  pheromone source consulted, up to ``MINLAT_PHEROMONE_FANIN``
* Target rq's lane heads: 1 cache line
* Wakee's lane node: 1 cache line

Total: ~5-10 cache lines per wake (vs current minlat's similar
~5-10 in steady state).

Lock acquisition
----------------

Same as current SCHED_MINLAT: rq lock for pick and enqueue, no
additional locks. Pheromone updates are per-task (no shared state),
so no new locking.

Adaptive workload classification
================================

A property that emerges from the design but is not present in any
production scheduler: **once you have pheromone tracking, you can
detect workload changes**. A task whose pheromone vector is *changing*
— new waker patterns appearing, old ones decaying — is in a state
transition. The scheduler can react:

* **Stable colony** — aggressive co-location, minimize migration.
* **Transitioning task** — relax co-location, allow exploration.
* **Solo task** (no significant pheromones) — pure topology placement.
* **Bursty task** (short-lived strong pheromones, then quiet) — keep
  pheromones for a graduation interval, then decay.

This is adaptive scheduler behaviour driven by observed task structure.
CFS, EEVDF, and current SCHED_MINLAT treat every wake the same
regardless of history. SCX schedulers can be programmed to do this
but most do not. **Workload classification falls out of the design
instead of being a separate heuristic.**

Concrete uses for this signal:

* When a task changes colonies (e.g., a worker is reassigned to a
  different message thread), the placement layer detects the new
  pattern within a few wakes and follows the new colony.
* When a task starts a new phase (e.g., a database worker that
  switches from "indexing" to "querying"), the pheromones reset and
  placement re-learns.
* When a task is solo (no pheromones), placement falls through to
  pure topology — same behavior as current SCHED_MINLAT for cold
  workloads.

Failure modes
=============

Adversarial workloads
---------------------

A task that wakes itself in a tight loop (``futex_wake`` → ``futex_wait``
→ ``futex_wake`` → ...) tries to stay in express forever to bypass
fairness. Defenses:

#. **Express capacity bound**: capacity = ``max(1, eff/2)``. After 1-2
   self-wakes, the task overflows express and demotes itself.
#. **Graduation interval**: after ``G(latency_nice)``, the task is
   forcibly demoted regardless of self-wake activity.
#. **Pheromone cycle detection**: a task whose strongest pheromone
   source is *itself* (tgid == own tgid) gets a graduation discount.
   This is optional but cheap.

A task that creates a fanout of N child tasks and wakes them all
simultaneously is *not* adversarial — that's the schbench / hackbench
pattern. The colony placement is designed to handle exactly this.

Hysteresis around regime boundaries
-----------------------------------

If the picker behavior changes abruptly when ``eff`` crosses a
threshold (e.g., 2 → 3), tasks oscillating around the boundary could
trigger expensive transitions. The colony design avoids this because:

* The picker behavior at eff=2 (alternation) and eff=3 (express+FIFO)
  produces the same answer when only 2-3 tasks are involved (the
  oldest-wait task wins in both cases).
* No state transitions happen at the boundary — ``wait_start_ns`` is
  the only state, and it doesn't reset.
* The lane membership is set on wake, not on regime transition.

Unlike e.g. CFS where a task transitioning from a non-throttled
cfs_rq to a throttled one has to go through cgroup state changes,
the colony picker has no analogous transition.

Pheromone staleness
-------------------

A task that has been sleeping for a long time has stale pheromones
when it wakes. The lazy decay mechanism handles this: the first
``minlat_record_pheromone`` after a long sleep applies a large
``half_lives`` value, decaying old entries to near-zero. After a
single wake, the pheromone state is fresh.

A task that has been migrated to a different CPU has stale colony
location data (the cached ``task_cpu`` of pheromone sources). The
colony location query reads ``task_cpu`` at query time, so it's
always fresh.

Cold start latency
------------------

The first wake of a fresh task has no pheromones. Placement falls
through to ``select_task_rq_minlat_wakeup_topology`` (the existing
``wake_affine`` + ``recent_used_cpu`` + ``minlat_select_idle_cpu``
path). After ~10 wakes, the pheromone array has enough data for
colony placement to take over.

This means the colony design has *no worse* cold-start behavior than
current SCHED_MINLAT. The improvement only kicks in for steady-state
workloads.

Cross-NUMA pheromone tracking
-----------------------------

On a multi-NUMA system, the colony location query needs to read the
``task_cpu`` of waker tasks on remote NUMA nodes. This is a remote
memory access. Cost: ~100-200 cycles per query.

For a typical wake with 4-8 active pheromones, the total cost is
400-1600 cycles — comparable to a single page-table walk. Acceptable
on the wake hot path.

If profiling reveals this is too expensive, the colony location query
can be limited to the wakee's NUMA node only, with cross-NUMA placement
falling back to the topology path. This is an open design question.

Pheromone graph cycles
----------------------

If A wakes B and B wakes A, both have each other in their pheromone
arrays. Colony location queries from either return the other's CPU.
This is the desired behavior — it's a tight pair, they should
co-locate.

If A wakes B, B wakes C, C wakes A, the cycle is detected only via
the strongest pheromone (A → C → ... → A). The colony query walks
the strongest first; cycles don't cause infinite loops because the
query is bounded by FANIN.

Relationship to existing minlat infrastructure
==============================================

What stays unchanged
--------------------

* **PELT load tracking** and integration with schedutil — unchanged.
* **CFS bandwidth** (``cpu.max``) throttling — unchanged.
* **Active balance and load balancing** — unchanged. The new picker
  uses the same load_avg signals.
* **Topology helpers** (LLC, NUMA, big.LITTLE, SMT) — unchanged. The
  pheromone layer queries them for colony location.
* **Misfit detection and energy-aware scheduling** (EAS) — unchanged.
  EAS placement runs *before* the colony placement and overrides it
  for energy-critical decisions.
* **The minlat-enabled runtime toggle** — unchanged.
* **The debugfs configuration interface** — adds new tunables,
  removes obsolete ones.

What changes
------------

* ``pick_task_minlat`` — completely rewritten, much shorter
* ``enqueue_task_minlat`` — sets ``wait_start_ns``, places in express
* ``dequeue_task_minlat`` — removes from whichever lane
* ``update_curr_minlat`` — runtime accounting only, no vruntime
* ``__set_next_task_minlat`` — out-of-lane on pick
* ``put_prev_task_minlat`` — re-enters its current lane on put-back
* ``task_tick_minlat`` — runs the graduation sweep
* ``yield_task_minlat`` — moves self to back of regular queue
* ``yield_to_task_minlat`` — promotes target to front of express
* ``select_task_rq_minlat`` — pheromone-driven placement
* ``wakeup_preempt_minlat`` — uniform handling, no eff-based branches
* ``minlat_sched_period`` / ``minlat_sched_slice`` — replaced by the
  graduation interval

What gets deleted
-----------------

* ``vruntime`` field from ``sched_minlat_entity``
* ``min_vruntime`` and related tracking
* ``rb_node`` from ``sched_minlat_entity`` (replaced by ``list_head``)
* ``tasks_timeline`` rb_root (replaced by two ``list_heads``)
* ``set_next_buddy_minlat`` / ``minlat_buddy_eligible`` / buddy slot
* ``__minlat_less`` rb-tree comparator
* All vruntime weight scaling helpers (``minlat_calc_delta``)
* Sleeper credit math in ``place_minlat_entity``
* The eff-based branches in ``wakeup_preempt_minlat`` (uniform handling)
* The ``next`` field in ``struct minlat_rq``
* ``MINLAT_LATENCY_NS`` as a vruntime budget (still exists as a wall-
  clock graduation interval)

Net code change is expected to be a small reduction (~200 lines)
relative to current SCHED_MINLAT, even with the new express/regular
machinery and pheromone state added. The deleted vruntime accounting
code is substantial.

Open design questions
=====================

These need answers before prototyping. Items marked **(blocker)** must
be resolved before any code is written.

Data structure questions
------------------------

#. **Pheromone array size** ``MINLAT_PHEROMONE_FANIN``: 4? 8? 16?
   Larger gives better pattern recognition at the cost of memory and
   update overhead. Starting point: 8.

#. **Pheromone slot eviction policy**: replace weakest? LRU? Replace
   only if new entry is stronger than weakest? Affects how quickly the
   array adapts to workload changes.

#. **Pheromone strength representation**: integer counter? Floating
   point? Saturating arithmetic to avoid overflow?

#. **Lane node placement** in ``sched_minlat_entity``: cacheline
   layout matters. The lane node + wait_start_ns should share a
   cacheline; they're touched together on every pick.

Decay and timing questions
--------------------------

#. **Decay rate** ``PHEROMONE_HALF_LIFE_NS``: 100 ms? 500 ms? 1 s?
   Affects how quickly stale relationships fade. Longer = more stable,
   slower to adapt.

#. **Decay implementation**: per-wake (lazy) decay or wall-clock
   decay? The lazy approach is simpler but doesn't decay idle
   relationships. A hybrid (lazy + occasional sweep) is probably
   right.

#. **Express graduation interval** ``G(latency_nice)``: how does it
   scale with latency_nice? Probably ``latency_thresh(latency_ns,
   wmult)``, mirroring the existing min_gran scaling.

#. **(blocker)** **Express graduation timing**: tick-based sweep
   (O(eff) per tick) vs lazy check on pick (O(1) but stale). The lazy
   approach is much cheaper but can let a stale express entry be
   picked one tick after it should have demoted. Tolerable, probably.

Cgroup and bandwidth questions
------------------------------

#. **(blocker)** **Cgroup cpu.weight**: the express + regular FIFO
   doesn't directly account for weights. Two options: (a) per-cgroup
   express + regular queues (multiplies state), (b) order regular by
   ``wait_start - weight_bonus`` so higher-weight tasks "appear" to
   have been waiting longer. Option (b) is simpler but not strictly
   proportional.

#. **Cgroup cpu.idle**: SCHED_IDLE tasks should be in regular only,
   never express. Their graduation is instant.

#. **Bandwidth throttling**: throttled tasks pause pheromone updates?
   Or continue normally? Probably normal — when they unthrottle, they
   should still know where their colony is.

#. **CFS bandwidth interaction**: how does ``cpu.max`` interact with
   the lane membership? Throttled tasks leave both queues entirely,
   re-enter regular on unthrottle.

Pheromone semantic questions
----------------------------

#. **Pheromone reset on exec()**: a task that does ``exec()`` runs
   different code; old pheromones are stale. Reset on exec.

#. **Pheromone inheritance on fork()**: a forked task inherits an
   empty pheromone array, or copies its parent's? Inheriting helps
   forked-worker patterns warm up faster, but pollutes the colony
   detection if the child is unrelated. Likely answer: empty.

#. **Cross-cgroup pheromones**: pheromones cross cgroup boundaries
   (they reflect actual wake patterns), but cgroup placement
   constraints override pheromone hints. This means a wakee may have
   strong pheromones to a CPU it can't run on; the colony query must
   filter.

#. **Pheromones for non-minlat wakers**: if a non-minlat task wakes
   a minlat task, do we record a pheromone? Probably yes — the
   relationship is real even if the waker isn't minlat.

Migration and locking questions
-------------------------------

#. **Cross-CPU migration**: should ``wait_start_ns`` survive a
   migration? Or reset? CFS keeps vruntime (after normalization).
   Wait time is wall-clock and arguably should not be reset. Likely
   answer: keep wait_start.

#. **Lane membership across migration**: a task migrated mid-burst
   keeps its lane membership? Or resets to express on the new rq?
   Probably reset to express — the migration is itself a
   "wake-equivalent" event.

#. **Pheromone update locking**: pheromones live on the wakee's
   ``sched_minlat_entity``. They're touched by the waker (in
   ``select_task_rq``) which holds the wakee's ``pi_lock`` but
   not the wakee's rq lock. RCU? Atomic? Probably WRITE_ONCE under
   pi_lock is sufficient.

Picker behavioral questions
---------------------------

#. **The saturation transition**: when ``eff`` goes from 2 → 3, the
   picker behaviour changes from "alternation" to "express + regular".
   Should be smooth — no sudden state resets, no leftmost reshuffling.
   With ``wait_start_ns`` as the only state, the transition is
   automatic.

#. **The pipe / IPC fast path**: at ``eff = 1``, both queues have at
   most one entry. The picker is trivial. **This needs to be measured**,
   not assumed — pipe latency is the most-tested microbenchmark and
   any regression here will block the design.

#. **Wake preempt**: when does a fresh wake preempt curr? Inheriting
   the v3a/v3b min_gran floor. The colony version is: preempt curr
   only if curr has run for ``min_gran`` AND the wakee has been
   waiting longer (or has higher latency_nice priority).

Acceptance criteria for the prototype
=====================================

The prototype branch (provisionally ``minlat-colony``) should be
considered worth pursuing only if all of these hold on the same test
machine and same workload set used for the current SCHED_MINLAT v7
measurements:

#. ``schbench wake p99`` is no worse than current SCHED_MINLAT v7
   (currently 49% better than CFS).
#. ``schbench wake p99.9`` is no worse than current SCHED_MINLAT v7
   (currently 46% better than CFS).
#. ``schbench req p99`` at the ``-m 2 -t 16`` key load is within 10%
   of CFS (current SCHED_MINLAT v7 is 28% worse).
#. ``schbench req p99.9`` at the ``-m 2 -t 16`` key load is within
   15% of CFS (current SCHED_MINLAT v7 is 46% worse).
#. ``schbench`` per-task max wait at the ``-m 2 -t 32`` overload is
   within 25% of CFS's clean 12-14 ms ceiling (current SCHED_MINLAT
   v7 is 24-80 ms).
#. ``hackbench -g16`` wall time is within 5% of CFS (current
   SCHED_MINLAT v7 is +9%).
#. ``perf bench sched pipe`` ops/sec is no worse than current
   SCHED_MINLAT v7 (currently ~+29% over CFS).
#. ``perf bench sched messaging -g8`` wall time is within 5% of CFS
   (current SCHED_MINLAT v7 is +3%).
#. ``cyclictest -D60 -p80 -i200`` max latency is no worse than 1 ms
   (current SCHED_MINLAT v7 is 9-90 µs).
#. No new regressions vs current SCHED_MINLAT v7 on any workload in
   the existing bench suite.

Failure on (1), (2), (7), or (9) indicates the design has lost
something essential and should not proceed. Failure on (3-6) or (8)
indicates the design is incomplete and needs more work before
submission. Failure on (10) indicates an unexpected interaction
that needs investigation.

Implementation plan
===================

This is not a v7-series patch. It is a separate proposal that should
live on its own branch (``minlat-colony``) and ship as its own RFC
patch series, parallel to (not on top of) the existing SCHED_MINLAT
v7 work.

Suggested sequencing:

#. **This document.** Shared review of the design before any code is
   written. Resolve the **(blocker)** open design questions above.
#. **Prototype branch** ``minlat-colony``, forked from ``minlat-v7``,
   with the picker and placement layers gutted and rebuilt per this
   design.

   Rough sequencing within the prototype:

   a. Replace ``sched_minlat_entity`` (drop vruntime, add
      ``wait_start_ns`` + ``lane_node`` + ``pheromone[]``).
   b. Replace ``minlat_rq`` (drop ``tasks_timeline`` + ``next``,
      add ``express_q`` + ``regular_q``).
   c. Rewrite ``enqueue_task_minlat``, ``dequeue_task_minlat``,
      ``put_prev_task_minlat``, ``__set_next_task_minlat``.
   d. Rewrite ``pick_task_minlat`` per the regime dispatch.
   e. Rewrite ``wakeup_preempt_minlat`` (uniform handling).
   f. Add the pheromone layer in ``select_task_rq_minlat``.
   g. Re-implement ``yield_task_minlat`` and ``yield_to_task_minlat``.
   h. Wire up the new debugfs tunables, remove obsolete ones.
   i. Boot the prototype and confirm basic functionality
      (``stress-ng``, ``hackbench`` smoke test).

#. **Microbenchmarks** against the existing SCHED_MINLAT v7 baseline
   and against CFS, on the same test machine and workload set. Use
   the existing ``bench-results/scripts/`` harness:

   * ``test_wake_burst_fix.sh`` for wake-burst pattern measurement
   * ``aggregate_fix_sweep.py`` for the schbench/hackbench/messaging
     sweep
   * ``oncpu_dist.py`` for on-CPU duration distribution
   * ``trace_worst.py`` for worst-event analysis
   * Newly written: pheromone graph visualization tool

#. **Iteration** on the open design questions above based on what
   the prototype reveals. Particular focus on:

   * Pheromone array size (FANIN)
   * Decay rate (HALF_LIFE_NS)
   * Express graduation interval scaling
   * Cgroup weight handling

#. **RFC patch series** to the linux-kernel mailing list, marked as
   a parallel design proposal — not a v8 of SCHED_MINLAT.

   Rough series shape:

   * Patch 1: Add ``wait_start_ns`` + ``lane_node`` + ``pheromone[]``
     to ``sched_minlat_entity``, add lane lists to ``minlat_rq``.
     No semantic changes — preparation only.
   * Patch 2: Implement express + regular FIFO picker. Replace
     ``pick_task_minlat`` and adjacent helpers.
   * Patch 3: Implement pheromone tracking and colony placement in
     ``select_task_rq_minlat``.
   * Patch 4: Delete vruntime, ``min_vruntime``, ``__minlat_less``,
     ``minlat_calc_delta``, the buddy slot, sleeper credit, the
     wake_burst_spread cookie state.
   * Patch 5: Update ``wakeup_preempt_minlat`` for uniform handling.
   * Patch 6: Add ``Documentation/scheduler/sched-minlat-colony.rst``
     describing the design (this document, updated to describe
     merged code).

This document is the input to step 1.

References
==========

* :doc:`sched-design-CFS` — the current proportional-fairness model
  SCHED_MINLAT inherits from.
* :doc:`sched-eevdf` — the production alternative that solves the
  fairness/latency tension via virtual deadlines.
* :doc:`sched-ext` — the BPF-based extensible scheduler class, which
  represents a different approach (programmable rather than
  redesigned).
* :doc:`sched-design-CFS` — for comparison of the wait-time vs
  consumed-time framings.
* ``kernel/sched/minlat.c`` — the current SCHED_MINLAT implementation
  this proposal aims to replace.
* ``kernel/sched/fair.c`` — the EEVDF implementation, particularly
  ``entity_eligible()``, ``__pick_eevdf()``, and ``set_next_buddy()``,
  for comparison points.
* Bonabeau, Dorigo, Theraulaz, *Swarm Intelligence: From Natural to
  Artificial Systems* (1999) — pheromone-trail foundations.
* Helbing, *Traffic and related self-driven many-particle systems*,
  Reviews of Modern Physics 73(4) — phase transitions in flow.
* Stoica et al, *A Proportional Share Resource Allocation Algorithm
  for Real-Time, Time-Shared Systems* (1996) — early WFQ-on-CPU.
