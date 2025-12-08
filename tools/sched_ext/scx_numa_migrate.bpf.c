/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A NUMA-aware scheduler demonstrating scx_bpf_migrate_task_pages().
 *
 * This scheduler tracks task migrations across NUMA nodes and hints async
 * page migration when tasks move to different nodes. It demonstrates:
 *
 * - Using scx_bpf_migrate_task_pages() to hint page migration
 * - NUMA-aware task placement decisions
 * - Statistics tracking for NUMA migrations and page hints
 *
 * The scheduler operates as a simple weighted vtime scheduler but adds
 * NUMA awareness by:
 * 1. Detecting when tasks migrate across NUMA boundaries
 * 2. Hinting page migration to follow the task to the new node
 * 3. Tracking statistics about NUMA decisions
 *
 * This is a demonstration scheduler showing best practices for using the
 * page migration hint API. Production schedulers may implement more
 * sophisticated policies.
 *
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* Configuration: minimum time (ns) between page migration hints for a task */
const volatile u64 hint_interval_ns = 1000000000ULL; /* 1 second default */
const volatile bool enable_migration_hints = true;

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0

/* Per-task state for tracking NUMA migrations */
struct task_numa_state {
	s32 last_nid;       /* Last NUMA node where task ran */
	u64 last_hint_time; /* Last time we hinted page migration */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(pid_t));
	__uint(value_size, sizeof(struct task_numa_state));
	__uint(max_entries, 10000);
} task_numa_map SEC(".maps");

/* Statistics */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 4);
} stats SEC(".maps");

enum stat_idx {
	STAT_LOCAL_QUEUE = 0,   /* Tasks queued to local DSQ */
	STAT_GLOBAL_QUEUE = 1,  /* Tasks queued to global DSQ */
	STAT_NUMA_CROSS = 2,    /* Tasks crossing NUMA boundaries */
	STAT_PAGE_HINTS = 3,    /* Page migration hints issued */
};

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

/*
 * Get the NUMA node ID for a CPU.
 * Returns -1 if topology info unavailable.
 */
static s32 cpu_to_node(s32 cpu)
{
	if (cpu < 0 || cpu >= scx_bpf_nr_cpu_ids())
		return -1;

	return scx_bpf_cpu_node(cpu);
}

s32 BPF_STRUCT_OPS(numa_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu, prev_nid, new_nid;
	struct task_numa_state *state;
	pid_t pid = p->pid;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	/* Get NUMA nodes */
	prev_nid = cpu_to_node(prev_cpu);
	new_nid = cpu_to_node(cpu);

	/*
	 * If task is crossing NUMA nodes and migration hints are enabled,
	 * hint async page migration to the new node.
	 */
	if (enable_migration_hints && prev_nid >= 0 && new_nid >= 0 &&
	    prev_nid != new_nid) {
		u64 now = bpf_ktime_get_ns();
		bool should_hint = false;

		stat_inc(STAT_NUMA_CROSS);

		/* Check if enough time has passed since last hint */
		state = bpf_map_lookup_elem(&task_numa_map, &pid);
		if (!state) {
			/* First time seeing this task - create state */
			struct task_numa_state new_state = {
				.last_nid = new_nid,
				.last_hint_time = now,
			};
			bpf_map_update_elem(&task_numa_map, &pid, &new_state,
					    BPF_ANY);
			should_hint = true;
		} else if (state->last_nid != new_nid) {
			/* Task moved to a different node */
			if (now - state->last_hint_time >= hint_interval_ns) {
				state->last_nid = new_nid;
				state->last_hint_time = now;
				should_hint = true;
			}
		}

		/*
		 * Hint page migration to follow the task.
		 * This is async and non-blocking.
		 */
		if (should_hint) {
			scx_bpf_migrate_task_pages(p, new_nid, 0);
			stat_inc(STAT_PAGE_HINTS);
		}
	}

	if (is_idle) {
		stat_inc(STAT_LOCAL_QUEUE);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(numa_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 vtime = p->scx.dsq_vtime;

	stat_inc(STAT_GLOBAL_QUEUE);

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
		vtime = vtime_now - SCX_SLICE_DFL;

	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
				 enq_flags);
}

void BPF_STRUCT_OPS(numa_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(numa_running, struct task_struct *p)
{
	/*
	 * Global vtime always progresses forward as tasks start executing.
	 * The test and update can be performed concurrently from multiple
	 * CPUs and thus racy. Any error should be contained and temporary.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(numa_stopping, struct task_struct *p, bool runnable)
{
	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(numa_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

void BPF_STRUCT_OPS(numa_disable, struct task_struct *p)
{
	pid_t pid = p->pid;

	/* Clean up task state when task exits or scheduler is disabled */
	bpf_map_delete_elem(&task_numa_map, &pid);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(numa_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(numa_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(numa_migrate_ops,
	       .select_cpu		= (void *)numa_select_cpu,
	       .enqueue			= (void *)numa_enqueue,
	       .dispatch		= (void *)numa_dispatch,
	       .running			= (void *)numa_running,
	       .stopping		= (void *)numa_stopping,
	       .enable			= (void *)numa_enable,
	       .disable			= (void *)numa_disable,
	       .init			= (void *)numa_init,
	       .exit			= (void *)numa_exit,
	       .name			= "numa_migrate");
