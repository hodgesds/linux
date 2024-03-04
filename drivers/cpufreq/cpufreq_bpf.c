// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/drivers/cpufreq/cpufreq_bpf.c
 *
 *  Copyright (C) 2024 Meta Platforms, Inc. and affiliates
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/cpufreq_bpf.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>


/* "extern" is to avoid sparse warning.  It is only used in bpf_struct_ops.c. */
extern struct bpf_struct_ops bpf_cpufreq_bpf_ops;

static DEFINE_MUTEX(cpufreq_ops_enable_mutex);
static struct cpufreq_bpf_ops *cpufreq_ops;
static struct cpufreq_bpf_ops default_cpufreq_ops;

// see
// net/ipv4/bpf_tcp_ca.c#L14
// /net/bpf/bpf_dummy_struct_ops.c


struct bpf_cpumask;

// Helpers
static inline struct cpufreq_policy *get_cpu_policy(unsigned int cpu)
{
	int ret;

	struct cpufreq_policy *policy;

	if (cpu > nr_cpu_ids)
		return NULL;

	ret = cpufreq_get_policy(policy, cpu);

	if (ret)
		return NULL;

	return policy;
}

// kfuncs
__bpf_hook_start()


// cpufreq_bpf_ops defaults
static int __bpf_cpufreq_policy_start(struct cpufreq_policy *policy)
{
	BUG_ON(!policy->cur);
	pr_debug("started managing cpu %u\n", policy->cpu);
	printk("cpufreq: bpf: %s stub", __func__);

	return 0;
}

static void __bpf_cpufreq_policy_stop(struct cpufreq_policy *policy)
{
	pr_debug("managing cpu %u stopped\n", policy->cpu);
	printk("cpufreq: bpf: %s stub", __func__);
}

static void __bpf_cpufreq_policy_limits(struct cpufreq_policy *policy)
{
	printk("cpufreq: bpf: %s stub", __func__);
	__cpufreq_driver_target(policy, policy->cur, CPUFREQ_RELATION_C);
}

static int __bpf_cpufreq_policy_store_setspeed(struct cpufreq_policy *policy, unsigned int freq)
{
	int ret = -EINVAL;
	printk("cpufreq: bpf: %s stub", __func__);

	policy->cur = freq;

	ret = __cpufreq_driver_target(policy, policy->cur, CPUFREQ_RELATION_C);

	return ret;
}


__bpf_kfunc int bpf_cpufreq_gov_set_cpu(unsigned int freq, unsigned int cpu)
{
	int ret = 0;

	struct cpufreq_policy *policy = cpufreq_cpu_acquire(cpu);

	printk("cpufreq: bpf: %s: freq %u", __func__, freq);

	if (!policy)
		return -EINVAL;

	ret = cpufreq_driver_fast_switch(policy, freq);

	cpufreq_cpu_release(policy);

	return ret;
}

__bpf_kfunc int bpf_cpufreq_gov_set(struct bpf_cpumask *mask, unsigned int freq)
{
	int cpu = 0;
	int ret = 0;

	for (cpu = cpumask_next(cpu, (struct cpumask *)&mask); cpu < nr_cpu_ids;
			cpu = cpumask_next(cpu, (struct cpumask *)&mask)) {
		ret = bpf_cpufreq_gov_set_cpu(freq, cpu);
		if (ret)
			break;
	}

	return ret;
}

__bpf_kfunc unsigned int bpf_cpufreq_drv_get_hw_max_freq(unsigned int cpu)
{
	return cpufreq_get_hw_max_freq(cpu);
}

__bpf_kfunc unsigned int bpf_cpufreq_drv_quick_get(unsigned int cpu)
{
	return cpufreq_quick_get(cpu);
}

__bpf_kfunc unsigned int bpf_cpufreq_drv_quick_get_max(unsigned int cpu)
{
	return cpufreq_quick_get_max(cpu);
}

__bpf_kfunc void bpf_cpufreq_drv_enable_fast_switch(unsigned int cpu)
{
	struct cpufreq_policy *policy = get_cpu_policy(cpu);

	cpufreq_enable_fast_switch(policy);
}

__bpf_kfunc void bpf_cpufreq_drv_disable_fast_switch(unsigned int cpu)
{
	struct cpufreq_policy *policy = get_cpu_policy(cpu);

	cpufreq_disable_fast_switch(policy);
}

__bpf_kfunc int bpf_cpufreq_drv_boost_enabled(void)
{
	return cpufreq_boost_enabled();
}

__bpf_kfunc void bpf_cpufreq_drv_enable_boost_support(void)
{
	cpufreq_enable_boost_support();
}


__bpf_hook_end();


// struct_ops


static const struct bpf_func_proto * bpf_cpufreq_get_func_proto(
	enum bpf_func_id func_id, const struct bpf_prog *prog
) {
	printk("cpufreq: bpf: %s: bpf_func_id: %d", __func__, func_id);

	switch (func_id) {
	// case BPF_FUNC_ktime_get_coarse_ns:
	//	return &bpf_ktime_get_coarse_ns_proto;
	case BPF_FUNC_task_storage_get:
		return &bpf_task_storage_get_proto;
	case BPF_FUNC_task_storage_delete:
		return &bpf_task_storage_delete_proto;
	case BPF_FUNC_trace_vprintk:
		printk("cpufreq: bpf: %s: got vprintk: %d", __func__, func_id);
		return bpf_get_trace_vprintk_proto();
	case BPF_FUNC_trace_printk:
		printk("cpufreq: bpf: %s: got printk: %d", __func__, func_id);
		return bpf_get_trace_printk_proto();
	default:
		struct bpf_func_proto * proto;
		proto = bpf_base_func_proto(func_id);
		if (proto) {
			printk("cpufreq: bpf: %s: base proto: %d", __func__, func_id);
			return proto;
		}
		proto = tracing_prog_func_proto(func_id, prog);
		printk("cpufreq: bpf: %s: tracing_prog_get_proto: %d", __func__, func_id);
		return proto;
	}
}

static bool bpf_cpufreq_is_valid_access(
	int off, int size, enum bpf_access_type type, const struct bpf_prog *prog,
	struct bpf_insn_access_aux *info
) {
	bool ret;

	ret = bpf_tracing_btf_ctx_access(off, size, type, prog, info);

	printk("cpufreq: bpf: %s: access %d", __func__, ret);

	return true;
}

static int bpf_cpufreq_btf_struct_access(
	struct bpf_verifier_log *log, const struct bpf_reg_state *reg, int off, int size
) {
	const struct btf_type *state;
	const struct btf_type *t;
	s32 type_id;

	printk("cpufreq: bpf: %s", __func__);

	type_id = btf_find_by_name_kind(reg->btf, "cpufreq_policy",
					BTF_KIND_STRUCT);
	if (type_id < 0) {
		bpf_log(log, "cpufreq: bpf: no good type id\n");
		printk("cpufreq: bpf: %s: invalid type_id", __func__);
		return -EINVAL;
	}

	t = btf_type_by_id(reg->btf, reg->btf_id);
	state = btf_type_by_id(reg->btf, type_id);
	if (t != state) {
		bpf_log(log, "cpufreq: bpf: only access to cpufreq_policy is supported\n");
		printk("cpufreq: bpf: %s: only access to cpufreq_policy is supported", __func__);
		return -EACCES;
	}

	if (off + size > sizeof(struct cpufreq_policy)) {
		printk("cpufreq: bpf: %s: only write beyond cpufreq_policy", __func__);
		bpf_log(log, "cpufreq: bpf: write access at off %d with size %d\n", off, size);
		return -EACCES;
	}

	return NOT_INIT;
}

static int bpf_cpufreq_init_member(const struct btf_type *t, const struct
		btf_member *member, void *kdata, const void *udata)
{
	const struct cpufreq_bpf_ops *uops = udata;

	struct cpufreq_bpf_ops *ops = kdata;

	u32 moff = __btf_member_bit_offset(t, member) / 8;

	int ret = 0;

	printk("cpufreq: bpf: %s: uops: %p, kdata_ops %p, cpufreq_ops %p", __func__, uops, ops, cpufreq_ops);

	switch (moff) {
	case offsetof(struct cpufreq_bpf_ops, start):
		printk("cpufreq: bpf: init start");
		if (*(u64 *)(udata+moff)) {
			printk("cpufreq: bpf: %s: start valid", __func__);
		} else {
			printk("cpufreq: bpf: %s: start invalid", __func__);
		}
		break;
	case offsetof(struct cpufreq_bpf_ops, stop):
		printk("cpufreq: bpf: init stop");
		break;
	case offsetof(struct cpufreq_bpf_ops, limits):
		printk("cpufreq: bpf: init limits");
		break;
	case offsetof(struct cpufreq_bpf_ops, store_setspeed):
		printk("cpufreq: bpf: init store_setspeed");
		break;
	}

	return ret;
}

static int bpf_cpufreq_check_member(const struct btf_type *t, const struct
		btf_member *member, const struct bpf_prog *prog)
{
	printk("cpufreq: bpf: check your member\n");
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct cpufreq_bpf_ops, start):
		printk("cpufreq: bpf: check start");
		break;
	case offsetof(struct cpufreq_bpf_ops, stop):
		printk("cpufreq: bpf: check stop");
		break;
	case offsetof(struct cpufreq_bpf_ops, limits):
		printk("cpufreq: bpf: check limits");
		break;
	case offsetof(struct cpufreq_bpf_ops, store_setspeed):
		printk("cpufreq: bpf: check store_setspeed");
		break;
	default:
		if (prog->aux->sleepable) {
			printk("no sleep till brooklyn");
			return -EINVAL;
		}
	}

       	return 0;
}

static int bpf_cpufreq_update(void *kdata, void *old_kdata)
{
	const struct cpufreq_bpf_ops *old_ops = old_kdata;
	struct cpufreq_bpf_ops *ops = kdata;

	printk("cpufreq: bpf: %s old_ops %p kops %p", __func__, old_ops, ops);
	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	return 0;
}

static int bpf_cpufreq_validate(void *kdata)
{
	struct cpufreq_bpf_ops *ops = kdata;
	printk("cpufreq: bpf: %s kops %p", __func__, ops);
	return 0;
}

static int bpf_cpufreq_init(struct btf *btf)
{
	printk("cpufreq: bpf: %s", __func__);
	return 0;
}

static int bpf_cpufreq_reg(void *kdata)
{
	struct cpufreq_bpf_ops *ops = kdata;

	printk("cpufreq: bpf: %s cpufreq_ops %p ops %p", __func__, cpufreq_ops, ops);
	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
	printk("cpufreq: bpf: %s cpufreq_ops %p ops %p", __func__, cpufreq_ops, ops);

	return 0;
}

static void bpf_cpufreq_unreg(void *kdata)
{
	struct cpufreq_bpf_ops *ops = kdata;

	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
}


BTF_SET8_START(cpufreq_bpf_ops_kfuncs)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_start, KF_ACQUIRE)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_stop, KF_ACQUIRE)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_limits, KF_ACQUIRE)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_store_setspeed, KF_ACQUIRE)
BTF_SET8_END(cpufreq_bpf_ops_kfuncs)

BTF_SET8_START(cpufreq_bpf_drv_kfuncs)
BTF_ID_FLAGS(func, bpf_cpufreq_gov_set_cpu)
BTF_ID_FLAGS(func, bpf_cpufreq_gov_set, KF_RCU)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_get_hw_max_freq)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_quick_get)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_quick_get_max)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_enable_fast_switch)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_disable_fast_switch)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_boost_enabled)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_enable_boost_support)
BTF_SET8_END(cpufreq_bpf_drv_kfuncs)


static const struct bpf_verifier_ops bpf_cpufreq_verifier_ops = {
	.get_func_proto		= bpf_cpufreq_get_func_proto,
	.is_valid_access	= bpf_cpufreq_is_valid_access,
	.btf_struct_access	= bpf_cpufreq_btf_struct_access,
};


static struct cpufreq_bpf_ops default_cpufreq_ops = {
	.start		= __bpf_cpufreq_policy_start,
	.stop		= __bpf_cpufreq_policy_stop,
	.limits		= __bpf_cpufreq_policy_limits,
	.store_setspeed	= __bpf_cpufreq_policy_store_setspeed,
};



struct bpf_struct_ops bpf_cpufreq_bpf_ops = {
	.verifier_ops = &bpf_cpufreq_verifier_ops,
	.reg = bpf_cpufreq_reg,
	.unreg = bpf_cpufreq_unreg,
	.update = bpf_cpufreq_update,
	.check_member = bpf_cpufreq_check_member,
	.init_member = bpf_cpufreq_init_member,
	.init = bpf_cpufreq_init,
	.validate = bpf_cpufreq_validate,
	.name = "cpufreq_bpf_ops",
};


static const struct btf_kfunc_id_set cpufreq_bpf_ops_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &cpufreq_bpf_ops_kfuncs,
};

static const struct btf_kfunc_id_set cpufreq_bpf_drv_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &cpufreq_bpf_drv_kfuncs,
};


// Governor

static int cpufreq_bpf_policy_init(struct cpufreq_policy *policy)
{
	struct cpufreq_bpf_gov *gov;
	//struct bpf_prog_array *progs;

	// enable fast switch by default
	printk("cpufreq: bpf: %s: ops %p cpu %u", __func__, &default_cpufreq_ops, policy->cpu);


	gov = kzalloc(sizeof(*gov), GFP_KERNEL);
	if (!gov) {
		printk("failed to alloc gov");
		return -ENOMEM;
	}

	policy->governor_data = gov;

	//progs = bpf_prog_array_alloc(CPUFREQ_BPF_MAX_PROGS_PER_GOV, GFP_KERNEL);
	//if (!progs) {
	//	printk("failed to alloc progs");
	//	return -ENOMEM;
	//}

	//gov->progs = progs;

	cpufreq_enable_fast_switch(policy);

	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	return 0;
}

static void cpufreq_bpf_policy_exit(struct cpufreq_policy *policy)
{
	printk("cpufreq: bpf: %s: cpu %u", __func__, policy->cpu);

	kfree(policy->governor_data);
	policy->governor_data = NULL;

	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
}

static int cpufreq_bpf_policy_start(struct cpufreq_policy *policy)
{
	struct cpufreq_bpf_gov *gov = policy->governor_data;

	int ret;

	ret = 0;

	BUG_ON(!policy->cur);

	printk("cpufreq: bpf: %s: ops %p cpu %u", __func__, &cpufreq_ops, policy->cpu);

	// down_write(&policy->rwsem);
	// ret = __bpf_cpufreq_ops.start(policy);
	//up_write(&policy->rwsem);

	if (!gov) {
		printk("cpufreq: bpf: no cpufreq_bpf_gov");
		return 0;
		// return -EINVAL;
	}

	ret = cpufreq_ops->start(policy);
	printk("cpufreq: bpf: %s: cpu %u ret: %u", __func__, policy->cpu, ret);

	return ret;
}

static void cpufreq_bpf_policy_stop(struct cpufreq_policy *policy)
{
	// void * ctx;

	printk("cpufreq: bpf: %s: ops %p cpu %u", __func__, &cpufreq_ops, policy->cpu);

	//down_write(&policy->rwsem);
	// __bpf_cpufreq_ops.stop(policy);
	//up_write(&policy->rwsem);

	struct cpufreq_bpf_gov *gov = policy->governor_data;
	if (!gov) {
		printk("cpufreq: bpf: no cpufreq_bpf_gov");
		return;
	}

	cpufreq_ops->stop(policy);

	printk("cpufreq: bpf: %s: setting defaults", __func__);

	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	//if (gov->progs) {
	//	printk("running stop progs");
	//	rcu_read_lock();
	//	bpf_prog_run_array(rcu_dereference(gov->progs), ctx, bpf_prog_run);
	//	rcu_read_unlock();
	//}
}

static void cpufreq_bpf_policy_limits(struct cpufreq_policy *policy)
{
	struct cpufreq_bpf_gov *gov = policy->governor_data;


	//down_write(&policy->rwsem);
	//__bpf_cpufreq_ops.limits(policy);
	//up_write(&policy->rwsem);

	if (!gov) {
		printk("cpufreq: bpf: %s: no cpufreq_bpf_gov", __func__);
		return;
	}

	printk("cpufreq: bpf: %s ops %p cpu %u", __func__, &cpufreq_ops, policy->cpu);

	cpufreq_ops->limits(policy);

	//if (gov->progs) {
	//	printk("running limits progs");
	//	rcu_read_lock();
	//	bpf_prog_run_array(rcu_dereference(gov->progs), ctx, bpf_prog_run);
	//	rcu_read_unlock();
	//}
}

static ssize_t cpufreq_bpf_show_setspeed(struct cpufreq_policy *policy, char *buf)
{
	printk("cpufreq: bpf: %s", __func__);

	return sprintf(buf, "%u\n", policy->cur);
}

static int cpufreq_bpf_store_setspeed(struct cpufreq_policy *policy, unsigned int freq)
{
	int ret = 0;

	printk("cpufreq: bpf: %s: cpu %u %u", __func__, policy->cpu, freq);
	policy->cur = freq;

	//down_write(&policy->rwsem);
	// ret =  __bpf_cpufreq_ops.store_setspeed(policy, freq);
	//up_write(&policy->rwsem);


	struct cpufreq_bpf_gov *gov = policy->governor_data;
	if (!gov) {
		printk("cpufreq: bpf: no cpufreq_bpf_gov");
		// return -EINVAL;
	}

	ret = cpufreq_ops->store_setspeed(policy, freq);

	printk("cpufreq: bpf: %s: %p setspeed %u ret: %u", __func__, &cpufreq_ops, policy->cpu, ret);


	return ret;
}


// Initialization

static struct cpufreq_governor cpufreq_gov_bpf = {
	.name		= "bpf",
	.init		= cpufreq_bpf_policy_init,
	.exit		= cpufreq_bpf_policy_exit,
	.start		= cpufreq_bpf_policy_start,
	.stop		= cpufreq_bpf_policy_stop,
	.limits		= cpufreq_bpf_policy_limits,
	.store_setspeed	= cpufreq_bpf_store_setspeed,
	.show_setspeed	= cpufreq_bpf_show_setspeed,
	.owner		= THIS_MODULE,
};


static int init_bpf(void)
{
	int ret;

	// struct_ops
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
			&cpufreq_bpf_ops_kfunc_set);
	printk("cpufreq: bpf: %s: BPF_PROG_TYPE_STRUCT_OPS: ret %d", __func__, ret);


	// Driver kfuncs
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
			&cpufreq_bpf_drv_kfunc_set);
	printk("cpufreq: bpf: %s: BPF_PROG_TYPE_SCHED_CLS: ret %d", __func__, ret);
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
			&cpufreq_bpf_drv_kfunc_set);
	printk("cpufreq: bpf: %s: BPF_PROG_TYPE_SCHED_ACT: ret %d", __func__, ret);
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
			&cpufreq_bpf_drv_kfunc_set);
	printk("cpufreq: bpf: %s: BPF_PROG_TYPE_TRACING: ret %d", __func__, ret);
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
			&cpufreq_bpf_drv_kfunc_set);
	printk("cpufreq: bpf: %s: BPF_PROG_TYPE_UNSPEC: ret %d", __func__, ret);
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
			&cpufreq_bpf_drv_kfunc_set);
	printk("cpufreq: bpf: %s: BPF_PROG_TYPE_SYSCALL: ret %d", __func__, ret);

	if (ret)
		return -EINVAL;

	return ret;
}

static int __init cpufreq_bpf_module_init(void)
{
	int ret;

	ret = cpufreq_register_governor(&cpufreq_gov_bpf);
	printk("cpufreq: bpf: %s: ret %d", __func__, ret);

	return ret;
}

static void __exit cpufreq_bpf_module_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_bpf);
}

late_initcall(init_bpf);
module_init(cpufreq_bpf_module_init);
module_exit(cpufreq_bpf_module_exit);

MODULE_AUTHOR("Daniel Hodges");
MODULE_DESCRIPTION("cpufreq policy governor 'bpf'");
MODULE_LICENSE("GPL");
