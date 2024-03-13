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


__bpf_hook_start();


// cpufreq_bpf_ops defaults
__bpf_kfunc static int __bpf_cpufreq_policy_start(struct cpufreq_policy *policy)
{
	return 0;
}

__bpf_kfunc static void __bpf_cpufreq_policy_stop(struct cpufreq_policy *policy) {}

__bpf_kfunc static void __bpf_cpufreq_policy_limits(struct cpufreq_policy *policy)
{
	if (!policy) {
		return;
	}

	// By default set the frequency as close to the policy.
	__cpufreq_driver_target(policy, policy->cur, CPUFREQ_RELATION_C);
}

__bpf_kfunc static int __bpf_cpufreq_policy_store_setspeed(struct cpufreq_policy *policy, unsigned int freq)
{
	if (!policy) {
		return 0;
	}

	int ret;

	policy->cur = freq;

	ret = __cpufreq_driver_target(policy, policy->cur, CPUFREQ_RELATION_C);

	return 0;
}

// kfunc helpers
__bpf_kfunc int bpf_cpufreq_gov_set_cpu(unsigned int freq, unsigned int cpu)
{
	struct cpufreq_policy *policy = cpufreq_cpu_acquire(cpu);

	if (!policy)
		return -EINVAL;

	policy->cur = freq;

	int ret = cpufreq_driver_fast_switch(policy, freq);

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

__bpf_kfunc int bpf_cpufreq_drv_boost_trigger_state(int state)
{
	return cpufreq_boost_trigger_state(state);
}

__bpf_hook_end();


// struct_ops implementation


static const struct bpf_func_proto * bpf_cpufreq_get_func_proto(
	enum bpf_func_id func_id, const struct bpf_prog *prog
) {

	// printk("cpufreq: bpf: %s: base_func_proto default for func_id %d", __func__, func_id);
	switch (func_id) {
	case BPF_FUNC_task_storage_get:
		return &bpf_task_storage_get_proto;
	case BPF_FUNC_task_storage_delete:
		return &bpf_task_storage_delete_proto;
	case BPF_FUNC_trace_vprintk:
		return bpf_get_trace_vprintk_proto();
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	// case BPF_FUNC___bpf_cpufreq_policy_start:
	// 	return &bpf_btf_cpufreq_policy_start_proto ;
	// case BPF_FUNC___bpf_cpufreq_policy_stop:
	// 	return &bpf_btf_cpufreq_policy_stop_proto ;
	// case BPF_FUNC___bpf_cpufreq_policy_limits:
	// 	return &bpf_btf_cpufreq_policy_limits_proto ;
	// case BPF_FUNC___bpf_cpufreq_policy_store_setspeed:
	// 	return &bpf_btf_cpufreq_policy_store_setspeed_proto ;
	default:
		// printk("cpufreq: bpf: %s: base_func_proto default for func_id %d", __func__, func_id);
		struct bpf_func_proto * proto;
		proto = bpf_base_func_proto(func_id);
		if (proto) {
			printk("cpufreq: bpf: %s: base_func_proto", __func__);
			return proto;
		}
		proto = tracing_prog_func_proto(func_id, prog);
		if (proto) {
			printk("cpufreq: bpf: %s: tracing_prog_func_proto", __func__);
		}
		return proto;
	}
}

static bool bpf_cpufreq_is_valid_access(
	int off, int size, enum bpf_access_type type, const struct bpf_prog *prog,
	struct bpf_insn_access_aux *info
) {
	printk("cpufreq: bpf: %s: off: %d size: %d type: %d", __func__, off, size, type);
	return true;
	// bool ret = bpf_tracing_btf_ctx_access(off, size, type, prog, info);
	// if (base_type(info->reg_type) == PTR_TO_BTF_ID &&
	//     !bpf_type_has_unsafe_modifiers(info->reg_type) &&
	//     info->btf_id == sock_id)
	// 	/* promote it to tcp_sock */
	// 	info->btf_id = tcp_sock_id;

	// return ret;
}

static int bpf_cpufreq_btf_struct_access(
	struct bpf_verifier_log *log, const struct bpf_reg_state *reg, int off, int size
) {
	const struct btf_type *state;
	const struct btf_type *t;
	s32 type_id;


	type_id = btf_find_by_name_kind(reg->btf, "cpufreq_policy", BTF_KIND_STRUCT);

	if (type_id < 0) {
		printk("cpufreq: bpf: %s: type_id < 0", __func__);
		// bpf_log(log, "[cpufreq] %s: type_id = %p", __func__, type_id);
		return -EINVAL;
	}

	t = btf_type_by_id(reg->btf, reg->btf_id);
	state = btf_type_by_id(reg->btf, type_id);

	if (t != state) {
		printk("cpufreq: bpf: %s: t != state", __func__);
		// bpf_log(log, "[cpufreq] %s: type = %p state= %p", __func__, t,
		// 		state);
		return -EACCES;
	}

	// [100275] STRUCT 'cpufreq_bpf_ops' size=32 vlen=4
        // 'start' type_id=3348 bits_offset=0
        // 'stop' type_id=3352 bits_offset=64
        // 'limits' type_id=3352 bits_offset=128
        // 'store_setspeed' type_id=3350 bits_offset=192

	if (off + size > sizeof(struct cpufreq_policy)) {
		printk("cpufreq: bpf: %s: off+size > sizeof cpufreq_policy", __func__);
		// bpf_log(log, "[cpufreq] %s: offset= %d size= %d sizeof(cpufreq_policy) %d", __func__, off,
		// 		size, sizeof(struct cpufreq_policy));
		return -EACCES;
	}

	return 0;
	// return RET_PTR_TO_MEM_OR_BTF_ID;
	// return RET_PTR_TO_BTF_ID_TRUSTED;
}

static int bpf_cpufreq_init_member(const struct btf_type *t, const struct
		btf_member *member, void *kdata, const void *udata)
{
	const struct cpufreq_bpf_ops *uops = udata;

	struct cpufreq_bpf_ops *ops = kdata;
	printk("cpufreq: %s: uops: %p ops: %p", __func__, uops, ops);

	u32 moff = __btf_member_bit_offset(t, member) / 8;

	int ret = 0;


	switch (moff) {
	case offsetof(struct cpufreq_bpf_ops, start):
		if (*(u64 *)(udata+moff)) {
			printk("cpufreq: bpf: %s: start valid", __func__);
		} else {
			printk("cpufreq: bpf: %s: start invalid", __func__);
		}
		return 1;
	case offsetof(struct cpufreq_bpf_ops, stop):
		printk("cpufreq: bpf: init stop");
		return 1;
	case offsetof(struct cpufreq_bpf_ops, limits):
		printk("cpufreq: bpf: init limits");
		return 1;
	case offsetof(struct cpufreq_bpf_ops, store_setspeed):
		printk("cpufreq: bpf: init store_setspeed");
		if (*(u64 *)(udata+moff)) {
			printk("cpufreq: bpf: %s: store_setspeed valid", __func__);
		} else {
			printk("cpufreq: bpf: %s: store_setspeed invalid", __func__);
		}
		return 1;
	}

	return ret;
}

static int bpf_cpufreq_check_member(const struct btf_type *t, const struct
		btf_member *member, const struct bpf_prog *prog)
{
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
			return -EINVAL;
		}
	}

	return 0;
}

static int bpf_cpufreq_update(void *kdata, void *old_kdata)
{
	const struct cpufreq_bpf_ops *old_ops = old_kdata;
	struct cpufreq_bpf_ops *ops = kdata;

	printk("cpufreq: bpf: %s: odl_ops: %p new_ops: %p");
	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	return 0;
}

static int bpf_cpufreq_validate(void *kdata)
{
	struct cpufreq_bpf_ops *ops = kdata;
	if (!ops)
		return -EINVAL;

	// Check if an existing struct_ops implementation is active.
	bool is_active = false;

	mutex_lock(&cpufreq_ops_enable_mutex);
	if (cpufreq_ops != &default_cpufreq_ops)
		is_active = true;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	if (is_active)
		return -EINVAL;
	printk("cpufreq: bpf: %s kops %p", __func__, ops);
	return 0;
}

static int bpf_cpufreq_init(struct btf *btf)
{
	return 0;
}

static int bpf_cpufreq_reg(void *kdata)
{
	struct cpufreq_bpf_ops *ops = kdata;
	printk("cpufreq: bpf: %s: registering %p for %p", ops, cpufreq_ops);

	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	return 0;
}

static void bpf_cpufreq_unreg(void *kdata)
{
	struct cpufreq_bpf_ops *ops = kdata;

	printk("cpufreq: bpf: %s: unregistering %p for %p with default %p", ops, cpufreq_ops, &default_cpufreq_ops);
	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
}


BTF_SET8_START(cpufreq_bpf_ops_kfuncs)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_start, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_stop, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_limits, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_store_setspeed, KF_TRUSTED_ARGS)
BTF_SET8_END(cpufreq_bpf_ops_kfuncs)

BTF_SET8_START(cpufreq_bpf_drv_kfuncs)
BTF_ID_FLAGS(func, bpf_cpufreq_gov_set_cpu)
BTF_ID_FLAGS(func, bpf_cpufreq_gov_set)
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


// Governor implementation

static int cpufreq_bpf_policy_init(struct cpufreq_policy *policy)
{
	cpufreq_enable_fast_switch(policy);

	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	return 0;
}

static void cpufreq_bpf_policy_exit(struct cpufreq_policy *policy)
{
	kfree(policy->governor_data);
	policy->governor_data = NULL;

	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
}

static int cpufreq_bpf_policy_start(struct cpufreq_policy *policy)
{
	int ret;

	BUG_ON(!policy->cur);

	ret = cpufreq_ops->start(policy);

	return ret;
}

static void cpufreq_bpf_policy_stop(struct cpufreq_policy *policy)
{
	cpufreq_ops->stop(policy);

	// Restore default ops
	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
}

static void cpufreq_bpf_policy_limits(struct cpufreq_policy *policy)
{
	cpufreq_ops->limits(policy);

}

static ssize_t cpufreq_bpf_show_setspeed(struct cpufreq_policy *policy, char *buf)
{
	return sprintf(buf, "%u\n", policy->cur);
}

static int cpufreq_bpf_store_setspeed(struct cpufreq_policy *policy, unsigned int freq)
{
	int ret = 0;

	policy->cur = freq;

	ret = cpufreq_ops->store_setspeed(policy, freq);

	return 0;
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

	// kfuncs
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
			&cpufreq_bpf_drv_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
			&cpufreq_bpf_drv_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
			&cpufreq_bpf_drv_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
			&cpufreq_bpf_drv_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
			&cpufreq_bpf_drv_kfunc_set);
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
