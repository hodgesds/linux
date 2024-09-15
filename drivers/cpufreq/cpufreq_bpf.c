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

// #include <acpi/cppc_acpi.h>

/* "extern" is to avoid sparse warning.  It is only used in bpf_struct_ops.c. */
extern struct bpf_struct_ops bpf_cpufreq_bpf_ops;

static DEFINE_MUTEX(cpufreq_ops_enable_mutex);
static struct cpufreq_bpf_ops *bpf_cpufreq_ops;
static struct cpufreq_bpf_ops default_cpufreq_ops;

#define CPU_FREQ_GOV_BPF (cpufreq_gov_bpf);

struct bpf_cpumask;


// Helpers
static inline struct cpufreq_policy *get_cpu_policy(unsigned int cpu)
{
	int ret;
	struct cpufreq_policy *policy;

	if (cpu > nr_cpu_ids)
		return NULL;

	if (!(ret = cpufreq_get_policy(policy, cpu)))
		return NULL;

	return policy;
}


__bpf_hook_start();


// cpufreq_bpf_ops defaults
__bpf_kfunc static int __bpf_cpufreq_policy_start(struct cpufreq_policy *policy)
{
	return 0;
}

__bpf_kfunc static void __bpf_cpufreq_policy_stop(struct cpufreq_policy *policy)
{}

__bpf_kfunc static void __bpf_cpufreq_policy_limits(struct cpufreq_policy *policy)
{
	// By default set the frequency as close to the policy.
	__cpufreq_driver_target(policy, policy->cur, CPUFREQ_RELATION_C);
}

__bpf_kfunc static int __bpf_cpufreq_policy_store_setspeed(
	struct cpufreq_policy *policy,
	unsigned int freq)
{
	int ret = 0;

	if (!policy)
		return ret;

	policy->cur = freq;
	if (cpufreq_this_cpu_can_update(policy))
		ret = __cpufreq_driver_target(policy, policy->cur,
					      CPUFREQ_RELATION_C);

	return ret;
}

// kfunc helpers
__bpf_kfunc int bpf_cpufreq_gov_set_cpu(unsigned int freq, unsigned int cpu)
{
	int ret = 0;
	struct cpufreq_policy *policy = cpufreq_cpu_acquire(cpu);

	if (!policy)
		return -EINVAL;

	policy->cur = freq;

	if (policy->fast_switch_enabled && policy->fast_switch_possible &&
	    cpufreq_this_cpu_can_update(policy))
		ret = cpufreq_driver_fast_switch(policy, freq);

	cpufreq_cpu_release(policy);

	return ret;
}

__bpf_kfunc int bpf_cpufreq_gov_set(struct bpf_cpumask *mask, unsigned int freq)
{
	int cpu = 0;
	int ret = 0;

	for (cpu = cpumask_next(cpu, (struct cpumask *)mask);
	     cpu < nr_cpu_ids;
	     cpu = cpumask_next(cpu, (struct cpumask *)mask)) {
		if ((ret = bpf_cpufreq_gov_set_cpu(freq, cpu)))
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

	if (policy)
		cpufreq_enable_fast_switch(policy);
}

__bpf_kfunc void bpf_cpufreq_drv_disable_fast_switch(unsigned int cpu)
{
	struct cpufreq_policy *policy = get_cpu_policy(cpu);

	if (policy)
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

// ACPI CPPC kfuncs
// int bpf_cppc_get_desired_perf(int cpunum, u64 *desired_perf) {
// 	return cppc_get_desired_perf(cpunum, desired_perf);
// }
// 
// int bpf_cppc_get_nominal_perf(int cpunum, u64 *nominal_perf) {
// 	return cppc_get_nominal_perf(cpunum, nominal_perf);
// }
// 
// int bpf_cppc_get_perf_ctrs(int cpu, struct cppc_perf_fb_ctrs *perf_fb_ctrs) {
// 	return cppc_get_perf_ctrs(cpu, perf_fb_ctrs);
// 
// }
// int bpf_cppc_set_perf(int cpu, struct cppc_perf_ctrls *perf_ctrls) {
// 	return cppc_set_perf(cpu, perf_ctrls);
// 
// }
// int bpf_cppc_set_enable(int cpu, bool enable) {
// 	return cppc_set_enable(cpu, enable);
// 
// }
// int bpf_cppc_get_perf_caps(int cpu, struct cppc_perf_caps *caps) {
// 	return cppc_get_perf_caps(cpu, caps);
// }
// 
// bool bpf_cppc_perf_ctrs_in_pcc(void) {
// 	return cppc_perf_ctrs_in_pcc();
// }

// unsigned int bpf_cppc_perf_to_khz(struct cppc_perf_caps *caps, unsigned int
// 		perf) {
// 	return cppc_perf_to_khz(caps, perf);
// }
//
// unsigned int bpf_cppc_khz_to_perf(struct cppc_perf_caps *caps, unsigned int
// 		freq) {
// 	return cppc_khz_to_perf(caps, freq);
// }

// bool bpf_acpi_cpc_valid(void) {
// 	return acpi_cpc_valid();
// }
// 
// bool bpf_cppc_allow_fast_switch(void) {
// 	return cppc_allow_fast_switch();
// }

// int bpf_acpi_get_psd_map(unsigned int cpu, struct cppc_cpudata *cpu_data) {
// 	return acpi_get_psd_map(cpu, cpu_data);
// }

// unsigned int bpf_cppc_get_transition_latency(int cpu) {
// 	return cppc_get_transition_latency(cpu);
// }
// 
// bool bpf_cpc_ffh_supported(void) {
// 	return cpc_ffh_supported();
// }

// bool bpf_cpc_supported_by_cpu(void) {
// 	return cpc_supported_by_cpu();
// }

// int bpf_cpc_read_ffh(int cpunum, struct cpc_reg *reg, u64 *val) {
// 	return cpc_read_ffh(cpunum, reg, val);
// }
// 
// int bpf_cpc_write_ffh(int cpunum, struct cpc_reg *reg, u64 val) {
// 	return cpc_write_ffh(cpunum, reg, val);
// }
// 
// int bpf_cppc_get_epp_perf(int cpunum, u64 *epp_perf) {
// 	return cppc_get_epp_perf(cpunum, epp_perf);
// }
// 
// int bpf_cppc_set_epp_perf(int cpu, struct cppc_perf_ctrls *perf_ctrls, bool
// 		enable) {
// 	return cppc_set_epp_perf(cpu, perf_ctrls, enable);
// }
// 
// int bpf_cppc_get_auto_sel_caps(int cpunum, struct cppc_perf_caps *perf_caps) {
// 	return cppc_get_auto_sel_caps(cpunum, perf_caps);
// }
// 
// int bpf_cppc_set_auto_sel(int cpu, bool enable) {
// 	return cppc_set_auto_sel(cpu, enable);
// }

__bpf_hook_end();


// struct_ops implementation


static const struct bpf_func_proto * bpf_cpufreq_get_func_proto(
	enum bpf_func_id func_id,
	const struct bpf_prog *prog)
{

	switch (func_id) {
	case BPF_FUNC_task_storage_get:
		return &bpf_task_storage_get_proto;
	case BPF_FUNC_task_storage_delete:
		return &bpf_task_storage_delete_proto;
	case BPF_FUNC_trace_vprintk:
		return bpf_get_trace_vprintk_proto();
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static bool bpf_cpufreq_is_valid_access(
	int off, int size,
	enum bpf_access_type type,
	const struct bpf_prog *prog,
	struct bpf_insn_access_aux *info)
{
	bpf_log(info->log, "[cpufreq] %s: offset: %d size: %d type: %d prog: %s", __func__, off, size, type, prog->aux->attach_func_name);
	printk("cpufreq: bpf: %s: off: %d size: %d type: %d prog: %s", __func__, off, size, type, prog->aux->attach_func_name);
	if (type != BPF_READ)
		return false;

	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;

	if (off % size != 0) {
		bpf_log(info->log, "[cpufreq] %s: offset: %d mod size", __func__, off);
		printk("cpufreq: bpf: %s: off: %d mod size", __func__, off);
		return false;
	}

	return btf_ctx_access(off, size, type, prog, info);

//	printk("cpufreq: bpf: %s: valid: %d", __func__, valid);
//	valid = bpf_tracing_btf_ctx_access(off, size, type, prog, info);
//	printk("cpufreq: bpf: %s: tracing valid ctx access: %d", __func__, valid);
//
//	return true;
//
	// return ret;
}

static int bpf_cpufreq_btf_struct_access(
	struct bpf_verifier_log *log,
	const struct bpf_reg_state *reg,
	int off,
	int size)
{
	const struct btf_type *state;
	const struct btf_type *t;
	s32 type_id;

	printk("cpufreq: bpf: %s: off: %d size: %d", __func__, off, size);
	bpf_log(log, "[cpufreq] %s: offset= %d size= %d sizeof(cpufreq_policy) %ld", __func__, off,
			size, sizeof(struct cpufreq_policy));

	type_id = btf_find_by_name_kind(reg->btf, "cpufreq_policy", BTF_KIND_STRUCT);
	// Check struct cpufreq_policy
	// return SCALAR_VALUE

	if (type_id < 0) {
		printk("cpufreq: bpf: %s: type_id < 0", __func__);
		bpf_log(log, "[cpufreq] %s: type_id < 0", __func__);
		return -EINVAL;
		// return 0;
	}

	t = btf_type_by_id(reg->btf, reg->btf_id);
	state = btf_type_by_id(reg->btf, type_id);

	if (t != state) {
		printk("cpufreq: bpf: %s: t != state", __func__);
		bpf_log(log, "[cpufreq] %s: t != state", __func__);
		// return 0;
		return -EACCES;
	}

	// [100275] STRUCT 'cpufreq_bpf_ops' size=32 vlen=4
        // 'start' type_id=3348 bits_offset=0
        // 'stop' type_id=3352 bits_offset=64
        // 'limits' type_id=3352 bits_offset=128
        // 'store_setspeed' type_id=3350 bits_offset=192

	// See
	// https://github.com/sched-ext/sched_ext/blob/047f5c2a9ee6e34f2b37bd86853a31e2ae2c300a/kernel/sched/ext.c#L3997

	if (off + size == sizeof(unsigned int) + sizeof(struct cpufreq_policy)) {
		printk("SCALAR");
		return SCALAR_VALUE;
	}

	if (off + size > sizeof(struct cpufreq_policy)) {
		printk("cpufreq: bpf: %s: off+size > sizeof cpufreq_policy", __func__);
		bpf_log(log, "[cpufreq] %s: offset= %d size= %d sizeof(cpufreq_policy) %ld", __func__, off,
				size, sizeof(struct cpufreq_policy));
		return -EACCES;
		// return 0;
	}
	// SCALAR_VALUE

	// return SCALAR_VALUE;
	// return 0;
	// return RET_PTR_TO_MEM_OR_BTF_ID;
	return RET_PTR_TO_BTF_ID_TRUSTED;
}

static int bpf_cpufreq_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct cpufreq_bpf_ops *uops = udata;
	struct cpufreq_bpf_ops *ops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;
	int ret;

	printk("cpufreq: %s: uops: %p ops: %p", __func__, uops, ops);

	switch (moff) {
	case offsetof(struct cpufreq_bpf_ops, name):
		ret = bpf_obj_name_cpy(ops->name, uops->name,
				       sizeof(uops->name));
		if (ret < 0)
			return ret;
		if (ret == 0)
			return -EINVAL;
		return 1;
	// case offsetof(struct cpufreq_bpf_ops, start):
	// case offsetof(struct cpufreq_bpf_ops, start):
	// 	if (*(u64 *)(udata+moff)) {
	// 		printk("cpufreq: bpf: %s: start valid", __func__);
	// 	} else {
	// 		printk("cpufreq: bpf: %s: start invalid", __func__);
	// 	}
	// 	return 1;
	// case offsetof(struct cpufreq_bpf_ops, stop):
	// 	printk("cpufreq: bpf: init stop");
	// 	return 1;
	// case offsetof(struct cpufreq_bpf_ops, limits):
	// 	printk("cpufreq: bpf: init limits");
	// 	return 1;
	// case offsetof(struct cpufreq_bpf_ops, store_setspeed):
	// 	printk("cpufreq: bpf: init store_setspeed");
	// 	if (*(u64 *)(udata+moff) + sizeof(void*)) {
	// 		printk("cpufreq: bpf: %s: store_setspeed valid", __func__);
	// 	} else {
	// 		printk("cpufreq: bpf: %s: store_setspeed invalid", __func__);
	// 	}
	// 	return 1;
	}

	return 0;
}

static int bpf_cpufreq_check_member(const struct btf_type *t,
				    const struct btf_member *member,
				    const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct cpufreq_bpf_ops, start):
		printk("cpufreq: bpf: %s check start moff %u", __func__, moff);
		break;
	case offsetof(struct cpufreq_bpf_ops, stop):
		printk("cpufreq: bpf: %s check stop moff %u", __func__, moff);
		break;
	case offsetof(struct cpufreq_bpf_ops, limits):
		printk("cpufreq: bpf: %s check limits moff %u", __func__, moff);
		break;
	case offsetof(struct cpufreq_bpf_ops, store_setspeed):
		printk("cpufreq: bpf: %s check store_setspeed moff %u", __func__, moff);

		break;
	default:
		if (prog->sleepable) {
			printk("cpufreq: bpf: %s: sleepable not allowed", __func__);
			return -EINVAL;
		}
	}

	return 0;
}

static int bpf_cpufreq_update(void *kdata, void *old_kdata,
			      struct bpf_link * link)
{
	const struct cpufreq_bpf_ops *old_ops = old_kdata;
	struct cpufreq_bpf_ops *ops = kdata;

	printk("cpufreq: bpf: %s: old_ops: %p new_ops: %p", __func__, old_ops, kdata);
	mutex_lock(&cpufreq_ops_enable_mutex);
	bpf_cpufreq_ops = ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	return 0;
}

static int bpf_cpufreq_validate(void *kdata)
{
	printk("cpufreq: bpf: %s kdata %p", __func__, kdata);
	struct cpufreq_bpf_ops *ops = kdata;

	if (!ops)
		return -EINVAL;

	// Check if an existing struct_ops implementation is active.
	bool is_active = false;

	mutex_lock(&cpufreq_ops_enable_mutex);
	if (bpf_cpufreq_ops != &default_cpufreq_ops)
		is_active = true;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	if (is_active)
		return -EINVAL;
	return 0;
}

static int bpf_cpufreq_init(struct btf *btf)
{
	return 0;
}

static int bpf_cpufreq_reg(void *kdata, struct bpf_link *link)
{
	struct cpufreq_bpf_ops *ops = kdata;
	printk("cpufreq: bpf: %s: registering %p for %p", __func__, ops, (void *)bpf_cpufreq_ops);

	mutex_lock(&cpufreq_ops_enable_mutex);
	bpf_cpufreq_ops = ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	return 0;
}

static void bpf_cpufreq_unreg(void *kdata, struct bpf_link *link)
{
	struct cpufreq_bpf_ops *ops = kdata;

	printk("cpufreq: bpf: %s: unregistering %p for %p with default %p", __func__, ops, bpf_cpufreq_ops, (void *)&default_cpufreq_ops);
	mutex_lock(&cpufreq_ops_enable_mutex);
	bpf_cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
}


BTF_KFUNCS_START(cpufreq_bpf_ops_kfuncs)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_start, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_stop, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_limits, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, __bpf_cpufreq_policy_store_setspeed, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(cpufreq_bpf_ops_kfuncs)

BTF_KFUNCS_START(cpufreq_bpf_drv_kfuncs)
BTF_ID_FLAGS(func, bpf_cpufreq_gov_set_cpu)
BTF_ID_FLAGS(func, bpf_cpufreq_gov_set)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_get_hw_max_freq)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_quick_get)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_quick_get_max)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_enable_fast_switch)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_disable_fast_switch)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_boost_enabled)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_enable_boost_support)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_boost_trigger_state)
BTF_KFUNCS_END(cpufreq_bpf_drv_kfuncs)

// BTF_KFUNCS_START(cpufreq_bpf_cppc_kfuncs)
// BTF_ID_FLAGS(func, bpf_cppc_get_desired_perf)
// BTF_ID_FLAGS(func, bpf_cppc_get_nominal_perf)
// BTF_ID_FLAGS(func, bpf_cppc_get_perf_ctrs)
// BTF_ID_FLAGS(func, bpf_cppc_set_perf)
// BTF_ID_FLAGS(func, bpf_cppc_set_enable)
// BTF_ID_FLAGS(func, bpf_cppc_get_perf_caps)
// BTF_ID_FLAGS(func, bpf_cppc_perf_ctrs_in_pcc)
// // BTF_ID_FLAGS(func, bpf_cppc_perf_to_khz)
// // BTF_ID_FLAGS(func, bpf_cppc_khz_to_perf)
// BTF_ID_FLAGS(func, bpf_acpi_cpc_valid)
// BTF_ID_FLAGS(func, bpf_cppc_allow_fast_switch)
// // BTF_ID_FLAGS(func, bpf_acpi_get_psd_map)
// BTF_ID_FLAGS(func, bpf_cppc_get_transition_latency)
// BTF_ID_FLAGS(func, bpf_cpc_ffh_supported)
// // BTF_ID_FLAGS(func, bpf_cpc_supported_by_cpu)
// BTF_ID_FLAGS(func, bpf_cpc_read_ffh)
// BTF_ID_FLAGS(func, bpf_cpc_write_ffh)
// BTF_ID_FLAGS(func, bpf_cppc_get_epp_perf)
// BTF_ID_FLAGS(func, bpf_cppc_set_epp_perf)
// BTF_ID_FLAGS(func, bpf_cppc_get_auto_sel_caps)
// BTF_ID_FLAGS(func, bpf_cppc_set_auto_sel)
// BTF_KFUNCS_END(cpufreq_bpf_cppc_kfuncs)


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
	.name		= "default",
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
	.owner = THIS_MODULE,
	.cfi_stubs = &default_cpufreq_ops,
};


static const struct btf_kfunc_id_set cpufreq_bpf_ops_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &cpufreq_bpf_ops_kfuncs,
};


static const struct btf_kfunc_id_set cpufreq_bpf_drv_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &cpufreq_bpf_drv_kfuncs,
};

// static const struct btf_kfunc_id_set cpufreq_bpf_cppc_kfunc_set = {
// 	.owner = THIS_MODULE,
// 	.set   = &cpufreq_bpf_cppc_kfuncs,
// };


// Governor implementation

static int cpufreq_bpf_policy_init(struct cpufreq_policy *policy)
{
	cpufreq_enable_fast_switch(policy);

	mutex_lock(&cpufreq_ops_enable_mutex);
	bpf_cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
	pr_info("cpufreq_bpf: initializing govenor %s", bpf_cpufreq_ops->name);

	return 0;
}

static void cpufreq_bpf_policy_exit(struct cpufreq_policy *policy)
{
	kfree(policy->governor_data);
	policy->governor_data = NULL;

	pr_info("cpufreq_bpf: stopping govenor %s", bpf_cpufreq_ops->name);

	mutex_lock(&cpufreq_ops_enable_mutex);
	bpf_cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
}

static int cpufreq_bpf_policy_start(struct cpufreq_policy *policy)
{
	int ret;

	BUG_ON(!policy->cur);

	pr_info("cpufreq_bpf: starting policy for govenor %s",
		bpf_cpufreq_ops->name);

	ret = bpf_cpufreq_ops->start(policy);

	return ret;
}

static void cpufreq_bpf_policy_stop(struct cpufreq_policy *policy)
{
	bpf_cpufreq_ops->stop(policy);

	pr_info("cpufreq_bpf: stopping policy for govenor %s",
		bpf_cpufreq_ops->name);

	// Restore default ops
	mutex_lock(&cpufreq_ops_enable_mutex);
	bpf_cpufreq_ops = &default_cpufreq_ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);
}

static void cpufreq_bpf_policy_limits(struct cpufreq_policy *policy)
{
	bpf_cpufreq_ops->limits(policy);

}

static ssize_t cpufreq_bpf_show_setspeed(struct cpufreq_policy *policy,
					 char *buf)
{
	return sprintf(buf, "%u\n", policy->cur);
}

static int cpufreq_bpf_store_setspeed(struct cpufreq_policy *policy,
				      unsigned int freq)
{
	int ret = 0;

	policy->cur = freq;

	ret = bpf_cpufreq_ops->store_setspeed(policy, freq);

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
	printk("cpufreq: bpf: %s: registering struct_ops", __func__);
	ret = register_bpf_struct_ops(&bpf_cpufreq_bpf_ops, cpufreq_bpf_ops);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					       &cpufreq_bpf_ops_kfunc_set);

	// kfuncs
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
			&cpufreq_bpf_drv_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
			&cpufreq_bpf_drv_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
			&cpufreq_bpf_drv_kfunc_set);

	// cppc kfuncs
	// ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
	// 		&cpufreq_bpf_cppc_kfunc_set);
	if (ret) {
		printk("cpufreq: bpf: %s: registering struct_ops %d", __func__, ret);
		return -EINVAL;
	}

	return ret;
}

static int __init cpufreq_bpf_module_init(void)
{
	int ret;

	printk("cpufreq: bpf: %s: registering governor", __func__);
	ret = cpufreq_register_governor(&cpufreq_gov_bpf);
	printk("cpufreq: bpf: %s: ret %d", __func__, ret);
	if (ret)
		return -EINVAL;

	return init_bpf();
}

static void __exit cpufreq_bpf_module_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_bpf);
}

module_init(cpufreq_bpf_module_init);
module_exit(cpufreq_bpf_module_exit);

MODULE_AUTHOR("Daniel Hodges");
MODULE_DESCRIPTION("cpufreq policy governor 'bpf'");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_BPF
struct cpufreq_governor *cpufreq_default_governor(void)
{
	return &CPU_FREQ_GOV_BPF;
}
#endif

