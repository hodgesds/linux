/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Daniel Hodges <hodges.daniel.scott@gmail.com>
 */
#ifdef CONFIG_SLAB_BPF

// kfuncs


#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/mutex.h>

/* "extern" is to avoid sparse warning.  It is only used in bpf_struct_ops.c. */
extern struct bpf_struct_ops bpf_cpufreq_bpf_ops;

static DEFINE_MUTEX(cpufreq_ops_enable_mutex);
static struct cpufreq_bpf_ops *cpufreq_ops;
static struct cpufreq_bpf_ops default_cpufreq_ops;

__bpf_hook_start();


// cpufreq_bpf_ops defaults

__bpf_kfunc static int __bpf_cpufreq_policy_start(struct cpufreq_policy *policy)
{
	return 0;
}

__bpf_hook_end();

// struct_ops implementation


static const struct bpf_func_proto * bpf_cpufreq_get_func_proto(
	enum bpf_func_id func_id, const struct bpf_prog *prog
) {

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
		struct bpf_func_proto * proto;
		proto = bpf_base_func_proto(func_id);
		if (proto)
			return proto;

		return tracing_prog_func_proto(func_id, prog);
	}
}

static bool bpf_cpufreq_is_valid_access(
	int off, int size, enum bpf_access_type type, const struct bpf_prog *prog,
	struct bpf_insn_access_aux *info
) {

	//if (off < 0 || off >= sizeof(struct cpufreq_bpf_ops))
	//	return false


	bpf_log(info->log, "[cpufreq] %s: offset: %d size: %d type: %d prog: %s", __func__, off, size, type, prog->aux->attach_func_name);
	printk("cpufreq: bpf: %s: off: %d size: %d type: %d prog: %s", __func__, off, size, type, prog->aux->attach_func_name);
	bool valid = btf_ctx_access(off, size, type, prog, info);
	printk("cpufreq: bpf: %s: valid: %d", __func__, valid);
	valid = bpf_tracing_btf_ctx_access(off, size, type, prog, info);
	printk("cpufreq: bpf: %s: tracing valid ctx access: %d", __func__, valid);

	return true;

	// return ret;
}

static int bpf_cpufreq_btf_struct_access(
	struct bpf_verifier_log *log, const struct bpf_reg_state *reg, int off, int size
) {
	const struct btf_type *state;
	const struct btf_type *t;
	s32 type_id;

	bpf_log(log, "[cpufreq] %s: offset= %d size= %d sizeof(cpufreq_policy) %ld", __func__, off,
			size, sizeof(struct cpufreq_policy));

	type_id = btf_find_by_name_kind(reg->btf, "cpufreq_policy", BTF_KIND_STRUCT);

	if (type_id < 0) {
		printk("cpufreq: bpf: %s: type_id < 0", __func__);
		// bpf_log(log, "[cpufreq] %s: type_id = %p", __func__, type_id);
		// return -EINVAL;
		return 0;
	}

	t = btf_type_by_id(reg->btf, reg->btf_id);
	state = btf_type_by_id(reg->btf, type_id);

	if (t != state) {
		printk("cpufreq: bpf: %s: t != state", __func__);
		// bpf_log(log, "[cpufreq] %s: type = %p state= %p", __func__, t,
		// 		state);
		return 0;
		// return -EACCES;
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
		// bpf_log(log, "[cpufreq] %s: offset= %d size= %d sizeof(cpufreq_policy) %d", __func__, off,
		// 		size, sizeof(struct cpufreq_policy));
		// return -EACCES;
		return 0;
	}
	// SCALAR_VALUE

	return SCALAR_VALUE;
	// return 0;
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

	int ret = 1;


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
		if (prog->aux->sleepable) {
			printk("cpufreq: bpf: %s: sleepable not allowed", __func__);
			return -EINVAL;
		}
	}

	return 0;
}

static int bpf_cpufreq_update(void *kdata, void *old_kdata)
{
	const struct cpufreq_bpf_ops *old_ops = old_kdata;
	struct cpufreq_bpf_ops *ops = kdata;

	printk("cpufreq: bpf: %s: old_ops: %p new_ops: %p", __func__, old_ops, kdata);
	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = ops;
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
	if (cpufreq_ops != &default_cpufreq_ops)
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

static int bpf_cpufreq_reg(void *kdata)
{
	struct cpufreq_bpf_ops *ops = kdata;
	printk("cpufreq: bpf: %s: registering %p for %p", __func__, ops, (void *)cpufreq_ops);

	mutex_lock(&cpufreq_ops_enable_mutex);
	cpufreq_ops = ops;
	mutex_unlock(&cpufreq_ops_enable_mutex);

	return 0;
}

static void bpf_cpufreq_unreg(void *kdata)
{
	struct cpufreq_bpf_ops *ops = kdata;

	printk("cpufreq: bpf: %s: unregistering %p for %p with default %p", __func__, ops, cpufreq_ops, (void *)&default_cpufreq_ops);
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


static const struct bpf_verifier_ops bpf_cpufreq_verifier_ops = {
	.get_func_proto		= bpf_cpufreq_get_func_proto,
	.is_valid_access	= bpf_cpufreq_is_valid_access,
	// .gen_prolouge           = bpf_cpufreq_gen_prologue,
	// .gen_ld_abs             = bpf_cpufreq_gen_ld_abs,
	// .convert_ctx_access     = bpf_cpufreq_convert_ctx_access,
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


#endif
