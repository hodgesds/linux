// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/drivers/cpufreq/cpufreq_bpf.c
 *
 *  Copyright (C) 2024 Meta Platforms, Inc. and affiliates
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>

struct bpf_cpumask;

struct bpf_policy {
	unsigned int is_managed;
	unsigned int setspeed;
	struct mutex mutex;
};


static int cpufreq_set(struct cpufreq_policy *policy, unsigned int freq)
{
	int ret = -EINVAL;
	struct bpf_policy *bpf = policy->governor_data;

	pr_debug("%s for cpu %u, freq %u kHz\n", __func__, policy->cpu, freq);

	mutex_lock(&bpf->mutex);
	if (!bpf->is_managed)
		goto err;

	bpf->setspeed = freq;

	ret = __cpufreq_driver_target(policy, freq, CPUFREQ_RELATION_H);
 err:
	mutex_unlock(&bpf->mutex);
	return ret;
}

static ssize_t show_speed(struct cpufreq_policy *policy, char *buf)
{
	return sprintf(buf, "%u\n", policy->cur);
}


/*
 * Any routine that writes to the policy struct will hold the "rwsem" of
 * policy struct that means it is free to free "governor_data" here.
 */
static void cpufreq_bpf_policy_exit(struct cpufreq_policy *policy)
{
	kfree(policy->governor_data);
	policy->governor_data = NULL;
}

static int cpufreq_bpf_policy_start(struct cpufreq_policy *policy)
{
	struct bpf_policy *bpf = policy->governor_data;

	BUG_ON(!policy->cur);
	pr_debug("started managing cpu %u\n", policy->cpu);

	mutex_lock(&bpf->mutex);
	bpf->is_managed = 1;
	bpf->setspeed = policy->cur;
	mutex_unlock(&bpf->mutex);

	return 0;
}

static void cpufreq_bpf_policy_stop(struct cpufreq_policy *policy)
{
	struct bpf_policy *bpf = policy->governor_data;

	pr_debug("managing cpu %u stopped\n", policy->cpu);

	mutex_lock(&bpf->mutex);
	bpf->is_managed = 0;
	bpf->setspeed = 0;
	mutex_unlock(&bpf->mutex);
}

static void cpufreq_bpf_policy_limits(struct cpufreq_policy *policy)
{
	struct bpf_policy *bpf = policy->governor_data;

	mutex_lock(&bpf->mutex);
	if (policy->max < bpf->setspeed)
		__cpufreq_driver_target(policy, policy->max,
					CPUFREQ_RELATION_H);
	else if (policy->min < bpf->setspeed)
		__cpufreq_driver_target(policy, bpf->setspeed,
					CPUFREQ_RELATION_C);
	else
		__cpufreq_driver_target(policy, policy->min,
					CPUFREQ_RELATION_L);
	mutex_unlock(&bpf->mutex);
}

static int cpufreq_bpf_policy_init(struct cpufreq_policy *policy)
{
	struct bpf_policy *bpf;

	// enable fast switch by default
	cpufreq_enable_fast_switch(policy);

	bpf = kzalloc(sizeof(*bpf), GFP_KERNEL);
	if (!bpf)
		return -ENOMEM;

	mutex_init(&bpf->mutex);

	policy->governor_data = bpf;
	return 0;
}

static struct cpufreq_governor cpufreq_gov_bpf = {
	.name		= "bpf",
	.init		= cpufreq_bpf_policy_init,
	.exit		= cpufreq_bpf_policy_exit,
	.start		= cpufreq_bpf_policy_start,
	.stop		= cpufreq_bpf_policy_stop,
	.limits		= cpufreq_bpf_policy_limits,
	.store_setspeed	= cpufreq_set,
	.show_setspeed	= show_speed,
	.owner		= THIS_MODULE,
};

static inline struct cpufreq_policy *get_cpu_policy(unsigned int cpu)
{
	if (cpu > nr_cpu_ids)
		return NULL;

	struct cpufreq_policy *policy;

	int ret = cpufreq_get_policy(policy, cpu);

	if (ret)
		return NULL;

	return policy;
}


// BPF kfuncs
__bpf_hook_start()

__bpf_kfunc int bpf_cpufreq_gov_set_cpu(unsigned int freq, unsigned int cpu)
{
	int ret = 0;

	struct cpufreq_policy *policy = cpufreq_cpu_acquire(cpu);

	if (!policy)
		return -EINVAL;

	struct bpf_policy *bpf = policy->governor_data;

	if (!bpf) {
		ret = -EINVAL;
		goto err;
	}

	mutex_lock(&bpf->mutex);
	if (!bpf->is_managed) {
		ret = -EINVAL;
		goto err;
	}

	bpf->setspeed = freq;
	ret = cpufreq_driver_fast_switch(policy, freq);

err:
	cpufreq_cpu_release(policy);
	if (bpf)
		mutex_unlock(&bpf->mutex);
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


BTF_SET8_START(cpufreq_bpf_gov_kfuncs)
BTF_ID_FLAGS(func, bpf_cpufreq_gov_set_cpu)
BTF_ID_FLAGS(func, bpf_cpufreq_gov_set, KF_RCU)
BTF_SET8_END(cpufreq_bpf_gov_kfuncs)

BTF_SET8_START(cpufreq_bpf_drv_kfuncs)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_get_hw_max_freq)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_quick_get)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_quick_get_max)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_enable_fast_switch)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_disable_fast_switch)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_boost_enabled)
BTF_ID_FLAGS(func, bpf_cpufreq_drv_enable_boost_support)
BTF_SET8_END(cpufreq_bpf_drv_kfuncs)


static const struct btf_kfunc_id_set cpufreq_bpf_gov_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &cpufreq_bpf_gov_kfuncs,
};

static const struct btf_kfunc_id_set cpufreq_bpf_drv_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &cpufreq_bpf_drv_kfuncs,
};


static int __init cpufreq_bpf_module_init(void)
{
	int ret;

	// Governor kfuncs
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
			&cpufreq_bpf_gov_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
			&cpufreq_bpf_gov_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
			&cpufreq_bpf_gov_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
			&cpufreq_bpf_gov_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
			&cpufreq_bpf_gov_kfunc_set);

	// Driver kfuncs
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
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

	return cpufreq_register_governor(&cpufreq_gov_bpf);
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
