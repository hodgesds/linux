#ifndef _CPUFREQ_BPF_H
#define _CPUFREQ_BPF_H

#include <linux/cpufreq.h>


struct cpufreq_bpf_ops {
	int	(*start)(struct cpufreq_policy *policy);
	void	(*stop)(struct cpufreq_policy *policy);
	void	(*limits)(struct cpufreq_policy *policy);
	int	(*store_setspeed)(struct cpufreq_policy *policy, unsigned int freq);
};

#endif
