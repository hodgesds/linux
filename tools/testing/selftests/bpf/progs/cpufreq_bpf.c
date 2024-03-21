#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("struct_ops/start")
int start_gov(struct cpufreq_policy *policy)
{
	bpf_trace_printk("Hello, world!\n", 0);
	return 0;
}

SEC("struct_ops/stop")
void stop_gov(struct cpufreq_policy *policy)
{
}

SEC("struct_ops/limits")
void limits_gov(struct cpufreq_policy *policy)
{
}

SEC("struct_ops/store_setspeed")
int setspeed_gov(struct cpufreq_policy *policy, unsigned int freq)
{
	policy->cur = freq;
	return 0;
}

SEC(".struct_ops")
struct cpufreq_bpf_ops gov_ops = {
	.start = (void *)start_gov,
	.stop = (void *)stop_gov,
	.limits = (void *)limits_gov,
	.store_setspeed = (void *)setspeed_gov,
};

char LICENSE[] SEC("license") = "GPL";
