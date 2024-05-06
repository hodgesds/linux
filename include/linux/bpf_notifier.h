/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/notifier.h>

#define BPF_MAX_NOTIFIERS 16

enum bpf_notifier_flags {
	BPF_NOTIFIER_CPUFREQ,
	BPF_NOTIFIER_CPU_PM,
	BPF_NOTIFIER_KEYBOARD,
	BPF_NOTIFIER_OOM,
	BPF_NOTIFIER_PM,
	BPF_NOTIFIER_REBOOT,
	BPF_NOTIFIER_RESTART,
	BPF_NOTIFIER_MAX,
};


struct bpf_notifier_ops {
	notifier_fn_t notifier_call;
	int priority;
	unsigned long flags;
};


