/* SPDX-License-Identifier: GPL-2.0 */
/* internal file - do not include directly */

#ifdef CONFIG_BPF_JIT
#ifdef CONFIG_NET
BPF_STRUCT_OPS_TYPE(bpf_dummy_ops)
#endif
#ifdef CONFIG_INET
#include <net/tcp.h>
BPF_STRUCT_OPS_TYPE(tcp_congestion_ops)
#endif
#ifdef CONFIG_CPU_FREQ_BPF
#include <linux/cpufreq_bpf.h>
BPF_STRUCT_OPS_TYPE(cpufreq_bpf_ops)
#endif
#endif
