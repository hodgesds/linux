// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "cpufreq_bpf.skel.h"

/* Need to keep consistent with definition in include/linux/bpf.h
struct bpf_cpufreq_bpf_ops_state {
	int val;
};
*/
static void test_cpufreq_bpf_st_ops_attach(void)
{
	struct cpufreq_bpf *skel;
	struct bpf_link *link;

	skel = cpufreq_bpf__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cpufreq_bpf_st_ops_load"))
		return;

	link = bpf_map__attach_struct_ops(skel->maps.gov_ops);
	ASSERT_EQ(libbpf_get_error(link), 0, "cpufreq_bpf__ops_attach");

	cpufreq_bpf__destroy(skel);
}

void test_cpufreq_bpf_st_ops(void)
{
	if (test__start_subtest("cpufreq_bpf_st_ops_attach"))
		test_cpufreq_bpf_st_ops_attach();
}
