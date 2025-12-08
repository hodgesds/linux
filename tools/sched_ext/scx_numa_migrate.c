/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_numa_migrate.bpf.skel.h"

const char help_fmt[] =
"A NUMA-aware sched_ext scheduler with automatic page migration hints.\n"
"\n"
"This scheduler demonstrates the scx_bpf_migrate_task_pages() kfunc by\n"
"detecting when tasks cross NUMA node boundaries and hinting async page\n"
"migration to follow the task.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-i INTERVAL_SEC] [-d] [-v]\n"
"\n"
"  -i INTERVAL_SEC   Minimum interval between page hints per task (default: 1s)\n"
"  -d                Disable page migration hints (for comparison)\n"
"  -v                Print libbpf debug messages\n"
"  -h                Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			    va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static void read_stats(struct scx_numa_migrate *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	assert(nr_cpus > 0);
	__u64 cnts[4][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 4);

	for (idx = 0; idx < 4; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

static void print_banner(void)
{
	printf("%-10s %-10s %-10s %-10s %-10s\n",
	       "TIME", "LOCAL", "GLOBAL", "NUMA_XING", "PAGE_HINTS");
	printf("%-10s %-10s %-10s %-10s %-10s\n",
	       "----", "-----", "------", "---------", "----------");
}

int main(int argc, char **argv)
{
	struct scx_numa_migrate *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;
	int interval_sec = 1;
	int time_sec = 0;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(numa_migrate_ops, scx_numa_migrate);

	while ((opt = getopt(argc, argv, "i:dvh")) != -1) {
		switch (opt) {
		case 'i':
			interval_sec = atoi(optarg);
			if (interval_sec < 0) {
				fprintf(stderr, "Invalid interval: %s\n", optarg);
				return 1;
			}
			skel->rodata->hint_interval_ns = interval_sec * 1000000000ULL;
			break;
		case 'd':
			skel->rodata->enable_migration_hints = false;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, numa_migrate_ops, scx_numa_migrate, uei);
	link = SCX_OPS_ATTACH(skel, numa_migrate_ops, scx_numa_migrate);

	printf("NUMA-aware scheduler started.\n");
	printf("Page migration hints: %s\n",
	       skel->rodata->enable_migration_hints ? "enabled" : "disabled");
	printf("Hint interval: %llu ns (%d seconds)\n",
	       (unsigned long long)skel->rodata->hint_interval_ns, interval_sec);
	printf("\n");
	print_banner();

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[4];

		read_stats(skel, stats);
		printf("%-10d %-10llu %-10llu %-10llu %-10llu\n",
		       time_sec++,
		       stats[0], /* local queue */
		       stats[1], /* global queue */
		       stats[2], /* NUMA crossings */
		       stats[3]  /* page hints */);
		fflush(stdout);
		sleep(1);
	}

	printf("\nScheduler exiting...\n");

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_numa_migrate__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
