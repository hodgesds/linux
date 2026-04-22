/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common helpers for NUMA page replication selftests.
 */
#ifndef NUMA_REPLICATE_COMMON_H
#define NUMA_REPLICATE_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/mman.h>

#ifndef MADV_NUMA_REPLICATE
#define MADV_NUMA_REPLICATE	26
#endif
#ifndef MADV_NUMA_NOREPLICATE
#define MADV_NUMA_NOREPLICATE	27
#endif

static inline long read_vmstat(const char *name)
{
	FILE *f;
	char key[64];
	long val;

	f = fopen("/proc/vmstat", "r");
	if (!f)
		return -1;
	while (fscanf(f, "%63s %ld", key, &val) == 2) {
		if (strcmp(key, name) == 0) {
			fclose(f);
			return val;
		}
	}
	fclose(f);
	return -1;
}

static inline int count_numa_nodes(void)
{
	char path[128];
	int n;

	for (n = 0; n < 64; n++) {
		snprintf(path, sizeof(path),
			 "/sys/devices/system/node/node%d", n);
		if (access(path, F_OK) != 0)
			break;
	}
	return n;
}

static inline int first_cpu_on_node(int node)
{
	char path[256];
	FILE *f;
	int cpu;

	snprintf(path, sizeof(path),
		 "/sys/devices/system/node/node%d/cpulist", node);
	f = fopen(path, "r");
	if (!f)
		return -1;
	if (fscanf(f, "%d", &cpu) != 1)
		cpu = -1;
	fclose(f);
	return cpu;
}

static inline int pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static inline int write_sysctl(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, val, strlen(val));
	close(fd);
	return n == (ssize_t)strlen(val) ? 0 : -1;
}

#endif /* NUMA_REPLICATE_COMMON_H */
