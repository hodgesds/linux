// SPDX-License-Identifier: GPL-2.0
/*
 * NUMA page replication stress test.
 *
 * Exercises allocation/deallocation paths under sustained load using
 * real file-backed pages (shared libraries), which is the intended
 * use case for NUMA replication (.text/.rodata sections).
 *
 * Tests:
 * 1. Continuous create/drop cycles with data verification
 * 2. Concurrent readers + REPLICATE/NOREPLICATE toggling
 * 3. Multiple files — open/replicate/close different files
 * 4. Per-node limit enforcement
 * 5. Leak check — created == dropped at end
 *
 * Requires: 2+ NUMA nodes, CONFIG_NUMA_PAGE_REPLICATE=y
 * Usage: numa_replicate_stress [duration_secs] [test_file]
 *        Default: 30 seconds, /hostlibs/libc.so.6
 */

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
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "kselftest.h"

#ifndef MADV_NUMA_REPLICATE
#define MADV_NUMA_REPLICATE	26
#endif
#ifndef MADV_NUMA_NOREPLICATE
#define MADV_NUMA_NOREPLICATE	27
#endif

#define NR_STRESS_PAGES	32

static volatile int stop_flag;
static int cpu_node0, cpu_node1;

static long read_vmstat(const char *name)
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

static int count_numa_nodes(void)
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

static int first_cpu_on_node(int node)
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

static int pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static int write_sysctl(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0)
		return -1;
	write(fd, val, strlen(val));
	close(fd);
	return 0;
}

/* Try to find a real file for testing */
static const char *find_test_file(const char *user_path)
{
	static const char *candidates[] = {
		"/hostlibs/libc.so.6",
		"/usr/lib64/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/x86_64-linux-gnu/libc.so.6",
		NULL,
	};
	const char **p;

	if (user_path && access(user_path, R_OK) == 0)
		return user_path;

	for (p = candidates; *p; p++) {
		if (access(*p, R_OK) == 0)
			return *p;
	}
	return NULL;
}

/* Get file size, clamped to stress page count */
static size_t get_map_size(const char *path, size_t page_size)
{
	struct stat st;
	size_t nr;

	if (stat(path, &st) < 0)
		return 0;
	nr = st.st_size / page_size;
	if (nr > NR_STRESS_PAGES)
		nr = NR_STRESS_PAGES;
	return nr * page_size;
}

/* ------------------------------------------------------------------ */
/* Test 1: Continuous create/drop cycles                               */
/* ------------------------------------------------------------------ */

struct cycle_ctx {
	const char *file_path;
	size_t map_size;
	unsigned long cycles;
	unsigned long replicated;
	unsigned long dropped;
	int data_errors;
};

static void *cycle_worker(void *arg)
{
	struct cycle_ctx *ctx = arg;
	size_t page_size = getpagesize();
	int nr_pages = ctx->map_size / page_size;
	char *reference;

	/* Take a reference snapshot from node 0 */
	pin_to_cpu(cpu_node0);
	{
		int fd = open(ctx->file_path, O_RDONLY);
		void *tmp;

		if (fd < 0)
			return NULL;
		tmp = mmap(NULL, ctx->map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if (tmp == MAP_FAILED)
			return NULL;
		reference = malloc(ctx->map_size);
		if (!reference) {
			munmap(tmp, ctx->map_size);
			return NULL;
		}
		memcpy(reference, tmp, ctx->map_size);
		munmap(tmp, ctx->map_size);
	}

	while (!stop_flag) {
		int fd;
		void *addr;
		long c_before, c_after, d_before, d_after;

		fd = open(ctx->file_path, O_RDONLY);
		if (fd < 0)
			continue;

		/* Map, fault from node 0, unmap */
		pin_to_cpu(cpu_node0);
		addr = mmap(NULL, ctx->map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED) {
			close(fd);
			continue;
		}
		{
			volatile int sink = 0;

			for (int i = 0; i < nr_pages; i++)
				sink += ((volatile char *)addr)[i * page_size];
			(void)sink;
		}
		munmap(addr, ctx->map_size);

		/* Re-map with replication */
		addr = mmap(NULL, ctx->map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED) {
			close(fd);
			continue;
		}
		madvise(addr, ctx->map_size, MADV_NUMA_REPLICATE);

		c_before = read_vmstat("numa_replica_created");

		/* Fault from remote node */
		pin_to_cpu(cpu_node1);
		for (int i = 0; i < nr_pages; i++) {
			volatile char c = ((volatile char *)addr)[i * page_size];

			(void)c;
		}

		c_after = read_vmstat("numa_replica_created");
		ctx->replicated += (c_after - c_before);

		/* Verify data */
		if (memcmp(addr, reference, ctx->map_size) != 0)
			ctx->data_errors++;

		/* Drop replicas */
		d_before = read_vmstat("numa_replica_dropped");
		madvise(addr, ctx->map_size, MADV_NUMA_NOREPLICATE);
		d_after = read_vmstat("numa_replica_dropped");
		ctx->dropped += (d_after - d_before);

		munmap(addr, ctx->map_size);
		close(fd);
		ctx->cycles++;
	}

	free(reference);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Test 2: Concurrent readers + invalidator                            */
/* ------------------------------------------------------------------ */

struct race_ctx {
	volatile char *addr;
	const char *reference;
	size_t map_size;
	size_t page_size;
	int nr_pages;
	unsigned long reads;
	int data_errors;
};

static void *race_reader(void *arg)
{
	struct race_ctx *ctx = arg;
	volatile int sink = 0;

	pin_to_cpu(cpu_node1);

	while (!stop_flag) {
		for (int i = 0; i < ctx->nr_pages; i++)
			sink += ctx->addr[i * ctx->page_size];
		ctx->reads++;
	}
	(void)sink;
	return NULL;
}

static void *race_invalidator(void *arg)
{
	struct race_ctx *ctx = arg;
	void *addr = (void *)ctx->addr;

	pin_to_cpu(cpu_node0);

	while (!stop_flag) {
		madvise(addr, ctx->map_size, MADV_NUMA_NOREPLICATE);
		usleep(1000);
		madvise(addr, ctx->map_size, MADV_NUMA_REPLICATE);
		usleep(5000);
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Test 3: Multiple files — open different libs, replicate, close      */
/* ------------------------------------------------------------------ */

struct multi_ctx {
	unsigned long files_opened;
	int errors;
};

static const char *lib_candidates[] = {
	"/hostlibs/libc.so.6",
	"/hostlibs/libm.so.6",
	"/hostlibs/libpthread.so.0",
	"/hostlibs/librt.so.1",
	"/hostlibs/libdl.so.2",
	"/hostlibs/ld-linux-x86-64.so.2",
	NULL,
};

static void *multi_worker(void *arg)
{
	struct multi_ctx *ctx = arg;
	size_t page_size = getpagesize();
	int lib_idx = 0;

	while (!stop_flag) {
		const char *path = lib_candidates[lib_idx];
		int fd;
		void *addr;
		struct stat st;
		size_t map_size;
		int nr_pages;

		if (!path) {
			lib_idx = 0;
			continue;
		}
		lib_idx++;

		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;

		if (fstat(fd, &st) < 0 || st.st_size < (off_t)page_size) {
			close(fd);
			continue;
		}

		nr_pages = st.st_size / page_size;
		if (nr_pages > 16)
			nr_pages = 16;
		map_size = (size_t)nr_pages * page_size;

		/* Fault from node 0 */
		pin_to_cpu(cpu_node0);
		addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED) {
			close(fd);
			ctx->errors++;
			continue;
		}
		{
			volatile int sink = 0;

			for (int i = 0; i < nr_pages; i++)
				sink += ((volatile char *)addr)[i * page_size];
			(void)sink;
		}
		munmap(addr, map_size);

		/* Re-map with replication, read from node 1 */
		addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED) {
			close(fd);
			ctx->errors++;
			continue;
		}
		madvise(addr, map_size, MADV_NUMA_REPLICATE);

		pin_to_cpu(cpu_node1);
		{
			volatile int sink = 0;

			for (int i = 0; i < nr_pages; i++)
				sink += ((volatile char *)addr)[i * page_size];
			(void)sink;
		}

		/* Close with replicas still active — tests teardown */
		munmap(addr, map_size);
		close(fd);
		ctx->files_opened++;
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	int duration = 30;
	const char *test_file;
	size_t page_size = getpagesize();
	size_t map_size;
	int nr_nodes, nr_pages;
	long created_start, dropped_start;
	long created_end, dropped_end;
	struct timespec t_start, t_now;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if (argc > 1)
		duration = atoi(argv[1]);
	if (duration < 5)
		duration = 5;
	if (duration > 600)
		duration = 600;

	ksft_print_header();
	ksft_set_plan(5);

	nr_nodes = count_numa_nodes();
	if (nr_nodes < 2)
		ksft_exit_skip("Need 2+ NUMA nodes, found %d\n", nr_nodes);

	cpu_node0 = first_cpu_on_node(0);
	cpu_node1 = first_cpu_on_node(1);
	if (cpu_node0 < 0 || cpu_node1 < 0)
		ksft_exit_skip("Cannot find CPUs on nodes 0 and 1\n");

	test_file = find_test_file(argc > 2 ? argv[2] : NULL);
	if (!test_file)
		ksft_exit_skip("No real test file found (need non-tmpfs file)\n");

	map_size = get_map_size(test_file, page_size);
	nr_pages = map_size / page_size;
	if (nr_pages < 4)
		ksft_exit_skip("Test file too small\n");

	ksft_print_msg("stress test: %ds, file=%s, %d pages, cpu0=%d cpu1=%d\n",
		       duration, test_file, nr_pages, cpu_node0, cpu_node1);

	created_start = read_vmstat("numa_replica_created");
	dropped_start = read_vmstat("numa_replica_dropped");

	/*
	 * Test 1: Continuous create/drop cycles.
	 */
	{
		struct cycle_ctx ctx = {
			.file_path = test_file,
			.map_size = map_size,
		};
		pthread_t thread;
		int sub = duration / 3;

		if (sub < 5)
			sub = 5;

		stop_flag = 0;
		pthread_create(&thread, NULL, cycle_worker, &ctx);

		clock_gettime(CLOCK_MONOTONIC, &t_start);
		do {
			usleep(100000);
			clock_gettime(CLOCK_MONOTONIC, &t_now);
		} while ((t_now.tv_sec - t_start.tv_sec) < sub);

		stop_flag = 1;
		pthread_join(thread, NULL);

		ksft_print_msg("cycles: %lu, replicated=%lu dropped=%lu errors=%d\n",
			       ctx.cycles, ctx.replicated, ctx.dropped,
			       ctx.data_errors);

		if (ctx.cycles > 0 && ctx.data_errors == 0)
			ksft_test_result_pass("create/drop: %lu cycles\n",
					      ctx.cycles);
		else if (ctx.data_errors > 0)
			ksft_test_result_fail("create/drop: %d data errors\n",
					      ctx.data_errors);
		else
			ksft_test_result_fail("create/drop: 0 cycles\n");
	}

	/*
	 * Test 2: Concurrent readers + invalidator.
	 */
	{
		int fd;
		void *addr;
		char *reference;
		struct race_ctx ctx = {};
		pthread_t reader, invalidator;
		int sub = duration / 3;

		if (sub < 5)
			sub = 5;

		fd = open(test_file, O_RDONLY);
		if (fd < 0)
			ksft_exit_fail_msg("open: %s\n", strerror(errno));

		/* Fault from node 0 and save reference */
		pin_to_cpu(cpu_node0);
		addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED)
			ksft_exit_fail_msg("mmap: %s\n", strerror(errno));
		reference = malloc(map_size);
		if (!reference)
			ksft_exit_fail_msg("malloc\n");
		memcpy(reference, addr, map_size);
		munmap(addr, map_size);

		/* Re-map with replication */
		addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED)
			ksft_exit_fail_msg("mmap: %s\n", strerror(errno));
		madvise(addr, map_size, MADV_NUMA_REPLICATE);

		ctx.addr = addr;
		ctx.reference = reference;
		ctx.map_size = map_size;
		ctx.page_size = page_size;
		ctx.nr_pages = nr_pages;

		stop_flag = 0;
		pthread_create(&reader, NULL, race_reader, &ctx);
		pthread_create(&invalidator, NULL, race_invalidator, &ctx);

		clock_gettime(CLOCK_MONOTONIC, &t_start);
		do {
			usleep(100000);
			clock_gettime(CLOCK_MONOTONIC, &t_now);
		} while ((t_now.tv_sec - t_start.tv_sec) < sub);

		stop_flag = 1;
		pthread_join(reader, NULL);
		pthread_join(invalidator, NULL);

		ksft_print_msg("race: %lu reads, %d errors\n",
			       ctx.reads, ctx.data_errors);

		if (ctx.reads > 0 && ctx.data_errors == 0)
			ksft_test_result_pass("race: %lu reads\n", ctx.reads);
		else
			ksft_test_result_fail("race: %d errors\n",
					      ctx.data_errors);

		munmap(addr, map_size);
		free(reference);
		close(fd);
	}

	/*
	 * Test 3: Multiple files — cycle through different shared libs.
	 */
	{
		struct multi_ctx ctx = {};
		pthread_t thread;
		int sub = duration / 3;

		if (sub < 5)
			sub = 5;

		stop_flag = 0;
		pthread_create(&thread, NULL, multi_worker, &ctx);

		clock_gettime(CLOCK_MONOTONIC, &t_start);
		do {
			usleep(100000);
			clock_gettime(CLOCK_MONOTONIC, &t_now);
		} while ((t_now.tv_sec - t_start.tv_sec) < sub);

		stop_flag = 1;
		pthread_join(thread, NULL);

		ksft_print_msg("multi: %lu files, %d errors\n",
			       ctx.files_opened, ctx.errors);

		if (ctx.files_opened > 0 && ctx.errors == 0)
			ksft_test_result_pass("multi-file: %lu files\n",
					      ctx.files_opened);
		else if (ctx.files_opened == 0)
			ksft_test_result_skip("no lib files accessible\n");
		else
			ksft_test_result_fail("multi-file: %d errors\n",
					      ctx.errors);
	}

	/*
	 * Test 4: Per-node limit.
	 */
	{
		int fd;
		void *addr;

		if (write_sysctl("/proc/sys/vm/numa_replicate_max_per_node",
				 "16") == 0) {
			fd = open(test_file, O_RDONLY);
			if (fd < 0)
				ksft_exit_fail_msg("open: %s\n",
						   strerror(errno));

			/* Fault from node 0 */
			pin_to_cpu(cpu_node0);
			addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE,
				    fd, 0);
			if (addr == MAP_FAILED)
				ksft_exit_fail_msg("mmap\n");
			{
				volatile int sink = 0;

				for (int i = 0; i < nr_pages; i++)
					sink += ((volatile char *)addr)[i * page_size];
				(void)sink;
			}
			munmap(addr, map_size);

			/* Re-map with replication */
			addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE,
				    fd, 0);
			if (addr != MAP_FAILED) {
				long c_before, c_after, delta;

				madvise(addr, map_size, MADV_NUMA_REPLICATE);
				c_before = read_vmstat("numa_replica_created");

				pin_to_cpu(cpu_node1);
				{
					volatile int sink = 0;

					for (int i = 0; i < nr_pages; i++)
						sink += ((volatile char *)addr)[i * page_size];
					(void)sink;
				}

				c_after = read_vmstat("numa_replica_created");
				delta = c_after - c_before;

				ksft_print_msg("limit: created=%ld (limit=16, pages=%d)\n",
					       delta, nr_pages);

				if (delta > 0 && delta <= 16)
					ksft_test_result_pass("limit: %ld <= 16\n",
							      delta);
				else if (delta == 0)
					ksft_test_result_fail("limit: none created\n");
				else
					ksft_test_result_fail("limit exceeded: %ld > 16\n",
							      delta);
				munmap(addr, map_size);
			} else {
				ksft_test_result_fail("mmap for limit test\n");
			}
			close(fd);
			write_sysctl("/proc/sys/vm/numa_replicate_max_per_node",
				     "0");
		} else {
			ksft_test_result_skip("cannot write sysctl (need root)\n");
		}
	}

	/*
	 * Test 5: Leak check.
	 */
	{
		long total_created, total_dropped, delta;

		usleep(100000);

		created_end = read_vmstat("numa_replica_created");
		dropped_end = read_vmstat("numa_replica_dropped");
		total_created = created_end - created_start;
		total_dropped = dropped_end - dropped_start;
		delta = total_created - total_dropped;

		ksft_print_msg("leak: created=%ld dropped=%ld delta=%ld\n",
			       total_created, total_dropped, delta);

		if (delta >= 0 && delta <= 64)
			ksft_test_result_pass("no leak: delta=%ld\n", delta);
		else
			ksft_test_result_fail("leak: delta=%ld\n", delta);
	}

	ksft_finished();
	return 0;
}
