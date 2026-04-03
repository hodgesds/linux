// SPDX-License-Identifier: GPL-2.0
/*
 * NUMA page replication workload test.
 *
 * Tests replication of read-only file-backed pages (.text/.rodata)
 * by mmapping a real shared library and reading from different NUMA
 * nodes. This exercises the actual production use case: clean,
 * file-backed pages from a real filesystem.
 *
 * Tests:
 * 1. Remote-node faults create replicas
 * 2. Data integrity — replica matches canonical
 * 3. Re-reading hits cached replicas
 * 4. MADV_NUMA_NOREPLICATE drops replicas
 * 5. Re-replication after drop
 * 6. Throughput comparison with/without replication
 * 7. Concurrent readers from both nodes
 *
 * Requires: 2+ NUMA nodes, CONFIG_NUMA_PAGE_REPLICATE=y
 * Needs a real file (not tmpfs/shmem): pass path as argv[1],
 * default tries /hostlibs/libc.so.6 (9p mount from QEMU script).
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>

#include "kselftest.h"

#ifndef MADV_NUMA_REPLICATE
#define MADV_NUMA_REPLICATE	26
#endif
#ifndef MADV_NUMA_NOREPLICATE
#define MADV_NUMA_NOREPLICATE	27
#endif

#define NR_TEST_PAGES	64

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

/*
 * Find a real (non-tmpfs) file to use for testing.
 * Tries paths in order, returns fd or -1.
 */
static int open_test_file(const char *user_path, size_t *file_size)
{
	static const char *candidates[] = {
		"/hostlibs/libc.so.6",   /* 9p mount from QEMU script */
		"/usr/lib64/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/x86_64-linux-gnu/libc.so.6",
		NULL,
	};
	const char **path;
	struct stat st;
	int fd;

	if (user_path) {
		fd = open(user_path, O_RDONLY);
		if (fd >= 0 && fstat(fd, &st) == 0 && st.st_size > 0) {
			*file_size = st.st_size;
			return fd;
		}
		if (fd >= 0)
			close(fd);
	}

	for (path = candidates; *path; path++) {
		fd = open(*path, O_RDONLY);
		if (fd < 0)
			continue;
		if (fstat(fd, &st) == 0 && st.st_size > 0) {
			ksft_print_msg("using test file: %s (%zu KB)\n",
				       *path, (size_t)st.st_size / 1024);
			*file_size = st.st_size;
			return fd;
		}
		close(fd);
	}

	return -1;
}

struct reader_args {
	const volatile char *addr;
	const char *reference;	/* snapshot from node 0 for comparison */
	size_t map_size;
	size_t page_size;
	int nr_pages;
	int cpu;
	int data_ok;
	volatile int sum;
};

static void *remote_reader(void *arg)
{
	struct reader_args *ra = arg;

	if (pin_to_cpu(ra->cpu) != 0) {
		ra->data_ok = -1;
		return NULL;
	}

	ra->data_ok = 1;

	for (int i = 0; i < ra->nr_pages; i++) {
		size_t off = (size_t)i * ra->page_size;

		ra->sum += ra->addr[off];
		ra->sum += ra->addr[off + ra->page_size / 2];
		ra->sum += ra->addr[off + ra->page_size - 1];

		/* Verify against reference snapshot */
		if (ra->reference &&
		    memcmp((const char *)ra->addr + off,
			   ra->reference + off, ra->page_size) != 0) {
			ra->data_ok = 0;
			ksft_print_msg("  data mismatch on page %d\n", i);
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	size_t page_size = getpagesize();
	size_t file_size, map_size;
	int nr_nodes, cpu0, cpu1;
	int fd, nr_pages;
	void *addr;
	char *reference;
	long created_before, created_after, created_delta;
	long hit_before, hit_after, hit_delta;
	long dropped_before, dropped_after, dropped_delta;
	pthread_t thread;
	struct reader_args ra;
	int ret;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	ksft_print_header();
	ksft_set_plan(7);

	nr_nodes = count_numa_nodes();
	if (nr_nodes < 2)
		ksft_exit_skip("Need 2+ NUMA nodes, found %d\n", nr_nodes);

	cpu0 = first_cpu_on_node(0);
	cpu1 = first_cpu_on_node(1);
	if (cpu0 < 0 || cpu1 < 0)
		ksft_exit_skip("Cannot find CPUs on nodes 0 and 1\n");

	fd = open_test_file(argc > 1 ? argv[1] : NULL, &file_size);
	if (fd < 0)
		ksft_exit_skip("No suitable test file found (need real filesystem, not tmpfs)\n");

	/* Use up to NR_TEST_PAGES pages from the file */
	nr_pages = file_size / page_size;
	if (nr_pages > NR_TEST_PAGES)
		nr_pages = NR_TEST_PAGES;
	if (nr_pages < 4)
		ksft_exit_skip("Test file too small (%zu bytes)\n", file_size);
	map_size = (size_t)nr_pages * page_size;

	ksft_print_msg("nodes=%d cpu0=%d(node0) cpu1=%d(node1) pages=%d (%zu KB)\n",
		       nr_nodes, cpu0, cpu1, nr_pages, map_size / 1024);

	/*
	 * Step 1: Fault pages from node 0 and save a reference copy.
	 * These are clean file-backed pages from a real filesystem.
	 */
	pin_to_cpu(cpu0);

	addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
		ksft_exit_fail_msg("mmap: %s\n", strerror(errno));

	/* Save a reference snapshot for data comparison */
	reference = malloc(map_size);
	if (!reference)
		ksft_exit_fail_msg("malloc\n");
	memcpy(reference, addr, map_size);
	munmap(addr, map_size);

	/*
	 * Step 2: Re-map and enable replication.
	 */
	addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
		ksft_exit_fail_msg("re-mmap: %s\n", strerror(errno));

	ret = madvise(addr, map_size, MADV_NUMA_REPLICATE);
	if (ret != 0)
		ksft_exit_fail_msg("madvise REPLICATE: %s\n", strerror(errno));

	/*
	 * Test 1: Remote reader triggers replica creation.
	 */
	created_before = read_vmstat("numa_replica_created");

	ra = (struct reader_args){
		.addr = addr,
		.reference = reference,
		.map_size = map_size,
		.page_size = page_size,
		.nr_pages = nr_pages,
		.cpu = cpu1,
	};

	pthread_create(&thread, NULL, remote_reader, &ra);
	pthread_join(thread, NULL);

	created_after = read_vmstat("numa_replica_created");
	created_delta = created_after - created_before;

	ksft_print_msg("replicas created: %ld\n", created_delta);

	if (created_delta > 0)
		ksft_test_result_pass("replicas created: %ld\n", created_delta);
	else
		ksft_test_result_fail("no replicas created (delta=%ld)\n",
				      created_delta);

	/*
	 * Test 2: Data integrity — replica content matches original.
	 */
	if (ra.data_ok == 1)
		ksft_test_result_pass("data integrity verified\n");
	else if (ra.data_ok == -1)
		ksft_test_result_skip("could not pin to cpu %d\n", cpu1);
	else
		ksft_test_result_fail("data corruption in replicas\n");

	/*
	 * Test 3: Re-reading hits existing replicas.
	 */
	munmap(addr, map_size);
	addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
		ksft_exit_fail_msg("re-mmap: %s\n", strerror(errno));
	madvise(addr, map_size, MADV_NUMA_REPLICATE);

	created_before = read_vmstat("numa_replica_created");
	hit_before = read_vmstat("numa_replica_hit");

	ra.addr = addr;
	ra.data_ok = 0;
	ra.sum = 0;
	pthread_create(&thread, NULL, remote_reader, &ra);
	pthread_join(thread, NULL);

	created_after = read_vmstat("numa_replica_created");
	hit_after = read_vmstat("numa_replica_hit");
	created_delta = created_after - created_before;
	hit_delta = hit_after - hit_before;

	ksft_print_msg("hits=%ld new_creates=%ld\n", hit_delta, created_delta);

	if (hit_delta > 0 && created_delta == 0)
		ksft_test_result_pass("replica hits: %ld\n", hit_delta);
	else if (hit_delta > 0)
		ksft_test_result_pass("replica hits: %ld (%ld new)\n",
				      hit_delta, created_delta);
	else
		ksft_test_result_fail("no hits (hit=%ld created=%ld)\n",
				      hit_delta, created_delta);

	/*
	 * Test 4: NOREPLICATE drops replicas.
	 */
	dropped_before = read_vmstat("numa_replica_dropped");
	madvise(addr, map_size, MADV_NUMA_NOREPLICATE);
	dropped_after = read_vmstat("numa_replica_dropped");
	dropped_delta = dropped_after - dropped_before;

	ksft_print_msg("dropped: %ld\n", dropped_delta);

	if (dropped_delta > 0)
		ksft_test_result_pass("NOREPLICATE dropped %ld\n",
				      dropped_delta);
	else
		ksft_test_result_fail("NOREPLICATE dropped=%ld\n",
				      dropped_delta);
	munmap(addr, map_size);

	/*
	 * Test 5: Re-replication after drop.
	 */
	addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
		ksft_exit_fail_msg("mmap: %s\n", strerror(errno));
	madvise(addr, map_size, MADV_NUMA_REPLICATE);

	created_before = read_vmstat("numa_replica_created");
	ra.addr = addr;
	ra.data_ok = 0;
	ra.sum = 0;
	pthread_create(&thread, NULL, remote_reader, &ra);
	pthread_join(thread, NULL);

	created_after = read_vmstat("numa_replica_created");
	created_delta = created_after - created_before;

	if (created_delta > 0)
		ksft_test_result_pass("re-replicated: %ld\n", created_delta);
	else
		ksft_test_result_fail("re-replication failed (delta=%ld)\n",
				      created_delta);
	munmap(addr, map_size);

	/*
	 * Test 6: Throughput comparison.
	 */
	{
		struct timespec t0, t1;
		int iterations = 20;
		double ns_no_repl, ns_repl;
		volatile int sink = 0;

		/* Without replication */
		addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED)
			ksft_exit_fail_msg("mmap: %s\n", strerror(errno));

		pin_to_cpu(cpu0);
		for (int i = 0; i < nr_pages; i++)
			sink += ((volatile char *)addr)[i * page_size];

		pin_to_cpu(cpu1);
		for (int i = 0; i < nr_pages; i++)
			sink += ((volatile char *)addr)[i * page_size];

		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (int iter = 0; iter < iterations; iter++)
			for (int i = 0; i < nr_pages; i++)
				sink += ((volatile char *)addr)[i * page_size];
		clock_gettime(CLOCK_MONOTONIC, &t1);
		ns_no_repl = (t1.tv_sec - t0.tv_sec) * 1e9 +
			     (t1.tv_nsec - t0.tv_nsec);
		munmap(addr, map_size);

		/* With replication */
		addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED)
			ksft_exit_fail_msg("mmap: %s\n", strerror(errno));

		pin_to_cpu(cpu0);
		for (int i = 0; i < nr_pages; i++)
			sink += ((volatile char *)addr)[i * page_size];

		madvise(addr, map_size, MADV_NUMA_REPLICATE);
		pin_to_cpu(cpu1);
		for (int i = 0; i < nr_pages; i++)
			sink += ((volatile char *)addr)[i * page_size];

		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (int iter = 0; iter < iterations; iter++)
			for (int i = 0; i < nr_pages; i++)
				sink += ((volatile char *)addr)[i * page_size];
		clock_gettime(CLOCK_MONOTONIC, &t1);
		ns_repl = (t1.tv_sec - t0.tv_sec) * 1e9 +
			  (t1.tv_nsec - t0.tv_nsec);
		munmap(addr, map_size);

		ksft_print_msg("throughput: no_repl=%.0fns repl=%.0fns speedup=%.2fx\n",
			       ns_no_repl, ns_repl,
			       ns_no_repl / (ns_repl > 0 ? ns_repl : 1));
		ksft_test_result_pass("throughput measured\n");
		(void)sink;
	}

	/*
	 * Test 7: Concurrent readers from both nodes.
	 */
	{
		pthread_t t0, t1;
		struct reader_args ra0, ra1;

		addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED)
			ksft_exit_fail_msg("mmap: %s\n", strerror(errno));
		madvise(addr, map_size, MADV_NUMA_REPLICATE);

		ra0 = (struct reader_args){
			.addr = addr, .reference = reference,
			.map_size = map_size, .page_size = page_size,
			.nr_pages = nr_pages, .cpu = cpu0,
		};
		ra1 = (struct reader_args){
			.addr = addr, .reference = reference,
			.map_size = map_size, .page_size = page_size,
			.nr_pages = nr_pages, .cpu = cpu1,
		};

		pthread_create(&t0, NULL, remote_reader, &ra0);
		pthread_create(&t1, NULL, remote_reader, &ra1);
		pthread_join(t0, NULL);
		pthread_join(t1, NULL);

		if (ra0.data_ok == 1 && ra1.data_ok == 1)
			ksft_test_result_pass("concurrent: both nodes verified\n");
		else
			ksft_test_result_fail("concurrent: node0=%d node1=%d\n",
					      ra0.data_ok, ra1.data_ok);
		munmap(addr, map_size);
	}

	free(reference);
	close(fd);
	ksft_finished();
	return 0;
}
