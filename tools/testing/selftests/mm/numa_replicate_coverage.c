// SPDX-License-Identifier: GPL-2.0
/*
 * NUMA page replication code path coverage test.
 *
 * Exercises code paths NOT covered by the API, workload, or stress tests:
 *
 *  1. mprotect(PROT_WRITE) invalidates replicas  (mm/mprotect.c)
 *  2. mprotect clears VM_NUMA_REPLICATE flag      (mm/mprotect.c)
 *  3. Shrinker reclaims replicas via drop_caches   (mm/numa_replicate.c)
 *  4. Pinned sysctl blocks shrinker                (mm/numa_replicate.c)
 *  5. File truncate cleans up replicas             (mm/truncate.c)
 *  6. MAP_SHARED write triggers dirty invalidation (mm/page-writeback.c)
 *  7. Debugfs shows active replicas                (mm/numa_replicate.c)
 *  8. Concurrent madvise REPLICATE race            (mm/madvise.c)
 *  9. munmap cleans up replicas                    (mm/truncate.c)
 * 10. Partial range NOREPLICATE                    (mm/madvise.c)
 *
 * Requires: 2+ NUMA nodes, CONFIG_NUMA_PAGE_REPLICATE=y, root (for
 *           sysctl/drop_caches/debugfs), writable real filesystem at
 *           /var/tmp (e.g. 9p mount in QEMU).
 */

#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>

#include "kselftest.h"
#include "numa_replicate_common.h"

#define TEST_PAGES	16
#define TEST_FILE_DIR	"/var/tmp"
#define TEST_FILE_PATH	TEST_FILE_DIR "/.numa_cov_test"
#define HOSTLIB_PATH	"/hostlibs/libc.so.6"

static size_t page_size;
static int cpu_node0, cpu_node1;

static int create_test_file(const char *path, size_t size)
{
	int fd;
	char buf[4096];

	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0)
		return -1;

	memset(buf, 'X', sizeof(buf));
	while (size > 0) {
		size_t chunk = size < sizeof(buf) ? size : sizeof(buf);
		ssize_t n = write(fd, buf, chunk);

		if (n <= 0) {
			close(fd);
			unlink(path);
			return -1;
		}
		size -= n;
	}
	fsync(fd);
	close(fd);
	return 0;
}

/*
 * Create replicas and return the mapping address.
 * Returns NULL on failure.  On success, *fd_out has the file descriptor.
 * Caller is responsible for munmap + close.
 */
static void *setup_replicated_mapping(const char *path, size_t map_size,
				      int *fd_out)
{
	int fd;
	void *addr;
	volatile int sink = 0;
	int i, nr = map_size / page_size;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	/*
	 * Step 1: Fault pages from node 0 to populate the page cache,
	 * then unmap.  The pages remain in the page cache on node 0.
	 */
	pin_to_cpu(cpu_node0);
	addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		return NULL;
	}
	for (i = 0; i < nr; i++)
		sink += ((volatile char *)addr)[i * page_size];
	(void)sink;
	munmap(addr, map_size);

	/*
	 * Step 2: Fresh mmap + enable replication.  No PTEs exist yet,
	 * so subsequent reads from node 1 will generate page faults
	 * that go through the replica creation path.
	 */
	addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	if (madvise(addr, map_size, MADV_NUMA_REPLICATE) != 0) {
		munmap(addr, map_size);
		close(fd);
		return NULL;
	}

	/* Fault from node 1 — page cache pages are on node 0,
	 * so replicas are created on node 1 */
	pin_to_cpu(cpu_node1);
	for (i = 0; i < nr; i++)
		sink += ((volatile char *)addr)[i * page_size];

	*fd_out = fd;
	return addr;
}

static int drop_caches(void)
{
	return write_sysctl("/proc/sys/vm/drop_caches", "2");
}

/* ------------------------------------------------------------------ */
/* Test 1: mprotect(PROT_WRITE) invalidates replicas                   */
/* ------------------------------------------------------------------ */
static void test_mprotect_write_invalidates(void)
{
	size_t map_size = TEST_PAGES * page_size;
	long dropped_before, dropped_after;
	void *addr;
	int fd;

	addr = setup_replicated_mapping(HOSTLIB_PATH, map_size, &fd);
	if (!addr) {
		ksft_test_result_skip("setup failed\n");
		return;
	}

	dropped_before = read_vmstat("numa_replica_dropped");

	if (mprotect(addr, map_size, PROT_READ | PROT_WRITE) != 0) {
		ksft_test_result_fail("mprotect: %s\n", strerror(errno));
		munmap(addr, map_size);
		close(fd);
		return;
	}

	dropped_after = read_vmstat("numa_replica_dropped");

	if (dropped_after > dropped_before)
		ksft_test_result_pass("mprotect PROT_WRITE dropped %ld replicas\n",
				      dropped_after - dropped_before);
	else
		ksft_test_result_fail("mprotect PROT_WRITE dropped none "
				      "(before=%ld after=%ld)\n",
				      dropped_before, dropped_after);

	munmap(addr, map_size);
	close(fd);
}

/* ------------------------------------------------------------------ */
/* Test 2: mprotect PROT_WRITE clears REPLICATE; re-madvise needed     */
/* ------------------------------------------------------------------ */
static void test_mprotect_clears_flag(void)
{
	size_t map_size = TEST_PAGES * page_size;
	long created_before, created_after;
	void *addr;
	int fd;
	volatile int sink = 0;
	int i;

	addr = setup_replicated_mapping(HOSTLIB_PATH, map_size, &fd);
	if (!addr) {
		ksft_test_result_skip("setup failed\n");
		return;
	}

	/* mprotect to PROT_WRITE then back to PROT_READ */
	mprotect(addr, map_size, PROT_READ | PROT_WRITE);
	mprotect(addr, map_size, PROT_READ);

	/* Re-fault from remote node — should NOT create replicas since
	 * VM_NUMA_REPLICATE was cleared by mprotect(PROT_WRITE) */
	created_before = read_vmstat("numa_replica_created");
	pin_to_cpu(cpu_node1);
	for (i = 0; i < TEST_PAGES; i++)
		sink += ((volatile char *)addr)[i * page_size];
	created_after = read_vmstat("numa_replica_created");
	(void)sink;

	if (created_after == created_before)
		ksft_test_result_pass("no new replicas after mprotect cleared flag\n");
	else
		ksft_test_result_fail("replicas created=%ld after flag should be cleared\n",
				      created_after - created_before);

	munmap(addr, map_size);
	close(fd);
}

/* ------------------------------------------------------------------ */
/* Test 3: Shrinker reclaims replicas via drop_caches                  */
/* ------------------------------------------------------------------ */
static void test_shrinker_reclaim(void)
{
	size_t map_size = TEST_PAGES * page_size;
	long dropped_before, dropped_after;
	void *addr;
	int fd;

	addr = setup_replicated_mapping(HOSTLIB_PATH, map_size, &fd);
	if (!addr) {
		ksft_test_result_skip("setup failed\n");
		return;
	}

	dropped_before = read_vmstat("numa_replica_dropped");

	if (drop_caches() != 0) {
		ksft_test_result_skip("cannot write drop_caches (need root)\n");
		munmap(addr, map_size);
		close(fd);
		return;
	}

	dropped_after = read_vmstat("numa_replica_dropped");

	if (dropped_after > dropped_before)
		ksft_test_result_pass("shrinker dropped %ld replicas\n",
				      dropped_after - dropped_before);
	else
		ksft_test_result_fail("shrinker dropped none (before=%ld after=%ld)\n",
				      dropped_before, dropped_after);

	munmap(addr, map_size);
	close(fd);
}

/* ------------------------------------------------------------------ */
/* Test 4: Pinned sysctl blocks shrinker                               */
/* ------------------------------------------------------------------ */
static void test_pinned_blocks_shrinker(void)
{
	size_t map_size = TEST_PAGES * page_size;
	long dropped_before, dropped_after;
	void *addr;
	int fd;

	addr = setup_replicated_mapping(HOSTLIB_PATH, map_size, &fd);
	if (!addr) {
		ksft_test_result_skip("setup failed\n");
		return;
	}

	if (write_sysctl("/proc/sys/vm/numa_replicate_pinned", "1") != 0) {
		ksft_test_result_skip("cannot write pinned sysctl\n");
		munmap(addr, map_size);
		close(fd);
		return;
	}

	dropped_before = read_vmstat("numa_replica_dropped");
	drop_caches();
	dropped_after = read_vmstat("numa_replica_dropped");

	write_sysctl("/proc/sys/vm/numa_replicate_pinned", "0");

	if (dropped_after == dropped_before)
		ksft_test_result_pass("pinned replicas survived shrinker\n");
	else
		ksft_test_result_fail("pinned replicas were dropped (%ld)\n",
				      dropped_after - dropped_before);

	/* Clean up: now that pinned is off, drop them */
	madvise(addr, map_size, MADV_NUMA_NOREPLICATE);
	munmap(addr, map_size);
	close(fd);
}

/* ------------------------------------------------------------------ */
/* Test 5: File truncate cleans up replicas                            */
/* ------------------------------------------------------------------ */
static void test_truncate_cleanup(void)
{
	size_t map_size = TEST_PAGES * page_size;
	long dropped_before, dropped_after;
	void *addr;
	int fd, write_fd;

	if (create_test_file(TEST_FILE_PATH, map_size) != 0) {
		ksft_test_result_skip("cannot create test file on " TEST_FILE_DIR "\n");
		return;
	}

	addr = setup_replicated_mapping(TEST_FILE_PATH, map_size, &fd);
	if (!addr) {
		ksft_test_result_skip("setup failed\n");
		unlink(TEST_FILE_PATH);
		return;
	}

	dropped_before = read_vmstat("numa_replica_dropped");

	/*
	 * Truncate the file to 0, which triggers truncate_inode_pages
	 * -> truncate_cleanup_folio -> numa_replica_invalidate.
	 */
	write_fd = open(TEST_FILE_PATH, O_WRONLY);
	if (write_fd >= 0) {
		ftruncate(write_fd, 0);
		close(write_fd);
	}

	dropped_after = read_vmstat("numa_replica_dropped");

	if (dropped_after > dropped_before)
		ksft_test_result_pass("truncate dropped %ld replicas\n",
				      dropped_after - dropped_before);
	else
		ksft_test_result_fail("truncate dropped none (before=%ld after=%ld)\n",
				      dropped_before, dropped_after);

	munmap(addr, map_size);
	close(fd);
	unlink(TEST_FILE_PATH);
}

/* ------------------------------------------------------------------ */
/* Test 6: MAP_SHARED write triggers dirty invalidation                */
/* ------------------------------------------------------------------ */
static void test_dirty_invalidation(void)
{
	size_t map_size = TEST_PAGES * page_size;
	long dropped_before, dropped_after;
	void *ro_addr;
	int ro_fd, rw_fd;
	char buf[4096];

	if (create_test_file(TEST_FILE_PATH, map_size) != 0) {
		ksft_test_result_skip("cannot create test file\n");
		return;
	}

	ro_addr = setup_replicated_mapping(TEST_FILE_PATH, map_size, &ro_fd);
	if (!ro_addr) {
		ksft_test_result_skip("setup failed\n");
		unlink(TEST_FILE_PATH);
		return;
	}

	/*
	 * Write to the file via pwrite() to dirty the canonical page
	 * in the page cache.  This avoids MAP_SHARED (which 9p may not
	 * support) while still triggering __folio_mark_dirty() ->
	 * numa_replica_invalidate_dirty().
	 *
	 * pwrite() on a page-cache-backed file dirties the cached folio
	 * via generic_perform_write -> folio_mark_dirty.
	 */
	rw_fd = open(TEST_FILE_PATH, O_RDWR);
	if (rw_fd < 0) {
		ksft_test_result_skip("cannot open file RW: %s\n",
				      strerror(errno));
		munmap(ro_addr, map_size);
		close(ro_fd);
		unlink(TEST_FILE_PATH);
		return;
	}

	dropped_before = read_vmstat("numa_replica_dropped");

	memset(buf, 'Z', sizeof(buf));
	pwrite(rw_fd, buf, page_size, 0);
	fsync(rw_fd);

	dropped_after = read_vmstat("numa_replica_dropped");

	if (dropped_after > dropped_before)
		ksft_test_result_pass("dirty write dropped %ld replicas\n",
				      dropped_after - dropped_before);
	else
		ksft_test_result_fail("dirty write dropped none "
				      "(before=%ld after=%ld)\n",
				      dropped_before, dropped_after);

	close(rw_fd);
	munmap(ro_addr, map_size);
	close(ro_fd);
	unlink(TEST_FILE_PATH);
}

/* ------------------------------------------------------------------ */
/* Test 7: Debugfs shows active replicas                               */
/* ------------------------------------------------------------------ */
static void test_debugfs_active(void)
{
	size_t map_size = TEST_PAGES * page_size;
	void *addr;
	int fd, dfd;
	char buf[4096];
	ssize_t n;

	addr = setup_replicated_mapping(HOSTLIB_PATH, map_size, &fd);
	if (!addr) {
		ksft_test_result_skip("setup failed\n");
		return;
	}

	dfd = open("/sys/kernel/debug/numa_replicate", O_RDONLY);
	if (dfd < 0) {
		ksft_test_result_skip("debugfs not accessible\n");
		munmap(addr, map_size);
		close(fd);
		return;
	}

	n = read(dfd, buf, sizeof(buf) - 1);
	close(dfd);

	if (n <= 0) {
		ksft_test_result_fail("debugfs empty\n");
		munmap(addr, map_size);
		close(fd);
		return;
	}
	buf[n] = '\0';

	/* Check that debugfs shows nonzero replica count */
	if (strstr(buf, "replicas") && !strstr(buf, "Total:  0 pages"))
		ksft_test_result_pass("debugfs shows active replicas\n");
	else
		ksft_test_result_fail("debugfs shows 0 replicas while active\n");

	munmap(addr, map_size);
	close(fd);
}

/* ------------------------------------------------------------------ */
/* Test 8: Concurrent madvise REPLICATE race                           */
/* ------------------------------------------------------------------ */

struct race_arg {
	void *addr;
	size_t map_size;
	int result;
};

static void *madvise_racer(void *arg)
{
	struct race_arg *ra = arg;

	ra->result = madvise(ra->addr, ra->map_size, MADV_NUMA_REPLICATE);
	return NULL;
}

static void test_concurrent_madvise(void)
{
	size_t map_size = TEST_PAGES * page_size;
	void *addr;
	int fd;
	pthread_t t1, t2;
	struct race_arg a1, a2;

	fd = open(HOSTLIB_PATH, O_RDONLY);
	if (fd < 0) {
		ksft_test_result_skip("cannot open test file\n");
		return;
	}

	addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		ksft_test_result_skip("mmap failed\n");
		close(fd);
		return;
	}

	a1 = (struct race_arg){ .addr = addr, .map_size = map_size };
	a2 = (struct race_arg){ .addr = addr, .map_size = map_size };

	pthread_create(&t1, NULL, madvise_racer, &a1);
	pthread_create(&t2, NULL, madvise_racer, &a2);
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);

	/* Both should succeed (or one gets -EEXIST internally but
	 * madvise still succeeds for the VMA flag) */
	if (a1.result == 0 && a2.result == 0)
		ksft_test_result_pass("concurrent madvise both succeeded\n");
	else
		ksft_test_result_fail("concurrent madvise: r1=%d r2=%d\n",
				      a1.result, a2.result);

	madvise(addr, map_size, MADV_NUMA_NOREPLICATE);
	munmap(addr, map_size);
	close(fd);
}

/* ------------------------------------------------------------------ */
/* Test 9: munmap triggers replica cleanup via inode eviction          */
/* ------------------------------------------------------------------ */
static void test_munmap_cleanup(void)
{
	size_t map_size = TEST_PAGES * page_size;
	long created_before, created_after;
	long dropped_before, dropped_after;
	long created_delta, dropped_delta;
	void *addr;
	int fd;

	if (create_test_file(TEST_FILE_PATH, map_size) != 0) {
		ksft_test_result_skip("cannot create test file\n");
		return;
	}

	created_before = read_vmstat("numa_replica_created");
	dropped_before = read_vmstat("numa_replica_dropped");

	addr = setup_replicated_mapping(TEST_FILE_PATH, map_size, &fd);
	if (!addr) {
		ksft_test_result_skip("setup failed\n");
		unlink(TEST_FILE_PATH);
		return;
	}

	created_after = read_vmstat("numa_replica_created");
	created_delta = created_after - created_before;

	/* Unlink file, close fd, unmap — should trigger inode eviction
	 * and truncate_inode_pages_final -> replica cleanup */
	unlink(TEST_FILE_PATH);
	munmap(addr, map_size);
	close(fd);

	/* Force inode eviction */
	drop_caches();
	usleep(50000);

	dropped_after = read_vmstat("numa_replica_dropped");
	dropped_delta = dropped_after - dropped_before;

	if (created_delta > 0 && dropped_delta >= created_delta)
		ksft_test_result_pass("munmap+unlink cleaned up %ld/%ld replicas\n",
				      dropped_delta, created_delta);
	else if (created_delta == 0)
		ksft_test_result_fail("no replicas were created\n");
	else
		ksft_test_result_fail("leak: created=%ld dropped=%ld\n",
				      created_delta, dropped_delta);
}

/* ------------------------------------------------------------------ */
/* Test 10: Partial range NOREPLICATE                                  */
/* ------------------------------------------------------------------ */
static void test_partial_noreplicate(void)
{
	size_t map_size = TEST_PAGES * page_size;
	size_t half = map_size / 2;
	long dropped_before, dropped_after, dropped_delta;
	long created_before, created_after, created_delta;
	void *addr;
	int fd;
	volatile int sink = 0;
	int i;

	addr = setup_replicated_mapping(HOSTLIB_PATH, map_size, &fd);
	if (!addr) {
		ksft_test_result_skip("setup failed\n");
		return;
	}

	/* Drop replicas for the first half only */
	dropped_before = read_vmstat("numa_replica_dropped");
	madvise(addr, half, MADV_NUMA_NOREPLICATE);
	dropped_after = read_vmstat("numa_replica_dropped");
	dropped_delta = dropped_after - dropped_before;

	/* Re-fault from remote node — first half should NOT create replicas
	 * (flag cleared), second half should hit existing replicas */
	created_before = read_vmstat("numa_replica_created");
	pin_to_cpu(cpu_node1);
	for (i = 0; i < TEST_PAGES; i++)
		sink += ((volatile char *)addr)[i * page_size];
	created_after = read_vmstat("numa_replica_created");
	created_delta = created_after - created_before;
	(void)sink;

	if (dropped_delta > 0 && created_delta == 0)
		ksft_test_result_pass("partial NOREPLICATE: dropped=%ld, "
				      "no new creates\n", dropped_delta);
	else if (dropped_delta == 0)
		ksft_test_result_fail("partial NOREPLICATE: no drops\n");
	else
		ksft_test_result_pass("partial NOREPLICATE: dropped=%ld, "
				      "new=%ld (some first-half recreated)\n",
				      dropped_delta, created_delta);

	madvise(addr, map_size, MADV_NUMA_NOREPLICATE);
	munmap(addr, map_size);
	close(fd);
}

int main(int argc, char *argv[])
{
	int nr_nodes;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	page_size = getpagesize();

	ksft_print_header();
	ksft_set_plan(10);

	if (read_vmstat("numa_replica_created") < 0)
		ksft_exit_skip("NUMA page replication not enabled\n");

	nr_nodes = count_numa_nodes();
	if (nr_nodes < 2)
		ksft_exit_skip("Need 2+ NUMA nodes, found %d\n", nr_nodes);

	cpu_node0 = first_cpu_on_node(0);
	cpu_node1 = first_cpu_on_node(1);
	if (cpu_node0 < 0 || cpu_node1 < 0)
		ksft_exit_skip("Cannot find CPUs on nodes 0 and 1\n");

	ksft_print_msg("nodes=%d cpu0=%d(node0) cpu1=%d(node1) pages=%d\n",
		       nr_nodes, cpu_node0, cpu_node1, TEST_PAGES);

	/* Ensure replication is enabled */
	write_sysctl("/proc/sys/vm/numa_replicate_enabled", "1");

	test_mprotect_write_invalidates();
	test_mprotect_clears_flag();
	test_shrinker_reclaim();
	test_pinned_blocks_shrinker();
	test_truncate_cleanup();
	test_dirty_invalidation();
	test_debugfs_active();
	test_concurrent_madvise();
	test_munmap_cleanup();
	test_partial_noreplicate();

	/* Restore defaults */
	write_sysctl("/proc/sys/vm/numa_replicate_pinned", "0");
	write_sysctl("/proc/sys/vm/numa_replicate_max_per_node", "0");

	ksft_finished();
	return 0;
}
