// SPDX-License-Identifier: GPL-2.0
/*
 * Test NUMA page replication via MADV_NUMA_REPLICATE.
 *
 * Tests:
 * 1. vmstat counters exist
 * 2. sysctls exist
 * 3. MADV_NUMA_REPLICATE succeeds on read-only file mappings
 * 4. Data readable and correct after REPLICATE
 * 5. MADV_NUMA_NOREPLICATE succeeds
 * 6. MADV_NUMA_REPLICATE fails on writable mappings
 * 7. MADV_NUMA_REPLICATE fails on anonymous mappings
 * 8. vmstat counters are readable
 * 9. debugfs file exists
 */

#include "kselftest.h"
#include "numa_replicate_common.h"

static int check_vmstat_counter(const char *name)
{
	return read_vmstat(name) >= 0;
}

static int check_sysctl_exists(const char *path)
{
	return access(path, R_OK) == 0;
}

int main(int argc, char *argv[])
{
	size_t page_size = getpagesize();
	size_t map_size = page_size * 16;
	void *addr;
	int fd, ret;

	ksft_print_header();
	ksft_set_plan(9);

	/* Skip entire suite if CONFIG_NUMA_PAGE_REPLICATE is not enabled */
	if (!check_vmstat_counter("numa_replica_created"))
		ksft_exit_skip("NUMA page replication not enabled\n");

	/* Test 1: vmstat counters exist */
	if (check_vmstat_counter("numa_replica_created") &&
	    check_vmstat_counter("numa_replica_dropped") &&
	    check_vmstat_counter("numa_replica_hit") &&
	    check_vmstat_counter("numa_replica_miss"))
		ksft_test_result_pass("vmstat counters exist\n");
	else
		ksft_test_result_fail("vmstat counters missing\n");

	/* Test 2: sysctls exist */
	if (check_sysctl_exists("/proc/sys/vm/numa_replicate_enabled") &&
	    check_sysctl_exists("/proc/sys/vm/numa_replicate_pinned"))
		ksft_test_result_pass("sysctls exist\n");
	else
		ksft_test_result_fail("sysctls missing\n");

	/*
	 * Create a file on a real filesystem, not tmpfs/shmem.
	 * memfd_create() and files on tmpfs are shmem-backed, which are
	 * rejected by MADV_NUMA_REPLICATE (vma_is_shmem() returns true).
	 * Try /var/tmp first (usually a real filesystem), then fall back
	 * to /tmp which may be tmpfs on some systems.
	 */
	fd = open("/var/tmp", O_TMPFILE | O_RDWR, 0600);
	if (fd < 0)
		fd = open("/tmp", O_TMPFILE | O_RDWR, 0600);
	if (fd < 0) {
		/* Fallback: try creating a named temp file */
		fd = open("/var/tmp/.numa_replicate_test", O_CREAT | O_RDWR | O_TRUNC, 0600);
		if (fd < 0)
			fd = open("/tmp/.numa_replicate_test", O_CREAT | O_RDWR | O_TRUNC, 0600);
		if (fd < 0) {
			ksft_test_result_fail("open tmpfile failed: %s\n",
					      strerror(errno));
			ksft_finished();
			return 1;
		}
		unlink("/var/tmp/.numa_replicate_test");
		unlink("/tmp/.numa_replicate_test");
	}

	/* Fill with recognizable pattern */
	{
		char *buf = malloc(page_size);

		if (!buf) {
			ksft_test_result_fail("malloc failed\n");
			ksft_finished();
			return 1;
		}
		for (size_t i = 0; i < map_size; i += page_size) {
			memset(buf, 'A' + (i / page_size) % 26, page_size);
			if (write(fd, buf, page_size) != (ssize_t)page_size) {
				free(buf);
				ksft_test_result_fail("write failed\n");
				ksft_finished();
				return 1;
			}
		}
		free(buf);
	}

	/* Test 3: MADV_NUMA_REPLICATE on read-only file mapping succeeds */
	addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		ksft_test_result_fail("mmap RO failed: %s\n", strerror(errno));
	} else {
		ret = madvise(addr, map_size, MADV_NUMA_REPLICATE);
		if (ret == 0)
			ksft_test_result_pass("madvise REPLICATE on RO file mapping\n");
		else
			ksft_test_result_fail("madvise REPLICATE on RO file: %s\n",
					      strerror(errno));

		/* Test 4: Data is still readable and correct */
		volatile char *p = (volatile char *)addr;
		int data_ok = 1;

		for (size_t i = 0; i < map_size; i += page_size) {
			char expected = 'A' + (i / page_size) % 26;

			if (p[i] != expected) {
				data_ok = 0;
				break;
			}
		}
		if (data_ok)
			ksft_test_result_pass("data readable after REPLICATE\n");
		else
			ksft_test_result_fail("data corrupted after REPLICATE\n");

		/* Test 5: MADV_NUMA_NOREPLICATE succeeds */
		ret = madvise(addr, map_size, MADV_NUMA_NOREPLICATE);
		if (ret == 0)
			ksft_test_result_pass("madvise NOREPLICATE\n");
		else
			ksft_test_result_fail("madvise NOREPLICATE: %s\n",
					      strerror(errno));

		munmap(addr, map_size);
	}

	/* Test 6: MADV_NUMA_REPLICATE fails on writable file mapping */
	addr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		ksft_test_result_fail("mmap RW failed: %s\n", strerror(errno));
	} else {
		ret = madvise(addr, map_size, MADV_NUMA_REPLICATE);
		if (ret == -1 && errno == EINVAL)
			ksft_test_result_pass("REPLICATE rejected on writable mapping\n");
		else
			ksft_test_result_fail("REPLICATE should fail on writable: ret=%d errno=%d\n",
					      ret, errno);
		munmap(addr, map_size);
	}

	/* Test 7: MADV_NUMA_REPLICATE fails on anonymous mapping */
	addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS,
		    -1, 0);
	if (addr == MAP_FAILED) {
		ksft_test_result_fail("mmap anon failed: %s\n",
				      strerror(errno));
	} else {
		ret = madvise(addr, map_size, MADV_NUMA_REPLICATE);
		if (ret == -1 && errno == EINVAL)
			ksft_test_result_pass("REPLICATE rejected on anonymous mapping\n");
		else
			ksft_test_result_fail("REPLICATE should fail on anon: ret=%d errno=%d\n",
					      ret, errno);
		munmap(addr, map_size);
	}

	close(fd);

	/* Test 8: vmstat counters are readable (values >= 0) */
	{
		long created = read_vmstat("numa_replica_created");
		long dropped = read_vmstat("numa_replica_dropped");

		if (created >= 0 && dropped >= 0)
			ksft_test_result_pass("vmstat counters readable: created=%ld dropped=%ld\n",
					      created, dropped);
		else
			ksft_test_result_fail("vmstat counters not readable\n");
	}

	/* Test 9: debugfs file exists (if debugfs mounted) */
	if (access("/sys/kernel/debug/numa_replicate", R_OK) == 0)
		ksft_test_result_pass("debugfs numa_replicate exists\n");
	else
		ksft_test_result_skip("debugfs not accessible (need root)\n");

	ksft_finished();
	return 0;
}
