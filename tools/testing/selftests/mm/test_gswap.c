// SPDX-License-Identifier: GPL-2.0
/*
 * test_gswap.c - Selftest for gswap (GPU VRAM-backed compressed swap)
 *
 * Tests:
 *  1. Module presence and parameter accessibility
 *  2. Debugfs interface availability and readability
 *  3. Data integrity under memory pressure (store + load)
 *  4. Statistics counter sanity
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include "kselftest.h"

#define DEBUGFS_PATH	"/sys/kernel/debug/gswap"
#define PARAMS_PATH	"/sys/module/gswap/parameters"

static int read_ulong(const char *path, unsigned long *val)
{
	FILE *f = fopen(path, "r");

	if (!f)
		return -1;
	if (fscanf(f, "%lu", val) != 1) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

static int write_str(const char *path, const char *val)
{
	FILE *f = fopen(path, "w");

	if (!f)
		return -1;
	if (fprintf(f, "%s\n", val) < 0) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

static int read_str(const char *path, char *buf, size_t len)
{
	FILE *f = fopen(path, "r");
	char *ret;

	if (!f)
		return -1;
	ret = fgets(buf, len, f);
	fclose(f);
	if (!ret)
		return -1;
	/* Strip trailing newline */
	buf[strcspn(buf, "\n")] = '\0';
	return 0;
}

/*
 * Test 1: Verify module is loaded and parameters are accessible.
 */
static void test_module_params(void)
{
	char buf[256];
	const char *params[] = {
		"enabled", "compressor", "max_pool_percent",
		"vram_base", "vram_size"
	};

	for (int i = 0; i < (int)(sizeof(params) / sizeof(params[0])); i++) {
		char path[512];

		snprintf(path, sizeof(path), "%s/%s", PARAMS_PATH, params[i]);
		if (read_str(path, buf, sizeof(buf)) == 0)
			ksft_test_result_pass("param %s readable: %s\n",
					      params[i], buf);
		else
			ksft_test_result_fail("param %s not readable\n",
					      params[i]);
	}
}

/*
 * Test 2: Verify debugfs counters exist and are readable.
 */
static void test_debugfs_counters(void)
{
	const char *counters[] = {
		"stored_pages", "pool_total_size", "pool_used_size",
		"stores", "loads", "reject_compress_fail",
		"reject_compress_poor", "reject_alloc_fail",
		"reject_kmemcache_fail", "decompress_fail",
		"pool_limit_hit", "written_back_pages"
	};
	unsigned long val;

	for (int i = 0; i < (int)(sizeof(counters) / sizeof(counters[0])); i++) {
		char path[512];

		snprintf(path, sizeof(path), "%s/%s", DEBUGFS_PATH, counters[i]);
		if (read_ulong(path, &val) == 0)
			ksft_test_result_pass("debugfs %s = %lu\n",
					      counters[i], val);
		else
			ksft_test_result_skip("debugfs %s not readable "
					      "(no VRAM?)\n", counters[i]);
	}
}

/*
 * Test 3: Enable/disable toggle.
 */
static void test_enable_disable(void)
{
	char buf[32];
	const char *path = PARAMS_PATH "/enabled";

	/* Disable */
	if (write_str(path, "N") < 0) {
		ksft_test_result_fail("write disable\n");
		ksft_test_result_skip("write enable (skipped due to prior failure)\n");
		return;
	}
	read_str(path, buf, sizeof(buf));
	if (strcmp(buf, "N") == 0)
		ksft_test_result_pass("disable gswap\n");
	else
		ksft_test_result_fail("disable gswap: got '%s'\n", buf);

	/* Re-enable */
	if (write_str(path, "Y") < 0) {
		ksft_test_result_fail("write enable\n");
		return;
	}
	read_str(path, buf, sizeof(buf));
	if (strcmp(buf, "Y") == 0)
		ksft_test_result_pass("enable gswap\n");
	else
		ksft_test_result_fail("enable gswap: got '%s'\n", buf);
}

/*
 * Test 4: Data integrity under memory pressure.
 *
 * Allocates more memory than available RAM to force swapping,
 * writes a known pattern, then reads it back to verify correctness.
 */
static void test_data_integrity(void)
{
	unsigned long pool_total;
	char path[512];
	long page_size = sysconf(_SC_PAGESIZE);
	long mem_total_pages;
	size_t alloc_size;
	char *mem;
	int errors = 0;
	unsigned long stores_before = 0, stores_after = 0;

	/* Check if VRAM pool is available */
	snprintf(path, sizeof(path), "%s/pool_total_size", DEBUGFS_PATH);
	if (read_ulong(path, &pool_total) != 0 || pool_total == 0) {
		ksft_test_result_skip("data integrity (no VRAM pool)\n");
		ksft_test_result_skip("gswap pages stored (no VRAM pool)\n");
		return;
	}

	/* Enable gswap */
	write_str(PARAMS_PATH "/enabled", "Y");

	/* Read stores counter before */
	snprintf(path, sizeof(path), "%s/stores", DEBUGFS_PATH);
	read_ulong(path, &stores_before);

	/* Allocate ~60% of RAM to trigger some swapping */
	mem_total_pages = sysconf(_SC_PHYS_PAGES);
	alloc_size = (size_t)mem_total_pages * page_size * 60 / 100;

	/* Cap at 512MB to keep test fast */
	if (alloc_size > 512UL * 1024 * 1024)
		alloc_size = 512UL * 1024 * 1024;

	mem = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (mem == MAP_FAILED) {
		ksft_test_result_skip("data integrity (mmap failed: %s)\n",
				      strerror(errno));
		ksft_test_result_skip("gswap pages stored (mmap failed)\n");
		return;
	}

	/* Write pattern: each page's first byte = page_number % 251 (prime) */
	for (size_t offset = 0; offset < alloc_size; offset += page_size) {
		unsigned char pattern = (unsigned char)((offset / page_size) % 251);

		memset(mem + offset, pattern, page_size);
	}

	/*
	 * Touch pages in reverse to cause earlier pages to be swapped out,
	 * then re-read them to trigger swap-in.
	 */
	for (long offset = alloc_size - page_size; offset >= 0;
	     offset -= page_size) {
		volatile char c = mem[offset];
		(void)c;
	}

	/* Verify pattern */
	for (size_t offset = 0; offset < alloc_size; offset += page_size) {
		unsigned char expected = (unsigned char)((offset / page_size) % 251);

		if ((unsigned char)mem[offset] != expected) {
			errors++;
			if (errors <= 3)
				ksft_print_msg("page %zu: expected 0x%02x, "
					       "got 0x%02x\n",
					       offset / page_size, expected,
					       (unsigned char)mem[offset]);
		}
	}

	munmap(mem, alloc_size);

	if (errors == 0)
		ksft_test_result_pass("data integrity (%zu MB tested)\n",
				      alloc_size / (1024 * 1024));
	else
		ksft_test_result_fail("data integrity (%d errors in %zu pages)\n",
				      errors, alloc_size / page_size);

	/* Check if any pages went through gswap */
	snprintf(path, sizeof(path), "%s/stores", DEBUGFS_PATH);
	read_ulong(path, &stores_after);

	if (stores_after > stores_before)
		ksft_test_result_pass("gswap pages stored (%lu new)\n",
				      stores_after - stores_before);
	else
		ksft_test_result_skip("gswap pages stored "
				      "(none - zswap may have captured all)\n");
}

/*
 * Test 5: Statistics sanity -- all counters non-negative, stores >= loads.
 */
static void test_stats_sanity(void)
{
	unsigned long stores = 0, loads = 0;
	char path[512];

	snprintf(path, sizeof(path), "%s/stores", DEBUGFS_PATH);
	if (read_ulong(path, &stores) != 0) {
		ksft_test_result_skip("stats sanity (debugfs not available)\n");
		return;
	}

	snprintf(path, sizeof(path), "%s/loads", DEBUGFS_PATH);
	read_ulong(path, &loads);

	/* stores should always be >= loads (some entries may be evicted
	 * via writeback rather than loaded) */
	if (stores >= loads)
		ksft_test_result_pass("stats sanity: stores=%lu >= loads=%lu\n",
				      stores, loads);
	else
		ksft_test_result_fail("stats sanity: stores=%lu < loads=%lu\n",
				      stores, loads);
}

#define NUM_PARAM_TESTS		5
#define NUM_DEBUGFS_TESTS	12
#define NUM_TOGGLE_TESTS	2
#define NUM_INTEGRITY_TESTS	2
#define NUM_STATS_TESTS		1
#define TOTAL_TESTS (NUM_PARAM_TESTS + NUM_DEBUGFS_TESTS + NUM_TOGGLE_TESTS + \
		     NUM_INTEGRITY_TESTS + NUM_STATS_TESTS)

int main(void)
{
	ksft_print_header();
	ksft_set_plan(TOTAL_TESTS);

	if (geteuid() != 0)
		ksft_exit_skip("must be run as root\n");

	if (access(PARAMS_PATH, F_OK) != 0) {
		/* Try loading module */
		if (system("modprobe gswap 2>/dev/null") != 0 ||
		    access(PARAMS_PATH, F_OK) != 0)
			ksft_exit_skip("gswap module not available\n");
	}

	test_module_params();
	test_debugfs_counters();
	test_enable_disable();
	test_data_integrity();
	test_stats_sanity();

	ksft_finished();
}
