// SPDX-License-Identifier: GPL-2.0
/*
 * bench_gswap.c - Benchmark for swap backends (gswap vs file-backed swap)
 *
 * Uses cgroups v2 memory limits to force real swapping regardless of
 * total system RAM.  Allocates more than the cgroup allows, forcing
 * pages through the swap path, then reads them back.
 *
 * Workloads:
 *   sequential - linear write then linear read-back
 *   random     - linear write then random-order read-back
 *   fault      - populate, MADV_PAGEOUT, then sequential re-read
 *
 * Usage:
 *   bench_gswap [-s SIZE_MB] [-m MEM_LIMIT_MB] [-w WORKLOAD] [-i ITER]
 *               [-d DATA] [-q]
 *
 *   SIZE_MB       allocation size in MB (default: 512)
 *   MEM_LIMIT_MB  cgroup memory limit in MB (default: SIZE_MB / 2)
 *   WORKLOAD      "sequential", "random", "fault", or "all" (default: all)
 *   ITERATIONS    read-back passes (default: 3)
 *   DATA          "repeat"  - single byte per page (very compressible)
 *                 "random"  - pseudorandom data (incompressible)
 *                 "mixed"   - alternating compressible/incompressible pages
 *                 (default: repeat)
 *   -q            quiet mode, machine-readable output
 */
#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <linux/limits.h>

#define DEBUGFS_PATH	"/sys/kernel/debug/gswap"
#define PARAMS_PATH	"/sys/module/gswap/parameters"
#define CGROUP_ROOT	"/sys/fs/cgroup"
#define CGROUP_NAME	"bench_gswap"

#define PAGE_SIZE	4096
#define DEFAULT_ALLOC_MB	512

enum data_pattern {
	DATA_REPEAT,	/* single byte per page (highly compressible) */
	DATA_RANDOM,	/* pseudorandom (incompressible) */
	DATA_MIXED,	/* even pages compressible, odd pages random */
};

static enum data_pattern data_mode = DATA_REPEAT;

/*
 * Simple xorshift64 PRNG — fast, deterministic, good enough for
 * generating incompressible data.  Seeded per-page so verification
 * can regenerate without storing state.
 */
static inline uint64_t xorshift64(uint64_t *state)
{
	uint64_t x = *state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*state = x;
	return x;
}

static void fill_page(char *page, size_t page_index)
{
	unsigned char pattern = (unsigned char)(page_index % 251);
	int use_random = 0;

	switch (data_mode) {
	case DATA_REPEAT:
		memset(page, pattern, PAGE_SIZE);
		return;
	case DATA_RANDOM:
		use_random = 1;
		break;
	case DATA_MIXED:
		use_random = (page_index & 1);
		break;
	}

	if (use_random) {
		uint64_t state = page_index * 6364136223846793005ULL + 1;
		uint64_t *p = (uint64_t *)page;
		size_t i;

		for (i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++)
			p[i] = xorshift64(&state);
	} else {
		memset(page, pattern, PAGE_SIZE);
	}
}

static int verify_page(const volatile unsigned char *page, size_t page_index)
{
	int expect_random = 0;

	switch (data_mode) {
	case DATA_REPEAT: {
		unsigned char pattern = (unsigned char)(page_index % 251);

		return *page == pattern ? 0 : -1;
	}
	case DATA_RANDOM:
		expect_random = 1;
		break;
	case DATA_MIXED:
		expect_random = (page_index & 1);
		break;
	}

	if (expect_random) {
		uint64_t state = page_index * 6364136223846793005ULL + 1;
		const volatile uint64_t *p = (const volatile uint64_t *)page;
		size_t i;

		for (i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++) {
			uint64_t expected = xorshift64(&state);

			if (p[i] != expected)
				return -1;
		}
		return 0;
	} else {
		unsigned char pattern = (unsigned char)(page_index % 251);

		return *page == pattern ? 0 : -1;
	}
}

struct gswap_stats {
	unsigned long stores;
	unsigned long loads;
	unsigned long stored_pages;
	unsigned long reject_compress_poor;
	unsigned long reject_alloc_fail;
	unsigned long written_back_pages;
	unsigned long pool_total_size;
	unsigned long pool_used_size;
};

struct bench_result {
	double write_secs;
	double read_secs;
	double write_mbps;
	double read_mbps;
	size_t alloc_mb;
	unsigned long swapped_pages;
	struct gswap_stats stats_before;	/* before write phase */
	struct gswap_stats stats_mid;		/* after write, before read */
	struct gswap_stats stats_after;		/* after read phase */
};

static char cgroup_path[256];
static int cgroup_created;
static size_t cgroup_mem_limit_mb;

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

static int write_file(const char *path, const char *val)
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

static int gswap_available(void)
{
	return access(PARAMS_PATH "/enabled", F_OK) == 0;
}

static int gswap_has_pool(void)
{
	unsigned long pool_total = 0;
	char path[256];

	snprintf(path, sizeof(path), "%s/pool_total_size", DEBUGFS_PATH);
	if (read_ulong(path, &pool_total) != 0)
		return 0;
	return pool_total > 0;
}

static void read_gswap_stats(struct gswap_stats *s)
{
	char path[256];

	memset(s, 0, sizeof(*s));
	if (!gswap_available())
		return;

#define READ_STAT(field) do {						\
	snprintf(path, sizeof(path), "%s/%s", DEBUGFS_PATH, #field);	\
	read_ulong(path, &s->field);					\
} while (0)

	READ_STAT(stores);
	READ_STAT(loads);
	READ_STAT(stored_pages);
	READ_STAT(reject_compress_poor);
	READ_STAT(reject_alloc_fail);
	READ_STAT(written_back_pages);
	READ_STAT(pool_total_size);
	READ_STAT(pool_used_size);
#undef READ_STAT
}

/*
 * Read swap usage from the cgroup's memory.stat.
 */
static unsigned long read_cgroup_swap_pages(void)
{
	char path[PATH_MAX], line[256];
	unsigned long val = 0;
	FILE *f;

	snprintf(path, sizeof(path), "%s/memory.stat", cgroup_path);
	f = fopen(path, "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "swap %lu", &val) == 1)
			break;
	}
	fclose(f);
	return val / PAGE_SIZE;
}

static void cgroup_set_mem_limit(const char *limit)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/memory.high", cgroup_path);
	write_file(path, limit);
	snprintf(path, sizeof(path), "%s/memory.max", cgroup_path);
	write_file(path, limit);
}

static void cgroup_restore_mem_limit(void)
{
	char path[PATH_MAX], val[64];

	snprintf(path, sizeof(path), "%s/memory.high", cgroup_path);
	snprintf(val, sizeof(val), "%zuM", cgroup_mem_limit_mb);
	write_file(path, val);

	/*
	 * Set memory.max only slightly above memory.high.  If max equals
	 * the allocation size the kernel can keep all pages resident and
	 * MADV_PAGEOUT won't force writeback — nothing reaches swap.
	 */
	snprintf(path, sizeof(path), "%s/memory.max", cgroup_path);
	snprintf(val, sizeof(val), "%zuM", cgroup_mem_limit_mb + cgroup_mem_limit_mb / 4);
	write_file(path, val);
}

static void cleanup_cgroup(void)
{
	char path[PATH_MAX];

	if (!cgroup_created)
		return;

	/* Remove memory limit before leaving so we don't get OOM'd */
	cgroup_set_mem_limit("max");

	/* Move ourselves back to the root cgroup */
	snprintf(path, sizeof(path), "%s/cgroup.procs", CGROUP_ROOT);
	write_file(path, "0");

	/* Remove our cgroup dir */
	rmdir(cgroup_path);
	cgroup_created = 0;
}

static void sighandler(int sig)
{
	(void)sig;
	cleanup_cgroup();
	_exit(1);
}

/*
 * Create a cgroup with a memory limit and move ourselves into it.
 * This forces the kernel to swap when our allocation exceeds the limit.
 */
static int setup_cgroup(size_t mem_limit_mb)
{
	char path[PATH_MAX], val[64];
	struct stat st;

	snprintf(cgroup_path, sizeof(cgroup_path), "%s/%s",
		 CGROUP_ROOT, CGROUP_NAME);

	/* Check cgroups v2 is mounted */
	snprintf(path, sizeof(path), "%s/cgroup.controllers", CGROUP_ROOT);
	if (stat(path, &st) != 0) {
		fprintf(stderr, "error: cgroups v2 not mounted at %s\n",
			CGROUP_ROOT);
		return -1;
	}

	/* Enable memory controller on root if needed */
	snprintf(path, sizeof(path), "%s/cgroup.subtree_control", CGROUP_ROOT);
	write_file(path, "+memory");

	/* Create our cgroup */
	if (mkdir(cgroup_path, 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "error: cannot create cgroup %s: %s\n",
			cgroup_path, strerror(errno));
		return -1;
	}
	cgroup_created = 1;

	/* Install signal handlers for cleanup */
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	/*
	 * Use memory.high for throttling instead of memory.max for hard
	 * limits.  memory.high slows allocations when exceeded, giving
	 * the swap device time to drain — this prevents OOM kills with
	 * slow swap backends (e.g. loop-backed files).  memory.max is
	 * set well above to catch runaway allocation without OOM.
	 */
	cgroup_mem_limit_mb = mem_limit_mb;
	snprintf(path, sizeof(path), "%s/memory.high", cgroup_path);
	snprintf(val, sizeof(val), "%zuM", mem_limit_mb);
	if (write_file(path, val) != 0) {
		fprintf(stderr, "error: cannot set memory.high: %s\n",
			strerror(errno));
		cleanup_cgroup();
		return -1;
	}

	/* Hard limit: tight above memory.high to force real swap pressure */
	snprintf(path, sizeof(path), "%s/memory.max", cgroup_path);
	snprintf(val, sizeof(val), "%zuM", mem_limit_mb + mem_limit_mb / 4);
	write_file(path, val);

	/* Allow unlimited swap so pages go to swap, not OOM */
	snprintf(path, sizeof(path), "%s/memory.swap.max", cgroup_path);
	write_file(path, "max");

	/* Move ourselves into the cgroup */
	snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_path);
	if (write_file(path, "0") != 0) {
		fprintf(stderr, "error: cannot join cgroup: %s\n",
			strerror(errno));
		cleanup_cgroup();
		return -1;
	}

	return 0;
}

static double timespec_diff(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) +
	       (end->tv_nsec - start->tv_nsec) / 1e9;
}

/*
 * Fisher-Yates shuffle for random access pattern.
 */
static void shuffle(size_t *arr, size_t n)
{
	for (size_t i = n - 1; i > 0; i--) {
		size_t j = (size_t)random() % (i + 1);
		size_t tmp = arr[i];

		arr[i] = arr[j];
		arr[j] = tmp;
	}
}

static void drop_caches(void)
{
	FILE *f = fopen("/proc/sys/vm/drop_caches", "w");

	if (f) {
		fprintf(f, "3\n");
		fclose(f);
	}
	usleep(100000);
}

/*
 * Wait for reclaim to push pages to swap.  After writing all pages,
 * the cgroup is over its memory limit — give the kernel time to
 * reclaim and swap out.
 */
static unsigned long read_gswap_stores(void)
{
	unsigned long val = 0;

	read_ulong(DEBUGFS_PATH "/stores", &val);
	return val;
}

static void wait_for_swap_settle(void)
{
	unsigned long prev, cur;
	int stable;

	/*
	 * With gswap, cgroup memory.stat may read 0 because gswap
	 * intercepts pages before they hit the block swap device.
	 *
	 * Writeback via kswapd is asynchronous — stores may still be
	 * in flight after MADV_PAGEOUT returns.  Wait for the
	 * cumulative stores counter to stabilize so that all pages
	 * are in VRAM before the read phase begins.
	 */
	if (gswap_available()) {
		prev = read_gswap_stores();
		stable = 0;
		for (int i = 0; i < 100; i++) {  /* max 10 seconds */
			usleep(100000);
			cur = read_gswap_stores();
			if (cur == prev) {
				if (++stable >= 5)
					return;
			} else {
				stable = 0;
			}
			prev = cur;
		}
		return;
	}

	prev = 0;
	stable = 0;
	for (int i = 0; i < 50; i++) {
		usleep(100000);
		cur = read_cgroup_swap_pages();
		if (cur > 0 && cur == prev) {
			if (++stable >= 3)
				return;
		} else {
			stable = 0;
		}
		prev = cur;
	}
}

/*
 * Sequential workload: write all pages linearly, then read back linearly.
 */
static int bench_sequential(size_t alloc_size, struct bench_result *res)
{
	struct timespec t_start, t_end;
	size_t nr_pages = alloc_size / PAGE_SIZE;
	volatile unsigned char *p;
	char *mem;

	mem = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (mem == MAP_FAILED)
		return -1;

	read_gswap_stats(&res->stats_before);

	/* Phase 1: sequential write — exceeds cgroup limit, forces swap-out */
	clock_gettime(CLOCK_MONOTONIC, &t_start);
	for (size_t i = 0; i < nr_pages; i++)
		fill_page(mem + i * PAGE_SIZE, i);
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	res->write_secs = timespec_diff(&t_start, &t_end);

	/*
	 * Push remaining resident pages to swap too, so the read phase
	 * measures pure swap-in without any RAM-resident hits.
	 */
	madvise(mem, alloc_size, MADV_PAGEOUT);
	wait_for_swap_settle();
	res->swapped_pages = read_cgroup_swap_pages();

	/*
	 * Lift the memory limit before read-back.  Without this, every
	 * swap-in triggers a swap-out (thrashing), conflating the two
	 * costs.  We want to measure pure swap-in throughput.
	 */
	cgroup_set_mem_limit("max");

	/* Phase 2: sequential read-back (pure swap-in) */
	read_gswap_stats(&res->stats_mid);
	clock_gettime(CLOCK_MONOTONIC, &t_start);
	for (size_t i = 0; i < nr_pages; i++) {
		p = (volatile unsigned char *)(mem + i * PAGE_SIZE);
		if (verify_page(p, i)) {
			fprintf(stderr, "data corruption at page %zu\n", i);
			munmap(mem, alloc_size);
			return -2;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	res->read_secs = timespec_diff(&t_start, &t_end);

	read_gswap_stats(&res->stats_after);
	munmap(mem, alloc_size);

	res->alloc_mb = alloc_size / (1024 * 1024);
	res->write_mbps = (alloc_size / (1024.0 * 1024.0)) / res->write_secs;
	res->read_mbps = (alloc_size / (1024.0 * 1024.0)) / res->read_secs;
	return 0;
}

/*
 * Random workload: write linearly, then read back in random page order.
 */
static int bench_random(size_t alloc_size, struct bench_result *res)
{
	struct timespec t_start, t_end;
	size_t nr_pages = alloc_size / PAGE_SIZE;
	volatile unsigned char *p;
	size_t *order;
	char *mem;

	mem = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (mem == MAP_FAILED)
		return -1;

	/* Build shuffled page index — allocate before entering timed region */
	order = malloc(nr_pages * sizeof(size_t));
	if (!order) {
		munmap(mem, alloc_size);
		return -1;
	}
	for (size_t i = 0; i < nr_pages; i++)
		order[i] = i;
	shuffle(order, nr_pages);

	read_gswap_stats(&res->stats_before);

	/* Phase 1: sequential write (cgroup pressure forces swap-out) */
	clock_gettime(CLOCK_MONOTONIC, &t_start);
	for (size_t i = 0; i < nr_pages; i++)
		fill_page(mem + i * PAGE_SIZE, i);
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	res->write_secs = timespec_diff(&t_start, &t_end);

	/* Push all remaining pages to swap for clean read measurement */
	madvise(mem, alloc_size, MADV_PAGEOUT);
	wait_for_swap_settle();
	res->swapped_pages = read_cgroup_swap_pages();

	/* Lift memory limit so reads don't cause concurrent eviction */
	cgroup_set_mem_limit("max");

	/* Phase 2: random read-back (pure swap-in) */
	read_gswap_stats(&res->stats_mid);
	clock_gettime(CLOCK_MONOTONIC, &t_start);
	for (size_t i = 0; i < nr_pages; i++) {
		size_t pg = order[i];

		p = (volatile unsigned char *)(mem + pg * PAGE_SIZE);
		if (verify_page(p, pg)) {
			fprintf(stderr, "data corruption at page %zu\n", pg);
			free(order);
			munmap(mem, alloc_size);
			return -2;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	res->read_secs = timespec_diff(&t_start, &t_end);

	read_gswap_stats(&res->stats_after);
	free(order);
	munmap(mem, alloc_size);

	res->alloc_mb = alloc_size / (1024 * 1024);
	res->write_mbps = (alloc_size / (1024.0 * 1024.0)) / res->write_secs;
	res->read_mbps = (alloc_size / (1024.0 * 1024.0)) / res->read_secs;
	return 0;
}

/*
 * Fault workload: populate, MADV_PAGEOUT to force all pages to swap,
 * then sequential re-read.  Measures pure swap-in cost.
 */
static int bench_fault(size_t alloc_size, struct bench_result *res)
{
	struct timespec t_start, t_end;
	size_t nr_pages = alloc_size / PAGE_SIZE;
	volatile unsigned char *p;
	char *mem;

	mem = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (mem == MAP_FAILED)
		return -1;

	read_gswap_stats(&res->stats_before);

	/* Populate all pages */
	for (size_t i = 0; i < nr_pages; i++)
		fill_page(mem + i * PAGE_SIZE, i);

	/* Force all pages to swap */
	madvise(mem, alloc_size, MADV_PAGEOUT);
	wait_for_swap_settle();

	res->swapped_pages = read_cgroup_swap_pages();
	res->write_secs = 0;
	res->write_mbps = 0;

	/* Lift memory limit so reads don't cause concurrent eviction */
	cgroup_set_mem_limit("max");

	/* Sequential re-read (pure swap-in) */
	read_gswap_stats(&res->stats_mid);
	clock_gettime(CLOCK_MONOTONIC, &t_start);
	for (size_t i = 0; i < nr_pages; i++) {
		p = (volatile unsigned char *)(mem + i * PAGE_SIZE);
		if (verify_page(p, i)) {
			fprintf(stderr, "data corruption at page %zu\n", i);
			munmap(mem, alloc_size);
			return -2;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	res->read_secs = timespec_diff(&t_start, &t_end);

	read_gswap_stats(&res->stats_after);
	munmap(mem, alloc_size);

	res->alloc_mb = alloc_size / (1024 * 1024);
	res->read_mbps = (alloc_size / (1024.0 * 1024.0)) / res->read_secs;
	return 0;
}

static void print_separator(void)
{
	printf("  %-20s %10s %10s %10s %10s\n",
	       "--------------------", "----------", "----------",
	       "----------", "----------");
}

static void print_result(const char *label, struct bench_result *res, int quiet)
{
	unsigned long gswap_stores_delta, gswap_loads_delta;

	/* stores happen during write phase (before → mid) */
	gswap_stores_delta = res->stats_mid.stores - res->stats_before.stores;
	/* loads happen during read phase (mid → after) */
	gswap_loads_delta = res->stats_after.loads - res->stats_mid.loads;

	if (quiet) {
		printf("%s\t%zu\t%.3f\t%.3f\t%.1f\t%.1f\t%lu\t%lu\t%lu\n",
		       label, res->alloc_mb,
		       res->write_secs, res->read_secs,
		       res->write_mbps, res->read_mbps,
		       gswap_stores_delta, gswap_loads_delta,
		       res->swapped_pages);
		return;
	}

	printf("\n  --- %s ---\n", label);
	printf("  %-20s %10s %10s %10s %10s\n",
	       "", "time (s)", "MB/s", "pages", "per-page");
	print_separator();

	if (res->write_secs > 0)
		printf("  %-20s %10.3f %10.1f %10zu %10s\n",
		       "swap-out (write)",
		       res->write_secs, res->write_mbps,
		       res->alloc_mb * 1024 * 1024 / PAGE_SIZE, "-");

	printf("  %-20s %10.3f %10.1f %10zu",
	       "swap-in (read)",
	       res->read_secs, res->read_mbps,
	       res->alloc_mb * 1024 * 1024 / PAGE_SIZE);

	if (res->read_secs > 0) {
		double nr_pages = (double)res->alloc_mb * 1024 * 1024 / PAGE_SIZE;
		double usec_per_page = (res->read_secs * 1e6) / nr_pages;

		printf(" %8.2f us", usec_per_page);
	}
	printf("\n");

	printf("\n  cgroup swap:   %lu pages (%lu MB) in swap before read-back\n",
	       res->swapped_pages,
	       res->swapped_pages * PAGE_SIZE / (1024 * 1024));

	if (gswap_available()) {
		printf("  gswap counters:\n");
		printf("    stores:      %lu (+%lu)\n",
		       res->stats_after.stores, gswap_stores_delta);
		printf("    loads:       %lu (+%lu)\n",
		       res->stats_after.loads, gswap_loads_delta);
		printf("    stored_pages: %lu\n",
		       res->stats_after.stored_pages);
		printf("    pool_used:   %lu / %lu bytes (%.1f%%)\n",
		       res->stats_after.pool_used_size,
		       res->stats_after.pool_total_size,
		       res->stats_after.pool_total_size > 0 ?
		       100.0 * res->stats_after.pool_used_size /
		       res->stats_after.pool_total_size : 0.0);
		printf("    writeback:   %lu (+%lu)\n",
		       res->stats_after.written_back_pages,
		       res->stats_after.written_back_pages -
		       res->stats_before.written_back_pages);
		printf("    reject_poor: %lu (+%lu)\n",
		       res->stats_after.reject_compress_poor,
		       res->stats_after.reject_compress_poor -
		       res->stats_before.reject_compress_poor);
		if (gswap_stores_delta == 0 && gswap_loads_delta == 0)
			printf("    WARNING: no gswap activity detected\n");
	}
}

static void print_header(size_t alloc_mb, size_t mem_limit_mb, int quiet)
{
	unsigned long mem_total_kb, swap_total_kb;
	FILE *f;
	char line[256];

	if (quiet)
		return;

	mem_total_kb = 0;
	swap_total_kb = 0;
	f = fopen("/proc/meminfo", "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			sscanf(line, "MemTotal: %lu kB", &mem_total_kb);
			sscanf(line, "SwapTotal: %lu kB", &swap_total_kb);
		}
		fclose(f);
	}

	printf("=== gswap benchmark ===\n\n");
	printf("  RAM:          %lu MB\n", mem_total_kb / 1024);
	printf("  Swap:         %lu MB\n", swap_total_kb / 1024);
	printf("  Alloc size:   %zu MB\n", alloc_mb);
	printf("  Memory limit: %zu MB (cgroup)\n", mem_limit_mb);
	printf("  Swap target:  ~%zu MB (alloc - limit)\n",
	       alloc_mb > mem_limit_mb ? alloc_mb - mem_limit_mb : 0);
	printf("  Page size:    %d bytes\n", PAGE_SIZE);
	printf("  Data pattern: %s\n",
	       data_mode == DATA_REPEAT ? "repeat (compressible)" :
	       data_mode == DATA_RANDOM ? "random (incompressible)" :
	       "mixed (50/50)");

	if (gswap_available()) {
		char buf[64] = "?";
		FILE *pf = fopen(PARAMS_PATH "/enabled", "r");

		if (pf) {
			if (fgets(buf, sizeof(buf), pf))
				buf[strcspn(buf, "\n")] = '\0';
			fclose(pf);
		}
		printf("  gswap:        %s (module loaded)\n", buf);
		if (gswap_has_pool()) {
			unsigned long pool = 0;

			read_ulong(DEBUGFS_PATH "/pool_total_size", &pool);
			printf("  VRAM pool:    %lu MB\n",
			       pool / (1024 * 1024));
		} else {
			printf("  VRAM pool:    none\n");
		}
	} else {
		printf("  gswap:        not loaded\n");
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-s SIZE_MB] [-m MEM_LIMIT_MB] [-w WORKLOAD] [-i ITERATIONS]\n"
		"          [-d DATA] [-q]\n"
		"\n"
		"  -s SIZE_MB       allocation size in MB (default: %d)\n"
		"  -m MEM_LIMIT_MB  cgroup memory limit in MB (default: SIZE_MB/2)\n"
		"  -w WORKLOAD      sequential, random, fault, or all (default: all)\n"
		"  -i ITERATIONS    read-back passes per workload (default: 3)\n"
		"  -d DATA          page data pattern (default: repeat)\n"
		"                     repeat - single byte per page (very compressible)\n"
		"                     random - pseudorandom (incompressible)\n"
		"                     mixed  - alternating compressible/random pages\n"
		"  -q               quiet/machine-readable output\n"
		"\n"
		"The cgroup limit must be less than the allocation size to force\n"
		"swapping.  Pages beyond the limit will be pushed to swap.\n",
		prog, DEFAULT_ALLOC_MB);
}

int main(int argc, char **argv)
{
	size_t alloc_size, alloc_mb = DEFAULT_ALLOC_MB;
	size_t mem_limit_mb = 0;
	int iterations = 3;
	int quiet = 0;
	const char *workload = "all";
	int opt;
	int do_seq, do_rand, do_fault;

	while ((opt = getopt(argc, argv, "s:m:w:i:d:qh")) != -1) {
		switch (opt) {
		case 's':
			alloc_mb = (size_t)atol(optarg);
			break;
		case 'm':
			mem_limit_mb = (size_t)atol(optarg);
			break;
		case 'w':
			workload = optarg;
			break;
		case 'i':
			iterations = atoi(optarg);
			if (iterations < 1)
				iterations = 1;
			break;
		case 'd':
			if (strcmp(optarg, "repeat") == 0)
				data_mode = DATA_REPEAT;
			else if (strcmp(optarg, "random") == 0)
				data_mode = DATA_RANDOM;
			else if (strcmp(optarg, "mixed") == 0)
				data_mode = DATA_MIXED;
			else {
				fprintf(stderr,
					"error: unknown data pattern '%s'\n",
					optarg);
				usage(argv[0]);
				return 1;
			}
			break;
		case 'q':
			quiet = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "error: must run as root\n");
		return 1;
	}

	if (alloc_mb < 64) {
		fprintf(stderr, "error: alloc size too small (min 64 MB)\n");
		return 1;
	}

	/* Default: memory limit = half the allocation, forcing ~50% to swap */
	if (mem_limit_mb == 0)
		mem_limit_mb = alloc_mb / 2;

	if (mem_limit_mb >= alloc_mb) {
		fprintf(stderr, "error: memory limit (%zu MB) must be less "
			"than allocation (%zu MB)\n", mem_limit_mb, alloc_mb);
		return 1;
	}

	alloc_size = alloc_mb * 1024 * 1024;

	do_seq = (strcmp(workload, "all") == 0 ||
		  strcmp(workload, "sequential") == 0);
	do_rand = (strcmp(workload, "all") == 0 ||
		   strcmp(workload, "random") == 0);
	do_fault = (strcmp(workload, "all") == 0 ||
		    strcmp(workload, "fault") == 0);

	if (!do_seq && !do_rand && !do_fault) {
		fprintf(stderr, "error: unknown workload '%s'\n", workload);
		usage(argv[0]);
		return 1;
	}

	srandom((unsigned int)time(NULL));

	/* Set up cgroup memory constraint */
	if (setup_cgroup(mem_limit_mb) != 0) {
		fprintf(stderr, "error: failed to set up cgroup\n");
		return 1;
	}

	print_header(alloc_mb, mem_limit_mb, quiet);

	if (quiet)
		printf("workload\tsize_mb\twrite_s\tread_s\twrite_mbps\t"
		       "read_mbps\tgswap_stores\tgswap_loads\tswapped_pages\n");

	for (int iter = 0; iter < iterations; iter++) {
		struct bench_result res;
		char label[64];
		int ret;

		if (!quiet && iterations > 1)
			printf("\n========== Iteration %d/%d ==========\n",
			       iter + 1, iterations);

		if (do_seq) {
			cgroup_restore_mem_limit();
			drop_caches();
			ret = bench_sequential(alloc_size, &res);
			if (ret == -2) {
				fprintf(stderr, "FATAL: data corruption\n");
				cleanup_cgroup();
				return 2;
			}
			if (ret < 0) {
				fprintf(stderr, "sequential: mmap failed: %s\n",
					strerror(errno));
				cleanup_cgroup();
				return 1;
			}
			snprintf(label, sizeof(label), "sequential[%d]",
				 iter + 1);
			print_result(label, &res, quiet);
		}

		if (do_rand) {
			cgroup_restore_mem_limit();
			drop_caches();
			ret = bench_random(alloc_size, &res);
			if (ret == -2) {
				fprintf(stderr, "FATAL: data corruption\n");
				cleanup_cgroup();
				return 2;
			}
			if (ret < 0) {
				fprintf(stderr, "random: mmap failed: %s\n",
					strerror(errno));
				cleanup_cgroup();
				return 1;
			}
			snprintf(label, sizeof(label), "random[%d]", iter + 1);
			print_result(label, &res, quiet);
		}

		if (do_fault) {
			cgroup_restore_mem_limit();
			drop_caches();
			ret = bench_fault(alloc_size, &res);
			if (ret == -2) {
				fprintf(stderr, "FATAL: data corruption\n");
				cleanup_cgroup();
				return 2;
			}
			if (ret < 0) {
				fprintf(stderr, "fault: mmap failed: %s\n",
					strerror(errno));
				cleanup_cgroup();
				return 1;
			}
			snprintf(label, sizeof(label), "fault[%d]", iter + 1);
			print_result(label, &res, quiet);
		}
	}

	if (!quiet)
		printf("\ndone.\n");

	cleanup_cgroup();
	return 0;
}
