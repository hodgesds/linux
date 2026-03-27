// SPDX-License-Identifier: GPL-2.0
/*
 * bench_zvram.c - Benchmark zvram (VRAM-backed zswap) performance
 *
 * Measures:
 *   1. Swap-out throughput (MADV_PAGEOUT to VRAM via zswap)
 *   2. Swap-in throughput (fault pages back from VRAM)
 *   3. Swap-in latency per page
 *   4. Mixed workload (working set > RAM, random access)
 *   5. Sequential vs random swap-in patterns
 *   6. Multi-threaded swap-out/in scaling
 *
 * Usage:
 *   bench_zvram [-s <size_mb>] [-i <iterations>] [-t <tests>] [-v]
 *
 * Requires: zswap.enabled=1 zswap.zpool=zvram
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <getopt.h>
#include <pthread.h>

#define PAGE_SIZE	4096
#define MB		(1024UL * 1024)

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT	21
#endif

static int verbose;

static double timespec_to_ms(struct timespec *ts)
{
	return ts->tv_sec * 1000.0 + ts->tv_nsec / 1e6;
}

static double timespec_diff_ms(struct timespec *start, struct timespec *end)
{
	return timespec_to_ms(end) - timespec_to_ms(start);
}

static long read_debugfs_long(const char *path)
{
	char buf[64];
	int fd;
	ssize_t n;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	return strtol(buf, NULL, 10);
}

static const char *zvram_debugfs = "/sys/kernel/debug/zvram";
static const char *zswap_params = "/sys/module/zswap/parameters";

struct zvram_stats {
	long pool_total;
	long pool_used;
};

static void zvram_get_stats(struct zvram_stats *st)
{
	char p[256];

	snprintf(p, sizeof(p), "%s/pool_total_size", zvram_debugfs);
	st->pool_total = read_debugfs_long(p);
	snprintf(p, sizeof(p), "%s/pool_used_size", zvram_debugfs);
	st->pool_used = read_debugfs_long(p);
}

static void print_stats(const char *label)
{
	struct zvram_stats st;

	zvram_get_stats(&st);
	printf("  %s:\n", label);
	if (st.pool_total >= 0)
		printf("    pool_total: %ld MB\n", st.pool_total / (long)MB);
	if (st.pool_used >= 0)
		printf("    pool_used:  %ld MB\n", st.pool_used / (long)MB);
}

static int check_zvram_active(void)
{
	char p[256], buf[64];
	int fd;
	ssize_t n;

	/* Check zswap is enabled */
	snprintf(p, sizeof(p), "%s/enabled", zswap_params);
	fd = open(p, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "error: cannot read %s\n", p);
		return 0;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n > 0) {
		buf[n] = '\0';
		if (buf[0] != 'Y' && buf[0] != '1') {
			fprintf(stderr, "error: zswap not enabled\n");
			return 0;
		}
	}

	/* Check zpool is zvram */
	snprintf(p, sizeof(p), "%s/zpool", zswap_params);
	fd = open(p, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "warning: cannot read zpool parameter\n");
		return 1;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n > 0) {
		buf[n] = '\0';
		/* Strip trailing newline */
		if (n > 0 && buf[n - 1] == '\n')
			buf[n - 1] = '\0';
		if (strcmp(buf, "zvram") != 0) {
			fprintf(stderr, "warning: zswap.zpool=%s (expected zvram)\n",
				buf);
		}
	}

	return 1;
}

/*
 * Fill memory with a verifiable pattern: each page stores its page
 * index so we can verify data integrity after swap-in.
 */
static void fill_pattern(char *base, size_t size)
{
	size_t i;
	size_t npages = size / PAGE_SIZE;

	for (i = 0; i < npages; i++)
		*(unsigned long *)(base + i * PAGE_SIZE) = i;
}

static int verify_pattern(char *base, size_t size)
{
	size_t i;
	size_t npages = size / PAGE_SIZE;
	int errors = 0;

	for (i = 0; i < npages; i++) {
		unsigned long val = *(unsigned long *)(base + i * PAGE_SIZE);

		if (val != i) {
			if (errors < 10)
				fprintf(stderr, "  MISMATCH page %zu: got %lu\n",
					i, val);
			errors++;
		}
	}
	return errors;
}

/* ------------------------------------------------------------------ */

/*
 * Test 1: Swap-out throughput
 *
 * Allocate + populate memory, then force it out via MADV_PAGEOUT.
 * Measures how fast pages can be compressed and stored in VRAM.
 */
static void bench_swapout(size_t size, int iterations)
{
	struct timespec start, end;
	double total_ms = 0;
	int i;

	printf("\n--- Swap-out throughput (MADV_PAGEOUT -> zvram) ---\n");
	printf("  Size: %zu MB, Iterations: %d\n", size / MB, iterations);

	for (i = 0; i < iterations; i++) {
		struct zvram_stats before, after;
		long pages_stored;

		char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			       -1, 0);
		if (p == MAP_FAILED) {
			perror("  mmap");
			return;
		}
		fill_pattern(p, size);

		zvram_get_stats(&before);

		clock_gettime(CLOCK_MONOTONIC, &start);
		if (madvise(p, size, MADV_PAGEOUT) < 0) {
			perror("  madvise(MADV_PAGEOUT)");
			munmap(p, size);
			return;
		}
		clock_gettime(CLOCK_MONOTONIC, &end);

		zvram_get_stats(&after);
		pages_stored = (after.pool_used - before.pool_used) / PAGE_SIZE;

		double ms = timespec_diff_ms(&start, &end);
		double mbps = (size / (double)MB) / (ms / 1000.0);

		if (verbose)
			printf("  [%d] %.1f ms  (%.1f MB/s, ~%ld pages to VRAM)\n",
			       i, ms, mbps, pages_stored);

		total_ms += ms;
		munmap(p, size);
	}

	double avg_ms = total_ms / iterations;

	printf("  avg: %.1f ms  (%.1f MB/s)\n",
	       avg_ms, (size / (double)MB) / (avg_ms / 1000.0));
}

/*
 * Test 2: Swap-in throughput
 *
 * Force pages out, then fault them all back in sequentially.
 */
static void bench_swapin(size_t size, int iterations)
{
	struct timespec start, end;
	double total_ms = 0;
	int i;

	printf("\n--- Swap-in throughput (sequential fault from zvram) ---\n");
	printf("  Size: %zu MB, Iterations: %d\n", size / MB, iterations);

	for (i = 0; i < iterations; i++) {
		volatile char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
					-1, 0);
		if (p == MAP_FAILED) {
			perror("  mmap");
			return;
		}
		fill_pattern((char *)p, size);

		if (madvise((void *)p, size, MADV_PAGEOUT) < 0) {
			perror("  madvise");
			munmap((void *)p, size);
			return;
		}

		/* Sequential swap-in: touch every page */
		clock_gettime(CLOCK_MONOTONIC, &start);
		for (size_t off = 0; off < size; off += PAGE_SIZE)
			(void)p[off];
		clock_gettime(CLOCK_MONOTONIC, &end);

		double ms = timespec_diff_ms(&start, &end);
		double mbps = (size / (double)MB) / (ms / 1000.0);

		/* Verify data integrity */
		int errors = verify_pattern((char *)p, size);

		if (verbose || errors)
			printf("  [%d] %.1f ms  (%.1f MB/s)%s\n",
			       i, ms, mbps,
			       errors ? "  DATA CORRUPTION" : "");

		total_ms += ms;
		munmap((void *)p, size);
	}

	double avg_ms = total_ms / iterations;

	printf("  avg: %.1f ms  (%.1f MB/s)\n",
	       avg_ms, (size / (double)MB) / (avg_ms / 1000.0));
}

/*
 * Test 3: Swap-in latency per page
 *
 * Swap out pages and measure individual page fault latency.
 * Uses a subset to keep runtime reasonable.
 */
static void bench_swapin_latency(size_t size, int iterations)
{
	struct timespec start, end;
	size_t npages = size / PAGE_SIZE;
	size_t sample_pages = npages < 4096 ? npages : 4096;
	double total_ns = 0;
	int i;

	printf("\n--- Swap-in latency per page ---\n");
	printf("  Size: %zu MB, Sample: %zu pages, Iterations: %d\n",
	       size / MB, sample_pages, iterations);

	for (i = 0; i < iterations; i++) {
		volatile char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
					-1, 0);
		if (p == MAP_FAILED) {
			perror("  mmap");
			return;
		}
		fill_pattern((char *)p, size);

		if (madvise((void *)p, size, MADV_PAGEOUT) < 0) {
			perror("  madvise");
			munmap((void *)p, size);
			return;
		}

		double iter_ns = 0;
		size_t stride = npages / sample_pages;

		for (size_t j = 0; j < sample_pages; j++) {
			size_t off = j * stride * PAGE_SIZE;

			clock_gettime(CLOCK_MONOTONIC, &start);
			(void)p[off];
			clock_gettime(CLOCK_MONOTONIC, &end);

			iter_ns += timespec_diff_ms(&start, &end) * 1e6;
		}

		double avg_ns = iter_ns / sample_pages;

		if (verbose)
			printf("  [%d] avg: %.0f ns/page  (%.1f us/page)\n",
			       i, avg_ns, avg_ns / 1000);

		total_ns += iter_ns;
		munmap((void *)p, size);
	}

	double grand_avg = total_ns / (iterations * sample_pages);

	printf("  avg: %.0f ns/page  (%.1f us/page)\n",
	       grand_avg, grand_avg / 1000);
}

/*
 * Test 4: Random swap-in pattern
 *
 * Swap out pages, then fault them back in random order.
 * This defeats any readahead and measures worst-case latency.
 */
static void bench_random_swapin(size_t size, int iterations)
{
	struct timespec start, end;
	size_t npages = size / PAGE_SIZE;
	size_t *order;
	double total_ms = 0;
	int i;

	printf("\n--- Random swap-in pattern ---\n");
	printf("  Size: %zu MB (%zu pages), Iterations: %d\n",
	       size / MB, npages, iterations);

	order = malloc(npages * sizeof(size_t));
	if (!order) {
		perror("  malloc");
		return;
	}

	/* Fisher-Yates shuffle */
	for (size_t j = 0; j < npages; j++)
		order[j] = j;

	for (i = 0; i < iterations; i++) {
		volatile char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
					-1, 0);
		if (p == MAP_FAILED) {
			perror("  mmap");
			break;
		}
		fill_pattern((char *)p, size);

		if (madvise((void *)p, size, MADV_PAGEOUT) < 0) {
			perror("  madvise");
			munmap((void *)p, size);
			break;
		}

		/* Shuffle for this iteration */
		for (size_t j = npages - 1; j > 0; j--) {
			size_t k = (size_t)rand() % (j + 1);
			size_t tmp = order[j];

			order[j] = order[k];
			order[k] = tmp;
		}

		clock_gettime(CLOCK_MONOTONIC, &start);
		for (size_t j = 0; j < npages; j++)
			(void)p[order[j] * PAGE_SIZE];
		clock_gettime(CLOCK_MONOTONIC, &end);

		double ms = timespec_diff_ms(&start, &end);
		double mbps = (size / (double)MB) / (ms / 1000.0);

		if (verbose)
			printf("  [%d] %.1f ms  (%.1f MB/s)\n", i, ms, mbps);

		total_ms += ms;
		munmap((void *)p, size);
	}

	double avg_ms = total_ms / iterations;

	printf("  avg: %.1f ms  (%.1f MB/s)\n",
	       avg_ms, (size / (double)MB) / (avg_ms / 1000.0));

	free(order);
}

/*
 * Test 5: Multi-threaded swap-out/in scaling
 *
 * Each thread allocates its own region, swaps it out, then swaps it in.
 * Measures whether zvram throughput scales with thread count.
 */
struct mt_swap_arg {
	size_t size;
	double swapout_ms;
	double swapin_ms;
	int ok;
};

static void *mt_swap_worker(void *arg)
{
	struct mt_swap_arg *a = arg;
	struct timespec start, end;
	volatile char *p;

	p = mmap(NULL, a->size, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (p == MAP_FAILED) {
		a->ok = 0;
		return NULL;
	}
	fill_pattern((char *)p, a->size);

	/* Swap out */
	clock_gettime(CLOCK_MONOTONIC, &start);
	madvise((void *)p, a->size, MADV_PAGEOUT);
	clock_gettime(CLOCK_MONOTONIC, &end);
	a->swapout_ms = timespec_diff_ms(&start, &end);

	/* Swap in (sequential) */
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (size_t off = 0; off < a->size; off += PAGE_SIZE)
		(void)p[off];
	clock_gettime(CLOCK_MONOTONIC, &end);
	a->swapin_ms = timespec_diff_ms(&start, &end);

	a->ok = 1;
	munmap((void *)p, a->size);
	return NULL;
}

static void bench_mt_swap(size_t size, int iterations)
{
	int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	int thread_counts[] = { 1, 2, 4, 8 };
	int tc, i;

	printf("\n--- Multi-threaded swap scaling ---\n");
	printf("  Per-thread size: %zu MB, CPUs: %d\n", size / MB, ncpus);

	for (tc = 0; tc < (int)(sizeof(thread_counts) / sizeof(thread_counts[0])); tc++) {
		int nthreads = thread_counts[tc];
		double total_out = 0, total_in = 0;

		if (nthreads > ncpus)
			break;

		printf("  threads=%d:\n", nthreads);

		for (i = 0; i < iterations; i++) {
			pthread_t *threads = calloc(nthreads, sizeof(pthread_t));
			struct mt_swap_arg *args = calloc(nthreads,
							  sizeof(struct mt_swap_arg));
			int t;
			double max_out = 0, max_in = 0;
			size_t total_size = 0;

			if (!threads || !args) {
				free(threads);
				free(args);
				return;
			}

			for (t = 0; t < nthreads; t++) {
				args[t].size = size;
				pthread_create(&threads[t], NULL,
					       mt_swap_worker, &args[t]);
			}
			for (t = 0; t < nthreads; t++)
				pthread_join(threads[t], NULL);

			for (t = 0; t < nthreads; t++) {
				if (!args[t].ok)
					continue;
				total_size += size;
				if (args[t].swapout_ms > max_out)
					max_out = args[t].swapout_ms;
				if (args[t].swapin_ms > max_in)
					max_in = args[t].swapin_ms;
			}

			double out_mbps = (total_size / (double)MB) / (max_out / 1000.0);
			double in_mbps = (total_size / (double)MB) / (max_in / 1000.0);

			if (verbose)
				printf("    [%d] out: %.1f ms (%.1f MB/s)  "
				       "in: %.1f ms (%.1f MB/s)\n",
				       i, max_out, out_mbps, max_in, in_mbps);

			total_out += max_out;
			total_in += max_in;

			free(threads);
			free(args);
		}

		size_t agg_size = (size_t)nthreads * size;
		double avg_out = total_out / iterations;
		double avg_in = total_in / iterations;

		printf("    avg out: %.1f ms (%.1f MB/s)  "
		       "in: %.1f ms (%.1f MB/s)\n",
		       avg_out, (agg_size / (double)MB) / (avg_out / 1000.0),
		       avg_in, (agg_size / (double)MB) / (avg_in / 1000.0));
	}
}

/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"\n"
		"Options:\n"
		"  -s MB      Allocation size in MB (default: 64)\n"
		"  -i ITERS   Iterations per test (default: 3)\n"
		"  -t TESTS   Comma-separated: swapout,swapin,latency,\n"
		"             random,mt,all (default: all)\n"
		"  -v         Verbose (per-iteration output)\n"
		"  -h         Help\n",
		prog);
}

int main(int argc, char **argv)
{
	size_t size_mb = 64;
	int iterations = 3;
	int opt;
	int do_swapout = 1, do_swapin = 1, do_latency = 1;
	int do_random = 1, do_mt = 1;

	srand(42);

	while ((opt = getopt(argc, argv, "s:i:t:vh")) != -1) {
		switch (opt) {
		case 's':
			size_mb = atol(optarg);
			break;
		case 'i':
			iterations = atoi(optarg);
			break;
		case 't':
			do_swapout = do_swapin = do_latency = 0;
			do_random = do_mt = 0;
			if (strstr(optarg, "all")) {
				do_swapout = do_swapin = do_latency = 1;
				do_random = do_mt = 1;
			} else {
				if (strstr(optarg, "swapout"))
					do_swapout = 1;
				if (strstr(optarg, "swapin"))
					do_swapin = 1;
				if (strstr(optarg, "latency"))
					do_latency = 1;
				if (strstr(optarg, "random"))
					do_random = 1;
				if (strstr(optarg, "mt"))
					do_mt = 1;
			}
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (!check_zvram_active())
		fprintf(stderr, "warning: zvram may not be active, "
			"results may reflect disk swap\n\n");

	size_t size = size_mb * MB;

	printf("=== zvram (VRAM-backed zswap) Benchmark ===\n");
	printf("  Size:      %zu MB\n", size_mb);
	printf("  Iters:     %d\n", iterations);

	print_stats("Initial state");

	if (do_swapout)
		bench_swapout(size, iterations);
	if (do_swapin)
		bench_swapin(size, iterations);
	if (do_latency)
		bench_swapin_latency(size, iterations);
	if (do_random)
		bench_random_swapin(size, iterations);
	if (do_mt)
		bench_mt_swap(size, iterations);

	print_stats("Final state");
	printf("\n=== Done ===\n");

	return 0;
}
