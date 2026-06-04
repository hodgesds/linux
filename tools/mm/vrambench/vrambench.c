// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * vrambench - out-of-tree module to measure WC read bandwidth from GPU VRAM.
 *
 * Reserves a chunk of VRAM via a DRM dumb buffer (same as zvram), maps it
 * write-combining, and times drm_memcpy_from_wc() reads in several shapes to
 * decompose where zvram's load path loses bandwidth vs a large contiguous read:
 *
 *   contig   : one big drm_memcpy_from_wc (best case)
 *   chunked  : the same bytes as many small 2 KiB reads at *sequential* offsets
 *              (isolates the per-small-transfer penalty)
 *   scattered: many small 2 KiB reads at scattered offsets (adds the
 *              random-address penalty -- what the buddy allocator produces)
 *
 * Each is run single-threaded and across N kthreads (aggregate).  Results go to
 * dmesg on insmod and to /sys/kernel/debug/vrambench/results.
 *
 * Build:  make -C /lib/modules/$(uname -r)/build M=$PWD modules
 * Run:    sudo insmod vrambench.ko [device=0000:03:00.0] [size_mb=1024]
 *         dmesg | tail; cat /sys/kernel/debug/vrambench/results
 *         sudo rmmod vrambench
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/iosys-map.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include <drm/drm_drv.h>
#include <drm/drm_client.h>
#include <drm/drm_dumb_buffers.h>
#include <drm/drm_file.h>
#include <drm/drm_gem.h>
#include <drm/drm_cache.h>

static char *device;
module_param(device, charp, 0444);
MODULE_PARM_DESC(device, "PCI slot of GPU (e.g. 0000:03:00.0); default first dGPU");

static unsigned long size_mb = 1024;
module_param(size_mb, ulong, 0444);
MODULE_PARM_DESC(size_mb, "MiB of VRAM to reserve");

#define VB_WIDTH	4096
#define VB_BPP		8
#define VB_STRIDE	VB_WIDTH
#define VB_CHUNK	(2UL << 10)	/* small-read size (a typical comp obj) */
#define VB_BLOCK	(64UL << 20)	/* per-thread contiguous slice */
#define VB_MS		300		/* multi-thread measurement window */
#define VB_THREADS	12

static struct pci_dev *vb_pdev;
static struct drm_client_dev vb_client;
static struct drm_gem_object *vb_obj;
static struct iosys_map vb_map;
static unsigned long vb_size;
static bool vb_client_ready;
static struct dentry *vb_dir;
static char vb_results[1024];

static const struct drm_client_funcs vb_funcs = { .owner = THIS_MODULE };

/* MiB/s from bytes and nanoseconds. */
static u64 mibps(u64 bytes, u64 ns)
{
	return ns ? (bytes >> 20) * NSEC_PER_SEC / ns : 0;
}

/* One contiguous read of @len from VRAM @off into @dst. */
static void vb_read(void *dst, unsigned long off, unsigned long len)
{
	struct iosys_map d = IOSYS_MAP_INIT_VADDR(dst);
	struct iosys_map s = vb_map;

	iosys_map_incr(&s, off);
	drm_memcpy_from_wc(&d, &s, len);
}

/* One contiguous write of @len from @src into VRAM @off (WC store path). */
static void vb_write(const void *src, unsigned long off, unsigned long len)
{
	iosys_map_memcpy_to(&vb_map, off, src, len);
	wmb();	/* flush write-combining buffers */
}

static u64 bench_write_contig(void *buf)
{
	u64 best = 0;
	int i;

	for (i = 0; i < 5; i++) {
		ktime_t t0 = ktime_get();
		u64 r;

		vb_write(buf, 0, VB_BLOCK);
		r = mibps(VB_BLOCK, ktime_to_ns(ktime_sub(ktime_get(), t0)));
		best = max(best, r);
	}
	return best;
}

/* ---- single-threaded shapes; return MiB/s ---- */

static u64 bench_contig(void *buf)
{
	u64 best = 0;
	int i;

	for (i = 0; i < 5; i++) {
		ktime_t t0 = ktime_get();
		u64 r;

		vb_read(buf, 0, VB_BLOCK);
		r = mibps(VB_BLOCK, ktime_to_ns(ktime_sub(ktime_get(), t0)));
		best = max(best, r);
	}
	return best;
}

static u64 bench_small(void *buf, bool scatter)
{
	unsigned long n = VB_BLOCK / VB_CHUNK, usable = vb_size - VB_CHUNK;
	u64 best = 0;
	int it;

	for (it = 0; it < 5; it++) {
		ktime_t t0 = ktime_get();
		unsigned long i;
		u64 r;

		for (i = 0; i < n; i++) {
			unsigned long off = scatter ?
				((i * 4099UL) % (usable / VB_CHUNK)) * VB_CHUNK :
				(i * VB_CHUNK) % usable;

			vb_read(buf, off, VB_CHUNK);
		}
		r = mibps(VB_BLOCK, ktime_to_ns(ktime_sub(ktime_get(), t0)));
		best = max(best, r);
	}
	return best;
}

/* ---- multi-threaded contiguous aggregate ---- */

struct vb_ctx {
	void		*buf;
	unsigned long	off;
	ktime_t		deadline;
	u64		bytes;
	bool		write;
};

static int vb_thread(void *arg)
{
	struct vb_ctx *c = arg;

	while (!kthread_should_stop()) {
		if (!ktime_before(ktime_get(), c->deadline)) {
			schedule_timeout_uninterruptible(1);
			continue;
		}
		if (c->write)
			vb_write(c->buf, c->off, VB_BLOCK);
		else
			vb_read(c->buf, c->off, VB_BLOCK);
		c->bytes += VB_BLOCK;
	}
	return 0;
}

static u64 bench_contig_mt(int nthreads, bool write)
{
	struct vb_ctx ctx[VB_THREADS];
	struct task_struct *th[VB_THREADS] = { };
	void *bufs[VB_THREADS] = { };
	u64 total = 0;
	int i, n = nthreads;

	while (n > 1 && vb_size < (unsigned long)n * VB_BLOCK)
		n--;
	for (i = 0; i < n; i++) {
		bufs[i] = vmalloc(VB_BLOCK);
		if (!bufs[i]) {
			n = i;
			break;
		}
	}
	if (!n)
		return 0;

	for (i = 0; i < n; i++) {
		ctx[i].buf = bufs[i];
		ctx[i].off = (unsigned long)i * VB_BLOCK;
		ctx[i].bytes = 0;
		ctx[i].write = write;
		ctx[i].deadline = ktime_add_ms(ktime_get(), VB_MS);
		th[i] = kthread_run(vb_thread, &ctx[i], "vrambench%d", i);
		if (IS_ERR(th[i]))
			th[i] = NULL;
	}
	msleep(VB_MS + 50);
	for (i = 0; i < n; i++)
		if (th[i])
			kthread_stop(th[i]);
	for (i = 0; i < n; i++) {
		total += ctx[i].bytes;
		vfree(bufs[i]);
	}
	return (total >> 20) * 1000 / VB_MS;
}

static void vb_run(void)
{
	void *buf = vmalloc(VB_BLOCK);
	u64 c1, ks, kc, rmt, w1, wmt;

	if (!buf)
		return;
	c1 = bench_contig(buf);
	kc = bench_small(buf, false);
	ks = bench_small(buf, true);
	w1 = bench_write_contig(buf);
	vfree(buf);
	rmt = bench_contig_mt(VB_THREADS, false);
	wmt = bench_contig_mt(VB_THREADS, true);

	scnprintf(vb_results, sizeof(vb_results),
		  "VRAM WC bandwidth (%lu MiB reserved on %s):\n"
		  "  READ  contiguous    1-thread : %llu MiB/s\n"
		  "  READ  2KiB sequential 1-thr  : %llu MiB/s\n"
		  "  READ  2KiB scattered  1-thr  : %llu MiB/s\n"
		  "  READ  contiguous   %d-thread : %llu MiB/s (aggregate)\n"
		  "  WRITE contiguous    1-thread : %llu MiB/s\n"
		  "  WRITE contiguous   %d-thread : %llu MiB/s (aggregate)\n",
		  vb_size >> 20, pci_name(vb_pdev),
		  c1, kc, ks, VB_THREADS, rmt, w1, VB_THREADS, wmt);
	pr_info("%s", vb_results);
}

static int vb_results_show(struct seq_file *m, void *v)
{
	vb_run();
	seq_printf(m, "%s", vb_results);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(vb_results);

static struct pci_dev *vb_find_gpu(void)
{
	unsigned int classes[] = { PCI_CLASS_DISPLAY_VGA, PCI_CLASS_DISPLAY_3D };
	struct pci_dev *pdev;
	unsigned int c;

	for (c = 0; c < ARRAY_SIZE(classes); c++) {
		pdev = NULL;
		while ((pdev = pci_get_class(classes[c] << 8, pdev))) {
			if (device && *device &&
			    strcmp(dev_name(&pdev->dev), device))
				continue;
			return pci_dev_get(pdev);
		}
	}
	return NULL;
}

static int vb_reserve(void)
{
	struct drm_mode_create_dumb args = {};
	struct drm_device *drm;
	struct drm_gem_object *obj;
	int ret;

	drm = drm_dev_get_by_parent(&vb_pdev->dev);
	if (!drm)
		return -ENODEV;

	ret = drm_client_init(drm, &vb_client, "vrambench", &vb_funcs);
	if (ret)
		goto out_put;

	vb_size = min(size_mb << 20, 4000UL << 20);	/* dumb buffer u32 cap */
	args.width = VB_WIDTH;
	args.height = vb_size / VB_STRIDE;
	args.bpp = VB_BPP;
	vb_size = (unsigned long)args.height * VB_STRIDE;
	ret = drm_mode_create_dumb(drm, &args, vb_client.file);
	if (ret)
		goto out_release;

	obj = drm_gem_object_lookup(vb_client.file, args.handle);
	drm_mode_destroy_dumb(drm, args.handle, vb_client.file);
	if (!obj) {
		ret = -ENOENT;
		goto out_release;
	}
	ret = drm_gem_vmap(obj, &vb_map);
	if (ret) {
		drm_gem_object_put(obj);
		goto out_release;
	}
	vb_obj = obj;
	drm_client_register(&vb_client);
	vb_client_ready = true;
	drm_dev_put(drm);
	pr_info("reserved %lu MiB on %s (iomem=%d)\n",
		vb_size >> 20, pci_name(vb_pdev), vb_map.is_iomem);
	return 0;

out_release:
	drm_client_release(&vb_client);
out_put:
	drm_dev_put(drm);
	return ret;
}

static int __init vrambench_init(void)
{
	int ret;

	vb_pdev = vb_find_gpu();
	if (!vb_pdev) {
		pr_err("no matching GPU found\n");
		return -ENODEV;
	}
	ret = vb_reserve();
	if (ret) {
		pr_err("VRAM reserve failed: %d\n", ret);
		pci_dev_put(vb_pdev);
		return ret;
	}

	vb_dir = debugfs_create_dir("vrambench", NULL);
	debugfs_create_file("results", 0444, vb_dir, NULL, &vb_results_fops);

	vb_run();	/* run once at load */
	return 0;
}

static void __exit vrambench_exit(void)
{
	debugfs_remove_recursive(vb_dir);
	if (vb_obj) {
		drm_gem_vunmap(vb_obj, &vb_map);
		drm_gem_object_put(vb_obj);
	}
	if (vb_client_ready)
		drm_client_release(&vb_client);
	pci_dev_put(vb_pdev);
}

module_init(vrambench_init);
module_exit(vrambench_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GPU VRAM WC read-bandwidth microbenchmark");
