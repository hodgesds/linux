# gswap design notes

## Writeback architecture

gswap writeback moves compressed pages from VRAM to the swap device,
freeing VRAM slots.  The writeback worker runs on a dedicated workqueue
(`gswap_writeback_wq`, `WQ_UNBOUND | WQ_MEM_RECLAIM`) using a
`delayed_work` so the retry path can back off under sustained failure.

### Key difference from zswap writeback

zswap's writeback runs from a **shrinker** callback invoked during direct
reclaim.  The reclaim path sets `PF_MEMALLOC`, which:
  - gives allocations access to emergency memory reserves
  - prevents recursive direct reclaim within the same task

gswap's writeback runs on a **standalone workqueue worker** — it does NOT
have `PF_MEMALLOC` context.  Three issues had to be addressed:

1. **Filesystem recursion** — `GFP_KERNEL` allocations in the worker
   (e.g. `swap_cache_alloc_folio`, `xa_cmpxchg` node allocation) can
   trigger direct reclaim, which re-enters the swap path.  With
   filesystem-backed operations this creates recursion.

   **Fix:** wrap the worker in `memalloc_nofs_save()`/`memalloc_nofs_restore()`
   to strip `__GFP_FS` from all allocations, preventing filesystem-level
   recursion.  `__GFP_IO` is intentionally preserved so reclaim can write
   dirty pages and swap pages to disk — without this, folio allocation
   fails under memory pressure because reclaim has nothing clean to free,
   and VRAM never drains.  The recursive swap-out path is safe:
   `gswap_store()` fast-rejects at the pool limit check and falls through
   to `__swap_writepage()`, and no gswap locks are held across the folio
   allocation.

2. **Swap-cache livelock** — when `swap_cache_alloc_folio()` finds the
   original folio still sitting in the swap cache (`folio_was_allocated ==
   false`), the old code returned `-EAGAIN` and re-queued the entry.  Under
   memory pressure the folio is not reclaimed quickly, so the worker
   busy-loops on the same entries without ever freeing VRAM.

   **Fix:** use the existing folio directly.  It already contains the
   correct decompressed page data from the original `gswap_store()`.
   `folio_trylock()` it, claim the xarray entry, free the VRAM slot, and
   call `__swap_writepage()` — no new allocation or decompression needed.

3. **Writeback retry livelock** — when the worker hits 4 consecutive
   failures, it bails out and reschedules.  Without a delay, this creates
   a tight CPU-wasting loop when folio allocation is persistently failing.

   **Fix:** use `delayed_work` with a 100ms backoff
   (`GSWAP_WRITEBACK_RETRY_DELAY`) for the retry path.  Normal triggers
   from `gswap_store()` use `mod_delayed_work(..., 0)` for immediate
   execution.  Teardown uses `cancel_delayed_work_sync()` to properly
   cancel any pending delayed retry before destroying the workqueue.

### Why not PF_MEMALLOC?

Full `PF_MEMALLOC` (dipping into emergency reserves) is not needed.  With
the existing-folio optimisation covering the common swap-cache-present
case, the worker almost always makes forward progress without touching
reserves.  When allocation does fail, the `-EAGAIN` path re-queues the
entry for later retry.  `PF_MEMALLOC` would risk draining emergency
reserves if the VRAM pool is large.

## Building (Arch Linux)

Build the kernel as an Arch Linux package:

    PACMAN_PKGBASE=linux-gswap make pacman-pkg -j$(nproc)

This produces four packages in the tree root:

  - `linux-gswap-<ver>.pkg.tar.zst`           — kernel + modules
  - `linux-gswap-headers-<ver>.pkg.tar.zst`    — headers for out-of-tree modules
  - `linux-gswap-api-headers-<ver>.pkg.tar.zst` — sanitized userspace headers
  - `linux-gswap-debug-<ver>.pkg.tar.zst`      — non-stripped vmlinux

Install with:

    sudo pacman -U linux-gswap-*.pkg.tar.zst

Required kernel command line parameters:

    zswap.enabled=0 gswap.enabled=1 gswap.device=<PCI_SLOT>

Optional parameters:

    gswap.max_pool_percent=25    # percentage of VRAM BAR to use (default 50)
    gswap.compressor=lz4         # compression algorithm (default lz4)
    gswap.ra_size=8              # VRAM readahead window, 0 to disable (default 8)

After boot, check gswap status via debugfs:

    cat /sys/kernel/debug/gswap/*

Stress test example:

    stress-ng --vm 2 --vm-bytes 80% --vm-method all --timeout 30s -M
