# gswap design notes

## Writeback architecture

gswap writeback moves compressed pages from VRAM to the swap device,
freeing VRAM slots.  The writeback worker runs on a dedicated workqueue
(`gswap_writeback_wq`, `WQ_UNBOUND | WQ_MEM_RECLAIM`).

### Key difference from zswap writeback

zswap's writeback runs from a **shrinker** callback invoked during direct
reclaim.  The reclaim path sets `PF_MEMALLOC`, which:
  - gives allocations access to emergency memory reserves
  - prevents recursive direct reclaim within the same task

gswap's writeback runs on a **standalone workqueue worker** — it does NOT
have `PF_MEMALLOC` context.  Two consequences had to be addressed:

1. **Recursive I/O deadlock** — `GFP_KERNEL` allocations in the worker
   (e.g. `swap_cache_alloc_folio`, `xa_cmpxchg` node allocation) can
   trigger direct reclaim, which re-enters the swap path, submitting more
   I/O to the swap device.  With a loop-backed swap device this creates a
   feedback loop: worker needs memory → reclaim swaps → I/O to loop →
   loop needs memory → reclaim swaps → …

   **Fix:** wrap the worker in `memalloc_noio_save()`/`memalloc_noio_restore()`
   to strip `__GFP_IO` from all allocations, breaking the recursive I/O
   cycle while still allowing clean page reclaim.

2. **Swap-cache livelock** — when `swap_cache_alloc_folio()` finds the
   original folio still sitting in the swap cache (`folio_was_allocated ==
   false`), the old code returned `-EAGAIN` and re-queued the entry.  Under
   memory pressure the folio is not reclaimed quickly, so the worker
   busy-loops on the same entries without ever freeing VRAM.

   **Fix:** use the existing folio directly.  It already contains the
   correct decompressed page data from the original `gswap_store()`.
   `folio_trylock()` it, claim the xarray entry, free the VRAM slot, and
   call `__swap_writepage()` — no new allocation or decompression needed.

### Why not PF_MEMALLOC?

Full `PF_MEMALLOC` (dipping into emergency reserves) is not needed.  With
the existing-folio optimisation covering the common swap-cache-present
case, the worker almost always makes forward progress without touching
reserves.  When allocation does fail, the `-EAGAIN` path re-queues the
entry for later retry.  `PF_MEMALLOC` would risk draining emergency
reserves if the VRAM pool is large.
