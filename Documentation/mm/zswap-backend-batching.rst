.. SPDX-License-Identifier: GPL-2.0

=====================================================================
Batched and asynchronous zswap storage backends (design notes / RFC)
=====================================================================

:Status: RFC / design exploration
:Audience: zswap, mm reclaim, and device-memory developers

This document proposes extending the zswap storage-backend interface so that
backends sitting behind a high-latency or asynchronous interconnect (GPU VRAM
over PCIe, CXL, computational storage, NIC/accelerator offload) can exploit
**batching**, **large/sequential transfers**, and **asynchronous submission**.
It builds on the pluggable ``struct zswap_backend`` interface (the small
indirection that replaced the per-pool ``zpool`` selection): zsmalloc is the
default RAM backend, and ``zvram`` stores compressed pages in GPU VRAM.

The proposal is **opt-in and regression-free**: the new operations are optional
and capability-gated.  A backend that does not advertise them (zsmalloc) runs
the existing per-page path unchanged.


Motivation
==========

The current backend interface is **per-page and synchronous**.  Each stored
object is written with one ``write()`` call, and read back with a
``read_begin()``/``read_end()`` pair around a single decompress::

    handle = backend->malloc(pool, dlen, gfp, nid);
    backend->write(pool, handle, buf, dlen);          /* store: one object  */
    ...
    backend->read_begin(pool, handle, sg, len);       /* load:  one object  */
    decompress(sg -> page);
    backend->read_end(pool, handle, sg);

For zsmalloc this is ideal: a store/load is a ``memcpy`` to/from host RAM with
no per-operation setup cost.  For a device backend it leaves most of the
hardware's capability on the floor:

* **Per-operation setup dominates.**  A DMA engine pays descriptor build +
  doorbell + completion-wait per submission.  Amortised over one 2 KiB object
  that overhead is the whole cost; amortised over a batch it disappears.

* **Latency, not bandwidth, is the wall.**  An uncached read from PCIe-attached
  VRAM cannot be cached or prefetched by the CPU.  A single ~2 KiB transfer is
  far too small to fill the read pipeline, so it runs at latency-bound speed.
  Large or batched transfers hide the latency.

* **The device is asynchronous.**  DMA engines and command queues want many
  requests in flight, overlapping transfer with the CPU's (de)compression.  A
  synchronous per-object API serialises everything.

Measured on a discrete GPU (Navi 22, PCIe), ``zvram`` load throughput is
latency-bound and recovers only through *thread* concurrency:

    =========  ==========  ===========
    threads    load        ns / page
    =========  ==========  ===========
    1          184 MiB/s   21198
    12         4286 MiB/s  911
    =========  ==========  ===========

The single-object read floor (~21 us/page) is the per-2 KiB-transfer PCIe
latency; the 23x scaling to 12 threads is just many small reads pipelining by
accident of concurrency.  The same hardware, reading a *cluster* of objects in
one large streaming transfer, reaches single-stream bandwidth in the multi-GB/s
range -- the headroom this proposal targets.

For context, the three storage tiers measured end to end (compressible data,
cold reads):

    ==================  =========  ==========
    tier                load T=1   load T=12
    ==================  =========  ==========
    RAM (zsmalloc)      1186       7968
    VRAM (zvram)        184        4286
    NVMe swapfile       62         67
    ==================  =========  ==========

VRAM is already a legitimate middle tier -- far faster than disk, slower than
RAM.  Batching aims to narrow the gap to RAM on the read path, where the device
is currently most penalised.


The key observation: zswap already has batch points
====================================================

A demand fault needs one page *now* and looks unbatchable.  But the two hot
paths each already operate on a batch that the backend interface throws away:

1. **Store is folio-granular.**  Reclaim hands ``zswap_store()`` a folio and it
   loops over the folio's pages, calling ``backend->write()`` once per page.
   That loop is a ready-made batch of N stores.

2. **Load readahead is cluster-granular.**  ``swapin_readahead()`` /
   ``swap_cluster_readahead()`` brings in a window of pages around the faulting
   page.  Today each becomes an independent ``zswap_load()`` and thus an
   independent ``read_begin()``.  That window is a ready-made batch of N loads
   -- and read-cluster batching is precisely how earlier VRAM-swap prototypes
   reached ~8 GB/s reads.

The proposal is simply to **expose these existing batches to the backend**.


Proposed interface
==================

Add a capability field and two optional batched operations to
``struct zswap_backend``.  The per-page ops remain and are the fallback::

    /* capability bits */
    #define ZSWAP_BE_BATCH   (1u << 0)   /* store_batch / load_batch present */
    #define ZSWAP_BE_ASYNC   (1u << 1)   /* submit/poll model (stage 2)      */

    struct zswap_io_req {
        unsigned long   handle;     /* in:  backend handle               */
        void           *buf;        /* in/out: host RAM object buffer     */
        size_t          len;        /* in:  object length                 */
        int             error;      /* out: per-request status            */
    };

    struct zswap_backend {
        /* ... existing per-page ops: create/destroy/malloc/free/write/
         *     read_begin/read_end/total_pages ... */
        unsigned int caps;

        /* optional: store N objects (a folio) in one submission */
        void (*store_batch)(void *pool, struct zswap_io_req *reqs, int n);
        /* optional: gather N objects (a readahead cluster) in one submission */
        void (*load_batch)(void *pool, struct zswap_io_req *reqs, int n);
    };

zswap uses the batched path only when (a) it has a batch and (b) the backend
advertises ``ZSWAP_BE_BATCH``; otherwise it calls the per-page ops in a loop,
exactly as today.  ``malloc()``/``free()`` are unchanged -- allocation stays
per-object (cheap, host-RAM metadata); only the *data movement* batches.

zsmalloc sets ``caps = 0`` and is byte-for-byte unchanged.  This is the crux of
the upstream argument: **no behaviour change for the default backend, opt-in
benefit for capable ones.**


Why batching wins even with a scattered allocator
=================================================

A natural objection: ``zvram``'s buddy allocator scatters a cluster's objects
across VRAM, so a "sequential" read is impossible.  Two answers:

* **Scatter-gather DMA.**  A DMA engine reads N scattered device addresses into
  one contiguous host buffer in a single submission.  ``load_batch`` over a
  readahead cluster therefore amortises setup and pipelines transfers **without
  any contiguous-storage requirement** -- the gather list is the batch.

* **CPU streaming still benefits.**  Even without a DMA engine, issuing the
  ``MOVNTDQA`` streaming loads for all N objects before waiting keeps many more
  CPU line-fill buffers in flight than a lone 2 KiB read, partially hiding
  latency.

So batching is the primary, lowest-risk lever and needs no allocator change.


A second, optional lever: store-side locality
=============================================

Independently, the backend may use the **store** batch to place a folio's
objects contiguously in device memory (a per-cluster bump region rather than
pure buddy).  Then the corresponding ``load_batch`` is a single *sequential*
transfer -- ideal for a simple/cheap DMA or pure CPU streaming, and the best
case for raw bandwidth.

Locality is optional and composes with batching; a backend can implement
``store_batch`` as plain per-object allocation today and add clustering later.


Asynchronous submission (stage 2)
================================

Batching is synchronous: zswap submits a batch and waits.  A later stage adds a
submit/poll model (gated by ``ZSWAP_BE_ASYNC``) so the backend can drive a DMA
ring and overlap transfer with (de)compression:

* **Store** is naturally deferrable: submit the folio's writes, return, let the
  ring complete in the background (with completion tracked before the entries
  are considered durable).

* **Demand-fault load** cannot be async -- the faulting thread needs the page.
  But **readahead load is a prefetch**: kick off the cluster transfer when the
  readahead window is chosen, so the pages are warm by the time they fault.
  This is where async pays, and it maps onto existing readahead machinery.

Async is more invasive (zswap's store/load are synchronous today), so it is
explicitly staged after synchronous batching.


Staged plan
===========

1. **Synchronous ``load_batch`` + readahead.**  Add ``caps`` and the batched
   ops; teach the readahead load path to collect a cluster's entries and call
   ``load_batch`` when supported.  Implement it in ``zvram`` as a scatter-gather
   streaming read.  Highest value (targets the read gap), least invasive.

2. **Synchronous ``store_batch`` (+ optional locality).**  Batch a folio's
   stores into one submission; optionally cluster objects contiguously to make
   future reads sequential.

3. **Asynchronous submit/poll + readahead prefetch.**  The ambitious stage;
   only worthwhile once 1--2 show the batched device path is transfer-bound
   rather than setup-bound.

Each stage is independently measurable and shippable.


Generality
==========

Nothing here is GPU-specific.  The pattern -- *the consumer has natural batch
points; expose them to the provider; let capable providers exploit
batching/SG/async and fall back per-op otherwise* -- applies to any zswap
backend on an interconnect that rewards batching: CXL type-2/3 memory,
computational-storage devices, and accelerator/NIC-attached compressed pools.
The capability bits and ``zswap_io_req`` vector are deliberately device-neutral.


Open questions
==============

* **Readahead batch assembly.**  ``swapin_readahead`` issues per-page reads
  through the swap cache; collecting a cluster into one ``load_batch`` needs a
  point where the set of zswap entries for the window is known together.  How
  much of the readahead path must change, and can it be confined to zswap?

* **Partial failure.**  ``zswap_io_req.error`` reports per-request status; the
  caller must fall back to disk for the failed members of a batch without
  penalising the rest.

* **Staging memory.**  Batched loads need N host buffers live across the
  decompress.  A mempool sized to the readahead window bounds this; the
  worst-case footprint vs. the readahead order needs sizing.

* **Completion accounting for async stores.**  Entries must not be considered
  durable until the ring signals completion; interaction with writeback and
  invalidation needs care.

* **When does batching lose?**  For tiny batches or a backend whose per-op cost
  is already zero (zsmalloc), the gather has overhead.  The capability gate and
  a minimum-batch threshold avoid regressing those cases.
