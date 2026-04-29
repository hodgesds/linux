.. SPDX-License-Identifier: GPL-2.0

=====================
NUMA Page Replication
=====================

Overview
========

NUMA page replication keeps a per-NUMA-node copy ("replica") of selected
read-only file-backed pages so that a CPU on a remote node can fetch the
data from its local memory controller instead of paying a cross-node
load penalty on every reference.  The most common workload that benefits
is shared-library text and ``rodata`` mapped into many processes spread
across NUMA nodes.

Replicas are created on demand at fault time, are tracked outside the
page cache (in a per-mapping XArray keyed by ``(pgoff, nid)``), and are
invalidated transparently whenever the canonical page becomes unsafe to
substitute -- on truncation, hole-punch, dirty transition, write-permission
upgrade, hardware-poison, or memory pressure via the dedicated shrinker.

Page replication is opt-in per VMA via ``madvise()`` and globally gated
by a sysctl, so a kernel built with ``CONFIG_NUMA_PAGE_REPLICATE=y`` has
no observable behavioural change until userspace explicitly enables it.

What gets replicated
====================

A page is eligible for replication only when **all** of the following
hold:

* the kernel is built with ``CONFIG_NUMA_PAGE_REPLICATE=y``,
* the global sysctl ``vm.numa_replicate_enabled`` is set to ``1``,
* the system has at least two online NUMA nodes,
* the VMA has been marked with ``madvise(MADV_NUMA_REPLICATE)`` (sets
  ``VM_NUMA_REPLICATE``),
* the VMA is file-backed and read-only -- writable, anonymous, shmem,
  and DAX VMAs are rejected at ``madvise()`` time,
* the canonical folio is order-0 and clean (large folios and dirty
  folios are skipped silently),
* the faulting CPU is on a different NUMA node than the canonical
  folio,
* the target node is below ``vm.numa_replicate_max_per_node`` and above
  the high watermark (anti-thrash check).

Replicas live entirely in the kernel's per-mapping replica XArray;
they are *not* in ``mapping->i_pages`` and ``folio_mapping(replica)``
returns ``NULL``.  Code that needs the canonical address_space uses
``folio_raw_mapping()``.

Userspace interface
===================

``madvise()``
-------------

Two new advice values control replication on a per-VMA range::

    int madvise(void *addr, size_t length, MADV_NUMA_REPLICATE);
    int madvise(void *addr, size_t length, MADV_NUMA_NOREPLICATE);

``MADV_NUMA_REPLICATE`` marks the range eligible for replica creation.
It pre-allocates the per-mapping replica tree (sleepable ``GFP_KERNEL``
allocation) and sets ``VM_NUMA_REPLICATE`` on the affected VMAs.  Returns
``-EINVAL`` for VMAs that are anonymous, writable, shmem, DAX, or have no
backing file.

``MADV_NUMA_NOREPLICATE`` clears ``VM_NUMA_REPLICATE`` on the range and
invalidates any replicas already present.  This is synchronous from the
caller's point of view; existing PTEs pointing at replicas are unmapped
before ``madvise()`` returns.

If ``CONFIG_NUMA_PAGE_REPLICATE=n``, both advice values fail with
``-EINVAL``.

Note that adding write permission via ``mprotect(... PROT_WRITE)`` to a
``VM_NUMA_REPLICATE`` VMA implicitly clears the flag and invalidates
replicas.  The flag is **not** automatically restored when write
permission is later removed; the application must re-issue
``MADV_NUMA_REPLICATE`` to opt back in.

sysctls
-------

Three sysctls under ``/proc/sys/vm/`` control runtime behaviour.  See
Documentation/admin-guide/sysctl/vm.rst for the authoritative description.

``numa_replicate_enabled``
    Master switch.  Default ``0``.

``numa_replicate_pinned``
    Disables the replica shrinker when set to ``1``.  Default ``0``.

``numa_replicate_max_per_node``
    Per-node hard cap on replica page count.  Default ``65536``
    (256 MiB on 4 KiB pages); ``0`` disables the cap.

vmstat counters
---------------

Four counters in ``/proc/vmstat``:

``numa_replica_created``
    Total replica folios installed via the fault path.

``numa_replica_dropped``
    Total replica folios released, by any path (shrinker, truncate,
    reclaim, dirty, mprotect, NOREPLICATE, hwpoison, inode eviction).

``numa_replica_hit``
    Replica was already present at fault time (no allocation needed).

``numa_replica_miss``
    Replica was absent and a new allocation was attempted.  A miss
    does not guarantee a successful create -- ``..._created`` lags
    ``..._miss`` by the number of skipped allocations.

debugfs
-------

If ``CONFIG_DEBUG_FS=y``, ``/sys/kernel/debug/numa_replicate`` shows
the current replica tally per NUMA node and per registered mapping
(by inode and device), plus the live values of the three sysctls.

Limitations
===========

* **Order-0 only.**  Large folios (transparent huge pages, mTHP, and
  large file folios) are skipped silently; the canonical folio is
  mapped without a replica.  Khugepaged may collapse small folios that
  have replicas into a large folio after the fact -- in that case the
  stale XArray entries persist until the shrinker reclaims them.  Data
  remains correct; replication for the collapsed range is lost until
  the next allocation cycle.

* **Migration blocked.**  Replica folios refuse migration with
  ``-EBUSY``.  Memory hot-unplug of a block containing replicas will
  therefore fail until those replicas are reclaimed or invalidated.
  Operators should ``echo 1 > /proc/sys/vm/drop_caches`` (which
  triggers the replica shrinker) before initiating offlining.

* **No cross-mapping sharing.**  Two processes mapping the same file
  through different mounts will share the same replica tree (one per
  ``address_space``); two processes mapping different files with the
  same content will not.

* **Memcg charging.**  Replicas are charged to the *faulter's* memcg,
  not the canonical folio's.  In containerised setups this means a
  container that triggers replica creation pays for the copy even
  though the original page may belong to a different cgroup.

Internals (brief)
=================

See ``mm/numa_replicate.c`` for the implementation.  The salient
points:

* Replicas are tagged via ``FOLIO_MAPPING_REPLICA`` (bit 2 of
  ``folio->mapping``) so ``folio_mapping()`` returns ``NULL`` for them.
* Insertion uses a two-phase pattern: ``numa_replica_prepare()``
  allocates and copies before PTL; ``numa_replica_install()`` does
  ``xa_store(GFP_NOWAIT)`` under PTL.
* All erase paths use ``xa_erase()`` return-value ownership: only the
  caller that observes a non-NULL return frees the folio, eliminating
  double-free races between the shrinker and invalidation.
* Lock ordering is ``canonical folio lock -> replica folio lock``.
  The shrinker only ever takes the replica lock, so ABBA against the
  invalidation paths is impossible.
* A static branch (``numa_replicate_active``) gates the hot-path checks
  in ``shrink_folio_list()`` and ``folio_mark_dirty()`` so the cost on
  systems without registered replicas is one ``NOP``.
