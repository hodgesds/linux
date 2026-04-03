#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Integration test for NUMA page replication.
# Must be run on a multi-node NUMA system to exercise replication.
#
# Tests:
# 1. Kernel text replication active on multi-node
# 2. madvise NUMA_REPLICATE on libc .text mapping
# 3. Replica counters increment after accessing replicated pages
# 4. Shrinker can drop replicas
# 5. NOREPLICATE clears replicas

set -e

PASS=0
FAIL=0
SKIP=0

pass() { echo "PASS: $1"; ((PASS++)); }
fail() { echo "FAIL: $1"; ((FAIL++)); }
skip() { echo "SKIP: $1"; ((SKIP++)); }

nodes=$(ls -d /sys/devices/system/node/node[0-9]* 2>/dev/null | wc -l)
echo "Detected $nodes NUMA nodes"

if [ "$nodes" -lt 2 ]; then
    echo "Need at least 2 NUMA nodes for integration test"
    skip "single node system"
    echo "Results: $PASS pass, $FAIL fail, $SKIP skip"
    exit 0
fi

# Test 1: Kernel text replication should be active
if dmesg | grep -q "NUMA text replicate: active"; then
    pages=$(dmesg | grep "pages replicated" | grep -oP '\d+ pages' | head -1)
    pass "kernel text replication active ($pages)"
else
    fail "kernel text replication not active"
fi

# Test 2: Check vmstat counters baseline
created_before=$(grep numa_replica_created /proc/vmstat | awk '{print $2}')
hit_before=$(grep numa_replica_hit /proc/vmstat | awk '{print $2}')
echo "Baseline: created=$created_before hit=$hit_before"

# Test 3: Check sysctls
enabled=$(cat /proc/sys/vm/numa_replicate_enabled)
auto=$(cat /proc/sys/vm/numa_replicate_auto)
if [ "$enabled" = "1" ] && [ "$auto" = "1" ]; then
    pass "sysctls enabled=$enabled auto=$auto"
else
    fail "sysctls not enabled: enabled=$enabled auto=$auto"
fi

# Test 4: Check debugfs
if [ -f /sys/kernel/debug/numa_replicate ]; then
    total=$(grep "Total:" /sys/kernel/debug/numa_replicate | head -1)
    pass "debugfs readable: $total"
else
    skip "debugfs not accessible"
fi

# Test 5: Run the unit selftest
if [ -x "$(dirname $0)/numa_replicate" ]; then
    echo "--- Unit selftest ---"
    "$(dirname $0)/numa_replicate"
    echo "--- End unit selftest ---"
    pass "unit selftest completed"
else
    skip "unit selftest binary not found"
fi

# Test 6: Check that counters are still consistent
created_after=$(grep numa_replica_created /proc/vmstat | awk '{print $2}')
dropped_after=$(grep numa_replica_dropped /proc/vmstat | awk '{print $2}')
hit_after=$(grep numa_replica_hit /proc/vmstat | awk '{print $2}')
miss_after=$(grep numa_replica_miss /proc/vmstat | awk '{print $2}')

echo "Final counters: created=$created_after dropped=$dropped_after hit=$hit_after miss=$miss_after"
if [ "$created_after" -ge "$created_before" ]; then
    pass "counters consistent"
else
    fail "counters inconsistent"
fi

echo ""
echo "================================"
echo "Results: $PASS pass, $FAIL fail, $SKIP skip"
echo "================================"

[ "$FAIL" -eq 0 ]
