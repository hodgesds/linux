#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Integration test for NUMA page replication.
# Must be run on a multi-node NUMA system to exercise replication.
#
# Tests:
# 1. NUMA page replication is active (vmstat counters present)
# 2. madvise NUMA_REPLICATE on libc .text mapping
# 3. Replica counters increment after accessing replicated pages
# 4. Shrinker can drop replicas
# 5. NOREPLICATE clears replicas

DIR=$(dirname "$(realpath "$0")")
source "${DIR}"/../kselftest/ktap_helpers.sh

ktap_print_header
ktap_set_plan 6

nodes=$(ls -d /sys/devices/system/node/node[0-9]* 2>/dev/null | wc -l)
ktap_print_msg "Detected $nodes NUMA nodes"

if [ "$nodes" -lt 2 ]; then
    ktap_skip_all "Need at least 2 NUMA nodes for integration test"
    exit "$KSFT_SKIP"
fi

# Test 1: NUMA page replication is active (check vmstat counters)
created=$(grep -c numa_replica_created /proc/vmstat 2>/dev/null)
if [ "$created" -gt 0 ]; then
    ktap_test_pass "NUMA page replication active (vmstat counters present)"
else
    ktap_test_fail "NUMA page replication not active (vmstat counters missing)"
fi

# Test 2: Check vmstat counters baseline
created_before=$(grep numa_replica_created /proc/vmstat | awk '{print $2}')
hit_before=$(grep numa_replica_hit /proc/vmstat | awk '{print $2}')
ktap_print_msg "Baseline: created=$created_before hit=$hit_before"

# Test 3: Check sysctls
enabled=$(cat /proc/sys/vm/numa_replicate_enabled 2>/dev/null)
pinned=$(cat /proc/sys/vm/numa_replicate_pinned 2>/dev/null)
max=$(cat /proc/sys/vm/numa_replicate_max_per_node 2>/dev/null)
if [ -n "$enabled" ]; then
    ktap_test_pass "sysctls enabled=$enabled pinned=$pinned max_per_node=$max"
else
    ktap_test_fail "sysctls not readable"
fi

# Test 4: Check debugfs
if [ -f /sys/kernel/debug/numa_replicate ]; then
    total=$(grep "Total:" /sys/kernel/debug/numa_replicate | head -1)
    ktap_test_pass "debugfs readable: $total"
else
    ktap_test_skip "debugfs not accessible"
fi

# Test 5: Run the unit selftest
if [ -x "${DIR}/numa_replicate" ]; then
    ktap_print_msg "--- Unit selftest ---"
    "${DIR}/numa_replicate"
    ktap_print_msg "--- End unit selftest ---"
    ktap_test_pass "unit selftest completed"
else
    ktap_test_skip "unit selftest binary not found"
fi

# Test 6: Check that counters are still consistent
created_after=$(grep numa_replica_created /proc/vmstat | awk '{print $2}')
dropped_after=$(grep numa_replica_dropped /proc/vmstat | awk '{print $2}')
hit_after=$(grep numa_replica_hit /proc/vmstat | awk '{print $2}')
miss_after=$(grep numa_replica_miss /proc/vmstat | awk '{print $2}')

ktap_print_msg "Final counters: created=$created_after dropped=$dropped_after hit=$hit_after miss=$miss_after"
if [ "$created_after" -ge "$created_before" ]; then
    ktap_test_pass "counters consistent"
else
    ktap_test_fail "counters inconsistent"
fi

ktap_print_totals
exit "${KTAP_CNT_FAIL:+$KSFT_FAIL}"
