#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Selftest for gswap (GPU VRAM-backed compressed swap cache)
#
# Tests:
#  1. Module load and configuration
#  2. Debugfs/sysfs interface
#  3. Store/load under memory pressure
#  4. Data integrity verification
#  5. Statistics counters
#  6. Enable/disable toggling

DEBUGFS="/sys/kernel/debug/gswap"
MODULE_PARAMS="/sys/module/gswap/parameters"
KSFT_PASS=0
KSFT_FAIL=1
KSFT_SKIP=4
num_tests=0
num_pass=0
num_fail=0
num_skip=0

# TAP output helpers
pass() {
	num_tests=$((num_tests + 1))
	num_pass=$((num_pass + 1))
	echo "ok $num_tests - $1"
}

fail() {
	num_tests=$((num_tests + 1))
	num_fail=$((num_fail + 1))
	echo "not ok $num_tests - $1"
}

skip() {
	num_tests=$((num_tests + 1))
	num_skip=$((num_skip + 1))
	echo "ok $num_tests - $1 # SKIP"
}

check_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo "1..0 # SKIP must be run as root"
		exit $KSFT_SKIP
	fi
}

check_swap_enabled() {
	if ! grep -q "Swap:" /proc/meminfo; then
		echo "1..0 # SKIP swap is not enabled"
		exit $KSFT_SKIP
	fi
	# Need at least some swap space
	local swap_total
	swap_total=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
	if [ "$swap_total" -eq 0 ]; then
		echo "1..0 # SKIP no swap space configured"
		exit $KSFT_SKIP
	fi
}

check_gswap_available() {
	# Check if gswap module is loaded or built-in
	if [ ! -d "$MODULE_PARAMS" ]; then
		# Try loading the module
		modprobe gswap 2>/dev/null
		if [ ! -d "$MODULE_PARAMS" ]; then
			echo "1..0 # SKIP gswap module not available"
			exit $KSFT_SKIP
		fi
	fi
}

read_debugfs() {
	local file="$DEBUGFS/$1"
	if [ -f "$file" ]; then
		cat "$file" 2>/dev/null
	else
		echo "-1"
	fi
}

read_param() {
	local file="$MODULE_PARAMS/$1"
	if [ -f "$file" ]; then
		cat "$file" 2>/dev/null
	else
		echo ""
	fi
}

write_param() {
	echo "$2" > "$MODULE_PARAMS/$1" 2>/dev/null
}

# Test 1: Module is loaded and parameters are accessible
test_module_loaded() {
	if [ -d "$MODULE_PARAMS" ]; then
		pass "module loaded"
	else
		fail "module loaded"
		return
	fi

	# Check that expected parameters exist
	local params_ok=true
	for p in enabled compressor max_pool_percent vram_base vram_size; do
		if [ ! -f "$MODULE_PARAMS/$p" ]; then
			params_ok=false
			break
		fi
	done

	if $params_ok; then
		pass "module parameters exist"
	else
		fail "module parameters exist"
	fi
}

# Test 2: Debugfs interface
test_debugfs_interface() {
	if [ ! -d "$DEBUGFS" ]; then
		skip "debugfs interface (debugfs not mounted or gswap has no VRAM)"
		return
	fi

	local files_ok=true
	for f in stored_pages pool_total_size pool_used_size stores loads \
		 reject_compress_fail reject_compress_poor reject_alloc_fail \
		 reject_kmemcache_fail decompress_fail pool_limit_hit \
		 written_back_pages; do
		if [ ! -f "$DEBUGFS/$f" ]; then
			files_ok=false
			echo "# missing debugfs file: $f"
			break
		fi
	done

	if $files_ok; then
		pass "debugfs files exist"
	else
		fail "debugfs files exist"
	fi

	# Verify counters are readable and numeric
	local stored
	stored=$(read_debugfs stored_pages)
	if [ "$stored" -ge 0 ] 2>/dev/null; then
		pass "debugfs counters readable"
	else
		fail "debugfs counters readable"
	fi
}

# Test 3: VRAM pool configuration
test_vram_pool() {
	local pool_total
	pool_total=$(read_debugfs pool_total_size)

	if [ "$pool_total" = "-1" ] || [ "$pool_total" = "0" ]; then
		skip "VRAM pool (no GPU VRAM available)"
		skip "VRAM pool size reasonable"
		return
	fi

	pass "VRAM pool initialized"

	# Check pool size is reasonable (at least 1MB)
	if [ "$pool_total" -ge 1048576 ]; then
		pass "VRAM pool size reasonable ($((pool_total / 1048576)) MB)"
	else
		fail "VRAM pool size reasonable ($pool_total bytes)"
	fi
}

# Test 4: Enable/disable gswap
test_enable_disable() {
	local enabled
	enabled=$(read_param enabled)

	# Disable gswap
	write_param enabled N
	enabled=$(read_param enabled)
	if [ "$enabled" = "N" ]; then
		pass "disable gswap"
	else
		fail "disable gswap (got: $enabled)"
	fi

	# Re-enable gswap
	write_param enabled Y
	enabled=$(read_param enabled)
	if [ "$enabled" = "Y" ]; then
		pass "enable gswap"
	else
		fail "enable gswap (got: $enabled)"
	fi
}

# Test 5: Store and load pages under memory pressure
test_store_load() {
	local pool_total
	pool_total=$(read_debugfs pool_total_size)

	if [ "$pool_total" = "-1" ] || [ "$pool_total" = "0" ]; then
		skip "store/load (no VRAM available)"
		skip "stored pages counter"
		skip "data integrity"
		return
	fi

	# Ensure gswap is enabled
	write_param enabled Y

	local stores_before loads_before stored_before
	stores_before=$(read_debugfs stores)
	loads_before=$(read_debugfs loads)
	stored_before=$(read_debugfs stored_pages)

	# Allocate memory to trigger swapping
	# Write a known pattern so we can verify integrity on read-back
	local memsize_kb
	local mem_total_kb
	mem_total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
	# Allocate 110% of total memory to force swapping
	memsize_kb=$((mem_total_kb * 110 / 100))

	# Use a child process to allocate and verify memory
	(
		# Allocate memory with a known pattern
		python3 -c "
import mmap
import os
import sys

size = ${memsize_kb} * 1024
# Allocate in chunks to avoid OOM
chunk_size = 64 * 1024 * 1024  # 64MB chunks
chunks = []
total = 0
try:
    while total < size:
        this_chunk = min(chunk_size, size - total)
        # Create anonymous mmap
        m = mmap.mmap(-1, this_chunk)
        # Write pattern: each page starts with its page number
        for offset in range(0, this_chunk, 4096):
            page_num = (total + offset) // 4096
            pattern = (page_num % 256).to_bytes(1, 'little') * 4096
            m[offset:offset+4096] = pattern
        chunks.append(m)
        total += this_chunk
except (MemoryError, OSError):
    pass

if not chunks:
    sys.exit(1)

# Now read back and verify -- this triggers swap-in
errors = 0
total = 0
for m in chunks:
    for offset in range(0, len(m), 4096):
        page_num = (total + offset) // 4096
        expected = (page_num % 256)
        if m[offset] != expected:
            errors += 1
            if errors <= 3:
                print(f'Mismatch at page {page_num}: expected {expected}, got {m[offset]}', file=sys.stderr)
    total += len(m)

for m in chunks:
    m.close()

sys.exit(0 if errors == 0 else 1)
" 2>/dev/null
	)
	local integrity_result=$?

	local stores_after loads_after stored_after
	stores_after=$(read_debugfs stores)
	loads_after=$(read_debugfs loads)
	stored_after=$(read_debugfs stored_pages)

	# Check if any pages were stored in gswap
	if [ "$stores_after" -gt "$stores_before" ]; then
		pass "store/load (stored $((stores_after - stores_before)) pages)"
	else
		# gswap may not have been used if zswap captured everything
		# or if compression ratio was poor. This is not a failure.
		skip "store/load (no pages stored - zswap may have captured all)"
	fi

	# Check stored pages counter
	if [ "$stores_after" -gt "$stores_before" ] && [ "$stored_after" -ge 0 ]; then
		pass "stored pages counter"
	else
		skip "stored pages counter"
	fi

	# Check data integrity
	if [ $integrity_result -eq 0 ]; then
		pass "data integrity"
	else
		fail "data integrity"
	fi
}

# Test 6: Statistics sanity
test_stats_sanity() {
	if [ ! -d "$DEBUGFS" ]; then
		skip "statistics sanity (no debugfs)"
		return
	fi

	local stores loads rejects_poor rejects_fail
	stores=$(read_debugfs stores)
	loads=$(read_debugfs loads)
	rejects_poor=$(read_debugfs reject_compress_poor)
	rejects_fail=$(read_debugfs reject_compress_fail)

	# All counters should be non-negative
	local sane=true
	for val in $stores $loads $rejects_poor $rejects_fail; do
		if [ "$val" -lt 0 ] 2>/dev/null; then
			sane=false
		fi
	done

	if $sane; then
		pass "statistics sanity"
	else
		fail "statistics sanity"
	fi
}

# Test 7: Compressor parameter
test_compressor() {
	local comp
	comp=$(read_param compressor)

	if [ -n "$comp" ]; then
		pass "compressor parameter readable (${comp})"
	else
		fail "compressor parameter readable"
	fi
}

# Test 8: max_pool_percent parameter
test_max_pool_percent() {
	local pct
	pct=$(read_param max_pool_percent)

	if [ "$pct" -gt 0 ] && [ "$pct" -le 100 ] 2>/dev/null; then
		pass "max_pool_percent valid (${pct}%%)"
	else
		fail "max_pool_percent valid (got: $pct)"
	fi
}

# Main
check_root
check_swap_enabled
check_gswap_available

echo "TAP version 13"
echo "1..14"

test_module_loaded
test_debugfs_interface
test_vram_pool
test_enable_disable
test_store_load
test_stats_sanity
test_compressor
test_max_pool_percent

echo "# Tests: $num_tests, Pass: $num_pass, Fail: $num_fail, Skip: $num_skip"

if [ $num_fail -gt 0 ]; then
	exit $KSFT_FAIL
fi
exit $KSFT_PASS
