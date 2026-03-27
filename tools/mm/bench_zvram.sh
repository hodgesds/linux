#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# bench_zvram.sh - Build and run zvram benchmark
#
# Usage: ./bench_zvram.sh [-s SIZE_MB] [-i ITERS] [-t TESTS] [-v]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BENCH="$SCRIPT_DIR/bench_zvram"

# Build if needed
if [ ! -f "$BENCH" ] || [ "$BENCH" -ot "$SCRIPT_DIR/bench_zvram.c" ]; then
    echo "Building bench_zvram..."
    gcc -O2 -Wall -o "$BENCH" "$SCRIPT_DIR/bench_zvram.c" -lpthread
fi

# Check prerequisites
if [ ! -d /sys/module/zswap ]; then
    echo "ERROR: zswap module not loaded"
    exit 1
fi

ZPOOL=$(cat /sys/module/zswap/parameters/zpool 2>/dev/null)
ENABLED=$(cat /sys/module/zswap/parameters/enabled 2>/dev/null)

echo "zswap.enabled=$ENABLED"
echo "zswap.zpool=$ZPOOL"

if [ -d /sys/kernel/debug/zvram ]; then
    echo "zvram pool_total: $(cat /sys/kernel/debug/zvram/pool_total_size 2>/dev/null || echo N/A)"
    echo "zvram pool_used:  $(cat /sys/kernel/debug/zvram/pool_used_size 2>/dev/null || echo N/A)"
fi

# Check swap is enabled
if ! swapon --show | grep -q .; then
    echo "WARNING: no swap devices active, MADV_PAGEOUT may not work"
fi

echo ""
exec "$BENCH" "$@"
