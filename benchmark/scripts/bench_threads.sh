#!/usr/bin/env bash
# Build and run benchmark/bench_threads.mojo: AsyncRT tasks vs OS threads.
#
# Output is `engine,workload,param,ns_per_op`. Knobs (all optional):
# BENCH_REPS, BENCH_SPAWN_N, BENCH_FANOUT_M, BENCH_BLOCK_N.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/target/bench_threads"
mkdir -p "$OUT"
cd "$ROOT"

mojo build -D ASSERT=none -I . benchmark/bench_threads.mojo -o "$OUT/bench_threads"
"$OUT/bench_threads"
