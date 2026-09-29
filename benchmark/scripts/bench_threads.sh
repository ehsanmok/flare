#!/usr/bin/env bash
# Build benchmark/bench_threads.mojo for both thread engines and run them.
#
# Output is `engine,workload,param,ns_per_op`, pthread rows first. Knobs
# (all optional): BENCH_REPS, BENCH_SPAWN_N, BENCH_FANOUT_M, BENCH_BLOCK_N.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/target/bench_threads"
mkdir -p "$OUT"
cd "$ROOT"

mojo build -D ASSERT=none -I . benchmark/bench_threads.mojo -o "$OUT/pthread"
mojo build -D ASSERT=none -D FLARE_ASYNCRT -I . benchmark/bench_threads.mojo -o "$OUT/asyncrt"

echo "engine,workload,param,ns_per_op"
"$OUT/pthread"
"$OUT/asyncrt"
