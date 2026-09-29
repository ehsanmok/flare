#!/usr/bin/env bash
# Interleaved A/B of flare_mc on the two thread engines:
#   A = pthread workers (default build)
#   B = AsyncRT workers (-D FLARE_ASYNCRT)
#
# Builds both binaries from benchmark/baselines/flare_mc/main.mojo, then
# hands them to ab_interleaved.sh (wrk2, plaintext keep-alive, Linux).
# Every ab_interleaved.sh knob passes through: REPS, RATE, DUR, PORT, WRK2.
#
# Under AsyncRT each flare worker holds one pool thread for the server's
# lifetime, and Scheduler.start refuses more than parallelism_level() - 1
# of them. ab_interleaved.sh runs 4 workers, so the box needs at least 5
# AsyncRT pool threads. AsyncRT leaves worker affinity off unless
# MODULAR_ENABLE_AFFINITY=1, while the pthread build pins; set it for a
# like-for-like comparison of pinned workers.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/target/bench_ab"
mkdir -p "$OUT"
cd "$ROOT"

SRC=benchmark/baselines/flare_mc/main.mojo
mojo build -D ASSERT=none -I . "$SRC" -o "$OUT/flare_mc_pthread"
mojo build -D ASSERT=none -D FLARE_ASYNCRT -I . "$SRC" -o "$OUT/flare_mc_asyncrt"

ncpu="$( (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null) || echo 0 )"
echo "── logical CPUs: $ncpu (AsyncRT pool is sized from the core count; need >= 5 for 4 workers)"
echo "── MODULAR_ENABLE_AFFINITY=${MODULAR_ENABLE_AFFINITY:-<unset>}"
echo "── A = pthread, B = asyncrt"

A_BIN="$OUT/flare_mc_pthread" B_BIN="$OUT/flare_mc_asyncrt" \
  exec bash benchmark/scripts/ab_interleaved.sh
