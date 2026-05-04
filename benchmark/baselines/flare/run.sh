#!/bin/bash
# Start the flare single-worker baseline.
#
# AOT-builds with `mojo build -D ASSERT=none` (Mojo defaults to
# -O3) for fair head-to-head with the Rust baselines, which build
# via `cargo build --release --locked`. The default ASSERT=safe
# mode keeps every flare debug_assert[assert_mode="safe"] call
# in the binary -- great for development, but Rust's release
# build emits no debug asserts so the comparison would otherwise
# be apples-to-oranges. -D ASSERT=none compiles all flare
# debug_asserts out, matching Rust's release posture exactly.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"

export FLARE_BENCH_PORT="${FLARE_BENCH_PORT:-8080}"

OUT="$ROOT/target/bench_baselines/flare"
mkdir -p "$(dirname "$OUT")"

cd "$ROOT"
# `mojo build` is idempotent but rerunning it incurs ~10-15s of
# parse + IR work. The bench harness invokes this script once per
# (target, workload, config) tuple so a per-invocation rebuild is
# in the noise vs a 5x30s measurement run.
mojo build -D ASSERT=none -I . "$DIR/main.mojo" -o "$OUT"
"$OUT" &
echo $! > "$PID_FILE"
