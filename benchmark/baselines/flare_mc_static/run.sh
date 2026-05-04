#!/bin/bash
# Start the flare multi-worker static-response baseline.
#
# AOT-builds with `mojo build -D ASSERT=none` (Mojo defaults to
# -O3) for fair head-to-head with the Rust baselines, which build
# via `cargo build --release --locked`. See the matching block in
# benchmark/baselines/flare/run.sh for the rationale.
#
# Per-worker SO_REUSEPORT listeners are the default for
# num_workers>=2 (matches actix_web's listener strategy). Set
# FLARE_REUSEPORT_WORKERS=0 to opt back into the single-listener
# EPOLLEXCLUSIVE shape.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"

export FLARE_BENCH_PORT="${FLARE_BENCH_PORT:-8080}"
export FLARE_BENCH_WORKERS="${FLARE_BENCH_WORKERS:-4}"
export FLARE_BENCH_PIN="${FLARE_BENCH_PIN:-1}"

OUT="$ROOT/target/bench_baselines/flare_mc_static"
mkdir -p "$(dirname "$OUT")"

cd "$ROOT"
mojo build -D ASSERT=none -I . "$DIR/main.mojo" -o "$OUT"
"$OUT" &
echo $! > "$PID_FILE"
