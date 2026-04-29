#!/bin/bash
# Start the axum baseline on 127.0.0.1:8080 with FLARE_BENCH_WORKERS workers.
# Writes PID to benchmark/results/.server.pid so the orchestrator can stop it.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"
PORT="${FLARE_BENCH_PORT:-8080}"

export FLARE_BENCH_PORT="$PORT"
export FLARE_BENCH_WORKERS="${FLARE_BENCH_WORKERS:-4}"

cd "$DIR"
# Build once (idempotent if cached), then run. --locked enforces
# Cargo.lock so bench numbers are reproducible across machines.
cargo build --release --locked --quiet
./target/release/server &
echo $! > "$PID_FILE"
