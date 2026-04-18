#!/bin/bash
# Start the Go net/http baseline on 127.0.0.1:8080 with GOMAXPROCS=1.
# Writes PID to benchmark/results/.server.pid so the orchestrator can stop it.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"
PORT="${FLARE_BENCH_PORT:-8080}"

export FLARE_BENCH_ADDR="127.0.0.1:$PORT"
export GOMAXPROCS=1

cd "$DIR"
# Build once (idempotent if cached), then run.
go build -o ./server main.go
./server &
echo $! > "$PID_FILE"
