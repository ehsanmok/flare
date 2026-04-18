#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"
PORT="${FLARE_BENCH_PORT:-8080}"

export FLARE_BENCH_ADDR="127.0.0.1:$PORT"
export GOMAXPROCS=1

cd "$DIR"
# Resolve dependencies and create go.sum (idempotent; first run pulls
# fasthttp from proxy.golang.org into the module cache).
go mod tidy > /dev/null 2>&1 || true
go build -o ./server main.go
./server &
echo $! > "$PID_FILE"
