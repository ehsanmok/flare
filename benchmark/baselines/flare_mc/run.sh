#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"

export FLARE_BENCH_PORT="${FLARE_BENCH_PORT:-8080}"
export FLARE_BENCH_WORKERS="${FLARE_BENCH_WORKERS:-4}"
export FLARE_BENCH_PIN="${FLARE_BENCH_PIN:-1}"

cd "$ROOT"
mojo -I . "$DIR/main.mojo" &
echo $! > "$PID_FILE"
