#!/usr/bin/env bash
# benchmark/scripts/_run_tail_quick.sh
#
# Drive wrk2 (with --latency for tail percentiles) against a
# locally-running flare server. v0.5.0 Step 2 / Track 6.1.
#
# Steps:
#   1. Build wrk2 from source if not already.
#   2. Start a flare static server on 127.0.0.1:8080.
#   3. Wait for the server to come up.
#   4. Run wrk2 -R rate -t threads -c connections -d duration
#      with --latency.
#   5. Tear down the server.
#
# Output goes to stdout for ad-hoc reading; the
# `bench_vs_baseline.sh` harness will adopt this in a follow-up
# (parse the --latency block into per-run JSON, apply the
# stdev gate, integrate with the multi-baseline matrix).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCH="$ROOT/benchmark"

# Build wrk2 if not already.
"$BENCH/scripts/_install_wrk2.sh"
WRK2_DIR="${WRK2_DIR:-$ROOT/build/wrk2}"
WRK2_BIN="$WRK2_DIR/wrk2"

if [ ! -x "$WRK2_BIN" ]; then
    echo "[bench-tail-quick] wrk2 not built at $WRK2_BIN" >&2
    exit 1
fi

# Read tail_quick.yaml for parameters (manual parse — yaml in
# bash). The schema is small enough to read with grep/awk.
CONF="$BENCH/configs/tail_quick.yaml"
if [ ! -f "$CONF" ]; then
    echo "[bench-tail-quick] config not found: $CONF" >&2
    exit 1
fi

THREADS=$(awk '/^wrk_threads:/{print $2}' "$CONF")
CONNS=$(awk '/^wrk_connections:/{print $2}' "$CONF")
DURATION=$(awk '/^wrk_duration_seconds:/{print $2}' "$CONF")
RATE=$(awk '/^wrk_rate:/{print $2}' "$CONF")
WARMUP=$(awk '/^warmup_seconds:/{print $2}' "$CONF")

PORT="${FLARE_BENCH_PORT:-8080}"
URL="http://127.0.0.1:${PORT}/"

echo "[bench-tail-quick] threads=$THREADS connections=$CONNS rate=$RATE duration=${DURATION}s"
echo "[bench-tail-quick] starting flare static server on :$PORT"

# Start a flare static server (the simplest server in the
# repo). The user can drop in their own server by setting
# FLARE_TAIL_QUICK_SERVER_CMD before running.
SERVER_CMD="${FLARE_TAIL_QUICK_SERVER_CMD:-pixi run --environment bench example-static-response}"
${SERVER_CMD} &
SERVER_PID=$!
trap "kill ${SERVER_PID} 2>/dev/null || true" EXIT

# Wait for the server to bind. wrk2 will hammer the URL anyway,
# but a brief warmup smooths out the JIT / page-table costs.
sleep "${WARMUP:-3}"

# Run wrk2 with --latency for full percentile output.
"$WRK2_BIN" \
    -t"$THREADS" \
    -c"$CONNS" \
    -d"${DURATION}s" \
    -R"$RATE" \
    --latency \
    "$URL"

# Tear down the server (also handled by trap).
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
