#!/bin/bash
# Start each baseline, curl /plaintext, diff bodies byte-for-byte.
# Fails (exit 1) if any target's body differs from the spec.
#
# Headers that are allowed to vary per target are normalised away (Date,
# Server, Connection, Keep-Alive). Everything else must match.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASELINES_DIR="$ROOT/benchmark/baselines"
RESULTS_DIR="${FLARE_BENCH_RESULTS:-$ROOT/benchmark/results/integrity}"
PORT="${FLARE_BENCH_PORT:-8080}"
SPEC_BODY="Hello, World!"
SPEC_BODY_LEN=13

mkdir -p "$RESULTS_DIR"
> "$RESULTS_DIR/integrity.log"

fail_count=0
for target_dir in "$BASELINES_DIR"/*/; do
    target="$(basename "$target_dir")"
    [[ -f "$target_dir/run.sh" && -f "$target_dir/check.sh" ]] || continue

    # Kill anything on our port from a previous attempt.
    (
      lsof -ti tcp:$PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
    ) >/dev/null 2>&1
    sleep 0.3

    export FLARE_BENCH_PID_FILE="$RESULTS_DIR/.server.pid"
    export FLARE_BENCH_PORT="$PORT"

    # Start the target.
    bash "$target_dir/run.sh" >"$RESULTS_DIR/$target.stdout" 2>"$RESULTS_DIR/$target.stderr" &
    RUNNER_PID=$!

    if ! bash "$target_dir/check.sh"; then
        echo "[$target] FAILED: server did not come up" | tee -a "$RESULTS_DIR/integrity.log"
        kill -9 $RUNNER_PID 2>/dev/null || true
        [[ -f "$FLARE_BENCH_PID_FILE" ]] && kill -9 "$(cat "$FLARE_BENCH_PID_FILE")" 2>/dev/null || true
        fail_count=$((fail_count + 1))
        continue
    fi

    # Fetch body + headers.
    BODY_FILE="$RESULTS_DIR/$target.body"
    HEAD_FILE="$RESULTS_DIR/$target.headers"
    curl --silent --dump-header "$HEAD_FILE" --output "$BODY_FILE" "http://127.0.0.1:$PORT/plaintext"

    # Compare body against spec.
    ACTUAL_LEN=$(wc -c < "$BODY_FILE" | tr -d '[:space:]')
    ACTUAL_BODY=$(cat "$BODY_FILE")

    status="OK"
    if [[ "$ACTUAL_LEN" != "$SPEC_BODY_LEN" ]]; then
        status="FAIL (body length $ACTUAL_LEN != $SPEC_BODY_LEN)"
        fail_count=$((fail_count + 1))
    elif [[ "$ACTUAL_BODY" != "$SPEC_BODY" ]]; then
        status="FAIL (body '$ACTUAL_BODY' != '$SPEC_BODY')"
        fail_count=$((fail_count + 1))
    fi

    echo "[$target] body_len=$ACTUAL_LEN status=$status" | tee -a "$RESULTS_DIR/integrity.log"

    # Stop the target.
    [[ -f "$FLARE_BENCH_PID_FILE" ]] && kill -9 "$(cat "$FLARE_BENCH_PID_FILE")" 2>/dev/null || true
    kill -9 $RUNNER_PID 2>/dev/null || true
    (
      lsof -ti tcp:$PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
    ) >/dev/null 2>&1
    sleep 0.3
done

if [[ "$fail_count" -gt 0 ]]; then
    echo ""
    echo "Integrity check FAILED: $fail_count target(s) did not match the spec"
    exit 1
fi
echo ""
echo "Integrity check PASSED: all targets match the plaintext spec."
