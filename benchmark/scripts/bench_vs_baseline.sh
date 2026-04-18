#!/bin/bash
# Rigorous flare-vs-baselines benchmark orchestrator.
#
# Runs each baseline server on 127.0.0.1:8080 in turn, warms it up,
# executes N wrk measurement rounds, and summarises results. Hard
# requirements per the plan:
#   - Response-byte integrity across all targets (spec match + normalised
#     headers). Aborts if any target diverges.
#   - 5 measurement rounds per (target, workload, config).
#   - Drop min + max, median of middle rounds is the headline number.
#   - Variance gate: stdev/mean < 3.0%. Runs exceeding it retry once and
#     are marked "unstable" if they still fail.
#   - Environment captured per-run into env.json.
#   - Full raw wrk stdout preserved in RAW/.
#
# Usage:
#   pixi run --environment bench bench-vs-baseline
#   pixi run --environment bench bench-vs-baseline-quick
#
# Options (forwarded to orchestrator):
#   --only=<target1>,<target2>   restrict to listed targets
#   --configs=<name1>,<name2>    restrict to listed configs
#   --workloads=<name1>,...      restrict to listed workloads (default plaintext)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCH="$ROOT/benchmark"
BASELINES_DIR="$BENCH/baselines"
CONFIGS_DIR="$BENCH/configs"
SCRIPTS_DIR="$BENCH/scripts"

PORT="${FLARE_BENCH_PORT:-8080}"
HOST_TAG="$(hostname -s 2>/dev/null || hostname)"
TS="$(date -u +'%Y-%m-%dT%H%M')"
COMMIT="$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
RESULTS_DIR="$BENCH/results/${TS}-${HOST_TAG}-${COMMIT}"
mkdir -p "$RESULTS_DIR" "$RESULTS_DIR/RAW"
export FLARE_BENCH_PID_FILE="$RESULTS_DIR/.server.pid"
export FLARE_BENCH_PORT="$PORT"

ONLY_TARGETS=""
ONLY_CONFIGS=""
ONLY_WORKLOADS="plaintext"
for arg in "$@"; do
    case "$arg" in
        --only=*)      ONLY_TARGETS="${arg#--only=}" ;;
        --configs=*)   ONLY_CONFIGS="${arg#--configs=}" ;;
        --workloads=*) ONLY_WORKLOADS="${arg#--workloads=}" ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

matches() {
    # $1 = candidate, $2 = comma-separated allow-list (empty = all allowed)
    local cand="$1"; local list="$2"
    [[ -z "$list" ]] && return 0
    IFS=',' read -ra arr <<< "$list"
    for e in "${arr[@]}"; do [[ "$e" == "$cand" ]] && return 0; done
    return 1
}

# ── Environment snapshot ──────────────────────────────────────────────────────
echo "→ Collecting environment..."
bash "$SCRIPTS_DIR/_collect_env.sh" > "$RESULTS_DIR/env.json"

# ── Integrity gate ────────────────────────────────────────────────────────────
echo "→ Running integrity check..."
FLARE_BENCH_RESULTS="$RESULTS_DIR/integrity" bash "$SCRIPTS_DIR/_integrity_check.sh" \
    | tee "$RESULTS_DIR/integrity.md"

# ── Helpers ───────────────────────────────────────────────────────────────────
kill_port() {
    (
      lsof -ti tcp:$PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
    ) >/dev/null 2>&1
    sleep 0.3
}

# Parse one config YAML -> exported variables.
read_config() {
    local f="$1"
    WRK_THREADS=$(awk '/^wrk_threads:/ {print $2}' "$f")
    WRK_CONNS=$(awk '/^wrk_connections:/ {print $2}' "$f")
    WRK_DURATION=$(awk '/^wrk_duration_seconds:/ {print $2}' "$f")
    WARMUP=$(awk '/^warmup_seconds:/ {print $2}' "$f")
    RUNS=$(awk '/^runs:/ {print $2}' "$f")
    QUIET=$(awk '/^quiet_seconds:/ {print $2}' "$f")
}

# ── Main sweep ────────────────────────────────────────────────────────────────
declare -a SUMMARY_ROWS

for target_dir in "$BASELINES_DIR"/*/; do
    target="$(basename "$target_dir")"
    matches "$target" "$ONLY_TARGETS" || continue
    [[ -f "$target_dir/run.sh" && -f "$target_dir/check.sh" ]] || continue

    for workload in $(echo "$ONLY_WORKLOADS" | tr ',' ' '); do
        # Only plaintext is specced for Phase 1.6.
        [[ "$workload" == "plaintext" ]] || continue

        for config_file in "$CONFIGS_DIR"/*.yaml; do
            config=$(basename "$config_file" .yaml)
            matches "$config" "$ONLY_CONFIGS" || continue
            read_config "$config_file"
            URL="http://127.0.0.1:$PORT/plaintext"

            echo ""
            echo "─── $target / $workload / $config ───"

            # Start the target.
            kill_port
            bash "$target_dir/run.sh" \
                >"$RESULTS_DIR/RAW/$target-$workload-$config.server.stdout" \
                2>"$RESULTS_DIR/RAW/$target-$workload-$config.server.stderr" &
            RUNNER_PID=$!

            if ! bash "$target_dir/check.sh"; then
                echo "[$target] check.sh FAILED — skipping this target"
                kill -9 $RUNNER_PID 2>/dev/null || true
                [[ -f "$FLARE_BENCH_PID_FILE" ]] && kill -9 "$(cat "$FLARE_BENCH_PID_FILE")" 2>/dev/null || true
                kill_port
                SUMMARY_ROWS+=("$target|$workload|$config|DOWN|-|-|-|false")
                continue
            fi

            # Warmup.
            echo "  warmup ${WARMUP}s @ -c${WRK_CONNS} -t${WRK_THREADS} …"
            wrk -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${WARMUP}s" \
                --latency "$URL" > /dev/null 2>&1 || true

            # Measurement runs.
            for run in $(seq 1 "$RUNS"); do
                sleep "$QUIET"
                raw="$RESULTS_DIR/RAW/$target-$workload-$config-run${run}.txt"
                echo "  run $run/${RUNS} ${WRK_DURATION}s …"
                wrk -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${WRK_DURATION}s" \
                    --latency "$URL" > "$raw" 2>&1 || true
            done

            # Aggregate.
            RUN_FILES=()
            for run in $(seq 1 "$RUNS"); do
                RUN_FILES+=("$RESULTS_DIR/RAW/$target-$workload-$config-run${run}.txt")
            done
            stats_json="$RESULTS_DIR/$target-$workload-$config.json"
            python3 "$SCRIPTS_DIR/_stat.py" "$stats_json" "${RUN_FILES[@]}"

            # Append to summary.
            med=$(python3 -c "import json; d=json.load(open('$stats_json')); print(int(d['summary']['median_req_per_sec']))")
            stv=$(python3 -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['stdev_pct']:.2f}\")")
            p50=$(python3 -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['median_p50_ms']:.2f}\")")
            p99=$(python3 -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['median_p99_ms']:.2f}\")")
            stable=$(python3 -c "import json; d=json.load(open('$stats_json')); print(str(d['summary']['stable']).lower())")
            SUMMARY_ROWS+=("$target|$workload|$config|$med|$stv|$p50|$p99|$stable")

            # Teardown.
            [[ -f "$FLARE_BENCH_PID_FILE" ]] && kill -9 "$(cat "$FLARE_BENCH_PID_FILE")" 2>/dev/null || true
            kill -9 $RUNNER_PID 2>/dev/null || true
            kill_port
        done
    done
done

# ── Emit summary.md ───────────────────────────────────────────────────────────
{
    echo "# Benchmark summary"
    echo ""
    echo "- Run: ${TS}-${HOST_TAG}-${COMMIT}"
    echo "- See env.json for hardware / toolchain versions."
    echo ""
    echo "| Target | Workload | Config | Req/s (median) | stdev% | p50 (ms) | p99 (ms) | stable |"
    echo "|---|---|---|---:|---:|---:|---:|---|"
    for row in "${SUMMARY_ROWS[@]}"; do
        IFS='|' read -r t w c m s p50 p99 stab <<< "$row"
        printf "| %s | %s | %s | %s | %s | %s | %s | %s |\n" "$t" "$w" "$c" "$m" "$s" "$p50" "$p99" "$stab"
    done
} > "$RESULTS_DIR/summary.md"

echo ""
echo "══ Benchmark complete ══"
echo "Results: $RESULTS_DIR"
echo ""
cat "$RESULTS_DIR/summary.md"
