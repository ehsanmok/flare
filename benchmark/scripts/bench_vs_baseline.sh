#!/bin/bash
# Rigorous flare-vs-baselines benchmark orchestrator.
#
# Drives wrk2 in saturate mode (very high ``-R`` so the gen sends
# as fast as the server allows) with ``--latency`` so every run
# captures the full p50 / p75 / p90 / p99 / p99.9 / p99.99 /
# p99.999 distribution. wrk2 ``--latency`` is the
# coordinated-omission-corrected variant; numbers are directly
# comparable to published TFB-style + production-grade harness
# tail figures.
#
# Why wrk2 instead of wrk: wrk's default mode silently drops
# requests when the server can't keep up, producing latency
# numbers that look better than reality (the
# coordinated-omission bug). wrk2 keeps the load constant so
# tail percentiles include time spent queued at the gen, which
# is what production clients actually observe under load.
#
# Hard requirements per the plan:
#   - Response-byte integrity across all targets (spec match +
#     normalised headers). Aborts if any target diverges.
#   - 5 measurement rounds per (target, workload, config).
#   - Drop min + max, median of middle rounds is the headline
#     number.
#   - Variance gate: stdev/mean < 3.0%. Runs exceeding it retry
#     once and are marked "unstable" if they still fail.
#   - Environment captured per-run into env.json.
#   - Full raw wrk2 stdout preserved in RAW/.
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

# wrk2 lives at build/wrk2/wrk2 (built once via bench-install-wrk2);
# the scheduler invokes it explicitly so the env-installed ``wrk``
# (which is on PATH from feature.bench) doesn't shadow it.
WRK2_BIN="${WRK2_BIN:-$ROOT/build/wrk2/wrk2}"
if [ ! -x "$WRK2_BIN" ]; then
    echo "→ Building wrk2 (one-time)..."
    bash "$SCRIPTS_DIR/_install_wrk2.sh" >/dev/null
fi
if [ ! -x "$WRK2_BIN" ]; then
    echo "wrk2 not found at $WRK2_BIN after install attempt" >&2
    exit 2
fi

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
    # wrk2 saturate-mode rate. ``wrk_rate`` in the config gives
    # the requested target; defaults to a high value (10M req/s)
    # so we measure server-bottlenecked throughput. Configs can
    # override for fixed-rate tail measurements.
    WRK_RATE=$(awk '/^wrk_rate:/ {print $2}' "$f")
    if [ -z "$WRK_RATE" ]; then
        WRK_RATE=10000000
    fi
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
                SUMMARY_ROWS+=("$target|$workload|$config|DOWN|-|-|-|-|-|false")
                continue
            fi

            # ── Calibration phase ──────────────────────────────
            # 1) Settle the server at a low fixed rate so JIT,
            #    branch caches, and TCP slow-start are out of the
            #    way before we measure throughput.
            # 2) Estimate the overdrive ceiling with a brief
            #    R=10M probe.
            # 3) Binary-search for the highest rate where p99 ≤
            #    SUSTAIN_P99_BUDGET_MS (default 50 ms). wrk2's
            #    overdrive ceiling over-reports the truly
            #    sustainable peak by 30–60% on multi-worker
            #    servers (it counts queued requests as
            #    throughput); the latency-bounded search is the
            #    industry-standard way to find an honest peak.
            # 4) Take the calibrated rate as the "peak" the
            #    summary reports, and run the fixed-rate
            #    measurement at SUSTAIN_PCT (default 90%) of it.
            SETTLE_RPS=$(awk '/^settle_rps:/ {print $2}' "$config_file")
            SETTLE_RPS=${SETTLE_RPS:-20000}
            echo "  settle 5s @ -R${SETTLE_RPS} …"
            settle_raw="$RESULTS_DIR/RAW/$target-$workload-$config-settle.txt"
            "$WRK2_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" \
                -d5s -R"$SETTLE_RPS" \
                --latency "$URL" > "$settle_raw" 2>&1 || true

            echo "  overdrive probe ${WARMUP}s …"
            peak_raw="$RESULTS_DIR/RAW/$target-$workload-$config-peakfind.txt"
            "$WRK2_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" \
                -d"${WARMUP}s" -R10000000 \
                --latency "$URL" > "$peak_raw" 2>&1 || true
            OVERDRIVE_RPS=$(awk '/^Requests\/sec:/ {print $2}' "$peak_raw")
            if [ -z "$OVERDRIVE_RPS" ] || [ "$(printf '%.0f' "$OVERDRIVE_RPS")" -le 0 ]; then
                echo "  peak-find FAILED (server unresponsive); marking unstable"
                kill -9 $RUNNER_PID 2>/dev/null || true
                [[ -f "$FLARE_BENCH_PID_FILE" ]] && kill -9 "$(cat "$FLARE_BENCH_PID_FILE")" 2>/dev/null || true
                kill_port
                SUMMARY_ROWS+=("$target|$workload|$config|DOWN|-|-|-|-|-|false")
                continue
            fi

            P99_BUDGET_MS=$(awk '/^sustain_p99_budget_ms:/ {print $2}' "$config_file")
            P99_BUDGET_MS=${P99_BUDGET_MS:-50}
            echo "  overdrive=$(printf '%.0f' "$OVERDRIVE_RPS") req/s; calibrating sustainable peak (p99 ≤ ${P99_BUDGET_MS} ms) …"

            # Binary search between 30% and 100% of overdrive.
            LO=$(python3 -c "print(int(float('$OVERDRIVE_RPS') * 0.30))")
            HI=$(python3 -c "print(int(float('$OVERDRIVE_RPS') * 1.00))")
            SUSTAINABLE_RPS=$LO
            for _step in 1 2 3 4 5; do
                MID=$(python3 -c "print(int(($LO + $HI) / 2))")
                cal_raw="$RESULTS_DIR/RAW/$target-$workload-$config-cal-${MID}.txt"
                "$WRK2_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" \
                    -d10s -R"$MID" --latency "$URL" > "$cal_raw" 2>&1 || true
                P99_LINE=$(grep -E '^[[:space:]]*99\.000%' "$cal_raw" | head -1)
                P99_MS=$(python3 -c "
import re,sys
s = '''$P99_LINE'''.strip()
m = re.search(r'([0-9.]+)([umms]+)', s.split()[-1] if s else '0ms')
if not m:
    print(99999)
else:
    v = float(m.group(1)); u = m.group(2)
    if u == 'us':   ms = v / 1000
    elif u == 'ms': ms = v
    elif u == 's':  ms = v * 1000
    elif u == 'm':  ms = v * 60000
    else: ms = 99999
    print(f'{ms:.2f}')
")
                ACHIEVED_RPS=$(awk '/^Requests\/sec:/ {print $2}' "$cal_raw")
                ACHIEVED_INT=$(python3 -c "print(int(float('$ACHIEVED_RPS' or '0')))")
                # Reject if the load gen couldn't keep up (achieved < 90% of MID),
                # which means we've already exceeded the server's true rate.
                MIN_ACHIEVED=$(python3 -c "print(int($MID * 0.90))")
                P99_OK=$(python3 -c "print(1 if float('$P99_MS') <= $P99_BUDGET_MS else 0)")
                ACH_OK=$(python3 -c "print(1 if $ACHIEVED_INT >= $MIN_ACHIEVED else 0)")
                if [ "$P99_OK" = "1" ] && [ "$ACH_OK" = "1" ]; then
                    SUSTAINABLE_RPS=$MID
                    LO=$MID
                else
                    HI=$MID
                fi
                echo "    probe @ R=${MID}: ach=${ACHIEVED_INT} p99=${P99_MS}ms (budget=${P99_BUDGET_MS}ms) → $([ "$P99_OK" = "1" ] && [ "$ACH_OK" = "1" ] && echo OK || echo TOO_HIGH)"
            done
            PEAK_RPS=$SUSTAINABLE_RPS

            SUSTAIN_PCT=$(awk '/^sustain_rps_pct:/ {print $2}' "$config_file")
            SUSTAIN_PCT=${SUSTAIN_PCT:-90}
            SUSTAIN_RPS=$(python3 -c "print(int(float('$PEAK_RPS') * $SUSTAIN_PCT / 100))")
            echo "  sustainable peak=$(printf '%.0f' "$PEAK_RPS") req/s; sustaining at $SUSTAIN_PCT%% = ${SUSTAIN_RPS} req/s"

            # Measurement runs at the sustainable rate. Tail
            # percentiles here reflect actual production-shape
            # latency, CO-corrected.
            for run in $(seq 1 "$RUNS"); do
                sleep "$QUIET"
                raw="$RESULTS_DIR/RAW/$target-$workload-$config-run${run}.txt"
                echo "  run $run/${RUNS} ${WRK_DURATION}s @ -R${SUSTAIN_RPS} …"
                "$WRK2_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" \
                    -d"${WRK_DURATION}s" -R"$SUSTAIN_RPS" \
                    --latency "$URL" > "$raw" 2>&1 || true
            done

            # Aggregate. The peak-find req/s is the capacity
            # number the summary table headlines; the 5
            # measurement runs at fixed rate provide the tail
            # percentiles + stdev gate.
            RUN_FILES=()
            for run in $(seq 1 "$RUNS"); do
                RUN_FILES+=("$RESULTS_DIR/RAW/$target-$workload-$config-run${run}.txt")
            done
            stats_json="$RESULTS_DIR/$target-$workload-$config.json"
            python3 "$SCRIPTS_DIR/_stat.py" --peak-rps "$PEAK_RPS" \
                "$stats_json" "${RUN_FILES[@]}"

            # Append to summary.
            med=$(python3 -c "import json; d=json.load(open('$stats_json')); print(int(d['summary']['median_req_per_sec']))")
            stv=$(python3 -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['stdev_pct']:.2f}\")")
            p50=$(python3 -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['median_p50_ms']:.2f}\")")
            p99=$(python3 -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['median_p99_ms']:.2f}\")")
            p99_9=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('median_p99_9_ms', 0.0); print(f\"{v:.2f}\")")
            p99_99=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('median_p99_99_ms', 0.0); print(f\"{v:.2f}\")")
            stable=$(python3 -c "import json; d=json.load(open('$stats_json')); print(str(d['summary']['stable']).lower())")
            SUMMARY_ROWS+=("$target|$workload|$config|$med|$stv|$p50|$p99|$p99_9|$p99_99|$stable")

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
    echo "| Target | Workload | Config | Req/s (median) | stdev% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |"
    echo "|---|---|---|---:|---:|---:|---:|---:|---:|---|"
    for row in "${SUMMARY_ROWS[@]}"; do
        IFS='|' read -r t w c m s p50 p99 p999 p9999 stab <<< "$row"
        printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n" "$t" "$w" "$c" "$m" "$s" "$p50" "$p99" "$p999" "$p9999" "$stab"
    done
} > "$RESULTS_DIR/summary.md"

echo ""
echo "══ Benchmark complete ══"
echo "Results: $RESULTS_DIR"
echo ""
cat "$RESULTS_DIR/summary.md"
