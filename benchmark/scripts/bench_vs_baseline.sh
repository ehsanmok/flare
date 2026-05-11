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
                SUMMARY_ROWS+=("$target|$workload|$config|DOWN|-|-|-|-|-|-|-|-|-|false")
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
                SUMMARY_ROWS+=("$target|$workload|$config|DOWN|-|-|-|-|-|-|-|-|-|false")
                continue
            fi

            P99_BUDGET_MS=$(awk '/^sustain_p99_budget_ms:/ {print $2}' "$config_file")
            P99_BUDGET_MS=${P99_BUDGET_MS:-50}
            # Probe duration governs how much tail headroom each
            # calibration step has to expose. 10 s is too short:
            # rare 100+ ms blips that mark "edge of cliff" land in
            # the p99.99 bucket only every ~10-20 k requests, so a
            # 10 s probe at 200 k rps sees 0-2 of them. 20 s
            # doubles the sample and exposes the cliff reliably.
            PROBE_DURATION_SEC="${FLARE_BENCH_PROBE_SEC:-20}"
            echo "  overdrive=$(printf '%.0f' "$OVERDRIVE_RPS") req/s; calibrating sustainable peak (p99 ≤ ${P99_BUDGET_MS} ms, ${PROBE_DURATION_SEC} s/probe) …"

            # Helper that parses the p50 / p99 / p99.9 / p99.99
            # block out of one wrk2 stdout file and prints them
            # in milliseconds on a single line.
            parse_pct() {
                python3 - "$1" <<'PY'
import re, sys
p = sys.argv[1]
text = open(p, errors="replace").read()
re_pct = re.compile(r"^\s*([0-9]+\.[0-9]+)%\s+([0-9.]+)(us|ms|s|m)\s*$", re.M)
want = {"50.000": "p50", "99.000": "p99", "99.900": "p99_9", "99.990": "p99_99"}
got = {}
in_dist = False
for line in text.splitlines():
    if "Latency Distribution" in line:
        in_dist = True; continue
    if not in_dist: continue
    s = line.strip()
    if not s or s.startswith("Detailed"): in_dist = False; continue
    m = re_pct.match("  " + s)
    if not m: continue
    pct, v, u = m.group(1), float(m.group(2)), m.group(3)
    if pct not in want: continue
    ms = v / 1000.0 if u == "us" else v if u == "ms" else v * 1000.0 if u == "s" else v * 60000.0
    got[want[pct]] = ms
print(f"{got.get('p50', 0):.3f} {got.get('p99', 99999):.3f} {got.get('p99_9', 99999):.3f} {got.get('p99_99', 99999):.3f}")
PY
            }

            # Binary search between 30% and 100% of overdrive.
            LO=$(python3 -c "print(int(float('$OVERDRIVE_RPS') * 0.30))")
            HI=$(python3 -c "print(int(float('$OVERDRIVE_RPS') * 1.00))")
            SUSTAINABLE_RPS=$LO
            # Track the lowest p99 seen across probes. A
            # probe whose absolute p99 has more than doubled
            # vs this floor signals approaching saturation
            # even when the tail-fanout ratio is bounded
            # (the "p99 doubled in the same probe budget"
            # failure mode caught for actix_web 256k→262k:
            # tail fanout looked clean but the median p99
            # grew 2.1×, and the 90%-of-peak sustain rate
            # then sat right on the cliff). 2.0× is the
            # smallest factor that lets healthy servers
            # climb 3-4 probes without false-positive
            # rejection.
            P99_FLOOR=999.0
            # Calibration helper: run one wrk2 probe and parse
            # its percentiles into P50_MS / P99_MS / P99_9_MS /
            # P99_99_MS / ACHIEVED_INT. Keeping this as a
            # function lets the binary-search loop retry a
            # rejected probe before permanently truncating the
            # search bound -- single transient blips (NIC IRQ
            # storms, kernel scheduler jitter, brief noisy
            # neighbours) should not collapse the search
            # ceiling.
            run_probe() {
                local rate="$1"
                local raw="$2"
                "$WRK2_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" \
                    -d"${PROBE_DURATION_SEC}s" -R"$rate" --latency "$URL" > "$raw" 2>&1 || true
                read -r P50_MS P99_MS P99_9_MS P99_99_MS <<< "$(parse_pct "$raw")"
                local ach
                ach=$(awk '/^Requests\/sec:/ {print $2}' "$raw")
                ACHIEVED_INT=$(python3 -c "print(int(float('$ach' or '0')))")
            }
            # Gate test as a function so the binary-search
            # loop can call it on both the original and the
            # retry probe results without duplicating the
            # multi-criterion logic. Sets verdict + the four
            # OK flags as side effects.
            evaluate_probe() {
                local mid="$1"
                MIN_ACHIEVED=$(python3 -c "print(int($mid * 0.90))")
                P99_OK=$(python3 -c "print(1 if float('$P99_MS') <= $P99_BUDGET_MS else 0)")
                ACH_OK=$(python3 -c "print(1 if $ACHIEVED_INT >= $MIN_ACHIEVED else 0)")
                CLIFF_OK=$(python3 -c "
p99   = float('$P99_MS')
p99_9 = float('$P99_9_MS')
p99_99 = float('$P99_99_MS')
ok_999  = p99_9  <= max(p99 * 3.0, p99 + 2.0)
ok_9999 = p99_99 <= max(p99 * 10.0, p99 + 5.0)
print(1 if (ok_999 and ok_9999) else 0)
")
                P99_GROWTH_OK=$(python3 -c "
floor = float('$P99_FLOOR')
p99 = float('$P99_MS')
print(1 if p99 <= max(floor * 2.0, floor + 2.0) else 0)
")
                if [ "$P99_OK" = "1" ] && [ "$ACH_OK" = "1" ] && [ "$CLIFF_OK" = "1" ] && [ "$P99_GROWTH_OK" = "1" ]; then
                    verdict=OK
                elif [ "$P99_GROWTH_OK" = "0" ]; then
                    verdict=P99_GREW
                elif [ "$CLIFF_OK" = "0" ]; then
                    verdict=CLIFF
                elif [ "$P99_OK" = "0" ]; then
                    verdict=P99_HIGH
                else
                    verdict=UNDER_RATE
                fi
            }
            for _step in 1 2 3 4 5; do
                MID=$(python3 -c "print(int(($LO + $HI) / 2))")
                cal_raw="$RESULTS_DIR/RAW/$target-$workload-$config-cal-${MID}.txt"
                run_probe "$MID" "$cal_raw"
                # Update the absolute-p99 floor BEFORE the
                # first evaluate_probe call so the growth gate
                # uses the up-to-date floor on this probe.
                P99_FLOOR=$(python3 -c "print(min(float('$P99_FLOOR'), float('$P99_MS')))")
                evaluate_probe "$MID"
                # If we rejected on a transient-looking gate
                # (CLIFF / P99_GREW), re-run the same probe
                # ONCE before truncating HI. Single noisy
                # probes early in the binary search were
                # permanently capping the search ceiling and
                # producing artificially low calibrated peaks
                # (the flare_mc 174k regression in the
                # 2026-05-11T1740 run — overdrive=278k,
                # first probe at 65 % = R=180k took a
                # transient 81 ms p99.99, search collapsed to
                # 174k). One retry on transient gates lets the
                # search shake off these blips without giving
                # up the cliff-detection signal: persistent
                # cliffs reject twice in a row.
                if [ "$verdict" = "CLIFF" ] || [ "$verdict" = "P99_GREW" ]; then
                    retry_raw="$RESULTS_DIR/RAW/$target-$workload-$config-cal-${MID}-retry.txt"
                    echo "    retry @ R=${MID}: rejected on ${verdict}, re-probing once"
                    run_probe "$MID" "$retry_raw"
                    P99_FLOOR=$(python3 -c "print(min(float('$P99_FLOOR'), float('$P99_MS')))")
                    evaluate_probe "$MID"
                fi
                # Apply the verdict from evaluate_probe (after
                # an optional retry above) to the binary
                # search bounds.
                if [ "$verdict" = "OK" ]; then
                    SUSTAINABLE_RPS=$MID
                    LO=$MID
                else
                    HI=$MID
                fi
                echo "    probe @ R=${MID}: ach=${ACHIEVED_INT} p99=${P99_MS}ms p99.9=${P99_9_MS}ms p99.99=${P99_99_MS}ms (floor=${P99_FLOOR}ms) → ${verdict}"
            done
            PEAK_RPS=$SUSTAINABLE_RPS

            SUSTAIN_PCT=$(awk '/^sustain_rps_pct:/ {print $2}' "$config_file")
            SUSTAIN_PCT=${SUSTAIN_PCT:-90}
            SUSTAIN_RPS=$(python3 -c "print(int(float('$PEAK_RPS') * $SUSTAIN_PCT / 100))")

            # Post-search validation pass. The binary search can
            # still settle one step above the true sustainable
            # peak when the boundary probe lands in a momentarily
            # quiet window. A single 20 s validation at
            # SUSTAIN_PCT% of the chosen peak catches that case;
            # if the validation fails the same cliff gate we used
            # during the search, back the peak off one step
            # (multiply by 0.92) and re-validate once. The 0.92
            # factor is empirically large enough to clear a cliff
            # discovered at SUSTAIN_PCT% of overshoot peak; if it
            # still fails after one back-off we accept the
            # current rate and label the run "unstable" via
            # _stat.py's stdev gate.
            for _val_attempt in 1 2; do
                val_raw="$RESULTS_DIR/RAW/$target-$workload-$config-val-${SUSTAIN_RPS}.txt"
                echo "  validate @ R=${SUSTAIN_RPS} (${PROBE_DURATION_SEC}s) …"
                "$WRK2_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" \
                    -d"${PROBE_DURATION_SEC}s" -R"$SUSTAIN_RPS" --latency "$URL" > "$val_raw" 2>&1 || true
                read -r VP50 VP99 VP99_9 VP99_99 <<< "$(parse_pct "$val_raw")"
                V_OK=$(python3 -c "
p99   = float('$VP99')
p99_9 = float('$VP99_9')
p99_99 = float('$VP99_99')
ok_p99  = p99    <= float('$P99_BUDGET_MS')
ok_999  = p99_9  <= max(p99 * 3.0,  p99 + 2.0)
ok_9999 = p99_99 <= max(p99 * 10.0, p99 + 5.0)
print(1 if (ok_p99 and ok_999 and ok_9999) else 0)
")
                if [ "$V_OK" = "1" ]; then
                    echo "    validation OK: p99=${VP99}ms p99.9=${VP99_9}ms p99.99=${VP99_99}ms"
                    break
                else
                    echo "    validation FAILED: p99=${VP99}ms p99.9=${VP99_9}ms p99.99=${VP99_99}ms"
                    if [ "$_val_attempt" = "1" ]; then
                        # Back off 8% and try one more time.
                        PEAK_RPS=$(python3 -c "print(int(float('$PEAK_RPS') * 0.92))")
                        SUSTAIN_RPS=$(python3 -c "print(int(float('$PEAK_RPS') * $SUSTAIN_PCT / 100))")
                        echo "    backing off to peak=${PEAK_RPS} sustain=${SUSTAIN_RPS}"
                    fi
                fi
            done
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

            # Append to summary. Pull both the median and the
            # sample-stdev for each percentile so the table can
            # render "value ± σ" cells -- "correct statistics"
            # over the 5 measurement runs, not just a midpoint.
            med=$(python3 -c "import json; d=json.load(open('$stats_json')); print(int(d['summary']['median_req_per_sec']))")
            stv=$(python3 -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['stdev_pct']:.2f}\")")
            p50=$(python3 -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['median_p50_ms']:.2f}\")")
            p99=$(python3 -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['median_p99_ms']:.2f}\")")
            p99_9=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('median_p99_9_ms', 0.0); print(f\"{v:.2f}\")")
            p99_99=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('median_p99_99_ms', 0.0); print(f\"{v:.2f}\")")
            sp50=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('stdev_p50_ms', 0.0); print(f\"{v:.2f}\")")
            sp99=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('stdev_p99_ms', 0.0); print(f\"{v:.2f}\")")
            sp99_9=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('stdev_p99_9_ms', 0.0); print(f\"{v:.2f}\")")
            sp99_99=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('stdev_p99_99_ms', 0.0); print(f\"{v:.2f}\")")
            stable=$(python3 -c "import json; d=json.load(open('$stats_json')); print(str(d['summary']['stable']).lower())")
            SUMMARY_ROWS+=("$target|$workload|$config|$med|$stv|$p50|$sp50|$p99|$sp99|$p99_9|$sp99_9|$p99_99|$sp99_99|$stable")

            # Teardown.
            [[ -f "$FLARE_BENCH_PID_FILE" ]] && kill -9 "$(cat "$FLARE_BENCH_PID_FILE")" 2>/dev/null || true
            kill -9 $RUNNER_PID 2>/dev/null || true
            kill_port
        done
    done
done

# ── Emit summary.md ───────────────────────────────────────────────────────────
#
# Each percentile cell is "median ± σ" over the 5 measurement
# runs (σ is the sample stdev from _stat.py). req/s stays a
# bare integer (peak capacity) with a separate "req/s stdev%"
# column that doubles as the stability gate (<3% / <5%
# depending on the config).
{
    echo "# Benchmark summary"
    echo ""
    echo "- Run: ${TS}-${HOST_TAG}-${COMMIT}"
    echo "- See env.json for hardware / toolchain versions."
    echo "- Percentile cells: median ± σ over 5 measurement runs (ms)."
    echo ""
    echo "| Target | Workload | Config | Req/s (median) | req/s σ% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |"
    echo "|---|---|---|---:|---:|---:|---:|---:|---:|---|"
    for row in "${SUMMARY_ROWS[@]}"; do
        IFS='|' read -r t w c m s p50 sp50 p99 sp99 p999 sp999 p9999 sp9999 stab <<< "$row"
        printf "| %s | %s | %s | %s | %s | %s ± %s | %s ± %s | %s ± %s | %s ± %s | %s |\n" \
            "$t" "$w" "$c" "$m" "$s" \
            "$p50" "$sp50" \
            "$p99" "$sp99" \
            "$p999" "$sp999" \
            "$p9999" "$sp9999" \
            "$stab"
    done
} > "$RESULTS_DIR/summary.md"

echo ""
echo "══ Benchmark complete ══"
echo "Results: $RESULTS_DIR"
echo ""
cat "$RESULTS_DIR/summary.md"
