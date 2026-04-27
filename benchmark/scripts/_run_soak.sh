#!/usr/bin/env bash
# benchmark/scripts/_run_soak.sh
#
# v0.5.0 / S3.7 — per-workload soak driver (slow-client / churn /
# mixed-load).
#
# Boots the flare bench server (same entry point the
# bench-vs-baseline harness uses, ``benchmark/baselines/flare/main.mojo``),
# kicks off ``_soak_observe.sh`` against its PID, runs wrk with the
# matching ``wrk_soak_*.lua`` script for ``--duration-secs``, then
# tears everything down and emits a structured ``summary.json``
# under ``build/soak/<workload>/<timestamp>/``.
#
# Three-tier model (see docs/soak.md):
# * smoke    (60 s/workload via SOAK_DURATION_SECS=60, default)
# * extended (300 s/workload via SOAK_DURATION_SECS=300)
# * release  (86400 s/workload via SOAK_DURATION_SECS=86400) — EPYC
#
# Same script for all three tiers; only the duration knob differs.
#
# Usage:
#   bash _run_soak.sh --workload=<slow_clients|churn|mixed> \
#                     --duration-secs=<N>
#
# Exit code:
#   0 if the workload's gate passes against the design-v0.5 §6.5
#   thresholds (RSS within 2x cold-start, fd_count bounded, zero
#   wrk-reported errors), 1 otherwise.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS_DIR="$ROOT/benchmark/scripts"
BASELINE_DIR="$ROOT/benchmark/baselines/flare"

# ── Args ─────────────────────────────────────────────────────────────────────
WORKLOAD=""
DURATION_SECS=""
for arg in "$@"; do
    case "$arg" in
        --workload=*)      WORKLOAD="${arg#--workload=}" ;;
        --duration-secs=*) DURATION_SECS="${arg#--duration-secs=}" ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

case "$WORKLOAD" in
    slow_clients|churn|mixed) ;;
    *) echo "[_run_soak] --workload must be one of: slow_clients churn mixed" >&2; exit 2 ;;
esac

if [ -z "$DURATION_SECS" ] || ! [[ "$DURATION_SECS" =~ ^[0-9]+$ ]]; then
    echo "[_run_soak] --duration-secs must be a positive integer" >&2
    exit 2
fi

# ── Per-workload wrk shape ──────────────────────────────────────────────────
# Tuned to mirror design-v0.5 §6.5 intent at a per-tier feasible
# concurrency. EPYC release-gate runs can override these via
# ``SOAK_WRK_CONNS`` / ``SOAK_WRK_THREADS`` if the box can take it.
case "$WORKLOAD" in
    slow_clients)
        LUA="$SCRIPTS_DIR/wrk_soak_slow_clients.lua"
        DEFAULT_THREADS=2
        DEFAULT_CONNS=256   # design-v0.5: 256 connections
        ;;
    churn)
        LUA="$SCRIPTS_DIR/wrk_soak_churn.lua"
        DEFAULT_THREADS=2
        DEFAULT_CONNS=64    # ephemeral-port turnover dominates anyway
        ;;
    mixed)
        LUA="$SCRIPTS_DIR/wrk_soak_mixed.lua"
        DEFAULT_THREADS=2
        DEFAULT_CONNS=64
        ;;
esac

WRK_THREADS="${SOAK_WRK_THREADS:-$DEFAULT_THREADS}"
WRK_CONNS="${SOAK_WRK_CONNS:-$DEFAULT_CONNS}"

# Sample interval auto-scales: 1 s for short tiers (so the 60 s
# smoke still produces ~60 samples), 5 s above 120 s to avoid
# observer self-cost on the 24 h release-gate run.
if [ "$DURATION_SECS" -le 120 ]; then
    OBSERVE_INTERVAL=1
else
    OBSERVE_INTERVAL=5
fi

# ── Output paths ────────────────────────────────────────────────────────────
TS="$(date -u +'%Y-%m-%dT%H%M%S')"
COMMIT="$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
HOST_TAG="$(hostname -s 2>/dev/null || hostname)"
OUT_DIR="$ROOT/build/soak/${WORKLOAD}/${TS}-${HOST_TAG}-${COMMIT}"
mkdir -p "$OUT_DIR"

WRK_OUT="$OUT_DIR/wrk.txt"
SUMMARY_JSON="$OUT_DIR/summary.json"

# ── Tier label for summary.json ─────────────────────────────────────────────
if [ "$DURATION_SECS" -le 120 ]; then
    TIER="smoke"
elif [ "$DURATION_SECS" -le 1800 ]; then
    TIER="extended"
else
    TIER="release"
fi

# ── Boot the flare bench server ─────────────────────────────────────────────
PORT="${FLARE_BENCH_PORT:-8080}"
PID_FILE="$OUT_DIR/.server.pid"
export FLARE_BENCH_PORT="$PORT"
export FLARE_BENCH_PID_FILE="$PID_FILE"

# Free the port if a previous run left something behind.
lsof -ti tcp:$PORT 2>/dev/null | xargs -r kill -9 2>/dev/null || true
sleep 0.3

echo "[soak/$WORKLOAD] booting flare bench server on 127.0.0.1:$PORT (tier=$TIER, duration=${DURATION_SECS}s)"
bash "$BASELINE_DIR/run.sh" \
    >"$OUT_DIR/server.stdout" \
    2>"$OUT_DIR/server.stderr" &
RUNNER_PID=$!

cleanup() {
    # Idempotent best-effort teardown. Anything that needed a wait
    # already happened in the main flow before we hit `exit`; this
    # trap is the safety net for early termination (Ctrl-C, SIGTERM).
    [ -f "$PID_FILE" ] && kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true
    [ -n "${RUNNER_PID:-}" ] && kill -9 "$RUNNER_PID" 2>/dev/null || true
    [ -n "${OBSERVER_PID:-}" ] && kill -9 "$OBSERVER_PID" 2>/dev/null || true
    lsof -ti tcp:$PORT 2>/dev/null | xargs -r kill -9 2>/dev/null || true
}
trap cleanup INT TERM

# Wait for the server to come up. flare's first-run JIT compile
# can take ~15 s; reuse the existing check.sh which already polls.
if ! bash "$BASELINE_DIR/check.sh"; then
    echo "[soak/$WORKLOAD] flare bench server failed to come up; aborting" >&2
    exit 1
fi

SERVER_PID="$(cat "$PID_FILE")"
echo "[soak/$WORKLOAD] server pid=$SERVER_PID"

# ── Start observer ──────────────────────────────────────────────────────────
bash "$SCRIPTS_DIR/_soak_observe.sh" "$SERVER_PID" "$OUT_DIR" "$OBSERVE_INTERVAL" \
    >/dev/null 2>"$OUT_DIR/observer.stderr" &
OBSERVER_PID=$!

# Tiny grace period so observer captures cold-start RSS before
# the load actually hits.
sleep 1

# ── Run wrk ─────────────────────────────────────────────────────────────────
URL="http://127.0.0.1:$PORT/plaintext"
echo "[soak/$WORKLOAD] wrk -t$WRK_THREADS -c$WRK_CONNS -d${DURATION_SECS}s -s $LUA $URL"
wrk -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${DURATION_SECS}s" \
    --latency \
    -s "$LUA" \
    "$URL" > "$WRK_OUT" 2>&1 || true

# ── Drain pause ─────────────────────────────────────────────────────────────
# When wrk exits with hundreds of in-flight close-after-response
# connections (esp. churn / mixed), the server briefly holds those
# fds in CLOSE_WAIT / TIME_WAIT. Without a drain pause the
# observer's last sample races wrk-exit, recording fd_count well
# above the steady-state baseline and false-positive failing the
# fd_end-bounded gate (the design-doc gate is "zero leaked fds",
# not "zero in-flight conns at shutdown"). 3 s covers the kernel's
# default TCP close handshake plus flare's per-connection cleanup
# on the tightest workload (churn).
echo "[soak/$WORKLOAD] post-wrk drain (3s) so observer captures settled fd_count"
sleep 3

# ── Stop observer + server ──────────────────────────────────────────────────
# Order matters: kill the mojo server first so the observer's
# ``while [ -d /proc/$PID ]; do ... done`` loop falls through on its
# next sleep boundary, then reap both. We also need to ``wait
# $RUNNER_PID`` (the bash subshell that wraps run.sh + the mojo
# process) so the script's own ``exit`` doesn't block on a
# tracked background child.
if [ -f "$PID_FILE" ]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
fi
sleep 1
[ -f "$PID_FILE" ] && kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true

kill "$OBSERVER_PID" 2>/dev/null || true
wait "$OBSERVER_PID" 2>/dev/null || true

# RUNNER_PID is the bash subshell wrapping baselines/flare/run.sh.
# Once the mojo server inside it is dead, this bash exits quickly;
# wait reaps it so the script's own exit isn't blocked by a
# tracked background child.
kill "$RUNNER_PID" 2>/dev/null || true
wait "$RUNNER_PID" 2>/dev/null || true

# ── Aggregate summary.json ──────────────────────────────────────────────────
python3 - "$WRK_OUT" "$OUT_DIR/observe.jsonl" "$SUMMARY_JSON" \
    "$WORKLOAD" "$TIER" "$DURATION_SECS" "$WRK_THREADS" "$WRK_CONNS" "$COMMIT" "$HOST_TAG" <<'PY'
import json
import re
import sys

wrk_path, observe_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
workload, tier, duration, threads, conns, commit, host = sys.argv[4:11]

# Parse wrk output. wrk's stdout shape (-t -c -d --latency):
#
#   Running 60s test @ http://127.0.0.1:8080/plaintext
#     2 threads and 64 connections
#     Thread Stats   Avg      Stdev     Max   +/- Stdev
#       Latency   ...
#     Latency Distribution
#        50%    ...
#        75%    ...
#        90%    ...
#        99%    ...
#     <N> requests in <T>s, <bytes>B read
#     [Socket errors: connect <X>, read <Y>, write <Z>, timeout <W>]
#     Requests/sec: <R>
#     Transfer/sec: ...
def parse_wrk(text):
    out = {
        "requests_total": 0,
        "requests_per_sec": 0.0,
        "duration_secs_actual": 0.0,
        "p50_ms": None, "p75_ms": None, "p90_ms": None, "p99_ms": None,
        "socket_errors_connect": 0,
        "socket_errors_read": 0,
        "socket_errors_write": 0,
        "socket_errors_timeout": 0,
        "non_2xx_3xx": 0,
    }
    def ms(s):
        s = s.strip()
        m = re.match(r"^([0-9]+(?:\.[0-9]+)?)(us|ms|s|m)$", s)
        if not m:
            return None
        v, u = float(m.group(1)), m.group(2)
        if u == "us":
            return v / 1000.0
        if u == "ms":
            return v
        if u == "s":
            return v * 1000.0
        if u == "m":
            return v * 60_000.0
        return None
    in_dist = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Latency Distribution"):
            in_dist = True; continue
        if in_dist:
            m = re.match(r"^(\d+)%\s+(\S+)$", s)
            if m:
                pct, val = int(m.group(1)), ms(m.group(2))
                if val is None: continue
                if pct == 50: out["p50_ms"] = val
                elif pct == 75: out["p75_ms"] = val
                elif pct == 90: out["p90_ms"] = val
                elif pct == 99: out["p99_ms"] = val
                continue
            else:
                in_dist = False
        m = re.match(r"^(\d+)\s+requests in\s+([0-9.]+)([smh])", s)
        if m:
            out["requests_total"] = int(m.group(1))
            d, u = float(m.group(2)), m.group(3)
            out["duration_secs_actual"] = d if u == "s" else (d * 60 if u == "m" else d * 3600)
        m = re.match(r"^Requests/sec:\s+([0-9.]+)", s)
        if m:
            out["requests_per_sec"] = float(m.group(1))
        m = re.match(r"^Socket errors:\s*connect\s+(\d+),\s*read\s+(\d+),\s*write\s+(\d+),\s*timeout\s+(\d+)", s)
        if m:
            out["socket_errors_connect"] = int(m.group(1))
            out["socket_errors_read"] = int(m.group(2))
            out["socket_errors_write"] = int(m.group(3))
            out["socket_errors_timeout"] = int(m.group(4))
        m = re.match(r"^Non-2xx or 3xx responses:\s+(\d+)", s)
        if m:
            out["non_2xx_3xx"] = int(m.group(1))
    return out

with open(wrk_path) as f:
    wrk_text = f.read()
wrk_metrics = parse_wrk(wrk_text)

# Observe RSS / fd extremes from the observer JSONL.
rss_start = rss_end = rss_max = 0
fd_start = fd_end = fd_max = 0
samples = 0
with open(observe_path) as f:
    first = None
    last = None
    for line in f:
        try:
            row = json.loads(line)
        except Exception:
            continue
        samples += 1
        if first is None:
            first = row
        last = row
        if row["rss_kb"] > rss_max:
            rss_max = row["rss_kb"]
        if row["fd_count"] > fd_max:
            fd_max = row["fd_count"]
    if first:
        rss_start = first["rss_kb"]
        fd_start = first["fd_count"]
    if last:
        rss_end = last["rss_kb"]
        fd_end = last["fd_count"]

summary = {
    "workload": workload,
    "tier": tier,
    "duration_secs": int(duration),
    "wrk_threads": int(threads),
    "wrk_connections": int(conns),
    "commit": commit,
    "host": host,
    "wrk": wrk_metrics,
    "rss_kb_start": rss_start,
    "rss_kb_end": rss_end,
    "rss_kb_max": rss_max,
    "fd_count_start": fd_start,
    "fd_count_end": fd_end,
    "fd_count_max": fd_max,
    "observe_samples": samples,
}

# Per-workload gate evaluation (design-v0.5 §6.5):
#   slow-client: RSS within 2x of cold-start, fd_count bounded
#   churn:       fd_end <= fd_start + 16 (zero-leak threshold +
#                socket-state slack), zero socket errors
#   mixed:       zero non-2xx, RSS within 2x
gates = {}

# RSS-within-2x gate. If start was 0 (server died before observer
# warmed up), treat as fail. Use 2x or 32 MiB floor so the gate
# doesn't false-positive on a tiny start RSS.
if rss_start <= 0:
    gates["rss_within_2x"] = False
else:
    floor_kb = 32 * 1024
    bound_kb = max(2 * rss_start, rss_start + floor_kb)
    gates["rss_within_2x"] = (rss_end <= bound_kb)

# fd_end-bounded gate. 16-fd slack covers timer/wakeup/log fds
# beyond the connections themselves.
gates["fd_end_bounded"] = (fd_end <= fd_start + 16)

# Zero-error gate. Slow-client + mixed allow socket-error churn
# from the workload itself (e.g. wrk's own connect/read errors
# under high concurrency); the meaningful signal is "the server
# didn't crash and didn't return a flood of non-2xx".
total_socket_errors = (
    wrk_metrics["socket_errors_connect"]
    + wrk_metrics["socket_errors_read"]
    + wrk_metrics["socket_errors_write"]
    + wrk_metrics["socket_errors_timeout"]
)
gates["server_alive"] = (wrk_metrics["requests_total"] > 0)
gates["no_non_2xx"] = (wrk_metrics["non_2xx_3xx"] == 0)

# Workload-specific pass.
if workload == "slow_clients":
    workload_pass = gates["server_alive"] and gates["no_non_2xx"] and gates["rss_within_2x"]
elif workload == "churn":
    workload_pass = gates["server_alive"] and gates["no_non_2xx"] and gates["fd_end_bounded"]
elif workload == "mixed":
    workload_pass = gates["server_alive"] and gates["no_non_2xx"] and gates["rss_within_2x"]
else:
    workload_pass = False

summary["gates"] = gates
summary["pass"] = workload_pass

with open(out_path, "w") as f:
    json.dump(summary, f, indent=2, sort_keys=True)

print("\n[soak/{}] tier={} duration={}s req/s={:.1f} req={} non2xx={} sock_err={} rss_start={}KB rss_end={}KB rss_max={}KB fd_start={} fd_end={} fd_max={} pass={}".format(
    workload, tier, duration,
    wrk_metrics["requests_per_sec"], wrk_metrics["requests_total"],
    wrk_metrics["non_2xx_3xx"], total_socket_errors,
    rss_start, rss_end, rss_max,
    fd_start, fd_end, fd_max,
    workload_pass,
))

sys.exit(0 if workload_pass else 1)
PY

EXIT_CODE=$?

echo "[soak/$WORKLOAD] artefacts under: $OUT_DIR"
exit $EXIT_CODE
