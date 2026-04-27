#!/usr/bin/env bash
# benchmark/scripts/_soak_observe.sh
#
# v0.5.0 / S3.7 — RSS / fd-count poller for the soak harness.
#
# Given a flare server PID and an output dir, samples
# ``VmRSS`` / ``VmHWM`` / ``VmPeak`` from ``/proc/$PID/status`` and the
# open-fd count from ``/proc/$PID/fd`` at a configurable interval.
# Writes one JSONL line per sample to ``$OUT_DIR/observe.jsonl`` with
# the schema
#
#   {"ts_ms": 12345, "rss_kb": 65432, "hwm_kb": 65432, "peak_kb": 65432,
#    "fd_count": 17}
#
# The driver (``_run_soak.sh``) consumes the JSONL after the run
# completes to compute start / end / max for the per-workload gates
# (RSS within 2x of cold-start, fds bounded).
#
# Usage:
#   bash _soak_observe.sh <pid> <out_dir> [interval_secs]
#
# Behaviour:
# * Auto-scales sample interval if the third arg is omitted: 1 s
#   (so the 60 s smoke window still has ~60 samples).
# * Bails cleanly when the PID is gone (``/proc/$PID`` no longer
#   exists). Designed to be SIGTERM-able from the parent driver.
# * Linux-only (relies on ``/proc/<pid>/status``); macOS path is the
#   ``ps -o rss=`` fallback elsewhere when this lands. Soak gates
#   are Linux-EPYC anyway per design-v0.5 §6.5, so this is the
#   only platform we need today.

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <pid> <out_dir> [interval_secs=1]" >&2
    exit 2
fi

PID="$1"
OUT_DIR="$2"
INTERVAL_SECS="${3:-1}"

mkdir -p "$OUT_DIR"
OBSERVE_FILE="$OUT_DIR/observe.jsonl"
: > "$OBSERVE_FILE"

# Capture absolute start so ts_ms is monotonic per run.
START_NS="$(date +%s%N)"

cleanup() {
    : # nothing else to do; observer exits as soon as the pid dies
      # or the parent SIGTERMs us.
}
trap cleanup INT TERM EXIT

read_kb() {
    # $1 = field prefix (e.g. "VmRSS")
    awk -v p="^${1}:" '$0 ~ p {print $2; exit}' "/proc/$PID/status" 2>/dev/null || echo 0
}

count_fds() {
    # Avoids piping ls into wc, which subprocess-spawns each iter
    # and inflates the observer's own RSS over a 24 h run.
    local n=0
    if [ -d "/proc/$PID/fd" ]; then
        for _ in /proc/"$PID"/fd/*; do
            n=$((n + 1))
        done
    fi
    echo "$n"
}

while [ -d "/proc/$PID" ]; do
    NOW_NS="$(date +%s%N)"
    TS_MS=$(( (NOW_NS - START_NS) / 1000000 ))

    RSS_KB="$(read_kb VmRSS)"
    HWM_KB="$(read_kb VmHWM)"
    PEAK_KB="$(read_kb VmPeak)"
    FD_COUNT="$(count_fds)"

    printf '{"ts_ms": %s, "rss_kb": %s, "hwm_kb": %s, "peak_kb": %s, "fd_count": %s}\n' \
        "$TS_MS" "${RSS_KB:-0}" "${HWM_KB:-0}" "${PEAK_KB:-0}" "$FD_COUNT" \
        >> "$OBSERVE_FILE"

    sleep "$INTERVAL_SECS"
done
