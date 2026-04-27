#!/usr/bin/env bash
# benchmark/scripts/_run_soak_smoke.sh
#
# v0.5.0 / S3.7 — smoke tier of the soak harness.
#
# Runs all three workloads back-to-back at 60 s/workload (~3 min
# total) and prints a one-line PASS/FAIL summary per workload at
# the end. Designed to be cheap enough for PR CI / iterative dev.
#
# The 60 s window evaluates every gate the 24 h release-gate run
# evaluates (zero non-2xx, RSS within 2x of cold-start, fd_count
# bounded). The "RSS flat after 1 hour" signal lives only in the
# release-gate run; smoke only catches the loud failures.
#
# See docs/soak.md and design-v0.5 §6.5 for the full gate
# definitions and the three-tier model.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DRIVER="$ROOT/benchmark/scripts/_run_soak.sh"

: > /tmp/_soak_smoke_results.txt

run_workload() {
    local wl="$1"
    if bash "$DRIVER" --workload="$wl" --duration-secs=60; then
        echo "PASS $wl" >> /tmp/_soak_smoke_results.txt
    else
        echo "FAIL $wl" >> /tmp/_soak_smoke_results.txt
    fi
}

run_workload slow_clients
run_workload churn
run_workload mixed

echo ""
echo "════════ Soak smoke summary (60s/workload) ════════"
cat /tmp/_soak_smoke_results.txt

# Exit non-zero if any workload failed.
if grep -q '^FAIL' /tmp/_soak_smoke_results.txt; then
    exit 1
fi
exit 0
