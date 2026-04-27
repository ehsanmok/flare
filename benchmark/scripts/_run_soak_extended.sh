#!/usr/bin/env bash
# benchmark/scripts/_run_soak_extended.sh
#
# v0.5.0 / S3.7 — extended tier of the soak harness.
#
# Runs all three workloads back-to-back at 300 s/workload (~15 min
# total). Stronger RSS-trend signal than the 60 s smoke; cheap
# enough to run on demand before pushing larger changes, but still
# below the 24 h release-gate threshold.
#
# Uses the same per-workload driver and the same gate definitions
# as the smoke + release-gate tiers. Only the duration knob
# differs.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DRIVER="$ROOT/benchmark/scripts/_run_soak.sh"

: > /tmp/_soak_extended_results.txt

run_workload() {
    local wl="$1"
    if bash "$DRIVER" --workload="$wl" --duration-secs=300; then
        echo "PASS $wl" >> /tmp/_soak_extended_results.txt
    else
        echo "FAIL $wl" >> /tmp/_soak_extended_results.txt
    fi
}

run_workload slow_clients
run_workload churn
run_workload mixed

echo ""
echo "════════ Soak extended summary (300s/workload) ════════"
cat /tmp/_soak_extended_results.txt

if grep -q '^FAIL' /tmp/_soak_extended_results.txt; then
    exit 1
fi
exit 0
