#!/usr/bin/env bash
# benchmark/scripts/bench_h2.sh -- HTTP/2 throughput harness.
#
# The h2 twin of bench_h3.sh: drives h2load over cleartext HTTP/2
# (h2c prior knowledge) against the flare unified server baseline and
# the reference baselines (nginx, go_nethttp, hyper, axum, actix_web)
# under one config, collects five measurement runs, parses the h2load
# --log-file per-request timings for tail percentiles via _stat_h3.py
# (same aggregator; h2load output shape is identical), and writes:
#
#   benchmark/results/v0.9/h2/${TARGET}.json
#   benchmark/results/v0.9/h2/${TARGET}.summary.txt
#
# Usage:
#   benchmark/scripts/bench_h2.sh flare        # flare h2c baseline
#   benchmark/scripts/bench_h2.sh nginx        # nginx baseline
#   benchmark/scripts/bench_h2.sh all          # every provisioned target
#
# Probe: needs h2load on PATH and the requested target's run.sh /
# check.sh. Missing either exits 0 with a banner (bench infra in place;
# host lacks the tool / baseline) so CI pins a deterministic posture.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="${1:-flare}"
CONFIG="${H2_CONFIG:-${REPO_ROOT}/benchmark/configs/h2_throughput.yaml}"
RESULTS_DIR="${REPO_ROOT}/benchmark/results/v0.9/h2"
RAW_DIR="${RESULTS_DIR}/RAW"
PORT="${FLARE_BENCH_PORT:-8080}"

mkdir -p "${RESULTS_DIR}" "${RAW_DIR}"

H2LOAD_BIN="$(command -v h2load 2>/dev/null || true)"

print_skip_banner() {
    cat <<EOF
==============================================================
bench_h2: h2load not available on this host

  Install nghttp2's h2load (Ubuntu: apt install nghttp2-client;
  macOS: brew install nghttp2) and re-run. The bench
  infrastructure is in place:

    benchmark/configs/h2_throughput.yaml   workload config
    benchmark/scripts/bench_h2.sh          this harness
    benchmark/scripts/_stat_h3.py          aggregator (shared)

  Exiting status 0 so a missing h2load isn't a CI regression.
==============================================================
EOF
}

probe_target() {
    local d="${REPO_ROOT}/benchmark/baselines/$1"
    [[ -x "${d}/run.sh" ]] && [[ -x "${d}/check.sh" ]]
}

cfg_value() {
    local v
    v="$(awk -v k="$1:" '$1 == k { print $2 }' "${CONFIG}" 2>/dev/null || true)"
    echo "${v:-$2}"
}

CLIENTS="$(cfg_value h2load_clients 1)"
STREAMS="$(cfg_value h2load_streams 100)"
DURATION_S="$(cfg_value h2load_duration_seconds 30)"
WARMUP_S="$(cfg_value warmup_seconds 10)"
RUNS="$(cfg_value runs 5)"
QUIET_S="$(cfg_value quiet_seconds 5)"

run_one_target() {
    local target="$1"
    local run_sh="${REPO_ROOT}/benchmark/baselines/${target}/run.sh"
    local check_sh="${REPO_ROOT}/benchmark/baselines/${target}/check.sh"
    local pid_file="${RESULTS_DIR}/.server.${target}.pid"
    local out_json="${RESULTS_DIR}/${target}.json"
    local out_summary="${RESULTS_DIR}/${target}.summary.txt"

    echo "==> [${target}] starting baseline on 127.0.0.1:${PORT}"
    rm -f "${pid_file}"
    FLARE_BENCH_PORT="${PORT}" FLARE_BENCH_PID_FILE="${pid_file}" \
        "${run_sh}" >"${RAW_DIR}/${target}-server.log" 2>&1 &
    local launcher_pid=$!

    local waited=0
    while [[ ! -s "${pid_file}" ]] && (( waited < 600 )); do
        sleep 1
        (( waited += 1 )) || true
        if ! kill -0 "${launcher_pid}" 2>/dev/null && [[ ! -s "${pid_file}" ]]; then
            echo "[${target}] run.sh failed before writing PID" >&2
            tail -20 "${RAW_DIR}/${target}-server.log" >&2 || true
            return 1
        fi
    done
    [[ -s "${pid_file}" ]] || { echo "[${target}] no PID file" >&2; return 1; }
    local srv_pid; srv_pid="$(cat "${pid_file}")"

    _ph2_cleanup() {
        if [[ -n "${srv_pid:-}" ]] && kill -0 "${srv_pid}" 2>/dev/null; then
            kill "${srv_pid}" 2>/dev/null || true
            sleep 0.5
            kill -9 "${srv_pid}" 2>/dev/null || true
        fi
        rm -f "${pid_file}"
    }
    trap '_ph2_cleanup' RETURN

    echo "==> [${target}] readiness via check.sh"
    FLARE_BENCH_PORT="${PORT}" "${check_sh}" || {
        echo "[${target}] check.sh failed" >&2; return 1; }
    sleep "${QUIET_S}"

    local url="http://127.0.0.1:${PORT}/plaintext"

    echo "==> [${target}] warmup (${WARMUP_S}s)"
    "${H2LOAD_BIN}" -c "${CLIENTS}" -m "${STREAMS}" -D "${WARMUP_S}" \
        "${url}" > "${RAW_DIR}/${target}-warmup.txt" 2>&1 || true

    local i raw log
    for i in $(seq 1 "${RUNS}"); do
        raw="${RAW_DIR}/${target}-run-${i}.txt"
        log="${raw}.log"
        echo "==> [${target}] run ${i}/${RUNS} (${DURATION_S}s)"
        "${H2LOAD_BIN}" -c "${CLIENTS}" -m "${STREAMS}" -D "${DURATION_S}" \
            --log-file="${log}" "${url}" > "${raw}" 2>&1 || true
        sleep "${QUIET_S}"
    done

    echo "==> [${target}] aggregating to ${out_json}"
    local agg_runs=()
    for i in $(seq 1 "${RUNS}"); do
        agg_runs+=( "${RAW_DIR}/${target}-run-${i}.txt" )
    done
    python3 "${REPO_ROOT}/benchmark/scripts/_stat_h3.py" \
        "${out_json}" "${agg_runs[@]}" | tee "${out_summary}"
}

if [[ -z "${H2LOAD_BIN}" ]]; then
    print_skip_banner
    exit 0
fi

case "${TARGET}" in
    all)
        for t in flare nginx go_nethttp hyper axum actix_web; do
            if probe_target "${t}"; then run_one_target "${t}"; fi
        done
        ;;
    *)
        probe_target "${TARGET}" || { echo "${TARGET} baseline missing"; exit 1; }
        run_one_target "${TARGET}"
        ;;
esac

"${REPO_ROOT}/benchmark/scripts/_collect_env.sh" > "${RESULTS_DIR}/env.json" 2>/dev/null || true
exit 0
