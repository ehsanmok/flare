#!/usr/bin/env bash
# benchmark/scripts/bench_h3.sh -- HTTP/3 throughput harness
# (v0.8 Phase D, Track Q7-W commit 3/4).
#
# Drives h2load --npn-list=h3 against the flare HTTP/3 server
# baseline and the quinn + quiche reference baselines under the
# same configuration; collects five measurement runs, parses the
# h2load --log-file per-request timings for tail percentiles,
# computes the median + sigma honesty meter, and writes the
# result table to:
#
#   benchmark/results/v0.8/h3/${TARGET}.json
#   benchmark/results/v0.8/h3/${TARGET}.summary.txt
#
# Usage:
#   benchmark/scripts/bench_h3.sh flare     # flare h3 baseline
#   benchmark/scripts/bench_h3.sh quinn     # quinn baseline
#   benchmark/scripts/bench_h3.sh quiche    # quiche baseline
#   benchmark/scripts/bench_h3.sh all       # run all three back-to-back
#
# Probe step: the harness checks that h2load with HTTP/3 support
# is on PATH AND each requested target's run.sh / check.sh
# exists. If either probe fails it exits cleanly with status 0
# and a banner -- the bench infrastructure is in place; the
# operator's machine just doesn't have the h3-enabled h2load
# build yet. This matches the v0.6 h2 harness's "h2load missing"
# treatment so CI can pin a deterministic posture rather than a
# flake. Hard-gate behaviour (status != 0 on actual regressions)
# kicks in once the probes pass.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="${1:-flare}"
# H3_CONFIG selects the workload; defaults to the single-connection
# throughput gate. Point it at h3_multiconn.yaml to exercise UDP GSO
# egress (Part II Cycle C).
CONFIG="${H3_CONFIG:-${REPO_ROOT}/benchmark/configs/h3_throughput.yaml}"
RESULTS_DIR="${REPO_ROOT}/benchmark/results/v0.8/h3"
RAW_DIR="${RESULTS_DIR}/RAW"
PORT="${FLARE_BENCH_PORT:-18443}"

mkdir -p "${RESULTS_DIR}" "${RAW_DIR}"

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

H2LOAD_BIN="$(command -v h2load 2>/dev/null || true)"

probe_h2load_h3() {
    # h2load needs to be built against ngtcp2 + nghttp3 for h3
    # support. The --help output lists --alpn-list when the
    # build supports h3 (renamed from --npn-list in nghttp2
    # v1.69.0+); the same flag is silently rejected on builds
    # without. Grep both: a missing binary AND a binary without
    # h3 surface both land in the same "probe fail" branch.
    if [[ -z "${H2LOAD_BIN}" ]]; then
        return 1
    fi
    if ! "${H2LOAD_BIN}" --help 2>&1 | grep -qE -- '--(alpn|npn)-list'; then
        return 1
    fi
    return 0
}

probe_target() {
    local t="$1"
    local d="${REPO_ROOT}/benchmark/baselines/${t}"
    if [[ ! -x "${d}/run.sh" ]] || [[ ! -x "${d}/check.sh" ]]; then
        return 1
    fi
    return 0
}

print_skip_banner() {
    cat <<EOF
==============================================================
bench_h3: h2load with HTTP/3 support not available on this host

  v0.8 Phase D Track Q7-W harness needs an h2load build that
  links ngtcp2 + nghttp3. Stock distro packages (nghttp2-client
  on Ubuntu, brew install nghttp2 on macOS) ship without h3
  support. To enable on the EPYC dev-box build h2load from
  source against vendored ngtcp2 + nghttp3:

      git clone https://github.com/nghttp2/nghttp2
      ./configure --enable-http3 --with-libngtcp2 --with-libnghttp3
      make -j

  The bench infrastructure for this gate is in place:

    benchmark/configs/h3_throughput.yaml        workload config
    benchmark/baselines/flare_h3/{run,check}.sh flare baseline
    benchmark/baselines/quinn/{run,check}.sh    quinn baseline
    benchmark/baselines/quiche/{run,check}.sh   quiche baseline
    benchmark/scripts/bench_h3.sh               this harness
    benchmark/scripts/_stat_h3.py               aggregator

  Exiting status 0 so the absence of h2load-h3 doesn't manifest
  as a CI regression. When the probe clears, this script
  produces real numbers without further edits.
==============================================================
EOF
}

# ---------------------------------------------------------------------------
# Pull workload knobs out of the YAML config (single-key awk -- the YAML
# is intentionally flat-shaped so the harness doesn't drag a python
# dependency just to read it).
# ---------------------------------------------------------------------------

cfg_value() {
    local key="$1"
    local default="$2"
    local v
    v="$(awk -v k="${key}:" '$1 == k { print $2 }' "${CONFIG}" 2>/dev/null || true)"
    echo "${v:-${default}}"
}

CLIENTS="$(cfg_value h2load_clients 1)"
STREAMS="$(cfg_value h2load_streams 100)"
REQUESTS="$(cfg_value h2load_requests 100000)"
DURATION_S="$(cfg_value h2load_duration_seconds 30)"
WARMUP_S="$(cfg_value warmup_seconds 10)"
RUNS="$(cfg_value runs 5)"
QUIET_S="$(cfg_value quiet_seconds 5)"

# ---------------------------------------------------------------------------
# Per-target runner: start server, wait for ready, warmup, 5 measurement
# runs, aggregate, write JSON + summary, stop server.
# ---------------------------------------------------------------------------

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

    # Wait for the launcher script to write the server PID
    # file. run.sh forks the binary into background and writes
    # its pid, so the launcher exits within a couple of seconds
    # of starting the server. quinn / quiche cargo builds can
    # take 30-300s on first build; bound the wait at 600s.
    local waited=0
    while [[ ! -s "${pid_file}" ]] && (( waited < 600 )); do
        sleep 1
        (( waited += 1 )) || true
        if ! kill -0 "${launcher_pid}" 2>/dev/null; then
            # launcher exited; if it didn't write a pid file the
            # server failed to start. Print log + abort.
            if [[ ! -s "${pid_file}" ]]; then
                echo "[${target}] run.sh failed before writing PID" >&2
                tail -20 "${RAW_DIR}/${target}-server.log" >&2 || true
                return 1
            fi
            break
        fi
    done
    if [[ ! -s "${pid_file}" ]]; then
        echo "[${target}] timed out waiting for PID file" >&2
        return 1
    fi
    local srv_pid
    srv_pid="$(cat "${pid_file}")"
    trap '_ph3_cleanup' RETURN

    # Inner cleanup closes the server even on early-return paths.
    _ph3_cleanup() {
        if [[ -n "${srv_pid:-}" ]] && kill -0 "${srv_pid}" 2>/dev/null; then
            kill "${srv_pid}" 2>/dev/null || true
            sleep 0.5
            kill -9 "${srv_pid}" 2>/dev/null || true
        fi
        rm -f "${pid_file}"
    }

    echo "==> [${target}] waiting for readiness via check.sh"
    if ! FLARE_BENCH_PORT="${PORT}" "${check_sh}"; then
        echo "[${target}] check.sh did not pass; baseline server not answering" >&2
        return 1
    fi
    sleep "${QUIET_S}"

    local url="https://127.0.0.1:${PORT}/plaintext"

    echo "==> [${target}] warmup (${WARMUP_S}s)"
    "${H2LOAD_BIN}" --npn-list=h3 \
        -c "${CLIENTS}" -m "${STREAMS}" \
        -D "${WARMUP_S}" \
        --connect-to "127.0.0.1:${PORT}" \
        "${url}" > "${RAW_DIR}/${target}-warmup.txt" 2>&1 || true

    local i raw log
    for i in $(seq 1 "${RUNS}"); do
        raw="${RAW_DIR}/${target}-run-${i}.txt"
        log="${raw}.log"
        echo "==> [${target}] run ${i}/${RUNS} (${DURATION_S}s)"
        "${H2LOAD_BIN}" --npn-list=h3 \
            -c "${CLIENTS}" -m "${STREAMS}" \
            -D "${DURATION_S}" \
            --log-file="${log}" \
            --connect-to "127.0.0.1:${PORT}" \
            "${url}" > "${raw}" 2>&1 || true
        sleep "${QUIET_S}"
    done

    echo "==> [${target}] aggregating to ${out_json}"
    local agg_runs=()
    for i in $(seq 1 "${RUNS}"); do
        agg_runs+=( "${RAW_DIR}/${target}-run-${i}.txt" )
    done
    python3 "${REPO_ROOT}/benchmark/scripts/_stat_h3.py" \
        "${out_json}" "${agg_runs[@]}" | tee "${out_summary}"

    # Closing the trap-installed cleanup runs once the function
    # returns to its caller.
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

case "${TARGET}" in
    flare|quinn|quiche)
        ;;
    all)
        ;;
    *)
        echo "Unknown bench target: ${TARGET}" >&2
        echo "Usage: $0 {flare|quinn|quiche|all}" >&2
        exit 2
        ;;
esac

if ! probe_h2load_h3; then
    print_skip_banner
    exit 0
fi

case "${TARGET}" in
    flare)
        probe_target flare_h3 || { echo "flare_h3 baseline missing"; exit 1; }
        run_one_target flare_h3
        ;;
    quinn)
        probe_target quinn || { echo "quinn baseline missing"; exit 1; }
        run_one_target quinn
        ;;
    quiche)
        probe_target quiche || { echo "quiche baseline missing"; exit 1; }
        run_one_target quiche
        ;;
    all)
        for t in flare_h3 quinn quiche; do
            probe_target "${t}" || { echo "${t} baseline missing"; exit 1; }
        done
        run_one_target flare_h3
        run_one_target quinn
        run_one_target quiche
        ;;
esac

# Drop an env snapshot alongside the result table so downstream
# consumers can pin (host, kernel, governor) to the JSON. Same
# helper the v0.6 bench-vs-baseline harness uses.
"${REPO_ROOT}/benchmark/scripts/_collect_env.sh" > "${RESULTS_DIR}/env.json" 2>/dev/null || true

exit 0
