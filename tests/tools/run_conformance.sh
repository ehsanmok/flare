#!/usr/bin/env bash
# tests/tools/run_conformance.sh -- external protocol conformance harness.
#
# Wires the three standard third-party conformance suites against a
# running flare server:
#
#   h2spec       -- HTTP/2 (RFC 9113) server conformance, run against the
#                   cleartext h2c server.
#   autobahn     -- WebSocket (RFC 6455 + RFC 7692) fuzzingclient against
#                   the flare WsServer.
#   quic-interop -- QUIC / HTTP-3 interop runner against the QuicListener.
#
# Each suite needs an external binary that is NOT bundled with the repo
# (h2spec, wstest/autobahn-testsuite, the quic-interop-runner harness).
# This script probes for each binary; when present it runs the suite,
# when absent it prints a clear "not provisioned on this host" notice and
# skips that leg. It exits non-zero only when a *provisioned* suite
# actually fails, so CI can wire it as a leg today and it turns green
# automatically once a runner image ships the binaries.
#
# Usage:
#   tests/tools/run_conformance.sh              # run every provisioned suite
#   tests/tools/run_conformance.sh h2spec       # run one suite by name
#
# Provisioning (documented host blocker):
#   h2spec:       https://github.com/summerwind/h2spec/releases
#   autobahn:     `wstest` on PATH, or a running Docker daemon (the
#                 harness falls back to crossbario/autobahn-testsuite;
#                 pip install autobahntestsuite is Python 2 only)
#   quic-interop: https://github.com/quic-interop/quic-interop-runner
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

SUITES="${*:-h2spec autobahn quic-interop}"
FAIL=0
RAN=0
SKIP=0

_have() { command -v "$1" >/dev/null 2>&1; }

H2SPEC_BIN="${H2SPEC_BIN:-build/h2spec/h2spec}"
H2SPEC_PORT="${H2SPEC_PORT:-18692}"
H2C_SERVER_BIN="target/conformance/flare_h2c"

_h2spec_cmd() {
  if [ -x "${REPO_ROOT}/${H2SPEC_BIN}" ]; then
    echo "${REPO_ROOT}/${H2SPEC_BIN}"
  elif _have h2spec; then
    echo "h2spec"
  fi
}

# Block until the port answers, so the suite never races the server.
_wait_for_port() {
  local port="$1" tries=0
  while [ "$tries" -lt 100 ]; do
    if curl -s -o /dev/null --http2-prior-knowledge \
        "http://127.0.0.1:${port}/plaintext" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
    tries=$((tries + 1))
  done
  return 1
}

run_h2spec() {
  local h2spec
  h2spec="$(_h2spec_cmd)"
  if [ -z "${h2spec}" ]; then
    echo "── h2spec: NOT PROVISIONED (run: pixi run install-h2spec); skipping"
    SKIP=$((SKIP + 1))
    return 0
  fi
  echo "── h2spec: starting flare h2c server + running suite"
  # Reuse the same server the interop smoke drives: it serves h2c
  # prior-knowledge on FLARE_BENCH_PORT and is already proven to answer
  # curl --http2-prior-knowledge with a 200.
  mkdir -p target/conformance
  if ! pixi run mojo build -D ASSERT=none -I . \
       benchmark/baselines/flare_mc/main.mojo -o "${H2C_SERVER_BIN}" \
       > target/conformance/build.log 2>&1; then
    echo "   h2c server BUILD FAILED"
    cat target/conformance/build.log
    FAIL=$((FAIL + 1))
    return 0
  fi
  FLARE_BENCH_PORT="${H2SPEC_PORT}" FLARE_BENCH_WORKERS=1 \
    "${H2C_SERVER_BIN}" > target/conformance/h2c-server.log 2>&1 &
  local srv=$!
  if ! _wait_for_port "${H2SPEC_PORT}"; then
    echo "   h2c server never came up on ${H2SPEC_PORT}"
    cat target/conformance/h2c-server.log
    kill -9 "${srv}" 2>/dev/null || true
    FAIL=$((FAIL + 1))
    return 0
  fi
  "${h2spec}" -h 127.0.0.1 -p "${H2SPEC_PORT}" -P /plaintext \
    --strict --timeout 5 | tee target/conformance/h2spec.txt
  kill -9 "${srv}" 2>/dev/null || true
  RAN=$((RAN + 1))
  _h2spec_verdict || FAIL=$((FAIL + 1))
  return 0
}

# Compare the failing case ids against the documented allowlist, so the
# gate is "no new failures" rather than "no failures". h2spec numbers
# each case as <suite>/<section>/<index>; reconstruct that from the
# report's indented section headings.
_h2spec_verdict() {
  local report="target/conformance/h2spec.txt"
  local allow="tests/tools/conformance/h2spec-known-fail.txt"
  [ -f "${report}" ] || return 1

  local failed
  failed="$(awk '
    /^Failures:/ { infail = 1; next }
    !infail { next }
    /^[A-Za-z]/ {
      if ($0 ~ /^Hypertext/) suite = "http2"
      else if ($0 ~ /^HPACK/) suite = "hpack"
      else if ($0 ~ /^Generic/) suite = "generic"
      next
    }
    /^ *[0-9]+(\.[0-9]+)*\. / { sec = $1; sub(/\.$/, "", sec); next }
    /^ *× [0-9]+:/ {
      n = $2; sub(/:$/, "", n)
      id = suite "/" sec "/" n
      # Dedupe in awk. This used to pipe through `sort -u`, and under
      # `pixi run` LD_LIBRARY_PATH points at the newer libssl in the
      # pixi env, so system /usr/bin/sort fails to load on ubuntu-latest,
      # wanting an OPENSSL_3.3.0 symbol version it cannot find. Inside
      # a command substitution that failure is silent: failed came
      # back empty and this function reported
      # "all cases passed" on a run h2spec had scored 146/147. The gate
      # was not gating. Same trap is documented at the example loop in
      # run_test_aggregates.sh.
      if (!seen[id]++) print id
    }
  ' "${report}")"

  # Cross-check the parse against h2spec's own tally, so a report whose
  # shape changes cannot silently yield an empty failure list again.
  local reported
  reported="$(awk '/[0-9]+ tests, / { for (i = 1; i <= NF; i++) if ($i == "failed") print $(i-1) }' "${report}" | tail -1)"
  local parsed
  parsed="$(printf '%s' "${failed}" | grep -c . || true)"
  if [ -n "${reported}" ] && [ "${reported}" != "${parsed}" ]; then
    echo "── h2spec: report says ${reported} failure(s), parsed ${parsed};" >&2
    echo "   refusing to grade a report this harness cannot read" >&2
    return 1
  fi

  if [ -z "${failed}" ]; then
    echo "── h2spec: all cases passed"
    return 0
  fi

  local unexpected=0
  while IFS= read -r case_id; do
    [ -z "${case_id}" ] && continue
    if grep -qxF "${case_id}" "${allow}" 2>/dev/null; then
      echo "── h2spec: ${case_id} fails (known, see ${allow})"
    else
      echo "── h2spec: ${case_id} FAILS and is not in ${allow}" >&2
      unexpected=1
    fi
  done <<< "${failed}"

  [ "${unexpected}" -eq 0 ]
}

WS_ECHO_PORT="${WS_ECHO_PORT:-19001}"
WS_ECHO_BIN="target/conformance/flare_ws_echo"

# Block until the WebSocket port accepts a TCP connection. The old code
# slept two seconds, which is both too long when the server is up and
# too short when the machine is loaded -- and a fuzzingclient that
# starts early reports every case as a connection failure, which reads
# like several hundred protocol bugs.
_wait_for_ws_port() {
  local port="$1" tries=0
  while [ "$tries" -lt 150 ]; do
    if _have nc; then
      nc -z 127.0.0.1 "${port}" >/dev/null 2>&1 && return 0
    elif python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1', ${port})) == 0 else 1)
" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
    tries=$((tries + 1))
  done
  return 1
}

# wstest as a binary if it is on PATH, otherwise the maintained Docker
# image. pip install autobahntestsuite only works on Python 2, so the
# image is the realistic route on a CI runner.
_wstest_available() {
  _have wstest && return 0
  # `docker info` blocks indefinitely when the CLI is installed but the
  # daemon is not answering -- the common state on a developer laptop.
  # Ask the daemon's own API with a deadline instead.
  if _have docker; then
    if curl -s --max-time 3 --unix-socket /var/run/docker.sock \
         http://localhost/_ping >/dev/null 2>&1; then
      return 0
    fi
  fi
  return 1
}

_run_wstest() {
  if _have wstest; then
    wstest -m fuzzingclient -s tests/tools/conformance/autobahn.json
    return $?
  fi
  docker run --rm --network host \
    -v "${REPO_ROOT}:/mnt" -w /mnt \
    crossbario/autobahn-testsuite:latest \
    wstest -m fuzzingclient -s tests/tools/conformance/autobahn.json
}

# Fail on any case whose behavior is not OK / NON-STRICT /
# INFORMATIONAL and is not on the documented allowlist.
_autobahn_verdict() {
  local index="target/conformance/autobahn/index.json"
  local allow="tests/tools/conformance/autobahn-known-fail.txt"
  if [ ! -f "${index}" ]; then
    echo "── autobahn: no index.json written; treating as a failure" >&2
    return 1
  fi
  python3 - "${index}" "${allow}" <<'PYEOF'
import json, sys

index_path, allow_path = sys.argv[1], sys.argv[2]
with open(index_path) as f:
    report = json.load(f)

allowed = set()
try:
    with open(allow_path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                allowed.add(line)
except FileNotFoundError:
    pass

ok = {"OK", "NON-STRICT", "INFORMATIONAL"}
bad, silenced = [], []
for agent, cases in report.items():
    for case_id, result in sorted(cases.items()):
        behavior = result.get("behavior", "MISSING")
        close = result.get("behaviorClose", "OK")
        if behavior in ok and close in ok:
            continue
        (silenced if case_id in allowed else bad).append(
            "%s  %s (behavior=%s close=%s)" % (agent, case_id, behavior, close)
        )

for line in silenced:
    print("   known-fail: " + line)
for line in bad:
    print("   FAIL: " + line)
print("── autobahn: %d case(s) failed outside the allowlist, %d known"
      % (len(bad), len(silenced)))
sys.exit(1 if bad else 0)
PYEOF
}

run_autobahn() {
  if ! _wstest_available; then
    echo "── autobahn: NOT PROVISIONED (need wstest on PATH, or a running"
    echo "   Docker daemon for crossbario/autobahn-testsuite); skipping"
    SKIP=$((SKIP + 1))
    return 0
  fi
  if [ ! -f "${REPO_ROOT}/tests/tools/conformance/autobahn.json" ]; then
    echo "── autobahn: wstest present but tests/tools/conformance/autobahn.json is"
    echo "   missing; cannot run. Skipping."
    SKIP=$((SKIP + 1))
    return 0
  fi
  echo "── autobahn: starting flare echo server + running fuzzingclient"
  mkdir -p target/conformance
  if ! pixi run mojo build -I . examples/basic/websocket_echo_server.mojo \
       -o "${WS_ECHO_BIN}" > target/conformance/ws-build.log 2>&1; then
    echo "   echo server BUILD FAILED"
    cat target/conformance/ws-build.log
    FAIL=$((FAIL + 1))
    return 0
  fi
  # Budget 0: serve until killed. The fuzzingclient opens one
  # connection per case, several hundred of them.
  FLARE_WS_ECHO_PORT="${WS_ECHO_PORT}" FLARE_WS_ECHO_MAX_CONNS=0 \
    "${WS_ECHO_BIN}" > target/conformance/ws-echo.log 2>&1 &
  local srv=$!
  if ! _wait_for_ws_port "${WS_ECHO_PORT}"; then
    echo "   echo server never came up on ${WS_ECHO_PORT}"
    cat target/conformance/ws-echo.log
    kill -9 "${srv}" 2>/dev/null || true
    FAIL=$((FAIL + 1))
    return 0
  fi
  _run_wstest
  kill -9 "${srv}" 2>/dev/null || true
  RAN=$((RAN + 1))
  _autobahn_verdict || FAIL=$((FAIL + 1))
  return 0
}

run_quic_interop() {
  if ! _have quic-interop-runner && [ ! -d "${QUIC_INTEROP_RUNNER:-/nonexistent}" ]; then
    echo "── quic-interop: NOT PROVISIONED (clone quic-interop/quic-interop-runner); skipping"
    SKIP=$((SKIP + 1))
    return 0
  fi
  # The runner is present but nothing drives it yet. Count this as a
  # skip, never a pass: reporting a suite as "ran" without invoking it
  # is worse than reporting it missing.
  echo "── quic-interop: runner found, but flare has no integration yet;"
  echo "   skipping (tracked as open work, not a pass)"
  SKIP=$((SKIP + 1))
  return 0
}

for suite in $SUITES; do
  case "$suite" in
    h2spec) run_h2spec ;;
    autobahn) run_autobahn ;;
    quic-interop) run_quic_interop ;;
    *) echo "unknown suite: $suite" >&2; exit 2 ;;
  esac
done

echo
echo "── conformance summary: ${RAN} ran, ${SKIP} skipped (not provisioned), ${FAIL} failed"
exit $FAIL
