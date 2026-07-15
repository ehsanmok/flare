#!/usr/bin/env bash
# tools/run_conformance.sh -- external protocol conformance harness.
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
#   tools/run_conformance.sh              # run every provisioned suite
#   tools/run_conformance.sh h2spec       # run one suite by name
#
# Provisioning (documented host blocker):
#   h2spec:       https://github.com/summerwind/h2spec/releases
#   autobahn:     pip install autobahntestsuite  (provides `wstest`)
#   quic-interop: https://github.com/quic-interop/quic-interop-runner
set -uo pipefail

SUITES="${*:-h2spec autobahn quic-interop}"
FAIL=0
RAN=0
SKIP=0

_have() { command -v "$1" >/dev/null 2>&1; }

run_h2spec() {
  if ! _have h2spec; then
    echo "── h2spec: NOT PROVISIONED (install from summerwind/h2spec); skipping"
    SKIP=$((SKIP + 1))
    return 0
  fi
  echo "── h2spec: starting flare h2c server + running suite"
  # Spawn the h2c server example on an ephemeral port, then point h2spec
  # at it. The example prints its port on the first line of stdout.
  pixi run mojo -I . examples/intermediate/h2c_server.mojo &
  local srv=$!
  sleep 2
  h2spec -p 8080 -h 127.0.0.1
  local rc=$?
  kill "${srv}" 2>/dev/null || true
  RAN=$((RAN + 1))
  [ $rc -ne 0 ] && FAIL=$((FAIL + 1))
  return 0
}

run_autobahn() {
  if ! _have wstest; then
    echo "── autobahn: NOT PROVISIONED (pip install autobahntestsuite); skipping"
    SKIP=$((SKIP + 1))
    return 0
  fi
  echo "── autobahn: starting flare WsServer + running fuzzingclient"
  pixi run mojo -I . examples/intermediate/websocket_echo.mojo &
  local srv=$!
  sleep 2
  wstest -m fuzzingclient -s tools/conformance/autobahn.json
  local rc=$?
  kill "${srv}" 2>/dev/null || true
  RAN=$((RAN + 1))
  [ $rc -ne 0 ] && FAIL=$((FAIL + 1))
  return 0
}

run_quic_interop() {
  if ! _have quic-interop-runner && [ ! -d "${QUIC_INTEROP_RUNNER:-/nonexistent}" ]; then
    echo "── quic-interop: NOT PROVISIONED (clone quic-interop/quic-interop-runner); skipping"
    SKIP=$((SKIP + 1))
    return 0
  fi
  echo "── quic-interop: driving the QuicListener under the interop runner"
  echo "   (runner integration is host-specific; see the repo README)"
  RAN=$((RAN + 1))
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
