#!/usr/bin/env bash
# tests/tools/interop_smoke.sh — talk to flare with a foreign client.
#
# Why this exists: flare's HTTP/2 server spent several releases unable
# to complete a request from curl, a browser, or h2load, while every
# in-tree h2 test passed. Http2Config.allow_huffman_decode defaulted to
# False, and flare's own client emits HPACK H=0 literals, so nothing in
# the suite ever sent a Huffman-coded header. The bug needed a client
# we did not write, and CI had none.
#
# So this is not a performance check and not a replacement for the unit
# suite. It is the narrow question "can software we did not write talk
# to us", asked on every wire we claim to serve.
#
# Since 0.11 it also asks the mirror question for the streaming client.
# Every in-tree test of `get_streaming` runs against a server in the
# same process; the reader had never pulled a megabyte across a real
# socket from a separately built, multi-worker server, which is where
# framing and flow-control mistakes actually show up.
#
# Uses curl (and h2load when present). No wrk, no benchmark harness,
# a few seconds total, safe to run on a shared box.
#
#   bash tests/tools/interop_smoke.sh
#   pixi run interop-smoke
#
# Exit 0 iff every checked path returns the expected status on the
# expected protocol version.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PORT="${INTEROP_PORT:-18690}"
TLS_PORT="${INTEROP_TLS_PORT:-18691}"
BIN="target/interop/flare_mc"
STREAM_BIN="target/interop/flare_stream_client"
CERT_DIR="build/tls-bench-certs"

PASS=0
FAIL=0

say()  { printf '   %-46s ' "$1"; }
okay() { echo "ok — $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAILED — $1"; FAIL=$((FAIL + 1)); }

if ! command -v curl >/dev/null 2>&1; then
    echo "interop_smoke: curl not on PATH; nothing to check" >&2
    exit 0
fi

echo "── building the interop server and streaming client ────────"
mkdir -p target/interop
if ! pixi run mojo build -I . benchmark/baselines/flare_mc/main.mojo \
     -o "$BIN" > target/interop/build.log 2>&1; then
    echo "BUILD FAILED"; cat target/interop/build.log; exit 1
fi
if ! pixi run mojo build -I . benchmark/baselines/flare_mc/stream_client.mojo \
     -o "$STREAM_BIN" > target/interop/build_client.log 2>&1; then
    echo "CLIENT BUILD FAILED"; cat target/interop/build_client.log; exit 1
fi
echo "   ok"

# One megabyte is deliberate: it is several HTTP/2 connection windows,
# so an h2 reader that forgets to flush its WINDOW_UPDATE stalls here
# and returns fewer bytes rather than passing by accident.
MB=1048576

# Run the streaming client and compare its whole report line. Args:
# label, url, expected wire, then any extra environment assignments.
stream_leg() {
    local label="$1" url="$2" wire="$3"; shift 3
    say "$label"
    local got
    got=$(env FLARE_STREAM_URL="$url" FLARE_STREAM_EXPECT="$MB" \
              FLARE_STREAM_WIRE="$wire" "$@" "$STREAM_BIN" 2>&1 | tail -1)
    # The pull count is not asserted: how a megabyte splits across
    # reads depends on socket buffers and h2 frame sizes, and pinning
    # it would make this fail for reasons that are not bugs.
    local want="wire=$wire bytes=$MB"
    if [[ "$got" == "$want "* ]]; then
        okay "$got"
    else
        bad "expected '$want ...', got '$got'"
    fi
}

if [[ ! -f "$CERT_DIR/server.pem" ]]; then
    bash benchmark/scripts/_make_self_signed.sh "$ROOT/$CERT_DIR" >/dev/null 2>&1
fi

SRV_PID=""
TLS_PID=""
cleanup() {
    [[ -n "$SRV_PID" ]] && kill -9 "$SRV_PID" 2>/dev/null
    [[ -n "$TLS_PID" ]] && kill -9 "$TLS_PID" 2>/dev/null
    return 0
}
trap cleanup EXIT INT TERM

# ── cleartext ───────────────────────────────────────────────────────
FLARE_BENCH_PORT="$PORT" FLARE_BENCH_WORKERS=2 "$BIN" \
    > target/interop/server.log 2>&1 &
SRV_PID=$!
sleep 3

echo "── cleartext (2 workers) ───────────────────────────────────"

say "HTTP/1.1 GET"
out=$(curl -s -o /dev/null -w '%{http_code} %{http_version}' \
      --max-time 5 "http://127.0.0.1:$PORT/plaintext" 2>&1)
[[ "$out" == "200 1.1" ]] && okay "$out" || bad "expected '200 1.1', got '$out'"

# The Huffman regression lived exactly here: curl sends HPACK-Huffman
# headers, flare's own client does not.
say "HTTP/2 prior-knowledge (h2c)"
out=$(curl -s --http2-prior-knowledge -o /dev/null -w '%{http_code} %{http_version}' \
      --max-time 5 "http://127.0.0.1:$PORT/plaintext" 2>&1)
[[ "$out" == "200 2" ]] && okay "$out" || bad "expected '200 2', got '$out'"

say "chunked request body round-trips"
# /upload answers with the byte count it received, so a wrong answer
# localises the bug: 0 means the body never arrived.
out=$(head -c 5000 /dev/zero | curl -s -X POST -H 'Transfer-Encoding: chunked' \
      --data-binary @- --max-time 5 "http://127.0.0.1:$PORT/upload" 2>&1)
[[ "$out" == "5000" ]] && okay "server read 5000 bytes" \
    || bad "expected the server to read 5000 bytes, got '$out'"

say "chunked streaming response"
out=$(curl -s -o /dev/null -w '%{http_code} %{size_download}' \
      --max-time 5 "http://127.0.0.1:$PORT/stream" 2>&1)
[[ "$out" == "200 4096" ]] && okay "$out" || bad "expected '200 4096', got '$out'"

stream_leg "flare get_streaming over HTTP/1.1" \
    "http://127.0.0.1:$PORT/1mb" "http/1.1"

stream_leg "flare get_streaming over h2c" \
    "http://127.0.0.1:$PORT/1mb" "h2" FLARE_STREAM_H2C=1

kill -9 "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
sleep 1

# ── TLS ─────────────────────────────────────────────────────────────
FLARE_BENCH_TLS=1 FLARE_BENCH_PORT="$TLS_PORT" FLARE_BENCH_WORKERS=2 "$BIN" \
    > target/interop/server_tls.log 2>&1 &
TLS_PID=$!
sleep 3

echo "── TLS (2 workers, ALPN h2 + http/1.1) ─────────────────────"

say "HTTPS with ALPN http/1.1"
out=$(curl -sk --http1.1 -o /dev/null -w '%{http_code} %{http_version}' \
      --max-time 5 "https://127.0.0.1:$TLS_PORT/plaintext" 2>&1)
[[ "$out" == "200 1.1" ]] && okay "$out" || bad "expected '200 1.1', got '$out'"

say "HTTPS with ALPN h2"
out=$(curl -sk --http2 -o /dev/null -w '%{http_code} %{http_version}' \
      --max-time 5 "https://127.0.0.1:$TLS_PORT/plaintext" 2>&1)
[[ "$out" == "200 2" ]] && okay "$out" || bad "expected '200 2', got '$out'"

say "HTTPS streaming response over h2"
out=$(curl -sk --http2 -o /dev/null -w '%{http_code} %{size_download}' \
      --max-time 5 "https://127.0.0.1:$TLS_PORT/stream" 2>&1)
[[ "$out" == "200 4096" ]] && okay "$out" || bad "expected '200 4096', got '$out'"

# ALPN picks h2 here, so this is the one leg that proves the client's
# wire selection and its h2 reader agree about what was negotiated.
stream_leg "flare get_streaming over TLS (ALPN h2)" \
    "https://127.0.0.1:$TLS_PORT/1mb" "h2" FLARE_STREAM_TLS=1

if command -v h2load >/dev/null 2>&1; then
    say "h2load over TLS (10 requests)"
    if h2load -n10 -c1 "https://127.0.0.1:$TLS_PORT/plaintext" \
         > target/interop/h2load.log 2>&1 \
       && grep -q ' 10 succeeded' target/interop/h2load.log; then
        okay "10 succeeded"
    else
        bad "see target/interop/h2load.log"
    fi
else
    say "h2load over TLS"
    echo "skipped — h2load not installed"
fi

echo
echo "── interop summary: ${PASS} passed, ${FAIL} failed"
[[ ${FAIL} -gt 0 ]] && exit 1
exit 0
