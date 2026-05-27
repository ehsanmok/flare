#!/bin/bash
# Repeatable allocation + CPU profile of the flare bench server.
#
# Used by the v0.8 deep-perf pass that surfaced and fixed the
# ``_is_valid_utf8_runtime`` 5%-of-CPU hot spot on the H1 plaintext
# path (commit 6e44e63). Re-running this against a future flare
# build reproduces the same three measurements so any regression
# on the hot path is visible at a glance:
#
#   1. heaptrack -- LD_PRELOAD-based malloc tracer. Prints "MOST
#      CALLS TO ALLOCATION FUNCTIONS" + per-call-site breakdown.
#      Healthy posture: every top entry is from Mojo runtime
#      startup (M::MLRT::getOrCreateRuntime); the per-request
#      hot path adds zero new alloc sites.
#
#   2. strace -c on brk/mmap/munmap/mremap -- syscall-level
#      allocator counts. Healthy posture: total syscalls / total
#      requests << 1.0 (v0.8 measurement: 171 syscalls / 600K
#      requests = 0.00029 syscalls/req, all during startup).
#
#   3. perf record -F 999 --call-graph dwarf -- sampling CPU
#      profile of the live server. Healthy posture: the top
#      user-space symbol should be the parser body (
#      ``_parse_http_request_bytes``) at ~2-3% of CPU, NOT a Mojo
#      stdlib helper (the original hot spot was
#      ``_is_valid_utf8_runtime`` at ~5%).
#
# Build is done once at the top with ``-D ASSERT=none`` to match
# the same posture Rust baselines use (``cargo build --release``).
# That flag elides every ``debug_assert[assert_mode="safe"]`` so
# the numbers are directly comparable to the cross-framework
# ``bench-vs-baseline`` harness.
#
# Usage:
#   pixi run -e dev perf-server-alloc            # full profile
#   pixi run -e dev perf-server-alloc --quick    # skip perf record
#
# Requires (already in [feature.dev.target.linux-64.dependencies]):
#   - valgrind  >= 3.22 (callgrind / massif / dhat)
#   - heaptrack >= 1.5
#   - gdb      >= 14
# Also requires (system-level, not pixi-managed):
#   - wrk      (sudo apt install wrk)
#   - perf     (linux-tools-$(uname -r))
#   - strace
#
# Tunables (env vars):
#   FLARE_PROFILE_PORT     port the bench server listens on (default 9090)
#   FLARE_PROFILE_DURATION wrk run length in seconds (default 8)
#   FLARE_PROFILE_CONNS    wrk -c value (default 64)
#   FLARE_PROFILE_THREADS  wrk -t value (default 1)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PORT="${FLARE_PROFILE_PORT:-9090}"
DURATION="${FLARE_PROFILE_DURATION:-8}"
CONNS="${FLARE_PROFILE_CONNS:-64}"
THREADS="${FLARE_PROFILE_THREADS:-1}"
QUICK=0
for a in "$@"; do case "$a" in --quick) QUICK=1 ;; esac; done

BIN="$ROOT/build/bench_server_prod"
OUT_DIR="$ROOT/build/perf-profile"
mkdir -p "$OUT_DIR"

# Mojo runtime libs live under the active env's lib/ — the AOT binary
# rpath's them but we set LD_LIBRARY_PATH anyway so a bare ./bench_server
# invocation works even without ``pixi shell``.
ENV_LIB="$ROOT/.pixi/envs/dev/lib"
if [ ! -d "$ENV_LIB" ]; then
    ENV_LIB="$ROOT/.pixi/envs/default/lib"
fi
export LD_LIBRARY_PATH="$ENV_LIB:${LD_LIBRARY_PATH:-}"

# ─── 0. Build (idempotent if up to date) ──────────────────────────────────
if [ ! -x "$BIN" ] || [ "$BIN" -ot "$ROOT/flare/http/server.mojo" ] \
                  || [ "$BIN" -ot "$ROOT/benchmark/bench_server.mojo" ]; then
    echo "→ Building $BIN with -D ASSERT=none ..."
    mojo build -D ASSERT=none -I . benchmark/bench_server.mojo -o "$BIN"
fi
ls -l "$BIN"

start_server() {
    "$BIN" > "$OUT_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1
}
start_under() {
    # $@ wraps the binary in a profiler-launcher.
    "$@" "$BIN" > "$OUT_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
}
stop_server() {
    # SIGINT first so heaptrack + strace flush their trailer.
    kill -INT "$SERVER_PID" 2>/dev/null || true
    sleep 1
    kill -KILL "$SERVER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    pkill -9 -f bench_server_prod 2>/dev/null || true
    sleep 0.5
}
hammer() {
    wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" \
        "http://localhost:$PORT/plaintext" 2>&1 | tail -3
}

# ─── 1. heaptrack ─────────────────────────────────────────────────────────
echo
echo "═══ heaptrack ═══"
rm -f "$OUT_DIR/heaptrack.zst"
start_under heaptrack -o "$OUT_DIR/heaptrack"
hammer
stop_server
if [ -f "$OUT_DIR/heaptrack.zst" ]; then
    echo "─── summary ───"
    heaptrack_print "$OUT_DIR/heaptrack.zst" 2>&1 \
        | awk '/^PEAK MEMORY CONSUMERS/{exit} /^MOST/{p=1} p' \
        | head -30 || true
    echo "─── totals ───"
    heaptrack_print "$OUT_DIR/heaptrack.zst" 2>&1 \
        | grep -iE "^(total|temporary|peak|leaked)" \
        | head -10
fi

# ─── 2. strace -c (alloc syscalls only) ───────────────────────────────────
echo
echo "═══ strace -c (brk/mmap/munmap/mremap) ═══"
start_under strace -f -c -e trace=brk,mmap,munmap,mremap \
                   -o "$OUT_DIR/strace_alloc.log"
hammer
stop_server
echo "─── totals ───"
cat "$OUT_DIR/strace_alloc.log"

# ─── 3. perf record ──────────────────────────────────────────────────────
if [ "$QUICK" -eq 1 ]; then
    echo
    echo "─── skipping perf record (--quick) ───"
    exit 0
fi
echo
echo "═══ perf record ═══"
if [ ! -x "$(command -v perf)" ]; then
    echo "perf not installed; skipping. (install: linux-tools-\$(uname -r))"
    exit 0
fi
# perf record needs to attach to an already-running process so we can
# profile worker threads (the parent ./bench_server thread does almost
# nothing once the workers are up).
start_server
echo "server pid: $SERVER_PID (threads: $(ls /proc/$SERVER_PID/task | wc -l))"
hammer &
WRK_PID=$!
sleep 1
perf record -F 999 --call-graph dwarf,16384 -p "$SERVER_PID" \
            -o "$OUT_DIR/perf.data" -- sleep $((DURATION - 2)) 2>&1 | tail -3
wait "$WRK_PID" 2>/dev/null || true
stop_server

echo "─── top 20 symbols ───"
perf report -i "$OUT_DIR/perf.data" --stdio --no-children -g none 2>/dev/null \
    | awk '/^# Samples:/{print; samples=1} samples && /^ *[0-9]+\./{print; n++} n>=20{exit}' \
    | head -25

echo
echo "═══ done ═══"
echo "Outputs in: $OUT_DIR"
echo "  heaptrack.zst    -- open with: heaptrack_gui  (or: heaptrack_print)"
echo "  strace_alloc.log -- text"
echo "  perf.data        -- open with: perf report -i ... (or: perf annotate)"
