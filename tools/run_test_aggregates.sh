#!/usr/bin/env bash
# Build and run the per-area aggregate test binaries, then the handful of
# tests that must stay in their own process.
#
# The `tests` task runs one `mojo -I .` per test file. Measured on CI that
# is ~9s per invocation across 274 of them, and the cost is dominated by
# re-elaborating an ~90k-line source graph rather than by the test bodies:
# one file measured 1.70s to compile and 0.31s to run. Aggregating an
# area into a single binary pays the elaboration once per area.
#
# Locally, `tests/http` (110 files, 1229 tests) builds in ~72s and runs in
# ~15s as one binary.
#
# Aggregates are generated -- see tools/gen_test_aggregates.py. `--check`
# below is the drift gate: an aggregate that is out of date with the tree
# silently stops running whatever was added, and because an aggregate with
# no registered tests still exits 0, nothing downstream would notice.

set -uo pipefail

AGG_DIR="tests/_agg"
# Default to the machine's core count: the build phase is ~55% of the run
# serially, and the aggregates are independent compiler invocations. Measured
# locally, the whole job went 550s -> 191s at 4 jobs. Override with AGG_JOBS.
_ncpu="$( (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null) || echo 2 )"
# Capped at 4: each job is a full mojo elaboration of the source graph, and
# the macOS runner has 7GB for 3 cores. The cap is what keeps a parallel
# build from turning into an OOM.
[ "$_ncpu" -gt 4 ] 2>/dev/null && _ncpu=4
JOBS="${AGG_JOBS:-$_ncpu}"
BUILD_DIR="${BUILD_DIR:-build/agg}"

# Tests that mutate process-global state (env vars, named semaphores,
# io_uring registrations) or are runtime-bound rather than compile-bound.
# Kept as their own processes; must match EXCLUDE in the generator.
STANDALONE=(
  tests/runtime/test_block_in_pool.mojo
  tests/runtime/test_closure_send_contract.mojo
  tests/runtime/test_handoff.mojo
  tests/runtime/test_uring_bufring_dispatch.mojo
  tests/runtime/test_reuseport.mojo
  tests/http/test_uring_serve_handler.mojo
  tests/http/test_uring_serve_handler_load.mojo
  tests/runtime/stress_scheduler.mojo
)

# Excluded from the aggregates *and* not run here: flaky, and not in the
# `tests` chain today either. See EXCLUDE in tools/gen_test_aggregates.py.

# Prerequisites the per-file chain interleaved into its `&&` sequence.
# Hoisted here so they run once rather than being rediscovered mid-run.
echo "── prerequisites ──"
mkdir -p build/gen
python tools/proto_gen.py tests/grpc/proto/sample.proto \
  -o build/gen/sample_pb.mojo \
  --doc 'Sample proto3 messages for the codegen round-trip test.' \
  || { echo "ERROR: proto_gen failed" >&2; exit 1; }
# tests/tls/test_rustls_quic*.mojo dlopen this wrapper at runtime.
cargo build --release --locked \
  --manifest-path flare/tls/ffi/rustls_wrapper/Cargo.toml \
  || { echo "ERROR: rustls wrapper build failed" >&2; exit 1; }

echo "── checking aggregates are up to date ──"
python3 tools/gen_test_aggregates.py --check || {
  echo "ERROR: aggregates are stale; run python3 tools/gen_test_aggregates.py" >&2
  exit 1
}

mkdir -p "$BUILD_DIR"
# Portable glob collection: macOS ships bash 3.2, which has no `mapfile`.
AGGS=()
for a in "$AGG_DIR"/agg_*.mojo; do [ -f "$a" ] && AGGS+=("$a"); done
if [ "${#AGGS[@]}" -eq 0 ]; then
  echo "ERROR: no aggregates found in $AGG_DIR" >&2
  exit 1
fi

echo "── building ${#AGGS[@]} aggregates (jobs=$JOBS) ──"
build_one() {
  local src="$1" out="$BUILD_DIR/$(basename "${1%.mojo}")"
  # Each aggregate imports bare module names, resolved against its own
  # area directory -- `-I tests` would let the repo's top-level
  # `conformance/` shadow `tests/conformance/`.
  local area="${src##*/agg_}"; area="${area%.mojo}"
  local inc="tests/$area"
  [ "$area" = "_root" ] && inc="tests"
  # build/gen holds the generated sample_pb that
  # tests/grpc/proto/test_codegen.mojo imports.
  if ! mojo build -I . -I "$inc" -I build/gen "$src" -o "$out" 2>"$out.log"; then
    echo "BUILD FAILED: $src"; sed -n '1,20p' "$out.log"; return 1
  fi
}
export -f build_one; export BUILD_DIR
build_failed=()
if [ "$JOBS" -gt 1 ]; then
  printf '%s\n' "${AGGS[@]}" | xargs -P "$JOBS" -n1 -I FF bash -c 'build_one FF'
  # xargs hides which item failed, so re-check the artifacts.
  for a in "${AGGS[@]}"; do
    [ -x "$BUILD_DIR/$(basename "${a%.mojo}")" ] || build_failed+=("$a")
  done
else
  # Keep going after a failure: stopping at the first one turns a run into
  # a one-bug-per-iteration loop.
  for a in "${AGGS[@]}"; do build_one "$a" || build_failed+=("$a"); done
fi
if [ "${#build_failed[@]}" -ne 0 ]; then
  echo "── ${#build_failed[@]} aggregate(s) failed to build ──"
  printf '  %s\n' "${build_failed[@]}"
  exit 1
fi

# Run everything and collect failures rather than stopping at the first.
# `&&`-chaining hid how many suites were broken behind whichever failed
# first; with one binary per area the remaining areas still carry signal.
failed=()
echo "── running aggregates ──"
for a in "${AGGS[@]}"; do
  bin="$BUILD_DIR/$(basename "${a%.mojo}")"
  if ! "$bin"; then failed+=("$a"); fi
done

echo "── running ${#STANDALONE[@]} standalone tests ──"
for t in "${STANDALONE[@]}"; do
  [ -f "$t" ] || { echo "MISSING: $t"; failed+=("$t"); continue; }
  if ! mojo -I . "$t"; then failed+=("$t"); fi
done

# Examples are programs, not test functions, so they cannot be aggregated
# the same way -- they stay one invocation each, as today. They are 59 of
# the chain's invocations and are part of what `tests` covers, so leaving
# them out would quietly drop that coverage.
echo "── running examples ──"
for e in $(git ls-files 'examples/**/*.mojo' | sort); do
  if ! mojo -I . "$e" >/dev/null; then failed+=("$e"); fi
done

if [ "${#failed[@]}" -ne 0 ]; then
  echo
  echo "── ${#failed[@]} suite(s) failed ──"
  printf '  %s\n' "${failed[@]}"
  exit 1
fi
echo "── all suites passed ──"
