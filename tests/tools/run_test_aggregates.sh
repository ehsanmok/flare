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
# Aggregates are generated -- see tests/tools/gen_test_aggregates.py. `--check`
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
# Kept as their own processes; must match EXCLUDE in the generator, which
# documents why each one is here.
STANDALONE=(
  tests/runtime/test_block_in_pool.mojo
  tests/runtime/test_closure_send_contract.mojo
  tests/runtime/test_handoff.mojo
  tests/runtime/test_uring_bufring_dispatch.mojo
  tests/runtime/test_io_uring_sqe.mojo
  tests/runtime/test_reuseport.mojo
  tests/http/test_uring_serve_handler.mojo
  tests/http/test_uring_serve_handler_load.mojo
  tests/runtime/stress_scheduler.mojo
)

# Excluded from the aggregates *and* not run here: flaky, and not in the
# `tests` chain today either. See EXCLUDE in tests/tools/gen_test_aggregates.py.

# Prerequisites the per-file chain interleaved into its `&&` sequence.
# Hoisted here so they run once rather than being rediscovered mid-run.
echo "── prerequisites ──"
mkdir -p build/gen
python tests/tools/proto_gen.py tests/grpc/proto/sample.proto \
  -o build/gen/sample_pb.mojo \
  --doc 'Sample proto3 messages for the codegen round-trip test.' \
  || { echo "ERROR: proto_gen failed" >&2; exit 1; }
# tests/tls/test_rustls_quic*.mojo dlopen this wrapper at runtime.
cargo build --release --locked \
  --manifest-path flare/tls/ffi/rustls_wrapper/Cargo.toml \
  || { echo "ERROR: rustls wrapper build failed" >&2; exit 1; }

echo "── checking aggregates are up to date ──"
python3 tests/tools/gen_test_aggregates.py --check || {
  echo "ERROR: aggregates are stale; run python3 tests/tools/gen_test_aggregates.py" >&2
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
  # area directory. Before the conformance fixtures moved under
  # `tests/conformance/`, `-I tests` would have let the repo's
  # then-existing top-level `conformance/` shadow `tests/conformance/`;
  # per-area scoping stays the default to sidestep that class of
  # collision uniformly.
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
# the same way -- they stay one invocation each, as today. They are 68 of
# the chain's invocations and are part of what `tests` covers, so leaving
# them out would quietly drop that coverage.
#
# `git ls-files` already emits sorted paths, so do NOT pipe through `sort`:
# under `pixi run`, LD_LIBRARY_PATH points at the env's newer libssl and the
# system `/usr/bin/sort` fails to load on ubuntu-latest ("version
# `OPENSSL_3.3.0' not found"). Inside `$(...)` that failure is silent -- the
# list comes back empty and all 68 examples are skipped with a green run.
# The count check below is the backstop for that class of bug.
echo "── running examples ──"
EXAMPLES=()
while IFS= read -r e; do [ -n "$e" ] && EXAMPLES+=("$e"); done < <(git ls-files 'examples/**/*.mojo')
if [ "${#EXAMPLES[@]}" -lt 50 ]; then
  echo "ERROR: found only ${#EXAMPLES[@]} examples; expected 68." >&2
  echo "       Refusing to report a pass over a truncated list." >&2
  exit 1
fi
echo "   ${#EXAMPLES[@]} examples"
# Examples cannot share a process -- each is its own `main` -- but they can
# share the *build* phase. Measured on ubuntu-latest, 68 `mojo -I .`
# invocations cost 12.5min of a 20.5min job, and that is compilation, not
# run time. Building them concurrently and then running the binaries keeps
# one process per example while cutting the wall clock by ~$JOBS.
build_example() {
  local src="$1" out="$BUILD_DIR/ex_${1//\//_}"
  out="${out%.mojo}"
  if ! mojo build -I . "$src" -o "$out" 2>"$out.log"; then
    echo "BUILD FAILED: $src"; sed -n '1,20p' "$out.log"; return 1
  fi
}
export -f build_example
printf '%s\n' "${EXAMPLES[@]}" | xargs -P "$JOBS" -n1 -I FF bash -c 'build_example FF'
for e in "${EXAMPLES[@]}"; do
  bin="$BUILD_DIR/ex_${e//\//_}"; bin="${bin%.mojo}"
  if [ ! -x "$bin" ]; then failed+=("$e (build)"); continue; fi
  if ! "$bin" >/dev/null; then failed+=("$e"); fi
done

if [ "${#failed[@]}" -ne 0 ]; then
  echo
  echo "── ${#failed[@]} suite(s) failed ──"
  printf '  %s\n' "${failed[@]}"
  exit 1
fi
echo "── all suites passed ──"
