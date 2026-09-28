#!/bin/bash
# Run a test command, retrying only the Mojo runtime's transient crash.
#
# usage: bash tests/tools/retry_on_runtime_crash.sh <command...>
#
# The Mojo runtime (libKGENCompilerRTShared) sometimes segfaults on a
# fresh process before any user code runs; see the header of
# .github/workflows/ci.yml. CI used to rerun the whole suite up to three
# times on *any* failure, which hid real flakes: a test that failed one
# run in three went green. This retries only when the log carries the
# runtime-crash signature and no test reported a failure. Anything else
# fails on the first attempt.
set +e
log=$(mktemp)
rc=1
for attempt in 1 2 3; do
  echo "── attempt $attempt/3: $* ──"
  "$@" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 0 ]; then
    rm -f "$log"
    exit 0
  fi
  if grep -qE 'FAIL \[|AssertionError|BUILD FAILED|ERROR: AddressSanitizer' "$log"; then
    echo "── attempt $attempt: test failures (rc=$rc); not retrying ──"
    break
  fi
  if ! grep -q 'libKGENCompilerRTShared' "$log"; then
    echo "── attempt $attempt failed (rc=$rc) without the runtime-crash signature; not retrying ──"
    break
  fi
  echo "── attempt $attempt hit the Mojo runtime crash; retrying ──"
  sleep ${RETRY_SLEEP_S:-5}
done
rm -f "$log"
exit "$rc"
