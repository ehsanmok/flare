"""libc time FFI.

Mojo has an empirically-observed anomaly when calling ``usleep``
via the inferred-signature overload of ``external_call``:
``usleep(c_uint(1000))`` (1 ms
expected) sleeps for ~1.5 seconds, and ``usleep(c_uint(50_000))``
(50 ms expected) sleeps for ~56 seconds. The exact root cause
hasn't been pinned down but the symptoms are consistent with a
register-width / type-coercion mismatch somewhere in the
``external_call`` path.

The fix is to bind libc time primitives ourselves with explicit
``Int32`` / pointer-to-``Int64`` signatures and stop relying on
``std.ffi.c_uint``. Both functions in this module are tested
empirically against monotonic-clock differences in
``tests/test_libc_time.mojo`` so any future regression is caught
in-tree rather than slowly through drain-test wall-time growth.

POSIX semantics:

- ``usleep(useconds_t usec)`` — suspends the calling thread for
  at least ``usec`` microseconds. ``useconds_t`` is uint32 on
  Linux + macOS. Values >= 1_000_000 are explicitly undefined;
  callers wanting >= 1 second should use ``nanosleep`` instead.
  Returns 0 on success, -1 on signal interruption.

- ``nanosleep(const struct timespec *req, struct timespec *rem)``
  — suspends for ``req->tv_sec`` seconds + ``req->tv_nsec``
  nanoseconds. No upper limit. Returns 0 on success, -1 on
  signal interruption (with ``rem`` populated with the remaining
  time).
"""

from std.ffi import external_call
from std.time import sleep
from std.memory import Pointer, stack_allocation
from std.sys.info import CompilationTarget

# ``CLOCK_MONOTONIC`` clock id is NOT portable: it is ``1`` on Linux but
# ``6`` on Darwin/macOS (where ``1`` is undefined, so ``clock_gettime``
# returns -1 and leaves the timespec at 0 -- the clock would read a
# constant 0 and elapsed math would silently collapse). Pick at compile
# time so each platform gets its real steady clock.
comptime _CLOCK_MONOTONIC: Int32 = Int32(
    6
) if CompilationTarget.is_macos() else Int32(1)


@always_inline
def monotonic_now_ms() -> Int:
    """Return the monotonic clock in milliseconds.

    Canonical ``flare.runtime`` wrapper over
    ``clock_gettime(CLOCK_MONOTONIC, ...)`` for deadline math in the
    streaming reactor and elsewhere. The clock is steady (never jumps
    backwards), so ``monotonic_now_ms() - start`` is a sound elapsed
    measure. ``CLOCK_MONOTONIC`` is id ``1`` on Linux and ``6`` on
    macOS (see ``_CLOCK_MONOTONIC``).

    Returns:
        Milliseconds since an unspecified but fixed epoch.
    """
    var ts = stack_allocation[2, Int64]()
    ts[unsafe_offset=0] = Int64(0)
    ts[unsafe_offset=1] = Int64(0)
    var ts_ext = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=Int(ts))
    _ = external_call[
        "clock_gettime",
        Int32,
        Int32,
        Pointer[Int64, MutUntrackedOrigin],
    ](_CLOCK_MONOTONIC, ts_ext)
    return (
        Int(ts[unsafe_offset=0]) * 1000 + Int(ts[unsafe_offset=1]) // 1_000_000
    )


@always_inline
def libc_usleep(microseconds: Int) -> Int:
    """Sleep for at least ``microseconds`` microseconds.

    Args:
        microseconds: Number of microseconds to sleep. Negative
            values are treated as 0. Values >= 1_000_000 are
            allowed but POSIX-undefined; for sleeps that long
            prefer ``libc_nanosleep_ms``.

    Returns:
        0 on success; -1 on signal interruption (the actual
        wall-clock sleep may be shorter than requested).
    """
    if microseconds <= 0:
        return 0
    var rc = external_call["usleep", Int32, Int32](Int32(microseconds))
    return Int(rc)


@always_inline
def libc_nanosleep_ms(ms: Int) -> Int:
    """Sleep for at least ``ms`` milliseconds.

    More flexible than ``usleep``: no 1-second ceiling and
    nanosecond-resolution semantics. Interrupt remainders are
    discarded; callers needing interrupt-aware sleeps go through
    ``nanosleep`` directly.

    Args:
        ms: Number of milliseconds to sleep. Negative values are
            treated as 0.

    Returns:
        Always 0. Kept as ``Int`` so the signature matches
        :func:`libc_usleep` and existing ``_ =`` call sites.
    """
    if ms <= 0:
        return 0
    # ``std.time.sleep``, not our own ``nanosleep`` extern. The stdlib
    # already declares ``nanosleep`` with a different signature, and Mojo
    # declares one extern per signature, so any binary that reaches both
    # refuses to lower with "existing function with conflicting
    # signature". Nothing in flare imports ``std.time.sleep`` today, so
    # flare alone never hit it -- but anything linked alongside flare that
    # does, directly or through a dependency, could not build at all.
    #
    # The remainder was already being discarded here and the stdlib's
    # sleep is the same ``nanosleep`` underneath, so only the linkage
    # changes.
    sleep(Float64(ms) / 1000.0)
    return 0
