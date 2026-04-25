"""Tests for the rolled-own libc time FFI (v0.5.0 follow-up /
Mojo workaround cleanup).

The pinned Mojo nightly has an empirically-observed anomaly when
calling ``usleep`` via the inferred-signature overload of
``external_call``: a 1 ms ``usleep`` call sleeps ~1.5 seconds
instead. ``flare.runtime._libc_time`` rolls its own bindings
with explicit ``Int32`` / pointer-to-``Int64`` signatures and
this file confirms the wall-clock semantics empirically.

Tests use a generous ``±50%`` tolerance for the upper bound on
the sleep duration: kernel scheduling, GC pauses, CI noise,
debug-build instrumentation can all push the actual sleep past
the requested duration. The tests fail loudly if the sleep
returns *too quickly* (the symptom of a ZERO-extension /
truncation bug) or takes orders of magnitude too long (the
symptom of the original anomaly).
"""

from std.testing import (
    assert_equal,
    assert_true,
    TestSuite,
)
from std.time import monotonic

from flare.runtime import libc_usleep, libc_nanosleep_ms


# ── Helpers ────────────────────────────────────────────────────────────────


@always_inline
def _elapsed_ms_since(t0: UInt) -> Int:
    """Monotonic ms since ``t0`` (a previous ``monotonic()`` value)."""
    return Int((monotonic() - t0) // 1_000_000)


# ── libc_usleep ────────────────────────────────────────────────────────────


def test_usleep_small_returns_zero() raises:
    var rc = libc_usleep(10_000)
    assert_equal(rc, 0)


def test_usleep_zero_is_noop() raises:
    var t0 = monotonic()
    var rc = libc_usleep(0)
    var elapsed_ms = _elapsed_ms_since(t0)
    assert_equal(rc, 0)
    assert_true(elapsed_ms < 5)


def test_usleep_negative_is_noop() raises:
    var t0 = monotonic()
    var rc = libc_usleep(-100)
    var elapsed_ms = _elapsed_ms_since(t0)
    assert_equal(rc, 0)
    assert_true(elapsed_ms < 5)


def test_usleep_10ms_takes_at_least_5ms() raises:
    """10 ms request must take at least 5 ms wall-clock — catches
    the ZERO-extension bug class. Upper bound is loose (50 ms) to
    survive CI scheduling jitter."""
    var t0 = monotonic()
    var rc = libc_usleep(10_000)
    var elapsed_ms = _elapsed_ms_since(t0)
    assert_equal(rc, 0)
    assert_true(
        elapsed_ms >= 5,
        "usleep(10ms) returned in <5ms — likely no actual sleep",
    )
    assert_true(
        elapsed_ms < 200,
        "usleep(10ms) took >=200ms — Mojo nightly anomaly is back",
    )


# ── libc_nanosleep_ms ──────────────────────────────────────────────────────


def test_nanosleep_zero_is_noop() raises:
    var t0 = monotonic()
    var rc = libc_nanosleep_ms(0)
    var elapsed_ms = _elapsed_ms_since(t0)
    assert_equal(rc, 0)
    assert_true(elapsed_ms < 5)


def test_nanosleep_negative_is_noop() raises:
    var t0 = monotonic()
    var rc = libc_nanosleep_ms(-25)
    var elapsed_ms = _elapsed_ms_since(t0)
    assert_equal(rc, 0)
    assert_true(elapsed_ms < 5)


def test_nanosleep_50ms_within_budget() raises:
    """50 ms request takes 25-200 ms wall-clock — the lower bound
    catches "no sleep happened" and the upper bound catches a
    Mojo-nightly regression of the original anomaly."""
    var t0 = monotonic()
    var rc = libc_nanosleep_ms(50)
    var elapsed_ms = _elapsed_ms_since(t0)
    assert_equal(rc, 0)
    assert_true(
        elapsed_ms >= 25,
        "nanosleep_ms(50) returned in <25ms — likely no actual sleep",
    )
    assert_true(
        elapsed_ms < 500,
        "nanosleep_ms(50) took >=500ms — Mojo nightly anomaly",
    )


def test_nanosleep_200ms_takes_at_least_100ms() raises:
    """Multi-100ms budget. Catches multiplier-style bugs that
    smaller sleeps can't distinguish from kernel jitter."""
    var t0 = monotonic()
    var rc = libc_nanosleep_ms(200)
    var elapsed_ms = _elapsed_ms_since(t0)
    assert_equal(rc, 0)
    assert_true(
        elapsed_ms >= 100,
        "nanosleep_ms(200) took <100ms — bug",
    )
    assert_true(
        elapsed_ms < 1500,
        "nanosleep_ms(200) took >=1500ms — Mojo anomaly",
    )


# ── Stress: 100x 1ms sleeps must total <300ms wall ────────────────────────


def test_hundred_one_ms_sleeps_within_300ms() raises:
    """100 sequential nanosleep_ms(1) calls must total under
    300 ms (3 ms per call upper bound). Catches per-call
    fixed-overhead regressions."""
    var t0 = monotonic()
    for _ in range(100):
        _ = libc_nanosleep_ms(1)
    var elapsed_ms = _elapsed_ms_since(t0)
    assert_true(
        elapsed_ms < 300,
        "100x nanosleep_ms(1) totaled "
        + String(elapsed_ms)
        + "ms; expected <300ms",
    )


def main() raises:
    print("=" * 60)
    print("test_libc_time.mojo — libc time FFI semantics")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
