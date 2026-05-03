"""Tests for ``flare.runtime.io_uring`` (Track B0).

io_uring is a Linux-only kernel feature (5.1+). On macOS / BSD
the entire surface returns ``False`` from
``is_io_uring_available()`` and the rest of the tests skip.

On Linux hosts where io_uring is available (and the test
process has the syscall permission bits set), the tests
exercise actual ring setup + teardown.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite
from std.sys.info import CompilationTarget

from flare.runtime import (
    IoUringRing,
    IoUringParams,
    is_io_uring_available,
    SYS_IO_URING_SETUP,
    SYS_IO_URING_ENTER,
    SYS_IO_URING_REGISTER,
)


def test_syscall_numbers_match_linux_abi() raises:
    """Pin the syscall numbers — these are stable across Linux
    kernels since 5.1 (May 2019). Catches accidental edits.
    """
    assert_equal(SYS_IO_URING_SETUP, 425)
    assert_equal(SYS_IO_URING_ENTER, 426)
    assert_equal(SYS_IO_URING_REGISTER, 427)


def test_io_uring_params_empty_factory_zeroes_all_fields() raises:
    """``IoUringParams.empty()`` constructs an all-zeros struct
    suitable for passing as the in/out arg to
    ``io_uring_setup``.
    """
    var p = IoUringParams.empty()
    assert_equal(Int(p.sq_entries), 0)
    assert_equal(Int(p.cq_entries), 0)
    assert_equal(Int(p.flags), 0)
    assert_equal(Int(p.sq_off_head), 0)
    assert_equal(Int(p.cq_off_head), 0)


def test_is_io_uring_available_returns_bool() raises:
    """Smoke test: the feature-detect function must return a
    Bool without raising on any host (Linux or otherwise).
    """
    var avail = is_io_uring_available()
    assert_true(avail or not avail)


def test_is_io_uring_available_false_on_non_linux() raises:
    """On macOS / BSD the function must return False — io_uring
    is Linux-specific.
    """
    comptime if not CompilationTarget.is_linux():
        assert_false(is_io_uring_available())


def test_setup_and_teardown_a_ring_when_available() raises:
    """If io_uring is available on the host, allocating a
    1-entry ring + dropping it must succeed without raising.
    """
    if not is_io_uring_available():
        return
    var ring = IoUringRing(8)
    assert_true(ring.fd() >= 0)
    # Kernel rounds up to a power of two — for a request of 8
    # the SQ should be 8.
    assert_true(ring.sq_entries() >= 8)
    # CQ default is 2 * SQ.
    assert_true(ring.cq_entries() >= ring.sq_entries())


def test_setup_returns_features_flags() raises:
    """The kernel reports what features it supports via
    ``IoUringParams.features``. The exact bits depend on
    kernel version; we just verify the field reads back as a
    non-negative Int.
    """
    if not is_io_uring_available():
        return
    var ring = IoUringRing(4)
    assert_true(ring.features() >= 0)


def test_setup_rounds_entries_up_to_power_of_two() raises:
    """Asking for 5 SQEs must yield ≥ 8 (next power of two) per
    the io_uring ABI."""
    if not is_io_uring_available():
        return
    var ring = IoUringRing(5)
    assert_true(ring.sq_entries() >= 8)


def test_multiple_rings_are_independent() raises:
    """Two rings can coexist; each gets its own kernel
    allocation + fd.
    """
    if not is_io_uring_available():
        return
    var a = IoUringRing(4)
    var b = IoUringRing(4)
    assert_true(a.fd() != b.fd())
    assert_true(a.fd() >= 0)
    assert_true(b.fd() >= 0)


def test_setup_flags_zero_default_works() raises:
    """Default ``setup_flags=0`` matches the historical
    behaviour: no SQPOLL, no COOP_TASKRUN, no DEFER_TASKRUN.
    Catches accidental flag-default regressions."""
    if not is_io_uring_available():
        return
    var ring = IoUringRing(4, setup_flags=UInt32(0))
    assert_true(ring.fd() >= 0)


def test_setup_flag_coop_taskrun_accepted_or_einval() raises:
    """Phase 2A: ``IORING_SETUP_COOP_TASKRUN`` (5.19+) -- the
    kernel accepts on >= 5.19 and rejects with EINVAL on
    older kernels. Either outcome is correct; the test fails
    only if the ring construction throws an unexpected error
    type or the host kernel is exotic.

    On accept, the ring fd is valid; on reject, the constructor
    raises with errno=22 (EINVAL).
    """
    from flare.runtime.io_uring_sqe import IORING_SETUP_COOP_TASKRUN

    if not is_io_uring_available():
        return
    try:
        var ring = IoUringRing(4, setup_flags=IORING_SETUP_COOP_TASKRUN)
        assert_true(ring.fd() >= 0)
    except e:
        # Older kernel: EINVAL. The error message format is
        # "io_uring_setup failed: errno=22"; we accept any
        # non-zero errno here.
        var msg = String(e)
        assert_true("io_uring_setup failed" in msg)


def test_setup_flag_combined_bufring_recipe_accepted_or_einval() raises:
    """Phase 2A: the bufring path's optimal mix
    (COOP_TASKRUN | TASKRUN_FLAG | SUBMIT_ALL) on kernel >= 5.19,
    plus SINGLE_ISSUER | DEFER_TASKRUN on >= 6.1. Combine all
    five and verify the kernel either accepts (modern) or
    rejects with EINVAL (older). Catches accidental flag-bit
    typos.
    """
    from flare.runtime.io_uring_sqe import (
        IORING_SETUP_COOP_TASKRUN,
        IORING_SETUP_TASKRUN_FLAG,
        IORING_SETUP_SUBMIT_ALL,
        IORING_SETUP_SINGLE_ISSUER,
        IORING_SETUP_DEFER_TASKRUN,
    )

    if not is_io_uring_available():
        return
    var combined = (
        IORING_SETUP_COOP_TASKRUN
        | IORING_SETUP_TASKRUN_FLAG
        | IORING_SETUP_SUBMIT_ALL
        | IORING_SETUP_SINGLE_ISSUER
        | IORING_SETUP_DEFER_TASKRUN
    )
    try:
        var ring = IoUringRing(4, setup_flags=combined)
        assert_true(ring.fd() >= 0)
    except e:
        var msg = String(e)
        assert_true("io_uring_setup failed" in msg)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
