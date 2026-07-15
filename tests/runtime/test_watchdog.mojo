"""Tests for the DeadlineWatchdog (K2 preemptive-deadline mechanism)."""

from std.atomic import Atomic, Ordering
from std.memory import UnsafePointer, alloc
from std.testing import assert_equal

from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime.watchdog import DeadlineWatchdog


def _new_cell() -> Int:
    var p = alloc[Int64](1)
    p.init_pointee_copy(Int64(0))
    return Int(p)


def _read_cell(addr: Int) -> Int:
    var p = UnsafePointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    return Int(
        Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](
            p.bitcast[Scalar[DType.int64]]()
        )
    )


def _free_cell(addr: Int):
    var p = UnsafePointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    p.free()


def test_watchdog_flips_cell_on_deadline() raises:
    """An armed slot whose deadline passes gets its cancel cell flipped
    to CancelReason.TIMEOUT (2)."""
    var cell = _new_cell()
    var wd = DeadlineWatchdog(poll_ms=1)
    wd.arm(0, 10, cell)
    _ = libc_nanosleep_ms(80)
    assert_equal(_read_cell(cell), 2)  # TIMEOUT
    wd.stop()
    _free_cell(cell)


def test_watchdog_disarm_prevents_flip() raises:
    """A slot disarmed before its deadline is never flipped."""
    var cell = _new_cell()
    var wd = DeadlineWatchdog(poll_ms=1)
    wd.arm(0, 1_000, cell)  # far-future deadline
    wd.disarm(0)
    _ = libc_nanosleep_ms(40)
    assert_equal(_read_cell(cell), 0)  # still live
    wd.stop()
    _free_cell(cell)


def main() raises:
    test_watchdog_flips_cell_on_deadline()
    print("OK test_watchdog_flips_cell_on_deadline")
    test_watchdog_disarm_prevents_flip()
    print("OK test_watchdog_disarm_prevents_flip")
    print("test_watchdog: 2 passed")
