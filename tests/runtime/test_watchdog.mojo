"""Tests for the DeadlineWatchdog (K2 preemptive-deadline mechanism)."""

from std.atomic import Atomic, Ordering
from std.memory import Layout, Pointer, alloc
from std.testing import assert_equal

from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime.watchdog import DeadlineWatchdog


def _new_cell() -> Int:
    var p = alloc(Layout[Int64](count=1)).unsafe_leak()
    p.unsafe_write(Int64(0))
    return Int(p)


def _read_cell(addr: Int) -> Int:
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    return Int(
        Atomic[Int64].load[ordering=Ordering.ACQUIRE](
            p.unsafe_bitcast[Scalar[DType.int64]]()
        )
    )


def _free_cell(addr: Int):
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    p.unsafe_free()


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
