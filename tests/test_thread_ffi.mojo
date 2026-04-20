"""Tests for ``flare.runtime._thread`` — pthread + CPU pinning FFI.

Covers:

- ``num_cpus`` returns at least 1 on any system.
- ``current_thread_id`` returns a non-zero value on the main thread.
- ``ThreadHandle.spawn`` + ``join`` round-trips.
- Multiple worker threads can each deliver a per-thread result back
  via the argument pointer.
- ``pin_to_cpu`` succeeds on Linux (first CPU) and is a no-op on macOS.

Threads that write into a caller-provided counter prove the thread
actually ran and saw the argument pointer.
"""

from std.testing import assert_true, assert_equal, TestSuite
from std.memory import UnsafePointer
from std.sys.info import CompilationTarget
from std.ffi import c_int

from flare.runtime._thread import (
    ThreadHandle,
    num_cpus,
    current_thread_id,
)


# ── Start routines used by the tests ───────────────────────────────────────


@always_inline
def _null_out() -> UnsafePointer[UInt8, MutExternalOrigin]:
    return UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=0)


def _write_42(
    arg: UnsafePointer[UInt8, MutExternalOrigin],
) -> UnsafePointer[UInt8, MutExternalOrigin]:
    """Treat ``arg`` as a ``UnsafePointer[Int]`` and write 42 to it."""
    var as_int_ptr = arg.bitcast[Int]()
    as_int_ptr[] = 42
    return _null_out()


def _increment_counter(
    arg: UnsafePointer[UInt8, MutExternalOrigin],
) -> UnsafePointer[UInt8, MutExternalOrigin]:
    """Treat ``arg`` as ``UnsafePointer[Int]``; non-atomic increment,
    fine because each test thread has its own counter.
    """
    var p = arg.bitcast[Int]()
    p[] = p[] + 1
    return _null_out()


def _nop(
    arg: UnsafePointer[UInt8, MutExternalOrigin],
) -> UnsafePointer[UInt8, MutExternalOrigin]:
    """Do nothing; used to probe join semantics in isolation."""
    return _null_out()


# ── num_cpus ────────────────────────────────────────────────────────────────


def test_num_cpus_at_least_one() raises:
    """``num_cpus`` never returns zero."""
    var n = num_cpus()
    assert_true(n >= 1)


def test_num_cpus_reasonable() raises:
    """``num_cpus`` returns a reasonable value (< 10000 — just a
    sanity upper bound, not a real system limit)."""
    var n = num_cpus()
    assert_true(n < 10000)


# ── pthread_self ────────────────────────────────────────────────────────────


def test_current_thread_id_nonzero() raises:
    """``current_thread_id`` returns a non-zero identifier on the main thread.
    """
    var tid = current_thread_id()
    assert_true(tid != UInt64(0))


# ── spawn + join round-trip ────────────────────────────────────────────────


def test_spawn_join_noop() raises:
    """A spawned thread that does nothing still joins cleanly."""
    var h = ThreadHandle.spawn[_nop](_null_out())
    h.join()


@always_inline
def _ptr_to_int(
    ref value: Int,
) -> UnsafePointer[UInt8, MutExternalOrigin]:
    """Get a MutExternalOrigin-typed UInt8 pointer to a stack Int.

    Safe here because every test joins the worker before ``value``
    goes out of scope.
    """
    var addr = Int(UnsafePointer[Int, _](to=value))
    return UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=addr)


@always_inline
def _ptr_to_u64(
    ref value: UInt64,
) -> UnsafePointer[UInt8, MutExternalOrigin]:
    var addr = Int(UnsafePointer[UInt64, _](to=value))
    return UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=addr)


def test_spawn_writes_argument() raises:
    """A spawned thread writing into its arg pointer produces the expected value.
    """
    var value = 0
    var h = ThreadHandle.spawn[_write_42](_ptr_to_int(value))
    h.join()
    assert_equal(value, 42)


def test_spawn_multiple_threads() raises:
    """Several worker threads each bump their own counter (3 threads)."""
    var c1 = 10
    var c2 = 20
    var c3 = 30
    var h1 = ThreadHandle.spawn[_increment_counter](_ptr_to_int(c1))
    var h2 = ThreadHandle.spawn[_increment_counter](_ptr_to_int(c2))
    var h3 = ThreadHandle.spawn[_increment_counter](_ptr_to_int(c3))
    h1.join()
    h2.join()
    h3.join()
    assert_equal(c1, 11)
    assert_equal(c2, 21)
    assert_equal(c3, 31)


# ── CPU pinning ────────────────────────────────────────────────────────────


def test_pin_to_cpu0_after_spawn() raises:
    """``pin_to_cpu(0)`` succeeds on Linux, no-op on macOS."""
    var value = 0
    var h = ThreadHandle.spawn[_write_42](_ptr_to_int(value))
    h.pin_to_cpu(0)
    h.join()
    assert_equal(value, 42)


def test_pin_to_cpu_min_of_available() raises:
    """Pin to the minimum of 1 and available CPUs; can't exceed the system."""
    var n = num_cpus()
    var target = 0
    if n > 1:
        target = 1
    var h = ThreadHandle.spawn[_nop](_null_out())
    h.pin_to_cpu(target)
    h.join()


# ── Many spawn / join cycles ───────────────────────────────────────────────


def test_many_spawn_join_cycles() raises:
    """Spawning + joining 8 threads in sequence does not leak resources."""
    for _ in range(8):
        var h = ThreadHandle.spawn[_nop](_null_out())
        h.join()


def _write_tid(
    arg: UnsafePointer[UInt8, MutExternalOrigin],
) -> UnsafePointer[UInt8, MutExternalOrigin]:
    var as_u64_ptr = arg.bitcast[UInt64]()
    as_u64_ptr[] = current_thread_id()
    return _null_out()


def test_thread_id_unique_across_workers() raises:
    """Each spawned thread writes its pthread_self into a slot; the
    two slots differ from each other and from the main thread.
    """
    var t1 = UInt64(0)
    var t2 = UInt64(0)
    var h1 = ThreadHandle.spawn[_write_tid](_ptr_to_u64(t1))
    var h2 = ThreadHandle.spawn[_write_tid](_ptr_to_u64(t2))
    h1.join()
    h2.join()
    assert_true(t1 != UInt64(0))
    assert_true(t2 != UInt64(0))
    assert_true(t1 != t2)
    var main_tid = current_thread_id()
    assert_true(t1 != main_tid)
    assert_true(t2 != main_tid)


# ── Entry point ───────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_thread_ffi.mojo — pthread + CPU pinning")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
