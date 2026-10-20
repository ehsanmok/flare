"""Tests for flare's thread engine in ``flare.runtime._thread``.

``spawn`` enqueues AsyncRT tasks (``flare.runtime._asyncrt``);
``spawn_os`` makes a dedicated OS thread.

Covers:

- ``spawn`` makes an AsyncRT task; ``spawn_os`` is always an OS thread.
- spawn + join round-trips.
- 1000 short tasks all run and all join.
- ``detach`` both before and after the task finishes (the cell must be
  freed exactly once either way).
- join from inside a spawned task, including one that spawns its own
  child (the path where an AsyncRT chain wait would donate).
- Serving leases: capped at the pool capacity process-wide, returned
  when the loop exits, and ``spawn_serving`` falling back to an OS
  thread when none is free.
- Pinning a worker the way a serving loop does, then restoring its mask.
- A forked child, which inherits AsyncRT's queue but none of its
  workers, still gets working threads (``spawn`` falls back to
  OS threads there).
"""

from std.atomic import Atomic, Ordering
from std.ffi import c_int, external_call
from std.memory import Layout, Pointer, alloc
from std.time import perf_counter_ns
from std.testing import assert_equal, assert_true, TestSuite

from flare.runtime._asyncrt import (
    asyncrt_leases_held,
    asyncrt_release_lease,
    asyncrt_try_lease,
    asyncrt_worker_capacity,
)
from flare.runtime._thread import (
    ThreadHandle,
    _KIND_ASYNCRT,
    _KIND_OS,
    _OpaquePtr,
    _null_ptr,
    current_thread_id,
    pin_target_cpu,
    restore_thread_affinity,
    save_thread_affinity,
)
from flare.utils import SIGKILL, exit, fork, kill


# ── Shared Int64 cells ──────────────────────────────────────────────────────


def _new_cells(n: Int) -> Int:
    var raw = alloc(Layout[Int64](count=n)).unsafe_leak()
    for i in range(n):
        raw.unsafe_offset(i).unsafe_write(Int64(0))
    return Int(raw)


def _free_cells(addr: Int):
    Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr).unsafe_free()


@always_inline
def _cell(
    addr: Int, i: Int
) -> Pointer[Scalar[DType.int64], MutUntrackedOrigin]:
    return (
        Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
        .unsafe_offset(i)
        .unsafe_bitcast[Scalar[DType.int64]]()
    )


@always_inline
def _load(addr: Int, i: Int) -> Int64:
    return Atomic[Int64].load[ordering=Ordering.ACQUIRE](_cell(addr, i))


@always_inline
def _store(addr: Int, i: Int, v: Int64):
    Atomic[Int64].store[ordering=Ordering.RELEASE](_cell(addr, i), v)


def _spin_until_nonzero(addr: Int, i: Int):
    while _load(addr, i) == 0:
        pass


# ── Start routines ──────────────────────────────────────────────────────────


def _record_thread(arg: _OpaquePtr) -> _OpaquePtr:
    """cells[0] = 42, cells[1] = the running thread's id."""
    var a = Int(arg)
    _store(a, 1, Int64(Int(current_thread_id())))
    _store(a, 0, 42)
    return _null_ptr()


def _bump(arg: _OpaquePtr) -> _OpaquePtr:
    """Atomically add 1 to cells[0]."""
    _ = Atomic[Int64].fetch_add(_cell(Int(arg), 0), 1)
    return _null_ptr()


def _gated(arg: _OpaquePtr) -> _OpaquePtr:
    """Wait for cells[0] (the gate), then set cells[1] (done)."""
    var a = Int(arg)
    _spin_until_nonzero(a, 0)
    _store(a, 1, 1)
    return _null_ptr()


def _set_done(arg: _OpaquePtr) -> _OpaquePtr:
    _store(Int(arg), 0, 1)
    return _null_ptr()


def _spawn_and_join_child(arg: _OpaquePtr) -> _OpaquePtr:
    """Spawn ``_record_thread`` on cells[2..] and join it from here.

    Sets cells[0] = 1 on success, 2 if spawn/join raised.
    """
    var a = Int(arg)
    try:
        var child = ThreadHandle.spawn[_record_thread](
            _OpaquePtr(unsafe_from_address=a + 2 * 8)
        )
        child.join()
        _store(a, 0, 1)
    except:
        _store(a, 0, 2)
    return _null_ptr()


def _mask_bits(mask: Int) -> Int:
    var n = 0
    var p = Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=mask)
    for i in range(128):
        var b = p.unsafe_offset(i)[]
        while b != 0:
            n += Int(b & 1)
            b >>= 1
    return n


def _masks_equal(a: Int, b: Int) -> Bool:
    var pa = Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=a)
    var pb = Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=b)
    for i in range(128):
        if pa.unsafe_offset(i)[] != pb.unsafe_offset(i)[]:
            return False
    return True


def _pin_then_restore(arg: _OpaquePtr) -> _OpaquePtr:
    """What a pinned serving loop does to the worker it runs on: pin to
    CPU 0, then put the saved mask back. cells[0] = 1 when the pin took
    and the mask came back unchanged (or the OS has no masks), 2 if not.
    """
    var a = Int(arg)
    var saved = save_thread_affinity()
    if saved == 0:
        _store(a, 0, 1)
        return _null_ptr()
    var before = save_thread_affinity()
    var ok = True
    try:
        ThreadHandle(_thread_id=current_thread_id()).pin_to_cpu(0)
    except:
        ok = False
    var pinned = save_thread_affinity()
    ok = ok and _mask_bits(pinned) == 1
    restore_thread_affinity(saved)
    var after = save_thread_affinity()
    ok = ok and _masks_equal(before, after)
    restore_thread_affinity(pinned)
    restore_thread_affinity(after)
    restore_thread_affinity(before)
    _store(a, 0, Int64(1 if ok else 2))
    return _null_ptr()


def _pin_target_follows_mask(arg: _OpaquePtr) -> _OpaquePtr:
    """Narrow this thread to one allowed CPU; every worker index must then
    map to it. cells[0] = 1 when it does (or the OS has no masks), 2 if not.
    """
    var a = Int(arg)
    var saved = save_thread_affinity()
    if saved == 0:
        _store(a, 0, 1)
        return _null_ptr()
    var only = pin_target_cpu(1)
    var ok = True
    try:
        ThreadHandle(_thread_id=current_thread_id()).pin_to_cpu(only)
    except:
        ok = False
    for idx in range(4):
        ok = ok and pin_target_cpu(idx) == only
    restore_thread_affinity(saved)
    _store(a, 0, Int64(1 if ok else 2))
    return _null_ptr()


# ── Tests ───────────────────────────────────────────────────────────────────


def test_pin_target_stays_inside_the_allowed_cpus() raises:
    var cells = _new_cells(1)
    var h = ThreadHandle.spawn[_pin_target_follows_mask](
        _OpaquePtr(unsafe_from_address=cells)
    )
    h.join()
    assert_equal(Int(_load(cells, 0)), 1)
    _free_cells(cells)


def test_pinned_worker_gets_its_mask_back() raises:
    var cells = _new_cells(1)
    var h = ThreadHandle.spawn[_pin_then_restore](
        _OpaquePtr(unsafe_from_address=cells)
    )
    h.join()
    assert_equal(Int(_load(cells, 0)), 1)
    _free_cells(cells)


def test_spawn_is_asyncrt_task() raises:
    var cells = _new_cells(2)
    var h = ThreadHandle.spawn[_record_thread](
        _OpaquePtr(unsafe_from_address=cells)
    )
    assert_equal(Int(h._kind), Int(_KIND_ASYNCRT))
    h.join()
    _free_cells(cells)


def test_spawn_os_is_always_os_thread() raises:
    var cells = _new_cells(2)
    var h = ThreadHandle.spawn_os[_record_thread](
        _OpaquePtr(unsafe_from_address=cells)
    )
    assert_equal(Int(h._kind), Int(_KIND_OS))
    h.join()
    assert_equal(Int(_load(cells, 0)), 42)
    _free_cells(cells)


def test_spawn_join_round_trip() raises:
    # Not "off the caller's thread": under ``mojo run`` main is itself a
    # pool worker, and its join may donate and run the task inline.
    var cells = _new_cells(2)
    var h = ThreadHandle.spawn[_record_thread](
        _OpaquePtr(unsafe_from_address=cells)
    )
    h.join()
    assert_equal(Int(_load(cells, 0)), 42)
    assert_true(_load(cells, 1) != 0)
    # A second join on the same handle is a no-op.
    h.join()
    _free_cells(cells)


def test_many_short_tasks() raises:
    comptime N = 1000
    var cells = _new_cells(1)
    var handles = alloc(Layout[ThreadHandle](count=N)).unsafe_leak()
    for i in range(N):
        handles.unsafe_offset(i).unsafe_write(
            ThreadHandle.spawn[_bump](_OpaquePtr(unsafe_from_address=cells))
        )
    for i in range(N):
        handles.unsafe_offset(i)[].join()
    assert_equal(Int(_load(cells, 0)), N)
    for i in range(N):
        handles.unsafe_offset(i).unsafe_deinit_pointee()
    handles.unsafe_free()
    _free_cells(cells)


def test_detach_before_completion() raises:
    # The task blocks on the gate, so detach lands while it is running
    # and the task has to free its own cell on the way out.
    var cells = _new_cells(2)
    var h = ThreadHandle.spawn[_gated](_OpaquePtr(unsafe_from_address=cells))
    h.detach()
    _store(cells, 0, 1)
    _spin_until_nonzero(cells, 1)
    # join after detach is a no-op, never a double free.
    h.join()
    # The task stops touching ``cells`` once it sets cells[1]; its
    # epilogue only touches its own task cell.
    _free_cells(cells)


def test_detach_after_completion() raises:
    var cells = _new_cells(1)
    var h = ThreadHandle.spawn[_set_done](_OpaquePtr(unsafe_from_address=cells))
    _spin_until_nonzero(cells, 0)
    # The task may or may not have reached its state CAS yet; whichever
    # side loses the race frees the task cell.
    h.detach()
    _free_cells(cells)


def test_join_from_inside_task() raises:
    # cells[0]: outer result; cells[2], cells[3]: child's record.
    var cells = _new_cells(4)
    var h = ThreadHandle.spawn[_spawn_and_join_child](
        _OpaquePtr(unsafe_from_address=cells)
    )
    h.join()
    assert_equal(Int(_load(cells, 0)), 1)
    assert_equal(Int(_load(cells, 2)), 42)
    _free_cells(cells)


def test_nested_join_under_load() raises:
    # Fill the pool with tasks that each spawn and join a child. With a
    # donating chain wait a parent could pick up a sibling instead of
    # returning; the state-word join must not care.
    comptime N = 64
    var cells = _new_cells(4 * N)
    var handles = alloc(Layout[ThreadHandle](count=N)).unsafe_leak()
    for i in range(N):
        handles.unsafe_offset(i).unsafe_write(
            ThreadHandle.spawn[_spawn_and_join_child](
                _OpaquePtr(unsafe_from_address=cells + i * 4 * 8)
            )
        )
    for i in range(N):
        handles.unsafe_offset(i)[].join()
        handles.unsafe_offset(i).unsafe_deinit_pointee()
    for i in range(N):
        assert_equal(Int(_load(cells + i * 4 * 8, 0)), 1)
        assert_equal(Int(_load(cells + i * 4 * 8, 2)), 42)
    handles.unsafe_free()
    _free_cells(cells)


def test_leases_stop_at_capacity() raises:
    var cap = asyncrt_worker_capacity()
    assert_true(cap >= 1)
    var base = asyncrt_leases_held()
    var taken = 0
    while asyncrt_try_lease():
        taken += 1
    assert_equal(base + taken, cap)
    for _ in range(taken):
        asyncrt_release_lease()
    assert_equal(asyncrt_leases_held(), base)


def test_spawn_serving_overflows_to_os_thread() raises:
    var taken = 0
    while asyncrt_try_lease():
        taken += 1
    var cells = _new_cells(2)
    var h = ThreadHandle.spawn_serving[_record_thread](
        _OpaquePtr(unsafe_from_address=cells)
    )
    assert_equal(Int(h._kind), Int(_KIND_OS))
    h.join()
    assert_equal(Int(_load(cells, 0)), 42)
    for _ in range(taken):
        asyncrt_release_lease()
    _free_cells(cells)


def test_spawn_serving_returns_its_lease() raises:
    var base = asyncrt_leases_held()
    var cells = _new_cells(2)
    var h = ThreadHandle.spawn_serving[_record_thread](
        _OpaquePtr(unsafe_from_address=cells)
    )
    assert_equal(Int(h._kind), Int(_KIND_ASYNCRT))
    h.wait_started()
    h.join()
    assert_equal(Int(_load(cells, 0)), 42)
    assert_equal(asyncrt_leases_held(), base)
    _free_cells(cells)


def test_spawn_join_in_forked_child() raises:
    # Touch the pool in the parent first, so the child inherits a cell
    # that says "alive" for the parent's pid.
    var warm = _new_cells(2)
    var w = ThreadHandle.spawn[_record_thread](
        _OpaquePtr(unsafe_from_address=warm)
    )
    w.join()
    _free_cells(warm)

    var pid = fork()
    if pid == 0:
        var code = 1
        try:
            var cells = _new_cells(2)
            var h = ThreadHandle.spawn[_record_thread](
                _OpaquePtr(unsafe_from_address=cells)
            )
            h.join()
            if _load(cells, 0) == 42:
                code = 42
        except:
            pass
        exit(code)
    assert_true(pid > 0, "fork failed")

    # Reap with WNOHANG so a child stuck on a dead pool fails the test
    # instead of hanging the suite. A yield loop against a deadline, not
    # a sleep: sleeps after pthread_create overshoot by orders of
    # magnitude here (see Scheduler.drain).
    comptime WNOHANG: c_int = 1
    var status = Int32(0)
    var status_addr = Int(Pointer[Int32, _](to=status))
    var reaped = False
    var deadline = perf_counter_ns() + 10_000_000_000
    while perf_counter_ns() < deadline:
        var rc = external_call["waitpid", c_int](
            c_int(pid), status_addr, WNOHANG
        )
        if rc == c_int(pid):
            reaped = True
            break
        _ = external_call["sched_yield", c_int]()
    if not reaped:
        _ = kill(pid, SIGKILL)
        _ = external_call["waitpid", c_int](c_int(pid), status_addr, c_int(0))
    assert_true(reaped, "forked child hung spawning a thread")
    assert_equal(Int((status >> 8) & 0xFF), 42)


def main() raises:
    print("=" * 60)
    print("test_thread_engine.mojo — AsyncRT tasks + OS threads")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
