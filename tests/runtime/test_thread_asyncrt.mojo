"""Tests for the thread-engine switch in ``flare.runtime._thread``.

Runs under both engines. Built plainly, ``spawn`` makes pthreads;
built with ``-D FLARE_ASYNCRT`` it enqueues AsyncRT tasks
(``flare.runtime._asyncrt``). ``pixi run test-thread-asyncrt`` runs the
file both ways.

Covers:

- ``spawn`` picks the engine the build asked for; ``spawn_os`` is
  always a pthread.
- spawn + join round-trips, off the calling thread.
- 1000 short tasks all run and all join.
- ``detach`` both before and after the task finishes (the cell must be
  freed exactly once either way).
- join from inside a spawned task, including one that spawns its own
  child (the path where an AsyncRT chain wait would donate).
- The pool-capacity check for long-lived workers.
- A forked child, which inherits AsyncRT's queue but none of its
  workers, still gets working threads (``spawn`` falls back to
  pthreads there).
"""

from std.atomic import Atomic, Ordering
from std.ffi import c_int, external_call
from std.memory import Layout, Pointer, alloc
from std.time import perf_counter_ns
from std.testing import assert_equal, assert_false, assert_true, TestSuite

from flare.runtime._asyncrt import (
    FLARE_USE_ASYNCRT,
    asyncrt_worker_capacity,
    check_asyncrt_capacity,
)
from flare.runtime._thread import (
    ThreadHandle,
    _KIND_ASYNCRT,
    _KIND_OS,
    _OpaquePtr,
    _null_ptr,
    current_thread_id,
)
from flare.runtime.scheduler import default_worker_count
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


# ── Tests ───────────────────────────────────────────────────────────────────


def test_engine_matches_build() raises:
    var cells = _new_cells(2)
    var h = ThreadHandle.spawn[_record_thread](
        _OpaquePtr(unsafe_from_address=cells)
    )
    comptime if FLARE_USE_ASYNCRT:
        assert_equal(Int(h._kind), Int(_KIND_ASYNCRT))
    else:
        assert_equal(Int(h._kind), Int(_KIND_OS))
    h.join()
    _free_cells(cells)


def test_spawn_os_is_always_pthread() raises:
    var cells = _new_cells(2)
    var h = ThreadHandle.spawn_os[_record_thread](
        _OpaquePtr(unsafe_from_address=cells)
    )
    assert_equal(Int(h._kind), Int(_KIND_OS))
    h.join()
    assert_equal(Int(_load(cells, 0)), 42)
    _free_cells(cells)


def test_spawn_join_runs_off_caller_thread() raises:
    var cells = _new_cells(2)
    var h = ThreadHandle.spawn[_record_thread](
        _OpaquePtr(unsafe_from_address=cells)
    )
    h.join()
    assert_equal(Int(_load(cells, 0)), 42)
    assert_true(_load(cells, 1) != Int64(Int(current_thread_id())))
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


def test_capacity_check() raises:
    var cap = asyncrt_worker_capacity()
    assert_true(cap >= 1)
    check_asyncrt_capacity("test", cap)
    var raised = False
    try:
        check_asyncrt_capacity("test", cap + 1)
    except:
        raised = True
    comptime if FLARE_USE_ASYNCRT:
        assert_true(raised)
        assert_true(default_worker_count() <= cap)
    else:
        assert_false(raised)


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
    comptime if FLARE_USE_ASYNCRT:
        print("test_thread_asyncrt.mojo — engine: AsyncRT")
    else:
        print("test_thread_asyncrt.mojo — engine: pthread")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
