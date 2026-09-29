"""Benchmark: flare's thread engine, pthread vs AsyncRT.

The same source, built twice:

    mojo build -D ASSERT=none -I . benchmark/bench_threads.mojo -o bt_pthread
    mojo build -D ASSERT=none -D FLARE_ASYNCRT -I . benchmark/bench_threads.mojo -o bt_asyncrt

``pixi run bench-threads`` does both builds and runs them back to back.
Each line is ``engine,workload,param,ns_per_op`` so the two outputs
paste into one table.

Workloads (each the median of ``BENCH_REPS`` runs, default 5):

- ``spawn_join``: spawn one empty task and join it, ``N`` times in a
  row. This is the per-task floor, and what a fine-grained work item
  pays.
- ``fanout``: spawn ``M`` tasks that each do a small fixed amount of
  arithmetic, then join them all. The time is reported per task.
- ``block_in_pool``: ``block_in_pool`` round trips of a trivial
  closure, the path a reactor handler takes to offload blocking work.
  ``block_in_pool`` also takes a named semaphore per call, so this row
  is not a pure spawn measurement on either engine.
"""

from std.atomic import Atomic
from std.memory import Layout, Pointer, alloc
from std.os import getenv
from std.time import perf_counter_ns

from flare.http import Cancel
from flare.runtime import block_in_pool
from flare.runtime._asyncrt import FLARE_USE_ASYNCRT
from flare.runtime._thread import ThreadHandle, _OpaquePtr, _null_ptr


def _engine() -> String:
    comptime if FLARE_USE_ASYNCRT:
        return "asyncrt"
    else:
        return "pthread"


def _env_int(name: String, default: Int) -> Int:
    var v = getenv(name)
    if v == "":
        return default
    try:
        return Int(v)
    except:
        return default


def _median(mut xs: List[Int]) -> Int:
    sort(xs)
    return xs[len(xs) // 2]


def _nop(arg: _OpaquePtr) -> _OpaquePtr:
    return _null_ptr()


def _work(arg: _OpaquePtr) -> _OpaquePtr:
    """~10k dependent adds, then publish into the shared sink."""
    var acc = Int(arg) & 0xFF
    for i in range(10_000):
        acc = acc * 31 + i
    var sink = Pointer[Int64, MutUntrackedOrigin](
        unsafe_from_address=Int(arg)
    ).unsafe_bitcast[Scalar[DType.int64]]()
    _ = Atomic[Int64].fetch_add(sink, Int64(acc & 1))
    return _null_ptr()


def _trivial() raises -> Int:
    return 1


def bench_spawn_join(n: Int) raises -> Int:
    var t0 = perf_counter_ns()
    for _ in range(n):
        var h = ThreadHandle.spawn[_nop](_null_ptr())
        h.join()
    return Int(perf_counter_ns() - t0) // n


def bench_fanout(m: Int) raises -> Int:
    var sink = alloc(Layout[Int64](count=1)).unsafe_leak()
    sink.unsafe_write(0)
    var handles = alloc(Layout[ThreadHandle](count=m)).unsafe_leak()
    var t0 = perf_counter_ns()
    for i in range(m):
        handles.unsafe_offset(i).unsafe_write(
            ThreadHandle.spawn[_work](_OpaquePtr(unsafe_from_address=Int(sink)))
        )
    for i in range(m):
        handles.unsafe_offset(i)[].join()
    var dt = Int(perf_counter_ns() - t0)
    for i in range(m):
        handles.unsafe_offset(i).unsafe_deinit_pointee()
    handles.unsafe_free()
    sink.unsafe_free()
    return dt // m


def bench_block_in_pool(n: Int) raises -> Int:
    var t0 = perf_counter_ns()
    var total = 0
    for _ in range(n):
        total += block_in_pool[Int](_trivial, Cancel.never())
    var dt = Int(perf_counter_ns() - t0)
    if total != n:
        raise Error("block_in_pool returned the wrong total")
    return dt // n


def main() raises:
    var reps = _env_int("BENCH_REPS", 5)
    var n = _env_int("BENCH_SPAWN_N", 2000)
    var m = _env_int("BENCH_FANOUT_M", 1000)
    var b = _env_int("BENCH_BLOCK_N", 500)
    var engine = _engine()

    # One untimed pass so first-touch costs (pool warm-up, page faults,
    # the semaphore's first open) stay out of the medians.
    _ = bench_spawn_join(16)
    _ = bench_fanout(16)
    _ = bench_block_in_pool(16)

    var sj = List[Int]()
    var fo = List[Int]()
    var bp = List[Int]()
    for _ in range(reps):
        sj.append(bench_spawn_join(n))
        fo.append(bench_fanout(m))
        bp.append(bench_block_in_pool(b))

    print(engine + ",spawn_join,n=" + String(n) + "," + String(_median(sj)))
    print(engine + ",fanout,m=" + String(m) + "," + String(_median(fo)))
    print(engine + ",block_in_pool,n=" + String(b) + "," + String(_median(bp)))
