"""Experimental AsyncRT task backend for ``ThreadHandle``.

Compiled in only when the program is built with ``-D FLARE_ASYNCRT``
(see ``FLARE_USE_ASYNCRT``). Without the flag nothing here is reached
and the binary has no AsyncRT calls in it.

AsyncRT is the work-queue runtime the Mojo stdlib and the rest of the
Modular stack run on. Every Mojo binary links it
(``libKGENCompilerRTShared``) and creates the pool before ``main``.
Putting flare's threads on that same pool means one thread engine per
process instead of two fighting over the cores.

The FFI surface is the C shims in ``Mojo/lib/CompilerRT/AsyncRT.cpp``
that the stdlib's own ``std.runtime._asyncrt`` uses, and nothing more,
since AsyncRT is internal and those entry points can change between
Mojo releases:

- ``KGEN_CompilerRT_AsyncRT_Execute(void (*)(int8_t *), int8_t *,
  ssize_t worker_id)`` enqueues a plain C callback. No coroutine is
  involved: the callback is a trampoline that runs the flare start
  routine and then completes the task's chain.
- ``InitializeChain`` / ``Complete`` / ``Wait`` / ``DestroyChain`` on
  an ``AsyncValueRef<Chain>`` (one pointer) give join.
- ``std.runtime.parallelism_level`` for the pool size.

Join waits on the chain, and a chain wait called from a pool worker
*donates* the worker: it runs other queued tasks inline until the
chain is ready. That is what makes nested fork/join work on a fixed
pool (a parent that blocked its worker outright would deadlock once
every worker held a parent waiting on a queued child). The cost is
that a donating waiter may pick up any queued task. For a short task
that only delays the waiter; for a serving loop that never returns it
would never get back. So serving loops (``Scheduler`` and WebSocket
workers) are started with ``wait_started``: the spawner waits until
every loop is running, so none is ever sitting in the queue where a
waiter could take it.

A forked child has no pool. ``fork`` copies only the calling thread,
so the child inherits AsyncRT's queue but none of its workers: a task
enqueued there never runs, and on macOS enqueueing can crash outright
(AsyncRT wakes workers through libdispatch, which traps when used
after ``fork``). So the child must not call into AsyncRT at all.
``asyncrt_pool_alive`` tells the two apart without doing so: a live
pool has its ``parallelism_level()`` worker threads, while a child
starts with one thread. ``ThreadHandle.spawn`` falls back to a pthread
when the pool is dead (a pre-fork server, or the fork-based server
tests).

Things that must not run here, and use ``ThreadHandle.spawn_os``
instead:

- Anything that never returns. Process exit releases the AsyncRT
  device, which shuts the work queue down and waits for running
  tasks, so a task that loops forever hangs exit.
- Anything that lives as long as a connection. The pool has a fixed
  number of workers (it does not grow when a task blocks), so one
  task per connection starves it.

Task cell layout (four ``Int64`` slots, native allocator):

- ``[0]`` the start routine's argument address.
- ``[1]`` state: ``RUNNING``, ``DONE`` or ``DETACHED``. The task and
  the handle race on it with CAS; see ``_asyncrt_trampoline``.
- ``[2]`` started flag, set when the task begins running.
- ``[3]`` the ``AsyncValueRef<Chain>`` storage.
"""

from std.atomic import Atomic, Ordering
from std.ffi import _get_global, c_int, external_call
from std.memory import Layout, OptionalPointer, Pointer, alloc
from std.runtime import parallelism_level
from std.sys import stderr
from std.sys.defines import is_defined
from std.sys.info import CompilationTarget
from std.time import perf_counter_ns


comptime FLARE_USE_ASYNCRT: Bool = is_defined["FLARE_ASYNCRT"]()
"""True when built with ``-D FLARE_ASYNCRT``: ``ThreadHandle.spawn``
enqueues onto the AsyncRT pool instead of calling ``pthread_create``."""

comptime _OpaquePtr = Pointer[UInt8, MutUntrackedOrigin]

comptime _CELL_ARG: Int = 0
comptime _CELL_STATE: Int = 1
comptime _CELL_STARTED: Int = 2
comptime _CELL_CHAIN: Int = 3
comptime _CELL_SLOTS: Int = 4

comptime _STATE_RUNNING: Int64 = 0
comptime _STATE_DONE: Int64 = 1
comptime _STATE_DETACHED: Int64 = 2


@always_inline
def _slot(
    cell: Int, i: Int
) -> Pointer[Scalar[DType.int64], MutUntrackedOrigin]:
    return (
        Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=cell)
        .unsafe_offset(i)
        .unsafe_bitcast[Scalar[DType.int64]]()
    )


@always_inline
def _load(cell: Int, i: Int) -> Int64:
    return Atomic[Int64].load[ordering=Ordering.ACQUIRE](_slot(cell, i))


@always_inline
def _cas_state(cell: Int, expected: Int64, desired: Int64) -> Bool:
    var e = expected
    return Atomic[Int64].compare_exchange(_slot(cell, _CELL_STATE), e, desired)


@always_inline
def _chain(cell: Int) -> _OpaquePtr:
    return _OpaquePtr(unsafe_from_address=cell + _CELL_CHAIN * 8)


@always_inline
def _chain_wait(cell: Int):
    external_call["KGEN_CompilerRT_AsyncRT_Wait", NoneType](_chain(cell))


@always_inline
def _chain_complete(cell: Int):
    external_call["KGEN_CompilerRT_AsyncRT_Complete", NoneType](_chain(cell))


def _destroy_cell(cell: Int):
    external_call["KGEN_CompilerRT_AsyncRT_DestroyChain", NoneType](
        _chain(cell)
    )
    Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=cell).unsafe_free()


def _asyncrt_trampoline[
    start: def(_OpaquePtr) thin -> _OpaquePtr
](cell_ptr: _OpaquePtr):
    """AsyncRT work item: run ``start(arg)``, then publish completion.

    Must not raise: it runs on an AsyncRT worker with no error channel,
    the same contract as a pthread start routine.

    The state CAS comes before the chain completes. After
    ``RUNNING -> DONE`` the joiner owns the cell and may free it as soon
    as the chain is ready, so completing the chain is the last touch.
    ``Complete`` takes its own reference to the chain before emplacing,
    so it never reads the cell after waking the joiner. If the handle
    was detached first nobody will join, and the task completes the
    chain and frees the cell itself.
    """
    var cell = Int(cell_ptr)
    Atomic[Int64].store[ordering=Ordering.RELEASE](
        _slot(cell, _CELL_STARTED), 1
    )
    var arg_addr = Int(_load(cell, _CELL_ARG))
    _ = start(_OpaquePtr(unsafe_from_address=arg_addr))
    if _cas_state(cell, _STATE_RUNNING, _STATE_DONE):
        _chain_complete(cell)
    else:
        # Detached. Complete before destroying: AsyncRT does not allow
        # dropping the last reference to a chain that never became
        # available.
        _chain_complete(cell)
        _destroy_cell(cell)


def asyncrt_spawn[
    start: def(_OpaquePtr) thin -> _OpaquePtr
](arg: _OpaquePtr) -> UInt64:
    """Enqueue ``start(arg)`` on the AsyncRT pool.

    Returns the task cell's address, which the ``ThreadHandle`` stores
    in place of a ``pthread_t``. Never fails: the work queue is
    unbounded, and the task runs once a pool worker is free.
    """
    var raw = alloc(Layout[Int64](count=_CELL_SLOTS)).unsafe_leak()
    for i in range(_CELL_SLOTS):
        raw.unsafe_offset(i).unsafe_write(Int64(0))
    raw.unsafe_offset(_CELL_ARG).unsafe_write(Int64(Int(arg)))
    var cell = Int(raw)
    external_call["KGEN_CompilerRT_AsyncRT_InitializeChain", NoneType](
        _chain(cell)
    )
    # worker_id -1: no worker preference, any free worker takes it.
    external_call[
        "KGEN_CompilerRT_AsyncRT_Execute",
        NoneType,
        def(_OpaquePtr) thin -> None,
        _OpaquePtr,
        Int,
    ](
        _asyncrt_trampoline[start],
        _OpaquePtr(unsafe_from_address=cell),
        -1,
    )
    return UInt64(cell)


def asyncrt_join(cell_id: UInt64):
    """Wait for the task at ``cell_id`` to finish, then free its cell.

    From a pool worker the wait donates the worker to other queued
    tasks; from any other thread (``main`` included) it just blocks.
    """
    var cell = Int(cell_id)
    _chain_wait(cell)
    _destroy_cell(cell)


def asyncrt_detach(cell_id: UInt64):
    """Let the task at ``cell_id`` finish on its own.

    ``RUNNING -> DETACHED`` makes the task free the cell when it
    returns. If the task already claimed ``DONE`` it is about to
    complete the chain (or has), so wait for that and free here.
    """
    var cell = Int(cell_id)
    if not _cas_state(cell, _STATE_RUNNING, _STATE_DETACHED):
        _chain_wait(cell)
        _destroy_cell(cell)


def _nudge_task(arg: _OpaquePtr):
    pass


comptime _NUDGE_EVERY_NS: Int = 1_000_000


def asyncrt_wait_started(cell_id: UInt64):
    """Block until the task at ``cell_id`` has begun running.

    Polls rather than waiting on a chain, so the caller never donates
    itself and never runs the task it is waiting for.

    While it waits it enqueues a no-op task every millisecond. AsyncRT
    pokes a sleeping worker only when one is suspended at the moment a
    task is enqueued, and otherwise counts on the awake workers to drain
    the queue. Serving loops break that assumption: enqueued back to
    back, each awake worker takes one and never returns, and a loop
    still queued can be left there while the remaining workers go to
    sleep (the stress scheduler hit this). Each nudge's enqueue wakes a
    sleeper, which then finds the stranded loop.
    """
    var cell = Int(cell_id)
    var last = perf_counter_ns()
    while _load(cell, _CELL_STARTED) == 0:
        var now = perf_counter_ns()
        if Int(now - last) >= _NUDGE_EVERY_NS:
            external_call[
                "KGEN_CompilerRT_AsyncRT_Execute",
                NoneType,
                def(_OpaquePtr) thin -> None,
                _OpaquePtr,
                Int,
            ](_nudge_task, _OpaquePtr(unsafe_from_address=cell), -1)
            last = now
        _ = external_call["sched_yield", c_int]()


# ── Pool liveness (fork) ────────────────────────────────────────────────────
# One process-global cell, via the stdlib's KGEN global table:
#   [0] pid the verdict belongs to, [1] verdict (_POOL_ALIVE / _POOL_DEAD).
# A forked child inherits the parent's cell, and the pid mismatch makes it
# decide again for itself.

comptime _POOL_ALIVE: Int64 = 1
comptime _POOL_DEAD: Int64 = 2


def _pool_cell_init() -> OptionalPointer[NoneType, UntrackedOrigin[mut=True]]:
    var raw = alloc(Layout[Int64](count=2)).unsafe_leak()
    raw.unsafe_offset(0).unsafe_write(Int64(0))
    raw.unsafe_offset(1).unsafe_write(Int64(0))
    return Pointer[NoneType, UntrackedOrigin[mut=True]](
        unsafe_from_address=Int(raw)
    )


def _pool_cell_destroy(p: OptionalPointer[NoneType, UntrackedOrigin[mut=True]]):
    if p:
        Pointer[Int64, MutUntrackedOrigin](
            unsafe_from_address=Int(p.value())
        ).unsafe_free()


def _pool_cell() -> Int:
    var p = _get_global[
        "flare_asyncrt_pool", _pool_cell_init, _pool_cell_destroy
    ]()
    return Int(p.value())


def _process_thread_count(pid: Int32) -> Int:
    """Threads in this process, or -1 if the OS would not say.

    macOS: ``proc_pidinfo(PROC_PIDTASKINFO)``, whose ``proc_taskinfo``
    is 96 bytes with ``pti_threadnum`` (an int32) at offset 84. Linux:
    field 20 (``num_threads``) of ``/proc/self/stat``, counted after the
    ``)`` that closes the command name, since the name may hold spaces.
    """
    comptime if CompilationTarget.is_macos():
        comptime PROC_PIDTASKINFO: c_int = 4
        comptime TASKINFO_SIZE: Int = 96
        comptime THREADNUM_OFFSET: Int = 84
        var buf = alloc(Layout[UInt8](count=TASKINFO_SIZE)).unsafe_leak()
        var rc = external_call["proc_pidinfo", c_int](
            c_int(pid), PROC_PIDTASKINFO, UInt64(0), buf, c_int(TASKINFO_SIZE)
        )
        var n = -1
        if Int(rc) == TASKINFO_SIZE:
            n = Int(
                buf.unsafe_offset(THREADNUM_OFFSET).unsafe_bitcast[Int32]()[]
            )
        buf.unsafe_free()
        return n
    else:
        try:
            var stat: String
            with open("/proc/self/stat", "r") as f:
                stat = f.read()
            var close = stat.rfind(")")
            if close < 0:
                return -1
            # After ")": field 3 (state) is index 0, so field 20 is 17.
            var fields = stat[byte = close + 1 :].split()
            if len(fields) <= 17:
                return -1
            return Int(fields[17])
        except:
            return -1


def asyncrt_pool_alive() -> Bool:
    """True when this process's AsyncRT pool has its worker threads.

    False in a child forked from a Mojo process (see the module
    docstring). Decided without calling into AsyncRT: the pool is
    alive when the process has at least ``parallelism_level() + 1``
    threads (the pool's workers plus the caller). A forked child starts
    with one. It would only be misjudged if it created that many threads
    of its own before its first flare spawn. If the OS won't report a
    count, the pool is assumed alive, which matches the behaviour
    without this check. Cached per pid, so after the first call in a
    process this is one ``getpid`` and two loads.
    """
    var cell = _pool_cell()
    var pid32 = external_call["getpid", Int32]()
    var pid = Int64(Int(pid32))
    if _load(cell, 0) == pid:
        return _load(cell, 1) == _POOL_ALIVE
    var threads = _process_thread_count(pid32)
    var alive = threads < 0 or threads >= parallelism_level() + 1
    # Verdict first, then pid: a reader that sees our pid (acquire)
    # sees our verdict.
    Atomic[Int64].store[ordering=Ordering.RELEASE](
        _slot(cell, 1), _POOL_ALIVE if alive else _POOL_DEAD
    )
    Atomic[Int64].store[ordering=Ordering.RELEASE](_slot(cell, 0), pid)
    if not alive:
        print(
            "flare: AsyncRT pool has no worker threads in pid",
            pid,
            "(forked child?); using pthreads in this process",
            file=stderr,
        )
    return alive


def asyncrt_worker_capacity() -> Int:
    """Pool workers flare may hold with long-lived tasks (serving loops).

    One below the pool size, so at least one worker stays free for
    short tasks (``block_in_pool``, DNS, the H3/H2 race) and for
    whatever else in the process uses AsyncRT. Never below 1.
    """
    var n = parallelism_level() - 1
    return n if n >= 1 else 1


def check_asyncrt_capacity(who: String, num_workers: Int) raises:
    """Raise if ``num_workers`` long-lived tasks would exhaust the pool.

    No-op unless built with ``-D FLARE_ASYNCRT``. The check is per call,
    not process-wide: two servers started side by side can still
    oversubscribe the pool together.
    """
    comptime if FLARE_USE_ASYNCRT:
        if not asyncrt_pool_alive():
            return  # workers will be pthreads, see ThreadHandle.spawn
        var cap = asyncrt_worker_capacity()
        if num_workers > cap:
            raise Error(
                who
                + ": num_workers="
                + String(num_workers)
                + " exceeds the AsyncRT pool capacity "
                + String(cap)
                + " (parallelism_level() - 1). Each worker holds a pool"
                " thread for the server's lifetime; lower num_workers or"
                " build without -D FLARE_ASYNCRT."
            )
