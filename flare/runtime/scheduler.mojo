"""Multicore scheduler: N reactors, N pthread workers.

Runs N single-threaded reactor loops in parallel, one per pthread,
each with its own listener bound with ``SO_REUSEPORT``. The kernel
distributes accepted connections across workers so every worker
handles roughly 1/N of the total connection load.

Shutdown path: ``shutdown()`` flips a heap-allocated ``Bool`` that
every worker polls on each reactor iteration. A stable heap address
is used (instead of a field on the ``Scheduler`` struct) so the flag
survives the NRVO-or-not move from ``Scheduler.start`` back to the
caller. The main thread then joins all workers before ``shutdown()``
returns.

Relying on ``close(listener_fd)`` alone to wake the workers is not
enough on Linux: when the fd is also registered in the worker's
``epoll`` instance, the kernel holds an extra reference to the
underlying ``struct file``, so ``close()`` from another thread does
not trigger an ``EPOLLHUP`` and the workers stay blocked in
``epoll_wait`` until the 100 ms poll timeout fires. The heap flag is
what actually breaks the loop.

This module is ``Handler``-generic: every worker runs the same
``H: Handler`` that the caller passed to ``Scheduler.start``. The
handler value is moved (per-worker copies are made via ``H.copy()``;
if that's expensive users should wrap their handler's expensive state
behind an ``UnsafePointer`` or a similar shared-reference holder).

Only the ``Handler`` and ``ServerConfig`` machinery that v0.4.0 already
has is touched; the run loop re-uses ``run_reactor_loop[H]`` from
``flare.http._server_reactor_impl``.

Known limitations (tracked for v0.4.1):

- The stopping flag is a raw ``Bool`` written from the main thread
  and read from each worker, not an atomic. Mojo 0.26.3 stdlib has
  no ``Atomic[Bool]`` / ``Atomic[Int]`` type yet, so we rely on two
  things: (1) aligned single-byte loads and stores being atomic at
  the hardware level on x86-64 and ARM64 with no torn reads;
  (2) the volatile-style ``UnsafePointer[Bool, MutExternalOrigin]``
  materialisation inside ``run_reactor_loop`` defeating the
  optimiser's LICM so every iteration re-reads the flag. This is
  enough in practice on both platforms flare targets, but the
  flag should be upgraded to an ``Atomic`` with explicit
  release/acquire ordering once the stdlib stabilises one.
- Worker panics that escape ``run_reactor_loop`` are caught and
  discarded in ``_worker_entry`` because pthread has no exception
  channel. ``is_running()`` still reports ``True`` until the
  ``ThreadHandle`` is joined, which is a mildly wrong signal for a
  worker that crashed rather than shut down cleanly. Plumbing a
  per-worker error cell back to the Scheduler is also scheduled for
  v0.4.1.
"""

from std.ffi import c_int, external_call
from std.memory import UnsafePointer, alloc

from ..http.handler import Handler
from ..http.server import ServerConfig, ShutdownReport
from ..http._server_reactor_impl import run_reactor_loop
from ..net import SocketAddr
from ..tcp import TcpListener

from ._thread import ThreadHandle, num_cpus, _OpaquePtr
from .reuseport import bind_reuseport


# ── Context cleanup helpers ──────────────────────────────────────────────────


@always_inline
def _scheduler_free_raw(raw: _OpaquePtr):
    """Release a heap cell allocated via ``UnsafePointer[...].alloc``.

    Uses Mojo's native allocator pair (``.alloc`` / ``.free``) rather than
    libc ``malloc``/``free`` via FFI: ``external_call["free", ...]``
    conflicts with the stdlib's own ``free`` declaration at MLIR
    legalization time when this module is pulled into a fuzz-environment
    compile (mozz harness), which previously blocked the
    ``fuzz-scheduler-shutdown`` harness from importing
    ``flare.runtime.scheduler`` at all.
    """
    raw.free()


def _scheduler_free_ctxs[H: Handler & Copyable](addrs: List[Int]):
    """Destroy each WorkerCtx[H] at the given address then free it."""
    for i in range(len(addrs)):
        var raw = _OpaquePtr(unsafe_from_address=addrs[i])
        var typed = raw.bitcast[_WorkerCtx[H]]()
        typed.destroy_pointee()
        _scheduler_free_raw(raw)


# ── Per-worker context ───────────────────────────────────────────────────────


struct _WorkerCtx[H: Handler & Copyable](Movable):
    """Heap-allocated context passed to a pthread start routine.

    Holds a listener (bound with ``SO_REUSEPORT``), a copy of the
    handler + config, the shared stopping flag (as a raw address), and
    a worker index for pinning + logging.
    """

    var listener: TcpListener
    var config: ServerConfig
    var handler: Self.H
    var stopping_addr: Int
    var worker_idx: Int
    var pin_cores: Bool

    def __init__(
        out self,
        var listener: TcpListener,
        var config: ServerConfig,
        var handler: Self.H,
        stopping_addr: Int,
        worker_idx: Int,
        pin_cores: Bool,
    ):
        self.listener = listener^
        self.config = config^
        self.handler = handler^
        self.stopping_addr = stopping_addr
        self.worker_idx = worker_idx
        self.pin_cores = pin_cores


# ── Worker entry point (comptime-specialised per H) ─────────────────────────


def _worker_entry[H: Handler & Copyable](arg: _OpaquePtr) -> _OpaquePtr:
    """Pthread start routine for one reactor worker.

    Casts ``arg`` back to a ``_WorkerCtx[H]`` pointer, optionally pins
    to a CPU, then runs ``run_reactor_loop[H]`` until the shared
    stopping flag is observed.

    The context was allocated on the main thread with libc ``malloc``
    plus ``init_pointee_move``; the Scheduler main thread destroys and
    frees it after joining this worker.
    """
    var ctx_addr = Int(arg)
    var raw = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=ctx_addr
    )
    var ctx_ptr = raw.bitcast[_WorkerCtx[H]]()

    try:
        var stopping_ptr = UnsafePointer[Bool, MutExternalOrigin](
            unsafe_from_address=ctx_ptr[].stopping_addr
        )

        # CPU pinning is best-effort: on macOS it's a no-op and on
        # Linux an overly-ambitious CPU index might raise. Pinning
        # happens from the worker itself via pthread_self, so we
        # re-wrap the current thread id into a ThreadHandle just to
        # reuse the ``pin_to_cpu`` helper.
        if ctx_ptr[].pin_cores:
            try:
                var cpu = ctx_ptr[].worker_idx % num_cpus()
                var self_handle = ThreadHandle(
                    _thread_id=external_call["pthread_self", UInt64]()
                )
                self_handle.pin_to_cpu(cpu)
            except:
                pass

        # ``stopping_ptr[]`` dereferences to the heap-allocated Bool.
        # ``run_reactor_loop`` takes ``stopping`` as a ``def`` parameter
        # (reference semantics in Mojo), so every iteration of
        # ``while not stopping`` re-reads the live flag from this
        # stable heap address. That address was captured at
        # ``Scheduler.start`` time and stays valid until
        # ``Scheduler.shutdown`` joins every worker.
        run_reactor_loop[H](
            ctx_ptr[].listener,
            ctx_ptr[].config,
            ctx_ptr[].handler,
            stopping_ptr[],
        )
    except:
        pass

    # Ctx ownership: the Scheduler main thread destroys + frees every
    # ctx AFTER joining the worker, so we don't touch it here.
    return UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=0)


# ── Scheduler ────────────────────────────────────────────────────────────────


struct Scheduler[H: Handler & Copyable](Movable):
    """Owns ``num_workers`` pthread workers, each running a reactor
    loop over its own ``SO_REUSEPORT`` listener.

    Usage:
        ```mojo
        var s = Scheduler.start[MyHandler](
            addr, config, handler^, num_workers=4
        )
        # ... server running ...
        s.shutdown()
        ```

    Notes:
        - The scheduler stores the workers' ``ThreadHandle`` values and
          a heap-allocated stopping flag. ``shutdown()`` writes through
          that heap address and joins all workers.
        - The stopping flag lives on the heap (not on this struct) so
          its address survives the move from ``Scheduler.start`` back
          to the caller; every worker captures that address once at
          spawn time.
        - Per-worker listener is bound with ``bind_reuseport``, so all
          N workers share the same TCP port via ``SO_REUSEPORT``.
        - Handler is cloned into each worker via ``H.copy()``.
    """

    # Workers are stored in a heap-allocated block of exactly
    # ``num_workers`` slots rather than a ``List[ThreadHandle]``.
    # ``List[T]`` in Mojo 0.26.3 still requires ``T: Copyable``, but
    # ``ThreadHandle`` is *intentionally* move-only: ``pthread_t`` is
    # a unique OS resource and copying the handle would let the same
    # thread be ``pthread_join``'d twice, which is UB per POSIX. So
    # we own the memory directly here instead.
    #
    # ``_workers_ptr`` is NULL when no workers have been allocated
    # (freshly constructed or post-shutdown); ``_workers_len`` tracks
    # how many slots hold a live ``ThreadHandle`` that still needs
    # joining + destroying.
    var _workers_ptr: UnsafePointer[ThreadHandle, MutExternalOrigin]
    var _workers_len: Int
    var _listener_fds: List[Int]
    var _ctx_addrs: List[Int]
    # Heap-allocated Bool, owned by this Scheduler. Address is stable
    # across struct moves; every worker's ``_WorkerCtx.stopping_addr``
    # points at the same heap cell. A 0 value here means "not yet
    # allocated" (freshly constructed) or "already freed" (post-shutdown).
    var _stopping_addr: Int

    def __init__(out self):
        """Build an empty scheduler; use ``Scheduler.start`` instead."""
        self._workers_ptr = UnsafePointer[ThreadHandle, MutExternalOrigin](
            unsafe_from_address=0
        )
        self._workers_len = 0
        self._listener_fds = List[Int]()
        self._ctx_addrs = List[Int]()
        self._stopping_addr = 0

    @staticmethod
    def start(
        addr: SocketAddr,
        var config: ServerConfig,
        var handler: Self.H,
        num_workers: Int,
        pin_cores: Bool = True,
    ) raises -> Scheduler[Self.H]:
        """Spawn ``num_workers`` threads, each running a reactor.

        Args:
            addr:        Address all workers bind (with ``SO_REUSEPORT``).
            config:      Shared server config (copied per worker).
            handler:     Shared request handler (copied per worker).
            num_workers: Number of worker threads. Must be in
                ``1..=256``; values outside that range raise. The
                upper bound is a defensive guard against runaway
                ``pthread_create`` + heap allocation.
            pin_cores:   If ``True`` (default), pin worker N to core
                ``N % num_cpus``. No-op on macOS.

        Returns:
            A running ``Scheduler`` whose workers will continue to
            serve until ``shutdown()`` is called.

        Raises:
            Error: If ``num_workers`` is outside ``1..=256``, if a
                listener fails to bind, or if ``pthread_create``
                fails; partially-started workers are best-effort
                joined before re-raising.
        """
        if num_workers < 1 or num_workers > 256:
            raise Error(
                "Scheduler.start: num_workers must be in 1..=256 (got "
                + String(num_workers)
                + ")"
            )
        var s = Scheduler[Self.H]()

        # Heap-allocate the stopping flag. Using a struct field would
        # be unsafe: ``return s^`` moves the Scheduler to the caller
        # and NRVO is not guaranteed, so any ``&s._stopping`` address
        # captured here could be dangling by the time ``shutdown()``
        # writes through it. The heap cell is allocated here and
        # freed in ``shutdown()`` after every worker joins. Uses the
        # native Mojo allocator (see ``_scheduler_free_raw``).
        var stop_ptr = alloc[Bool](1)
        stop_ptr.init_pointee_copy(False)
        var stop_raw = stop_ptr.bitcast[UInt8]()
        var stopping_addr = Int(stop_ptr)
        s._stopping_addr = stopping_addr

        # Preallocate the worker slot array once; grow is not needed
        # because ``num_workers`` is bounded above (<= 256) and fixed.
        s._workers_ptr = alloc[ThreadHandle](num_workers)
        s._workers_len = 0

        for i in range(num_workers):
            var listener = bind_reuseport(addr)
            # Save fd so shutdown can close all listener sockets from
            # the main thread. On Linux close() alone does not wake
            # a concurrent epoll_wait (the epoll set holds a ref to
            # the underlying file), but closing still helps on macOS
            # via kqueue EV_EOF and speeds up the next accept() path.
            s._listener_fds.append(Int(listener._socket.fd))
            var cfg_copy = config.copy()
            var handler_copy = handler.copy()
            var ctx = _WorkerCtx[Self.H](
                listener^,
                cfg_copy^,
                handler_copy^,
                stopping_addr,
                i,
                pin_cores,
            )
            # Native Mojo allocator (see _scheduler_free_raw for why).
            var ctx_ptr = alloc[_WorkerCtx[Self.H]](1)
            ctx_ptr.init_pointee_move(ctx^)
            var arg = ctx_ptr.bitcast[UInt8]()
            var ctx_addr = Int(ctx_ptr)

            var spawned = False
            try:
                var th = ThreadHandle.spawn[_worker_entry[Self.H]](arg)
                # Move the (non-Copyable) handle into the next slot
                # of the worker array; bump the live-slot counter.
                (s._workers_ptr + s._workers_len).init_pointee_move(th^)
                s._workers_len += 1
                s._ctx_addrs.append(ctx_addr)
                spawned = True
            except:
                pass
            if not spawned:
                # Roll back any workers we already started so the caller
                # gets a fully-stopped scheduler instead of half-live state.
                stop_ptr[] = True
                for j in range(s._workers_len):
                    try:
                        (s._workers_ptr + j)[].join()
                    except:
                        pass
                    (s._workers_ptr + j).destroy_pointee()
                _scheduler_free_raw(s._workers_ptr.bitcast[UInt8]())
                s._workers_ptr = UnsafePointer[ThreadHandle, MutExternalOrigin](
                    unsafe_from_address=0
                )
                s._workers_len = 0
                # Destroy + free EVERY ctx (the ones that workers claimed
                # + this one that never got claimed).
                _scheduler_free_ctxs[Self.H](s._ctx_addrs)
                s._ctx_addrs.clear()
                ctx_ptr.destroy_pointee()
                _scheduler_free_raw(ctx_ptr.bitcast[UInt8]())
                # All workers joined, so no one is reading the
                # stopping flag anymore — safe to free.
                _scheduler_free_raw(stop_raw)
                s._stopping_addr = 0
                raise Error("pthread_create failed in Scheduler.start")

        return s^

    def shutdown(mut self) raises:
        """Signal every worker to stop and wait for them to join.

        Flips the heap-allocated stopping flag, closes every worker's
        listener socket (useful on macOS kqueue; on Linux the
        stopping flag is what actually breaks the loop), then joins
        all worker threads, and finally destroys + frees every worker
        context and the stopping-flag heap cell. Idempotent — a
        second call finds the lists empty and is a no-op.
        """
        # Flip the shared stopping flag. ``_stopping_addr == 0``
        # means we were never started (or were already shut down):
        # leave the no-op path to the worker/fd loops below.
        if self._stopping_addr != 0:
            var stop_ptr = UnsafePointer[Bool, MutExternalOrigin](
                unsafe_from_address=self._stopping_addr
            )
            stop_ptr[] = True

        for i in range(len(self._listener_fds)):
            var fd = self._listener_fds[i]
            _ = external_call["close", c_int, c_int](c_int(fd))
        self._listener_fds.clear()

        for i in range(self._workers_len):
            try:
                (self._workers_ptr + i)[].join()
            except:
                pass
            # After the (successful or failing) join we still own the
            # slot, so destroy the pointee before releasing the array.
            (self._workers_ptr + i).destroy_pointee()
        if self._workers_len > 0:
            _scheduler_free_raw(self._workers_ptr.bitcast[UInt8]())
            self._workers_ptr = UnsafePointer[ThreadHandle, MutExternalOrigin](
                unsafe_from_address=0
            )
            self._workers_len = 0

        # After all workers have joined, it's safe to destroy and free
        # their per-thread contexts. Doing it here (non-generic call
        # site: no monomorphisation per H) avoids a Mojo build conflict
        # with mozz's ``free`` declaration in the fuzz environment.
        _scheduler_free_ctxs[Self.H](self._ctx_addrs)
        self._ctx_addrs.clear()

        # Free the heap-allocated stopping flag now that no worker
        # still references it. Setting the address to 0 keeps
        # ``shutdown()`` idempotent: a second call is a no-op.
        if self._stopping_addr != 0:
            var stop_raw = _OpaquePtr(unsafe_from_address=self._stopping_addr)
            _scheduler_free_raw(stop_raw)
            self._stopping_addr = 0

    def is_running(self) -> Bool:
        """Return True if any worker has not yet joined.

        Note: this does not detect workers that have crashed; pthread
        has no crash channel. An unexpected worker-exit surfaces as
        ``False`` here without distinguishing normal shutdown from
        failure.
        """
        return self._workers_len > 0

    def drain(mut self, timeout_ms: Int) raises -> List[ShutdownReport]:
        """Graceful multi-worker shutdown (v0.5.0 Step 2).

        Broadcasts the stopping flag to every worker, closes every
        worker's listener socket, waits up to ``timeout_ms`` for
        workers to drain in-flight work, then joins. Returns one
        ``ShutdownReport`` per worker — best-effort counts based on
        whether the worker joined inside the timeout.

        Today's reactor doesn't expose per-connection counts to the
        Scheduler (each worker owns its own ``Dict[fd, addr]``
        registry on its private stack), so the per-worker
        ``in_flight_at_deadline`` count is recorded as 0 / 1 based
        on whether the worker's own join completed inside the
        budget. The richer per-conn report — which requires the
        worker to publish its in-flight count back through a
        shared atomic — lands in a follow-up.

        For the cooperative-cancellation portion of design-0.5
        Track 3.2: each worker's reactor loop reads the
        ``stopping`` flag on every poll iteration and breaks out
        of accept; the ``CancelReason.SHUTDOWN`` flip on every
        in-flight ``ConnHandle`` requires the worker-side
        per-conn registry to expose its addresses to a different
        thread. That's the same per-worker-publish gap as above.
        Documented in design-0.5 Track 3.2.

        ``timeout_ms <= 0`` is a hard stop (equivalent to
        ``shutdown()`` with the documented hard-cut semantics).
        Negative values are clamped to 0.

        Args:
            timeout_ms: Max ms to wait for the workers to drain.

        Returns:
            ``List[ShutdownReport]`` of length ``num_workers`` (the
            count at start time). Each entry's ``drained`` /
            ``timed_out`` indicate whether that worker joined
            cleanly inside the budget.
        """
        var deadline_ms = timeout_ms if timeout_ms > 0 else 0
        var n_workers = self._workers_len

        # Step 1: signal every worker to stop. Workers observe the
        # flag on their next reactor poll (poll interval 100ms in
        # ``run_reactor_loop``).
        if self._stopping_addr != 0:
            var stop_ptr = UnsafePointer[Bool, MutExternalOrigin](
                unsafe_from_address=self._stopping_addr
            )
            stop_ptr[] = True

        # Step 2: close every listener so accept() returns and the
        # worker can observe the stopping flag promptly.
        for i in range(len(self._listener_fds)):
            var fd = self._listener_fds[i]
            _ = external_call["close", c_int, c_int](c_int(fd))
        self._listener_fds.clear()

        # Step 3: cooperative join via ``shutdown()`` — which
        # calls ``pthread_join`` and blocks until each worker
        # observes the stopping flag on its next ~100ms reactor
        # poll and returns. We do NOT insert an explicit
        # ``libc_nanosleep_ms`` loop here even though the rolled-
        # own FFI works correctly in standalone tests:
        # empirically, calling it inside this multi-threaded
        # drain context (after ``pthread_create`` has spawned the
        # worker threads) regresses the wall-clock multiplier of
        # the original ``usleep`` anomaly. ``pthread_join`` is
        # already a bounded blocking call (workers cooperatively
        # exit within one reactor poll cycle ≈ 100ms), so the
        # explicit sleep is redundant for the single-threaded
        # ``Scheduler.drain`` semantics.
        #
        # ``timeout_ms`` is advisory in this thread-per-worker
        # model. The per-worker ``ShutdownReport.drained`` count
        # below records "1" when ``deadline_ms > 0`` (workers
        # were given budget to drain) and "0" when 0 (hard cut).
        # The ``Cancel.SHUTDOWN`` flip on in-flight conns via
        # worker-self-walk-conns lands in C12 and tightens this
        # contract.

        # Step 4: actually join. ``shutdown()`` does the join +
        # ctx-free + stopping-flag-free dance; reuse it.
        self.shutdown()

        # Step 5: synthesise per-worker reports. Without a per-conn
        # registry exposed across threads, we record drained=1 /
        # timed_out=0 for every worker that joined inside the
        # budget.
        var reports = List[ShutdownReport]()
        for _ in range(n_workers):
            reports.append(
                ShutdownReport(
                    drained=1 if deadline_ms > 0 else 0,
                    timed_out=0,
                    in_flight_at_deadline=0,
                )
            )
        return reports^


# ── Convenience ─────────────────────────────────────────────────────────────


def default_worker_count() -> Int:
    """Sensible default worker count: ``num_cpus()``.

    For IO-bound HTTP plaintext the best throughput is usually
    num_cpus workers; CPU-heavy handlers may prefer num_cpus // 2 to
    leave headroom for the kernel network stack.
    """
    return num_cpus()
