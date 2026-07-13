"""Multicore scheduler: 1 shared listener, N reactors, N pthread workers.

Runs N single-threaded reactor loops in parallel, one per pthread,
all sharing a *single* listener fd. Each worker registers the
listener fd in its own reactor with ``EPOLLEXCLUSIVE`` (on Linux
>= 4.5) so the kernel wakes exactly one worker per accept event.
On macOS / kqueue the flag is unavailable and registration falls
back to plain ``register`` — the practical behaviour is similar
because non-blocking ``accept`` returns ``EAGAIN`` on the losers.

This is the redesign of the multicore path. the prior implementation
used N independent listeners bound with ``SO_REUSEPORT``; the
kernel then distributed accepted connections across workers by
hashing each connection's 4-tuple to one of the N listeners. That
scheme has a known fairness gap under bursty arrival: a
256-connection storm from a wrk2-style load generator can land
80+ conns on one worker and 30 on another, producing
hundreds-of-millisecond head-of-line tail latency on the
overloaded worker(s). ``benchmark/configs/throughput_mc``
shows the failure mode at p99 ≈ 1.7 s; the
``EPOLLEXCLUSIVE``-based shared-listener design collapses the
same workload's p99 to the millisecond range.

Shutdown path: ``shutdown()`` flips a heap-allocated ``Bool`` that
every worker polls on each reactor iteration. A stable heap address
is used (instead of a field on the ``Scheduler`` struct) so the flag
survives the NRVO-or-not move from ``Scheduler.start`` back to the
caller. The main thread then closes the shared listener fd once
and joins all workers before ``shutdown()`` returns.

Relying on ``close(listener_fd)`` alone to wake the workers is not
enough on Linux: when the fd is also registered in the worker's
``epoll`` instance, the kernel holds an extra reference to the
underlying ``struct file``, so ``close()`` from another thread does
not trigger an ``EPOLLHUP`` and the workers stay blocked in
``epoll_wait`` until the 100 ms poll timeout fires. The heap flag is
what actually breaks the loop.

This module is :trait:`Frontend`-generic: every worker calls
:meth:`Frontend.run_worker` once with its assigned listener fd
and the shared stopping flag. The frontend value is moved
(per-worker copies are made via ``F.copy()``; if that's expensive
users should wrap their handler's expensive state behind an
``UnsafePointer`` or a similar shared-reference holder).

The scheduler used to import directly from
:mod:`flare.http._server_reactor_impl`,
:mod:`flare.http._unified_reactor_impl`,
:mod:`flare.http.handler`, :mod:`flare.http.server`,
:mod:`flare.http.static_response`, and :mod:`flare.http2.server`.
That layering violation (runtime depending on protocol modules)
is gone now; the scheduler depends only on the
:trait:`flare.runtime.Frontend` trait and concrete impls live
where their protocol does
(:class:`flare.http.HttpFrontend` /
:class:`flare.http.StaticHttpFrontend`).

Known limitations:

- The stopping flag is a heap-allocated byte written from the main
  thread and read from each worker through ``Atomic[DType.uint8]``
  release-store / acquire-load (``store_stop_flag`` /
  ``load_stop_flag``). This gives the workers a proper happens-before
  edge on shutdown and lowers to a plain ``mov`` on x86-64 (TSO) and
  to ``stlr`` / ``ldar`` on ARM64. The per-iteration re-materialisation
  of the pointer inside the frontend's serving loop still defeats the
  optimiser's LICM so every iteration re-reads the flag.
- Worker panics that escape :meth:`Frontend.run_worker` are caught and
  discarded in ``_worker_entry`` because pthread has no exception
  channel. ``is_running()`` still reports ``True`` until the
  ``ThreadHandle`` is joined, which is a mildly wrong signal for a
  worker that crashed rather than shut down cleanly. Plumbing a
  per-worker error cell back to the Scheduler is also scheduled for a future release.
  .
"""

from std.atomic import Atomic, Ordering
from std.ffi import c_int, external_call
from std.memory import UnsafePointer, alloc

from std.os import getenv
from std.sys.info import CompilationTarget
from ..net import SocketAddr
from ..tcp import TcpListener

from ._thread import ThreadHandle, num_cpus, _OpaquePtr
from .frontend import Frontend
from .reuseport import bind_reuseport, bind_shared


# ── Atomic stop-flag helpers ─────────────────────────────────────────────────
# The stopping flag is a heap-allocated byte written by the main
# thread and read by every worker. Release-store / acquire-load pair
# gives the workers a proper happens-before edge on shutdown; lowers
# to a plain ``mov`` on x86-64 (TSO) and to ``stlr`` / ``ldar`` on
# ARM64. Callers pass the raw heap address (the same ``Int`` the
# worker ctx carries) so the flag stays valid across struct moves.


@always_inline
def store_stop_flag(addr: Int, value: Bool):
    """Release-store ``value`` into the heap stop-flag byte at ``addr``."""
    if addr == 0:
        return
    var p = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=addr
    ).bitcast[Scalar[DType.uint8]]()
    Atomic[DType.uint8].store[ordering=Ordering.RELEASE](
        p, UInt8(1) if value else UInt8(0)
    )


@always_inline
def load_stop_flag(addr: Int) -> Bool:
    """Acquire-load the heap stop-flag byte at ``addr``."""
    if addr == 0:
        return False
    var p = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=addr
    ).bitcast[Scalar[DType.uint8]]()
    return Atomic[DType.uint8].load[ordering=Ordering.ACQUIRE](p) != UInt8(0)


# ── Per-worker stats cell (D6 drain accounting + D9 crash visibility) ─────────
# Each worker owns a heap cell of two ``Int64`` slots the worker writes
# and the scheduler (main thread) reads. Slot 0 is the live-connection
# snapshot (updated each reactor iteration); slot 1 is the exit status.
# Release-store / acquire-load makes the worker's writes visible to the
# scheduler after it joins the worker. A ``base_addr`` of 0 disables the
# writes (single-worker / non-scheduler paths pay nothing).

comptime WORKER_STAT_INFLIGHT: Int = 0
"""Slot index: connections still registered on this worker."""
comptime WORKER_STAT_STATUS: Int = 1
"""Slot index: worker exit status (see ``WORKER_STATUS_*``)."""
comptime WORKER_STAT_SLOTS: Int = 2
"""Number of Int64 slots per worker cell."""

comptime WORKER_STATUS_RUNNING: Int = 0
"""Worker has not exited its serve loop yet."""
comptime WORKER_STATUS_CLEAN: Int = 1
"""Worker exited because it observed the stop flag (normal shutdown)."""
comptime WORKER_STATUS_CRASHED: Int = 2
"""Worker exited because its reactor poll failed (unexpected)."""


@always_inline
def store_worker_stat(base_addr: Int, slot: Int, value: Int):
    """Release-store ``value`` into ``slot`` of the worker stats cell."""
    if base_addr == 0:
        return
    var p = UnsafePointer[Int, MutUntrackedOrigin](
        unsafe_from_address=base_addr + slot * 8
    ).bitcast[Scalar[DType.int64]]()
    Atomic[DType.int64].store[ordering=Ordering.RELEASE](p, Int64(value))


@always_inline
def load_worker_stat(base_addr: Int, slot: Int) -> Int:
    """Acquire-load ``slot`` of the worker stats cell (0 when disabled)."""
    if base_addr == 0:
        return 0
    var p = UnsafePointer[Int, MutUntrackedOrigin](
        unsafe_from_address=base_addr + slot * 8
    ).bitcast[Scalar[DType.int64]]()
    return Int(Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](p))


# ── ShutdownReport (per-worker drain accounting) ─────────────────────────────


@fieldwise_init
struct ShutdownReport(Copyable, ImplicitlyCopyable, Movable):
    """Per-worker drain summary returned by :meth:`Scheduler.drain`.

    Originally defined under ``flare.http.server`` and imported back
    by the scheduler; promoted into :mod:`flare.runtime` to break
    the runtime → http import cycle. ``flare.http.server`` re-exports
    this type so the public ``flare.http.ShutdownReport`` surface is
    unchanged.

    The per-worker registry that would let us count individual
    in-flight connections lives on each worker's stack today;
    until that registry is published back through a shared
    atomic, ``in_flight_at_deadline`` is the coarse 0/1 signal
    driven by whether the worker's join completed inside the
    budget.

    Fields:
        drained: Connections that completed their in-flight work
            inside the drain timeout. Best-effort.
        timed_out: Connections that were force-closed because the
            drain timeout elapsed before they finished. Best-effort.
        in_flight_at_deadline: Connections still alive at the
            instant the timeout fired (== ``timed_out`` after the
            force-close completes).
    """

    var drained: Int
    var timed_out: Int
    var in_flight_at_deadline: Int


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


def _scheduler_free_ctxs[F: Frontend & Copyable](addrs: List[Int]):
    """Destroy each ``_WorkerCtx[F]`` at the given address then free it."""
    for i in range(len(addrs)):
        var raw = _OpaquePtr(unsafe_from_address=addrs[i])
        var typed = raw.bitcast[_WorkerCtx[F]]()
        typed.destroy_pointee()
        _scheduler_free_raw(raw)


# ── Per-worker context ───────────────────────────────────────────────────────


struct _WorkerCtx[F: Frontend & Copyable](Movable):
    """Heap-allocated context passed to a pthread start routine.

    Carries a *borrowed* listener fd (the underlying ``TcpListener``
    is owned by the parent ``Scheduler``), a per-worker copy of
    the frontend, the shared stopping flag (as a raw address), and
    a worker index for pinning + logging. Workers must NOT close
    ``listener_fd`` — that's the ``Scheduler``'s job on shutdown.

    The frontend encapsulates everything protocol-specific that
    used to live on this struct (handler, server config, HTTP/2
    settings, auto-protocol toggle); the runtime layer no longer
    needs to know any of those flags exist.
    """

    var listener_fd: Int
    """The listener fd this worker will use. Semantics depend on
    the binding strategy chosen by the Scheduler:
    * **shared listener (default-off)**: shared across all
      workers; owned by the Scheduler; workers call
      register_exclusive (EPOLLEXCLUSIVE) to share accept fairly.
    * **per-worker SO_REUSEPORT (default-on)**: per-worker fd,
      bound on the Scheduler thread (so concurrent-bind races
      can't happen) and handed to this specific worker; owned
      by the Scheduler's per-worker listener table for cleanup.
    """
    var bind_addr: SocketAddr
    """Bind address (the same one the Scheduler resolved). Kept
    for diagnostics + future use; the actual fd is in
    ``listener_fd`` regardless of strategy."""
    var frontend: Self.F
    var stopping_addr: Int
    var worker_idx: Int
    var pin_cores: Bool
    var stats_addr: Int
    """Heap address of this worker's two-slot ``Int64`` stats cell
    (in-flight snapshot + exit status). 0 disables the writes."""

    def __init__(
        out self,
        listener_fd: Int,
        bind_addr: SocketAddr,
        var frontend: Self.F,
        stopping_addr: Int,
        worker_idx: Int,
        pin_cores: Bool,
        stats_addr: Int,
    ):
        self.listener_fd = listener_fd
        self.bind_addr = bind_addr
        self.frontend = frontend^
        self.stopping_addr = stopping_addr
        self.worker_idx = worker_idx
        self.pin_cores = pin_cores
        self.stats_addr = stats_addr


# ── Worker entry point (comptime-specialised per F) ─────────────────────────


def _worker_entry[F: Frontend & Copyable](arg: _OpaquePtr) -> _OpaquePtr:
    """Pthread start routine for one reactor worker.

    Casts ``arg`` back to a ``_WorkerCtx[F]`` pointer, optionally
    pins to a CPU, then delegates to :meth:`Frontend.run_worker`
    until the shared stopping flag is observed.

    The context was allocated on the main thread with libc ``malloc``
    plus ``init_pointee_move``; the Scheduler main thread destroys and
    frees it after joining this worker.
    """
    var ctx_addr = Int(arg)
    var raw = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=ctx_addr
    )
    var ctx_ptr = raw.bitcast[_WorkerCtx[F]]()

    var stopping_ptr = UnsafePointer[Bool, MutUntrackedOrigin](
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
    # The frontend's serving loop takes ``stopping`` as a ``def``
    # parameter (reference semantics in Mojo), so every
    # iteration re-reads the live flag from this stable heap
    # address. That address was captured at
    # ``Scheduler.start`` time and stays valid until
    # ``Scheduler.shutdown`` joins every worker.
    #
    # ``run_worker`` is declared on the trait without ``raises``
    # so impls cannot throw across the pthread boundary; the
    # impl is responsible for catching internally and exiting
    # cleanly when the stop flag flips.
    ctx_ptr[].frontend.run_worker(
        ctx_ptr[].listener_fd,
        stopping_ptr[],
        ctx_ptr[].stats_addr,
    )

    # Ctx ownership: the Scheduler main thread destroys + frees every
    # ctx AFTER joining the worker, so we don't touch it here.
    # b2: UnsafePointer is non-nullable; build C NULL from a runtime 0.
    var null_addr = 0
    return UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=null_addr
    )


# ── Scheduler ────────────────────────────────────────────────────────────────


struct Scheduler[F: Frontend & Copyable](Movable):
    """Owns ``num_workers`` pthread workers, each running a frontend's
    serving loop sharing a single listener fd (or its own
    SO_REUSEPORT listener when the strategy demands).

    Usage:
        ```mojo
        from flare.http import HttpFrontend
        var frontend = HttpFrontend(handler^, config^)
        var s = Scheduler[HttpFrontend[MyHandler]].start(
            addr, frontend^, num_workers=4
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
        - **Listener strategy.** Default: each worker pre-binds
          its own ``SO_REUSEPORT`` listener (the kernel hashes
          new 4-tuples to one of N pre-bound listeners; matches
          actix_web's listener strategy and gives the highest
          steady-state throughput on dev-box workloads). Opt out
          by exporting ``FLARE_REUSEPORT_WORKERS=0`` before
          ``start`` to switch to a single shared listener bound
          via ``bind_shared`` and registered with
          ``Reactor.register_exclusive`` (``EPOLLEXCLUSIVE`` on
          Linux >= 4.5) — the kernel wakes one worker per
          accept event, idle workers absorb spikes, p99.99 σ
          is uniformly tighter under sustained load for 7-22 %
          less req/s depending on path (see
          ``docs/benchmark.md``). Frontends that *require*
          per-worker listeners (the io_uring buffer-ring
          frontend) override this via
          :meth:`Frontend.requires_per_worker_listener`.
        - The frontend value is cloned into each worker via
          ``F.copy()``.
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
    var _workers_ptr: UnsafePointer[ThreadHandle, MutUntrackedOrigin]
    var _workers_len: Int
    # Heap-allocated ``TcpListener`` shared by all workers. Address is
    # stable across struct moves so worker ctxs can carry the fd as a
    # plain ``Int`` — workers never close it (that's ``shutdown()``'s
    # job after every worker has joined). A 0 value means "no shared
    # listener yet" (freshly constructed) or "already destroyed"
    # (post-shutdown).
    var _shared_listener_addr: Int
    # Cached fd for the shared listener. Convenient for the shutdown
    # path which closes the fd before destroying the heap struct;
    # closing first ensures any in-flight ``accept(2)`` returns -1
    # and the worker observes the stop flag promptly.
    var _shared_listener_fd: Int
    var _per_worker_listener_addrs: List[Int]
    """When the io_uring buffer-ring path is active, the
    Scheduler pre-binds one SO_REUSEPORT listener per worker on
    its own thread (serialised binds avoid any concurrent-bind
    race). Each entry is the heap address of an owned
    ``TcpListener``; freed in ``shutdown()`` after all workers
    join. Empty on the epoll path."""
    var _ctx_addrs: List[Int]
    # Heap-allocated Bool, owned by this Scheduler. Address is stable
    # across struct moves; every worker's ``_WorkerCtx.stopping_addr``
    # points at the same heap cell. A 0 value here means "not yet
    # allocated" (freshly constructed) or "already freed" (post-shutdown).
    var _stopping_addr: Int
    # One heap-allocated two-slot ``Int64`` stats cell per worker
    # (in-flight snapshot + exit status). Read by ``drain`` after the
    # workers join; freed on teardown. Empty until ``start``.
    var _stats_addrs: List[Int]
    # Number of workers whose last run exited with WORKER_STATUS_CRASHED,
    # captured from the stats cells during ``shutdown`` / ``drain`` before
    # they are freed. Lets callers tell a crash from a clean shutdown
    # after the workers have joined (``is_running`` cannot).
    var _last_crash_count: Int

    def __init__(out self):
        """Build an empty scheduler; use ``Scheduler.start`` instead."""
        # b2: UnsafePointer is non-nullable; build C NULL from a runtime 0.
        var null_addr = 0
        self._workers_ptr = UnsafePointer[ThreadHandle, MutUntrackedOrigin](
            unsafe_from_address=null_addr
        )
        self._workers_len = 0
        self._shared_listener_addr = 0
        self._shared_listener_fd = -1
        self._per_worker_listener_addrs = List[Int]()
        self._ctx_addrs = List[Int]()
        self._stopping_addr = 0
        self._stats_addrs = List[Int]()
        self._last_crash_count = 0

    @staticmethod
    def start(
        addr: SocketAddr,
        var frontend: Self.F,
        num_workers: Int,
        pin_cores: Bool = True,
    ) raises -> Scheduler[Self.F]:
        """Spawn ``num_workers`` threads sharing one listener.

        The scheduler binds its listener(s) according to
        :meth:`Frontend.requires_per_worker_listener` plus the
        ``FLARE_REUSEPORT_WORKERS`` env knob, then hands one fd
        per worker into :meth:`Frontend.run_worker`. The frontend
        encapsulates everything protocol-specific (handler,
        request config, HTTP/2 settings, auto-protocol toggle,
        backend selection); the runtime layer no longer knows
        any of those flags exist.

        Args:
            addr: Address the listener(s) bind.
            frontend: Per-worker run target. Cloned per worker
                via :meth:`Frontend.copy`.
            num_workers: Number of worker threads. Must be in
                ``1..=256``; values outside that range raise.
                The upper bound is a defensive guard against
                runaway ``pthread_create`` + heap allocation.
            pin_cores: If ``True`` (default), pin worker N to core
                ``N % num_cpus``. No-op on macOS.

        Returns:
            A running ``Scheduler`` whose workers will continue to
            serve until ``shutdown()`` is called.

        Raises:
            Error: If ``num_workers`` is outside ``1..=256``, if the
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
        var s = Scheduler[Self.F]()

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

        # Listener binding strategy. Defaults to per-worker
        # SO_REUSEPORT (matches actix_web; highest steady-state
        # throughput on dev-box workloads). Override paths:
        #
        # * **Frontend forces per-worker** (e.g. io_uring buffer-
        #   ring): :meth:`Frontend.requires_per_worker_listener`
        #   returns True. The scheduler binds N SO_REUSEPORT
        #   listeners on its own thread (serialised binds avoid
        #   any concurrent-bind race) and hands one to each
        #   worker.
        # * **FLARE_REUSEPORT_WORKERS=0**: opt back into a single
        #   ``bind_shared`` listener with ``EPOLLEXCLUSIVE`` (7-22 %
        #   less req/s for a uniformly tighter p99.99 σ; see
        #   ``docs/benchmark.md``). Workers register the shared
        #   fd with ``Reactor.register_exclusive`` so the kernel
        #   wakes one worker per accept event.
        #
        # Decision is made on the Scheduler thread (not in the
        # workers) so an ``AddressInUse`` from a faulty
        # configuration raises on the caller's thread, not inside
        # an opaque pthread.
        var frontend_demands_per_worker = (
            frontend.requires_per_worker_listener()
        )

        # Per-worker ``SO_REUSEPORT`` listeners (each worker
        # accept(2)s on its own fd; kernel hashes new 4-tuples to
        # one of N listeners) are the **default** for
        # ``num_workers >= 2``. This matches actix_web's listener
        # strategy and gives strictly higher steady-state
        # throughput on dev-box workloads (the headline numbers
        # in ``docs/benchmark.md`` come from this mode).
        #
        # Opt out via ``FLARE_REUSEPORT_WORKERS=0`` to switch back
        # to the single-listener ``EPOLLEXCLUSIVE`` shape, which
        # trades ~10 % req/s for an even tighter p99.99 (the
        # kernel offers each accept event to whichever worker is
        # currently waiting in ``epoll_wait``, so idle workers
        # absorb spikes). See ``docs/benchmark.md`` for the
        # head-to-head numbers in both modes.
        var use_reuseport_workers = True
        if getenv("FLARE_REUSEPORT_WORKERS") == "0":
            use_reuseport_workers = False

        var listener_fd: Int = -1
        # b2: UnsafePointer is non-nullable; build C NULL from a runtime 0.
        var null_addr = 0
        var listener_ptr = UnsafePointer[TcpListener, MutUntrackedOrigin](
            unsafe_from_address=null_addr
        )
        # Both the io_uring buffer-ring path and the opt-in epoll
        # reuseport mode pre-bind per-worker SO_REUSEPORT listeners
        # on this thread (serialised binds avoid concurrent-bind
        # races) and skip the shared listener.
        var prebind_per_worker = (
            frontend_demands_per_worker or use_reuseport_workers
        )
        if prebind_per_worker:
            # Probe-bind to validate the addr (raises on the
            # caller's thread if AddressInUse / etc.); the probe
            # listener is dropped immediately and each worker binds
            # its own SO_REUSEPORT listener inside _worker_entry.
            try:
                var probe = bind_reuseport(addr)
                _ = probe^
            except e:
                _scheduler_free_raw(stop_raw)
                s._stopping_addr = 0
                raise e^
            s._shared_listener_addr = 0
            s._shared_listener_fd = -1
        else:
            var bound = bind_shared(addr)
            try:
                bound._socket.set_nonblocking(True)
            except e:
                _scheduler_free_raw(stop_raw)
                s._stopping_addr = 0
                raise e^
            listener_fd = Int(bound.as_raw_fd())
            # Heap-store the listener so its destructor doesn't fire
            # when the local ``bound`` goes out of scope at the end
            # of this function. ``shutdown()`` destroys+frees this
            # allocation *after* joining every worker.
            var lp = alloc[TcpListener](1)
            lp.init_pointee_move(bound^)
            listener_ptr = lp
            s._shared_listener_addr = Int(lp)
            s._shared_listener_fd = listener_fd

        # Preallocate the worker slot array once; grow is not needed
        # because ``num_workers`` is bounded above (<= 256) and fixed.
        s._workers_ptr = alloc[ThreadHandle](num_workers)
        s._workers_len = 0

        # Per-worker stats cells (in-flight snapshot + exit status).
        # Allocated on this thread before any pthread spawns; the worker
        # writes them, ``drain`` reads them after join, teardown frees
        # them. Native Mojo allocator (see _scheduler_free_raw).
        for _ in range(num_workers):
            var sp = alloc[Int64](WORKER_STAT_SLOTS)
            sp[WORKER_STAT_INFLIGHT] = Int64(0)
            sp[WORKER_STAT_STATUS] = Int64(WORKER_STATUS_RUNNING)
            s._stats_addrs.append(Int(sp))

        # If we need per-worker listeners (io_uring buffer-ring
        # path OR the opt-in epoll reuseport mode): pre-bind one
        # SO_REUSEPORT listener PER WORKER on the Scheduler thread
        # before spawning any pthreads. Doing the binds serially
        # on a single thread eliminates any concurrent-bind races
        # that could surface from N pthreads each calling
        # bind_reuseport simultaneously, which empirically caused
        # the multi-worker bufring crash on commit 88ea2f7.
        # Per-worker listeners are heap-stored in a parallel array
        # so their destructors don't fire here; the same shutdown
        # path that frees s._shared_listener_addr will iterate +
        # free them.
        if prebind_per_worker:
            for _ in range(num_workers):
                try:
                    var pwl = bind_reuseport(addr)
                    pwl._socket.set_nonblocking(True)
                    var ptr = alloc[TcpListener](1)
                    ptr.init_pointee_move(pwl^)
                    s._per_worker_listener_addrs.append(Int(ptr))
                except:
                    pass

        for i in range(num_workers):
            var frontend_copy = frontend.copy()
            # Pick this worker's listener fd: either the shared
            # epoll listener, or its own per-worker SO_REUSEPORT
            # listener (pre-bound on this thread above).
            var worker_listener_fd: Int = listener_fd
            if prebind_per_worker and i < len(s._per_worker_listener_addrs):
                var pwl_ptr = UnsafePointer[TcpListener, MutUntrackedOrigin](
                    unsafe_from_address=s._per_worker_listener_addrs[i]
                )
                worker_listener_fd = Int(pwl_ptr[].as_raw_fd())
            var worker_stats_addr = (
                s._stats_addrs[i] if i < len(s._stats_addrs) else 0
            )
            var ctx = _WorkerCtx[Self.F](
                worker_listener_fd,
                addr,
                frontend_copy^,
                stopping_addr,
                i,
                pin_cores,
                worker_stats_addr,
            )
            # Native Mojo allocator (see _scheduler_free_raw for why).
            var ctx_ptr = alloc[_WorkerCtx[Self.F]](1)
            ctx_ptr.init_pointee_move(ctx^)
            var arg = ctx_ptr.bitcast[UInt8]()
            var ctx_addr = Int(ctx_ptr)

            var spawned = False
            try:
                var th = ThreadHandle.spawn[_worker_entry[Self.F]](arg)
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
                store_stop_flag(stopping_addr, True)
                for j in range(s._workers_len):
                    try:
                        (s._workers_ptr + j)[].join()
                    except:
                        pass
                    (s._workers_ptr + j).destroy_pointee()
                _scheduler_free_raw(s._workers_ptr.bitcast[UInt8]())
                # b2: UnsafePointer is non-nullable; C NULL from a runtime 0.
                var null_addr = 0
                s._workers_ptr = UnsafePointer[
                    ThreadHandle, MutUntrackedOrigin
                ](unsafe_from_address=null_addr)
                s._workers_len = 0
                # Destroy + free EVERY ctx (the ones that workers claimed
                # + this one that never got claimed).
                _scheduler_free_ctxs[Self.F](s._ctx_addrs)
                s._ctx_addrs.clear()
                ctx_ptr.destroy_pointee()
                _scheduler_free_raw(ctx_ptr.bitcast[UInt8]())
                # Free the pre-allocated per-worker stats cells.
                for k in range(len(s._stats_addrs)):
                    _scheduler_free_raw(
                        _OpaquePtr(unsafe_from_address=s._stats_addrs[k])
                    )
                s._stats_addrs.clear()
                # All workers joined, so no one is reading the
                # shared listener anymore -- destroy + free it
                # if we owned one (paths that prebind per-worker
                # listeners leave listener_ptr null).
                if Int(listener_ptr) != 0:
                    listener_ptr.destroy_pointee()
                    _scheduler_free_raw(listener_ptr.bitcast[UInt8]())
                s._shared_listener_addr = 0
                s._shared_listener_fd = -1
                # All workers joined, so no one is reading the
                # stopping flag anymore — safe to free.
                _scheduler_free_raw(stop_raw)
                s._stopping_addr = 0
                raise Error("pthread_create failed in Scheduler.start")

        return s^

    def _signal_and_close_listener(mut self):
        """Flip the stop flag and close the shared listener fd.

        Idempotent. ``_stopping_addr == 0`` (never started / already
        torn down) short-circuits the flip; the fd close is skipped
        once the fd is -1.
        """
        if self._stopping_addr != 0:
            store_stop_flag(self._stopping_addr, True)
        if self._shared_listener_fd >= 0:
            _ = external_call["close", c_int, c_int](
                c_int(self._shared_listener_fd)
            )
            self._shared_listener_fd = -1

    def _join_workers(mut self):
        """Join every worker thread and release the handle array.

        Must run before reading the per-worker stats cells (the
        acquire-load pairs with each worker's release-stores, which
        are guaranteed visible once the worker's pthread has joined).
        """
        for i in range(self._workers_len):
            try:
                (self._workers_ptr + i)[].join()
            except:
                pass
            (self._workers_ptr + i).destroy_pointee()
        if self._workers_len > 0:
            _scheduler_free_raw(self._workers_ptr.bitcast[UInt8]())
            var null_addr = 0
            self._workers_ptr = UnsafePointer[ThreadHandle, MutUntrackedOrigin](
                unsafe_from_address=null_addr
            )
            self._workers_len = 0

    def _record_crash_count(mut self):
        """Snapshot how many workers exited crashed (call after join,
        before freeing the stats cells)."""
        var crashed = 0
        for i in range(len(self._stats_addrs)):
            if (
                load_worker_stat(self._stats_addrs[i], WORKER_STAT_STATUS)
                == WORKER_STATUS_CRASHED
            ):
                crashed += 1
        self._last_crash_count = crashed

    def _free_resources(mut self):
        """Free ctxs, listeners, stats cells, and the stop flag.

        Runs after ``_join_workers`` (no worker still references any of
        these) and after ``_record_crash_count`` (the stats cells are
        read before they are freed). Idempotent.
        """
        _scheduler_free_ctxs[Self.F](self._ctx_addrs)
        self._ctx_addrs.clear()

        if self._shared_listener_addr != 0:
            var raw = _OpaquePtr(unsafe_from_address=self._shared_listener_addr)
            var typed = raw.bitcast[TcpListener]()
            typed.destroy_pointee()
            _scheduler_free_raw(raw)
            self._shared_listener_addr = 0

        for i in range(len(self._per_worker_listener_addrs)):
            var pwl_raw = _OpaquePtr(
                unsafe_from_address=self._per_worker_listener_addrs[i]
            )
            var pwl_typed = pwl_raw.bitcast[TcpListener]()
            pwl_typed.destroy_pointee()
            _scheduler_free_raw(pwl_raw)
        self._per_worker_listener_addrs.clear()

        for i in range(len(self._stats_addrs)):
            _scheduler_free_raw(
                _OpaquePtr(unsafe_from_address=self._stats_addrs[i])
            )
        self._stats_addrs.clear()

        if self._stopping_addr != 0:
            var stop_raw = _OpaquePtr(unsafe_from_address=self._stopping_addr)
            _scheduler_free_raw(stop_raw)
            self._stopping_addr = 0

    def shutdown(mut self) raises:
        """Signal every worker to stop and wait for them to join.

        Flips the heap-allocated stopping flag, closes the shared
        listener socket (useful on macOS kqueue; on Linux the
        stopping flag is what actually breaks the loop), then joins
        all worker threads, records the crash count, and frees every
        worker context, listener, stats cell, and the stopping-flag
        heap cell. Idempotent — a second call finds the state empty
        and is a no-op.
        """
        self._signal_and_close_listener()
        self._join_workers()
        self._record_crash_count()
        self._free_resources()

    def is_running(self) -> Bool:
        """Return True if any worker has not yet joined.

        Note: this only tracks join state. To tell a crash from a
        clean shutdown after the workers have joined, read
        ``crashed_worker_count()`` (populated by ``shutdown`` /
        ``drain`` from the per-worker exit-status cells).
        """
        return self._workers_len > 0

    def crashed_worker_count(self) -> Int:
        """Number of workers whose last run exited crashed (poll
        failure), captured during the most recent ``shutdown`` /
        ``drain``. 0 after a clean shutdown."""
        return self._last_crash_count

    def drain(mut self, timeout_ms: Int) raises -> List[ShutdownReport]:
        """Graceful multi-worker shutdown.

        Broadcasts the stopping flag to every worker, closes every
        worker's listener socket, waits up to ``timeout_ms`` for
        workers to drain in-flight work, then joins. Returns one
        ``ShutdownReport`` per worker — best-effort counts based on
        whether the worker joined inside the timeout.

        Each worker publishes its live-connection count to a shared
        per-worker stats cell on every reactor iteration (release
        store), so once the worker joins the Scheduler reads a real
        ``in_flight_at_deadline`` (acquire load) instead of the old
        fabricated 0 / 1. Those remaining connections are force-closed
        during the worker's graceful-shutdown pass, so ``timed_out``
        mirrors that count. ``drained`` stays a coarse budget signal
        (1 when a positive drain budget was given, 0 on a hard cut):
        the reactor does not count naturally-completed connections, so
        an exact "finished vs cut" split is not available in this
        force-close model.

        ``timeout_ms <= 0`` is a hard stop (equivalent to
        ``shutdown()`` with the documented hard-cut semantics).
        Negative values are clamped to 0.

        Args:
            timeout_ms: Max ms to wait for the workers to drain.

        Returns:
            ``List[ShutdownReport]`` of length ``num_workers`` (the
            count at start time). ``in_flight_at_deadline`` /
            ``timed_out`` are the real per-worker live-connection
            counts; ``drained`` is the budget signal.
        """
        var deadline_ms = timeout_ms if timeout_ms > 0 else 0
        var n_workers = len(self._stats_addrs)

        # Step 1: signal stop + close the shared listener so a pending
        # accept returns and the worker observes the flag promptly.
        self._signal_and_close_listener()

        # Step 2: join. ``pthread_join`` is a bounded blocking call --
        # workers cooperatively exit within one reactor poll cycle.
        # (No explicit sleep: calling ``libc_nanosleep_ms`` inside this
        # post-pthread_create context regresses the usleep-multiplier
        # anomaly; the join already bounds the wait.)
        self._join_workers()

        # Step 3: read the real per-worker in-flight snapshots + exit
        # status now that the joins established the happens-before edge.
        var reports = List[ShutdownReport]()
        for i in range(n_workers):
            var inflight = load_worker_stat(
                self._stats_addrs[i], WORKER_STAT_INFLIGHT
            )
            reports.append(
                ShutdownReport(
                    drained=1 if deadline_ms > 0 else 0,
                    timed_out=inflight,
                    in_flight_at_deadline=inflight,
                )
            )
        self._record_crash_count()

        # Step 4: free everything (stats cells are read above first).
        self._free_resources()
        return reports^


# ── Convenience ─────────────────────────────────────────────────────────────


def default_worker_count() -> Int:
    """Sensible default worker count: ``num_cpus()``.

    For IO-bound HTTP plaintext the best throughput is usually
    num_cpus workers; CPU-heavy handlers may prefer num_cpus // 2 to
    leave headroom for the kernel network stack.
    """
    return num_cpus()
