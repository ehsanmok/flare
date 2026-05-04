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

This module is ``Handler``-generic: every worker runs the same
``H: Handler`` that the caller passed to ``Scheduler.start``. The
handler value is moved (per-worker copies are made via ``H.copy()``;
if that's expensive users should wrap their handler's expensive state
behind an ``UnsafePointer`` or a similar shared-reference holder).

Only the ``Handler`` and ``ServerConfig`` machinery that already
has is touched; the run loop is ``run_reactor_loop_shared[H]`` from
``flare.http._server_reactor_impl`` (the shared-listener
variant of the prior ``run_reactor_loop``).

Known limitations:

- The stopping flag is a raw ``Bool`` written from the main thread
  and read from each worker, not an atomic. Mojo 0.26.3 stdlib has
  no ``Atomic[Bool]`` / ``Atomic[Int]`` type yet, so we rely on two
  things: (1) aligned single-byte loads and stores being atomic at
  the hardware level on x86-64 and ARM64 with no torn reads;
  (2) the volatile-style ``UnsafePointer[Bool, MutExternalOrigin]``
  materialisation inside ``run_reactor_loop_shared`` defeating
  the optimiser's LICM so every iteration re-reads the flag.
  This is enough in practice on both platforms flare targets,
  but the flag should be upgraded to an ``Atomic`` with explicit
  release/acquire ordering once the stdlib stabilises one.
- Worker panics that escape ``run_reactor_loop_shared`` are caught and
  discarded in ``_worker_entry`` because pthread has no exception
  channel. ``is_running()`` still reports ``True`` until the
  ``ThreadHandle`` is joined, which is a mildly wrong signal for a
  worker that crashed rather than shut down cleanly. Plumbing a
  per-worker error cell back to the Scheduler is also scheduled for a future release.
  .
"""

from std.ffi import c_int, external_call
from std.memory import UnsafePointer, alloc

from ..http.handler import Handler
from ..http.server import ServerConfig, ShutdownReport
from ..http._server_reactor_impl import (
    run_reactor_loop_shared,
    run_reactor_loop_static_shared,
    run_uring_bufring_reactor_loop_shared,
)
from ..http._unified_reactor_impl import run_unified_reactor_loop_shared
from ..http.static_response import StaticResponse
from ..http2.server import Http2Config
from .uring_reactor import use_uring_backend
from std.os import getenv
from std.sys.info import CompilationTarget
from ..net import SocketAddr
from ..tcp import TcpListener

from ._thread import ThreadHandle, num_cpus, _OpaquePtr
from .reuseport import bind_reuseport, bind_shared


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

    Carries a *borrowed* listener fd (the underlying ``TcpListener``
    is owned by the parent ``Scheduler``), a copy of the handler +
    config, the shared stopping flag (as a raw address), and a
    worker index for pinning + logging. Workers must NOT close
    ``listener_fd`` — that's the ``Scheduler``'s job on shutdown.
    """

    var listener_fd: Int
    """The listener fd this worker will use. Semantics depend on
    the backend:
    * **epoll path**: shared across all workers; owned by the
      Scheduler; workers call register_exclusive (EPOLLEXCLUSIVE)
      to share accept fairly.
    * **io_uring buffer-ring path**: per-worker fd, bound via
      SO_REUSEPORT on the Scheduler thread (so concurrent-bind
      races can't happen) and handed to this specific worker;
      owned by the Scheduler's _shared_listener_addr table for
      cleanup. Each worker arms multishot accept on its OWN fd."""
    var bind_addr: SocketAddr
    """Bind address (the same one the Scheduler resolved). Kept
    for diagnostics + future use; the actual fd is in
    ``listener_fd`` regardless of backend now."""
    var config: ServerConfig
    var handler: Self.H
    var stopping_addr: Int
    var worker_idx: Int
    var pin_cores: Bool
    # ``unified``: True -> dispatch to
    # ``flare.http._unified_reactor_impl.run_unified_reactor_loop_shared``
    # (auto HTTP/1.1 + HTTP/2 dispatch via preface peek). False
    # (default) -> use the HTTP/1.1-only legacy
    # ``run_reactor_loop_shared`` and preserve byte-for-byte the
    # behaviour for callers that haven't opted into the unified
    # path.
    var auto_protocol: Bool
    # ``h2_config``: HTTP/2 SETTINGS used by the unified path's
    # ``H2ConnHandle``. Ignored when ``unified`` is False.
    var h2_config: Http2Config

    def __init__(
        out self,
        listener_fd: Int,
        bind_addr: SocketAddr,
        var config: ServerConfig,
        var handler: Self.H,
        stopping_addr: Int,
        worker_idx: Int,
        pin_cores: Bool,
        auto_protocol: Bool,
        var h2_config: Http2Config,
    ):
        self.listener_fd = listener_fd
        self.bind_addr = bind_addr
        self.config = config^
        self.handler = handler^
        self.stopping_addr = stopping_addr
        self.worker_idx = worker_idx
        self.pin_cores = pin_cores
        self.auto_protocol = auto_protocol
        self.h2_config = h2_config^


# ── Worker entry point (comptime-specialised per H) ─────────────────────────


def _worker_entry[H: Handler & Copyable](arg: _OpaquePtr) -> _OpaquePtr:
    """Pthread start routine for one reactor worker.

    Casts ``arg`` back to a ``_WorkerCtx[H]`` pointer, optionally pins
    to a CPU, then runs ``run_reactor_loop_shared[H]`` until the shared
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
        # The shared reactor loop takes ``stopping`` as a ``def``
        # parameter (reference semantics in Mojo), so every
        # iteration re-reads the live flag from this stable heap
        # address. That address was captured at
        # ``Scheduler.start`` time and stays valid until
        # ``Scheduler.shutdown`` joins every worker.
        #
        # Multi-worker buffer-ring path (FLARE_BUFRING_HANDLER=1):
        # opt-in via ``FLARE_BUFRING_HANDLER=1`` (see the
        # HttpServer.serve wire-in for the rationale on why this
        # is opt-in rather than default). Each pthread worker
        # owns its own UringReactor + per-worker recv buffer
        # pool; multishot accept on the shared listener fd
        # distributes new conns to one worker each.
        comptime if CompilationTarget.is_linux():
            if use_uring_backend() and getenv("FLARE_BUFRING_HANDLER") == "1":
                # SO_REUSEPORT per-worker bind: each worker has
                # its OWN pre-bound listener fd (bound on the
                # Scheduler thread before pthread spawn so binds
                # are serialised, avoiding any concurrent-bind
                # race). The fd is passed through
                # ``ctx_ptr[].listener_fd``; the corresponding
                # TcpListener struct is owned by the Scheduler's
                # per_worker_listener_ptrs table and freed on
                # Scheduler.shutdown.
                run_uring_bufring_reactor_loop_shared[H](
                    ctx_ptr[].listener_fd,
                    ctx_ptr[].config,
                    ctx_ptr[].handler,
                    stopping_ptr[],
                )
                return UnsafePointer[UInt8, MutExternalOrigin](
                    unsafe_from_address=0
                )
        # Pick the unified (HTTP/1.1 + HTTP/2 auto-dispatch)
        # reactor loop or the HTTP/1.1-only loop based on what
        # the Scheduler caller requested. The unified path
        # auto-detects the wire protocol per connection by
        # peeking the first 24 bytes for the H2 preface.
        if ctx_ptr[].auto_protocol:
            run_unified_reactor_loop_shared[H](
                ctx_ptr[].listener_fd,
                ctx_ptr[].config,
                ctx_ptr[].h2_config.copy(),
                ctx_ptr[].handler,
                stopping_ptr[],
            )
        else:
            run_reactor_loop_shared[H](
                ctx_ptr[].listener_fd,
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
    loop sharing a single listener fd.

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
        - **Listener strategy.** Default: one listener bound via
          ``bind_shared`` and borrowed by every worker, registered
          with ``Reactor.register_exclusive`` so the kernel wakes
          one worker per accept event (``EPOLLEXCLUSIVE`` on
          Linux >= 4.5). Tightest p99.99 because idle workers
          absorb spikes. Opt in to per-worker ``SO_REUSEPORT``
          listeners by exporting ``FLARE_REUSEPORT_WORKERS=1``
          before ``start`` -- the kernel hashes new 4-tuples to
          one of N pre-bound listeners, ~21 % more req/s for
          ~0.25 ms more p99.99 (see ``docs/benchmark.md``). The
          io_uring buffer-ring path (``FLARE_BUFRING_HANDLER=1``)
          uses per-worker SO_REUSEPORT unconditionally.
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

    def __init__(out self):
        """Build an empty scheduler; use ``Scheduler.start`` instead."""
        self._workers_ptr = UnsafePointer[ThreadHandle, MutExternalOrigin](
            unsafe_from_address=0
        )
        self._workers_len = 0
        self._shared_listener_addr = 0
        self._shared_listener_fd = -1
        self._per_worker_listener_addrs = List[Int]()
        self._ctx_addrs = List[Int]()
        self._stopping_addr = 0

    @staticmethod
    def start(
        addr: SocketAddr,
        var config: ServerConfig,
        var handler: Self.H,
        num_workers: Int,
        pin_cores: Bool = True,
        auto_protocol: Bool = False,
        var h2_config: Http2Config = Http2Config(),
    ) raises -> Scheduler[Self.H]:
        """Spawn ``num_workers`` threads sharing one listener.

        Args (in addition to the existing ones):
            unified: When ``True``, every worker dispatches to
                :func:`flare.http._unified_reactor_impl.run_unified_reactor_loop_shared`
                (auto HTTP/1.1 + HTTP/2 dispatch). When ``False``
                (default), uses the legacy HTTP/1.1-only loop --
                preserves byte-for-byte the v0.6/v0.7 behaviour
                for callers that haven't opted in.
            h2_config: HTTP/2 SETTINGS used by the unified path.
                Ignored when ``unified`` is ``False``.

        redesign: the scheduler binds a single ``TcpListener``
        (via ``bind_shared``) and hands its fd to every worker. Each
        worker registers the fd with ``Reactor.register_exclusive``
        so the kernel wakes only one worker per accept event
        (``EPOLLEXCLUSIVE`` on Linux >= 4.5). On macOS the flag is
        unavailable and the fallback is the classic non-blocking
        accept "wake-all, one-wins" pattern.

        This eliminates the prior ``SO_REUSEPORT`` 4-tuple-hash
        distribution variance that caused multi-second tail latency
        under high-concurrency loads.

        Args:
            addr: Address the shared listener binds.
            config: Shared server config (copied per worker).
            handler: Shared request handler (copied per worker).
            num_workers: Number of worker threads. Must be in
                ``1..=256``; values outside that range raise. The
                upper bound is a defensive guard against runaway
                ``pthread_create`` + heap allocation.
            pin_cores: If ``True`` (default), pin worker N to core
                ``N % num_cpus``. No-op on macOS.

        Returns:
            A running ``Scheduler`` whose workers will continue to
            serve until ``shutdown()`` is called.

        Raises:
            Error: If ``num_workers`` is outside ``1..=256``, if the
                shared listener fails to bind, or if
                ``pthread_create`` fails; partially-started workers
                are best-effort joined before re-raising.
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

        # Listener binding strategy depends on the per-worker
        # backend:
        #
        # * **epoll path (default)**: bind ONE listener via
        #   ``bind_shared`` (no SO_REUSEPORT) and hand its fd to
        #   every worker. ``Reactor.register_exclusive`` +
        #   EPOLLEXCLUSIVE wakes only one worker per accept event,
        #   giving fairer accept-time distribution than
        #   SO_REUSEPORT's 4-tuple hash. Workers borrow the fd
        #   via ``ctx.listener_fd``.
        #
        # * **io_uring buffer-ring path** (FLARE_BUFRING_HANDLER=1):
        #   the Scheduler does NOT bind its own listener -- if it
        #   did, the kernel's SO_REUSEPORT group would route some
        #   incoming connections to the Scheduler's listener
        #   (which has no accepter), causing them to time out in
        #   the listen backlog. Instead, each worker binds its
        #   OWN SO_REUSEPORT listener inside ``_worker_entry``.
        #   ``ctx.listener_fd`` is set to -1 and ignored by the
        #   io_uring dispatch.
        #
        # Decision is made on the Scheduler thread (not in the
        # workers) so an ``AddressInUse`` from a faulty
        # configuration raises on the caller's thread, not inside
        # an opaque pthread.
        var use_io_uring_handler = False
        comptime if CompilationTarget.is_linux():
            if use_uring_backend() and getenv("FLARE_BUFRING_HANDLER") == "1":
                use_io_uring_handler = True

        # ``FLARE_REUSEPORT_WORKERS=1`` opts the epoll path into
        # per-worker ``SO_REUSEPORT`` listeners (each worker
        # accept(2)s on its own fd, kernel hashes new 4-tuples to
        # one of N listeners). The default keeps the single-listener
        # ``EPOLLEXCLUSIVE`` shape because it gives strictly tighter
        # p99.99 (the kernel offers each accept event to whichever
        # worker is currently waiting in ``epoll_wait``, so idle
        # workers absorb spikes). The reuseport mode trades a few
        # ms of p99.99 for measurably higher throughput on dev-box
        # workloads where actix_web (which ships per-worker
        # reuseport listeners by default) leads the multi-worker
        # pack. See ``docs/benchmark.md`` for the head-to-head
        # numbers and the rationale.
        var use_reuseport_workers = False
        if getenv("FLARE_REUSEPORT_WORKERS") == "1":
            use_reuseport_workers = True

        var listener_fd: Int = -1
        var listener_ptr = UnsafePointer[TcpListener, MutExternalOrigin](
            unsafe_from_address=0
        )
        # Both the io_uring buffer-ring path and the opt-in epoll
        # reuseport mode pre-bind per-worker SO_REUSEPORT listeners
        # on this thread (serialised binds avoid concurrent-bind
        # races) and skip the shared listener.
        var prebind_per_worker = use_io_uring_handler or use_reuseport_workers
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
            var cfg_copy = config.copy()
            var handler_copy = handler.copy()
            # Pick this worker's listener fd: either the shared
            # epoll listener, or its own per-worker SO_REUSEPORT
            # listener (pre-bound on this thread above).
            var worker_listener_fd: Int = listener_fd
            if prebind_per_worker and i < len(s._per_worker_listener_addrs):
                var pwl_ptr = UnsafePointer[TcpListener, MutExternalOrigin](
                    unsafe_from_address=s._per_worker_listener_addrs[i]
                )
                worker_listener_fd = Int(pwl_ptr[].as_raw_fd())
            var ctx = _WorkerCtx[Self.H](
                worker_listener_fd,
                addr,
                cfg_copy^,
                handler_copy^,
                stopping_addr,
                i,
                pin_cores,
                auto_protocol,
                h2_config.copy(),
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
                # shared listener anymore -- destroy + free it
                # if we owned one (the io_uring handler path uses
                # per-worker listeners and leaves listener_ptr null).
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

    def shutdown(mut self) raises:
        """Signal every worker to stop and wait for them to join.

        Flips the heap-allocated stopping flag, closes the shared
        listener socket (useful on macOS kqueue; on Linux the
        stopping flag is what actually breaks the loop), then joins
        all worker threads, destroys + frees every worker context,
        the heap-allocated shared listener, and the stopping-flag
        heap cell. Idempotent — a second call finds the state
        empty and is a no-op.
        """
        # Flip the shared stopping flag. ``_stopping_addr == 0``
        # means we were never started (or were already shut down):
        # leave the no-op path to the worker/fd loops below.
        if self._stopping_addr != 0:
            var stop_ptr = UnsafePointer[Bool, MutExternalOrigin](
                unsafe_from_address=self._stopping_addr
            )
            stop_ptr[] = True

        # Close the shared listener fd up-front. This is a no-op on
        # the per-worker epoll registrations (the kernel keeps a
        # ``struct file`` ref while any epoll holds it), but it
        # speeds up the macOS kqueue path and is harmless on Linux.
        # The actual fd-table close happens when ``TcpListener.__del__``
        # runs below, but doing this early helps the listener
        # transition to a "no further accepts" state.
        if self._shared_listener_fd >= 0:
            _ = external_call["close", c_int, c_int](
                c_int(self._shared_listener_fd)
            )
            self._shared_listener_fd = -1

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

        # Drop the shared ``TcpListener`` now that every worker has
        # joined. ``destroy_pointee`` runs the listener's
        # ``__del__``, which closes the fd. The early ``close()``
        # above is idempotent — closing an already-closed fd just
        # gets ``EBADF`` which we ignore.
        if self._shared_listener_addr != 0:
            var raw = _OpaquePtr(unsafe_from_address=self._shared_listener_addr)
            var typed = raw.bitcast[TcpListener]()
            typed.destroy_pointee()
            _scheduler_free_raw(raw)
            self._shared_listener_addr = 0

        # Free any per-worker SO_REUSEPORT listeners (io_uring
        # buffer-ring path). Each listener's destructor closes
        # its fd; the kernel cancels any in-flight io_uring ops
        # against that fd as part of the close.
        for i in range(len(self._per_worker_listener_addrs)):
            var pwl_raw = _OpaquePtr(
                unsafe_from_address=self._per_worker_listener_addrs[i]
            )
            var pwl_typed = pwl_raw.bitcast[TcpListener]()
            pwl_typed.destroy_pointee()
            _scheduler_free_raw(pwl_raw)
        self._per_worker_listener_addrs.clear()

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
        """Graceful multi-worker shutdown.

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
        # ``run_reactor_loop_shared``).
        if self._stopping_addr != 0:
            var stop_ptr = UnsafePointer[Bool, MutExternalOrigin](
                unsafe_from_address=self._stopping_addr
            )
            stop_ptr[] = True

        # Step 2: close the shared listener so a pending ``accept(2)``
        # returns and the worker can observe the stopping flag
        # promptly. Idempotent with ``shutdown()`` below.
        if self._shared_listener_fd >= 0:
            _ = external_call["close", c_int, c_int](
                c_int(self._shared_listener_fd)
            )
            self._shared_listener_fd = -1

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


# ── Static-response multi-worker scheduler ──────────────────────────────────
#
# StaticScheduler is the multi-worker twin of HttpServer.serve_static.
# It binds ONE shared listener (no SO_REUSEPORT -- same EPOLLEXCLUSIVE
# fairness story as the regular Scheduler) and spawns N pthread workers
# that each run run_reactor_loop_static_shared with a copy of the
# StaticResponse. The per-request work in each worker collapses to:
#
#   epoll_wait -> recv -> _scan_content_length -> memcpy(resp.bytes) -> send
#
# No parser builds a HeaderMap, no handler is called, no Response is
# allocated, no headers are looked up, no body is re-serialised. This is
# the fastest path flare exposes for fixed-response endpoints (health
# checks, TFB-style benchmarks, low-latency micro-services) and scales
# near-linearly across the N pthreads because each worker owns its own
# conns dict + write buffers (no cross-thread state).
#
# Design choice: NOT generic. StaticResponse is a concrete type so we
# don't need the H: Handler & Copyable templating that the regular
# Scheduler uses. This keeps monomorphisation cost down and makes the
# struct + worker_entry trivially callable.


struct _StaticWorkerCtx(Movable):
    """Per-worker context for the static-response scheduler.

    Like ``_WorkerCtx[H]`` but carries a ``StaticResponse`` instead of
    a handler. The ``StaticResponse`` is copied per-worker so each
    pthread has its own immutable view of the response bytes (the
    buffers themselves are owned per-worker; the original is dropped
    after spawn).
    """

    var listener_fd: Int
    var bind_addr: SocketAddr
    var config: ServerConfig
    var resp: StaticResponse
    var stopping_addr: Int
    var worker_idx: Int
    var pin_cores: Bool

    def __init__(
        out self,
        listener_fd: Int,
        bind_addr: SocketAddr,
        var config: ServerConfig,
        var resp: StaticResponse,
        stopping_addr: Int,
        worker_idx: Int,
        pin_cores: Bool,
    ):
        self.listener_fd = listener_fd
        self.bind_addr = bind_addr
        self.config = config^
        self.resp = resp^
        self.stopping_addr = stopping_addr
        self.worker_idx = worker_idx
        self.pin_cores = pin_cores


def _static_worker_entry(arg: _OpaquePtr) -> _OpaquePtr:
    """Pthread start routine for one static-response reactor worker.

    Casts ``arg`` back to a ``_StaticWorkerCtx`` pointer, optionally
    pins to a CPU, then runs ``run_reactor_loop_static_shared`` until
    the shared stopping flag is observed.
    """
    var ctx_addr = Int(arg)
    var raw = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=ctx_addr
    )
    var ctx_ptr = raw.bitcast[_StaticWorkerCtx]()

    try:
        var stopping_ptr = UnsafePointer[Bool, MutExternalOrigin](
            unsafe_from_address=ctx_ptr[].stopping_addr
        )

        if ctx_ptr[].pin_cores:
            try:
                var cpu = ctx_ptr[].worker_idx % num_cpus()
                var self_handle = ThreadHandle(
                    external_call["pthread_self", UInt64]()
                )
                self_handle.pin_to_cpu(cpu)
            except:
                pass

        run_reactor_loop_static_shared(
            ctx_ptr[].listener_fd,
            ctx_ptr[].config,
            ctx_ptr[].resp,
            stopping_ptr[],
        )
    except:
        pass

    return UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=0)


def _static_scheduler_free_ctxs(addrs: List[Int]):
    """Destroy each _StaticWorkerCtx at the given address then free it."""
    for i in range(len(addrs)):
        var raw = _OpaquePtr(unsafe_from_address=addrs[i])
        var typed = raw.bitcast[_StaticWorkerCtx]()
        typed.destroy_pointee()
        _scheduler_free_raw(raw)


struct StaticScheduler(Movable):
    """Multi-worker scheduler that serves a single ``StaticResponse``.

    Multi-worker twin of ``HttpServer.serve_static``. Spawns N
    pthread workers, each running ``run_reactor_loop_static_shared``
    with a copy of the pre-encoded response bytes.

    Listener strategy mirrors ``Scheduler``:

    - Default: one listener via ``bind_shared``, borrowed by every
      worker, registered with ``EPOLLEXCLUSIVE`` (tightest p99.99).
    - ``FLARE_REUSEPORT_WORKERS=1``: pre-bind one ``SO_REUSEPORT``
      listener per worker on this thread (highest throughput; ~21 %
      more req/s for ~0.25 ms more p99.99 on this dev-box).

    Use ``StaticScheduler.start(addr, config, resp, num_workers)`` to
    launch and ``shutdown()`` to drain. Same lifecycle contract as
    ``Scheduler``.

    Intended for the TFB plaintext gate (where every response is
    identical) and for production health-check / fixed-response
    endpoints under heavy load.
    """

    var _workers_ptr: UnsafePointer[ThreadHandle, MutExternalOrigin]
    var _workers_len: Int
    var _shared_listener_addr: Int
    var _shared_listener_fd: Int
    var _per_worker_listener_addrs: List[Int]
    """When ``FLARE_REUSEPORT_WORKERS=1`` is set, the StaticScheduler
    pre-binds one SO_REUSEPORT listener per worker on its own thread
    (serialised binds avoid any concurrent-bind race). Each entry
    is the heap address of an owned ``TcpListener``; freed in
    ``shutdown()`` after all workers join. Empty in shared-listener
    EPOLLEXCLUSIVE mode (the default)."""
    var _ctx_addrs: List[Int]
    var _stopping_addr: Int

    def __init__(out self):
        """Build an empty scheduler; use ``StaticScheduler.start``."""
        self._workers_ptr = UnsafePointer[ThreadHandle, MutExternalOrigin](
            unsafe_from_address=0
        )
        self._workers_len = 0
        self._shared_listener_addr = 0
        self._shared_listener_fd = -1
        self._per_worker_listener_addrs = List[Int]()
        self._ctx_addrs = List[Int]()
        self._stopping_addr = 0

    @staticmethod
    def start(
        addr: SocketAddr,
        var config: ServerConfig,
        var resp: StaticResponse,
        num_workers: Int,
        pin_cores: Bool = True,
    ) raises -> StaticScheduler:
        """Spawn ``num_workers`` static-response workers sharing one listener.

        Args:
            addr: Address the shared listener binds.
            config: Per-worker copy of ``ServerConfig``.
            resp: Pre-encoded response bytes (copied per worker).
            num_workers: Number of worker threads. ``1..=256``.
            pin_cores: Pin worker N to core ``N % num_cpus``. No-op
                on macOS.

        Returns:
            A running ``StaticScheduler`` whose workers serve ``resp``
            until ``shutdown()``.
        """
        if num_workers < 1 or num_workers > 256:
            raise Error(
                "StaticScheduler.start: num_workers must be in 1..=256 (got "
                + String(num_workers)
                + ")"
            )
        var s = StaticScheduler()

        var stop_ptr = alloc[Bool](1)
        stop_ptr.init_pointee_copy(False)
        var stop_raw = stop_ptr.bitcast[UInt8]()
        var stopping_addr = Int(stop_ptr)
        s._stopping_addr = stopping_addr

        # ``FLARE_REUSEPORT_WORKERS=1`` opts into per-worker
        # SO_REUSEPORT listeners (each worker owns its own
        # listener fd, kernel hashes new 4-tuples to one of N).
        # Default is the single shared listener with
        # EPOLLEXCLUSIVE — strictly tighter p99.99 because the
        # kernel offers each accept to whichever worker is
        # currently parked in epoll_wait, but the reuseport
        # mode delivers measurably higher throughput on
        # workloads where actix_web (per-worker reuseport by
        # default) leads the multi-worker pack. See
        # ``docs/benchmark.md`` for the head-to-head numbers.
        var use_reuseport_workers = False
        if getenv("FLARE_REUSEPORT_WORKERS") == "1":
            use_reuseport_workers = True

        var listener_fd: Int = -1
        if use_reuseport_workers:
            # Probe-bind to surface AddressInUse / etc. on the
            # caller's thread before spawning any workers.
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
            var lp = alloc[TcpListener](1)
            lp.init_pointee_move(bound^)
            s._shared_listener_addr = Int(lp)
            s._shared_listener_fd = listener_fd

        s._workers_ptr = alloc[ThreadHandle](num_workers)
        s._workers_len = 0

        # Pre-bind per-worker SO_REUSEPORT listeners on this
        # thread (serialised binds avoid concurrent-bind races).
        if use_reuseport_workers:
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
            var cfg_copy = config.copy()
            var resp_copy = resp.copy()
            # Pick this worker's listener fd: either the shared
            # epoll listener, or its own per-worker SO_REUSEPORT
            # listener (pre-bound on this thread above).
            var worker_listener_fd: Int = listener_fd
            if use_reuseport_workers and i < len(s._per_worker_listener_addrs):
                var pwl_ptr = UnsafePointer[TcpListener, MutExternalOrigin](
                    unsafe_from_address=s._per_worker_listener_addrs[i]
                )
                worker_listener_fd = Int(pwl_ptr[].as_raw_fd())
            var ctx = _StaticWorkerCtx(
                worker_listener_fd,
                addr,
                cfg_copy^,
                resp_copy^,
                stopping_addr,
                i,
                pin_cores,
            )
            var ctx_ptr = alloc[_StaticWorkerCtx](1)
            ctx_ptr.init_pointee_move(ctx^)
            var arg = ctx_ptr.bitcast[UInt8]()
            var ctx_addr = Int(ctx_ptr)

            var spawned = False
            try:
                var th = ThreadHandle.spawn[_static_worker_entry](arg)
                (s._workers_ptr + s._workers_len).init_pointee_move(th^)
                s._workers_len += 1
                s._ctx_addrs.append(ctx_addr)
                spawned = True
            except:
                pass
            if not spawned:
                # Roll back partial start.
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
                _static_scheduler_free_ctxs(s._ctx_addrs)
                s._ctx_addrs.clear()
                ctx_ptr.destroy_pointee()
                _scheduler_free_raw(ctx_ptr.bitcast[UInt8]())
                var lpr = _OpaquePtr(
                    unsafe_from_address=s._shared_listener_addr
                )
                var lpt = lpr.bitcast[TcpListener]()
                lpt.destroy_pointee()
                _scheduler_free_raw(lpr)
                s._shared_listener_addr = 0
                s._shared_listener_fd = -1
                _scheduler_free_raw(stop_raw)
                s._stopping_addr = 0
                raise Error("pthread_create failed in StaticScheduler.start")

        return s^

    def shutdown(mut self) raises:
        """Signal every worker to stop and wait for them to join."""
        if self._stopping_addr != 0:
            var stop_ptr = UnsafePointer[Bool, MutExternalOrigin](
                unsafe_from_address=self._stopping_addr
            )
            stop_ptr[] = True

        if self._shared_listener_fd >= 0:
            _ = external_call["close", c_int, c_int](
                c_int(self._shared_listener_fd)
            )
            self._shared_listener_fd = -1

        for i in range(self._workers_len):
            try:
                (self._workers_ptr + i)[].join()
            except:
                pass
            (self._workers_ptr + i).destroy_pointee()
        if self._workers_len > 0:
            _scheduler_free_raw(self._workers_ptr.bitcast[UInt8]())
            self._workers_ptr = UnsafePointer[ThreadHandle, MutExternalOrigin](
                unsafe_from_address=0
            )
            self._workers_len = 0

        _static_scheduler_free_ctxs(self._ctx_addrs)
        self._ctx_addrs.clear()

        if self._shared_listener_addr != 0:
            var raw = _OpaquePtr(unsafe_from_address=self._shared_listener_addr)
            var typed = raw.bitcast[TcpListener]()
            typed.destroy_pointee()
            _scheduler_free_raw(raw)
            self._shared_listener_addr = 0

        # Free any per-worker SO_REUSEPORT listeners
        # (FLARE_REUSEPORT_WORKERS=1 path). Each listener's
        # destructor closes its fd; in-flight epoll registrations
        # against that fd are unregistered as the worker reactor
        # tears down before join.
        for i in range(len(self._per_worker_listener_addrs)):
            var pwl_raw = _OpaquePtr(
                unsafe_from_address=self._per_worker_listener_addrs[i]
            )
            var pwl_typed = pwl_raw.bitcast[TcpListener]()
            pwl_typed.destroy_pointee()
            _scheduler_free_raw(pwl_raw)
        self._per_worker_listener_addrs.clear()

        if self._stopping_addr != 0:
            var stop_raw = _OpaquePtr(unsafe_from_address=self._stopping_addr)
            _scheduler_free_raw(stop_raw)
            self._stopping_addr = 0

    def is_running(self) -> Bool:
        """Return True if any worker has not yet joined."""
        return self._workers_len > 0
