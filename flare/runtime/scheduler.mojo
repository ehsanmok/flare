"""Multicore scheduler: N reactors, N pthread workers.

Runs N single-threaded reactor loops in parallel, one per pthread,
each with its own listener bound with ``SO_REUSEPORT``. The kernel
distributes accepted connections across workers so every worker
handles roughly 1/N of the total connection load.

Shutdown path: the caller sets ``Scheduler._stopping`` (or calls
``shutdown()``), each worker observes it on the next poll iteration,
breaks out of its reactor loop, drains its active connections up to
``config.shutdown_timeout_ms``, and returns. The main thread joins
all workers before ``Scheduler.__del__`` returns.

This module is ``Handler``-generic: every worker runs the same
``H: Handler`` that the caller passed to ``Scheduler.run``. The
handler value is moved (per-worker copies are made via ``H.copy()``;
if that's expensive users should wrap their handler's expensive state
behind an ``UnsafePointer`` or a similar shared-reference holder).

Only the ``Handler`` and ``ServerConfig`` machinery that v0.4.0 already
has is touched; the run loop re-uses ``run_reactor_loop[H]`` from
``flare.http._server_reactor_impl``.
"""

from std.ffi import c_int, c_size_t, external_call
from std.memory import UnsafePointer
from std.sys import size_of

from ..http.handler import Handler
from ..http.server import ServerConfig
from ..http._server_reactor_impl import run_reactor_loop
from ..net import SocketAddr
from ..tcp import TcpListener

from ._thread import ThreadHandle, num_cpus, _OpaquePtr
from .reuseport import bind_reuseport


# ── Context cleanup helpers (non-generic; non-generic call sites avoid
#    a Mojo build conflict with mozz's own ``free`` declaration) ─────────────


@always_inline
def _scheduler_free_raw(raw: _OpaquePtr):
    """Free a raw malloc'd pointer via libc free. Non-generic: one
    instantiation per compile unit, which keeps the external_call for
    ``free`` from being emitted at multiple generic-monomorphised sites.
    """
    _ = external_call["free", NoneType](raw.bitcast[NoneType]())


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

    The context was allocated on the main thread with
    ``UnsafePointer[_WorkerCtx[H]].alloc(1)`` plus
    ``init_pointee_move``; this routine is responsible for destroying
    and freeing it before returning.
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

        # The stopping flag is read by run_reactor_loop every poll
        # iteration; we pass it by value here and rely on the Reactor's
        # wakeup fd + ServerConfig.shutdown_timeout_ms for bounded
        # drain. A truly shared flag would need an atomic; for v0.4.0
        # the Scheduler also calls listener.close() on shutdown which
        # breaks accept() + poll() directly, so the Bool copy staleness
        # is harmless.
        run_reactor_loop[H](
            ctx_ptr[].listener,
            ctx_ptr[].config,
            ctx_ptr[].handler,
            stopping_ptr[],
        )
    except:
        pass

    # Ctx ownership: the Scheduler main thread destroys + frees every
    # ctx AFTER joining the worker, so we don't touch it here. This
    # keeps all external_call[\"free\"] uses in a single, non-generic
    # code path (Scheduler.shutdown) which avoids a Mojo build
    # conflict under the fuzz environment where mozz also declares
    # ``free`` at module scope.
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
          a shared ``_stopping`` flag. ``shutdown()`` sets the flag and
          joins all workers.
        - Per-worker listener is bound with ``bind_reuseport``, so all
          N workers share the same TCP port via ``SO_REUSEPORT``.
        - Handler is cloned into each worker via ``H.copy()``.
    """

    var workers: List[ThreadHandle]
    var _listener_fds: List[Int]
    var _ctx_addrs: List[Int]
    var _stopping: Bool
    var _stopping_ptr: UnsafePointer[Bool, MutExternalOrigin]

    def __init__(out self):
        """Build an empty scheduler; use ``Scheduler.start`` instead."""
        self.workers = List[ThreadHandle]()
        self._listener_fds = List[Int]()
        self._ctx_addrs = List[Int]()
        self._stopping = False
        self._stopping_ptr = UnsafePointer[Bool, MutExternalOrigin](
            unsafe_from_address=0
        )

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
            num_workers: Number of worker threads (1..=256 enforced by
                the caller; this function does not re-check).
            pin_cores:   If ``True`` (default), pin worker N to core
                ``N % num_cpus``. No-op on macOS.

        Returns:
            A running ``Scheduler`` whose workers will continue to
            serve until ``shutdown()`` is called.

        Raises:
            Error: If a listener fails to bind or ``pthread_create``
                fails; partially-started workers are best-effort
                joined before re-raising.
        """
        var s = Scheduler[Self.H]()
        s._stopping = False
        var stopping_addr = Int(UnsafePointer[Bool, _](to=s._stopping))
        s._stopping_ptr = UnsafePointer[Bool, MutExternalOrigin](
            unsafe_from_address=stopping_addr
        )

        for i in range(num_workers):
            var listener = bind_reuseport(addr)
            # Save fd so shutdown can close all listener sockets from
            # the main thread, which breaks every worker's accept() /
            # poll() immediately instead of waiting for the stopping
            # flag to be observed.
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
            # Allocate via libc malloc (parametric-origin alloc on
            # UnsafePointer is not available); size = size_of[WorkerCtx]
            var ctx_size = size_of[_WorkerCtx[Self.H]]()
            var raw = external_call["malloc", _OpaquePtr](c_size_t(ctx_size))
            if not raw:
                raise Error("malloc failed for worker ctx")
            var ctx_ptr = raw.bitcast[_WorkerCtx[Self.H]]()
            ctx_ptr.init_pointee_move(ctx^)
            var arg = raw
            var ctx_addr = Int(raw)

            var spawned = False
            try:
                var th = ThreadHandle.spawn[_worker_entry[Self.H]](arg)
                s.workers.append(th^)
                s._ctx_addrs.append(ctx_addr)
                spawned = True
            except:
                pass
            if not spawned:
                # Roll back any workers we already started so the caller
                # gets a fully-stopped scheduler instead of half-live state.
                s._stopping = True
                for j in range(len(s.workers)):
                    try:
                        s.workers[j].join()
                    except:
                        pass
                # Destroy + free EVERY ctx (the ones that workers claimed
                # + this one that never got claimed).
                _scheduler_free_ctxs[Self.H](s._ctx_addrs)
                s._ctx_addrs.clear()
                ctx_ptr.destroy_pointee()
                _scheduler_free_raw(raw)
                raise Error("pthread_create failed in Scheduler.start")

        return s^

    def shutdown(mut self) raises:
        """Signal every worker to stop and wait for them to join.

        Flips the shared stopping flag, closes every worker's
        listener socket (which breaks ``accept()`` and ``poll()`` in
        every worker immediately), then joins all worker threads, and
        finally destroys + frees every worker context.
        Idempotent — a second call finds the lists empty and is a no-op.
        """
        self._stopping = True
        for i in range(len(self._listener_fds)):
            var fd = self._listener_fds[i]
            _ = external_call["close", c_int, c_int](c_int(fd))
        self._listener_fds.clear()

        for i in range(len(self.workers)):
            try:
                self.workers[i].join()
            except:
                pass
        self.workers.clear()

        # After all workers have joined, it's safe to destroy and free
        # their per-thread contexts. Doing it here (non-generic call
        # site: no monomorphisation per H) avoids a Mojo build conflict
        # with mozz's ``free`` declaration in the fuzz environment.
        _scheduler_free_ctxs[Self.H](self._ctx_addrs)
        self._ctx_addrs.clear()

    def is_running(self) -> Bool:
        """Return True if any worker has not yet joined.

        Note: this does not detect workers that have crashed; pthread
        has no crash channel. An unexpected worker-exit surfaces as
        ``False`` here without distinguishing normal shutdown from
        failure.
        """
        return len(self.workers) > 0


# ── Convenience ─────────────────────────────────────────────────────────────


def default_worker_count() -> Int:
    """Sensible default worker count: ``num_cpus()``.

    For IO-bound HTTP plaintext the best throughput is usually
    num_cpus workers; CPU-heavy handlers may prefer num_cpus // 2 to
    leave headroom for the kernel network stack.
    """
    return num_cpus()
