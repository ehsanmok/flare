"""Per-worker context and pthread entry point for the scheduler.

Split out of ``scheduler.mojo`` when that file crossed the 1000-line
reactor-size budget. The seam is a real one rather than a line count:
``_WorkerCtx`` and ``_worker_entry`` are the boundary between the
scheduler (which owns listeners, threads and lifecycle) and one
worker's execution, and neither touches ``Scheduler`` internals.
"""

from std.ffi import c_int, external_call
from std.memory import Pointer, alloc

from ..net import SocketAddr

from ._thread import ThreadHandle, num_cpus, _OpaquePtr
from .frontend import Frontend
from .scheduler_stats import load_stop_flag, store_worker_stat


# ── Per-worker context ───────────────────────────────────────────────────────


struct _WorkerCtx[F: Frontend](Movable):
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
    var extra_fds: List[Int]
    """This worker's listeners on the *additional* bind addresses,
    one fd per extra address, in the order the addresses were passed
    to :meth:`Scheduler.start`. Empty for a single-address scheduler.

    Each fd is this worker's own ``SO_REUSEPORT`` listener, not a
    shared one: N addresses x M workers means N*M listeners, all
    bound serially on the scheduler thread. Owned by the Scheduler;
    workers must not close them."""
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
        var extra_fds: List[Int] = List[Int](),
    ):
        self.listener_fd = listener_fd
        self.bind_addr = bind_addr
        self.frontend = frontend^
        self.stopping_addr = stopping_addr
        self.worker_idx = worker_idx
        self.pin_cores = pin_cores
        self.stats_addr = stats_addr
        self.extra_fds = extra_fds^


# ── Worker entry point (comptime-specialised per F) ─────────────────────────


def _worker_entry[F: Frontend](arg: _OpaquePtr) -> _OpaquePtr:
    """Pthread start routine for one reactor worker.

    Casts ``arg`` back to a ``_WorkerCtx[F]`` pointer, optionally
    pins to a CPU, then delegates to :meth:`Frontend.run_worker`
    until the shared stopping flag is observed.

    The context was allocated on the main thread with libc ``malloc``
    plus ``unsafe_write``; the Scheduler main thread destroys and
    frees it after joining this worker.
    """
    var ctx_addr = Int(arg)
    var raw = Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=ctx_addr)
    var ctx_ptr = raw.unsafe_bitcast[_WorkerCtx[F]]()

    var stopping_ptr = Pointer[Bool, MutUntrackedOrigin](
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
        ctx_ptr[].extra_fds.copy(),
    )

    # Ctx ownership: the Scheduler main thread destroys + frees every
    # ctx AFTER joining the worker, so we don't touch it here.
    # Pointer is non-nullable; build C NULL from a runtime 0.
    var null_addr = 0
    return Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=null_addr)
