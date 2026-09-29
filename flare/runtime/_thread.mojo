"""Low-level pthread FFI and CPU pinning for flare's scheduler.

Wraps just enough of libpthread (and, on Linux, ``pthread_setaffinity_np``)
for the multicore ``Scheduler`` to spawn + join N worker threads, each
pinned to a specific core. The API is intentionally small and unsafe:

- ``ThreadHandle.spawn(start, arg)`` wraps ``pthread_create``. The
  start routine is a ``def(Pointer[None]) thin abi("C") -> Pointer[None]``
  that never raises; the reactor loop inside the worker is responsible
  for converting Mojo exceptions into a sentinel pointer.
- ``ThreadHandle.join()`` wraps ``pthread_join``. Returns the worker's
  return value (usually unused).
- ``ThreadHandle.pin_to_cpu(cpu)`` pins the thread to a specific core
  on Linux via ``pthread_setaffinity_np``. On macOS this is a no-op
  placeholder (Mach's ``thread_policy_set`` with
  ``THREAD_AFFINITY_POLICY`` is a hint rather than a hard pin, and
  documenting that cleanly needs more surface area than deserves — the macOS scheduler's own topology picker is good
  enough for our benchmark targets).

Threads that outlive their ``ThreadHandle`` are undefined behaviour
unless the handle was ``detach()``ed first. Join before dropping, or
detach and let the OS reclaim the thread.

Platform notes:
- Linux uses libpthread (``libpthread.so.0``); symbols are resolved via
  ``external_call`` like the rest of ``flare/net/_libc.mojo``.
- macOS bundles pthread into ``libSystem.dylib``; symbols there are
  reachable from the default dynamic link namespace.

Thread engine. By default ``spawn`` creates a pthread. Built with
``-D FLARE_ASYNCRT`` it enqueues a task on Mojo's AsyncRT pool instead
(``flare.runtime._asyncrt``); ``spawn_os`` always creates a pthread,
for threads that never return or that live as long as a connection.
Both kinds share ``join`` / ``detach`` / the move-only handle.

This file is *internal* — it is used by the runtime, the WebSocket
server, async DNS and the H3/H2 connect race.
"""

from std.ffi import (
    external_call,
    c_int,
    c_size_t,
    OwnedDLHandle,
    get_errno,
)
from std.memory import Layout, Pointer, alloc, unsafe_memset_zero
from std.sys.info import CompilationTarget

from ._asyncrt import (
    FLARE_USE_ASYNCRT,
    asyncrt_detach,
    asyncrt_join,
    asyncrt_pool_alive,
    asyncrt_spawn,
    asyncrt_wait_started,
)


# ── Start routine signature ──────────────────────────────────────────────────

# C pthread_create expects `void *(*)(void *)`. On both Linux x86_64 and
# macOS arm64 Mojo's plain ``fn`` type uses the platform C calling
# convention, so a bare ``fn(Pointer[UInt8, _]) -> Pointer[UInt8, _]``
# is ABI-compatible with what pthread expects. The function must not
# raise (pthread has no exception channel); convert any error to a
# sentinel pointer value before returning.
comptime _OpaquePtr = Pointer[UInt8, MutUntrackedOrigin]

comptime _KIND_OS: UInt8 = 0
"""``ThreadHandle`` owns a pthread (``_thread_id`` is a ``pthread_t``)."""
comptime _KIND_ASYNCRT: UInt8 = 1
"""``ThreadHandle`` owns an AsyncRT task (``_thread_id`` is its task
cell address, see ``flare.runtime._asyncrt``)."""


# Shortcut for making a NULL pointer of the flavour we use throughout.
# Pointer is non-nullable and rejects a comptime-literal address
# of 0, but pthread genuinely needs a C NULL here (NULL attr arg, NULL
# retval slot, NULL start-routine return). Build it from a runtime
# zero so the non-null constraint doesn't fire. A cleaner fix would
# model these as Optional[Pointer], which marshals as NULL
# across FFI with identical layout (the null address is the None niche).
@always_inline
def _null_ptr() -> _OpaquePtr:
    var null_addr = 0
    return _OpaquePtr(unsafe_from_address=null_addr)


# ── ThreadHandle ─────────────────────────────────────────────────────────────


struct ThreadHandle(Movable):
    """Owning handle to a live OS thread or AsyncRT task.

    Stores ``pthread_t`` as a ``UInt64`` — on Linux x86_64 it is
    ``unsigned long`` and on macOS arm64 it is an opaque pointer;
    both are 64 bits. Do not rely on the concrete bit pattern.

    ``ThreadHandle`` is ``Movable`` but *not* ``Copyable`` on
    purpose. A ``pthread_t`` identifies one OS thread and POSIX
    forbids calling ``pthread_join`` more than once on the same
    value — that is a property of the underlying resource, not of
    one Mojo value pointing at it. Making the handle move-only
    puts the "exactly one owner, exactly one join" invariant in
    the type system.

    As a defence in depth ``join()`` also zeroes ``_thread_id`` on
    success, so if the compiler's move-checking is ever bypassed
    (e.g. a ``memcpy``-style bitwise aliasing) a redundant call on
    that specific handle short-circuits rather than double-joining.

    Because ``List[T]`` requires ``T: Copyable``, ``Scheduler`` stores
    its workers in an ``Pointer[ThreadHandle]`` instead of a
    ``List`` — see ``flare.runtime.scheduler``.
    """

    var _thread_id: UInt64
    """Opaque pthread_t handle, or the AsyncRT task cell address when
    ``_kind == _KIND_ASYNCRT``. Zeroed by ``join()`` on success so a
    second call on *the same handle* is a no-op."""

    var _kind: UInt8
    """``_KIND_OS`` or ``_KIND_ASYNCRT``."""

    def __init__(out self, *, _thread_id: UInt64, _kind: UInt8 = _KIND_OS):
        self._thread_id = _thread_id
        self._kind = _kind

    @staticmethod
    def spawn[
        start: def(_OpaquePtr) thin -> _OpaquePtr
    ](arg: _OpaquePtr,) raises -> ThreadHandle:
        """Run ``start(arg)`` on the configured thread engine.

        A pthread by default. Built with ``-D FLARE_ASYNCRT``, a task
        on the AsyncRT pool: it runs once a pool worker is free, and
        holds that worker until ``start`` returns. In a process whose
        pool has no workers (a forked child) it is a pthread anyway. Use ``spawn_os`` for
        work that never returns or lives as long as a connection.

        Parameters:
            start: Entry function; same contract as ``spawn_os``.

        Args:
            arg: Opaque pointer delivered to the start function.

        Returns:
            A handle the caller must ``join()`` or ``detach()``.

        Raises:
            Error: If ``pthread_create`` fails (pthread engine only).
        """
        comptime if FLARE_USE_ASYNCRT:
            # A forked child has no pool workers; see asyncrt_pool_alive.
            if asyncrt_pool_alive():
                return ThreadHandle(
                    _thread_id=asyncrt_spawn[start](arg), _kind=_KIND_ASYNCRT
                )
        return ThreadHandle.spawn_os[start](arg)

    @staticmethod
    def spawn_os[
        start: def(_OpaquePtr) thin -> _OpaquePtr
    ](arg: _OpaquePtr,) raises -> ThreadHandle:
        """Spawn a dedicated OS thread (pthread) that runs ``start(arg)``,
        whatever engine ``spawn`` is configured for.

        Parameters:
            start: Entry function. Signature
                ``fn(Pointer[UInt8]) thin abi("C") -> Pointer[UInt8]``.
                Must not raise; convert errors into a sentinel return
                value before returning.

        Args:
            arg: Opaque pointer delivered to the start function.

        Returns:
            A ``ThreadHandle`` the caller must ``join()`` or
            ``detach()``.

        Raises:
            Error: If ``pthread_create`` returns non-zero (the return
                value is the POSIX error, already interpreted as a
                human-readable message). Nothing was spawned, so
                anything handed to ``arg`` is still the caller's to
                free.
        """
        var tid = UInt64(0)
        var tid_addr = Int(Pointer[UInt64, _](to=tid))
        var tid_ptr = Pointer[UInt64, MutUntrackedOrigin](
            unsafe_from_address=tid_addr
        )

        # attr == NULL means default thread attributes (PTHREAD_CREATE_JOINABLE).
        var null_attr = _null_ptr()

        var rc = external_call[
            "pthread_create",
            c_int,
            Pointer[UInt64, MutUntrackedOrigin],  # thread*
            _OpaquePtr,  # attr*
            def(_OpaquePtr) thin -> _OpaquePtr,  # start routine
            _OpaquePtr,  # arg
        ](tid_ptr, null_attr, start, arg)

        if rc != c_int(0):
            raise Error("pthread_create failed with rc=" + String(Int(rc)))
        return ThreadHandle(_thread_id=tid)

    def join(mut self) raises:
        """Wait for the thread to finish.

        Discards the thread's return value. Safe to call more than
        once on the same handle: after the first successful join
        ``_thread_id`` is zeroed, so subsequent calls short-circuit
        and return without invoking ``pthread_join`` again (``pthread_join``
        on a stale thread id is undefined behaviour).

        Raises:
            Error: If ``pthread_join`` returns non-zero. The handle
                is left untouched so the caller can retry or
                propagate.
        """
        if self._thread_id == 0:
            # Already joined (successfully) — redundant call is a
            # no-op rather than an undefined second pthread_join.
            return
        if self._kind == _KIND_ASYNCRT:
            asyncrt_join(self._thread_id)
            self._thread_id = UInt64(0)
            return
        var rc = external_call[
            "pthread_join",
            c_int,
            UInt64,  # thread
            _OpaquePtr,  # retval** (NULL)
        ](self._thread_id, _null_ptr())
        if rc != c_int(0):
            raise Error("pthread_join failed with rc=" + String(Int(rc)))
        # Zero out so a second join() on this handle is a no-op.
        # Without this, the handle is in a "joined" state but a
        # further pthread_join on the stale id is UB per POSIX.
        self._thread_id = UInt64(0)

    def detach(mut self) raises:
        """Detach the thread so the OS reclaims it when it exits.

        Wraps ``pthread_detach``. A detached thread runs to completion
        on its own and must NOT be ``join()``ed. This is what a
        fire-and-forget worker that outlives the spawning call frame
        needs -- one pthread per offloaded WebSocket connection, say;
        a joinable thread nobody ever joins holds its kernel
        bookkeeping until the process exits.

        ``_thread_id`` is zeroed on success, so a later ``join()`` on
        this handle short-circuits instead of joining a detached
        thread (undefined per POSIX).

        Raises:
            Error: If ``pthread_detach`` returns non-zero. The handle
                is left untouched so the caller can retry or
                propagate.
        """
        if self._thread_id == 0:
            return
        if self._kind == _KIND_ASYNCRT:
            asyncrt_detach(self._thread_id)
            self._thread_id = UInt64(0)
            return
        var rc = external_call["pthread_detach", c_int, UInt64](self._thread_id)
        if rc != c_int(0):
            raise Error("pthread_detach failed with rc=" + String(Int(rc)))
        self._thread_id = UInt64(0)

    def wait_started(self):
        """Block until the thread has begun running its start routine.

        A no-op for a pthread, which is running as soon as ``spawn``
        returns. An AsyncRT task sits in the pool's queue until a worker
        takes it, and a joiner elsewhere that donates its worker while
        waiting could take a queued task. Spawners of tasks that never
        return on their own (serving loops) call this for each one so
        none is left in the queue for a donating waiter to run inline.
        """
        if self._kind == _KIND_ASYNCRT and self._thread_id != 0:
            asyncrt_wait_started(self._thread_id)

    def pin_to_cpu(self, cpu: Int) raises:
        """Pin the thread to CPU ``cpu``.

        On Linux, calls ``pthread_setaffinity_np`` with a ``cpu_set_t``
        whose only set bit is ``cpu``. On macOS this function is a no-op
        (the OS's scheduler already does a good job for our benchmark
        shapes; a Mach ``thread_policy_set`` hint would not be a hard
        pin anyway).

        Args:
            cpu: Zero-based CPU index.

        A no-op for an AsyncRT task: the pool owns its workers'
        affinity (``MODULAR_ENABLE_AFFINITY``), and the thread a task
        lands on is shared with every other task.

        Raises:
            Error: If ``pthread_setaffinity_np`` returns non-zero on
                Linux. Never raises on macOS.
        """
        if self._kind == _KIND_ASYNCRT:
            return
        comptime if CompilationTarget.is_linux():
            # cpu_set_t on glibc is 1024 bits = 128 bytes by default.
            # Allocate and zero-fill a 128-byte buffer, then set the bit
            # for the target CPU.
            comptime _CPUSET_SIZE: Int = 128
            # Native Mojo allocator (``std.memory.alloc`` / ``.free()``)
            # instead of libc malloc/free via FFI:
            # ``external_call["free", ...]`` conflicts with the stdlib's
            # own ``free`` declaration at MLIR legalization time when
            # this module is pulled into a fuzz-environment compile
            # (mozz harness).
            var cpuset_ptr = alloc(
                Layout[UInt8](count=_CPUSET_SIZE)
            ).unsafe_leak()
            unsafe_memset_zero(cpuset_ptr, _CPUSET_SIZE)
            var byte_idx = cpu // 8
            var bit_idx = cpu % 8
            if byte_idx < _CPUSET_SIZE:
                cpuset_ptr[unsafe_offset=byte_idx] = cpuset_ptr[
                    unsafe_offset=byte_idx
                ] | UInt8(1 << bit_idx)
            var rc = external_call[
                "pthread_setaffinity_np",
                c_int,
                UInt64,
                c_size_t,
                _OpaquePtr,  # cpu_set_t *
            ](self._thread_id, c_size_t(_CPUSET_SIZE), cpuset_ptr)
            cpuset_ptr.unsafe_free()
            if rc != c_int(0):
                raise Error(
                    "pthread_setaffinity_np failed with rc=" + String(Int(rc))
                )
        else:
            # macOS: no hard pin. Leave the scheduler alone.
            pass


# ── pthread_self convenience ─────────────────────────────────────────────────


@always_inline
def current_thread_id() -> UInt64:
    """Return the OS thread id of the calling thread (pthread_self)."""
    return external_call["pthread_self", UInt64]()


# ── Number of available CPUs ─────────────────────────────────────────────────


def num_cpus() -> Int:
    """Return the number of available logical CPUs.

    Uses ``sysconf(_SC_NPROCESSORS_ONLN)`` which is portable across
    Linux and macOS.
    """
    comptime _SC_NPROCESSORS_ONLN_LINUX: c_int = 84
    comptime _SC_NPROCESSORS_ONLN_MACOS: c_int = 58
    comptime if CompilationTarget.is_linux():
        var rc = external_call["sysconf", Int, c_int](
            _SC_NPROCESSORS_ONLN_LINUX
        )
        if rc <= 0:
            return 1
        return rc
    else:
        var rc = external_call["sysconf", Int, c_int](
            _SC_NPROCESSORS_ONLN_MACOS
        )
        if rc <= 0:
            return 1
        return rc
