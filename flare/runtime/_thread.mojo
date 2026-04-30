"""Low-level pthread FFI and CPU pinning for flare's scheduler.

Wraps just enough of libpthread (and, on Linux, ``pthread_setaffinity_np``)
for the multicore ``Scheduler`` to spawn + join N worker threads, each
pinned to a specific core. The API is intentionally small and unsafe:

- ``ThreadHandle.spawn(start, arg)`` wraps ``pthread_create``. The
  start routine is a ``def(UnsafePointer[None]) thin abi("C") -> UnsafePointer[None]``
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

Threads that outlive their ``ThreadHandle`` are undefined behaviour.
Always join before dropping.

Platform notes:
- Linux uses libpthread (``libpthread.so.0``); symbols are resolved via
  ``external_call`` like the rest of ``flare/net/_libc.mojo``.
- macOS bundles pthread into ``libSystem.dylib``; symbols there are
  reachable from the default dynamic link namespace.

This file is *internal* — it is used by
``flare.runtime.scheduler`` and nothing else.
"""

from std.ffi import (
    external_call,
    c_int,
    c_size_t,
    OwnedDLHandle,
    get_errno,
)
from std.memory import UnsafePointer, alloc, memcpy, memset_zero
from std.sys.info import CompilationTarget


# ── Start routine signature ──────────────────────────────────────────────────

# C pthread_create expects `void *(*)(void *)`. On both Linux x86_64 and
# macOS arm64 Mojo's plain ``fn`` type uses the platform C calling
# convention, so a bare ``fn(UnsafePointer[UInt8, _]) -> UnsafePointer[UInt8, _]``
# is ABI-compatible with what pthread expects. The function must not
# raise (pthread has no exception channel); convert any error to a
# sentinel pointer value before returning.
comptime _OpaquePtr = UnsafePointer[UInt8, MutExternalOrigin]


# Shortcut for making a NULL pointer of the flavour we use throughout.
@always_inline
def _null_ptr() -> _OpaquePtr:
    return _OpaquePtr(unsafe_from_address=0)


# ── ThreadHandle ─────────────────────────────────────────────────────────────


@fieldwise_init
struct ThreadHandle(Movable):
    """Owning handle to a live OS thread.

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

    Because ``List[T]`` in Mojo 0.26.3 still requires ``T: Copyable``,
    ``Scheduler`` stores its workers in an ``UnsafePointer[ThreadHandle]``
    instead of a ``List`` — see ``flare.runtime.scheduler``.
    """

    var _thread_id: UInt64
    """Opaque pthread_t handle. Zeroed by ``join()`` on success so
    a second call on *the same handle* is a no-op."""

    @staticmethod
    def spawn[
        start: def(_OpaquePtr) thin -> _OpaquePtr
    ](arg: _OpaquePtr,) raises -> ThreadHandle:
        """Spawn a thread that runs ``start(arg)``.

        Args:
            start: Entry function. Signature
                ``fn(UnsafePointer[UInt8]) thin abi("C") -> UnsafePointer[UInt8]``.
                Must not raise; convert errors into a sentinel return
                value before returning.
            arg: Opaque pointer delivered to the start function.

        Returns:
            A ``ThreadHandle`` the caller must ``join()``.

        Raises:
            Error: If ``pthread_create`` returns non-zero (the return
                value is the POSIX error, already interpreted as a
                human-readable message).
        """
        var tid = UInt64(0)
        var tid_addr = Int(UnsafePointer[UInt64, _](to=tid))
        var tid_ptr = UnsafePointer[UInt64, MutExternalOrigin](
            unsafe_from_address=tid_addr
        )

        # attr == NULL means default thread attributes (PTHREAD_CREATE_JOINABLE).
        var null_attr = _null_ptr()

        var rc = external_call[
            "pthread_create",
            c_int,
            UnsafePointer[UInt64, MutExternalOrigin],  # thread*
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

    def pin_to_cpu(self, cpu: Int) raises:
        """Pin the thread to CPU ``cpu``.

        On Linux, calls ``pthread_setaffinity_np`` with a ``cpu_set_t``
        whose only set bit is ``cpu``. On macOS this function is a no-op
        (the OS's scheduler already does a good job for our benchmark
        shapes; a Mach ``thread_policy_set`` hint would not be a hard
        pin anyway).

        Args:
            cpu: Zero-based CPU index.

        Raises:
            Error: If ``pthread_setaffinity_np`` returns non-zero on
                Linux. Never raises on macOS.
        """
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
            var cpuset_ptr = alloc[UInt8](_CPUSET_SIZE)
            memset_zero(cpuset_ptr, _CPUSET_SIZE)
            var byte_idx = cpu // 8
            var bit_idx = cpu % 8
            if byte_idx < _CPUSET_SIZE:
                cpuset_ptr[byte_idx] = cpuset_ptr[byte_idx] | UInt8(
                    1 << bit_idx
                )
            var rc = external_call[
                "pthread_setaffinity_np",
                c_int,
                UInt64,
                c_size_t,
                _OpaquePtr,  # cpu_set_t *
            ](self._thread_id, c_size_t(_CPUSET_SIZE), cpuset_ptr)
            cpuset_ptr.free()
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
