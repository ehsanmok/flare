"""Internal libc event-loop syscall bindings -- not part of the public API.

The lowest-level epoll (Linux) and kqueue (macOS) wrappers, their struct
constants and byte-layout helpers, plus the eventfd/pipe wakeup
primitives that drive the reactor in :mod:`flare.runtime`. Split out of
``flare/net/_libc.mojo`` to keep that module within the file-size budget;
``_libc`` re-exports every name so existing
``from flare.net._libc import EPOLLIN`` (and every other epoll/kqueue
constant or wrapper) call site keeps resolving unchanged.

Platform struct-layout quirks are documented inline below.
"""

from std.ffi import external_call, c_int, c_uint
from std.memory import UnsafePointer
from std.sys.info import CompilationTarget

# ──────────────────────────────────────────────────────────────────────────────
# Event-loop syscalls: epoll (Linux) + kqueue (macOS)
# ──────────────────────────────────────────────────────────────────────────────
#
# These power the reactor in ``flare.runtime`` (Stage 1). epoll and kqueue
# have different semantics but the reactor presents a common API over both.
# Constants and FFI wrappers here are the lowest level.
#
# Platform struct-layout quirks (important):
#
# 1. ``struct epoll_event`` on Linux is PACKED on x86_64 (12 bytes, data at
# offset 4) but NATURALLY ALIGNED on aarch64 (16 bytes, data at offset 8).
# See glibc's ``EPOLL_PACKED`` macro. ``EPOLL_EVENT_SIZE`` and
# ``EPOLL_DATA_OFFSET`` below handle both.
#
# 2. ``struct kevent`` on macOS is 32 bytes (ident=8, filter=2, flags=2,
# fflags=4, data=8, udata=8). Same on both arm64 and x86_64 macOS.

# ── Epoll constants (Linux) ──────────────────────────────────────────────────
# Event bits (ORed into ``epoll_event.events``).
# Same numeric values on all Linux archs.
comptime EPOLLIN: UInt32 = 0x001
comptime EPOLLPRI: UInt32 = 0x002
comptime EPOLLOUT: UInt32 = 0x004
comptime EPOLLERR: UInt32 = 0x008
comptime EPOLLHUP: UInt32 = 0x010
comptime EPOLLRDHUP: UInt32 = 0x2000
comptime EPOLLEXCLUSIVE: UInt32 = 0x10000000  # 1u << 28; Linux >= 4.5
comptime EPOLLET: UInt32 = 0x80000000  # edge-triggered

# epoll_ctl() operations.
comptime EPOLL_CTL_ADD: c_int = 1
comptime EPOLL_CTL_DEL: c_int = 2
comptime EPOLL_CTL_MOD: c_int = 3

# epoll_create1() flags. EPOLL_CLOEXEC closes epfd on exec().
comptime EPOLL_CLOEXEC: c_int = 0o2000000  # 0x80000

# ``struct epoll_event`` size and the offset of the ``data.u64`` field.
# On x86_64 the struct is packed (12 bytes, data @ offset 4).
# On aarch64 it has natural alignment (16 bytes, data @ offset 8).
comptime EPOLL_EVENT_SIZE: Int = 12 if CompilationTarget.is_x86() else 16
comptime EPOLL_EVENT_DATA_OFF: Int = 4 if CompilationTarget.is_x86() else 8

# ── Eventfd constants (Linux) ────────────────────────────────────────────────
# eventfd(2) creates a lightweight counter-backed fd used as a cross-thread
# wakeup primitive. Write any 8-byte uint64 to increment the counter; read to
# drain. We use it to wake the reactor from another thread (Stage 2+).
comptime EFD_CLOEXEC: c_int = 0o2000000  # same as O_CLOEXEC
comptime EFD_NONBLOCK: c_int = 0o4000  # 2048
comptime EFD_SEMAPHORE: c_int = 0o1  # not used

# ── Kqueue constants (macOS) ─────────────────────────────────────────────────
# Filter values. Negative integers (passed as Int16).
comptime EVFILT_READ: Int16 = -1
comptime EVFILT_WRITE: Int16 = -2
comptime EVFILT_TIMER: Int16 = -7
comptime EVFILT_USER: Int16 = -10  # user-triggered, used for wakeup

# ``flags`` bits in ``struct kevent``.
comptime EV_ADD: UInt16 = 0x0001
comptime EV_DELETE: UInt16 = 0x0002
comptime EV_ENABLE: UInt16 = 0x0004
comptime EV_DISABLE: UInt16 = 0x0008
comptime EV_ONESHOT: UInt16 = 0x0010
comptime EV_CLEAR: UInt16 = 0x0020
comptime EV_EOF: UInt16 = 0x8000
comptime EV_ERROR: UInt16 = 0x4000

# ``fflags`` bits for EVFILT_USER (cross-thread wakeup).
comptime NOTE_TRIGGER: UInt32 = 0x01000000
comptime NOTE_FFNOP: UInt32 = 0x00000000

# Size of ``struct kevent`` on 64-bit macOS.
comptime KEVENT_SIZE: Int = 32
# Field offsets in ``struct kevent``.
comptime KEVENT_IDENT_OFF: Int = 0  # uintptr_t, 8 bytes
comptime KEVENT_FILTER_OFF: Int = 8  # int16_t, 2 bytes
comptime KEVENT_FLAGS_OFF: Int = 10  # uint16_t, 2 bytes
comptime KEVENT_FFLAGS_OFF: Int = 12  # uint32_t, 4 bytes
comptime KEVENT_DATA_OFF: Int = 16  # intptr_t, 8 bytes
comptime KEVENT_UDATA_OFF: Int = 24  # void*, 8 bytes

# ──────────────────────────────────────────────────────────────────────────────
# Epoll struct-field helpers (Linux)
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _epoll_event_set(
    buf: UnsafePointer[UInt8, _], events: UInt32, data_u64: UInt64
) where type_of(buf).mut:
    """Populate one ``struct epoll_event`` in-place.

    The caller must provide a ``EPOLL_EVENT_SIZE``-byte buffer.

    Args:
        buf: Pointer to uninitialised epoll_event buffer.
        events: ``EPOLLIN | EPOLLOUT | EPOLLET | ...`` bitmask.
        data_u64: Token stored in ``data.u64`` (used by reactor as its
                  per-fd opaque handle).
    """
    # events field is always at offset 0, little-endian UInt32.
    (buf + 0).init_pointee_copy(UInt8(events & 0xFF))
    (buf + 1).init_pointee_copy(UInt8((events >> 8) & 0xFF))
    (buf + 2).init_pointee_copy(UInt8((events >> 16) & 0xFF))
    (buf + 3).init_pointee_copy(UInt8((events >> 24) & 0xFF))

    # x86_64 packs the struct: data starts at offset 4. aarch64 keeps natural
    # alignment: 4 bytes of padding then data at offset 8.
    comptime if not CompilationTarget.is_x86():
        (buf + 4).init_pointee_copy(UInt8(0))
        (buf + 5).init_pointee_copy(UInt8(0))
        (buf + 6).init_pointee_copy(UInt8(0))
        (buf + 7).init_pointee_copy(UInt8(0))

    # data.u64 is 8 bytes, little-endian.
    var off = EPOLL_EVENT_DATA_OFF
    for i in range(8):
        (buf + off + i).init_pointee_copy(
            UInt8((data_u64 >> UInt64(8 * i)) & 0xFF)
        )


@always_inline
def _epoll_event_read_events(buf: UnsafePointer[UInt8, _]) -> UInt32:
    """Read the ``events`` field from an ``epoll_event`` buffer."""
    return (
        UInt32((buf + 0).load())
        | (UInt32((buf + 1).load()) << 8)
        | (UInt32((buf + 2).load()) << 16)
        | (UInt32((buf + 3).load()) << 24)
    )


@always_inline
def _epoll_event_read_data(buf: UnsafePointer[UInt8, _]) -> UInt64:
    """Read ``data.u64`` from an ``epoll_event`` buffer."""
    var off = EPOLL_EVENT_DATA_OFF
    var v: UInt64 = 0
    for i in range(8):
        v |= UInt64((buf + off + i).load()) << UInt64(8 * i)
    return v


# ──────────────────────────────────────────────────────────────────────────────
# Kevent struct-field helpers (macOS)
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _kevent_set(
    buf: UnsafePointer[UInt8, _],
    ident: UInt64,
    filter: Int16,
    flags: UInt16,
    fflags: UInt32,
    data: Int64,
    udata: UInt64,
) where type_of(buf).mut:
    """Populate one ``struct kevent`` in-place.

    Args:
        buf: Pointer to ``KEVENT_SIZE``-byte buffer.
        ident: Identifier (usually an fd).
        filter: ``EVFILT_READ``, ``EVFILT_WRITE``, ``EVFILT_TIMER``,
                ``EVFILT_USER``.
        flags: ``EV_ADD | EV_ENABLE | EV_ONESHOT | ...``.
        fflags: Filter-specific flags (e.g. ``NOTE_TRIGGER`` for EVFILT_USER).
        data: Filter-specific data (e.g. timer duration).
        udata: User token, stored in ``udata`` field.
    """
    # ident: 8 bytes LE
    for i in range(8):
        (buf + KEVENT_IDENT_OFF + i).init_pointee_copy(
            UInt8((ident >> UInt64(8 * i)) & 0xFF)
        )
    # filter: 2 bytes LE (Int16 -> two's complement via UInt16 bit-cast)
    var f16 = UInt16(filter & 0xFFFF) if filter >= 0 else UInt16(
        (UInt32(Int32(filter)) & 0xFFFF)
    )
    (buf + KEVENT_FILTER_OFF + 0).init_pointee_copy(UInt8(f16 & 0xFF))
    (buf + KEVENT_FILTER_OFF + 1).init_pointee_copy(UInt8((f16 >> 8) & 0xFF))
    # flags: 2 bytes LE
    (buf + KEVENT_FLAGS_OFF + 0).init_pointee_copy(UInt8(flags & 0xFF))
    (buf + KEVENT_FLAGS_OFF + 1).init_pointee_copy(UInt8((flags >> 8) & 0xFF))
    # fflags: 4 bytes LE
    for i in range(4):
        (buf + KEVENT_FFLAGS_OFF + i).init_pointee_copy(
            UInt8((fflags >> UInt32(8 * i)) & 0xFF)
        )
    # data: 8 bytes LE (treat as bit pattern; caller supplies non-negative
    # values for our use-cases)
    var d64 = UInt64(data) if data >= 0 else UInt64(Int(data))
    for i in range(8):
        (buf + KEVENT_DATA_OFF + i).init_pointee_copy(
            UInt8((d64 >> UInt64(8 * i)) & 0xFF)
        )
    # udata: 8 bytes LE
    for i in range(8):
        (buf + KEVENT_UDATA_OFF + i).init_pointee_copy(
            UInt8((udata >> UInt64(8 * i)) & 0xFF)
        )


@always_inline
def _kevent_read_ident(buf: UnsafePointer[UInt8, _]) -> UInt64:
    """Read the ``ident`` field from a ``kevent`` buffer."""
    var v: UInt64 = 0
    for i in range(8):
        v |= UInt64((buf + KEVENT_IDENT_OFF + i).load()) << UInt64(8 * i)
    return v


@always_inline
def _kevent_read_filter(buf: UnsafePointer[UInt8, _]) -> Int16:
    """Read the ``filter`` field from a ``kevent`` buffer."""
    var lo = UInt16((buf + KEVENT_FILTER_OFF + 0).load())
    var hi = UInt16((buf + KEVENT_FILTER_OFF + 1).load())
    var v = lo | (hi << 8)
    return Int16(v) if v < 0x8000 else Int16(Int(v) - 0x10000)


@always_inline
def _kevent_read_flags(buf: UnsafePointer[UInt8, _]) -> UInt16:
    """Read the ``flags`` field from a ``kevent`` buffer."""
    return UInt16((buf + KEVENT_FLAGS_OFF + 0).load()) | (
        UInt16((buf + KEVENT_FLAGS_OFF + 1).load()) << 8
    )


@always_inline
def _kevent_read_fflags(buf: UnsafePointer[UInt8, _]) -> UInt32:
    """Read the ``fflags`` field from a ``kevent`` buffer."""
    var v: UInt32 = 0
    for i in range(4):
        v |= UInt32((buf + KEVENT_FFLAGS_OFF + i).load()) << UInt32(8 * i)
    return v


@always_inline
def _kevent_read_udata(buf: UnsafePointer[UInt8, _]) -> UInt64:
    """Read the ``udata`` field from a ``kevent`` buffer."""
    var v: UInt64 = 0
    for i in range(8):
        v |= UInt64((buf + KEVENT_UDATA_OFF + i).load()) << UInt64(8 * i)
    return v


# ──────────────────────────────────────────────────────────────────────────────
# Epoll syscalls (Linux)
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _epoll_create1(flags: c_int) -> c_int:
    """Wrapper around ``epoll_create1(2)``.

    Args:
        flags: ``0`` or ``EPOLL_CLOEXEC``.

    Returns:
        New epoll fd on success, -1 on error.
    """
    return external_call["epoll_create1", c_int](flags)


@always_inline
def _epoll_ctl(
    epfd: c_int, op: c_int, fd: c_int, event: UnsafePointer[UInt8, _]
) -> c_int:
    """Wrapper around ``epoll_ctl(2)``.

    Args:
        epfd: epoll fd from ``epoll_create1``.
        op: ``EPOLL_CTL_ADD``, ``EPOLL_CTL_MOD``, or ``EPOLL_CTL_DEL``.
        fd: Target fd to register/modify/remove.
        event: Pointer to a populated ``epoll_event`` buffer (ignored for
               ``EPOLL_CTL_DEL`` but kernel still expects non-NULL on some
               kernels; pass a valid buffer even for DEL).

    Returns:
        0 on success, -1 on error.
    """
    return external_call["epoll_ctl", c_int](
        epfd, op, fd, event.bitcast[NoneType]()
    )


@always_inline
def _epoll_wait(
    epfd: c_int,
    events: UnsafePointer[UInt8, _],
    maxevents: c_int,
    timeout_ms: c_int,
) -> c_int:
    """Wrapper around ``epoll_wait(2)``.

    Args:
        epfd: epoll fd.
        events: Pointer to an array of ``maxevents`` ``epoll_event``
                    structs (each ``EPOLL_EVENT_SIZE`` bytes).
        maxevents: Maximum events to return; must be > 0.
        timeout_ms: Milliseconds to block; -1 blocks indefinitely, 0 polls.

    Returns:
        Number of events written to ``events`` on success (0 on timeout),
        -1 on error (errno set; EINTR is normal).
    """
    return external_call["epoll_wait", c_int](
        epfd, events.bitcast[NoneType](), maxevents, timeout_ms
    )


# ──────────────────────────────────────────────────────────────────────────────
# Kqueue syscalls (macOS)
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _kqueue() -> c_int:
    """Wrapper around ``kqueue(2)``.

    macOS only; on Linux the symbol does not exist in libc, so we gate the
    ``external_call`` behind a ``comptime if`` to keep the JIT's symbol
    resolver from failing the whole module at link time. Linux callers
    always take the epoll path and never invoke this function at runtime;
    the stub return of ``-1`` is just a compile-time placeholder.

    Returns:
        New kqueue fd on success, -1 on error (always -1 on Linux).
    """
    comptime if CompilationTarget.is_macos():
        return external_call["kqueue", c_int]()
    else:
        return c_int(-1)


@always_inline
def _kevent(
    kq: c_int,
    changelist: UnsafePointer[UInt8, _],
    nchanges: c_int,
    eventlist: UnsafePointer[UInt8, _],
    nevents: c_int,
    timeout: UnsafePointer[UInt8, _],
) -> c_int:
    """Wrapper around ``kevent(2)``.

    Registers the ``changelist`` (``nchanges`` events) and waits for events
    on ``eventlist`` (up to ``nevents`` events).

    macOS only: on Linux the ``kevent`` symbol is absent, so the
    ``external_call`` is guarded by a ``comptime if`` to prevent the JIT
    from rejecting the whole module at link time. Linux callers take the
    epoll path; the stub return of ``-1`` is just a compile-time
    placeholder so the Mojo module still type-checks there.

    Args:
        kq: kqueue fd.
        changelist: Pointer to array of changes (kevent structs). May be
                    NULL (pass stack_allocation base) if ``nchanges == 0``.
        nchanges: Number of entries in ``changelist``.
        eventlist: Pointer to output array for received events.
        nevents: Max events to receive.
        timeout: Pointer to ``struct timespec`` (16 bytes: tv_sec + tv_nsec).
                    Pass NULL for infinite, or a populated timespec for
                    bounded wait.

    Returns:
        Number of events placed in ``eventlist`` (0 on timeout), -1 on
        error (always -1 on Linux).
    """
    comptime if CompilationTarget.is_macos():
        return external_call["kevent", c_int](
            kq,
            changelist.bitcast[NoneType](),
            nchanges,
            eventlist.bitcast[NoneType](),
            nevents,
            timeout.bitcast[NoneType](),
        )
    else:
        return c_int(-1)


# ──────────────────────────────────────────────────────────────────────────────
# Wakeup primitives: eventfd (Linux) + pipe (cross-platform fallback)
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _eventfd(initval: c_uint, flags: c_int) -> c_int:
    """Wrapper around ``eventfd(2)`` (Linux only).

    Creates a counter-backed fd used as a cross-thread wakeup primitive.
    Writing any 8-byte uint64 increments the counter; reading drains.
    With ``EFD_NONBLOCK``, reads return EAGAIN when the counter is 0.

    Args:
        initval: Initial value of the internal counter.
        flags: ``EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE``.

    Returns:
        New eventfd on success, -1 on error.

    Note:
        Linux only. On macOS callers should use ``_pipe`` + self-pipe trick.
    """
    return external_call["eventfd", c_int](initval, flags)


@always_inline
def _pipe(fds: UnsafePointer[c_int, _]) -> c_int:
    """Wrapper around ``pipe(2)``.

    Creates a pair of connected fds: ``fds[0]`` is the read end, ``fds[1]``
    is the write end. Used for the self-pipe wakeup trick on macOS and as a
    fallback on Linux.

    Args:
        fds: Pointer to a 2-element ``c_int`` array; filled in on success.

    Returns:
        0 on success, -1 on error.
    """
    return external_call["pipe", c_int](fds.bitcast[NoneType]())
