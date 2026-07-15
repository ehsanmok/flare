"""Internal libc socket bindings — not part of the public API.

All raw system calls used by ``flare.net``, ``flare.tcp``, ``flare.udp``
and ``flare.dns`` live here. Higher-level modules import from this file
rather than calling ``external_call`` directly.

Platform quirks handled here:
- macOS ``sockaddr_in`` has an extra ``sin_len`` byte (BSD-style).
- ``errno`` is accessed via ``__error()`` on macOS, ``__errno_location()``
  on Linux; use the stdlib ``get_errno()`` from ``ffi`` instead.
- Socket-option constants differ between Linux and macOS.

Safety contract:
    Every function that returns a negative value on failure calls
    ``get_errno()`` **immediately** after the failing call, before any
    other libc function that could clobber errno.
"""

from std.ffi import (
    external_call,
    c_int,
    c_uint,
    c_size_t,
    c_ssize_t,
    c_char,
    get_errno,
    ErrNo,
    OwnedDLHandle,
    CStringSlice,
)
from std.memory import UnsafePointer, stack_allocation
from std.sys.info import CompilationTarget, platform_map
from std.os import getenv

from ..utils.dylib import find_flare_lib

# ── platform_map shorthand ────────────────────────────────────────────────────
comptime _pm = platform_map[T=Int, ...]

# ── Address families ──────────────────────────────────────────────────────────
comptime AF_UNSPEC: c_int = 0
comptime AF_INET: c_int = 2
comptime AF_INET6: c_int = c_int(_pm["AF_INET6", linux=10, macos=30]())

# ── Socket types ──────────────────────────────────────────────────────────────
comptime SOCK_STREAM: c_int = 1
comptime SOCK_DGRAM: c_int = 2

# ── Protocol numbers ──────────────────────────────────────────────────────────
comptime IPPROTO_TCP: c_int = 6
comptime IPPROTO_UDP: c_int = 17

# ── SOL_SOCKET + options ──────────────────────────────────────────────────────
comptime SOL_SOCKET: c_int = c_int(_pm["SOL_SOCKET", linux=1, macos=0xFFFF]())
comptime SO_REUSEADDR: c_int = c_int(_pm["SO_REUSEADDR", linux=2, macos=4]())
comptime SO_REUSEPORT: c_int = c_int(
    _pm["SO_REUSEPORT", linux=15, macos=0x0200]()
)
comptime SO_KEEPALIVE: c_int = c_int(_pm["SO_KEEPALIVE", linux=9, macos=8]())
comptime SO_RCVTIMEO: c_int = c_int(
    _pm["SO_RCVTIMEO", linux=20, macos=0x1006]()
)
comptime SO_SNDTIMEO: c_int = c_int(
    _pm["SO_SNDTIMEO", linux=21, macos=0x1005]()
)
comptime SO_SNDBUF: c_int = c_int(_pm["SO_SNDBUF", linux=7, macos=0x1001]())
comptime SO_RCVBUF: c_int = c_int(_pm["SO_RCVBUF", linux=8, macos=0x1002]())

# ── TCP options ───────────────────────────────────────────────────────────────
comptime TCP_NODELAY: c_int = 1

# ── fcntl ─────────────────────────────────────────────────────────────────────
comptime F_GETFL: c_int = 3
comptime F_SETFL: c_int = 4
comptime O_NONBLOCK: c_int = c_int(_pm["O_NONBLOCK", linux=2048, macos=4]())

# ── Sentinel ──────────────────────────────────────────────────────────────────
comptime INVALID_FD: c_int = -1

# ── Sockaddr sizes ────────────────────────────────────────────────────────────
comptime SOCKADDR_IN_SIZE: c_uint = 16
comptime SOCKADDR_IN6_SIZE: c_uint = 28

# ── Timeval struct size (for SO_RCVTIMEO / SO_SNDTIMEO) ──────────────────────
comptime TIMEVAL_SIZE: c_uint = 16  # 8 bytes tv_sec + 8 bytes tv_usec on 64-bit

# ── POSIX send/recv flags ─────────────────────────────────────────────────────
comptime MSG_NOSIGNAL: c_int = c_int(
    _pm["MSG_NOSIGNAL", linux=0x4000, macos=0]()
)
# Per-call non-blocking flag for recv/send so a batched drain loop
# avoids changing SO_RCVTIMEO each iteration.
comptime MSG_DONTWAIT: c_int = c_int(
    _pm["MSG_DONTWAIT", linux=0x40, macos=0x80]()
)
# macOS: MSG_NOSIGNAL = 0 (not supported). Use SO_NOSIGPIPE socket option to
# suppress SIGPIPE delivery when writing to a broken connection.
comptime SO_NOSIGPIPE: c_int = c_int(
    _pm["SO_NOSIGPIPE", linux=0, macos=0x1022]()
)

# ── SO_ERROR (for non-blocking connect result check) ──────────────────────────
comptime SO_ERROR: c_int = c_int(_pm["SO_ERROR", linux=4, macos=0x1007]())

# ── shutdown(2) how values ────────────────────────────────────────────────────
comptime SHUT_RD: c_int = 0
comptime SHUT_WR: c_int = 1
comptime SHUT_RDWR: c_int = 2

# ── poll(2) event bits ────────────────────────────────────────────────────────
comptime POLLOUT: c_int = 4
comptime POLLERR: c_int = 8
comptime POLLHUP: c_int = 16

# ── SO_BROADCAST ──────────────────────────────────────────────────────────────
comptime SO_BROADCAST: c_int = c_int(
    _pm["SO_BROADCAST", linux=6, macos=0x0020]()
)

# ── pollfd struct size ─────────────────────────────────────────────────────────
# struct pollfd { int fd; short events; short revents; } = 8 bytes
comptime POLLFD_SIZE: Int = 8

# ── getaddrinfo ───────────────────────────────────────────────────────────────
comptime AI_PASSIVE: c_int = c_int(_pm["AI_PASSIVE", linux=1, macos=1]())
comptime AI_NUMERICHOST: c_int = c_int(
    _pm["AI_NUMERICHOST", linux=4, macos=4]()
)
comptime NI_MAXHOST: Int = 1025
comptime NI_MAXSERV: Int = 32

# ── addrinfo struct byte layout ───────────────────────────────────────────────
# Field order differs between macOS (BSD) and Linux:
#
# macOS (BSD) – ai_canonname before ai_addr:
# ai_flags : int32 @ 0
# ai_family : int32 @ 4
# ai_socktype : int32 @ 8
# ai_protocol : int32 @ 12
# ai_addrlen : uint32 @ 16
# (pad 4 bytes) @ 20
# ai_canonname : *char @ 24
# ai_addr : *sockaddr @ 32
# ai_next : *addrinfo @ 40 total = 48 bytes
#
# Linux – ai_addr before ai_canonname:
# ai_flags : int32 @ 0
# ai_family : int32 @ 4
# ai_socktype : int32 @ 8
# ai_protocol : int32 @ 12
# ai_addrlen : uint32 @ 16
# (pad 4 bytes) @ 20
# ai_addr : *sockaddr @ 24
# ai_canonname : *char @ 32
# ai_next : *addrinfo @ 40 total = 48 bytes
comptime ADDRINFO_AI_FAMILY_OFF: Int = 4
comptime ADDRINFO_AI_SOCKTYPE_OFF: Int = 8
comptime ADDRINFO_AI_ADDRLEN_OFF: Int = 16
comptime ADDRINFO_AI_ADDR_OFF: Int = _pm["AI_ADDR_OFF", linux=24, macos=32]()
comptime ADDRINFO_AI_NEXT_OFF: Int = 40
comptime ADDRINFO_SIZE: Int = 48


# ──────────────────────────────────────────────────────────────────────────────
# Byte-order helpers
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _htons(x: UInt16) -> UInt16:
    """Convert a ``UInt16`` from host byte order to network (big-endian) order.

    All target platforms (macOS ARM64, Linux x86_64/aarch64) are
    little-endian, so this is always a byte swap.
    """
    return ((x & 0xFF) << 8) | (x >> 8)


@always_inline
def _ntohs(x: UInt16) -> UInt16:
    """Convert a ``UInt16`` from network byte order to host order."""
    return _htons(x)  # byte-swap is its own inverse


@always_inline
def _htonl(x: UInt32) -> UInt32:
    """Convert a ``UInt32`` from host byte order to network (big-endian) order.
    """
    return (
        ((x & 0xFF) << 24)
        | (((x >> 8) & 0xFF) << 16)
        | (((x >> 16) & 0xFF) << 8)
        | (x >> 24)
    )


# ──────────────────────────────────────────────────────────────────────────────
# sockaddr helpers
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _fill_sockaddr_in(
    buf: UnsafePointer[UInt8, _],
    port: UInt16,
    ip_bytes: UnsafePointer[UInt8, _],
) where type_of(buf).mut:
    """Populate a 16-byte IPv4 ``sockaddr_in`` buffer in-place.

    Args:
        buf: Caller-allocated 16-byte uninitialized buffer.
        port: Port in host byte order; stored as big-endian.
        ip_bytes: 4-byte IPv4 address in network byte order (from
                  ``inet_pton``).

    Safety:
        ``buf`` must point to at least 16 bytes of uninitialized (or
        trivially-destructible initialized) memory. ``ip_bytes`` must
        point to at least 4 valid bytes.
    """

    comptime if CompilationTarget.is_macos():
        # BSD-style: first byte is struct length, second is family
        (buf + 0).init_pointee_copy(UInt8(16))  # sin_len
        (buf + 1).init_pointee_copy(UInt8(2))  # AF_INET
    else:
        # Linux: sin_family as little-endian UInt16 → [2, 0]
        (buf + 0).init_pointee_copy(UInt8(2))  # family low byte
        (buf + 1).init_pointee_copy(UInt8(0))  # family high byte

    # Port in network byte order (big-endian)
    (buf + 2).init_pointee_copy(UInt8(port >> 8))
    (buf + 3).init_pointee_copy(UInt8(port & 0xFF))

    # IPv4 address (already in network byte order from inet_pton)
    (buf + 4).init_pointee_copy((ip_bytes + 0).load())
    (buf + 5).init_pointee_copy((ip_bytes + 1).load())
    (buf + 6).init_pointee_copy((ip_bytes + 2).load())
    (buf + 7).init_pointee_copy((ip_bytes + 3).load())
    # bytes 8-15 remain zero-initialised by caller (sin_zero padding)


@always_inline
def _fill_sockaddr_in6(
    buf: UnsafePointer[UInt8, _],
    port: UInt16,
    ip_bytes: UnsafePointer[UInt8, _],
) where type_of(buf).mut:
    """Populate a 28-byte IPv6 ``sockaddr_in6`` buffer in-place.

    Layout (28 bytes):
        - [0-1] sin6_family (AF_INET6) — BSD: [len, family]; Linux: [family_lo, family_hi]
        - [2-3] sin6_port (big-endian)
        - [4-7] sin6_flowinfo (zeroed)
        - [8-23] sin6_addr (16-byte IPv6 address, from ``inet_pton``)
        - [24-27] sin6_scope_id (zeroed)

    Args:
        buf: Caller-allocated 28-byte buffer.
        port: Port in host byte order; stored as big-endian.
        ip_bytes: 16-byte IPv6 address in network byte order.

    Safety:
        ``buf`` must point to at least 28 bytes. ``ip_bytes`` must
        point to at least 16 valid bytes.
    """
    var af6 = Int(AF_INET6)

    comptime if CompilationTarget.is_macos():
        (buf + 0).init_pointee_copy(UInt8(28))  # sin6_len
        (buf + 1).init_pointee_copy(UInt8(af6))  # AF_INET6
    else:
        (buf + 0).init_pointee_copy(UInt8(af6 & 0xFF))
        (buf + 1).init_pointee_copy(UInt8((af6 >> 8) & 0xFF))

    # Port in network byte order
    (buf + 2).init_pointee_copy(UInt8(port >> 8))
    (buf + 3).init_pointee_copy(UInt8(port & 0xFF))

    # sin6_flowinfo (4 bytes zeroed)
    for i in range(4, 8):
        (buf + i).init_pointee_copy(UInt8(0))

    # sin6_addr (16 bytes)
    for i in range(16):
        (buf + 8 + i).init_pointee_copy((ip_bytes + i).load())

    # sin6_scope_id (4 bytes zeroed)
    for i in range(24, 28):
        (buf + i).init_pointee_copy(UInt8(0))


@always_inline
def _read_port_from_sockaddr(buf: UnsafePointer[UInt8, _]) -> UInt16:
    """Extract and byte-swap the port from a ``sockaddr_in`` buffer.

    Args:
        buf: Pointer to a 16-byte ``sockaddr_in`` buffer returned by
             ``getsockname`` or ``getpeername``.

    Returns:
        The port in host byte order.
    """
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "_read_port_from_sockaddr: null sockaddr buffer"
    )
    # buf[2] is the high byte and buf[3] is the low byte of the port in
    # network byte order (big-endian). Reconstructing the integer manually
    # as (high << 8 | low) already yields the host-byte-order value on
    # little-endian platforms (x86-64, ARM64). Applying _ntohs here would
    # byte-swap a second time and produce a wrong result.
    return UInt16(buf[2]) << 8 | UInt16(buf[3])


@always_inline
def _read_ip_from_sockaddr(buf: UnsafePointer[UInt8, _]) raises -> String:
    """Extract the IPv4 address string from a ``sockaddr_in`` buffer.

    Args:
        buf: Pointer to a 16-byte ``sockaddr_in``.

    Returns:
        The dotted-decimal IPv4 string (e.g. ``"192.168.1.1"``).

    Raises:
        Error: If ``inet_ntop`` fails.

    Safety:
        ``buf`` must be a valid ``sockaddr_in`` returned by the kernel.
    """
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "_read_ip_from_sockaddr: null sockaddr buffer"
    )
    var ntop_buf = stack_allocation[64, UInt8]()
    for i in range(64):
        (ntop_buf + i).init_pointee_copy(0)

    # inet_ntop(AF_INET, &sin_addr, dst, dst_len) — sin_addr is at offset 4
    _ = external_call["inet_ntop", UnsafePointer[UInt8, MutUntrackedOrigin]](
        AF_INET,
        (buf + 4).bitcast[NoneType](),
        ntop_buf.bitcast[c_char](),
        c_uint(64),
    )
    if ntop_buf[0] == 0:
        raise Error("inet_ntop failed: errno " + String(get_errno()))
    return String(
        StringSlice(
            unsafe_from_utf8=CStringSlice(
                unsafe_from_ptr=ntop_buf.bitcast[Int8]()
            )
        )
    )


@always_inline
def _read_ipv6_from_sockaddr(buf: UnsafePointer[UInt8, _]) raises -> String:
    """Extract the IPv6 address string from a ``sockaddr_in6`` buffer.

    Args:
        buf: Pointer to a 28-byte ``sockaddr_in6``.

    Returns:
        The IPv6 address string (e.g. ``"::1"``).

    Raises:
        Error: If ``inet_ntop`` fails.
    """
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "_read_ipv6_from_sockaddr: null sockaddr buffer"
    )
    var ntop_buf = stack_allocation[64, UInt8]()
    for i in range(64):
        (ntop_buf + i).init_pointee_copy(0)

    # inet_ntop(AF_INET6, &sin6_addr, dst, dst_len) — sin6_addr at offset 8
    _ = external_call["inet_ntop", UnsafePointer[UInt8, MutUntrackedOrigin]](
        AF_INET6,
        (buf + 8).bitcast[NoneType](),
        ntop_buf.bitcast[c_char](),
        c_uint(64),
    )
    if ntop_buf[0] == 0:
        raise Error("inet_ntop (IPv6) failed: errno " + String(get_errno()))
    return String(
        StringSlice(
            unsafe_from_utf8=CStringSlice(
                unsafe_from_ptr=ntop_buf.bitcast[Int8]()
            )
        )
    )


@always_inline
def _get_family_from_sockaddr(buf: UnsafePointer[UInt8, _]) -> c_int:
    """Read the address family from a sockaddr buffer.

    Handles both Linux (sa_family at offset 0, 2 bytes LE) and macOS/BSD
    (sa_family at offset 1, 1 byte).

    Returns:
        ``AF_INET`` or ``AF_INET6``.
    """
    comptime if CompilationTarget.is_macos():
        return c_int(Int(buf[1]))
    else:
        return c_int(Int(buf[0]) | (Int(buf[1]) << 8))


# ──────────────────────────────────────────────────────────────────────────────
# errno → typed error helpers
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _strerror(code: c_int) -> String:
    """Call ``strerror(code)`` and return the result as a ``String``.

    Args:
        code: The errno value to describe.

    Returns:
        The human-readable error string.
    """
    var ptr = external_call[
        "strerror", UnsafePointer[UInt8, MutUntrackedOrigin]
    ](code)
    if ptr[0] == 0:
        return "unknown error " + String(code)
    return String(
        StringSlice(
            unsafe_from_utf8=CStringSlice(unsafe_from_ptr=ptr.bitcast[Int8]())
        )
    )


@always_inline
def _os_error(op: String) -> String:
    """Return a formatted error string from the current ``errno``.

    Args:
        op: Name of the failing operation (e.g. ``"connect"``).

    Returns:
        String like ``"connect: Connection refused (errno 111)"``.
    """
    var e = get_errno()
    return op + ": " + _strerror(e.value) + " (errno " + String(e.value) + ")"


# ──────────────────────────────────────────────────────────────────────────────
# Core socket system calls
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _socket(family: c_int, kind: c_int, protocol: c_int) -> c_int:
    """Wrapper around ``socket(2)``.

    Returns:
        File descriptor on success, ``INVALID_FD`` on failure (errno set).
    """
    return external_call["socket", c_int](family, kind, protocol)


@always_inline
def _close(fd: c_int) -> c_int:
    """Wrapper around ``close(2)``."""
    return external_call["close", c_int](fd)


@always_inline
def _bind(fd: c_int, addr: UnsafePointer[UInt8, _], addrlen: c_uint) -> c_int:
    """Wrapper around ``bind(2)``."""
    debug_assert[assert_mode="safe"](
        Int(addr) != 0 and Int(addrlen) > 0,
        "_bind: null addr or zero addrlen",
    )
    return external_call["bind", c_int](fd, addr.bitcast[NoneType](), addrlen)


@always_inline
def _listen(fd: c_int, backlog: c_int) -> c_int:
    """Wrapper around ``listen(2)``."""
    return external_call["listen", c_int](fd, backlog)


@always_inline
def _accept(
    fd: c_int,
    addr: UnsafePointer[UInt8, _],
    addrlen: UnsafePointer[c_uint, _],
) -> c_int:
    """Wrapper around ``accept(2)``."""
    debug_assert[assert_mode="safe"](
        Int(addr) != 0 and Int(addrlen) != 0,
        "_accept: null addr / addrlen out-parameter",
    )
    return external_call["accept", c_int](fd, addr.bitcast[NoneType](), addrlen)


@always_inline
def _connect(
    fd: c_int, addr: UnsafePointer[UInt8, _], addrlen: c_uint
) -> c_int:
    """Wrapper around ``connect(2)``."""
    debug_assert[assert_mode="safe"](
        Int(addr) != 0 and Int(addrlen) > 0,
        "_connect: null addr or zero addrlen",
    )
    return external_call["connect", c_int](
        fd, addr.bitcast[NoneType](), addrlen
    )


@always_inline
def _getsockname(
    fd: c_int,
    addr: UnsafePointer[UInt8, _],
    addrlen: UnsafePointer[c_uint, _],
) -> c_int:
    """Wrapper around ``getsockname(2)``."""
    debug_assert[assert_mode="safe"](
        Int(addr) != 0 and Int(addrlen) != 0,
        "_getsockname: null addr / addrlen out-parameter",
    )
    return external_call["getsockname", c_int](
        fd, addr.bitcast[NoneType](), addrlen
    )


@always_inline
def _getpeername(
    fd: c_int,
    addr: UnsafePointer[UInt8, _],
    addrlen: UnsafePointer[c_uint, _],
) -> c_int:
    """Wrapper around ``getpeername(2)``."""
    debug_assert[assert_mode="safe"](
        Int(addr) != 0 and Int(addrlen) != 0,
        "_getpeername: null addr / addrlen out-parameter",
    )
    return external_call["getpeername", c_int](
        fd, addr.bitcast[NoneType](), addrlen
    )


@always_inline
def _send(
    fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t, flags: c_int
) -> c_ssize_t:
    """Wrapper around ``send(2)``."""
    debug_assert[assert_mode="safe"](
        Int(n) == 0 or Int(buf) != 0, "_send: null buffer with non-zero length"
    )
    return external_call["send", c_ssize_t](
        fd, buf.bitcast[NoneType](), n, flags
    )


@always_inline
def _writev(
    fd: c_int, iov: UnsafePointer[UInt8, _], iovcnt: c_int
) -> c_ssize_t:
    """Wrapper around ``writev(2)``.

    ``iov`` is a pointer to a contiguous array of ``iovcnt``
    ``struct iovec`` cells. Each cell is laid out as
    ``{ void *iov_base; size_t iov_len; }`` — 16 bytes on every
    64-bit Linux / macOS target. The caller is responsible for
    constructing that buffer (typically via
    ``flare.runtime.iovec.IoVecBuf`` which packs the pairs into
    ``stack_allocation`` or ``alloc`` memory).

    Returns the number of bytes written across all vectors, or a
    negative value on failure (with ``errno`` set per the usual
    libc convention).
    """
    debug_assert[assert_mode="safe"](
        Int(iovcnt) >= 0 and (Int(iovcnt) == 0 or Int(iov) != 0),
        "_writev: null iovec array with non-zero iovcnt",
    )
    return external_call["writev", c_ssize_t](
        fd, iov.bitcast[NoneType](), iovcnt
    )


@always_inline
def _recv(
    fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t, flags: c_int
) -> c_ssize_t:
    """Wrapper around ``recv(2)``."""
    debug_assert[assert_mode="safe"](
        Int(n) == 0 or Int(buf) != 0, "_recv: null buffer with non-zero length"
    )
    return external_call["recv", c_ssize_t](
        fd, buf.bitcast[NoneType](), n, flags
    )


@always_inline
def _sendto(
    fd: c_int,
    buf: UnsafePointer[UInt8, _],
    n: c_size_t,
    flags: c_int,
    addr: UnsafePointer[UInt8, _],
    addrlen: c_uint,
) -> c_ssize_t:
    """Wrapper around ``sendto(2)``."""
    return external_call["sendto", c_ssize_t](
        fd,
        buf.bitcast[NoneType](),
        n,
        flags,
        addr.bitcast[NoneType](),
        addrlen,
    )


@always_inline
def _recvfrom(
    fd: c_int,
    buf: UnsafePointer[UInt8, _],
    n: c_size_t,
    flags: c_int,
    addr: UnsafePointer[UInt8, _],
    addrlen: UnsafePointer[c_uint, _],
) -> c_ssize_t:
    """Wrapper around ``recvfrom(2)``."""
    return external_call["recvfrom", c_ssize_t](
        fd,
        buf.bitcast[NoneType](),
        n,
        flags,
        addr.bitcast[NoneType](),
        addrlen,
    )


@always_inline
def _recvmmsg(
    fd: c_int,
    msgvec: UnsafePointer[UInt8, _],
    vlen: c_uint,
    flags: c_int,
    timeout: Int,
) -> c_int:
    """Wrapper around Linux ``recvmmsg(2)``.

    ``msgvec`` points at a contiguous ``struct mmsghdr[vlen]`` array
    (64 bytes per cell on x86_64 / aarch64 Linux). The caller owns
    and lays out that buffer (see ``flare.udp.batch.BatchReceiver``).
    Returns the number of messages received, or a negative value with
    ``errno`` set. ``ENOSYS`` means the running kernel lacks the
    syscall and the caller must fall back to per-datagram ``recvfrom``.
    Linux-only: not present on macOS.

    ``timeout`` is the address of a ``struct timespec`` or ``0`` for a
    NULL timeout. Pass ``0`` together with ``MSG_DONTWAIT`` to drain
    every immediately-available datagram in one call without blocking;
    a non-NULL ``{0,0}`` timespec would instead make the kernel return
    after the first datagram (per-message timeout check).
    """
    debug_assert[assert_mode="safe"](
        Int(vlen) == 0 or Int(msgvec) != 0,
        "_recvmmsg: null msgvec with non-zero vlen",
    )
    comptime if CompilationTarget.is_linux():
        return external_call["recvmmsg", c_int](
            fd, msgvec.bitcast[NoneType](), vlen, flags, timeout
        )
    else:
        # recvmmsg(2) is Linux-only; on other targets the symbol does not
        # exist so referencing it at all breaks JIT materialization. The
        # comptime gate keeps the symbol out of non-Linux builds. Callers
        # are guarded by udp_batch_supported() and never reach this branch.
        _ = (fd, msgvec, vlen, flags, timeout)
        return c_int(-1)


@always_inline
def _sendmmsg(
    fd: c_int,
    msgvec: UnsafePointer[UInt8, _],
    vlen: c_uint,
    flags: c_int,
) -> c_int:
    """Wrapper around Linux ``sendmmsg(2)``.

    Sends up to ``vlen`` datagrams in one syscall; returns the number
    of messages sent (each cell's ``msg_len`` is updated with the byte
    count). ``ENOSYS`` => fall back to per-datagram ``sendto``.
    Linux-only.
    """
    debug_assert[assert_mode="safe"](
        Int(vlen) == 0 or Int(msgvec) != 0,
        "_sendmmsg: null msgvec with non-zero vlen",
    )
    comptime if CompilationTarget.is_linux():
        return external_call["sendmmsg", c_int](
            fd, msgvec.bitcast[NoneType](), vlen, flags
        )
    else:
        # sendmmsg(2) is Linux-only; gate the symbol out of non-Linux
        # builds (see _recvmmsg). Callers are guarded by
        # udp_batch_supported() and never reach this branch.
        _ = (fd, msgvec, vlen, flags)
        return c_int(-1)


@always_inline
def _sendmsg(
    fd: c_int,
    msg: UnsafePointer[UInt8, _],
    flags: c_int,
) -> c_ssize_t:
    """Wrapper around ``sendmsg(2)``.

    Used for UDP GSO (generic segmentation offload): a single
    ``struct msghdr`` carrying one big buffer plus a ``UDP_SEGMENT``
    control message tells the kernel to slice the buffer into wire
    datagrams of the cmsg's segment size. Returns bytes accepted.
    """
    debug_assert[assert_mode="safe"](
        Int(msg) != 0, "_sendmsg: null msghdr pointer"
    )
    return external_call["sendmsg", c_ssize_t](
        fd, msg.bitcast[NoneType](), flags
    )


@always_inline
def _setsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: UnsafePointer[UInt8, _],
    optlen: c_uint,
) -> c_int:
    """Wrapper around ``setsockopt(2)``."""
    return external_call["setsockopt", c_int](
        fd, level, optname, optval.bitcast[NoneType](), optlen
    )


@always_inline
def _fcntl2(fd: c_int, cmd: c_int, arg: c_int) -> c_int:
    """Wrapper around ``fcntl(fd, cmd, arg)``."""
    return external_call["fcntl", c_int](fd, cmd, arg)


@always_inline
def _shutdown(fd: c_int, how: c_int) -> c_int:
    """Wrapper around ``shutdown(2)``."""
    return external_call["shutdown", c_int](fd, how)


@always_inline
def _getsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: UnsafePointer[UInt8, _],
    optlen: UnsafePointer[c_uint, _],
) -> c_int:
    """Wrapper around ``getsockopt(2)``."""
    return external_call["getsockopt", c_int](
        fd, level, optname, optval.bitcast[NoneType](), optlen
    )


@always_inline
def _poll(
    fds: UnsafePointer[UInt8, _], nfds: c_uint, timeout_ms: c_int
) -> c_int:
    """Wrapper around ``poll(2)``.

    Args:
        fds: Pointer to an array of ``pollfd`` structs (8 bytes each).
        nfds: Number of entries in ``fds``.
        timeout_ms: Milliseconds to wait; -1 = infinite, 0 = immediate.

    Returns:
        Number of fds with events, 0 on timeout, -1 on error.
    """
    return external_call["poll", c_int](
        fds.bitcast[NoneType](), nfds, timeout_ms
    )


@always_inline
def _getaddrinfo(
    host: String,
    hints: UnsafePointer[UInt8, _],
    res_slot: UnsafePointer[UInt8, _],
) -> c_int:
    """Wrapper around ``getaddrinfo(3)``.

    Resolves *host* with no service constraint (port is not set). The caller
    must pass a zero-initialised 48-byte hints buffer and an 8-byte slot to
    receive the ``addrinfo*`` result pointer.

    Args:
        host: Hostname or numeric IP string to resolve.
        hints: Pointer to a 48-byte zero-initialised ``addrinfo`` buffer;
                  caller sets ``ai_socktype`` before calling.
        res_slot: Pointer to an 8-byte zero-initialised slot; on success this
                  receives the linked-list head pointer.

    Returns:
        0 on success, non-zero ``EAI_*`` error code on failure.
    """
    var host_copy = host
    return external_call["getaddrinfo", c_int](
        host_copy.as_c_string_slice(),
        Optional[UnsafePointer[UInt8, MutUntrackedOrigin]](None),
        hints.bitcast[NoneType](),
        res_slot.bitcast[NoneType](),
    )


@always_inline
def _freeaddrinfo(head: Int):
    """Wrapper around ``freeaddrinfo(3)``.

    Args:
        head: Integer address of the ``addrinfo`` linked-list head returned by
              ``getaddrinfo``. Passing 0 is a no-op.
    """
    if head == 0:
        return
    _ = external_call["freeaddrinfo", NoneType](
        UnsafePointer[NoneType, MutUntrackedOrigin](unsafe_from_address=head)
    )


@always_inline
def _gai_strerror(code: c_int) -> String:
    """Return the human-readable ``getaddrinfo`` error string.

    Args:
        code: Non-zero ``EAI_*`` return value from ``getaddrinfo``.

    Returns:
        The error description string.
    """
    var ptr = external_call[
        "gai_strerror", UnsafePointer[UInt8, MutUntrackedOrigin]
    ](code)
    if ptr[0] == 0:
        return "unknown getaddrinfo error " + String(code)
    return String(
        StringSlice(
            unsafe_from_utf8=CStringSlice(unsafe_from_ptr=ptr.bitcast[Int8]())
        )
    )


@always_inline
def _inet_pton(
    family: c_int, src: String, dst: UnsafePointer[UInt8, _]
) -> c_int:
    """Convert a text IP address to its binary form.

    Args:
        family: ``AF_INET`` or ``AF_INET6``.
        src: Human-readable IP address string.
        dst: Output buffer (4 bytes for AF_INET, 16 for AF_INET6).

    Returns:
        1 on success, 0 if the input is not valid, -1 on error.
    """
    # as_c_string_slice() is mutating; copy into a local var first.
    var src_copy = src
    return external_call["inet_pton", c_int](
        family, src_copy.as_c_string_slice(), dst.bitcast[NoneType]()
    )


# ──────────────────────────────────────────────────────────────────────────────
# Event-loop syscalls: epoll (Linux) + kqueue (macOS) + eventfd/pipe wakeup
# These live in ``_libc_event.mojo`` (split out for file size); re-exported
# here so existing ``from flare.net._libc import ...`` call sites resolve.
# ──────────────────────────────────────────────────────────────────────────────
from ._libc_event import (
    EPOLLIN,
    EPOLLPRI,
    EPOLLOUT,
    EPOLLERR,
    EPOLLHUP,
    EPOLLRDHUP,
    EPOLLEXCLUSIVE,
    EPOLLET,
    EPOLL_CTL_ADD,
    EPOLL_CTL_DEL,
    EPOLL_CTL_MOD,
    EPOLL_CLOEXEC,
    EPOLL_EVENT_SIZE,
    EPOLL_EVENT_DATA_OFF,
    EFD_CLOEXEC,
    EFD_NONBLOCK,
    EFD_SEMAPHORE,
    EVFILT_READ,
    EVFILT_WRITE,
    EVFILT_TIMER,
    EVFILT_USER,
    EV_ADD,
    EV_DELETE,
    EV_ENABLE,
    EV_DISABLE,
    EV_ONESHOT,
    EV_CLEAR,
    EV_EOF,
    EV_ERROR,
    NOTE_TRIGGER,
    NOTE_FFNOP,
    KEVENT_SIZE,
    KEVENT_IDENT_OFF,
    KEVENT_FILTER_OFF,
    KEVENT_FLAGS_OFF,
    KEVENT_FFLAGS_OFF,
    KEVENT_DATA_OFF,
    KEVENT_UDATA_OFF,
    _epoll_event_set,
    _epoll_event_read_events,
    _epoll_event_read_data,
    _kevent_set,
    _kevent_read_ident,
    _kevent_read_filter,
    _kevent_read_flags,
    _kevent_read_fflags,
    _kevent_read_udata,
    _epoll_create1,
    _epoll_ctl,
    _epoll_wait,
    _kqueue,
    _kevent,
    _eventfd,
    _pipe,
)


# ──────────────────────────────────────────────────────────────────────────────
# Raw read/write (for non-socket fds: pipe, eventfd)
# These live in ``_libc_fileio.mojo`` (split out for file size); re-exported
# here so existing ``from flare.net._libc import ...`` call sites resolve.
# ──────────────────────────────────────────────────────────────────────────────
from ._libc_fileio import (
    _find_flare_lib_for_io,
    FlareRawIO,
    _do_read_fd,
    _do_write_fd,
    _read_fd,
    _write_fd,
)
