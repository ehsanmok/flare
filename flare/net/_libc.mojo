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
)
from std.memory import UnsafePointer, stack_allocation
from std.sys.info import CompilationTarget, platform_map
from std.os import getenv

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
# struct pollfd { int fd; short events; short revents; }  = 8 bytes
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
#   ai_flags     : int32     @ 0
#   ai_family    : int32     @ 4
#   ai_socktype  : int32     @ 8
#   ai_protocol  : int32     @ 12
#   ai_addrlen   : uint32    @ 16
#   (pad 4 bytes)            @ 20
#   ai_canonname : *char     @ 24
#   ai_addr      : *sockaddr @ 32
#   ai_next      : *addrinfo @ 40   total = 48 bytes
#
# Linux – ai_addr before ai_canonname:
#   ai_flags     : int32     @ 0
#   ai_family    : int32     @ 4
#   ai_socktype  : int32     @ 8
#   ai_protocol  : int32     @ 12
#   ai_addrlen   : uint32    @ 16
#   (pad 4 bytes)            @ 20
#   ai_addr      : *sockaddr @ 24
#   ai_canonname : *char     @ 32
#   ai_next      : *addrinfo @ 40   total = 48 bytes
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
        buf:      Caller-allocated 16-byte uninitialized buffer.
        port:     Port in host byte order; stored as big-endian.
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
        - [0-1]   sin6_family (AF_INET6) — BSD: [len, family]; Linux: [family_lo, family_hi]
        - [2-3]   sin6_port (big-endian)
        - [4-7]   sin6_flowinfo (zeroed)
        - [8-23]  sin6_addr (16-byte IPv6 address, from ``inet_pton``)
        - [24-27] sin6_scope_id (zeroed)

    Args:
        buf:      Caller-allocated 28-byte buffer.
        port:     Port in host byte order; stored as big-endian.
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
    var ntop_buf = stack_allocation[64, UInt8]()
    for i in range(64):
        (ntop_buf + i).init_pointee_copy(0)

    # inet_ntop(AF_INET, &sin_addr, dst, dst_len) — sin_addr is at offset 4
    _ = external_call["inet_ntop", UnsafePointer[UInt8, MutExternalOrigin]](
        AF_INET,
        (buf + 4).bitcast[NoneType](),
        ntop_buf.bitcast[c_char](),
        c_uint(64),
    )
    if ntop_buf[0] == 0:
        raise Error("inet_ntop failed: errno " + String(get_errno()))
    return String(StringSlice(unsafe_from_utf8_ptr=ntop_buf))


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
    var ntop_buf = stack_allocation[64, UInt8]()
    for i in range(64):
        (ntop_buf + i).init_pointee_copy(0)

    # inet_ntop(AF_INET6, &sin6_addr, dst, dst_len) — sin6_addr at offset 8
    _ = external_call["inet_ntop", UnsafePointer[UInt8, MutExternalOrigin]](
        AF_INET6,
        (buf + 8).bitcast[NoneType](),
        ntop_buf.bitcast[c_char](),
        c_uint(64),
    )
    if ntop_buf[0] == 0:
        raise Error("inet_ntop (IPv6) failed: errno " + String(get_errno()))
    return String(StringSlice(unsafe_from_utf8_ptr=ntop_buf))


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
        "strerror", UnsafePointer[UInt8, MutExternalOrigin]
    ](code)
    if ptr[0] == 0:
        return "unknown error " + String(code)
    return String(StringSlice(unsafe_from_utf8_ptr=ptr))


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
    return external_call["accept", c_int](fd, addr.bitcast[NoneType](), addrlen)


@always_inline
def _connect(
    fd: c_int, addr: UnsafePointer[UInt8, _], addrlen: c_uint
) -> c_int:
    """Wrapper around ``connect(2)``."""
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
    return external_call["getpeername", c_int](
        fd, addr.bitcast[NoneType](), addrlen
    )


@always_inline
def _send(
    fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t, flags: c_int
) -> c_ssize_t:
    """Wrapper around ``send(2)``."""
    return external_call["send", c_ssize_t](
        fd, buf.bitcast[NoneType](), n, flags
    )


@always_inline
def _recv(
    fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t, flags: c_int
) -> c_ssize_t:
    """Wrapper around ``recv(2)``."""
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
        fds:        Pointer to an array of ``pollfd`` structs (8 bytes each).
        nfds:       Number of entries in ``fds``.
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

    Resolves *host* with no service constraint (port is not set).  The caller
    must pass a zero-initialised 48-byte hints buffer and an 8-byte slot to
    receive the ``addrinfo*`` result pointer.

    Args:
        host:     Hostname or numeric IP string to resolve.
        hints:    Pointer to a 48-byte zero-initialised ``addrinfo`` buffer;
                  caller sets ``ai_socktype`` before calling.
        res_slot: Pointer to an 8-byte zero-initialised slot; on success this
                  receives the linked-list head pointer.

    Returns:
        0 on success, non-zero ``EAI_*`` error code on failure.
    """
    var host_copy = host
    return external_call["getaddrinfo", c_int](
        host_copy.as_c_string_slice(),
        UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=0),
        hints.bitcast[NoneType](),
        res_slot.bitcast[NoneType](),
    )


@always_inline
def _freeaddrinfo(head: Int):
    """Wrapper around ``freeaddrinfo(3)``.

    Args:
        head: Integer address of the ``addrinfo`` linked-list head returned by
              ``getaddrinfo``.  Passing 0 is a no-op.
    """
    if head == 0:
        return
    _ = external_call["freeaddrinfo", NoneType](
        UnsafePointer[NoneType, MutExternalOrigin](unsafe_from_address=head)
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
        "gai_strerror", UnsafePointer[UInt8, MutExternalOrigin]
    ](code)
    if ptr[0] == 0:
        return "unknown getaddrinfo error " + String(code)
    return String(StringSlice(unsafe_from_utf8_ptr=ptr))


@always_inline
def _inet_pton(
    family: c_int, src: String, dst: UnsafePointer[UInt8, _]
) -> c_int:
    """Convert a text IP address to its binary form.

    Args:
        family: ``AF_INET`` or ``AF_INET6``.
        src:    Human-readable IP address string.
        dst:    Output buffer (4 bytes for AF_INET, 16 for AF_INET6).

    Returns:
        1 on success, 0 if the input is not valid, -1 on error.
    """
    # as_c_string_slice() is mutating; copy into a local var first.
    var src_copy = src
    return external_call["inet_pton", c_int](
        family, src_copy.as_c_string_slice(), dst.bitcast[NoneType]()
    )


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
#    offset 4) but NATURALLY ALIGNED on aarch64 (16 bytes, data at offset 8).
#    See glibc's ``EPOLL_PACKED`` macro. ``EPOLL_EVENT_SIZE`` and
#    ``EPOLL_DATA_OFFSET`` below handle both.
#
# 2. ``struct kevent`` on macOS is 32 bytes (ident=8, filter=2, flags=2,
#    fflags=4, data=8, udata=8). Same on both arm64 and x86_64 macOS.

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
        buf:      Pointer to uninitialised epoll_event buffer.
        events:   ``EPOLLIN | EPOLLOUT | EPOLLET | ...`` bitmask.
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
        buf:    Pointer to ``KEVENT_SIZE``-byte buffer.
        ident:  Identifier (usually an fd).
        filter: ``EVFILT_READ``, ``EVFILT_WRITE``, ``EVFILT_TIMER``,
                ``EVFILT_USER``.
        flags:  ``EV_ADD | EV_ENABLE | EV_ONESHOT | ...``.
        fflags: Filter-specific flags (e.g. ``NOTE_TRIGGER`` for EVFILT_USER).
        data:   Filter-specific data (e.g. timer duration).
        udata:  User token, stored in ``udata`` field.
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
        epfd:  epoll fd from ``epoll_create1``.
        op:    ``EPOLL_CTL_ADD``, ``EPOLL_CTL_MOD``, or ``EPOLL_CTL_DEL``.
        fd:    Target fd to register/modify/remove.
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
        epfd:       epoll fd.
        events:     Pointer to an array of ``maxevents`` ``epoll_event``
                    structs (each ``EPOLL_EVENT_SIZE`` bytes).
        maxevents:  Maximum events to return; must be > 0.
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
        kq:         kqueue fd.
        changelist: Pointer to array of changes (kevent structs). May be
                    NULL (pass stack_allocation base) if ``nchanges == 0``.
        nchanges:   Number of entries in ``changelist``.
        eventlist:  Pointer to output array for received events.
        nevents:    Max events to receive.
        timeout:    Pointer to ``struct timespec`` (16 bytes: tv_sec + tv_nsec).
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
        flags:   ``EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE``.

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


# ──────────────────────────────────────────────────────────────────────────────
# Raw read/write (for non-socket fds: pipe, eventfd)
# ──────────────────────────────────────────────────────────────────────────────
# ``_recv`` / ``_send`` above only work on sockets. Eventfd and pipe require
# plain ``read(2)`` / ``write(2)``. We route through ``flare_read`` /
# ``flare_write`` exposed by ``libflare_tls.so`` because Mojo's stdlib also
# declares ``external_call["read" / "write", ...]`` for ``FileDescriptor``
# with a different signature, and the two collide at the MLIR lowering
# stage. The C wrappers compile to a single tail-call; no measurable cost.
#
# Both platforms load the library on demand via ``OwnedDLHandle``:
#
# - macOS:  SIP blocks ``DYLD_INSERT_LIBRARIES`` for non-signed binaries,
#           so a preload-style injection is impossible.
# - Linux:  Mojo's JIT symbol resolver does **not** look at
#           ``LD_PRELOAD``ed globals — it only searches the small set of
#           shared objects it opened itself. So even on Linux we must
#           ``dlopen`` via ``OwnedDLHandle`` to get a callable pointer.
#
# Two call shapes are provided:
#
# * ``FlareRawIO`` — a cached handle + function-pointer struct. Owners
#   (like ``Reactor``) construct one at init time and call
#   ``io.read() / io.write()`` on the hot path. No dlopen/dlsym per
#   call. Pattern lifted straight from
#   ``ehsanmok/json``'s ``SimdjsonFFI``.
# * ``_read_fd`` / ``_write_fd`` — thin module-level helpers that open
#   the library per call. Convenient for one-off use from tests and
#   non-hot-path call sites; do **not** use in anything that runs
#   per-request or per-wakeup.


def _find_flare_lib_for_io() -> String:
    """Locate ``libflare_tls.so`` at runtime.

    Search order:
    1. ``$CONDA_PREFIX/lib/libflare_tls.so`` — the canonical location,
       populated by ``flare/tls/ffi/build.sh`` on pixi activation.
    2. ``build/libflare_tls.so`` — bare-checkout fallback when running
       outside a conda/pixi environment.

    Same logic as ``flare.net.socket._find_flare_lib`` but local to this
    module to avoid a cyclic dependency between ``_libc.mojo`` and
    ``socket.mojo``.

    The path is built via ``String("") += prefix += literal`` rather than
    the ``prefix + literal`` concat operator. See the module docstring
    of ``flare.tls.config`` for the full rationale (Mojo 0.26's concat
    can return a String whose buffer aliases another ``getenv`` +
    literal result, so two sequential ``CONDA_PREFIX + …`` calls can
    clobber each other's bytes).
    """
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix == "":
        return "build/libflare_tls.so"
    var out = String("")
    out += prefix
    out += "/lib/libflare_tls.so"
    return out^


# ── FlareRawIO: cached handle for the reactor's hot-path ─────────────────────
#
# The reactor calls ``_read_fd`` / ``_write_fd`` on every wakeup to drain
# the eventfd / self-pipe. Doing ``dlopen + dlsym + dlclose`` per wakeup
# is measurable under churn (Stage 2+ multi-threaded wakeup, the
# ``fuzz_reactor_churn`` workload). ``FlareRawIO`` opens the library and
# resolves ``flare_read`` / ``flare_write`` exactly once — subsequent
# I/O is a plain indirect call through the cached function pointer.
#
# Ownership invariant: the ``OwnedDLHandle`` field keeps the library
# mapped for the lifetime of the struct, so the cached function
# pointers stay valid. Moving the struct moves the handle + pointers
# together. ``Copyable`` would be wrong because duplicating an
# ``OwnedDLHandle`` would double-free on destruction.


struct FlareRawIO(Movable):
    """Cached dlopen handle + function pointers for ``flare_read`` /
    ``flare_write`` in ``libflare_tls.so``.

    Construct once per owner (typically a ``Reactor``), then call
    ``read()`` / ``write()`` on the hot path without paying a dlopen
    cost per syscall. See the module comment above for the full
    rationale and the ``ehsanmok/json`` ``SimdjsonFFI`` pattern we
    inherit from.
    """

    var _lib: OwnedDLHandle
    """Owned dlopen handle. Keeps the library mapped for the lifetime of
    the struct so the cached function pointers stay valid."""

    var _read: def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
    """Cached pointer to ``flare_read`` in ``libflare_tls.so``."""

    var _write: def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
    """Cached pointer to ``flare_write`` in ``libflare_tls.so``."""

    def __init__(out self) raises:
        """Open ``libflare_tls.so`` and resolve the raw I/O entry points.

        Raises:
            Error: If the library can't be located (via
                ``_find_flare_lib_for_io``) or any symbol is missing.
        """
        self._lib = OwnedDLHandle(_find_flare_lib_for_io())
        self._read = self._lib.get_function[
            def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
        ]("flare_read")
        self._write = self._lib.get_function[
            def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
        ]("flare_write")

    @always_inline
    def read(
        self, fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t
    ) -> c_ssize_t:
        """Read up to ``n`` bytes from ``fd`` into ``buf`` via the cached
        ``flare_read`` pointer.

        Mirrors ``read(2)`` semantics: returns the byte count on success
        (0 on EOF), or -1 on error with ``errno`` set.
        """
        return self._read(fd, Int(buf), n)

    @always_inline
    def write(
        self, fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t
    ) -> c_ssize_t:
        """Write up to ``n`` bytes from ``buf`` to ``fd`` via the cached
        ``flare_write`` pointer.

        Mirrors ``write(2)`` semantics: returns the byte count actually
        written, or -1 on error with ``errno`` set.
        """
        return self._write(fd, Int(buf), n)


# ── Per-call wrappers (convenience; prefer FlareRawIO on hot paths) ──────────
#
# Implementation note — ``read lib`` borrow trick:
#
# Mojo's ASAP (As Soon As Possible) destruction policy destroys an
# ``OwnedDLHandle`` immediately after its *last Mojo-visible use*, which
# in a naive ``var lib = OwnedDLHandle(...); var fn = lib.get_function(...);
# return fn(...)`` pattern is the ``get_function`` call, not the actual
# ``fn(...)`` invocation. ASAP then ``dlclose``s the library and unmaps
# it *before* the function pointer is called, crashing the JIT on both
# macOS ARM64 and Linux. (This was hidden earlier on Linux by the pixi
# activation script ``LD_PRELOAD``ing ``libflare_tls.so``, which kept
# the library mapped regardless of ``dlclose``.)
#
# The fix, lifted from ``flare/http/encoding.mojo``: each public entry
# point opens ``lib`` itself, then delegates to a private helper that
# accepts ``lib`` as a ``read`` (borrowed) parameter. A borrow cannot
# be ASAP-destroyed — it stays alive for the helper's entire
# execution, including every C call inside it.


def _do_read_fd(
    read lib: OwnedDLHandle,
    fd: c_int,
    buf: UnsafePointer[UInt8, _],
    n: c_size_t,
) raises -> c_ssize_t:
    """Inner helper: resolve ``flare_read`` on the borrowed ``lib`` and
    call it. The ``read`` parameter keeps ``lib`` alive across the
    ``fn_r(...)`` call so ASAP doesn't ``dlclose`` it mid-helper.
    """
    var fn_r = lib.get_function[
        def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
    ]("flare_read")
    return fn_r(fd, Int(buf), n)


def _do_write_fd(
    read lib: OwnedDLHandle,
    fd: c_int,
    buf: UnsafePointer[UInt8, _],
    n: c_size_t,
) raises -> c_ssize_t:
    """Inner helper: resolve ``flare_write`` on the borrowed ``lib``
    and call it. See ``_do_read_fd`` for the borrow rationale.
    """
    var fn_w = lib.get_function[
        def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
    ]("flare_write")
    return fn_w(fd, Int(buf), n)


@always_inline
def _read_fd(
    fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t
) raises -> c_ssize_t:
    """Read from any fd (socket, pipe, eventfd) via ``libflare_tls.so``.

    Opens the library once per call through ``OwnedDLHandle``. Fine for
    one-off test/tool use; for anything that runs per-wakeup or per-
    request, use ``FlareRawIO`` instead to avoid a dlopen on every call.

    Raises if the library can't be located or opened.
    """
    var lib = OwnedDLHandle(_find_flare_lib_for_io())
    return _do_read_fd(lib, fd, buf, n)


@always_inline
def _write_fd(
    fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t
) raises -> c_ssize_t:
    """Write to any fd (socket, pipe, eventfd) via ``libflare_tls.so``.

    Opens the library once per call through ``OwnedDLHandle``. Fine for
    one-off test/tool use; for anything that runs per-wakeup or per-
    request, use ``FlareRawIO`` instead to avoid a dlopen on every call.

    Raises if the library can't be located or opened.
    """
    var lib = OwnedDLHandle(_find_flare_lib_for_io())
    return _do_write_fd(lib, fd, buf, n)
