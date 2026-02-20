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

from ffi import (
    external_call,
    c_int,
    c_uint,
    c_size_t,
    c_ssize_t,
    c_char,
    get_errno,
    ErrNo,
)
from memory import UnsafePointer, stack_allocation
from sys.info import CompilationTarget, platform_map

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
# macOS uses SO_NOSIGPIPE socket option instead; MSG_NOSIGNAL = 0 is safe.

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
fn _htons(x: UInt16) -> UInt16:
    """Convert a ``UInt16`` from host byte order to network (big-endian) order.

    All target platforms (macOS ARM64, Linux x86_64/aarch64) are
    little-endian, so this is always a byte swap.
    """
    return ((x & 0xFF) << 8) | (x >> 8)


@always_inline
fn _ntohs(x: UInt16) -> UInt16:
    """Convert a ``UInt16`` from network byte order to host order."""
    return _htons(x)  # byte-swap is its own inverse


@always_inline
fn _htonl(x: UInt32) -> UInt32:
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
fn _fill_sockaddr_in(
    buf: UnsafePointer[UInt8], port: UInt16, ip_bytes: UnsafePointer[UInt8]
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

    @parameter
    if CompilationTarget.is_macos():
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
fn _read_port_from_sockaddr(buf: UnsafePointer[UInt8]) -> UInt16:
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
fn _read_ip_from_sockaddr(buf: UnsafePointer[UInt8]) raises -> String:
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


# ──────────────────────────────────────────────────────────────────────────────
# errno → typed error helpers
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
fn _strerror(code: c_int) -> String:
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
fn _os_error(op: String) -> String:
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
fn _socket(family: c_int, kind: c_int, protocol: c_int) -> c_int:
    """Wrapper around ``socket(2)``.

    Returns:
        File descriptor on success, ``INVALID_FD`` on failure (errno set).
    """
    return external_call["socket", c_int](family, kind, protocol)


@always_inline
fn _close(fd: c_int) -> c_int:
    """Wrapper around ``close(2)``."""
    return external_call["close", c_int](fd)


@always_inline
fn _bind(fd: c_int, addr: UnsafePointer[UInt8], addrlen: c_uint) -> c_int:
    """Wrapper around ``bind(2)``."""
    return external_call["bind", c_int](fd, addr.bitcast[NoneType](), addrlen)


@always_inline
fn _listen(fd: c_int, backlog: c_int) -> c_int:
    """Wrapper around ``listen(2)``."""
    return external_call["listen", c_int](fd, backlog)


@always_inline
fn _accept(
    fd: c_int,
    addr: UnsafePointer[UInt8],
    addrlen: UnsafePointer[c_uint],
) -> c_int:
    """Wrapper around ``accept(2)``."""
    return external_call["accept", c_int](fd, addr.bitcast[NoneType](), addrlen)


@always_inline
fn _connect(fd: c_int, addr: UnsafePointer[UInt8], addrlen: c_uint) -> c_int:
    """Wrapper around ``connect(2)``."""
    return external_call["connect", c_int](
        fd, addr.bitcast[NoneType](), addrlen
    )


@always_inline
fn _getsockname(
    fd: c_int,
    addr: UnsafePointer[UInt8],
    addrlen: UnsafePointer[c_uint],
) -> c_int:
    """Wrapper around ``getsockname(2)``."""
    return external_call["getsockname", c_int](
        fd, addr.bitcast[NoneType](), addrlen
    )


@always_inline
fn _getpeername(
    fd: c_int,
    addr: UnsafePointer[UInt8],
    addrlen: UnsafePointer[c_uint],
) -> c_int:
    """Wrapper around ``getpeername(2)``."""
    return external_call["getpeername", c_int](
        fd, addr.bitcast[NoneType](), addrlen
    )


@always_inline
fn _send(
    fd: c_int, buf: UnsafePointer[UInt8], n: c_size_t, flags: c_int
) -> c_ssize_t:
    """Wrapper around ``send(2)``."""
    return external_call["send", c_ssize_t](
        fd, buf.bitcast[NoneType](), n, flags
    )


@always_inline
fn _recv(
    fd: c_int, buf: UnsafePointer[UInt8], n: c_size_t, flags: c_int
) -> c_ssize_t:
    """Wrapper around ``recv(2)``."""
    return external_call["recv", c_ssize_t](
        fd, buf.bitcast[NoneType](), n, flags
    )


@always_inline
fn _sendto(
    fd: c_int,
    buf: UnsafePointer[UInt8],
    n: c_size_t,
    flags: c_int,
    addr: UnsafePointer[UInt8],
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
fn _recvfrom(
    fd: c_int,
    buf: UnsafePointer[UInt8],
    n: c_size_t,
    flags: c_int,
    addr: UnsafePointer[UInt8],
    addrlen: UnsafePointer[c_uint],
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
fn _setsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: UnsafePointer[UInt8],
    optlen: c_uint,
) -> c_int:
    """Wrapper around ``setsockopt(2)``."""
    return external_call["setsockopt", c_int](
        fd, level, optname, optval.bitcast[NoneType](), optlen
    )


@always_inline
fn _fcntl2(fd: c_int, cmd: c_int, arg: c_int) -> c_int:
    """Wrapper around ``fcntl(fd, cmd, arg)``."""
    return external_call["fcntl", c_int](fd, cmd, arg)


@always_inline
fn _shutdown(fd: c_int, how: c_int) -> c_int:
    """Wrapper around ``shutdown(2)``."""
    return external_call["shutdown", c_int](fd, how)


@always_inline
fn _getsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: UnsafePointer[UInt8],
    optlen: UnsafePointer[c_uint],
) -> c_int:
    """Wrapper around ``getsockopt(2)``."""
    return external_call["getsockopt", c_int](
        fd, level, optname, optval.bitcast[NoneType](), optlen
    )


@always_inline
fn _poll(fds: UnsafePointer[UInt8], nfds: c_uint, timeout_ms: c_int) -> c_int:
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
fn _getaddrinfo(
    host: String,
    hints: UnsafePointer[UInt8],
    res_slot: UnsafePointer[UInt8],
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
fn _freeaddrinfo(head: Int):
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
fn _gai_strerror(code: c_int) -> String:
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
fn _inet_pton(family: c_int, src: String, dst: UnsafePointer[UInt8]) -> c_int:
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
