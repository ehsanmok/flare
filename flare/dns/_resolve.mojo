"""DNS hostname resolution via libc ``getaddrinfo(3)``.

References:
    - https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
    - ``flare/net/_libc.mojo`` for low-level FFI wrappers

Memory safety contract:
    ``_freeaddrinfo`` MUST be called on the linked-list head in ALL code
    paths — including every error path that follows a successful
    ``_getaddrinfo`` call.  This invariant is maintained by calling
    ``_freeaddrinfo(head)`` before every ``raise`` and at the successful
    return path.
"""

from ffi import c_int, c_uint, c_char, get_errno
from memory import stack_allocation

from ..net._libc import (
    AF_INET,
    AF_INET6,
    ADDRINFO_AI_FAMILY_OFF,
    ADDRINFO_AI_ADDR_OFF,
    ADDRINFO_AI_NEXT_OFF,
    _getaddrinfo,
    _freeaddrinfo,
    _gai_strerror,
)

comptime _ADDRINFO_AI_SOCKTYPE_OFF: Int = 8
from ..net import IpAddr
from ..net.error import DnsError, AddressParseError


fn resolve(host: String) raises -> List[IpAddr]:
    """Resolve a hostname to a list of IP addresses.

    Calls ``getaddrinfo(3)`` which respects ``/etc/hosts``,
    ``/etc/resolv.conf``, and ``nsswitch.conf``.  Returns both IPv4 and
    IPv6 results in OS-preference order.

    Args:
        host: Hostname or numeric IP string to resolve
              (e.g. ``"example.com"``, ``"localhost"``, ``"127.0.0.1"``).

    Returns:
        A non-empty ``List[IpAddr]``.  The first entry is the OS-preferred
        address for this host.

    Raises:
        AddressParseError: If ``host`` is empty.
        DnsError: On NXDOMAIN, timeout, or system resolver failure.

    Example:
        ```mojo
        var addrs = resolve("localhost")
        for a in addrs:
            print(a[])
        ```
    """
    if len(host) == 0:
        raise AddressParseError("empty hostname")

    # Security: validate hostname before passing to getaddrinfo(3).
    #
    # (1) Null bytes: C string passed to getaddrinfo would be silently
    #     truncated at the null, resolving a different host than requested.
    # (2) CRLF: hostnames embedded downstream in HTTP Host headers could
    #     enable header injection.
    # (3) '@': user-info prefix — "user@host" is not a hostname.
    # (4) Length: RFC 1035 §2.3.4 limits FQDNs to 253 octets and individual
    #     labels to 63 octets.  Reject early to avoid resolver undefined behaviour.
    var host_bytes = host.as_bytes()
    var n = len(host_bytes)
    if n > 253:
        raise AddressParseError(
            "hostname too long (max 253 chars): " + host[:20] + "…"
        )
    var label_len = 0
    for b in host_bytes:
        if (
            b == 0
            or b == UInt8(0x0A)
            or b == UInt8(0x0D)
            or b == UInt8(ord("@"))
        ):
            raise AddressParseError(
                "hostname contains forbidden character (null, CR, LF, or @): "
                + host
            )
        if b == UInt8(ord(".")):
            label_len = 0
        else:
            label_len += 1
            if label_len > 63:
                raise AddressParseError(
                    "hostname label exceeds 63 characters: " + host
                )

    # hints: 48-byte zeroed addrinfo — ai_socktype = SOCK_STREAM(1)
    var hints = stack_allocation[48, UInt8]()
    for i in range(48):
        (hints + i).init_pointee_copy(0)
    (hints + _ADDRINFO_AI_SOCKTYPE_OFF).bitcast[Int32]().init_pointee_copy(
        Int32(1)
    )

    # result slot: 8-byte buffer that receives the addrinfo* pointer
    var res_slot = stack_allocation[8, UInt8]()
    for i in range(8):
        (res_slot + i).init_pointee_copy(0)

    var rc = _getaddrinfo(host, hints, res_slot)
    if rc != 0:
        raise DnsError(host, Int(rc), _gai_strerror(rc))

    var head = Int(res_slot.bitcast[UInt64]().load())
    var results = List[IpAddr]()

    var cur = head
    var guard = 0
    while cur != 0:
        if guard >= 64:
            break
        guard += 1

        var node = UnsafePointer[UInt8, MutExternalOrigin](
            unsafe_from_address=cur
        )
        var family = Int(
            (node + ADDRINFO_AI_FAMILY_OFF).bitcast[Int32]().load()
        )
        var sa_ptr = Int((node + ADDRINFO_AI_ADDR_OFF).bitcast[UInt64]().load())

        if sa_ptr != 0:
            if family == Int(AF_INET):
                var ip_str = _ipv4_from_sockaddr(sa_ptr)
                try:
                    results.append(IpAddr.parse(ip_str))
                except:
                    pass
            elif family == Int(AF_INET6):
                var ip_str = _ipv6_from_sockaddr(sa_ptr)
                try:
                    results.append(IpAddr.parse(ip_str))
                except:
                    pass

        cur = Int((node + ADDRINFO_AI_NEXT_OFF).bitcast[UInt64]().load())

    _freeaddrinfo(head)

    if len(results) == 0:
        raise DnsError(host, 0, "no addresses returned")

    return results^


fn resolve_v4(host: String) raises -> List[IpAddr]:
    """Resolve a hostname, returning only IPv4 results.

    Args:
        host: Hostname to resolve.

    Returns:
        A non-empty ``List[IpAddr]`` containing only IPv4 addresses.

    Raises:
        AddressParseError: If ``host`` is empty.
        DnsError: If no IPv4 address is found, or resolution fails.

    Example:
        ```mojo
        var addrs = resolve_v4("localhost")
        print(addrs[0])  # 127.0.0.1
        ```
    """
    var all = resolve(host)
    var v4 = List[IpAddr]()
    for a in all:
        if not a.is_v6():
            v4.append(a.copy())
    if len(v4) == 0:
        raise DnsError(host, 0, "no IPv4 addresses returned")
    return v4^


fn resolve_v6(host: String) raises -> List[IpAddr]:
    """Resolve a hostname, returning only IPv6 results.

    Args:
        host: Hostname to resolve.

    Returns:
        A non-empty ``List[IpAddr]`` containing only IPv6 addresses.

    Raises:
        AddressParseError: If ``host`` is empty.
        DnsError: If no IPv6 address is found, or resolution fails.
    """
    var all = resolve(host)
    var v6 = List[IpAddr]()
    for a in all:
        if a.is_v6():
            v6.append(a.copy())
    if len(v6) == 0:
        raise DnsError(host, 0, "no IPv6 addresses returned")
    return v6^


# ── Internal helpers ──────────────────────────────────────────────────────────


fn _ipv4_from_sockaddr(sa_ptr: Int) -> String:
    """Extract an IPv4 address string from a ``sockaddr_in`` pointer.

    Args:
        sa_ptr: Integer address of a ``sockaddr_in`` struct.

    Returns:
        Dotted-decimal string (e.g. ``"127.0.0.1"``), or empty string on
        ``inet_ntop`` failure.
    """
    from ffi import external_call

    var sa = UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=sa_ptr)
    var ntop = stack_allocation[64, UInt8]()
    for i in range(64):
        (ntop + i).init_pointee_copy(0)

    # sockaddr_in: [sin_len/family(2), sin_port(2), sin_addr(4), ...]
    # sin_addr is at byte offset 4 on both macOS and Linux
    _ = external_call["inet_ntop", UnsafePointer[UInt8, MutExternalOrigin]](
        c_int(2),
        (sa + 4).bitcast[NoneType](),
        ntop.bitcast[c_char](),
        c_uint(64),
    )
    if ntop[0] == 0:
        return ""
    return String(StringSlice(unsafe_from_utf8_ptr=ntop))


fn _ipv6_from_sockaddr(sa_ptr: Int) -> String:
    """Extract an IPv6 address string from a ``sockaddr_in6`` pointer.

    Args:
        sa_ptr: Integer address of a ``sockaddr_in6`` struct.

    Returns:
        Colon-hex string (e.g. ``"::1"``), or empty string on failure.
    """
    from ffi import external_call
    from sys.info import CompilationTarget, platform_map

    comptime _pm = platform_map[T=Int, ...]
    comptime AF_INET6_VAL: c_int = c_int(_pm["AF_INET6", linux=10, macos=30]())

    var sa = UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=sa_ptr)
    var ntop = stack_allocation[64, UInt8]()
    for i in range(64):
        (ntop + i).init_pointee_copy(0)

    # sockaddr_in6: [family(2), port(2), flowinfo(4), addr(16), ...]
    # sin6_addr starts at byte offset 8
    _ = external_call["inet_ntop", UnsafePointer[UInt8, MutExternalOrigin]](
        AF_INET6_VAL,
        (sa + 8).bitcast[NoneType](),
        ntop.bitcast[c_char](),
        c_uint(64),
    )
    if ntop[0] == 0:
        return ""
    return String(StringSlice(unsafe_from_utf8_ptr=ntop))
