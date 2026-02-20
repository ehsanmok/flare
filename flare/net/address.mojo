"""IP address and socket address types.

Both ``IpAddr`` and ``SocketAddr`` are copyable value types — they hold
no OS resources, so copying is safe and cheap.

IP address parsing uses the OS ``inet_pton(3)`` function for correctness
on both IPv4 and IPv6; formatting uses ``inet_ntop(3)``.
"""

from format import Writable, Writer
from memory import UnsafePointer, stack_allocation
from ffi import external_call, c_int, c_uint, c_char

from ._libc import AF_INET, AF_INET6, _inet_pton


struct IpAddr(
    Copyable, Equatable, ImplicitlyCopyable, Movable, Stringable, Writable
):
    """An IP address: either IPv4 or IPv6.

    The address is stored as a validated string produced by ``inet_ntop``
    after successful ``inet_pton`` parsing. This guarantees all instances
    hold a canonical, valid representation.

    Fields:
        _addr:  Canonical string form (e.g. ``"127.0.0.1"`` or ``"::1"``).
        _is_v6: ``True`` for IPv6, ``False`` for IPv4.

    Example:
        ```mojo
        var lo = IpAddr.parse("127.0.0.1")
        print(lo)                # 127.0.0.1
        print(lo.is_loopback())  # True
        ```
    """

    var _addr: String
    var _is_v6: Bool

    fn __init__(out self, addr: String, is_v6: Bool):
        """Construct an ``IpAddr`` directly from a pre-validated string.

        Prefer ``IpAddr.parse`` for user-supplied strings.

        Args:
            addr:  Canonical IP address string.
            is_v6: ``True`` if this is an IPv6 address.
        """
        self._addr = addr
        self._is_v6 = is_v6

    # ── Factories ─────────────────────────────────────────────────────────────

    @staticmethod
    fn parse(s: String) raises -> IpAddr:
        """Parse and validate an IP address string.

        Accepts dotted-decimal IPv4 (``"192.168.1.1"``) and colon-separated
        IPv6 (``"::1"``, ``"2001:db8::1"``). Uses ``inet_pton`` for
        correctness, then ``inet_ntop`` to obtain the canonical form.

        Args:
            s: The address string to parse.

        Returns:
            A validated ``IpAddr``.

        Raises:
            AddressParseError: If ``s`` is not a valid IPv4 or IPv6 address.

        Example:
            ```mojo
            var v4 = IpAddr.parse("192.168.0.1")
            var v6 = IpAddr.parse("::1")
            ```
        """
        from .error import AddressParseError

        if s == "":
            raise AddressParseError(s)

        # Security: reject any string containing bytes that are invalid in a
        # hostname — null bytes, CR, LF, or '@'.  Without this check a caller
        # could pass "127.0.0.1\x00evil" and inet_pton would silently parse only
        # the part before the null, resolving a different address than requested.
        var s_bytes = s.as_bytes()
        for b in s_bytes:
            if (
                b == 0
                or b == UInt8(0x0A)
                or b == UInt8(0x0D)
                or b == UInt8(ord("@"))
            ):
                raise AddressParseError(s)

        # Try IPv4 first
        var ip4 = stack_allocation[4, UInt8]()
        for i in range(4):
            (ip4 + i).init_pointee_copy(0)
        if _inet_pton(AF_INET, s, ip4) == 1:
            var ntop = stack_allocation[64, UInt8]()
            for i in range(64):
                (ntop + i).init_pointee_copy(0)
            _ = external_call[
                "inet_ntop", UnsafePointer[UInt8, MutExternalOrigin]
            ](
                AF_INET,
                ip4.bitcast[NoneType](),
                ntop.bitcast[c_char](),
                c_uint(64),
            )
            if ntop[0] == 0:
                raise AddressParseError(s)
            return IpAddr(String(StringSlice(unsafe_from_utf8_ptr=ntop)), False)

        # Try IPv6
        var ip6 = stack_allocation[16, UInt8]()
        for i in range(16):
            (ip6 + i).init_pointee_copy(0)
        if _inet_pton(AF_INET6, s, ip6) == 1:
            var ntop = stack_allocation[64, UInt8]()
            for i in range(64):
                (ntop + i).init_pointee_copy(0)
            _ = external_call[
                "inet_ntop", UnsafePointer[UInt8, MutExternalOrigin]
            ](
                AF_INET6,
                ip6.bitcast[NoneType](),
                ntop.bitcast[c_char](),
                c_uint(64),
            )
            if ntop[0] == 0:
                raise AddressParseError(s)
            return IpAddr(String(StringSlice(unsafe_from_utf8_ptr=ntop)), True)

        raise AddressParseError(s)

    @staticmethod
    fn localhost() -> IpAddr:
        """Return the IPv4 loopback address ``127.0.0.1``.

        Returns:
            ``IpAddr`` for ``127.0.0.1``.
        """
        return IpAddr("127.0.0.1", False)

    @staticmethod
    fn localhost_v6() -> IpAddr:
        """Return the IPv6 loopback address ``::1``.

        Returns:
            ``IpAddr`` for ``::1``.
        """
        return IpAddr("::1", True)

    @staticmethod
    fn unspecified() -> IpAddr:
        """Return the IPv4 wildcard address ``0.0.0.0`` (all interfaces).

        Returns:
            ``IpAddr`` for ``0.0.0.0``.
        """
        return IpAddr("0.0.0.0", False)

    @staticmethod
    fn unspecified_v6() -> IpAddr:
        """Return the IPv6 wildcard address ``::`` (all interfaces).

        Returns:
            ``IpAddr`` for ``"::"``
        """
        return IpAddr("::", True)

    # ── Predicates ───────────────────────────────────────────────────────────

    fn is_v4(self) -> Bool:
        """Return ``True`` if this is an IPv4 address."""
        return not self._is_v6

    fn is_v6(self) -> Bool:
        """Return ``True`` if this is an IPv6 address."""
        return self._is_v6

    fn is_loopback(self) -> Bool:
        """Return ``True`` if this is a loopback address.

        IPv4 loopback range is ``127.0.0.0/8``; IPv6 loopback is ``::1``.
        """
        if self._is_v6:
            return self._addr == "::1"
        return self._addr.startswith("127.")

    fn is_unspecified(self) -> Bool:
        """Return ``True`` if this is the wildcard/unspecified address.

        IPv4: ``"0.0.0.0"``; IPv6: ``"::"``.
        """
        if self._is_v6:
            return self._addr == "::"
        return self._addr == "0.0.0.0"

    fn is_private(self) -> Bool:
        """Return ``True`` if this is an RFC 1918 private address.

        Covers ``10.0.0.0/8``, ``172.16.0.0/12``, and ``192.168.0.0/16``.
        IPv6 ULA (``fc00::/7``) is not yet detected and returns ``False``.
        """
        if self._is_v6:
            return False
        if self._addr.startswith("10.") or self._addr.startswith("192.168."):
            return True
        if self._addr.startswith("172."):
            return _is_172_private(self._addr)
        return False

    fn is_multicast(self) -> Bool:
        """Return ``True`` if this is a multicast address.

        IPv4 multicast: ``224.0.0.0/4`` (first octet 224–239).
        IPv6 multicast: addresses starting with ``"ff"``.
        """
        if self._is_v6:
            return self._addr.startswith("ff")
        var dot = _find_char(self._addr, UInt8(ord(".")))
        if dot < 0:
            return False
        var bytes = self._addr.as_bytes()
        # Parse first octet manually to avoid raises from atol
        var octet: Int = 0
        for i in range(dot):
            octet = octet * 10 + Int(bytes[i]) - Int(UInt8(ord("0")))
        return octet >= 224 and octet <= 239

    # ── Equality ──────────────────────────────────────────────────────────────

    fn __eq__(self, other: IpAddr) -> Bool:
        """Return ``True`` if both addresses have the same family and string.

        Args:
            other: The address to compare with.
        """
        return self._is_v6 == other._is_v6 and self._addr == other._addr

    fn __ne__(self, other: IpAddr) -> Bool:
        """Return ``True`` if the addresses differ.

        Args:
            other: The address to compare with.
        """
        return not self.__eq__(other)

    # ── Display ───────────────────────────────────────────────────────────────

    fn write_to[W: Writer](self, mut writer: W):
        """Write the canonical address string to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write(self._addr)

    fn __str__(self) -> String:
        """Return the canonical address string.

        Returns:
            E.g. ``"127.0.0.1"`` or ``"::1"``.
        """
        return self._addr


# ── Module-private helpers ────────────────────────────────────────────────────


fn _is_172_private(addr: String) -> Bool:
    """Return ``True`` for ``172.16.x.x`` – ``172.31.x.x``.

    Args:
        addr: IPv4 address string known to start with ``"172."``.
    """
    var start = 4  # skip "172."
    var dot = _find_char_from(addr, UInt8(ord(".")), start)
    if dot < 0:
        return False
    # Parse second octet manually (avoids raises from atol)
    var bytes = addr.as_bytes()
    var octet: Int = 0
    for i in range(start, dot):
        octet = octet * 10 + Int(bytes[i]) - Int(UInt8(ord("0")))
    return octet >= 16 and octet <= 31


fn _find_char(s: String, ch: UInt8) -> Int:
    """Return the index of the first occurrence of byte ``ch`` in ``s``, or -1.

    Args:
        s:  String to search.
        ch: Byte value to find (e.g. ``UInt8(ord("."))``.
    """
    var bytes = s.as_bytes()
    for i in range(len(bytes)):
        if bytes[i] == ch:
            return i
    return -1


fn _find_char_from(s: String, ch: UInt8, start: Int) -> Int:
    """Return the index of the first ``ch`` byte at or after ``start``, or -1.

    Args:
        s:     String to search.
        ch:    Byte value to find.
        start: First index to check.
    """
    var bytes = s.as_bytes()
    for i in range(start, len(bytes)):
        if bytes[i] == ch:
            return i
    return -1


# ──────────────────────────────────────────────────────────────────────────────


struct SocketAddr(
    Copyable, Equatable, ImplicitlyCopyable, Movable, Stringable, Writable
):
    """A socket address: an IP address combined with a port number.

    Fields:
        ip:   The IP address component.
        port: The port number (0–65535).

    Example:
        ```mojo
        var addr = SocketAddr(IpAddr.localhost(), 8080)
        print(addr)     # 127.0.0.1:8080

        var v6 = SocketAddr(IpAddr.localhost_v6(), 443)
        print(v6)       # [::1]:443
        ```
    """

    var ip: IpAddr
    var port: UInt16

    fn __init__(out self, ip: IpAddr, port: UInt16):
        """Initialise a ``SocketAddr``.

        Args:
            ip:   The IP address component.
            port: The port number (0–65535).
        """
        self.ip = ip.copy()
        self.port = port

    @staticmethod
    fn localhost(port: UInt16) -> SocketAddr:
        """Return ``SocketAddr("127.0.0.1", port)``.

        Args:
            port: The port number.

        Returns:
            A loopback ``SocketAddr``.
        """
        return SocketAddr(IpAddr.localhost(), port)

    @staticmethod
    fn unspecified(port: UInt16) -> SocketAddr:
        """Return ``SocketAddr("0.0.0.0", port)`` — bind on all interfaces.

        Args:
            port: The port number.

        Returns:
            A ``SocketAddr`` for the wildcard address.
        """
        return SocketAddr(IpAddr.unspecified(), port)

    @staticmethod
    fn parse(s: String) raises -> SocketAddr:
        """Parse a ``"host:port"`` or ``"[ipv6]:port"`` string.

        Args:
            s: Address string in one of these forms:
               - ``"1.2.3.4:8080"`` for IPv4.
               - ``"[::1]:443"`` for IPv6.

        Returns:
            A ``SocketAddr``.

        Raises:
            AddressParseError: If the string cannot be parsed.

        Example:
            ```mojo
            var a = SocketAddr.parse("127.0.0.1:9000")
            var b = SocketAddr.parse("[::1]:9000")
            ```
        """
        from .error import AddressParseError

        if s == "":
            raise AddressParseError(s)

        # Security: reject injection characters before any parsing.
        # CRLF in a socket address string can corrupt log output or HTTP headers
        # that embed the address (e.g. "Location: http://HOST/").
        var s_bytes = s.as_bytes()
        for b in s_bytes:
            if b == 0 or b == 0x0A or b == 0x0D:
                raise AddressParseError(s)

        if s.startswith("["):
            var close = _find_char(s, UInt8(ord("]")))
            var sbytes = s.as_bytes()
            if (
                close < 0
                or close + 1 >= len(sbytes)
                or sbytes[close + 1] != UInt8(ord(":"))
            ):
                raise AddressParseError(s)
            var ip = IpAddr.parse(String(s[1:close]))
            return SocketAddr(ip, UInt16(atol(s[close + 2 :])))
        else:
            var colon = _find_char(s, UInt8(ord(":")))
            if colon < 0:
                raise AddressParseError(s)
            var ip = IpAddr.parse(String(s[:colon]))
            return SocketAddr(ip, UInt16(atol(s[colon + 1 :])))

    # ── Equality ──────────────────────────────────────────────────────────────

    fn __eq__(self, other: SocketAddr) -> Bool:
        """Return ``True`` if IP and port both match.

        Args:
            other: The address to compare.
        """
        return self.ip == other.ip and self.port == other.port

    fn __ne__(self, other: SocketAddr) -> Bool:
        """Return ``True`` if IP or port differ.

        Args:
            other: The address to compare.
        """
        return not self.__eq__(other)

    # ── Display ───────────────────────────────────────────────────────────────

    fn write_to[W: Writer](self, mut writer: W):
        """Write ``"ip:port"`` or ``"[ip]:port"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        if self.ip.is_v6():
            writer.write("[", self.ip, "]:", self.port)
        else:
            writer.write(self.ip, ":", self.port)

    fn __str__(self) -> String:
        """Return ``"ip:port"`` or ``"[ip]:port"`` as a string.

        Returns:
            Human-readable socket address string.
        """
        if self.ip.is_v6():
            return "[" + String(self.ip) + "]:" + String(Int(self.port))
        return String(self.ip) + ":" + String(Int(self.port))
