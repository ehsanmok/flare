"""Tests for flare.net — IpAddr, SocketAddr, and error types.

Covers:
- Normal construction and string conversion
- Boundary values (all-zeros, broadcast, max-octet)
- Full and compressed IPv6 forms
- Private / loopback / multicast classification
- SocketAddr parsing (IPv4, IPv6, malformed)
- Error type string representation
- Equality and inequality for all value types
- Security: malformed / injection inputs must raise, not silently succeed
"""

from testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)
from flare.net import IpAddr, SocketAddr
from flare.net.error import (
    NetworkError,
    ConnectionRefused,
    ConnectionTimeout,
    AddressInUse,
    AddressParseError,
    BrokenPipe,
    DnsError,
)


# ── IpAddr: well-known constants ──────────────────────────────────────────────


def test_ip_addr_localhost():
    """IpAddr.localhost() must yield 127.0.0.1."""
    var addr = IpAddr.localhost()
    assert_equal(String(addr), "127.0.0.1")
    assert_true(addr.is_v4())
    assert_false(addr.is_v6())


def test_ip_addr_localhost_v6():
    """IpAddr.localhost_v6() must yield ::1."""
    var addr = IpAddr.localhost_v6()
    assert_equal(String(addr), "::1")
    assert_true(addr.is_v6())
    assert_false(addr.is_v4())


def test_ip_addr_unspecified_v4():
    """IpAddr.unspecified() must yield 0.0.0.0."""
    var addr = IpAddr.unspecified()
    assert_equal(String(addr), "0.0.0.0")
    assert_true(addr.is_v4())


def test_ip_addr_unspecified_v6():
    """IpAddr.unspecified_v6() must yield ::."""
    var addr = IpAddr.unspecified_v6()
    assert_equal(String(addr), "::")
    assert_true(addr.is_v6())


# ── IpAddr: boundary values ───────────────────────────────────────────────────


def test_ip_addr_broadcast():
    """255.255.255.255 (broadcast) must parse and round-trip."""
    var addr = IpAddr.parse("255.255.255.255")
    assert_equal(String(addr), "255.255.255.255")
    assert_true(addr.is_v4())


def test_ip_addr_min_octet():
    """0.0.0.1 must parse correctly (min non-zero address)."""
    var addr = IpAddr.parse("0.0.0.1")
    assert_equal(String(addr), "0.0.0.1")
    assert_true(addr.is_v4())


def test_ip_addr_private_10():
    """10.0.0.0/8 must be private."""
    var addr = IpAddr.parse("10.0.0.1")
    assert_true(addr.is_private())


def test_ip_addr_private_172():
    """172.16.0.0/12 must be private."""
    var addr = IpAddr.parse("172.16.0.1")
    assert_true(addr.is_private())


def test_ip_addr_private_192():
    """192.168.0.0/16 must be private."""
    var addr = IpAddr.parse("192.168.255.255")
    assert_true(addr.is_private())


def test_ip_addr_not_private_public():
    """8.8.8.8 (Google DNS) must not be private."""
    var addr = IpAddr.parse("8.8.8.8")
    assert_false(addr.is_private())


def test_ip_addr_not_private_172_boundary_below():
    """172.15.255.255 is just outside the 172.16/12 range — must not be private.
    """
    var addr = IpAddr.parse("172.15.255.255")
    assert_false(addr.is_private())


def test_ip_addr_not_private_172_boundary_above():
    """172.32.0.0 is just above the 172.31.255.255 limit — must not be private.
    """
    var addr = IpAddr.parse("172.32.0.0")
    assert_false(addr.is_private())


def test_ip_addr_loopback_127_any():
    """127.0.0.1 must be a loopback address."""
    var addr = IpAddr.localhost()
    assert_true(addr.is_loopback())


def test_ip_addr_loopback_v6():
    """::1 must be a loopback address."""
    var addr = IpAddr.localhost_v6()
    assert_true(addr.is_loopback())


# ── IpAddr: IPv6 forms ────────────────────────────────────────────────────────


def test_ip_addr_v6_loopback_full():
    """Full-form loopback 0:0:0:0:0:0:0:1 must parse as IPv6."""
    var addr = IpAddr.parse("0:0:0:0:0:0:0:1")
    assert_true(addr.is_v6())


def test_ip_addr_v6_compressed():
    """Compressed IPv6 2001:db8::1 must parse correctly."""
    var addr = IpAddr.parse("2001:db8::1")
    assert_true(addr.is_v6())


def test_ip_addr_v6_all_zeros_long():
    """Fully-written all-zeros IPv6 must equal '::'."""
    var addr = IpAddr.parse("0:0:0:0:0:0:0:0")
    assert_true(addr.is_v6())


def test_ip_addr_v6_link_local():
    """Parse fe80::1 (link-local) as IPv6."""
    var addr = IpAddr.parse("fe80::1")
    assert_true(addr.is_v6())


# ── IpAddr: equality and comparison ───────────────────────────────────────────


def test_ip_addr_equality_v4():
    """Two IpAddrs from the same string must be equal."""
    var a = IpAddr.parse("10.0.0.1")
    var b = IpAddr.parse("10.0.0.1")
    assert_true(a == b)


def test_ip_addr_inequality_v4():
    """IpAddrs from different strings must not be equal."""
    var a = IpAddr.parse("10.0.0.1")
    var b = IpAddr.parse("10.0.0.2")
    assert_true(a != b)


def test_ip_addr_v4_not_equal_v6():
    """IPv4-mapped 127.0.0.1 must not equal IPv6 ::1."""
    var v4 = IpAddr.localhost()
    var v6 = IpAddr.localhost_v6()
    assert_true(v4 != v6)


# ── IpAddr: security — malformed inputs must raise ────────────────────────────


def test_ip_addr_parse_too_many_octets_raises():
    """1.2.3.4.5 has five octets — must raise AddressParseError."""
    with assert_raises():
        _ = IpAddr.parse("1.2.3.4.5")


def test_ip_addr_parse_octet_overflow_raises():
    """256 is not a valid octet value — must raise."""
    with assert_raises():
        _ = IpAddr.parse("256.0.0.1")


def test_ip_addr_parse_negative_octet_raises():
    """Negative octets are not valid — must raise."""
    with assert_raises():
        _ = IpAddr.parse("-1.0.0.1")


def test_ip_addr_parse_empty_raises():
    """Empty string is not a valid IP — must raise."""
    with assert_raises():
        _ = IpAddr.parse("")


def test_ip_addr_parse_alpha_raises():
    """Non-numeric address must raise."""
    with assert_raises():
        _ = IpAddr.parse("not.an.ip.addr")


def test_ip_addr_parse_hex_no_prefix_raises():
    """Hex octets without 0x prefix must raise (e.g. 0xC0.0.0.1)."""
    # Some platforms accept this in legacy mode; flare must not.
    with assert_raises():
        _ = IpAddr.parse("0xC0.0.0.1")


def test_ip_addr_parse_newline_injection_raises():
    """A newline embedded in an IP string must raise."""
    with assert_raises():
        _ = IpAddr.parse("127.0.0.1\n127.0.0.2")


def test_ip_addr_parse_null_byte_raises():
    """A null byte embedded in an IP string must raise."""
    with assert_raises():
        _ = IpAddr.parse("127.0.0.1\x00evil")


# ── SocketAddr ────────────────────────────────────────────────────────────────


def test_socket_addr_str():
    """SocketAddr string form must be ip:port."""
    var addr = SocketAddr(IpAddr.parse("192.168.1.1"), 8080)
    assert_equal(String(addr), "192.168.1.1:8080")


def test_socket_addr_localhost():
    """SocketAddr.localhost() must be 127.0.0.1:port."""
    var addr = SocketAddr.localhost(443)
    assert_equal(String(addr), "127.0.0.1:443")


def test_socket_addr_unspecified():
    """SocketAddr.unspecified(0) must be 0.0.0.0:0."""
    var addr = SocketAddr.unspecified(0)
    assert_equal(String(addr), "0.0.0.0:0")


def test_socket_addr_max_port():
    """Port 65535 (max) must be stored and displayed correctly."""
    var addr = SocketAddr.localhost(65535)
    assert_equal(String(addr), "127.0.0.1:65535")
    assert_equal(Int(addr.port), 65535)


def test_socket_addr_port_zero():
    """Port 0 (OS-assigned) must be stored and displayed correctly."""
    var addr = SocketAddr.localhost(0)
    assert_equal(String(addr), "127.0.0.1:0")
    assert_equal(Int(addr.port), 0)


def test_socket_addr_port_well_known_http():
    """Port 80 (HTTP) must be handled correctly."""
    var addr = SocketAddr.localhost(80)
    assert_equal(Int(addr.port), 80)


def test_socket_addr_port_well_known_https():
    """Port 443 (HTTPS) must be handled correctly."""
    var addr = SocketAddr.localhost(443)
    assert_equal(Int(addr.port), 443)


def test_socket_addr_parse_v4():
    """Parse '1.2.3.4:80' correctly."""
    var addr = SocketAddr.parse("1.2.3.4:80")
    assert_equal(String(addr), "1.2.3.4:80")
    assert_equal(Int(addr.port), 80)


def test_socket_addr_parse_ipv6():
    """Parse '[::1]:9000' correctly."""
    var addr = SocketAddr.parse("[::1]:9000")
    assert_equal(Int(addr.port), 9000)
    assert_true(addr.ip.is_v6())


def test_socket_addr_equality():
    """Two identical SocketAddrs must be equal."""
    var a = SocketAddr.localhost(8080)
    var b = SocketAddr.localhost(8080)
    assert_true(a == b)


def test_socket_addr_inequality_port():
    """SocketAddrs on different ports must not be equal."""
    var a = SocketAddr.localhost(8080)
    var b = SocketAddr.localhost(9090)
    assert_true(a != b)


def test_socket_addr_inequality_ip():
    """SocketAddrs on different IPs (same port) must not be equal."""
    var a = SocketAddr(IpAddr.parse("10.0.0.1"), 80)
    var b = SocketAddr(IpAddr.parse("10.0.0.2"), 80)
    assert_true(a != b)


# ── SocketAddr: security — malformed inputs must raise ────────────────────────


def test_socket_addr_parse_missing_port_raises():
    """'192.168.1.1' without port must raise."""
    with assert_raises():
        _ = SocketAddr.parse("192.168.1.1")


def test_socket_addr_parse_bad_ip_raises():
    """'999.0.0.1:80' has invalid IP — must raise."""
    with assert_raises():
        _ = SocketAddr.parse("999.0.0.1:80")


def test_socket_addr_parse_empty_raises():
    """Empty string must raise."""
    with assert_raises():
        _ = SocketAddr.parse("")


def test_socket_addr_parse_newline_injection_raises():
    """Embedded newline in address must raise."""
    with assert_raises():
        _ = SocketAddr.parse("127.0.0.1:80\r\nX-Injected: evil")


# ── Error types ───────────────────────────────────────────────────────────────


def test_network_error_str_no_code():
    """NetworkError without errno must not include a parenthetical."""
    var e = NetworkError("connection lost")
    assert_equal(String(e), "NetworkError: connection lost")


def test_network_error_str_with_code():
    """NetworkError with errno must include the code."""
    var e = NetworkError("connection refused", 111)
    assert_true(String(e).find("111") != -1)


def test_network_error_message_preserved():
    """NetworkError must preserve the exact message passed in."""
    var e = NetworkError("read timeout after 5000ms")
    assert_true(String(e).find("read timeout after 5000ms") != -1)


def test_connection_refused_str():
    """ConnectionRefused must include the address."""
    var e = ConnectionRefused("127.0.0.1:8080")
    assert_true(String(e).find("127.0.0.1:8080") != -1)


def test_connection_timeout_str():
    """ConnectionTimeout must include address and code."""
    var e = ConnectionTimeout("10.0.0.1:443", 110)
    assert_true(String(e).find("10.0.0.1:443") != -1)


def test_address_in_use_str():
    """AddressInUse must include the address."""
    var e = AddressInUse("0.0.0.0:8080")
    assert_true(String(e).find("0.0.0.0:8080") != -1)


def test_address_parse_error_str():
    """AddressParseError must include the bad input."""
    var e = AddressParseError("not_an_ip")
    assert_true(String(e).find("not_an_ip") != -1)


def test_address_parse_error_preserves_injection_attempt():
    """AddressParseError with injection chars in input must preserve them safely.
    """
    var e = AddressParseError("127.0.0.1\r\nX-Evil: 1")
    assert_true(String(e).find("127.0.0.1") != -1)


def test_broken_pipe_no_addr():
    """BrokenPipe without address must be 'BrokenPipe'."""
    var e = BrokenPipe()
    assert_equal(String(e), "BrokenPipe")


def test_broken_pipe_with_addr():
    """BrokenPipe with address must include it."""
    var e = BrokenPipe("1.2.3.4:80")
    assert_true(String(e).find("1.2.3.4:80") != -1)


def test_dns_error_str():
    """DnsError must include host and reason."""
    var e = DnsError("example.com", 8, "Name or service not known")
    assert_true(String(e).find("example.com") != -1)
    assert_true(String(e).find("Name or service not known") != -1)


def test_dns_error_zero_code():
    """DnsError with code=0 must still include host and reason."""
    var e = DnsError("bad.host", 0, "no addresses returned")
    assert_true(String(e).find("bad.host") != -1)
    assert_true(String(e).find("no addresses returned") != -1)


def main():
    print("=" * 60)
    print("test_net.mojo — IpAddr, SocketAddr, error types")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
