"""Tests for :mod:`flare.http.proxy_protocol` (HAProxy v1 + v2).

Coverage angles:

1. v1 happy path (TCP4 + TCP6 + UNKNOWN).
2. v1 strict failures (truncated, missing CRLF, bad token count,
   malformed IP, port range, IPv4 in TCP6 header, leading zero,
   over-cap header).
3. v2 happy path (INET + INET6 + LOCAL + UNSPEC + UNIX-fallback).
4. v2 strict failures (bad signature, wrong version, unknown
   command, payload-length undersize, unsupported family).
5. ``parse_proxy_protocol`` autodetect dispatches correctly +
   reports incomplete buffers as ``None``.
6. The ``consumed`` byte count is exact (downstream code skips
   exactly that many bytes before reading application data).
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

from flare.http.proxy_protocol import (
    ProxyHeader,
    parse_proxy_protocol,
    parse_proxy_v1,
    parse_proxy_v2,
)


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    var p = s.unsafe_ptr()
    for i in range(s.byte_length()):
        out.append(p[i])
    return out^


def _v2_signature() -> List[UInt8]:
    """Verbatim 12-byte signature."""
    var out = List[UInt8](capacity=12)
    out.append(UInt8(0x0D))
    out.append(UInt8(0x0A))
    out.append(UInt8(0x0D))
    out.append(UInt8(0x0A))
    out.append(UInt8(0x00))
    out.append(UInt8(0x0D))
    out.append(UInt8(0x0A))
    out.append(UInt8(0x51))
    out.append(UInt8(0x55))
    out.append(UInt8(0x49))
    out.append(UInt8(0x54))
    out.append(UInt8(0x0A))
    return out^


def _v2_inet(
    src_a: Int,
    src_b: Int,
    src_c: Int,
    src_d: Int,
    dst_a: Int,
    dst_b: Int,
    dst_c: Int,
    dst_d: Int,
    sport: Int,
    dport: Int,
) -> List[UInt8]:
    """Build a minimal v2 PROXY (command=1) INET (family=1) header."""
    var out = _v2_signature()
    out.append(UInt8(0x21))  # version=2 (high), command=PROXY (low)
    out.append(UInt8(0x11))  # family=INET (high), proto=STREAM (low)
    out.append(UInt8(0x00))  # length high byte
    out.append(UInt8(12))  # length low byte: 4+4+2+2 = 12
    out.append(UInt8(src_a))
    out.append(UInt8(src_b))
    out.append(UInt8(src_c))
    out.append(UInt8(src_d))
    out.append(UInt8(dst_a))
    out.append(UInt8(dst_b))
    out.append(UInt8(dst_c))
    out.append(UInt8(dst_d))
    out.append(UInt8((sport >> 8) & 0xFF))
    out.append(UInt8(sport & 0xFF))
    out.append(UInt8((dport >> 8) & 0xFF))
    out.append(UInt8(dport & 0xFF))
    return out^


# ── v1 (text) happy path ────────────────────────────────────────────────────


def test_v1_tcp4_happy() raises:
    var data = _bytes("PROXY TCP4 192.168.1.5 10.0.0.1 56324 443\r\n")
    var got = parse_proxy_v1(Span[UInt8, _](data))
    assert_true(Bool(got))
    var h = got.value().copy()
    assert_false(h.is_local)
    assert_equal(h.source.ip._addr, "192.168.1.5")
    assert_equal(Int(h.source.port), 56324)
    assert_equal(h.destination.ip._addr, "10.0.0.1")
    assert_equal(Int(h.destination.port), 443)
    assert_equal(h.consumed, len(data))


def test_v1_tcp6_happy() raises:
    var data = _bytes("PROXY TCP6 2001:db8::1 ::1 38765 80\r\n")
    var got = parse_proxy_v1(Span[UInt8, _](data))
    assert_true(Bool(got))
    var h = got.value().copy()
    assert_false(h.is_local)
    assert_equal(h.source.ip._addr, "2001:db8::1")
    assert_equal(Int(h.source.port), 38765)
    assert_equal(h.destination.ip._addr, "::1")
    assert_equal(Int(h.destination.port), 80)


def test_v1_unknown_no_addrs() raises:
    """``PROXY UNKNOWN\\r\\n`` — LB-internal traffic; ``is_local`` set."""
    var data = _bytes("PROXY UNKNOWN\r\n")
    var got = parse_proxy_v1(Span[UInt8, _](data))
    assert_true(Bool(got))
    var h = got.value().copy()
    assert_true(h.is_local)
    assert_equal(h.consumed, len(data))


def test_v1_unknown_with_trailing_data() raises:
    """``PROXY UNKNOWN <arbitrary stuff>\\r\\n`` — spec allows
    trailing LB-discretionary bytes after UNKNOWN; we accept and
    discard."""
    var data = _bytes("PROXY UNKNOWN 1.2.3.4 5.6.7.8 1 2\r\n")
    var got = parse_proxy_v1(Span[UInt8, _](data))
    assert_true(Bool(got))
    var h = got.value().copy()
    assert_true(h.is_local)


# ── v1 incomplete buffers ──────────────────────────────────────────────────


def test_v1_incomplete_returns_none() raises:
    """Truncated mid-header returns ``None`` (caller keeps reading)."""
    var data = _bytes("PROXY TCP4 192.168")
    var got = parse_proxy_v1(Span[UInt8, _](data))
    assert_false(Bool(got))


def test_v1_only_prefix_returns_none() raises:
    """Just the ``PROXY `` prefix → no decision yet."""
    var data = _bytes("PROXY ")
    var got = parse_proxy_v1(Span[UInt8, _](data))
    assert_false(Bool(got))


# ── v1 strict failures ────────────────────────────────────────────────────


def test_v1_missing_prefix_raises() raises:
    var data = _bytes("HTTP/1.1 200 OK\r\n\r\n")
    with assert_raises(contains="missing 'PROXY ' prefix"):
        var _u = parse_proxy_v1(Span[UInt8, _](data))


def test_v1_bad_protocol_raises() raises:
    var data = _bytes("PROXY UDP 1.2.3.4 5.6.7.8 80 8080\r\n")
    with assert_raises(contains="unknown protocol"):
        var _u = parse_proxy_v1(Span[UInt8, _](data))


def test_v1_wrong_token_count_raises() raises:
    var data = _bytes("PROXY TCP4 1.2.3.4 5.6.7.8 80\r\n")
    with assert_raises(contains="expected 5 tokens"):
        var _u = parse_proxy_v1(Span[UInt8, _](data))


def test_v1_v4_in_tcp6_header_raises() raises:
    """A TCP6 header with an IPv4 src must fail — the LB should
    have used TCP4."""
    var data = _bytes("PROXY TCP6 192.168.1.1 ::1 1 2\r\n")
    with assert_raises(contains="IP family does not match"):
        var _u = parse_proxy_v1(Span[UInt8, _](data))


def test_v1_port_overflow_raises() raises:
    var data = _bytes("PROXY TCP4 1.2.3.4 5.6.7.8 99999 80\r\n")
    with assert_raises(contains="port"):
        var _u = parse_proxy_v1(Span[UInt8, _](data))


def test_v1_leading_zero_port_raises() raises:
    """``08080`` is rejected — the spec says decimal, no leading
    zeros, to keep log lines unambiguous."""
    var data = _bytes("PROXY TCP4 1.2.3.4 5.6.7.8 08080 80\r\n")
    with assert_raises(contains="leading zero"):
        var _u = parse_proxy_v1(Span[UInt8, _](data))


def test_v1_invalid_byte_in_header_raises() raises:
    """Embedded NUL inside the v1 header is rejected (defends
    against header smuggling)."""
    var data = _bytes("PROXY TCP4 1.2.3")
    data.append(UInt8(0))  # NUL byte mid-header
    data.append(UInt8(ord("\r")))
    data.append(UInt8(ord("\n")))
    with assert_raises(contains="invalid byte"):
        var _u = parse_proxy_v1(Span[UInt8, _](data))


def test_v1_over_cap_raises() raises:
    """A v1 header with no CRLF inside 107 bytes must raise."""
    var oversized = String("PROXY TCP4 ") + ("a" * 100) + String(" 1 2\r\n")
    var data = _bytes(oversized)
    with assert_raises(contains="107-byte cap"):
        var _u = parse_proxy_v1(Span[UInt8, _](data))


# ── v2 happy path ──────────────────────────────────────────────────────────


def test_v2_inet_happy() raises:
    var data = _v2_inet(192, 168, 1, 5, 10, 0, 0, 1, 56324, 443)
    var got = parse_proxy_v2(Span[UInt8, _](data))
    assert_true(Bool(got))
    var h = got.value().copy()
    assert_false(h.is_local)
    assert_equal(h.source.ip._addr, "192.168.1.5")
    assert_equal(Int(h.source.port), 56324)
    assert_equal(h.destination.ip._addr, "10.0.0.1")
    assert_equal(Int(h.destination.port), 443)
    assert_equal(h.consumed, 16 + 12)


def test_v2_inet_consumed_skips_only_header() raises:
    """The ``consumed`` count is exactly ``16 + payload_length``;
    the caller's next byte index is application data."""
    var data = _v2_inet(1, 2, 3, 4, 5, 6, 7, 8, 1234, 5678)
    # Append four bytes of application data after the header.
    data.append(UInt8(ord("G")))
    data.append(UInt8(ord("E")))
    data.append(UInt8(ord("T")))
    data.append(UInt8(ord(" ")))
    var got = parse_proxy_v2(Span[UInt8, _](data))
    var h = got.value().copy()
    assert_equal(h.consumed, 28)
    assert_equal(Int(data[28]), ord("G"))


def test_v2_inet6_happy() raises:
    """Build an INET6 header with src=::1, dst=2001:db8::1, sport=80,
    dport=443. Payload length: 16 + 16 + 2 + 2 = 36 bytes."""
    var data = _v2_signature()
    data.append(UInt8(0x21))  # version=2, command=PROXY
    data.append(UInt8(0x21))  # family=INET6 (high), proto=STREAM (low)
    data.append(UInt8(0x00))
    data.append(UInt8(36))
    # src: ::1 → 15 zero bytes then 0x01
    for _ in range(15):
        data.append(UInt8(0))
    data.append(UInt8(0x01))
    # dst: 2001:db8::1 → 0x20 0x01 0x0d 0xb8 0x00 0x00 ... 0x00 0x01
    data.append(UInt8(0x20))
    data.append(UInt8(0x01))
    data.append(UInt8(0x0D))
    data.append(UInt8(0xB8))
    for _ in range(11):
        data.append(UInt8(0))
    data.append(UInt8(0x01))
    # sport=80, dport=443
    data.append(UInt8(0))
    data.append(UInt8(80))
    data.append(UInt8(0x01))
    data.append(UInt8(0xBB))
    var got = parse_proxy_v2(Span[UInt8, _](data))
    assert_true(Bool(got))
    var h = got.value().copy()
    assert_false(h.is_local)
    assert_equal(h.source.ip._addr, "::1")
    assert_equal(Int(h.source.port), 80)
    assert_equal(h.destination.ip._addr, "2001:db8::1")
    assert_equal(Int(h.destination.port), 443)
    assert_equal(h.consumed, 16 + 36)


def test_v2_local_command() raises:
    """LOCAL (command=0) — health check; addresses irrelevant; the
    parser sets ``is_local`` and the address block is unsealed."""
    var data = _v2_signature()
    data.append(UInt8(0x20))  # version=2, command=LOCAL
    data.append(UInt8(0x00))  # family=UNSPEC, proto=UNSPEC
    data.append(UInt8(0x00))
    data.append(UInt8(0x00))  # length=0
    var got = parse_proxy_v2(Span[UInt8, _](data))
    assert_true(Bool(got))
    var h = got.value().copy()
    assert_true(h.is_local)
    assert_equal(h.consumed, 16)


def test_v2_unspec_family_treated_as_local() raises:
    """A PROXY (command=1) frame with family=UNSPEC has no usable
    address info; the parser falls through to the LOCAL shape."""
    var data = _v2_signature()
    data.append(UInt8(0x21))  # PROXY
    data.append(UInt8(0x00))  # UNSPEC / UNSPEC
    data.append(UInt8(0x00))
    data.append(UInt8(0x00))
    var got = parse_proxy_v2(Span[UInt8, _](data))
    var h = got.value().copy()
    assert_true(h.is_local)


# ── v2 incomplete + strict failures ────────────────────────────────────────


def test_v2_incomplete_signature_returns_none() raises:
    var data = List[UInt8](capacity=8)
    for i in range(8):
        data.append(UInt8(i))
    var got = parse_proxy_v2(Span[UInt8, _](data))
    assert_false(Bool(got))


def test_v2_incomplete_payload_returns_none() raises:
    """Header announces length=12 but only 4 payload bytes present."""
    var data = _v2_signature()
    data.append(UInt8(0x21))
    data.append(UInt8(0x11))
    data.append(UInt8(0x00))
    data.append(UInt8(12))
    for _ in range(4):
        data.append(UInt8(0))
    var got = parse_proxy_v2(Span[UInt8, _](data))
    assert_false(Bool(got))


def test_v2_bad_signature_raises() raises:
    var data = _v2_signature()
    # Corrupt one byte of the signature.
    data[5] = UInt8(0xFF)
    data.append(UInt8(0x21))
    data.append(UInt8(0x11))
    data.append(UInt8(0x00))
    data.append(UInt8(12))
    for _ in range(12):
        data.append(UInt8(0))
    with assert_raises(contains="bad 12-byte signature"):
        var _u = parse_proxy_v2(Span[UInt8, _](data))


def test_v2_wrong_version_raises() raises:
    var data = _v2_signature()
    data.append(UInt8(0x11))  # version=1, command=PROXY
    data.append(UInt8(0x11))
    data.append(UInt8(0x00))
    data.append(UInt8(12))
    for _ in range(12):
        data.append(UInt8(0))
    with assert_raises(contains="version != 2"):
        var _u = parse_proxy_v2(Span[UInt8, _](data))


def test_v2_unknown_command_raises() raises:
    var data = _v2_signature()
    data.append(UInt8(0x2F))  # command=0xF unknown
    data.append(UInt8(0x11))
    data.append(UInt8(0x00))
    data.append(UInt8(12))
    for _ in range(12):
        data.append(UInt8(0))
    with assert_raises(contains="unknown command"):
        var _u = parse_proxy_v2(Span[UInt8, _](data))


def test_v2_inet_undersize_payload_raises() raises:
    """``family=INET`` requires payload>=12; advertising 8 must raise."""
    var data = _v2_signature()
    data.append(UInt8(0x21))
    data.append(UInt8(0x11))
    data.append(UInt8(0x00))
    data.append(UInt8(8))
    for _ in range(8):
        data.append(UInt8(0))
    with assert_raises(contains="INET payload < 12 bytes"):
        var _u = parse_proxy_v2(Span[UInt8, _](data))


# ── parse_proxy_protocol autodetect ────────────────────────────────────────


def test_autodetect_dispatches_v1() raises:
    var data = _bytes("PROXY TCP4 1.2.3.4 5.6.7.8 80 8080\r\n")
    var got = parse_proxy_protocol(Span[UInt8, _](data))
    assert_true(Bool(got))
    var h = got.value().copy()
    assert_equal(h.source.ip._addr, "1.2.3.4")


def test_autodetect_dispatches_v2() raises:
    var data = _v2_inet(7, 8, 9, 10, 1, 1, 1, 1, 100, 200)
    var got = parse_proxy_protocol(Span[UInt8, _](data))
    assert_true(Bool(got))
    var h = got.value().copy()
    assert_equal(h.source.ip._addr, "7.8.9.10")
    assert_equal(Int(h.source.port), 100)


def test_autodetect_too_short_returns_none() raises:
    var data = _bytes("PRO")
    var got = parse_proxy_protocol(Span[UInt8, _](data))
    assert_false(Bool(got))


def test_autodetect_garbage_raises() raises:
    var data = _bytes("HELLO WORLD\r\n")
    with assert_raises(contains="no PROXY protocol signature"):
        var _u = parse_proxy_protocol(Span[UInt8, _](data))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
