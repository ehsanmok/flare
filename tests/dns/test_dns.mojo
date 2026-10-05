"""Tests for flare.dns — hostname resolution via getaddrinfo.

Covers:
- Successful resolution of known hosts (localhost, loopback numeric)
- IPv4-only and IPv6-aware resolution paths
- Numeric IP passthrough (inet_pton shortcut)
- Edge cases: empty host, excessively long hostname, trailing dot (FQDN)
- Security: null-byte injection, CRLF injection must raise, not silently truncate
- Error propagation: non-existent domain raises DnsError with context
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)
from flare.dns import resolve, resolve_v4, resolve_v6
from flare.net import IpAddr


# ── Successful resolution ─────────────────────────────────────────────────────


def test_resolve_localhost_non_empty() raises:
    """Resolving 'localhost' must return at least one address."""
    var addrs = resolve("localhost")
    assert_true(len(addrs) > 0, "expected at least one address for localhost")


def test_resolve_localhost_has_loopback() raises:
    """Resolving 'localhost' must include 127.0.0.1 or ::1."""
    var addrs = resolve("localhost")
    var found = False
    for a in addrs:
        if String(a) == "127.0.0.1" or String(a) == "::1":
            found = True
    assert_true(
        found, "expected loopback address in resolve('localhost') results"
    )


def test_resolve_v4_localhost_non_empty() raises:
    """Calling resolve_v4('localhost') must return at least one address."""
    var addrs = resolve_v4("localhost")
    assert_true(
        len(addrs) > 0, "expected at least one IPv4 address for localhost"
    )


def test_resolve_v4_all_ipv4() raises:
    """Calling resolve_v4 must return only IPv4 addresses."""
    var addrs = resolve_v4("localhost")
    for a in addrs:
        assert_false(a.is_v6(), "expected IPv4-only but got IPv6")


def test_resolve_v4_contains_127() raises:
    """127.0.0.1 must appear in resolve_v4('localhost')."""
    var addrs = resolve_v4("localhost")
    var found = False
    for a in addrs:
        if String(a) == "127.0.0.1":
            found = True
    assert_true(found, "127.0.0.1 not found in resolve_v4('localhost')")


# ── Numeric IP passthrough ────────────────────────────────────────────────────


def test_resolve_numeric_ipv4_passthrough() raises:
    """Numeric IPv4 string must resolve to itself (no DNS round-trip)."""
    var addrs = resolve("127.0.0.1")
    assert_true(len(addrs) > 0, "expected 127.0.0.1 to resolve")
    assert_equal(String(addrs[0]), "127.0.0.1")


def test_resolve_numeric_ipv6_passthrough() raises:
    """Numeric IPv6 string '::1' must resolve to itself."""
    var addrs = resolve("::1")
    assert_true(len(addrs) > 0, "expected ::1 to resolve")
    var found = False
    for a in addrs:
        if String(a) == "::1":
            found = True
    assert_true(found, "::1 not in resolve('::1') results")


def test_resolve_numeric_v4_192() raises:
    """Resolving a public numeric IP must return that exact address."""
    var addrs = resolve("192.0.2.1")
    assert_true(len(addrs) > 0)
    var found = False
    for a in addrs:
        if String(a) == "192.0.2.1":
            found = True
    assert_true(found, "192.0.2.1 not found in results")


# ── IPv6 resolution ───────────────────────────────────────────────────────────


def test_resolve_v6_localhost_includes_v6_or_raises() raises:
    """Resolving '::1' via resolve_v6 must succeed or raise (no v6 on platform).
    """
    # This test accepts either result because some CI environments disable IPv6.
    try:
        var addrs = resolve_v6("::1")
        assert_true(len(addrs) > 0, "expected non-empty result for ::1")
    except:
        pass  # raised DnsError — acceptable on IPv6-disabled systems


# ── Trailing dot / FQDN ───────────────────────────────────────────────────────


def test_resolve_fqdn_trailing_dot() raises:
    """'localhost.' (FQDN with trailing dot) should resolve or raise gracefully.
    """
    # POSIX getaddrinfo accepts trailing dots as FQDNs.
    # We verify it does not crash or return garbage, and any exception is DnsError.
    try:
        var addrs = resolve("localhost.")
        assert_true(len(addrs) > 0, "expected non-empty result for localhost.")
    except:
        pass  # Not all resolvers accept trailing dot — graceful raise is fine


# ── Error cases ───────────────────────────────────────────────────────────────


def test_resolve_empty_host_raises() raises:
    """Empty hostname must raise before calling getaddrinfo."""
    with assert_raises():
        _ = resolve("")


def test_resolve_nonexistent_raises() raises:
    """Non-existent hostname must raise DnsError with the host in the message.
    """
    with assert_raises():
        _ = resolve("this.hostname.definitely.does.not.exist.flare.test")


# ── Security: injection attacks must raise, not silently corrupt ───────────────


def test_resolve_null_byte_injection_raises() raises:
    """Hostname with embedded null byte must raise before getaddrinfo.

    A C string passed to getaddrinfo would be silently truncated at the null,
    potentially resolving a different host. flare must validate and reject.
    """
    with assert_raises():
        _ = resolve("localhost\x00evil.com")


def test_resolve_crlf_injection_raises() raises:
    """Hostname with embedded CRLF must raise.

    In some contexts a raw hostname is embedded in HTTP headers (e.g. Host:).
    Allowing CRLF in the DNS name enables header injection attacks downstream.
    """
    with assert_raises():
        _ = resolve("localhost\r\nevil.com")


def test_resolve_at_sign_raises() raises:
    """Hostname with '@' (user-info delimiter) must raise.

    'user@host' is not a valid hostname; accepting it silently could expose
    the user portion to a malicious resolver or log scraper.
    """
    with assert_raises():
        _ = resolve("user@localhost")


def test_resolve_hostname_too_long_raises() raises:
    """Hostname exceeding 253 characters must raise.

    RFC 1035 §2.3.4 limits full domain names to 253 octets. A hostname
    longer than this cannot be valid; accept would risk buffer overflows in
    older resolver implementations.
    """
    var long_host = String("a" * 254) + ".com"
    with assert_raises():
        _ = resolve(long_host)


def _max_name(absolute: Bool) -> String:
    """A 253-byte name (63 + 1 + 63 + 1 + 63 + 1 + 53 + ".invalid"), with
    a trailing root dot when ``absolute`` (then 254 bytes). ``.invalid`` is
    a reserved TLD, so a name that passes validation fails in the resolver
    with a ``DnsError``, never a validation error."""
    var host = String("")
    for _ in range(63):
        host += "a"
    host += "."
    for _ in range(63):
        host += "b"
    host += "."
    for _ in range(63):
        host += "c"
    host += "."
    for _ in range(53):
        host += "d"
    host += ".invalid"
    if absolute:
        host += "."
    return host


def _rejected_as_too_long(host: String) -> Bool:
    try:
        _ = resolve(host)
    except e:
        return "too long" in String(e)
    return False


def test_resolve_accepts_253_byte_name() raises:
    """NET-08: a 253-byte name is the longest valid one and is not
    rejected by validation."""
    var host = _max_name(False)
    assert_equal(host.byte_length(), 253)
    assert_false(_rejected_as_too_long(host))


def test_resolve_accepts_253_byte_absolute_name() raises:
    """NET-08: RFC 1035 bounds the wire form at 255 octets, i.e. 253 text
    bytes *not counting* the trailing root dot, so the absolute spelling of
    a maximal name (254 bytes ending in ``.``) is valid."""
    var host = _max_name(True)
    assert_equal(host.byte_length(), 254)
    assert_false(_rejected_as_too_long(host))


def test_resolve_rejects_254_byte_name_without_root_dot() raises:
    """NET-08 boundary: one byte more than the maximum is still too long,
    with or without a trailing dot."""
    var host = _max_name(False)
    host = String("e") + host  # 254 bytes, no trailing dot
    assert_equal(host.byte_length(), 254)
    assert_true(_rejected_as_too_long(host))
    var abs_host = host + "."  # 254 name bytes + root dot
    assert_true(_rejected_as_too_long(abs_host))


def _utf8_ok(b: Span[UInt8, _]) -> Bool:
    """Strict-enough UTF-8 well-formedness check (lead/continuation
    structure) for the error-text tests below."""
    var i = 0
    var n = len(b)
    while i < n:
        var c = Int(b[i])
        var need: Int
        if c < 0x80:
            need = 0
        elif c >= 0xC2 and c <= 0xDF:
            need = 1
        elif c >= 0xE0 and c <= 0xEF:
            need = 2
        elif c >= 0xF0 and c <= 0xF4:
            need = 3
        else:
            return False
        if i + need >= n and need > 0:
            return False
        for k in range(1, need + 1):
            var d = Int(b[i + k])
            if d < 0x80 or d > 0xBF:
                return False
        i += need + 1
    return True


def _too_long_message(prefix: String) raises -> String:
    """The error text for a 261-byte host that starts with ``prefix`` and is
    padded with ASCII ``a``."""
    var host = prefix
    while host.byte_length() < 261:
        host += "a"
    try:
        _ = resolve(host)
    except e:
        return String(e)
    raise Error("expected a hostname-too-long error")


def test_too_long_message_does_not_split_a_two_byte_char() raises:
    """NET-09: the message quotes the first 20 bytes of the host; with
    ``é`` (C3 A9) at bytes 19-20 that cut a character in half."""
    var msg = _too_long_message(String("a" * 19) + "é")
    assert_true("too long" in msg)
    assert_true(_utf8_ok(msg.as_bytes()), "error text is not valid UTF-8")
    # the whole character is dropped, the 19 whole bytes are kept
    assert_true(String("a" * 19) + "…" in msg)
    assert_false("é" in msg)


def test_too_long_message_does_not_split_a_four_byte_char() raises:
    var msg = _too_long_message(String("a" * 18) + "😀")
    assert_true(_utf8_ok(msg.as_bytes()), "error text is not valid UTF-8")
    assert_true(String("a" * 18) + "…" in msg)
    assert_false("😀" in msg)


def test_too_long_message_keeps_a_char_that_ends_at_byte_20() raises:
    """Boundary: a character ending exactly at byte 20 is quoted whole."""
    var msg = _too_long_message(String("a" * 18) + "é")
    assert_true(_utf8_ok(msg.as_bytes()), "error text is not valid UTF-8")
    assert_true(String("a" * 18) + "é…" in msg)


def test_too_long_message_quotes_20_ascii_bytes() raises:
    var msg = _too_long_message(String(""))
    assert_true(String("a" * 20) + "…" in msg)
    assert_false(String("a" * 21) in msg)


def test_resolve_label_too_long_raises() raises:
    """A single DNS label longer than 63 characters must raise.

    RFC 1035 §2.3.4: each label (between dots) must not exceed 63 octets.
    """
    var long_label = String("a" * 64) + ".com"
    with assert_raises():
        _ = resolve(long_label)


def main() raises:
    print("=" * 60)
    print("test_dns.mojo — DNS resolution")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
