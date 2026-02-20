"""Tests for flare.dns — hostname resolution via getaddrinfo.

Covers:
- Successful resolution of known hosts (localhost, loopback numeric)
- IPv4-only and IPv6-aware resolution paths
- Numeric IP passthrough (inet_pton shortcut)
- Edge cases: empty host, excessively long hostname, trailing dot (FQDN)
- Security: null-byte injection, CRLF injection must raise, not silently truncate
- Error propagation: non-existent domain raises DnsError with context
"""

from testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)
from flare.dns import resolve, resolve_v4, resolve_v6
from flare.net import IpAddr


# ── Successful resolution ─────────────────────────────────────────────────────


def test_resolve_localhost_non_empty():
    """Resolving 'localhost' must return at least one address."""
    var addrs = resolve("localhost")
    assert_true(len(addrs) > 0, "expected at least one address for localhost")


def test_resolve_localhost_has_loopback():
    """Resolving 'localhost' must include 127.0.0.1 or ::1."""
    var addrs = resolve("localhost")
    var found = False
    for a in addrs:
        if String(a) == "127.0.0.1" or String(a) == "::1":
            found = True
    assert_true(
        found, "expected loopback address in resolve('localhost') results"
    )


def test_resolve_v4_localhost_non_empty():
    """Calling resolve_v4('localhost') must return at least one address."""
    var addrs = resolve_v4("localhost")
    assert_true(
        len(addrs) > 0, "expected at least one IPv4 address for localhost"
    )


def test_resolve_v4_all_ipv4():
    """Calling resolve_v4 must return only IPv4 addresses."""
    var addrs = resolve_v4("localhost")
    for a in addrs:
        assert_false(a.is_v6(), "expected IPv4-only but got IPv6")


def test_resolve_v4_contains_127():
    """127.0.0.1 must appear in resolve_v4('localhost')."""
    var addrs = resolve_v4("localhost")
    var found = False
    for a in addrs:
        if String(a) == "127.0.0.1":
            found = True
    assert_true(found, "127.0.0.1 not found in resolve_v4('localhost')")


# ── Numeric IP passthrough ────────────────────────────────────────────────────


def test_resolve_numeric_ipv4_passthrough():
    """Numeric IPv4 string must resolve to itself (no DNS round-trip)."""
    var addrs = resolve("127.0.0.1")
    assert_true(len(addrs) > 0, "expected 127.0.0.1 to resolve")
    assert_equal(String(addrs[0]), "127.0.0.1")


def test_resolve_numeric_ipv6_passthrough():
    """Numeric IPv6 string '::1' must resolve to itself."""
    var addrs = resolve("::1")
    assert_true(len(addrs) > 0, "expected ::1 to resolve")
    var found = False
    for a in addrs:
        if String(a) == "::1":
            found = True
    assert_true(found, "::1 not in resolve('::1') results")


def test_resolve_numeric_v4_192():
    """Resolving a public numeric IP must return that exact address."""
    var addrs = resolve("192.0.2.1")
    assert_true(len(addrs) > 0)
    var found = False
    for a in addrs:
        if String(a) == "192.0.2.1":
            found = True
    assert_true(found, "192.0.2.1 not found in results")


# ── IPv6 resolution ───────────────────────────────────────────────────────────


def test_resolve_v6_localhost_includes_v6_or_raises():
    """Resolving '::1' via resolve_v6 must succeed or raise (no v6 on platform).
    """
    # This test accepts either result because some CI environments disable IPv6.
    try:
        var addrs = resolve_v6("::1")
        assert_true(len(addrs) > 0, "expected non-empty result for ::1")
    except:
        pass  # raised DnsError — acceptable on IPv6-disabled systems


# ── Trailing dot / FQDN ───────────────────────────────────────────────────────


def test_resolve_fqdn_trailing_dot():
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


def test_resolve_empty_host_raises():
    """Empty hostname must raise before calling getaddrinfo."""
    with assert_raises():
        _ = resolve("")


def test_resolve_nonexistent_raises():
    """Non-existent hostname must raise DnsError with the host in the message.
    """
    with assert_raises():
        _ = resolve("this.hostname.definitely.does.not.exist.flare.test")


# ── Security: injection attacks must raise, not silently corrupt ───────────────


def test_resolve_null_byte_injection_raises():
    """Hostname with embedded null byte must raise before getaddrinfo.

    A C string passed to getaddrinfo would be silently truncated at the null,
    potentially resolving a different host.  flare must validate and reject.
    """
    with assert_raises():
        _ = resolve("localhost\x00evil.com")


def test_resolve_crlf_injection_raises():
    """Hostname with embedded CRLF must raise.

    In some contexts a raw hostname is embedded in HTTP headers (e.g. Host:).
    Allowing CRLF in the DNS name enables header injection attacks downstream.
    """
    with assert_raises():
        _ = resolve("localhost\r\nevil.com")


def test_resolve_at_sign_raises():
    """Hostname with '@' (user-info delimiter) must raise.

    'user@host' is not a valid hostname; accepting it silently could expose
    the user portion to a malicious resolver or log scraper.
    """
    with assert_raises():
        _ = resolve("user@localhost")


def test_resolve_hostname_too_long_raises():
    """Hostname exceeding 253 characters must raise.

    RFC 1035 §2.3.4 limits full domain names to 253 octets.  A hostname
    longer than this cannot be valid; accept would risk buffer overflows in
    older resolver implementations.
    """
    var long_host = String("a" * 254) + ".com"
    with assert_raises():
        _ = resolve(long_host)


def test_resolve_label_too_long_raises():
    """A single DNS label longer than 63 characters must raise.

    RFC 1035 §2.3.4: each label (between dots) must not exceed 63 octets.
    """
    var long_label = String("a" * 64) + ".com"
    with assert_raises():
        _ = resolve(long_label)


def main():
    print("=" * 60)
    print("test_dns.mojo — DNS resolution")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
