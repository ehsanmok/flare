"""Strings that cross into C as ``char*`` (``flare/net/cstr.mojo``).

C reads a ``char*`` up to its first NUL, so a string holding a NUL reaches
C cut short, and an empty string must not be passed as whatever
``as_c_string_span().ptr()`` returns for it (issue #42). These tests check
the verdict and every wrapper that routes through it.
"""

from std.ffi import OwnedDLHandle, external_call
from std.memory import stack_allocation
from std.os.path import exists
from std.testing import assert_equal, assert_raises, assert_true, TestSuite

from flare.net import _find_flare_lib
from flare.net._libc import AF_INET, _getaddrinfo, _inet_pton
from flare.net.cstr import (
    CSTR_NULL,
    CSTR_PASS,
    CSTR_REJECT,
    EMPTY_NULL,
    EMPTY_PASS,
    EMPTY_REJECT,
    c_str_addr,
    c_str_verdict,
)
from flare.tls import TlsConfig
from flare.tls.stream import _build_ssl_ctx
from flare.uds._libc import unlink_path


def _nul(a: String, b: String) -> String:
    var bytes = List[UInt8](a.as_bytes())
    bytes.append(0)
    bytes.extend(b.as_bytes())
    return String(unsafe_from_utf8=Span(bytes))


def test_verdict() raises:
    assert_equal(c_str_verdict("localhost".as_bytes(), EMPTY_REJECT), CSTR_PASS)
    assert_equal(c_str_verdict("".as_bytes(), EMPTY_NULL), CSTR_NULL)
    assert_equal(c_str_verdict("".as_bytes(), EMPTY_REJECT), CSTR_REJECT)
    assert_equal(c_str_verdict("".as_bytes(), EMPTY_PASS), CSTR_PASS)
    var cut = _nul("localhost", ".evil")
    for mode in [EMPTY_REJECT, EMPTY_NULL, EMPTY_PASS]:
        assert_equal(c_str_verdict(cut.as_bytes(), mode), CSTR_REJECT)
    var lead = _nul("", "x")
    assert_equal(c_str_verdict(lead.as_bytes(), EMPTY_PASS), CSTR_REJECT)


def test_default_ca_bundle_reaches_c_as_empty() raises:
    """The string of issue #42 reaches C as ``""`` where empty is a value
    and as NULL where it means the default."""
    var s = TlsConfig().ca_bundle
    var addr = c_str_addr(s, EMPTY_PASS, "test")
    assert_true(addr != 0)
    assert_equal(external_call["strlen", Int](addr), 0)
    _ = s^
    var t = TlsConfig().ca_bundle
    assert_equal(c_str_addr(t, EMPTY_NULL, "test"), 0)


def test_inet_pton_refuses_nul() raises:
    """C would parse only ``1.2.3.4`` and report success."""
    var buf = stack_allocation[4, UInt8]()
    assert_equal(Int(_inet_pton(AF_INET, "1.2.3.4", buf)), 1)
    assert_equal(Int(_inet_pton(AF_INET, _nul("1.2.3.4", "junk"), buf)), 0)
    assert_equal(Int(_inet_pton(AF_INET, "", buf)), 0)


def test_getaddrinfo_refuses_nul() raises:
    """C would resolve ``localhost`` for ``localhost\\0.evil``."""
    var hints = stack_allocation[48, UInt8]()
    var slot = stack_allocation[8, UInt8]()
    for i in range(48):
        hints.unsafe_offset(i).unsafe_write(0)
    with assert_raises(contains="NUL"):
        _ = _getaddrinfo(_nul("localhost", ".evil"), hints, slot)


def test_unlink_refuses_nul() raises:
    """C would unlink ``victim`` for ``victim\\0x``."""
    var victim = "/tmp/flare_test_cstr_victim"
    with open(victim, "w") as f:
        f.write("x")
    assert_equal(Int(unlink_path(_nul(victim, "x"))), -1)
    assert_true(exists(victim))
    assert_equal(Int(unlink_path(victim)), 0)
    assert_equal(Int(unlink_path("")), -1)


def test_tls_ca_bundle_with_nul_refused() raises:
    """A CA path C would read cut short is refused before OpenSSL sees it."""
    var lib = OwnedDLHandle(_find_flare_lib())
    with assert_raises(contains="TlsConfig.ca_bundle"):
        _ = _build_ssl_ctx(
            lib, TlsConfig(ca_bundle=_nul("tests/certs/ca.crt", "junk"))
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
