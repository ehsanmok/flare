"""Unit tests for the ``Connection`` header byte-fast-path helpers
(``_connection_is_keepalive`` / ``_connection_is_close`` /
``_compute_close_after``) in
:mod:`flare.http._server_reactor_impl`.

Phase 1B (throughput parity with Rust libs): the per-request
``_ascii_lower(req.headers.get("connection"))`` allocation in the
keep-alive policy decision dominated CPU time on the TFB-plaintext
hot path with wrk2's exact-bytes ``Connection: keep-alive``. The
new byte-fast-path matches the lowercase wire format in 10-byte
loads (no allocation) and falls through to the slow
``_ascii_lower`` path only on mixed-case / unusual values.

This file locks in:

1. The exact-lowercase keep-alive wire format short-circuits to
   ``close_after = False`` without going through ``_ascii_lower``.
2. The exact-lowercase + mixed-case "Close" wire format short-
   circuits to ``close_after = True``.
3. Mixed-case "Keep-Alive" / "KEEP-ALIVE" / unusual values still
   land on the correct decision via the slow path.
4. Missing Connection header defaults to keep-alive on HTTP/1.1
   and close on HTTP/1.0 (RFC 9112).
5. ``Connection: close`` over HTTP/1.0 still closes (regression
   guard).
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http._server_reactor_impl import (
    _connection_is_keepalive,
    _connection_is_close,
    _compute_close_after,
)
from flare.http.headers import HeaderMap


# ── _connection_is_keepalive ────────────────────────────────────────────────


def test_keepalive_exact_lowercase_matches() raises:
    """The wrk2 / curl / nearly-every-Rust-client wire format
    ``keep-alive`` matches the byte-fast-path."""
    assert_true(_connection_is_keepalive(String("keep-alive")))


def test_keepalive_uppercase_does_not_match() raises:
    """Mixed-case falls through to the slow path."""
    assert_false(_connection_is_keepalive(String("Keep-Alive")))
    assert_false(_connection_is_keepalive(String("KEEP-ALIVE")))


def test_keepalive_wrong_length_does_not_match() raises:
    assert_false(_connection_is_keepalive(String("keep-aliv")))
    assert_false(_connection_is_keepalive(String("keep-alivex")))
    assert_false(_connection_is_keepalive(String("")))


def test_keepalive_close_does_not_match() raises:
    assert_false(_connection_is_keepalive(String("close")))


# ── _connection_is_close ────────────────────────────────────────────────────


def test_close_exact_lowercase_matches() raises:
    assert_true(_connection_is_close(String("close")))


def test_close_capital_c_matches() raises:
    """Mixed-case ``Close`` (capital C only) is the most common
    HTTP/1.0 client form; the byte-fast-path includes it."""
    assert_true(_connection_is_close(String("Close")))


def test_close_uppercase_does_not_match() raises:
    """``CLOSE`` falls through to the slow path."""
    assert_false(_connection_is_close(String("CLOSE")))


def test_close_wrong_length_does_not_match() raises:
    assert_false(_connection_is_close(String("clos")))
    assert_false(_connection_is_close(String("closex")))
    assert_false(_connection_is_close(String("")))


def test_close_keepalive_does_not_match() raises:
    assert_false(_connection_is_close(String("keep-alive")))


# ── _compute_close_after end-to-end via HeaderMap ──────────────────────────


def _hmap_with_connection(value: String) raises -> HeaderMap:
    var h = HeaderMap()
    h.append("Connection", value)
    return h^


def test_compute_keepalive_lowercase_http11_keeps_open() raises:
    """The wrk2 hot path."""
    var h = _hmap_with_connection(String("keep-alive"))
    assert_false(_compute_close_after(h, String("HTTP/1.1")))


def test_compute_close_lowercase_http11_closes() raises:
    var h = _hmap_with_connection(String("close"))
    assert_true(_compute_close_after(h, String("HTTP/1.1")))


def test_compute_close_capital_c_http11_closes() raises:
    var h = _hmap_with_connection(String("Close"))
    assert_true(_compute_close_after(h, String("HTTP/1.1")))


def test_compute_keepalive_mixed_case_http11_keeps_open() raises:
    """Slow-path: ``Keep-Alive`` reaches the _ascii_lower fallback."""
    var h = _hmap_with_connection(String("Keep-Alive"))
    assert_false(_compute_close_after(h, String("HTTP/1.1")))


def test_compute_close_uppercase_http11_closes() raises:
    """Slow-path: ``CLOSE`` reaches the _ascii_lower fallback."""
    var h = _hmap_with_connection(String("CLOSE"))
    assert_true(_compute_close_after(h, String("HTTP/1.1")))


def test_compute_no_header_http11_keeps_open() raises:
    """RFC 9112: HTTP/1.1 default is keep-alive."""
    var h = HeaderMap()
    assert_false(_compute_close_after(h, String("HTTP/1.1")))


def test_compute_no_header_http10_closes() raises:
    """RFC 9112: HTTP/1.0 default is close."""
    var h = HeaderMap()
    assert_true(_compute_close_after(h, String("HTTP/1.0")))


def test_compute_keepalive_lowercase_http10_keeps_open() raises:
    """HTTP/1.0 explicit ``Connection: keep-alive`` overrides default
    close."""
    var h = _hmap_with_connection(String("keep-alive"))
    assert_false(_compute_close_after(h, String("HTTP/1.0")))


def test_compute_close_lowercase_http10_closes() raises:
    var h = _hmap_with_connection(String("close"))
    assert_true(_compute_close_after(h, String("HTTP/1.0")))


def test_compute_unusual_value_http11_keeps_open() raises:
    """``Connection: Foo`` (unrecognised value) does NOT close on
    HTTP/1.1 (default-keep-alive); does close on HTTP/1.0
    (default-close)."""
    var h11 = _hmap_with_connection(String("Foo"))
    assert_false(_compute_close_after(h11, String("HTTP/1.1")))
    var h10 = _hmap_with_connection(String("Foo"))
    assert_true(_compute_close_after(h10, String("HTTP/1.0")))


def main() raises:
    var suite = TestSuite()
    suite.test[test_keepalive_exact_lowercase_matches]()
    suite.test[test_keepalive_uppercase_does_not_match]()
    suite.test[test_keepalive_wrong_length_does_not_match]()
    suite.test[test_keepalive_close_does_not_match]()
    suite.test[test_close_exact_lowercase_matches]()
    suite.test[test_close_capital_c_matches]()
    suite.test[test_close_uppercase_does_not_match]()
    suite.test[test_close_wrong_length_does_not_match]()
    suite.test[test_close_keepalive_does_not_match]()
    suite.test[test_compute_keepalive_lowercase_http11_keeps_open]()
    suite.test[test_compute_close_lowercase_http11_closes]()
    suite.test[test_compute_close_capital_c_http11_closes]()
    suite.test[test_compute_keepalive_mixed_case_http11_keeps_open]()
    suite.test[test_compute_close_uppercase_http11_closes]()
    suite.test[test_compute_no_header_http11_keeps_open]()
    suite.test[test_compute_no_header_http10_closes]()
    suite.test[test_compute_keepalive_lowercase_http10_keeps_open]()
    suite.test[test_compute_close_lowercase_http10_closes]()
    suite.test[test_compute_unusual_value_http11_keeps_open]()
    suite^.run()
