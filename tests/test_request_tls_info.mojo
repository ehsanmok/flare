"""Tests for ``Request.tls_info`` and ALPN advertisement
( / Tracks 5.2 + 5.5).

Covers:

- ``Request.tls_info`` defaults to ``None`` for plain-HTTP /
  test constructions.
- ``Request.tls_info`` carries a ``TlsInfo`` value when set
  explicitly.
- ALPN protocol list on ``TlsServerConfig`` round-trips via the
  config (ordering preserved — first match wins on the wire).
- ``TlsInfo.alpn_protocol`` exposes the negotiated protocol
  to handlers.

The reactor-side handshake that actually populates ``tls_info``
from a real TLS handshake lands as the follow-up;
these tests cover the type plumbing that handlers can target
today.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    TestSuite,
)
from std.collections import Optional

from flare.http import Request, Method
from flare.tls import TlsInfo, TlsServerConfig


# ── Request.tls_info default ───────────────────────────────────────────────


def test_request_tls_info_default_none() raises:
    var req = Request(method=Method.GET, url="/")
    assert_false(Bool(req.tls_info))


def test_request_tls_info_set_explicit() raises:
    var info = TlsInfo(
        protocol="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        sni_host="example.com",
        alpn_protocol="h2",
    )
    var req = Request(
        method=Method.GET,
        url="/",
        tls_info=Optional[TlsInfo](info^),
    )
    assert_true(Bool(req.tls_info))
    if req.tls_info:
        assert_equal(req.tls_info.value().protocol, "TLSv1.3")
        assert_equal(req.tls_info.value().sni_host, "example.com")
        assert_equal(req.tls_info.value().alpn_protocol, "h2")


# ── ALPN advertisement on TlsServerConfig ──────────────────────────────────


def test_alpn_default_empty() raises:
    var cfg = TlsServerConfig(cert_file="/c.pem", key_file="/k.pem")
    assert_equal(len(cfg.alpn), 0)


def test_alpn_preference_order_preserved() raises:
    """ALPN list ordering is the server-side preference order.
    OpenSSL's selection callback picks the first server-listed
    protocol that's also in the client's advertised list."""
    var alpn = List[String]()
    alpn.append("h2")
    alpn.append("http/1.1")
    var cfg = TlsServerConfig(cert_file="/c.pem", key_file="/k.pem", alpn=alpn^)
    assert_equal(cfg.alpn[0], "h2")
    assert_equal(cfg.alpn[1], "http/1.1")


def test_alpn_single_protocol() raises:
    """Servers that only speak HTTP/1.1 advertise just that."""
    var alpn = List[String]()
    alpn.append("http/1.1")
    var cfg = TlsServerConfig(cert_file="/c.pem", key_file="/k.pem", alpn=alpn^)
    assert_equal(len(cfg.alpn), 1)
    assert_equal(cfg.alpn[0], "http/1.1")


# ── Combined: ALPN result threaded through TlsInfo.alpn_protocol ──────────


def test_tls_info_alpn_protocol_round_trip() raises:
    """Once the reactor lands the handshake, the negotiated ALPN
    protocol is threaded through ``TlsInfo.alpn_protocol``;
    handlers can branch on it (e.g. dispatch HTTP/1.1 vs HTTP/2).
    Today we just verify the field exists on ``TlsInfo`` and
    survives the Request round-trip.
    """
    var info = TlsInfo(alpn_protocol="h2")
    var req = Request(
        method=Method.GET,
        url="/",
        tls_info=Optional[TlsInfo](info^),
    )
    if req.tls_info:
        assert_equal(req.tls_info.value().alpn_protocol, "h2")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
