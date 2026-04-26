"""Tests for the server-side TLS acceptor scaffolding (v0.5.0
Step 3 / Track 5.1).

Covers the API-surface portion landing in this commit:
``TlsServerConfig`` value semantics, ``TlsInfo`` defaults,
``TlsAcceptor`` construction + reload-as-no-op,
``TlsServerError`` / ``TlsServerNotImplemented`` formatting.

The reactor-side handshake state machine (non-blocking
``SSL_accept`` driven by edge-triggered readable / writable
events) lands in the v0.5.0 Step 3 follow-up; tests for the
end-to-end TLS round-trip (``TlsAcceptor.serve(handler)`` ->
``curl --cacert``) move with it.

Re-exports from ``flare.tls`` and the root ``flare`` package
resolve.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)

from flare.tls import (
    TlsAcceptor,
    TlsServerConfig,
    TlsInfo,
    TlsServerError,
    TlsServerNotImplemented,
    TLS_PROTOCOL_TLS12,
    TLS_PROTOCOL_TLS13,
)


# ── TlsServerConfig ────────────────────────────────────────────────────────


def test_config_minimal() raises:
    var cfg = TlsServerConfig(
        cert_file="/etc/cert.pem", key_file="/etc/key.pem"
    )
    assert_equal(cfg.cert_file, "/etc/cert.pem")
    assert_equal(cfg.key_file, "/etc/key.pem")
    assert_equal(len(cfg.alpn), 0)
    assert_false(cfg.require_client_cert)
    assert_equal(cfg.client_ca_bundle, "")
    assert_equal(cfg.min_protocol, TLS_PROTOCOL_TLS12)


def test_config_with_alpn_and_mtls() raises:
    var alpn = List[String]()
    alpn.append("h2")
    alpn.append("http/1.1")
    var cfg = TlsServerConfig(
        cert_file="/c.pem",
        key_file="/k.pem",
        alpn=alpn^,
        require_client_cert=True,
        client_ca_bundle="/etc/ca.pem",
        min_protocol=TLS_PROTOCOL_TLS13,
    )
    assert_equal(len(cfg.alpn), 2)
    assert_equal(cfg.alpn[0], "h2")
    assert_equal(cfg.alpn[1], "http/1.1")
    assert_true(cfg.require_client_cert)
    assert_equal(cfg.client_ca_bundle, "/etc/ca.pem")
    assert_equal(cfg.min_protocol, TLS_PROTOCOL_TLS13)


def test_protocol_constants_distinct() raises:
    assert_true(TLS_PROTOCOL_TLS12 != TLS_PROTOCOL_TLS13)
    # Sanity: TLS 1.2 < TLS 1.3 numerically (matches OpenSSL).
    assert_true(TLS_PROTOCOL_TLS12 < TLS_PROTOCOL_TLS13)


# ── mTLS validation (Track 5.4) ────────────────────────────────────────────


def test_mtls_requires_ca_bundle() raises:
    """``require_client_cert=True`` without a ``client_ca_bundle``
    raises at construction time. mTLS without trust anchors is
    meaningless — the verify callback would have nothing to
    check against. Failing at construction time closes the
    Track 5.4 misconfiguration foot-gun.
    """
    with assert_raises():
        _ = TlsServerConfig(
            cert_file="/c.pem",
            key_file="/k.pem",
            require_client_cert=True,
            # client_ca_bundle defaults to empty string.
        )


def test_mtls_requires_ca_bundle_explicit_empty() raises:
    """Explicit empty string for ``client_ca_bundle`` is also a
    misconfiguration."""
    with assert_raises():
        _ = TlsServerConfig(
            cert_file="/c.pem",
            key_file="/k.pem",
            require_client_cert=True,
            client_ca_bundle="",
        )


def test_mtls_with_ca_bundle_succeeds() raises:
    var cfg = TlsServerConfig(
        cert_file="/c.pem",
        key_file="/k.pem",
        require_client_cert=True,
        client_ca_bundle="/etc/ca.pem",
    )
    assert_true(cfg.require_client_cert)
    assert_equal(cfg.client_ca_bundle, "/etc/ca.pem")


def test_mtls_off_ignores_ca_bundle() raises:
    """``require_client_cert=False`` is allowed regardless of
    whether a client CA bundle was provided — the bundle is
    just unused."""
    var cfg1 = TlsServerConfig(cert_file="/c.pem", key_file="/k.pem")
    assert_false(cfg1.require_client_cert)

    var cfg2 = TlsServerConfig(
        cert_file="/c.pem",
        key_file="/k.pem",
        require_client_cert=False,
        client_ca_bundle="/etc/ca.pem",
    )
    assert_false(cfg2.require_client_cert)


# ── TlsInfo ────────────────────────────────────────────────────────────────


def test_tls_info_default_empty() raises:
    var info = TlsInfo()
    assert_equal(info.protocol, "")
    assert_equal(info.cipher, "")
    assert_equal(info.sni_host, "")
    assert_equal(info.alpn_protocol, "")
    assert_equal(info.client_cert_subject, "")


def test_tls_info_with_values() raises:
    var info = TlsInfo(
        protocol="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        sni_host="example.com",
        alpn_protocol="h2",
        client_cert_subject="CN=alice",
    )
    assert_equal(info.protocol, "TLSv1.3")
    assert_equal(info.cipher, "TLS_AES_128_GCM_SHA256")
    assert_equal(info.sni_host, "example.com")
    assert_equal(info.alpn_protocol, "h2")
    assert_equal(info.client_cert_subject, "CN=alice")


# ── TlsAcceptor ────────────────────────────────────────────────────────────


comptime _CERT: String = (
    "/Users/ehsan/workspace/flare/build/tls-bench-certs/server.pem"
)
comptime _KEY: String = (
    "/Users/ehsan/workspace/flare/build/tls-bench-certs/server.key"
)


def test_acceptor_construct() raises:
    """C7: TlsAcceptor now actually loads the cert / key + sets
    up the SSL_CTX. Construction succeeds with a real cert pair
    (the bench-tls-setup self-signed cert)."""
    var cfg = TlsServerConfig(cert_file=_CERT, key_file=_KEY)
    var acc = TlsAcceptor(cfg^)
    assert_equal(acc.config.cert_file, _CERT)
    assert_equal(acc.config.key_file, _KEY)


def test_acceptor_construct_raises_on_missing_cert() raises:
    """C7: Construction fails fast if the cert path is bad —
    deployments learn at server-start that they have a bad
    cert, not at the first inbound handshake."""
    var cfg = TlsServerConfig(cert_file="/nonexistent/cert.pem", key_file=_KEY)
    with assert_raises():
        _ = TlsAcceptor(cfg^)


def test_acceptor_reload_swaps_cert() raises:
    """``reload()`` re-reads the cert + key files. Calling it
    repeatedly is safe — SIGHUP / inotify / cron triggers fire
    regardless of whether the file actually changed."""
    var cfg = TlsServerConfig(cert_file=_CERT, key_file=_KEY)
    var acc = TlsAcceptor(cfg^)
    acc.reload()


def test_acceptor_reload_repeated_safe() raises:
    """Cert-rotation deployments call ``reload`` on every
    event regardless of whether the file changed."""
    var cfg = TlsServerConfig(cert_file=_CERT, key_file=_KEY)
    var acc = TlsAcceptor(cfg^)
    for _ in range(10):
        acc.reload()


def test_acceptor_info_placeholder_returns_empty() raises:
    var cfg = TlsServerConfig(cert_file=_CERT, key_file=_KEY)
    var acc = TlsAcceptor(cfg^)
    var info = acc.info_placeholder()
    assert_equal(info.protocol, "")


def test_acceptor_with_alpn_succeeds() raises:
    """Constructor wires the ALPN list through to the FFI."""
    var alpn = List[String]()
    alpn.append("h2")
    alpn.append("http/1.1")
    var cfg = TlsServerConfig(cert_file=_CERT, key_file=_KEY, alpn=alpn^)
    var acc = TlsAcceptor(cfg^)
    assert_equal(len(acc.config.alpn), 2)


def test_acceptor_with_mtls_succeeds() raises:
    """``require_client_cert=True`` + a real CA bundle wires
    through to the FFI's verify-peer callback."""
    var cfg = TlsServerConfig(
        cert_file=_CERT,
        key_file=_KEY,
        require_client_cert=True,
        client_ca_bundle=_CERT,  # self-signed: cert is its own CA
    )
    var acc = TlsAcceptor(cfg^)
    assert_true(acc.config.require_client_cert)


# ── Errors ─────────────────────────────────────────────────────────────────


def test_tls_server_error_writes_message_and_code() raises:
    var e = TlsServerError("handshake failed", code=42)
    assert_equal(e.message, "handshake failed")
    assert_equal(e.code, 42)
    assert_equal(String(e), "TlsServerError(handshake failed code=42)")


def test_tls_server_not_implemented_default_message() raises:
    var e = TlsServerNotImplemented()
    assert_true(e.message.find("scaffolding only") >= 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
