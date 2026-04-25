"""Server-side TLS acceptor scaffolding (v0.5.0 Step 3 / Track 5.1).

``TlsAcceptor`` is the server-side counterpart to ``TlsStream`` —
it wraps a ``TcpListener`` and produces ``TlsStream`` connections
after completing the TLS handshake against a server certificate
chain. ``TlsServerConfig`` carries the acceptor's policy: cert /
key paths, ALPN protocols to advertise, optional CA bundle for
mTLS client-cert verification.

This commit ships the **type infrastructure**: ``TlsServerConfig``,
``TlsAcceptor`` shell, ``TlsInfo`` value type, ``TlsServerError``
hierarchy, plus the public re-exports through ``flare.tls`` and
the root ``flare`` package. The reactor-side handshake state
machine — non-blocking ``SSL_accept`` driven by edge-triggered
readable / writable events — is a focused follow-up that lands
once the OpenSSL ``SSL_CTX_*`` server-side surface is wired into
the existing ``flare/tls/ffi/openssl_wrapper.cpp``.

Why split: the C-side handshake state machine is ~150 lines of
``SSL_accept`` + ``SSL_get_error`` + ``BIO`` plumbing, plus
matching reactor surgery. Landing the API surface in this commit
lets S3.2 (``Request.tls_info``), S3.3 (cert reload), and S3.4
(mTLS) all plug into the public surface; the actual cipher-on-
the-wire bits land together in a single follow-up the user can
review in one shot.

Closes the API-surface portion of design-0.5 Track 5.1.

Public API:

    from flare.tls import (
        TlsServerConfig, TlsAcceptor, TlsInfo,
        TlsServerError, TlsServerNotImplemented,
    )

    var cfg = TlsServerConfig(
        cert_file="/etc/letsencrypt/live/example.com/fullchain.pem",
        key_file="/etc/letsencrypt/live/example.com/privkey.pem",
        alpn=["h2", "http/1.1"],     # served preference order
        require_client_cert=False,    # mTLS off by default
        client_ca_bundle="",
    )
    var acceptor = TlsAcceptor.bind(addr, cfg)
    # acceptor.serve(handler) — flips on with the reactor
    # follow-up that lands the SSL_accept state machine.
"""

from std.format import Writable, Writer


# ── Server-side errors ─────────────────────────────────────────────────────


struct TlsServerError(Copyable, Movable, Writable):
    """Generic server-side TLS failure (handshake, cert load, etc.).

    ``message`` describes the failure in human-readable form;
    ``code`` carries the underlying OpenSSL error code if
    available (0 if not).
    """

    var message: String
    var code: Int

    def __init__(out self, message: String, code: Int = 0):
        self.message = message
        self.code = code

    def write_to[W: Writer](self, mut writer: W):
        writer.write(
            "TlsServerError(",
            self.message,
            " code=",
            String(self.code),
            ")",
        )


struct TlsServerNotImplemented(Copyable, Movable, Writable):
    """Marker raised by the API-surface scaffolding to signal
    that the reactor-side handshake state machine has not landed
    yet. Distinct type so callers can match on it for graceful
    degradation while the implementation is in flight.
    """

    var message: String

    def __init__(out self):
        self.message = (
            "TlsAcceptor scaffolding only — reactor-side SSL_accept"
            " state machine lands in the v0.5.0 Step 3 follow-up."
        )

    def write_to[W: Writer](self, mut writer: W):
        writer.write(self.message)


# ── TlsServerConfig ────────────────────────────────────────────────────────


struct TlsServerConfig(Copyable, Movable):
    """Server-side TLS policy.

    Fields:
        cert_file:           Path to the server certificate chain
                             in PEM format (full chain — leaf
                             first, then intermediates). Required.
        key_file:            Path to the server private key in
                             PEM format. Required.
        alpn:                ALPN protocol identifiers to
                             advertise during the handshake. Order
                             is preference order (the OpenSSL
                             callback selects the first
                             intersection with the client's
                             advertised list). Empty = no ALPN.
        require_client_cert: Whether to require a client
                             certificate (mTLS). Defaults False.
                             When True, ``client_ca_bundle`` must
                             also be set.
        client_ca_bundle:    Path to a PEM bundle of trust anchors
                             for verifying client certificates
                             (mTLS). Empty = use OpenSSL's default
                             trust store.
        min_protocol:        Minimum TLS protocol version to
                             negotiate. Default
                             ``TLS_PROTOCOL_TLS12``. TLS 1.0 / 1.1
                             are explicitly rejected.

    Reload semantics: ``cert_file`` / ``key_file`` are re-read at
    every call to ``TlsAcceptor.reload()``; the config struct
    itself is value-copied at acceptor construction time.
    """

    var cert_file: String
    var key_file: String
    var alpn: List[String]
    var require_client_cert: Bool
    var client_ca_bundle: String
    var min_protocol: Int

    def __init__(
        out self,
        cert_file: String,
        key_file: String,
        var alpn: List[String] = List[String](),
        require_client_cert: Bool = False,
        client_ca_bundle: String = "",
        min_protocol: Int = TLS_PROTOCOL_TLS12,
    ):
        self.cert_file = cert_file
        self.key_file = key_file
        self.alpn = alpn^
        self.require_client_cert = require_client_cert
        self.client_ca_bundle = client_ca_bundle
        self.min_protocol = min_protocol


# Protocol version constants. Mirror OpenSSL's
# ``TLS1_VERSION`` / ``TLS1_2_VERSION`` / ``TLS1_3_VERSION``.

comptime TLS_PROTOCOL_TLS12: Int = 0x0303
comptime TLS_PROTOCOL_TLS13: Int = 0x0304


# ── TlsInfo ────────────────────────────────────────────────────────────────


struct TlsInfo(Copyable, Movable):
    """Per-request TLS metadata threaded onto ``Request`` via
    ``Request.tls_info``.

    Available when the connection terminated TLS at flare's
    ``TlsAcceptor``. Plain-HTTP connections see ``Request.tls_info
    = None`` (this struct is not threaded onto them).

    Fields:
        protocol:           Negotiated protocol version
                            (e.g. ``"TLSv1.3"``).
        cipher:             Cipher suite name
                            (e.g. ``"TLS_AES_128_GCM_SHA256"``).
        sni_host:           Client-Hello SNI hostname, or empty
                            string if the client didn't send one.
        alpn_protocol:      Negotiated ALPN protocol
                            (e.g. ``"h2"``, ``"http/1.1"``), or
                            empty string if ALPN didn't fire.
        client_cert_subject: Subject DN of the client certificate
                             when mTLS is on; empty string
                             otherwise.
    """

    var protocol: String
    var cipher: String
    var sni_host: String
    var alpn_protocol: String
    var client_cert_subject: String

    def __init__(
        out self,
        protocol: String = "",
        cipher: String = "",
        sni_host: String = "",
        alpn_protocol: String = "",
        client_cert_subject: String = "",
    ):
        self.protocol = protocol
        self.cipher = cipher
        self.sni_host = sni_host
        self.alpn_protocol = alpn_protocol
        self.client_cert_subject = client_cert_subject


# ── TlsAcceptor ────────────────────────────────────────────────────────────


struct TlsAcceptor(Movable):
    """Server-side TLS acceptor.

    Wraps a ``TlsServerConfig`` and produces ``TlsStream``
    connections after completing the TLS handshake against the
    server's certificate chain.

    The full constructor + handshake state machine + reactor
    integration land in the v0.5.0 Step 3 follow-up; this
    scaffolding gives downstream code (``Request.tls_info``,
    ``HttpsServer``, the cert-reload helper, the mTLS opt-in,
    the ALPN selector) a stable place to plug into.
    """

    var config: TlsServerConfig
    """The acceptor's policy. Mutable via ``reload()`` for cert
    rotation without restart (S3.3)."""

    def __init__(out self, var config: TlsServerConfig):
        """Construct an acceptor. The handshake state machine and
        certificate-load step are deferred to the reactor-side
        follow-up — instantiating this struct does not yet
        validate the cert / key files.
        """
        self.config = config^

    def reload(mut self) raises:
        """Re-read the cert + key files from disk without
        restarting the acceptor. Designed for cert rotation under
        live traffic; in-flight handshakes complete with the
        previous cert, new connections pick up the new one.

        Until the reactor-side handshake lands this is a no-op;
        the public method exists so callers (and the
        ``examples/25_cert_reload.mojo`` demo in S3.3) can wire
        the SIGHUP / inotify / file-watcher trigger today.
        """
        # Reactor follow-up: validate paths exist + readable;
        # construct a fresh ``SSL_CTX``; atomically swap into the
        # acceptor's reference for new connections.
        pass

    def info_placeholder(self) -> TlsInfo:
        """Return a default ``TlsInfo`` value with empty strings
        in every field. Used by code paths that need to thread
        a TlsInfo onto a ``Request`` before the reactor-side
        handshake lands; the real handshake replaces this with
        live values pulled from ``SSL_get_*``.
        """
        return TlsInfo()
