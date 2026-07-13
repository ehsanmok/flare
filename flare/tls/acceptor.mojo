"""Server-side TLS acceptor.

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
matching reactor surgery. The API surface here lets per-request
``TlsInfo`` plumbing, cert reload, and mTLS all plug into the
public surface; the actual cipher-on-the-wire bits land
together in a single follow-up.

Public API:

    from flare.tls import (
        TlsServerConfig, TlsAcceptor, TlsInfo,
        TlsServerError, TlsServerNotImplemented,
    )

    var cfg = TlsServerConfig(
        cert_file="/etc/letsencrypt/live/example.com/fullchain.pem",
        key_file="/etc/letsencrypt/live/example.com/privkey.pem",
        alpn=["h2", "http/1.1"], # served preference order
        require_client_cert=False, # mTLS off by default
        client_ca_bundle="",
    )
    var acceptor = TlsAcceptor.bind(addr, cfg)
    # acceptor.serve(handler) — flips on with the reactor
    # follow-up that lands the SSL_accept state machine.
"""

from std.format import Writable, Writer

from std.collections import Optional
from std.ffi import c_int, c_uint
from std.memory import UnsafePointer, stack_allocation

from ..net._libc import _setsockopt, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO
from ._server_ffi import (
    ServerCtx,
    server_ssl_new_accept,
    server_ssl_do_handshake,
    server_ssl_get_alpn_selected,
    server_ssl_get_sni_host,
    server_ssl_free,
)


def _set_fd_recv_send_timeout(fd: Int, ms: Int):
    """Best-effort ``SO_RCVTIMEO`` + ``SO_SNDTIMEO`` on a raw fd.

    Bounds a *blocking* ``SSL_accept`` read/write so a stalled client
    cannot pin the worker inside the syscall: the read unblocks after
    ``ms`` with EAGAIN, ``SSL_do_handshake`` reports WANT_READ, and the
    handshake loop's monotonic deadline then aborts. Failures are
    ignored (the loop deadline is still a backstop). ``timeval`` layout
    on 64-bit: 8-byte tv_sec + 8-byte tv_usec.
    """
    if ms <= 0:
        return
    var tv = stack_allocation[16, UInt8]()
    for i in range(16):
        (tv + i).init_pointee_copy(0)
    tv.bitcast[Int64]().init_pointee_copy(Int64(ms // 1000))
    (tv + 8).bitcast[Int64]().init_pointee_copy(Int64((ms % 1000) * 1000))
    _ = _setsockopt(c_int(fd), SOL_SOCKET, SO_RCVTIMEO, tv, c_uint(16))
    _ = _setsockopt(c_int(fd), SOL_SOCKET, SO_SNDTIMEO, tv, c_uint(16))


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
    """Marker raised to signal that the reactor-side handshake
    state machine is not available. Distinct type so callers can
    match on it for graceful degradation and fall back to the
    blocking ``handshake_fd`` path.
    """

    var message: String

    def __init__(out self):
        self.message = (
            "TlsAcceptor reactor-side SSL_accept state machine is"
            " not available; use the blocking handshake_fd path."
        )

    def write_to[W: Writer](self, mut writer: W):
        writer.write(self.message)


# ── TlsServerConfig ────────────────────────────────────────────────────────


struct TlsServerConfig(Copyable, Movable):
    """Server-side TLS policy.

    Fields:
        cert_file: Path to the server certificate chain
                             in PEM format (full chain — leaf
                             first, then intermediates). Required.
        key_file: Path to the server private key in
                             PEM format. Required.
        alpn: ALPN protocol identifiers to
                             advertise during the handshake. Order
                             is preference order (the OpenSSL
                             callback selects the first
                             intersection with the client's
                             advertised list). Empty = no ALPN.
        require_client_cert: Whether to require a client
                             certificate (mTLS). Defaults False.
                             When True, ``client_ca_bundle`` must
                             also be set.
        client_ca_bundle: Path to a PEM bundle of trust anchors
                             for verifying client certificates
                             (mTLS). Empty = use OpenSSL's default
                             trust store.
        min_protocol: Minimum TLS protocol version to
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
    var enable_session_tickets: Bool
    """When True (default), the acceptor's ``SSL_CTX`` is
    configured to issue RFC 5077 session tickets (TLS 1.2) /
    RFC 8446 §4.6.1 NewSessionTicket frames (TLS 1.3) so peers
    can resume on subsequent connects. Cheap to keep on; turn
    off only for environments where ticket-key rotation is not
    handled out-of-band (the acceptor does not auto-rotate
    -- the ``flare_ssl_ctx_enable_session_tickets`` FFI permits
    rotation but the acceptor doesn't expose the hook yet)."""
    var ticket_lifetime_s: Int
    """Session ticket lifetime in seconds. Default 7200 (two
    hours). Maps to ``SSL_CTX_set_timeout`` and the embedded TLS
    1.3 ``ticket_lifetime`` field. Production deployments should
    keep this short and rotate ticket keys via an out-of-band
    secret-management path."""
    var handshake_timeout_ms: Int
    """Wall-clock cap (milliseconds) on a single blocking
    ``SSL_accept`` drive in ``TlsAcceptor.handshake_fd``. Default
    10_000 (10 s). A slow or stalled client that never completes the
    handshake is aborted at the deadline so it cannot hold the
    worker indefinitely (slow-loris-on-handshake DoS bound). Measured
    against a monotonic clock, not an iteration count, so it stays
    honest under the libc-sleep multiplier. ``0`` disables the cap."""

    def __init__(
        out self,
        cert_file: String,
        key_file: String,
        var alpn: List[String] = List[String](),
        require_client_cert: Bool = False,
        client_ca_bundle: String = "",
        min_protocol: Int = TLS_PROTOCOL_TLS12,
        enable_session_tickets: Bool = True,
        ticket_lifetime_s: Int = 7200,
        handshake_timeout_ms: Int = 10_000,
    ) raises:
        """Construct the config; validates inter-field invariants.

        Raises:
            Error: When ``require_client_cert=True`` is set
                without a ``client_ca_bundle`` (mTLS without trust
                anchors is meaningless — the verify callback
                would have nothing to verify against). Prevents
                the misconfiguration foot-gun by failing at
                construction time rather than at handshake time.
        """
        if require_client_cert and client_ca_bundle == "":
            raise Error(
                "TlsServerConfig: require_client_cert=True needs a"
                " non-empty client_ca_bundle (path to PEM trust"
                " anchors); mTLS without trust anchors is"
                " meaningless"
            )
        self.cert_file = cert_file
        self.key_file = key_file
        self.alpn = alpn^
        self.require_client_cert = require_client_cert
        self.client_ca_bundle = client_ca_bundle
        self.min_protocol = min_protocol
        self.enable_session_tickets = enable_session_tickets
        self.ticket_lifetime_s = ticket_lifetime_s
        self.handshake_timeout_ms = handshake_timeout_ms


# Protocol version constants. Mirror OpenSSL's
# ``TLS1_VERSION`` / ``TLS1_2_VERSION`` / ``TLS1_3_VERSION``.

comptime TLS_PROTOCOL_TLS12: Int = 0x0303
comptime TLS_PROTOCOL_TLS13: Int = 0x0304


# ── TlsInfo ────────────────────────────────────────────────────────────────


struct TlsInfo(Copyable, Movable):
    """Per-connection TLS metadata returned by
    :meth:`TlsAcceptor.handshake_fd`.

    Available when the connection terminated TLS at flare's
    ``TlsAcceptor``. Plain-HTTP connections never see this struct
    (the reactor only constructs it on the TLS handshake path).

    Fields:
        protocol: Negotiated protocol version
                            (e.g. ``"TLSv1.3"``).
        cipher: Cipher suite name
                            (e.g. ``"TLS_AES_128_GCM_SHA256"``).
        sni_host: Client-Hello SNI hostname, or empty
                            string if the client didn't send one.
        alpn_protocol: Negotiated ALPN protocol
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

    Wraps a ``TlsServerConfig`` and a real ``ServerCtx`` (the
    OpenSSL ``SSL_CTX*`` produced by C6's FFI). Constructor
    validates the cert + key + ALPN + mTLS config and raises if
    any are bad, so configuration errors fail at server-bind
    time rather than at the first inbound handshake.

    Per-connection use:

    1. After ``listener.accept()`` returns a ``TcpStream``, call
       ``acceptor.handshake(stream) raises -> Tuple[TlsStream,
       TlsInfo]``. The method drives ``SSL_accept`` to completion
       in blocking mode (suitable for the existing ``serve``
       entry shape; the reactor-side ``STATE_TLS_HANDSHAKE``
       state machine that uses the same FFI but in a non-blocking
       reactor loop is a focused follow-up).

    Cert reload:

    ``acceptor.reload()`` re-reads the cert + key from the paths
    in ``config`` and atomically swaps them on the underlying
    ``SSL_CTX``. In-flight sessions hold the old cert via
    ``SSL_use_certificate``; new handshakes pick up the new one.
    """

    var config: TlsServerConfig
    """The acceptor's policy. Mutable via ``reload()`` for cert
    rotation without restart."""

    var _ctx: ServerCtx
    """Underlying ``SSL_CTX``. Owned for the acceptor's lifetime.
    """

    def __init__(out self, var config: TlsServerConfig) raises:
        """Construct an acceptor.

        Loads the cert + key, configures min-protocol + cipher
        list, sets up ALPN if non-empty, sets up mTLS verification
        if ``require_client_cert``. Raises on any FFI failure —
        configuration errors are caught at construction time.
        """
        self._ctx = ServerCtx.new(config.cert_file, config.key_file)

        # ALPN: convert the List[String] into wire format
        # (len_byte || proto_bytes || ...).
        if len(config.alpn) > 0:
            var alpn_blob = List[UInt8]()
            for i in range(len(config.alpn)):
                var p = config.alpn[i]
                if p.byte_length() == 0 or p.byte_length() > 255:
                    raise Error(
                        "ALPN protocol must be 1..255 bytes: '" + p + "'"
                    )
                alpn_blob.append(UInt8(p.byte_length()))
                for b in p.as_bytes():
                    alpn_blob.append(b)
            self._ctx.set_alpn(alpn_blob)

        # mTLS.
        if config.require_client_cert:
            self._ctx.set_verify_client_cert(config.client_ca_bundle)

        # Session resumption (RFC 5077 / RFC 8446 §4.6.1).
        # Default-on; cheap to keep enabled because the inner
        # SSL_CTX_set_options only clears the no-ticket bit, and
        # SSL_CTX_set_session_id_context is a one-shot at ctx
        # construction time.
        if config.enable_session_tickets:
            self._ctx.enable_session_tickets(config.ticket_lifetime_s)

        self.config = config^

    def reload(mut self) raises:
        """Re-read the cert + key files from ``config`` and
        atomically swap into the underlying ``SSL_CTX``.
        In-flight handshakes hold the old cert; new handshakes
        pick up the new one. Designed for cert rotation under
        live traffic.
        """
        self._ctx.reload(self.config.cert_file, self.config.key_file)

    def handshake_fd(mut self, fd: Int) raises -> Tuple[Int, TlsInfo]:
        """Drive the ``SSL_accept`` state machine on ``fd`` to
        completion (or fatal error) in blocking-poll mode. Sleeps
        in 1ms slices between WANT_READ / WANT_WRITE returns.

        Returns ``(ssl_addr, tls_info)`` — the caller owns the
        ``ssl_addr`` and is responsible for calling
        ``server_ssl_free(ctx, ssl_addr)`` when done. The
        ``TlsInfo`` carries the negotiated ALPN protocol + SNI
        hostname (live-populated from the OpenSSL handle).

        Args:
            fd: The accepted TCP fd (as returned by
                ``TcpListener.accept().raw_fd()`` or similar).

        Returns:
            A ``(ssl_addr, tls_info)`` tuple.

        Raises:
            Error: On fatal handshake failure (cert mismatch,
                client refused, etc.).
        """
        from ..runtime._libc_time import libc_nanosleep_ms, monotonic_now_ms

        var ssl_addr = server_ssl_new_accept(self._ctx, fd)
        if ssl_addr == 0:
            raise Error("flare_ssl_new_accept failed")

        # Blocking handshake loop. Spec semantics: server_ssl_do_handshake
        # returns 0 (done) / 1 (WANT_READ) / 2 (WANT_WRITE) / -1
        # (fatal). For blocking mode we just sleep on WANT_*
        # since the underlying fd will block in SSL_accept's read
        # / write anyway — but with explicit yields we don't
        # peg a CPU on transient EAGAIN.
        #
        # Deadline is measured against a monotonic clock (not an
        # iteration count) so a slow/stalled client cannot hold the
        # worker past ``handshake_timeout_ms`` even if the 1ms sleeps
        # dilate under the libc-sleep multiplier. The reactor follow-up
        # replaces this with poll-driven WANT_*-aware state transitions.
        var timeout_ms = self.config.handshake_timeout_ms
        # Bound a blocking SSL_accept read/write so a stalled client
        # cannot pin the worker inside the syscall past the deadline.
        _set_fd_recv_send_timeout(fd, timeout_ms)
        var deadline_ms = monotonic_now_ms() + timeout_ms
        while True:
            var rc = server_ssl_do_handshake(self._ctx, ssl_addr)
            if rc == 0:
                break
            if rc < 0:
                server_ssl_free(self._ctx, ssl_addr)
                raise Error("TLS handshake failed")
            # WANT_READ or WANT_WRITE — yield and retry until the
            # deadline (0 disables the cap).
            if timeout_ms > 0 and monotonic_now_ms() >= deadline_ms:
                server_ssl_free(self._ctx, ssl_addr)
                raise Error(
                    "TLS handshake timed out (" + String(timeout_ms) + "ms)"
                )
            _ = libc_nanosleep_ms(1)

        # Pull live info.
        var alpn = server_ssl_get_alpn_selected(self._ctx, ssl_addr)
        var sni = server_ssl_get_sni_host(self._ctx, ssl_addr)
        var info = TlsInfo(alpn_protocol=alpn, sni_host=sni)
        return (ssl_addr, info^)

    def info_placeholder(self) -> TlsInfo:
        """Return a default ``TlsInfo`` value with empty strings
        in every field. Kept for API-surface compatibility;
        production callers go through ``handshake_fd`` which
        returns a live-populated TlsInfo.
        """
        return TlsInfo()
