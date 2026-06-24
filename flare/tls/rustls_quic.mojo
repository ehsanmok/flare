"""`flare.tls.rustls_quic` -- rustls QUIC binding surface.

QUIC's TLS shape is fundamentally different from TLS-over-TCP:
the handshake runs *inside* QUIC frames, keys are derived per
encryption level (Initial / Handshake / 1-RTT / 0-RTT), and the
API the TLS library exposes is record-shaped rather than
byte-stream-shaped. See [`docs/tls-strategy.md`](../../docs/tls-strategy.md)
for the full rationale on why flare's QUIC path uses rustls
instead of extending the OpenSSL FFI for QUIC: the BoringSSL-
shape QUIC API is what the broader ecosystem (quiche, ngtcp2,
lsquic, msquic) standardized on, and `rustls` carries that API
natively (`rustls::quic::ServerConnection`).

## Module surface

This module declares:

- :class:`RustlsQuicConfig` -- server-side acceptor config
  (certificate chain, private key, ALPN list). Owns the
  configuration the Rust crate reads through the C ABI.
- :class:`RustlsQuicAcceptor` -- factory for per-connection
  TLS sessions. Conceptually parallel to
  :class:`flare.tls.acceptor.TlsAcceptor`, but produces QUIC
  sessions rather than TCP TLS streams.
- :class:`RustlsQuicSession` -- per-connection rustls handle.
  The QUIC reactor feeds it CRYPTO-frame bytes per
  encryption level and pulls handshake output bytes plus
  derived keys back out.
- :class:`RustlsQuicError` -- typed error carrier for the
  cases the reactor must distinguish (handshake-incomplete,
  protocol violation, certificate rejected, internal error).

Both ``RustlsQuicAcceptor`` and ``RustlsQuicSession`` are
``Movable`` (not ``Copyable``) because they own a Rust-allocated
``Box<Acceptor>`` / ``Box<Session>`` respectively; copy would
double-free on drop. The carriers route every FFI call through
``read lib`` borrow helpers (see
``flare/tls/_rustls_quic_ffi.mojo``) so Mojo's ASAP destructor
cannot unmap ``libflare_rustls_quic.so`` between
``get_function`` and the call.

References:
- RFC 9001 "Using TLS to Secure QUIC".
- RFC 8446 "The Transport Layer Security (TLS) Protocol Version 1.3".
- BoringSSL QUIC API conventions (the shape rustls implements).
"""

from std.collections import List, Optional
from std.ffi import OwnedDLHandle

from ._rustls_quic_ffi import (
    _do_acceptor_new,
    _do_acceptor_free,
    _do_accept,
    _do_connector_new,
    _do_connector_free,
    _do_connect,
    _do_session_free,
    _do_feed_crypto,
    _do_take_crypto,
    _do_is_handshake_complete,
    _do_alpn,
    _do_have_keys,
    _do_install_early_keys,
    _do_is_early_data_accepted,
    _do_packet_encrypt,
    _do_packet_decrypt,
    _do_header_encrypt,
    _do_header_decrypt,
    _do_last_error,
    _find_rustls_quic_lib,
    _encode_alpn_wire,
)


# ── Encryption levels (RFC 9001 §4) ─────────────────────────────────────


struct QuicEncryptionLevel:
    """RFC 9001 §4.1 packet protection levels.

    Each level has its own set of secret-keyed AEAD keys derived
    by the TLS handshake. The rustls QUIC binding emits CRYPTO
    frames at one level at a time and returns the derived keys
    when each level transitions into "ready".
    """

    comptime INITIAL: Int = 0
    """RFC 9001 §4.1 -- keyed by the QUIC v1 initial salt mixed
    with the client's Destination Connection ID. Used for the
    first client-hello flight."""

    comptime EARLY_DATA: Int = 1
    """RFC 9001 §4.1 -- 0-RTT keys. Captured from rustls via
    :meth:`RustlsQuicSession.install_early_keys` (which wraps
    ``Connection::zero_rtt_keys()``) rather than the per-level
    ``KeyChange`` pump; the AEAD + header-protection thunks accept
    this level for the 0-RTT send/recv path on a resumed
    connection."""

    comptime HANDSHAKE: Int = 2
    """RFC 9001 §4.1 -- handshake keys derived after the server
    accepts the client's Initial. Used for ServerHello and
    EncryptedExtensions."""

    comptime APPLICATION: Int = 3
    """RFC 9001 §4.1 -- 1-RTT keys. Used for all post-handshake
    application traffic; this is the keyed level the H3 server
    will see for every request."""


# ── Configuration carrier ──────────────────────────────────────────────


struct RustlsQuicConfig(Copyable, Defaultable, Movable):
    """Server-side rustls QUIC configuration carrier.

    Mirrors the shape of :class:`flare.tls.config.TlsConfig` but
    targets the rustls QUIC backend. Fields are owned by Mojo;
    the Rust crate reads them through the C ABI at acceptor
    construction time and never mutates them.

    The actual configuration that rustls would consume is built
    inside :class:`RustlsQuicAcceptor.__init__` -- this struct
    is the inputs.
    """

    var cert_chain_pem: String
    """PEM-encoded server certificate chain (leaf cert plus any
    intermediates). Empty string is invalid; the Rust crate
    will reject construction."""

    var private_key_pem: String
    """PEM-encoded server private key (PKCS#8). RFC 9001 §4.6
    says only TLS 1.3 is supported for QUIC; the Rust crate
    will reject non-TLS-1.3-compatible keys."""

    var alpn_protocols: List[String]
    """ALPN protocol identifiers the server is willing to
    negotiate (RFC 7301). For HTTP/3 this should include
    ``"h3"`` (RFC 9114 §3.1). Order matters -- earlier entries
    are preferred."""

    var max_early_data_size: UInt32
    """Maximum 0-RTT data the server will accept. Set to 0 to
    disable 0-RTT (the default). 0-RTT replay protection is
    out of scope for this cycle; see RFC 9001 §9.2."""

    var session_resumption_enabled: Bool
    """Whether to issue NewSessionTicket frames for session
    resumption. Default is True for production parity with
    OpenSSL acceptor."""

    def __init__(out self):
        self.cert_chain_pem = String("")
        self.private_key_pem = String("")
        self.alpn_protocols = List[String]()
        self.max_early_data_size = UInt32(0)
        self.session_resumption_enabled = True


# ── Error carrier ──────────────────────────────────────────────────────


struct RustlsQuicError(Copyable, Movable):
    """Typed error carrier for the rustls QUIC binding.

    The reactor distinguishes these cases for connection-close
    reason mapping (RFC 9000 §10.2 -- CONNECTION_CLOSE frame
    types and reasons). String reason is for logs only.
    """

    var kind: Int
    """One of the :class:`RustlsQuicErrorKind` codepoints."""

    var reason: String
    """Human-readable reason string for logs and the
    CONNECTION_CLOSE reason phrase."""

    @staticmethod
    def not_built() -> Self:
        """The Rust crate is not built; the reactor should
        treat this as a configuration error (not a per-packet
        failure). The build_rustls.sh activation script wired
        into pixi's [activation.scripts] auto-builds the crate
        on `pixi install`; this carrier exists for the rare
        path where activation didn't run (e.g. a bare mojo
        invocation outside a pixi shell)."""
        return Self(
            kind=RustlsQuicErrorKind.NOT_BUILT,
            reason=String(
                "rustls QUIC binding: the rustls Rust crate"
                " (flare/tls/ffi/rustls_wrapper) is not built."
                " Run `pixi run -e dev build-rustls-quic` to"
                " build it, or `pixi install` to re-trigger the"
                " activation script."
            ),
        )

    def __init__(out self, kind: Int, reason: String):
        self.kind = kind
        self.reason = reason


struct RustlsQuicErrorKind:
    """RFC 9000 §20.2 + RFC 9001 §4.8 cryptographic-error
    enumeration plus the local "not built" sentinel."""

    comptime NOT_BUILT: Int = 0
    """The Rust crate is not built. Returned by the constructor
    when the FFI symbol lookup fails (the activation script
    didn't run); resolved by re-running `pixi install`."""

    comptime HANDSHAKE_INCOMPLETE: Int = 1
    """The session needs more CRYPTO frame bytes before it can
    advance. Reactor should keep feeding bytes; not a real
    error from the connection's perspective."""

    comptime PROTOCOL_VIOLATION: Int = 2
    """The peer violated the TLS 1.3 wire grammar or the QUIC
    transport-parameter encoding. Maps to PROTOCOL_VIOLATION
    (0x0a) in CONNECTION_CLOSE."""

    comptime CERTIFICATE_INVALID: Int = 3
    """The server's certificate chain failed validation (only
    meaningful for client-side mTLS, which is the v0.10 line
    item -- this exists to keep the enum complete)."""

    comptime INTERNAL_ERROR: Int = 4
    """An internal Rust panic crossed the FFI boundary, or the
    C ABI returned an unexpected return code. Maps to
    INTERNAL_ERROR (0x01) in CONNECTION_CLOSE."""


# ── Acceptor ────────────────────────────────────────────────────────────


struct RustlsQuicAcceptor(Movable):
    """Factory for per-connection rustls QUIC sessions.

    Long-lived. One instance per QUIC listener, shared across
    every connection it accepts. The actual rustls
    ``rustls::quic::ServerConfig`` lives behind a heap-allocated
    Rust ``Box<Acceptor>``; this carrier holds the raw pointer
    (as ``Int``) plus the loaded ``libflare_rustls_quic.so``
    handle.

    Constructed lifecycle:

    - ``__init__`` calls ``flare_rustls_quic_acceptor_new`` with
      the PEM cert + key + wire-format ALPN list. Returns a
      carrier whose ``_opaque_handle`` is 0 when the FFI
      rejects the input (e.g. empty / malformed PEM). The
      reactor and per-connection ``accept()`` path treat a 0
      handle as a configuration error and bounce every
      connection immediately, surfacing the rustls last-error
      message via ``RustlsQuicError``.
    - ``__del__`` calls ``flare_rustls_quic_acceptor_free``
      to release the Rust-side ``Box<Acceptor>`` (no-op on a
      0 handle).
    - ``accept(dcid)`` calls ``flare_rustls_quic_accept`` to
      construct a fresh per-connection
      ``rustls::quic::ServerConnection`` and wraps it in
      :class:`RustlsQuicSession`.
    """

    var config: RustlsQuicConfig

    var _opaque_handle: Int
    """Raw ``Box<Acceptor>*`` (as ``Int``). Zero when the FFI
    construction failed; the reactor surfaces a configuration
    error in that case."""

    var _lib: OwnedDLHandle
    """Pinned library handle so ``dlclose`` doesn't tear the
    .so out from under any in-flight ``Session`` we created.
    Same defensive pattern as :class:`flare.tls._server_ffi.ServerCtx`.
    """

    def __init__(out self, var config: RustlsQuicConfig) raises:
        """Construct an acceptor from the supplied config.

        Does not raise on FFI rejection: the carrier always
        constructs (with ``_opaque_handle == 0`` on failure)
        so the reactor can surface the rustls last-error
        message via :class:`RustlsQuicError` rather than a
        partial-construction half-state.
        """
        var lib = OwnedDLHandle(_find_rustls_quic_lib())
        var cert_bytes = List[UInt8]()
        for b in config.cert_chain_pem.as_bytes():
            cert_bytes.append(b)
        var key_bytes = List[UInt8]()
        for b in config.private_key_pem.as_bytes():
            key_bytes.append(b)
        # The wire-format ALPN encoder raises on invalid (empty
        # or >255-byte) protocols. Surfacing that to the caller
        # is more useful than silently dropping the ALPN list,
        # so we propagate the raise. The PEM cert / key parse
        # failure path is non-raising -- it returns a NULL
        # handle that the reactor surfaces via
        # ``RustlsQuicError`` (see ``accept()`` below).
        var alpn_wire = _encode_alpn_wire(config.alpn_protocols)
        var handle = _do_acceptor_new(
            lib,
            cert_bytes,
            key_bytes,
            alpn_wire,
            config.max_early_data_size,
        )
        self._lib = lib^
        self._opaque_handle = handle
        self.config = config^

    def __del__(deinit self):
        if self._opaque_handle != 0:
            _do_acceptor_free(self._lib, self._opaque_handle)

    def free_session(self, handle: Int):
        """Release a per-connection rustls session previously
        produced by :func:`flare.tls._rustls_quic_ffi._do_accept`
        through the acceptor's pinned library handle.

        NULL is a no-op. Used by :class:`flare.quic.server.QuicListener`
        to drop every session in its slab from inside the
        listener's destructor without sub-field access on
        ``self.tls_acceptor._lib`` (which Mojo's ``deinit``
        ordering rule forbids).
        """
        _do_session_free(self._lib, handle)

    def accept(self, dst_cid: List[UInt8]) raises -> RustlsQuicSession:
        """Create a new per-connection session bound to the
        client's Destination Connection ID.

        The reactor calls this once per connection after parsing
        the first Initial packet. The DCID is required because
        the rustls binding uses it (via the QUIC transport
        parameters extension) to bind initial-secret derivation
        to the per-connection identity (RFC 9001 §5.2).
        """
        if self._opaque_handle == 0:
            var detail = _do_last_error(self._lib)
            raise Error(
                String(
                    "RustlsQuicAcceptor.accept: acceptor handle is"
                    " NULL (typically because the supplied PEM"
                    " cert or key failed to parse, or the ALPN"
                    " wire-format encoding raised); last_error="
                )
                + detail
            )
        # Empty transport_params here: the QUIC server reactor
        # encodes the real transport parameters (initial_max_data,
        # initial_max_streams_*, etc.); for the handshake-only
        # path here the rustls side accepts an empty extension blob.
        var tp = List[UInt8]()
        var session_handle = _do_accept(self._lib, self._opaque_handle, tp)
        if session_handle == 0:
            var detail = _do_last_error(self._lib)
            raise Error(String("RustlsQuicAcceptor.accept failed: ") + detail)
        # Each session opens its own OwnedDLHandle. The .so
        # itself stays mapped via LD_PRELOAD (set by the
        # build_rustls.sh activation script on Linux) and via
        # the acceptor's own handle, so opening multiple times
        # is just a refcount bump.
        var session_lib = OwnedDLHandle(_find_rustls_quic_lib())
        return RustlsQuicSession._wrap(
            session_lib^, session_handle, dst_cid.copy()
        )


# ── Connector (client role) ─────────────────────────────────────────────


struct RustlsQuicConnector(Movable):
    """Client-role factory for per-connection rustls QUIC sessions.

    The mirror of :class:`RustlsQuicAcceptor`: long-lived, one
    instance per HttpClient h3 origin policy (trust roots + ALPN),
    reused across every QUIC connection the client opens. Wraps a
    heap-allocated Rust ``Box<Connector>`` (the rustls
    ``ClientConfig``) behind a raw pointer carried as ``Int`` plus
    the pinned ``libflare_rustls_quic.so`` handle.

    Lifecycle mirrors the acceptor: ``__init__`` ->
    ``flare_rustls_quic_connector_new`` (0 handle on PEM/ALPN
    failure, surfaced by :meth:`connect`); ``__del__`` ->
    ``flare_rustls_quic_connector_free``; :meth:`connect` ->
    ``flare_rustls_quic_connect`` returning a
    :class:`RustlsQuicSession` (role-agnostic on the Mojo side).
    """

    var alpn_protocols: List[String]
    """ALPN identifiers advertised to the origin (``"h3"`` for
    HTTP/3). Order is preference order, as the acceptor's list."""

    var _opaque_handle: Int
    """Raw ``Box<Connector>*`` (as ``Int``). Zero when the FFI
    rejected the CA bundle / ALPN list."""

    var _lib: OwnedDLHandle
    """Pinned library handle (same defensive pin as the acceptor)."""

    def __init__(
        out self, ca_pem: String, var alpn_protocols: List[String]
    ) raises:
        """Build a connector from a trust-anchor PEM bundle + ALPN list.

        ``ca_pem`` is a PEM bundle of trusted roots; for a loopback
        link to flare's own server, pass that server's self-signed
        cert (a self-signed leaf is its own root). Does not raise on
        PEM-parse failure -- the carrier constructs with a 0 handle
        and :meth:`connect` surfaces the rustls last-error -- so a
        configuration mistake is one clear error at connect time, not
        a partial-construction half-state. Raises only on an invalid
        ALPN list (empty or >255-byte protocol).
        """
        var lib = OwnedDLHandle(_find_rustls_quic_lib())
        var ca_bytes = List[UInt8]()
        for b in ca_pem.as_bytes():
            ca_bytes.append(b)
        var alpn_wire = _encode_alpn_wire(alpn_protocols)
        var handle = _do_connector_new(lib, ca_bytes, alpn_wire)
        self._lib = lib^
        self._opaque_handle = handle
        self.alpn_protocols = alpn_protocols^

    def __del__(deinit self):
        if self._opaque_handle != 0:
            _do_connector_free(self._lib, self._opaque_handle)

    def free_session(self, handle: Int):
        """Release a per-connection session through the connector's
        pinned library handle (mirror of
        :meth:`RustlsQuicAcceptor.free_session`). NULL is a no-op."""
        _do_session_free(self._lib, handle)

    def connect(
        self,
        server_name: String,
        transport_params: List[UInt8] = List[UInt8](),
    ) raises -> RustlsQuicSession:
        """Open a client-role session against ``server_name`` (SNI).

        ``transport_params`` is the client's encoded QUIC transport
        parameters (empty is accepted for the handshake-only path;
        the QUIC client driver in H3C-1 fills the real blob). The
        returned :class:`RustlsQuicSession` drives the client
        handshake through the same feed/take CRYPTO + AEAD + header
        thunks the server session uses; the first
        ``take_crypto(INITIAL)`` drains the ClientHello.
        """
        if self._opaque_handle == 0:
            var detail = _do_last_error(self._lib)
            raise Error(
                String(
                    "RustlsQuicConnector.connect: connector handle is"
                    " NULL (typically because the supplied CA PEM"
                    " failed to parse, or the ALPN wire-format"
                    " encoding raised); last_error="
                )
                + detail
            )
        var name_bytes = List[UInt8]()
        for b in server_name.as_bytes():
            name_bytes.append(b)
        var session_handle = _do_connect(
            self._lib, self._opaque_handle, name_bytes, transport_params
        )
        if session_handle == 0:
            var detail = _do_last_error(self._lib)
            raise Error(String("RustlsQuicConnector.connect failed: ") + detail)
        var session_lib = OwnedDLHandle(_find_rustls_quic_lib())
        # The client picks its own SCID/DCID in the QUIC driver
        # (H3C-1), so the session-handle carrier holds no DCID-bound
        # identity here; an empty dcid is the right placeholder.
        return RustlsQuicSession._wrap(
            session_lib^, session_handle, List[UInt8]()
        )


# ── Session ─────────────────────────────────────────────────────────────


struct RustlsQuicSession(Movable):
    """Per-connection rustls handle.

    The reactor's per-connection state machine drives this:

    1. Feed inbound CRYPTO frame bytes via :meth:`feed_crypto`.
    2. Pull outbound CRYPTO frame bytes via :meth:`take_crypto`.
    3. :meth:`is_handshake_complete` returns True once the
       1-RTT keys are derived; from there the application can
       send data on streams.
    4. :meth:`selected_alpn` returns the negotiated ALPN
       identifier (e.g. ``"h3"``) so the reactor can dispatch
       to the right application-layer driver.

    Construction:

    - Direct ``RustlsQuicSession(dcid)`` builds a carrier with
      a 0 handle; every FFI-touching method then raises with a
      clear "NULL session" message. Tests use this shape to
      exercise the failure path without needing a real
      acceptor.
    - The production path uses
      :meth:`RustlsQuicAcceptor.accept` which calls into the
      ``RustlsQuicSession._wrap`` private constructor with a
      real Rust-side ``Box<Session>*``.
    """

    var dst_cid: List[UInt8]
    """The DCID this session was created for. Carried so the
    reactor can sanity-check key derivation later."""

    var _opaque_session_handle: Int
    """Raw ``Box<Session>*`` (as ``Int``). Zero for a standalone
    constructor (test path); non-zero after a successful
    :meth:`RustlsQuicAcceptor.accept`."""

    var _lib: OwnedDLHandle
    """Pinned library handle so ``dlclose`` doesn't tear the
    .so out from under the in-flight FFI calls."""

    var _level: Int
    """Current outbound encryption level. Starts at
    :data:`QuicEncryptionLevel.INITIAL`; advances as the
    handshake progresses."""

    def __init__(out self, dst_cid: List[UInt8]) raises:
        """Build a session carrier with a NULL handle. Every
        FFI-touching method raises on a NULL handle.

        Useful for testing the level machine + DCID round-trip
        without a real acceptor; the production path uses
        :meth:`RustlsQuicAcceptor.accept`.
        """
        self._lib = OwnedDLHandle(_find_rustls_quic_lib())
        self.dst_cid = dst_cid.copy()
        self._opaque_session_handle = 0
        self._level = QuicEncryptionLevel.INITIAL

    def __init__(
        out self,
        var lib: OwnedDLHandle,
        handle: Int,
        var dst_cid: List[UInt8],
    ):
        """Internal: wrap a real Rust-side ``Box<Session>*`` that
        :meth:`RustlsQuicAcceptor.accept` just produced.

        Each session gets its own ``OwnedDLHandle`` so the .so
        refcount stays high until the session drops; on Linux the
        ``LD_PRELOAD`` from ``build_rustls.sh`` is the additional
        belt-and-suspenders pin.
        """
        self._lib = lib^
        self._opaque_session_handle = handle
        self.dst_cid = dst_cid^
        self._level = QuicEncryptionLevel.INITIAL

    @staticmethod
    def _wrap(
        var lib: OwnedDLHandle, handle: Int, var dst_cid: List[UInt8]
    ) -> Self:
        """Internal: wrap a real Rust-side ``Box<Session>*`` that
        :meth:`RustlsQuicAcceptor.accept` just produced.
        """
        return Self(lib^, handle, dst_cid^)

    def __del__(deinit self):
        if self._opaque_session_handle != 0:
            _do_session_free(self._lib, self._opaque_session_handle)

    def feed_crypto(mut self, level: Int, data: List[UInt8]) raises:
        """Feed inbound CRYPTO frame bytes at ``level``.

        The reactor calls this after dispatching a CRYPTO frame
        out of a packet at the matching encryption level. The
        ``data`` buffer is a contiguous chunk; the rustls side
        reassembles fragments internally.
        """
        if self._opaque_session_handle == 0:
            raise Error(
                "RustlsQuicSession.feed_crypto: NULL session handle"
                " (construct via RustlsQuicAcceptor.accept for the"
                " production path)"
            )
        var rc = _do_feed_crypto(
            self._lib, self._opaque_session_handle, level, data
        )
        if rc != 0:
            var detail = _do_last_error(self._lib)
            raise Error(
                String("flare_rustls_quic_feed_crypto rc=")
                + String(rc)
                + ": "
                + detail
            )
        # Lift the current outbound level conservatively as the
        # rustls side advances. The reactor uses this to tag the
        # take_crypto output for packetization; commit 4/4 will
        # tighten this to track the rustls KeyChange enum.
        if level > self._level:
            self._level = level

    def take_crypto(self, level: Int) raises -> List[UInt8]:
        """Drain pending outbound CRYPTO frame bytes at ``level``.

        Returns an empty list when no bytes are pending. The
        reactor packages the result into CRYPTO frames inside
        packets at the matching encryption level.
        """
        if self._opaque_session_handle == 0:
            raise Error(
                "RustlsQuicSession.take_crypto: NULL session handle"
                " (construct via RustlsQuicAcceptor.accept for the"
                " production path)"
            )
        return _do_take_crypto(self._lib, self._opaque_session_handle, level)

    def is_handshake_complete(self) -> Bool:
        """Whether the 1-RTT keys are derived. Returns False on a
        NULL session (test path) or while handshaking; True after
        rustls flips into the application-keyed state."""
        return _do_is_handshake_complete(self._lib, self._opaque_session_handle)

    def selected_alpn(self) raises -> String:
        """ALPN identifier the rustls side picked.

        Returns the negotiated identifier from the ALPN list
        passed at config time (e.g. ``"h3"``). The reactor uses
        this to dispatch to the H3 server vs an alternative
        application protocol over QUIC.
        """
        return _do_alpn(self._lib, self._opaque_session_handle)

    def current_level(self) -> Int:
        """Current outbound encryption level. Useful for tests
        confirming the level machine compiles."""
        return self._level

    # ── Per-level AEAD + header protection ───────────────────────────

    def have_keys(self, level: Int) -> Bool:
        """Whether rustls has installed per-level keys at the
        given encryption level (2 = Handshake, 3 = 1-RTT).

        Initial-level keys never flow through rustls's
        ``KeyChange`` (they derive from the connection ID per
        RFC 9001 §5.2 and the flare side runs Initial AEAD
        through :class:`flare.quic.crypto.OpenSslQuicCrypto`),
        so this returns False for level 0. The reactor polls
        :meth:`have_keys` after every :meth:`take_crypto` pump to
        learn when to install Handshake / 1-RTT keys onto the
        owning :class:`flare.quic.server.QuicConnection`.

        NULL session handles (the test-only constructor path)
        return False without raising.
        """
        if self._opaque_session_handle == 0:
            return False
        return _do_have_keys(self._lib, self._opaque_session_handle, level) == 1

    def install_early_keys(self) -> Bool:
        """Capture rustls's 0-RTT (EarlyData) keys into the session,
        if available (RFC 9001 §4.1; wraps
        ``Connection::zero_rtt_keys()``).

        On the client this returns True right after
        :meth:`RustlsQuicConnector.connect` IFF the connector's
        session store held a ticket for the SNI (a resumed
        connection) and early data is enabled; on the server it
        returns True once the resumed ClientHello has been fed and
        0-RTT was accepted. After True, the
        :data:`QuicEncryptionLevel.EARLY_DATA` AEAD + header
        thunks encrypt/decrypt 0-RTT packets. Returns False on a
        NULL session (test path) or when rustls has no 0-RTT keys
        for this connection (the common first-flight case).
        """
        if self._opaque_session_handle == 0:
            return False
        return (
            _do_install_early_keys(self._lib, self._opaque_session_handle) == 1
        )

    def is_early_data_accepted(self) -> Bool:
        """Whether the server signalled it will process the client's
        0-RTT data (RFC 8446 §4.2.10; client-role only).

        A False after the handshake completes means the server
        rejected early data and the client must replay it in 1-RTT.
        Returns False on a NULL session or for the server role.
        """
        if self._opaque_session_handle == 0:
            return False
        return (
            _do_is_early_data_accepted(self._lib, self._opaque_session_handle)
            == 1
        )

    def packet_encrypt(
        self,
        level: Int,
        packet_number: UInt64,
        header: List[UInt8],
        mut payload: List[UInt8],
    ) raises -> List[UInt8]:
        """Encrypt ``payload`` in place at ``level`` via rustls's
        ``Keys.local.packet.encrypt_in_place`` (RFC 9001 §5.3).

        ``header`` is the QUIC packet header (used as AEAD AAD);
        the returned tag is the 16-byte authentication tag the
        caller appends to the on-wire packet. Raises if the FFI
        rejects (e.g. keys not yet installed at ``level``); the
        rustls error text is in :func:`_do_last_error`.
        """
        if self._opaque_session_handle == 0:
            raise Error("RustlsQuicSession.packet_encrypt: NULL session handle")
        return _do_packet_encrypt(
            self._lib,
            self._opaque_session_handle,
            level,
            packet_number,
            header,
            payload,
        )

    def packet_decrypt(
        self,
        level: Int,
        packet_number: UInt64,
        header: List[UInt8],
        mut payload: List[UInt8],
    ) raises -> Int:
        """Verify + strip the AEAD tag from ``payload`` in place
        at ``level`` via rustls's
        ``Keys.remote.packet.decrypt_in_place`` (RFC 9001 §5.3).

        Returns the plaintext length (always ``len(payload) - 16``
        for the AEAD-GCM / ChaCha20-Poly1305 suites rustls speaks);
        raises if rustls rejects the tag (the typical wrong-keys-
        at-this-level symptom).
        """
        if self._opaque_session_handle == 0:
            raise Error("RustlsQuicSession.packet_decrypt: NULL session handle")
        return _do_packet_decrypt(
            self._lib,
            self._opaque_session_handle,
            level,
            packet_number,
            header,
            payload,
        )

    def header_encrypt(
        self,
        level: Int,
        sample: List[UInt8],
        first_byte_addr: Int,
        pn_addr: Int,
        pn_len: Int,
    ) raises:
        """Apply QUIC header protection (RFC 9001 §5.4) to the
        packet's first byte + packet-number bytes via rustls's
        ``Keys.local.header.encrypt_in_place``.

        ``sample`` MUST be a 16-byte slice of the encrypted
        payload (4 bytes past the start of the packet-number
        field). ``first_byte_addr`` / ``pn_addr`` are raw pointer
        values (as Int) so the caller can keep the byte cells on
        the stack and let rustls write through.
        """
        if self._opaque_session_handle == 0:
            raise Error("RustlsQuicSession.header_encrypt: NULL session handle")
        _do_header_encrypt(
            self._lib,
            self._opaque_session_handle,
            level,
            sample,
            first_byte_addr,
            pn_addr,
            pn_len,
        )

    def header_decrypt(
        self,
        level: Int,
        sample: List[UInt8],
        first_byte_addr: Int,
        pn_addr: Int,
        pn_len: Int,
    ) raises:
        """Remove QUIC header protection (RFC 9001 §5.4) from
        the packet's first byte + packet-number bytes via
        rustls's ``Keys.remote.header.decrypt_in_place``. Same
        sample contract as :meth:`header_encrypt`.
        """
        if self._opaque_session_handle == 0:
            raise Error("RustlsQuicSession.header_decrypt: NULL session handle")
        _do_header_decrypt(
            self._lib,
            self._opaque_session_handle,
            level,
            sample,
            first_byte_addr,
            pn_addr,
            pn_len,
        )
