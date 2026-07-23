# TLS strategy

flare's TLS layer today is **OpenSSL via FFI** through
[`flare/tls/ffi/openssl_wrapper.cpp`](../flare/tls/ffi/openssl_wrapper.cpp).
That choice has carried through server-side termination, hot
reload, session resumption, and ALPN dispatch, with new
features layered on top -- ``WsAutoClient`` advertises ALPN on
``wss://``, the ``HttpClient`` over ``https://`` advertises
``["h2", "http/1.1"]``. This page documents the rationale, the
boundaries, and the planned rustls-for-QUIC direction that lands
alongside the QUIC server.

## Current posture

| Aspect | Status |
|---|---|
| TLS backend | OpenSSL 3.x via FFI. Pinned per pixi env. |
| Protocols | TLS 1.2 + 1.3. TLS 1.0 / 1.1 explicitly refused. |
| Cipher policy | Forward-secret AEAD whitelist. RC4 / 3DES / CBC chains absent from the negotiated set. |
| ALPN | Advertised on both sides; refusal-to-downgrade enforced. |
| Cert reload | ``TlsAcceptor.reload()`` atomic swap (no in-flight drop). |
| Session resumption | RFC 5077 tickets + RFC 8446 §4.6.1 ``NewSessionTicket`` capture/replay. Server-side opt-in via ``TlsServerConfig.enable_session_tickets``; client-side opt-in via ``TlsConfig.enable_session_resumption``. |
| mTLS | Construction-time CA chain validation; ``TlsAcceptor.with_client_cert_verification`` enforces presence + chain. |
| HTTPS server termination | In-process, non-blocking. ``HttpServer.bind_tls`` / ``serve_tls`` terminate TLS on a ``TlsConnHandle`` and serve HTTP/1.1 (buffered + chunked-streaming) over ``SSL_read`` / ``SSL_write``. See below. |
| OCSP stapling | Not in-tree. Most production deployments terminate TLS at a proxy with stapling enabled. |
| Encrypted ClientHello (ECH) | Not in-tree. The plan is to land it when OpenSSL stable carries it. |

## In-process HTTPS server termination

flare terminates TLS itself -- no reverse proxy required to speak
``https://``. The primitive is
[`TlsConnHandle`](../flare/http/_reactor/tls_conn_handle.mojo): it owns
the accepted ``TcpStream``, forces the fd non-blocking, and drives
OpenSSL's non-blocking ``SSL_accept`` / ``SSL_read`` / ``SSL_write``,
mapping ``WANT_READ`` / ``WANT_WRITE`` onto the reactor's own
``StepResult`` re-arm contract (the FFI seams
``flare_ssl_read_ex`` / ``flare_ssl_write_ex`` return explicit
``FLARE_SSL_IO_*`` sentinels rather than ambiguous ``-1``). ALPN + SNI
are read on handshake completion so the caller can dispatch h1 vs h2.

The application-facing surface is two calls:

```mojo
var srv = HttpServer.bind_tls(
    SocketAddr.localhost(8443),
    cert_file="server.crt",
    key_file="server.key",
    alpn=["http/1.1"],
)
srv.serve_tls(router^)
```

``bind_tls`` loads the PEM cert/key into a server ``SSL_CTX`` and
advertises ALPN; ``serve_tls`` runs the accept loop, driving each
connection through the handshake and an HTTP/1.1 keep-alive loop that
reuses the **exact** plaintext request-parse + response-serialise
helpers -- only the byte transport differs. Streaming composes for
free: a handler returning ``stream_response(source)`` is emitted with
``Transfer-Encoding: chunked`` framing written as ciphertext, so the
same handler streams byte-identically on h1, h2, h3, and https (the
head is framed by the shared ``frame_h1_stream_head_into`` adapter; the
wire is an implementation detail). See
[`examples/advanced/https_server.mojo`](../examples/advanced/https_server.mojo)
(`pixi run example-https`).

Scope today: ``serve_tls`` is synchronous (one connection at a time on
the calling thread, matching the original blocking ``HttpServer``
semantics) and frames HTTP/1.1 only -- an ALPN-negotiated ``h2``
connection is closed cleanly rather than mis-framed. Reactor-multiplexed
TLS (many concurrent TLS connections on one event loop) and h2-over-TLS
reuse this same ``TlsConnHandle`` state machine and are the follow-up.

## Why OpenSSL + FFI rather than a Mojo-native stack

Three reasons, in priority order:

1. **Coverage.** OpenSSL handles the entire matrix: TLS 1.2 +
   1.3, every cipher policy real customers ask for, OCSP, ALPN,
   session tickets, NewSessionTicket replay, the cert-chain
   builder, the X.509 verifier, certificate-name matching with
   wildcard + IP-literal SANs. Re-implementing any one of these
   in Mojo would be a six-month project for marginal value.
2. **Trust.** OpenSSL is the most-audited TLS stack on the
   planet. Every CVE that lands gets a same-day pixi bump --
   far better than carrying our own bug in the bytes we put on
   the wire.
3. **Footprint.** The FFI shim is ~1,200 lines of C++
   (`flare/tls/ffi/openssl_wrapper.cpp`); the rest
   is Mojo. We do not pay for the abstraction layer at runtime
   (the FFI calls inline into the reactor's read / write
   stages with one libc indirection).

The alternative (Mojo-native TLS) was scoped and rejected: the
shape would require a 5K+-line Mojo crate plus a separate set
of conformance suites (NIST SP 800-52, BoringSSL test vectors).
That is the same investment as the rest of flare's HTTP/2 + WS
+ runtime layers combined. The cost is not justified.

## Why rustls for QUIC (planned)

QUIC has a different TLS shape than TLS-over-TCP: the handshake
runs inside QUIC frames, the keys are derived per-encryption-
level (Initial / Handshake / 1-RTT / 0-RTT), and the API the
TLS library exposes is record-shaped rather than byte-stream-
shaped. OpenSSL's QUIC API has shipped in 3.2+ but is
**not** the BoringSSL QUIC API that the broader ecosystem
(quiche, ngtcp2, lsquic, msquic) standardised on. Building
against OpenSSL 3.2+ QUIC means re-implementing the
key-derivation + record-shape dance that the rest of the
ecosystem ships off-the-shelf.

flare's QUIC server will use **rustls + quinn-style
QUIC API bindings** through a Rust FFI shim. The rationale:

- `rustls` carries the BoringSSL-shape QUIC API natively (the
  `QuicConfig` / `QuicServer` traits already exist).
- The Rust toolchain is in `pixi.toml` already (the bench
  harness baselines build via cargo); adding a second
  ``rustls_wrapper`` shim is a small extension.
- A single TLS strategy for QUIC + new TLS-over-TCP wires
  (h2 / WS-over-h2) is technically possible but is out of scope
  for now; the OpenSSL path stays for TCP, the rustls path is
  added for QUIC, and collapsing onto a single backend is a
  later consideration.

## What stays out-of-tree

- **Certificate issuance + renewal**: use certbot / cert-
  manager / ACME directly. flare's ``TlsAcceptor.reload`` is
  the integration point.
- **TLS 1.3 0-RTT over TCP** (OpenSSL h1 / h2 / WS): not
  implemented. Replay protection is trickier than it looks and the
  win is small for our target workloads (API servers + sidecars).
  Note this is the TCP path only -- **QUIC 0-RTT is implemented**
  (rustls EarlyData): the server admits + dispatches early data
  with per-connection (``EarlyDataReplayGuard``) and cross-
  connection (``EarlyDataStrikeSet``) replay defense, and the H3
  client (``Http3ClientConnection.fetch_0rtt``) emits idempotent
  requests in the first EarlyData flight, replaying transparently
  at 1-RTT on server reject.
- **DTLS / SCTP**: not in scope.
- **CRL / OCSP responder**: out-of-tree; if you need
  revocation enforcement, terminate at a proxy.

## Version + verification cadence

| Pin | Where | When it changes |
|---|---|---|
| OpenSSL major | `pixi.toml` ``openssl = ">=3.6.1,<4"`` | On CVE response or scheduled minor bump. |
| Conda channel | `pixi.toml` ``channels = ["conda-forge"]`` | Stable; conda-forge is the single source of truth. |
| TLS test corpus | `tests/tls/test_tls*.mojo` | Every release cycle; runs under sanitiser. |
| TLS session-resumption replay test | `tests/tls/test_tls_resume.mojo` | Every release cycle. |

See [`security.md`](security.md) and [`threat-model.md`](threat-model.md)
for the layered posture across all of flare.
