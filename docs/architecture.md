# Architecture

flare is a layered library. Higher layers depend on lower layers and peer
modules at the same layer don't import each other. The runtime scheduler
is generic over a `Frontend` trait, so the runtime → http edge that used
to exist is now an http → runtime edge (the HTTP worker bring-up lives
in `flare.http.multicore` and plugs into `Scheduler[F]` via the trait).
The historic intra-package edge between `flare.http` and `flare.http2`
is now broken: shared wire types (`Request`, `Response`, `HeaderMap`,
`Method`, `Status`) live in the neutral `flare.http.wire` re-export
layer, and both `flare.http` and `flare.http2` import from there
instead of each other. The lint `pixi run check-no-http-http2-cycle`
enforces the rule. No global state, no hidden runtime.

```
flare.io       BufReader (Readable trait, generic buffered reader)
flare.ws       WebSocket client + server (RFC 6455). Multi-worker
               server via WsServer.serve(handler, num_workers=N)
               on a SO_REUSEPORT-shared port. WsClient.connect
               advertises ALPN ["http/1.1"] on wss:// to lock in
               the existing Upgrade-based path. RFC 8441
               WebSocket-over-HTTP/2 (Extended CONNECT,
               :protocol=websocket): server-side capture in
               flare.http2 + WsOverH2Stream client-side
               adapter that bridges DATA frames to/from
               WsFrame. RFC 7692 permessage-deflate codec --
               no_context_takeover via free functions
               (compress_message / decompress_message), plus
               context-takeover via PermessageDeflateContext
               (persistent z_stream pair carrying the LZ77
               window between messages; per-message cap on
               both paths to bound zip-bomb risk).                ALPN-aware
               WsAutoClient.connect dispatches on the
               negotiated protocol -- h1 via the existing
               Upgrade handshake, h2 routed to WsOverH2Stream
               via Extended CONNECT.
flare.http2    Low-level HTTP/2 byte drivers (RFC 9113 +
               RFC 7541): Frame codec, HPACK enc/dec (incl.
               H=1 Huffman literals + a 256-entry table-driven
               fast decoder for short codes, 3-4x scalar),
               stream + connection state machines,
               H2Connection (server byte driver),
               Http2ClientConnection (client byte driver,
               with SETTINGS_ENABLE_CONNECT_PROTOCOL +
               send_extended_connect for WS-over-h2),
               h2c upgrade detection (preface peek + Upgrade
               dance), per-stream RST_STREAM Cancel
               propagation, ALPN dispatch helper.
flare.http     HTTP/1.1 client + reactor server + Handler / Router
               + extractors (incl. Form / Multipart / Cookies)
               + ComptimeRouter + StaticResponse + Cancel / CancelHandler
               + middleware stack (Logger / RequestId / Compress
               / CatchPanic / Retry / PostHocDeadline)
               + Cors + FileServer (with HEAD + Range)
               + Cache[Inner, S] (RFC 9111 wrapping middleware --
               freshness check, conditional revalidation, Vary-
               aware secondary keying)
               + content-encoding (gzip + brotli)
               + signed cookies + typed Session[T] stores
               + HTTP/1.1 trailers (parse + emit) + multi-listener
               HttpServer.bind_many + HttpClient.with_pool
               connection pool + h2c-via-Upgrade client.
               Sans-I/O parser sublayer under flare.http.proto.*
               with _ExperimentalH1LeniencyConfig (future-policy
               knobs; the strict default is the only wire shape
               currently enforced); conformance corpora under
               conformance/h1/ + conformance/ws/. Template
               engine with single-level inheritance via {% block %}
               + {% extends %}. RFC 9111 cache primitives --
               CacheControl directive parser, CacheKey + Vary-
               aware keying, bounded FIFO InMemoryCacheStore
               with parsed freshness on CacheEntry.is_fresh.
               Router is Copyable (refcounted struct-handler list)
               and resolves the multi-worker overload directly.
flare.grpc     gRPC primitives on top of the HTTP/2 reactor.
               Wire codecs (length-prefixed message framing,
               canonical Status codes, Metadata carrier with
               binary / text key discipline) plus the unary
               server adapter: GrpcUnary handler trait, request-
               header validator (`content-type: application/grpc`,
               `te: trailers`, `grpc-timeout` parser), LPM
               stitching from HTTP/2 DATA frames, and the
               sans-I/O run_unary_call orchestrator that emits
               response bytes + final GrpcStatus + trailing
               GrpcMetadata. Server-streaming, client-streaming,
               bidirectional, the client side, and proto3
               codegen ship in follow-up cycles.
flare.openapi  OpenAPI 3.1 spec model + deterministic JSON
               emitter (stable key order for diffable specs).
               Auto-derivation from ComptimeRouter +
               serve_openapi + Swagger UI mount ship later.
flare.quic     Sans-I/O QUIC v1 codec primitives + pure state
               machines: variable-length integer codec
               (RFC 9000 §16); long / short packet header codec
               (RFC 9000 §17); all 22 RFC 9000 §19 transport
               frames driven by a `FrameHandler` trait +
               `parse_frame_into[H](buf, handler)` dispatcher
               that fires per-type `on_*` callbacks against the
               caller's handler (no intermediate union carrier),
               with the per-type `encode_*(payload, mut out:
               List[UInt8])` writers appending to a caller-owned
               buffer; transport-parameter codec (RFC 9000 §18);
               connection + stream state machines (RFC 9000 §3,
               §10, §13); CUBIC + HyStart++ congestion
               controller + RFC 9002 §7.7 pacing budget as pure
               functions over a `CcState` value. The
               `CongestionController` trait pairs a CUBIC default
               (production) with a Reno fallback (deterministic
               tests) per RFC 9002 Appendix B.
               `flare.quic.crypto` carries the RFC 9001 §5 +
               RFC 5869 HKDF key schedule + the `QuicCrypto`
               trait + the `OpenSslQuicCrypto` AEAD backend
               (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305,
               header-protection masks per RFC 9001 §5.3 /
               §5.4); `flare.quic.protection` wraps the AEAD
               backend in the per-level `unprotect_initial` /
               `protect_initial` / `unprotect_handshake` /
               `protect_handshake` / `unprotect_1rtt` /
               `protect_1rtt` helpers per RFC 9001 §5.4.
               `flare.quic.server` runs the live UDP reactor
               loop: `QuicListener.run` binds, a non-blocking
               `recv_from` drain feeds `ConnectionIdTable.lookup`,
               the per-datagram bytes flow through
               `OpenSslQuicCrypto.decrypt` ->
               `parse_frame_into[H]` -> `Connection.handle_frame`
               -> `ConnectionEvents`; each tick drains the
               per-connection egress, coalescing ACK / flow-control
               / HANDSHAKE_DONE / H3 STREAM frames into single
               1-RTT datagrams via `_drain_1rtt_coalesced` ->
               header-protection -> `send_to(peer)`; PTO + idle
               + ack-delay timers sit on the shared
               `flare.runtime.TimerWheel`; CC + pacing budget
               gate the egress path. ECN is echoed per
               RFC 9002 §A.4.
flare.h3       Sans-I/O HTTP/3 codec primitives: frame codec +
               SETTINGS payload (RFC 9114 §7); request-stream
               state machine (`H3RequestReader` + the
               `H3RequestEventHandler` trait + `feed_into[H]`
               dispatcher) that consumes wire bytes and fires
               typed `on_headers` / `on_data` / `on_trailers` /
               `on_unknown_frame` / `on_protocol_error`
               callbacks on the caller's handler per RFC 9114
               §4; response-stream writer that emits HEADERS /
               DATA / TRAILERS frames with QPACK-encoded field
               sections, ASCII header-name lowercasing, and
               pseudo-header validation. The encoders accept a
               `mut out: List[UInt8]` so the caller threads a
               per-connection buffer through repeated writes.
               The `H3Connection` driver in `flare.h3.server`
               drives per-stream `H3RequestReader` allocation,
               `feed_stream_chunk` -> Handler -> response writer
               dispatch, `take_response_frames` egress draining,
               and CONTROL + QPACK uni-stream type dispatch per
               RFC 9114 §6.2 (SETTINGS / GOAWAY / MAX_PUSH_ID
               consumed; QPACK dynamic-table inserts rejected
               per the SETTINGS we advertise). Per Phase E
               Track Q12-W the `H3Connection` is slot-allocated
               on `QuicListener.h3_connections` per
               `QuicConnection`; decrypted STREAM payloads route
               through `QuicListener._route_h3_stream_chunks`
               using the extended `ConnectionEvents.stream_chunks`,
               and `HttpServer.serve_h3[H]` walks
               `take_h3_completed_streams -> take_h3_request ->
               handler.serve -> emit_h3_response ->
               take_h3_response_egress` every reactor tick.
flare.qpack    Sans-I/O static-only QPACK encoder + decoder
               (RFC 9204). Static table per Appendix A (99
               entries), literal field lines with literal
               names, Huffman shared with the HPACK
               implementation in `flare.http.proto.huffman`.
               Dynamic table deferred to a follow-up cycle.
flare.crypto   HMAC-SHA256, base64url codec
flare.tls      TLS 1.2/1.3 (OpenSSL); TlsAcceptor + ALPN +
               session resumption (RFC 5077 tickets / RFC 8446
               §4.6.1 NewSessionTicket capture and replay).
               The QUIC-side binding (`RustlsQuicAcceptor` +
               `RustlsQuicSession`) wraps `rustls::quic::ServerConnection`
               (rustls 0.23) through a C ABI shim; per-level
               CRYPTO frames feed / drain through
               `flare_rustls_quic_feed_crypto` / `_take_crypto`,
               negotiated ALPN through `flare_rustls_quic_alpn`.
               OpenSSL stays the canonical h1 / h2 TLS acceptor;
               rustls handles the QUIC TLS exchange because the
               OpenSSL QUIC API is still tracking the IETF
               draft branch.
flare.tcp      TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      UdpSocket (IPv4 + IPv6)
flare.uds      UnixListener + UnixStream (AF_UNIX sidecar IPC)
flare.dns      getaddrinfo (dual-stack)
flare.net      IpAddr, SocketAddr, RawSocket
flare.runtime  Reactor (kqueue/epoll + EPOLLEXCLUSIVE), TimerWheel,
               Scheduler, HandoffQueue + WorkerHandoffPool,
               num_cpus / default_worker_count, pthread + pinning,
               block_in_pool (per-call pthread escape hatch)
flare.testing  fork-and-serve helpers (`fork_server` /
               `kill_forked_server`) for cookbook examples and
               integration tests that need a real bound port
               in a child process; plus TestClient[H] -- a
               FastAPI-shaped in-process handler tester that
               drives Handler.serve directly without binding
               a port, for fast unit tests.
flare.utils    POSIX FFI thunks (`fork` / `waitpid` / `kill` /
               `usleep` / `exit` / `getpid` + SIGKILL / SIGTERM /
               SIGINT) the Mojo stdlib doesn't expose yet.
               Cross-cutting layer: pulled by tests, examples,
               and `flare.testing` so each call site stops
               re-declaring the same `external_call` thunks.
```

---

## Reactor + per-connection state machine

A single event loop per worker drives every connection. No
thread-per-connection. No locks on the hot path. The reactor wraps
`kqueue` on macOS and `epoll` on Linux through a thin abstraction
in [`flare/runtime/reactor.mojo`](../flare/runtime/reactor.mojo).

Each accepted connection owns a small state machine in
[`flare/http/_server_reactor_impl.mojo`](../flare/http/_server_reactor_impl.mojo):

```mermaid
stateDiagram-v2
    [*] --> READING : accept + register
    READING --> WRITING : handler returned
    WRITING --> READING : flushed + keep-alive
    WRITING --> CLOSING : flushed + close
    READING --> CLOSING : peer FIN / error / timeout
    WRITING --> CLOSING : peer FIN / error / timeout
    CLOSING --> [*] : unregister + close fd
```

The state machine **does not own** the reactor or the timer wheel. It
exposes `on_readable`, `on_writable`, and `on_timeout` and returns a
small `StepResult` per call telling the reactor how to update its
interest mask, whether to re-arm the idle timer, and whether the
connection is finished. The reactor owns the lifecycle.

A 3-cycle inline fast path in `run_reactor_loop` lets a single
readable event drive the next writable + the next readable in
sequence (without going back through `kqueue.kevent` / `epoll_wait`)
when the buffers permit. This is the single biggest win on the
plaintext keep-alive workload — the syscall overhead is the
dominant per-request cost on flare's hot path.

---

## Request lifecycle

```mermaid
sequenceDiagram
    participant client
    participant kernel as kqueue/epoll
    participant accept as _accept_loop
    participant conn as ConnHandle
    participant cancel as Cancel cell
    participant timers as TimerWheel
    participant handler as Handler.serve

    client->>kernel: SYN
    kernel->>accept: readable on listener fd
    accept->>conn: stream.peer_addr() captured
    accept->>conn: heap-allocate ConnHandle, set_nonblocking
    accept->>kernel: register fd, INTEREST_READ

    client->>kernel: bytes
    kernel->>conn: on_readable
    conn->>conn: parse headers + body
    conn->>cancel: install fresh cell
    conn->>timers: arm request_timeout_ms
    conn->>handler: serve(req, cancel)

    Note over kernel,conn: if peer FIN before response: cancel.flag = PEER_CLOSED
    Note over timers,cancel: if deadline fires:    cancel.flag = TIMEOUT
    Note over conn,cancel: if drain():            cancel.flag = SHUTDOWN

    handler->>conn: Response
    conn->>conn: serialize to write_buf
    conn->>kernel: send (non-blocking)
    kernel->>conn: on_writable for any remainder
    conn->>kernel: keep-alive: re-arm idle, INTEREST_READ
    conn->>kernel: close: unregister, close fd
```

Caveat: in the default `HttpServer.serve(handler)` shape the handler runs
synchronously between the parser and the response serializer, so the
notes above describe `CancelHandler` callers (and `block_in_pool` work)
where the flip is observable mid-flight. A plain `Handler` that runs
quickly will see the cell only between requests.

The Cancel cell is a heap-allocated machine word (`0` = live; `PEER_FIN /
TIMEOUT / SHUTDOWN` otherwise — see `CancelReason` in
[`flare/http/cancel.mojo`](../flare/http/cancel.mojo)). The reactor flips
it before the next `cancel.cancelled()` poll. We do not preempt — Mojo
can't, and synchronous preemption would defeat the per-thread invariant.
Cooperation is the contract.

---

## Multicore: thread-per-core, two listener modes

`HttpServer.serve(handler, num_workers=N)` with `N >= 2` runs N
pthread workers via `Scheduler`. Each worker owns its own reactor,
its own timer wheel, its own per-connection state.
**Shared-nothing.** Two listener strategies are supported:

- **Default — per-worker `SO_REUSEPORT` listeners.** The
  Scheduler pre-binds one `SO_REUSEPORT` listener per worker on
  its own thread (serialised binds avoid concurrent-bind races)
  and hands each worker its own fd. The kernel hashes new
  4-tuples to one of N listeners, matching `actix_web`'s
  default shape. Highest steady-state throughput on dev-box
  workloads -- this is what the published p99 / p99.99 numbers
  in [`docs/benchmark.md`](benchmark.md) measure. The io_uring
  buffer-ring path (`FLARE_BUFRING_HANDLER=1`) uses per-worker
  `SO_REUSEPORT` unconditionally because io_uring's multishot
  accept attaches to a single fd per ring.
- **Opt-out — shared listener with `EPOLLEXCLUSIVE`
  (`FLARE_REUSEPORT_WORKERS=0`).** One listener fd is bound
  via `bind_shared` and borrowed by every worker, registered
  with `Reactor.register_exclusive` so the kernel wakes one
  worker per accept event (Linux >= 4.5; macOS degrades to
  plain `register`). Idle workers absorb spikes; busy workers
  aren't burdened with extra accepts. Trades 7–22 % req/s
  (handler vs static fast path) for a uniformly tighter p99.99
  σ across both paths under sustained load — see
  [`docs/benchmark.md`](benchmark.md#listener-mode-ab-flare-only)
  for the head-to-head numbers.

`pin_cores=True` (default) pins worker `i` to core `i % num_cpus()`
on Linux via `pthread_setaffinity_np`. macOS does not expose CPU
affinity to userspace, so pinning is a no-op there. The upper
bound on `num_workers` is 256, enforced by `Scheduler.start`.

`Scheduler.shutdown` and `Scheduler.drain(timeout_ms)` coordinate
across workers. Drain returns one `ShutdownReport` per worker. SIGTERM
wiring is left to the caller.

---

## HTTP/2 + HTTP/3: one server, one client, version-aware

There is no separate `Http2Server` / `Http2Client` /
`Http3Server` to learn. `flare.http.HttpServer` and
`flare.http.HttpClient` are HTTP-version-aware internally:

- `HttpServer.serve(handler, num_workers=N)` runs a unified
  reactor loop ([`flare/http/_unified_reactor_impl.mojo`](../flare/http/_unified_reactor_impl.mojo))
  that auto-dispatches every accepted TCP connection to either
  the existing HTTP/1.1 `ConnHandle` or the new HTTP/2
  `H2ConnHandle` based on the first 24 bytes (RFC 9113 §3.4
  client connection preface). The same handler is invoked
  for both wires.
- `HttpServer.bind_with_h3(addr, quic_cfg)` adds a UDP
  listener alongside the TCP one and routes h3 to
  `flare.h3.H3Connection` after the rustls QUIC handshake
  selects ALPN `h3`. The same handler is invoked on h1, h2,
  and h3 simultaneously; see
  [`http3_server.mojo`](../examples/advanced/http3_server.mojo).
- `HttpClient` advertises ALPN `["h2", "http/1.1"]` on every
  TLS ClientHello and dispatches internally based on what
  the server selected; if the server picks `http/1.1` (or
  doesn't speak ALPN at all) the existing HTTP/1.1 wire is
  used. For cleartext `http://` URLs the default is HTTP/1.1;
  pass `prefer_h2c=True` to force HTTP/2 cleartext via prior
  knowledge.

Per-connection state machines:

```mermaid
flowchart LR
    Accept["accept() new connection"] --> Pending["PendingConnHandle (24-byte preface peek)"]
    Pending -->|"first byte != 'P'"| H1["ConnHandle (HTTP/1.1)"]
    Pending -->|"24 bytes == H2 preface"| H2["H2ConnHandle (HTTP/2)"]
    H1 --> Handler["handler.serve(req)"]
    H2 --> Handler
```

Both terminal handles run in the same reactor (`epoll` /
`kqueue`), share the same accept-fairness story
(`EPOLLEXCLUSIVE` shared listener vs per-worker `SO_REUSEPORT`
based on `FLARE_REUSEPORT_WORKERS`), and produce the same
`flare.http.Response` -- so the entire application surface
(`Router`, every middleware, every typed extractor,
`Cancel`, `Session[T]`, `FileServer`, content negotiation,
structured logging, Prometheus metrics, auth extractors,
`CsrfToken`, templates) works identically on both wires.

Low-level driver primitives stay public in `flare.http2` for
callers who want to roll their own dispatch loop:
`H2Connection`, `Http2ClientConnection`, `Http2Config`,
`Http2ClientConfig`, `HpackEncoder`, `HpackDecoder`, the frame
codec, and the helpers `is_h2_alpn` / `detect_h2c_upgrade`.

What *doesn't* port automatically (RFC 9113 §8.2.2):

- **Connection-level headers** (`Connection`, `Keep-Alive`,
  `Transfer-Encoding`, `Proxy-Connection`, `Upgrade`) -- the
  HttpClient h2 path strips these before encoding HEADERS;
  the H2Connection server-side does the same.
- **WebSocket-over-HTTP/2** (RFC 8441 Extended CONNECT) is
  wired through the same `WsClient.connect(url)` /
  `WsServer.serve(handler)` surface (negotiated automatically
  via ALPN); HTTP/1.1 Upgrade stays the fallback path. See
  [`flare/ws/`](../flare/ws/) for the bridge.

### API surface parity

End-state: the public client + server APIs are unified, so
there is no parity table any more -- one type, one shape:

| Surface | Type |
|---|---|
| HTTP server (HTTP/1.1 + HTTP/2 via auto-dispatch) | [`flare.http.HttpServer`](../flare/http/server.mojo) |
| HTTP server (HTTP/1.1 + HTTP/2 + HTTP/3 via ALPN; UDP listener mounted alongside TCP) | [`flare.http.HttpServer.bind_with_h3`](../flare/http/server.mojo) |
| HTTP client (HTTP/1.1 + HTTP/2 via TLS+ALPN or `prefer_h2c=True`) | [`flare.http.HttpClient`](../flare/http/client.mojo) |
| WebSocket server (HTTP/1.1 Upgrade; RFC 8441 over h2 wired on the byte driver) | [`flare.ws.WsServer`](../flare/ws/server.mojo) |
| WebSocket server (multi-worker via SO_REUSEPORT) | `flare.ws.WsServer.serve(handler, num_workers=N)` |
| WebSocket client (`ws://` / `wss://` — HTTP/1.1 Upgrade; ALPN advertises `http/1.1` on `wss://` to lock in the Upgrade path) | [`flare.ws.WsClient`](../flare/ws/client.mojo) |
| Low-level HTTP/2 byte driver (server) | [`flare.http2.H2Connection`](../flare/http2/server.mojo) |
| Low-level HTTP/2 byte driver (client) | [`flare.http2.Http2ClientConnection`](../flare/http2/client.mojo) |

---

## Timer wheel

[`flare/runtime/timer_wheel.mojo`](../flare/runtime/timer_wheel.mojo)
is a hashed timing wheel with millisecond resolution and a fixed
slot count. Inserts and cancels are O(1) amortised; `advance(now_ms)`
fires every expired entry in slot order. It's the single source of
truth for `idle_timeout_ms`, `write_timeout_ms`,
`read_body_timeout_ms`, `handler_timeout_ms`, and
`request_timeout_ms`.

Resolution: 1 ms tick, 512 slots, fixed memory; deadlines longer than
the wheel use an overflow list. Deadlines below 1 ms round up. This is
well below the noise floor of any HTTP deadline a real service cares
about.

---

## What stays out of the reactor

flare deliberately keeps a few things on the application thread, not
the reactor thread:

- **TLS handshake.** Client handshake is inline on
  `TlsStream.connect`. The server-side `TlsAcceptor` exposes a
  blocking `handshake_fd(fd)`; a non-blocking reactor-state-machine
  variant (advanced via the same `on_readable` / `on_writable` calls
  as HTTP) is gated on a Mojo improvement.
- **DNS resolution.** `getaddrinfo` is a blocking call; the
  client uses it pre-connect. The reactor never blocks on it.
- **Long-running handler work.** The contract is synchronous: a
  slow handler blocks its worker's reactor. The `Cancel` token
  ensures the *caller* doesn't pay for it (peer FIN, timeout,
  drain all flip the cell); the `block_in_pool` escape hatch is
  the documented way to push work off the reactor thread when a
  blocking call is unavoidable.

---

## Where to read the code

| Concern | Source |
|---|---|
| Reactor abstraction | [`flare/runtime/reactor.mojo`](../flare/runtime/reactor.mojo) |
| `kqueue` impl | [`flare/runtime/_kqueue.mojo`](../flare/runtime/_kqueue.mojo) |
| `epoll` impl | [`flare/runtime/_epoll.mojo`](../flare/runtime/_epoll.mojo) |
| Timer wheel | [`flare/runtime/timer_wheel.mojo`](../flare/runtime/timer_wheel.mojo) |
| Multicore scheduler | [`flare/runtime/scheduler.mojo`](../flare/runtime/scheduler.mojo) |
| HTTP request parsing | [`flare/http/server.mojo`](../flare/http/server.mojo) |
| HTTP per-conn state machine | [`flare/http/_server_reactor_impl.mojo`](../flare/http/_server_reactor_impl.mojo) |
| `Cancel` cell + `CancelHandler` | [`flare/http/cancel.mojo`](../flare/http/cancel.mojo) |
| Server-side TLS | [`flare/tls/acceptor.mojo`](../flare/tls/acceptor.mojo) |
| Streaming response bodies | [`flare/http/streaming_response.mojo`](../flare/http/streaming_response.mojo) |
| `block_in_pool` escape hatch | [`flare/runtime/blocking.mojo`](../flare/runtime/blocking.mojo) |

If you want a one-page tour of each, the layered docstrings on the
public types (`HttpServer`, `Router`, `Handler`, `App`) are the place
to start; they include "Failure modes" sections describing what
raises, what becomes a 4xx vs 5xx, what gets logged, and what never
returns.
