# HttpClient streaming over h2/h3

- Issue: https://github.com/ehsanmok/flare/issues/5
- Status: implemented, pending review

## Implementation outcome

This section records the final implementation; the remainder of this document
is the approved proposal and retains its original terminology.

- The public response type is `HttpStreamResponse`. It owns one exclusive
  connection and exposes final headers immediately, bounded `read_chunk`,
  `read_all_limited`, explicit cancellation via `close`, and trailers after EOS.
- `send_streaming(req)` supports arbitrary methods, headers, and a buffered
  request body. `send_chunked` keeps a streamed request body and buffered reply.
- Cleartext streaming supports HTTP/1.1, h2 prior knowledge, and h2c upgrade;
  TLS negotiates H2/H1, and eligible direct HTTPS origins can select H3.
- Trailers are surfaced. Automatic decompression is disabled for streamed
  responses unless the caller buffers and decodes explicitly.
- The implementation required protocol hardening omitted by the initial plan:
  deferred H2 stream credit, an H2 request-body cap, H2 response ordering checks,
  incremental H3 DATA parsing, per-stream H3 error isolation, and reliable QUIC
  retransmission of flow-control and cancellation frames.
- Full duplex, connection pooling, upload retries, and upload redirects remain
  outside this API.

## Problem

`HttpClient.get_streaming_tls()` pins ALPN to `http/1.1`, so a caller
who wants a bounded-memory streaming download over `https://` never
gets h2 or h3 even when the peer (and flare) supports them. Reported
by `bowyern` on issue #5 after flare's server-side streaming support
shipped:

> I was looking for streaming on the HttpClient side. It looks like
> there's get_streaming_tls() but it downgrades to 1.1

`send_chunked()` (streaming *upload*) has the same limitation,
documented explicitly: "ALPN forced to `http/1.1`; ... does not go
through ... h2, or h3".

`HttpClient.send()` already negotiates h2/h3 transparently (ALPN +
`Alt-Svc` cache + `prefer_http3`) for the *buffered* request/response
path. This spec extends that same negotiation to the two streaming
entry points.

## Scope

- Streaming **download** (`get_streaming` / `get_streaming_tls`) over
  h2 and h3, auto-negotiated the same way `send()` already picks a
  wire.
- Streaming **upload** (`send_chunked`) over h2 and h3, same
  negotiation. The reply stays a buffered `Response` (unchanged
  return type) -- only the *request* body streams.
- The two directions are independent: a streaming download still
  sends a normal buffered request; a streaming upload still reads a
  normal buffered response. Full duplex (stream both directions in
  one call) is explicitly out of scope.
- `send_chunked` keeps its documented "no connection pooling, no
  redirects, no retries" tradeoff on h2/h3 too, for consistency with
  the existing h1 behavior.
- Client-side trailers are not surfaced (matches today's h1 behavior,
  which already discards chunked trailers on read). `Http3Response`
  happens to carry `trailers`, but the streaming reader does not
  expose them -- no scope creep here unless requested later.

## Existing primitives this reuses (no new wire-protocol code)

- `flare/http/_client/alt_svc.mojo`'s `decide_http3_wire(scheme,
  prefer_http3, h3_cached_available, quic_supported)` -- the exact
  pure policy function `send()` already calls. Reused as-is.
- `Http2ClientConnection`'s "incremental streaming surface"
  (`send_request_open`, `send_data`, `headers_received`,
  `stream_ended`, `drain_body`, `response_headers`,
  `stream_error`, `discard_stream`) -- already built for
  `flare/grpc/streaming.mojo`'s `GrpcServerStream` /
  `GrpcBidiStream`. No h2-layer changes needed for the download side.
- `Http3ClientConnection`'s multiplexed reader surface (`request`,
  `poll_responses`, `head_ready`, `stream_status`, `stream_headers`,
  `poll_body`, `take_if_complete`) -- already built for the h3
  client. No h3-layer changes needed for the download side.
- `flare/grpc/streaming.mojo`'s `_H2Transport` -- the
  `Pool`-address-indirection pattern for erasing "TCP or TLS stream"
  behind one concrete type. The new `HttpStreamDownload` reuses this
  same pattern, widened to 4 backends.

## Download side: `HttpStreamDownload`

A new type-erased reader in `flare/http/_client/download.mojo` (or a
new sibling file if it grows large), holding one of four backends
behind `Pool`-address indirection, mirroring `_H2Transport`:

```
struct HttpStreamDownload(Movable):
    # exactly one of these addresses is non-zero
    var _h1_tcp_addr: Int   # Pool[HttpDownload[TcpStream]]
    var _h1_tls_addr: Int   # Pool[HttpDownload[TlsStream]]
    var _h2_addr: Int       # Pool[Http2Download]
    var _h3_addr: Int       # Pool[Http3Download]

    def status(self) -> Int: ...
    def reason(self) -> String: ...
    def headers(self) -> HeaderMap: ...
    def read_chunk(mut self, max_bytes: Int = 65536) raises -> List[UInt8]: ...
    def read_all(mut self, max_bytes: Int = 65536) raises -> List[UInt8]: ...
    def close(mut self): ...
```

New backend structs:

- `Http2Download` (new, `flare/http/_client/h2_download.mojo`): owns
  `Http2ClientConnection` + the TCP/TLS transport (via `_H2Transport`,
  exported from `flare.grpc.streaming` or duplicated locally -- decide
  in the plan whether to promote `_H2Transport` to a shared,
  non-gRPC-specific module) + `sid`. `read_chunk` mirrors
  `GrpcServerStream.recv`'s pump loop (`drain_body` /
  `stream_ended` / `stream_error` / socket read / `feed` / `drain`),
  but returns raw bytes instead of decoded LPM messages.
- `Http3Download` (new, `flare/http/_client/h3_download.mojo`): owns
  `Http3ClientConnection` + `sid`. `read_chunk` loops `poll_body(sid)`
  until it returns non-empty data or `done`.

`get_streaming_tls(url)`:

1. Resolve the URL, run `decide_http3_wire(...)`.
2. If `HTTP_3`: dial QUIC (reuse `_dial_http3`), send the request via
   `Http3ClientConnection.send_request` (existing one-shot, since a
   GET has no body), wrap the resulting `sid` + connection in
   `Http3Download`, return it wrapped in `HttpStreamDownload`. On any
   QUIC dial/handshake failure, fall through to the h2-or-lower path
   (same fallback `send()` already does).
3. Else: attempt TLS+ALPN `["h2", "http/1.1"]`. If the peer selected
   `h2`: send the request via `Http2ClientConnection.send_request`,
   wrap in `Http2Download`. If `http/1.1`: fall through to today's
   `HttpDownload[TlsStream]` path unchanged.
4. Wrap whichever concrete reader results in `HttpStreamDownload`.

`get_streaming(url)` (cleartext `http://`) is unchanged -- h1 only,
since h2c-without-prior-knowledge and h3 both need signaling this
entry point has no path to (no TLS ALPN, no Alt-Svc yet for this
origin on a first cleartext call). Note this in the docstring.

## Upload side: `send_chunked` over h2/h3

Same negotiation as above, then:

- **h2**: `Http2ClientConnection.send_request_open(sid, ...)`
  (existing) to open the stream without `END_STREAM`, then loop
  `source.next(cancel)` -> `send_data(sid, chunk, fin=False)` ->
  `drain()` -> `write_all()`; final iteration (source returns `None`)
  sends an empty `send_data(sid, [], fin=True)`. Then reuse the
  existing `_send_h2_over_tls`-style read pump
  (`response_ready`/`feed`/`drain`/`take_response`) to get the
  buffered reply.
- **h3**: needs one new thin method on `Http3ClientConnection`,
  `send_request_open`, mirroring the h2 one: open a bidi stream, write
  HEADERS via `encode_request_headers` with `fin=False`, register a
  `_PendingRequest` entry (same bookkeeping `request()` does) so
  `poll_responses()`/`take_if_complete()` work afterward. Then loop
  `source.next(cancel)` -> `encode_request_data(chunk, wire)` ->
  `send_stream(sid, wire, fin=False)`; final iteration sends an empty
  `send_stream(sid, [], fin=True)`. Then reuse the existing
  `fetch()`-style poll loop to get the buffered `Http3Response`.
- **h1**: unchanged.

`send_chunked`'s signature and return type (`Response`) do not
change.

## Fallback / error semantics

- Wire selection failures (QUIC dial fails, ALPN doesn't offer h2)
  fall back exactly like `send()` does today -- silent, transparent,
  no exception.
- Failures *mid-transfer* (peer `RST_STREAM`, GOAWAY, connection
  drop) raise `NetworkError`, matching today's `HttpDownload` /
  `GrpcServerStream` behavior. No automatic retry -- a
  partially-consumed download or a partially-sent upload cannot be
  safely replayed without caller-level buffering, which defeats the
  point of streaming.

## Public API impact

- `get_streaming` / `get_streaming_tls`: same names, same call
  signature. Return type changes from `HttpDownload[TcpStream]` /
  `HttpDownload[TlsStream]` to `HttpStreamDownload`. Source-compatible
  for callers using the documented surface (`status`, `reason`,
  `headers`, `read_chunk`, `read_all`, `header(name)`).
- `send_chunked`: no signature or return-type change.
- `docs/features.md`: update the `get_streaming_tls` row to drop "h2
  / h3 streaming downloads ... are still a follow-up"; update the
  `send_chunked` row similarly.
- `docs/cookbook.md`: update the streaming-download row.

## Testing plan

Mirrors existing test file conventions:

- `tests/http/test_client_stream_download_h2.mojo` -- loopback h2
  TLS server (self-signed cert, same fixture the existing TLS tests
  use), assert bytes arrive intact + bounded per-pull.
- `tests/http/test_client_stream_download_h3.mojo` -- loopback QUIC
  server, forked process (same pattern as `test_h3_live_dial.mojo`).
- `tests/http/test_client_stream_upload_h2.mojo` /
  `test_client_stream_upload_h3.mojo` -- mirror
  `test_client_stream_upload.mojo`, assert the server saw the full
  body and the client never buffered more than one chunk.
- A fallback test: an h1-only TLS server (ALPN negotiates
  `http/1.1`) still round-trips correctly through both
  `get_streaming_tls` and `send_chunked` (negotiation degrades
  cleanly, no behavior change for the common case).
- Existing `test_client_stream_download_tls.mojo` /
  `test_client_stream_upload.mojo` continue to pass unmodified,
  confirming the h1 path is untouched.

## Open implementation decisions for the plan phase

- Whether to promote `_H2Transport` out of `flare/grpc/streaming.mojo`
  into a shared, protocol-neutral location (e.g.
  `flare/http/_client/h2_transport.mojo`) so both the gRPC streaming
  client and the new `Http2Download` reuse one definition, vs.
  duplicating a small struct. Leaning toward promoting it (DRY, small
  struct, no gRPC-specific fields) but the plan should confirm no
  import-cycle issue between `flare.grpc` and `flare.http._client`.
- Exact file layout for the two new backend structs (new files vs.
  folding into `flare/http/_client/download.mojo`) -- guided by
  keeping files under the existing size conventions
  (`tools/check_reactor_size.sh`).
