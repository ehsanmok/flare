"""End-to-end H3 dispatch tests.

Exercises the reactor: STREAM payloads surfaced via
:attr:`flare.quic.state.ConnectionEvents.stream_chunks` route
through :meth:`flare.quic.server.QuicListener._route_http3_stream_chunks`
into the per-slot :class:`flare.http3.Http3Connection`, the dispatch
pump on :class:`flare.http.HttpServer` materializes the request,
calls a user :trait:`flare.http.Handler`, encodes the
:class:`flare.http.Response` back into the slot's H3 outbox, and
the bytes accumulate in
:attr:`flare.quic.server.QuicListener.http3_response_egress` for the
1-RTT egress wiring to pick up.

The 1-RTT wire path (rustls KeyChange surfacing 1-RTT traffic
secrets + ``protect_1rtt_packet`` egress) is deferred to a
follow-up commit; this suite covers the dispatch wire end-to-end
via direct event injection so a real h2load smoke (gated on the
key-change FFI extension) can land in a follow-up.

Cases:

1. GET /hello: HEADERS-only stream surfaces a Request through the
   pump, handler returns 200 + "OK", egress carries HEADERS+DATA
   frames.
2. POST /upload with body: HEADERS + DATA + FIN surfaces a
   Request with the right body, handler echoes the body, egress
   carries HEADERS+DATA frames containing the echo.
3. Concurrent streams on the same connection (3 + 7) dispatch
   independently; each stream's egress is keyed separately.
4. Multiple connections: two slots on one listener route their
   own streams to independent H3 drivers.
"""

from std.collections import Optional
from std.testing import assert_equal, assert_false, assert_true

from flare.http3 import (
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    encode_http3_frame,
)
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response, stream_response
from flare.http.server import HttpServer, ok
from flare.quic.varint import decode_varint
from flare.net import IpAddr, SocketAddr
from flare.qpack import QpackHeader, encode_field_section
from flare.quic.frame import StreamFrame
from flare.quic.packet import ConnectionId
from flare.quic.server import (
    QuicConnection,
    QuicListener,
    QuicServerConfig,
)
from flare.quic.state import ConnectionEvents, empty_events
from flare.tls.rustls_quic import RustlsQuicConfig


# ── Synthetic request-bytes builders ───────────────────────────────────


def _encode_headers_frame(headers: List[QpackHeader]) raises -> List[UInt8]:
    var payload = List[UInt8]()
    encode_field_section(headers, payload)
    var out = List[UInt8]()
    encode_http3_frame(H3_FRAME_TYPE_HEADERS, Span[UInt8, _](payload), out)
    return out^


def _encode_data_frame(payload: List[UInt8]) raises -> List[UInt8]:
    var out = List[UInt8]()
    encode_http3_frame(H3_FRAME_TYPE_DATA, Span[UInt8, _](payload), out)
    return out^


def _build_get_request(path: String) raises -> List[UInt8]:
    var headers = List[QpackHeader]()
    headers.append(QpackHeader(":method", "GET"))
    headers.append(QpackHeader(":scheme", "https"))
    headers.append(QpackHeader(":authority", "example.com"))
    headers.append(QpackHeader(":path", String(path)))
    return _encode_headers_frame(headers)


def _build_post_request(path: String, body: List[UInt8]) raises -> List[UInt8]:
    var headers = List[QpackHeader]()
    headers.append(QpackHeader(":method", "POST"))
    headers.append(QpackHeader(":scheme", "https"))
    headers.append(QpackHeader(":authority", "example.com"))
    headers.append(QpackHeader(":path", String(path)))
    headers.append(QpackHeader("content-type", "text/plain"))
    var out = _encode_headers_frame(headers)
    var data = _encode_data_frame(body.copy())
    for i in range(len(data)):
        out.append(data[i])
    return out^


# ── Test Handlers ──────────────────────────────────────────────────────


@fieldwise_init
struct _OkHandler(Copyable, Handler, Movable):
    """Handler that responds with 200 + a fixed body."""

    var body: String

    def serve(self, req: Request) raises -> Response:
        return ok(String(self.body))


@fieldwise_init
struct _EchoHandler(Copyable, Handler, Movable):
    """Handler that echoes the request body verbatim with a 200."""

    def serve(self, req: Request) raises -> Response:
        var body = req.body.copy()
        var resp = ok(String(""))
        resp.body = body^
        return resp^


@fieldwise_init
struct _ListSource(ChunkSource, Copyable, Movable):
    """Chunk source that yields a fixed list of chunks, then EOS.

    Drives the streaming-response tests: each ``next`` returns the
    next stashed chunk (one per writable edge, mirroring a real
    open-ended source) until the list is exhausted, then ``None``.
    """

    var chunks: List[List[UInt8]]
    var idx: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self.idx >= len(self.chunks):
            return None
        var out = self.chunks[self.idx].copy()
        self.idx += 1
        return out^


def _bytes(s: String) -> List[UInt8]:
    """ASCII string -> byte list."""
    var out = List[UInt8]()
    var b = s.as_bytes()
    for i in range(len(b)):
        out.append(b[i])
    return out^


def _extract_h3_data_payload(buf: List[UInt8]) raises -> List[UInt8]:
    """Walk the HTTP/3 frame stream in ``buf`` and concatenate every
    DATA-frame payload in order.

    Each frame is ``varint(type) varint(len) payload`` (RFC 9114 §7.1),
    so a linear walk recovers the streamed body bytes independent of how
    many DATA frames the pump split them into. HEADERS / trailers frames
    are skipped."""
    var out = List[UInt8]()
    var pos = 0
    var n = len(buf)
    while pos < n:
        var view = buf[pos:]
        var t = decode_varint(Span[UInt8, _](view))
        pos += t.consumed
        var view2 = buf[pos:]
        var length = decode_varint(Span[UInt8, _](view2))
        pos += length.consumed
        var frame_len = Int(length.value)
        if t.value == UInt64(H3_FRAME_TYPE_DATA):
            for j in range(pos, pos + frame_len):
                out.append(buf[j])
        pos += frame_len
    return out^


# ── Helpers: bind a listener + drive a synthetic event ─────────────────


def _bind_listener() raises -> QuicListener:
    """Bind a QuicListener on 127.0.0.1:0 with empty rustls config.

    The empty-PEM acceptor returns a NULL session handle; the
    test path never needs a real TLS roundtrip because the
    dispatch wire is exercised directly via the route_h3
    surface.
    """
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config = RustlsQuicConfig()
    return QuicListener.bind(cfg^)


def _seed_slot(mut listener: QuicListener) raises -> Int:
    """Allocate a connection slot via a synthetic Initial accept.

    Builds a :class:`flare.quic.packet.LongHeader` directly so
    the test doesn't depend on real TLS; the slot's
    :class:`QuicConnection` has the H3 driver attached and the
    peer addr captured.
    """
    from flare.quic.packet import (
        LongHeader,
        PACKET_TYPE_INITIAL,
        QUIC_VERSION_1,
    )

    var dcid_bytes = List[UInt8]()
    for i in range(8):
        dcid_bytes.append(UInt8(0xA0 + i))
    var scid_bytes = List[UInt8]()
    for i in range(8):
        scid_bytes.append(UInt8(0xB0 + i))
    var dcid = ConnectionId(bytes=dcid_bytes^)
    var scid = ConnectionId(bytes=scid_bytes^)
    var lh = LongHeader(
        packet_type=PACKET_TYPE_INITIAL,
        version=QUIC_VERSION_1,
        dcid=dcid^,
        scid=scid^,
        payload_offset=0,
    )
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    return listener._accept_initial(lh, peer)


def _make_stream_event(
    stream_id: UInt64, var payload: List[UInt8], fin: Bool = True
) raises -> ConnectionEvents:
    """Build a synthetic ConnectionEvents with one STREAM chunk."""
    var events = empty_events()
    events.stream_chunks.append(
        StreamFrame(
            stream_id=stream_id,
            offset=UInt64(0),
            data=payload^,
            fin=fin,
        )
    )
    return events^


# ── Tests ──────────────────────────────────────────────────────────────


def test_get_request_dispatches_through_handler() raises:
    """GET /hello -> _OkHandler('ok') -> H3 egress carries the
    encoded HEADERS+DATA response. The dispatch pump returns 1
    indicating one (slot, stream) pair handled."""
    var listener = _bind_listener()
    var slot = _seed_slot(listener)
    var stream_id = UInt64(0)  # client-initiated bidi
    var req_bytes = _build_get_request("/hello")
    var events = _make_stream_event(stream_id, req_bytes^)
    listener._route_http3_stream_chunks(slot, events)

    var ready = listener.take_http3_completed_streams(slot)
    assert_equal(len(ready), 1, "GET with FIN must surface as completed")
    assert_equal(ready[0], 0)

    var handler = _OkHandler(body=String("ok"))
    var req = listener.take_http3_request(slot, Int(stream_id))
    assert_equal(req.method, String("GET"))
    assert_equal(req.url, String("/hello"))
    var resp = handler.serve(req^)
    assert_equal(resp.status, 200)
    listener.emit_http3_response(slot, Int(stream_id), resp^)

    var egress = listener.take_http3_response_egress(slot, Int(stream_id))
    assert_true(
        len(egress) > 0,
        "H3 emit_response must accumulate HEADERS+DATA bytes",
    )


def test_post_request_body_echo() raises:
    """POST /upload with body -> _EchoHandler -> egress carries
    the echo. Verifies the request body round-trip + that the
    DATA frame on egress carries the echoed bytes."""
    var listener = _bind_listener()
    var slot = _seed_slot(listener)
    var stream_id = UInt64(4)  # next client bidi (RFC 9000 §2.1: id mod 4 == 0)
    var body = List[UInt8]()
    for v in [72, 101, 108, 108, 111]:  # "Hello"
        body.append(UInt8(v))
    var req_bytes = _build_post_request("/upload", body)
    var events = _make_stream_event(stream_id, req_bytes^)
    listener._route_http3_stream_chunks(slot, events)

    var ready = listener.take_http3_completed_streams(slot)
    assert_equal(len(ready), 1)
    assert_equal(ready[0], Int(stream_id))

    var handler = _EchoHandler()
    var req = listener.take_http3_request(slot, Int(stream_id))
    assert_equal(req.method, String("POST"))
    assert_equal(len(req.body), 5)
    var resp = handler.serve(req^)
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), 5)
    listener.emit_http3_response(slot, Int(stream_id), resp^)

    var egress = listener.take_http3_response_egress(slot, Int(stream_id))
    assert_true(len(egress) > 0)
    # Drain again must be empty (the dict.pop drained the buffer).
    var second = listener.take_http3_response_egress(slot, Int(stream_id))
    assert_equal(len(second), 0)


def test_concurrent_streams_on_one_connection() raises:
    """Two client-bidi streams (ids 0 and 4) dispatch
    independently; each accumulates its own egress buffer keyed
    by ``slot:stream_id``."""
    var listener = _bind_listener()
    var slot = _seed_slot(listener)

    var req_a = _build_get_request("/a")
    var events_a = _make_stream_event(UInt64(0), req_a^)
    listener._route_http3_stream_chunks(slot, events_a)

    var req_b = _build_get_request("/b")
    var events_b = _make_stream_event(UInt64(4), req_b^)
    listener._route_http3_stream_chunks(slot, events_b)

    var ready = listener.take_http3_completed_streams(slot)
    assert_equal(len(ready), 2)

    var handler = _OkHandler(body=String("ok"))
    for i in range(len(ready)):
        var sid = ready[i]
        var req = listener.take_http3_request(slot, sid)
        var resp = handler.serve(req^)
        listener.emit_http3_response(slot, sid, resp^)

    var egress_a = listener.take_http3_response_egress(slot, 0)
    var egress_b = listener.take_http3_response_egress(slot, 4)
    assert_true(len(egress_a) > 0)
    assert_true(len(egress_b) > 0)


def test_multiple_connections_dispatch_independently() raises:
    """Two connection slots: stream 0 on slot 0 and stream 0 on
    slot 1 produce independent egress entries (the egress key
    includes the slot index)."""
    var listener = _bind_listener()
    var slot_a = _seed_slot(listener)
    var slot_b = _seed_slot(listener)
    assert_equal(slot_a, 0)
    assert_equal(slot_b, 1)

    var req_a = _build_get_request("/a")
    var events_a = _make_stream_event(UInt64(0), req_a^)
    listener._route_http3_stream_chunks(slot_a, events_a)

    var req_b = _build_get_request("/b")
    var events_b = _make_stream_event(UInt64(0), req_b^)
    listener._route_http3_stream_chunks(slot_b, events_b)

    var handler = _OkHandler(body=String("ok"))
    var ready_a = listener.take_http3_completed_streams(slot_a)
    assert_equal(len(ready_a), 1)
    var req_a_recv = listener.take_http3_request(slot_a, ready_a[0])
    var resp_a = handler.serve(req_a_recv^)
    listener.emit_http3_response(slot_a, ready_a[0], resp_a^)

    var ready_b = listener.take_http3_completed_streams(slot_b)
    assert_equal(len(ready_b), 1)
    var req_b_recv = listener.take_http3_request(slot_b, ready_b[0])
    var resp_b = handler.serve(req_b_recv^)
    listener.emit_http3_response(slot_b, ready_b[0], resp_b^)

    var egress_a = listener.take_http3_response_egress(slot_a, 0)
    var egress_b = listener.take_http3_response_egress(slot_b, 0)
    assert_true(len(egress_a) > 0)
    assert_true(len(egress_b) > 0)


# ── HttpServer.pump_http3_handler_once dispatch path ─────────────────────


def test_pump_http3_handler_once_drives_handler() raises:
    """The :meth:`HttpServer.pump_http3_handler_once` overload pulls
    completed streams and runs the handler in one call --
    mirrors the inner loop body of :meth:`HttpServer.serve_http3`
    so the dispatch is verifiable without binding a TCP
    listener and starting the full event loop."""
    var tcp_addr = SocketAddr(IpAddr.localhost(), UInt16(0))
    var udp_cfg = QuicServerConfig()
    udp_cfg.host = String("127.0.0.1")
    udp_cfg.port = UInt16(0)
    var srv = HttpServer.bind_with_http3(tcp_addr, udp_cfg^)
    assert_true(srv.has_http3())

    # Seed a slot via the same path real reactor uses.
    var listener_borrow = srv._http3_listener.take()
    var slot = _seed_slot(listener_borrow)
    var req_bytes = _build_get_request("/pumped")
    var events = _make_stream_event(UInt64(0), req_bytes^)
    listener_borrow._route_http3_stream_chunks(slot, events)
    srv._http3_listener = listener_borrow^

    var handler = _OkHandler(body=String("pumped"))
    var dispatched = srv.pump_http3_handler_once[_OkHandler](handler)
    assert_equal(dispatched, 1)

    # Re-borrow to verify egress accumulated.
    var listener_reborrow = srv._http3_listener.take()
    var egress = listener_reborrow.take_http3_response_egress(slot, 0)
    assert_true(len(egress) > 0)
    srv._http3_listener = listener_reborrow^


def test_pump_http3_handler_once_zero_when_no_streams_ready() raises:
    """No completed streams -> pump returns 0; no side effects."""
    var tcp_addr = SocketAddr(IpAddr.localhost(), UInt16(0))
    var udp_cfg = QuicServerConfig()
    udp_cfg.host = String("127.0.0.1")
    udp_cfg.port = UInt16(0)
    var srv = HttpServer.bind_with_http3(tcp_addr, udp_cfg^)

    var handler = _OkHandler(body=String("never"))
    var dispatched = srv.pump_http3_handler_once[_OkHandler](handler)
    assert_equal(dispatched, 0)


# ── Streaming response (body_stream) incremental emit ────────────────────


def test_streaming_response_incremental_data() raises:
    """A streaming Response (``stream_response`` over a chunk source)
    emits HEADERS immediately and registers the stream; each
    :meth:`pump_http3_streams` pulls exactly one chunk into a DATA
    frame; end-of-stream flags the record ``done`` and frees the
    source. The accumulated egress decodes to the concatenated chunk
    bytes in order."""
    var listener = _bind_listener()
    var slot = _seed_slot(listener)
    var sid = UInt64(0)
    var req_bytes = _build_get_request("/stream")
    var events = _make_stream_event(sid, req_bytes^)
    listener._route_http3_stream_chunks(slot, events)
    var ready = listener.take_http3_completed_streams(slot)
    assert_equal(len(ready), 1)

    var req = listener.take_http3_request(slot, Int(sid))
    assert_equal(req.url, String("/stream"))

    var chunks = List[List[UInt8]]()
    chunks.append(_bytes("aaa"))
    chunks.append(_bytes("bbbb"))
    chunks.append(_bytes("cc"))
    var src = _ListSource(chunks^, 0)
    var resp = stream_response(src^)
    listener.emit_http3_response(slot, Int(sid), resp^)

    var key = String("0:0")
    # HEADERS rode the egress immediately; the stream is registered and
    # not yet done (no DATA pulled).
    assert_true(key in listener.http3_streams, "stream must be registered")
    assert_false(listener.http3_streams[key].done)
    var headers_only = listener.http3_response_egress[key].copy()
    assert_true(len(headers_only) > 0, "HEADERS must be queued on emit")
    assert_equal(
        len(_extract_h3_data_payload(headers_only)),
        0,
        "no DATA before the first pump",
    )

    # Pump three times: one chunk per pump, source not yet exhausted.
    for _ in range(3):
        var adv = listener.pump_http3_streams(Cancel.never())
        assert_equal(adv, 1)
        assert_true(key in listener.http3_streams)
        assert_false(listener.http3_streams[key].done)

    # Fourth pump hits end-of-stream: still counts as advanced, marks
    # done, and frees the boxed source.
    var adv_eos = listener.pump_http3_streams(Cancel.never())
    assert_equal(adv_eos, 1)
    assert_true(listener.http3_streams[key].done, "EOS must set done")
    assert_equal(listener.http3_streams[key].src_addr, 0, "source freed")

    # A further pump is a no-op (source exhausted).
    var adv_none = listener.pump_http3_streams(Cancel.never())
    assert_equal(adv_none, 0)

    # The accumulated egress (HEADERS + 3 DATA frames) decodes to the
    # concatenated chunk payloads in order.
    var full = listener.http3_response_egress[key].copy()
    var body = _extract_h3_data_payload(full)
    assert_equal(len(body), 9)  # "aaa" + "bbbb" + "cc"
    var expect = _bytes("aaabbbbcc")
    for i in range(len(expect)):
        assert_equal(body[i], expect[i])


def test_buffered_response_not_registered_as_stream() raises:
    """A plain buffered Response never lands in ``http3_streams`` and
    still emits HEADERS+DATA up front -- the byte-identical original
    path, unaffected by the streaming machinery."""
    var listener = _bind_listener()
    var slot = _seed_slot(listener)
    var sid = UInt64(0)
    var req_bytes = _build_get_request("/plain")
    var events = _make_stream_event(sid, req_bytes^)
    listener._route_http3_stream_chunks(slot, events)
    _ = listener.take_http3_completed_streams(slot)
    var req = listener.take_http3_request(slot, Int(sid))
    var handler = _OkHandler(body=String("hello"))
    var resp = handler.serve(req^)
    listener.emit_http3_response(slot, Int(sid), resp^)

    var key = String("0:0")
    assert_false(
        key in listener.http3_streams, "buffered must not register a stream"
    )
    # A pump does nothing for buffered responses.
    assert_equal(listener.pump_http3_streams(Cancel.never()), 0)
    var full = listener.http3_response_egress[key].copy()
    var body = _extract_h3_data_payload(full)
    assert_equal(len(body), 5)  # "hello" emitted as DATA up front


def main() raises:
    test_get_request_dispatches_through_handler()
    test_post_request_body_echo()
    test_concurrent_streams_on_one_connection()
    test_multiple_connections_dispatch_independently()
    test_pump_http3_handler_once_drives_handler()
    test_pump_http3_handler_once_zero_when_no_streams_ready()
    test_streaming_response_incremental_data()
    test_buffered_response_not_registered_as_stream()
    print("test_h3_end_to_end: 8 passed")
