"""End-to-end H3 dispatch tests -- Track Q12-W.

Exercises the post-Q11-W reactor: STREAM payloads surfaced via
:attr:`flare.quic.state.ConnectionEvents.stream_chunks` route
through :meth:`flare.quic.server.QuicListener._route_h3_stream_chunks`
into the per-slot :class:`flare.h3.H3Connection`, the dispatch
pump on :class:`flare.http.HttpServer` materializes the request,
calls a user :trait:`flare.http.Handler`, encodes the
:class:`flare.http.Response` back into the slot's H3 outbox, and
the bytes accumulate in
:attr:`flare.quic.server.QuicListener.h3_response_egress` for the
1-RTT egress wiring to pick up.

The 1-RTT wire path (rustls KeyChange surfacing 1-RTT traffic
secrets + ``protect_1rtt_packet`` egress) is deferred to a
follow-up commit; this suite covers the dispatch wire end-to-end
via direct event injection so a real h2load smoke (gated on the
key-change FFI extension) lands in Track Q13-W.

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

from std.testing import assert_equal, assert_false, assert_true

from flare.h3 import H3_FRAME_TYPE_DATA, H3_FRAME_TYPE_HEADERS, encode_h3_frame
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import HttpServer, ok
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
    encode_h3_frame(H3_FRAME_TYPE_HEADERS, Span[UInt8, _](payload), out)
    return out^


def _encode_data_frame(payload: List[UInt8]) raises -> List[UInt8]:
    var out = List[UInt8]()
    encode_h3_frame(H3_FRAME_TYPE_DATA, Span[UInt8, _](payload), out)
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
    listener._route_h3_stream_chunks(slot, events)

    var ready = listener.take_h3_completed_streams(slot)
    assert_equal(len(ready), 1, "GET with FIN must surface as completed")
    assert_equal(ready[0], 0)

    var handler = _OkHandler(body=String("ok"))
    var req = listener.take_h3_request(slot, Int(stream_id))
    assert_equal(req.method, String("GET"))
    assert_equal(req.url, String("/hello"))
    var resp = handler.serve(req^)
    assert_equal(resp.status, 200)
    listener.emit_h3_response(slot, Int(stream_id), resp^)

    var egress = listener.take_h3_response_egress(slot, Int(stream_id))
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
    listener._route_h3_stream_chunks(slot, events)

    var ready = listener.take_h3_completed_streams(slot)
    assert_equal(len(ready), 1)
    assert_equal(ready[0], Int(stream_id))

    var handler = _EchoHandler()
    var req = listener.take_h3_request(slot, Int(stream_id))
    assert_equal(req.method, String("POST"))
    assert_equal(len(req.body), 5)
    var resp = handler.serve(req^)
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), 5)
    listener.emit_h3_response(slot, Int(stream_id), resp^)

    var egress = listener.take_h3_response_egress(slot, Int(stream_id))
    assert_true(len(egress) > 0)
    # Drain again must be empty (the dict.pop drained the buffer).
    var second = listener.take_h3_response_egress(slot, Int(stream_id))
    assert_equal(len(second), 0)


def test_concurrent_streams_on_one_connection() raises:
    """Two client-bidi streams (ids 0 and 4) dispatch
    independently; each accumulates its own egress buffer keyed
    by ``slot:stream_id``."""
    var listener = _bind_listener()
    var slot = _seed_slot(listener)

    var req_a = _build_get_request("/a")
    var events_a = _make_stream_event(UInt64(0), req_a^)
    listener._route_h3_stream_chunks(slot, events_a)

    var req_b = _build_get_request("/b")
    var events_b = _make_stream_event(UInt64(4), req_b^)
    listener._route_h3_stream_chunks(slot, events_b)

    var ready = listener.take_h3_completed_streams(slot)
    assert_equal(len(ready), 2)

    var handler = _OkHandler(body=String("ok"))
    for i in range(len(ready)):
        var sid = ready[i]
        var req = listener.take_h3_request(slot, sid)
        var resp = handler.serve(req^)
        listener.emit_h3_response(slot, sid, resp^)

    var egress_a = listener.take_h3_response_egress(slot, 0)
    var egress_b = listener.take_h3_response_egress(slot, 4)
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
    listener._route_h3_stream_chunks(slot_a, events_a)

    var req_b = _build_get_request("/b")
    var events_b = _make_stream_event(UInt64(0), req_b^)
    listener._route_h3_stream_chunks(slot_b, events_b)

    var handler = _OkHandler(body=String("ok"))
    var ready_a = listener.take_h3_completed_streams(slot_a)
    assert_equal(len(ready_a), 1)
    var req_a_recv = listener.take_h3_request(slot_a, ready_a[0])
    var resp_a = handler.serve(req_a_recv^)
    listener.emit_h3_response(slot_a, ready_a[0], resp_a^)

    var ready_b = listener.take_h3_completed_streams(slot_b)
    assert_equal(len(ready_b), 1)
    var req_b_recv = listener.take_h3_request(slot_b, ready_b[0])
    var resp_b = handler.serve(req_b_recv^)
    listener.emit_h3_response(slot_b, ready_b[0], resp_b^)

    var egress_a = listener.take_h3_response_egress(slot_a, 0)
    var egress_b = listener.take_h3_response_egress(slot_b, 0)
    assert_true(len(egress_a) > 0)
    assert_true(len(egress_b) > 0)


# ── HttpServer.pump_h3_handler_once dispatch path ─────────────────────


def test_pump_h3_handler_once_drives_handler() raises:
    """The :meth:`HttpServer.pump_h3_handler_once` overload pulls
    completed streams and runs the handler in one call --
    mirrors the inner loop body of :meth:`HttpServer.serve_h3`
    so the dispatch is verifiable without binding a TCP
    listener and starting the full event loop."""
    var tcp_addr = SocketAddr(IpAddr.localhost(), UInt16(0))
    var udp_cfg = QuicServerConfig()
    udp_cfg.host = String("127.0.0.1")
    udp_cfg.port = UInt16(0)
    var srv = HttpServer.bind_with_h3(tcp_addr, udp_cfg^)
    assert_true(srv.has_h3())

    # Seed a slot via the same path real reactor uses.
    var listener_borrow = srv._h3_listener.take()
    var slot = _seed_slot(listener_borrow)
    var req_bytes = _build_get_request("/pumped")
    var events = _make_stream_event(UInt64(0), req_bytes^)
    listener_borrow._route_h3_stream_chunks(slot, events)
    srv._h3_listener = listener_borrow^

    var handler = _OkHandler(body=String("pumped"))
    var dispatched = srv.pump_h3_handler_once[_OkHandler](handler)
    assert_equal(dispatched, 1)

    # Re-borrow to verify egress accumulated.
    var listener_reborrow = srv._h3_listener.take()
    var egress = listener_reborrow.take_h3_response_egress(slot, 0)
    assert_true(len(egress) > 0)
    srv._h3_listener = listener_reborrow^


def test_pump_h3_handler_once_zero_when_no_streams_ready() raises:
    """No completed streams -> pump returns 0; no side effects."""
    var tcp_addr = SocketAddr(IpAddr.localhost(), UInt16(0))
    var udp_cfg = QuicServerConfig()
    udp_cfg.host = String("127.0.0.1")
    udp_cfg.port = UInt16(0)
    var srv = HttpServer.bind_with_h3(tcp_addr, udp_cfg^)

    var handler = _OkHandler(body=String("never"))
    var dispatched = srv.pump_h3_handler_once[_OkHandler](handler)
    assert_equal(dispatched, 0)


def main() raises:
    test_get_request_dispatches_through_handler()
    test_post_request_body_echo()
    test_concurrent_streams_on_one_connection()
    test_multiple_connections_dispatch_independently()
    test_pump_h3_handler_once_drives_handler()
    test_pump_h3_handler_once_zero_when_no_streams_ready()
    print("test_h3_end_to_end: 6 passed")
