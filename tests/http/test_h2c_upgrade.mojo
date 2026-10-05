"""HTTP/2 over HTTP/1.1 Upgrade ("h2c", RFC 7540 paragraph 3.2).

Covers the unit-level wiring added in v0.7 for h2c-via-Upgrade:

* :meth:`flare.http2.server.Http2Connection.from_h2c_upgrade` — server-side
  state seeded from an h1 request becoming stream id 1 plus the
  decoded ``HTTP2-Settings`` payload from the upgrade request.
* :meth:`flare.http._server_reactor_impl.ConnHandle._h2c_upgrade_decode_settings`
  — base64url + length-multiple-of-6 validation of the inbound
  ``HTTP2-Settings`` header value.

The full reactor-level integration (h1 ConnHandle queues the
``101 Switching Protocols`` response, the unified reactor migrates
the conn-dict entry from ``KIND_H1`` to ``KIND_H2`` once the 101
flushes, the client sends its connection preface + SETTINGS frame
on the same TCP fd, the response for stream 1 is dispatched via the
user handler and serialised back as h2 frames) is exercised by
``tests/test_unified_http_server.mojo`` when an h2c client hits the
unified port -- this file deliberately scopes to the deterministic
unit-level paths that a fork-based loopback test would obscure.
"""

from std.collections import Dict
from std.ffi import c_int
from std.testing import assert_equal, assert_false, assert_true

from flare.crypto.hmac import base64url_encode
from flare.http import Request, Response, ServerConfig
from flare.http.handler import FnHandler
from flare.http.headers import HeaderMap
from flare.http2 import Http2Connection, Http2Config
from flare.http2.state import StreamState
from flare.http._reactor.tagged_dispatch import (
    KIND_H1,
    KIND_H2,
    _addr,
    _kind,
    _pack,
)
from flare.http._server_reactor_epoll import _conn_alloc_addr
from flare.http._unified_reactor_impl import (
    _conn_ptr_from_int,
    _unified_handle_conn_event,
)
from flare.net import SocketAddr
from flare.runtime import INTEREST_READ, Reactor, TimerWheel
from flare.tcp import TcpListener, TcpStream


def _build_settings_payload(initial_window_size: Int) -> List[UInt8]:
    """Build a minimal SETTINGS payload carrying just ``initial_window_size``
    (RFC 9113 paragraph 6.5.2 setting id 0x4)."""
    var p = List[UInt8]()
    p.append(UInt8(0x00))  # id high byte
    p.append(UInt8(0x04))  # id low byte (INITIAL_WINDOW_SIZE)
    p.append(UInt8((initial_window_size >> 24) & 0xFF))
    p.append(UInt8((initial_window_size >> 16) & 0xFF))
    p.append(UInt8((initial_window_size >> 8) & 0xFF))
    p.append(UInt8(initial_window_size & 0xFF))
    return p^


def test_from_h2c_upgrade_creates_stream_1_with_request_headers() raises:
    """``Http2Connection.from_h2c_upgrade`` pre-populates stream id 1
    with the original h1 request's pseudo-headers (``:method``,
    ``:scheme``, ``:path``, ``:authority``) and marks both header /
    data complete so the next ``take_completed_streams`` returns
    [1]."""
    var req = Request(method="GET", url="/api/users", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    req.headers.set("X-Custom", "abc")

    var settings_payload = _build_settings_payload(131072)
    var conn = Http2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )

    var ready = conn.take_completed_streams()
    assert_equal(len(ready), 1)
    assert_equal(ready[0], 1)

    # Re-materialise the request from stream 1.
    var seen = conn.take_request(1)
    assert_equal(seen.method, "GET")
    assert_equal(seen.url, "/api/users")
    assert_equal(seen.headers.get("Host"), "example.com")
    assert_equal(seen.headers.get("x-custom"), "abc")


def test_from_h2c_upgrade_applies_settings_payload() raises:
    """The decoded ``HTTP2-Settings`` payload is applied to the
    connection state without emitting a SETTINGS_ACK."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    req.headers.set("Host", "example.com")

    var settings_payload = _build_settings_payload(131072)
    var conn = Http2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )

    # The client's INITIAL_WINDOW_SIZE is *its* receive window: what we
    # may send on a stream. Our own advertised window is unchanged.
    assert_equal(conn.conn.peer_initial_window_size, 131072)
    assert_equal(
        conn.conn.initial_window_size, Http2Config().initial_window_size
    )


def test_from_h2c_upgrade_seeds_outbox_with_server_settings() raises:
    """The server's initial SETTINGS frame is queued in the outbox
    (the server-side connection preface for the h2c-upgraded connection)
    so the reactor flushes it on the first writable event."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    var settings_payload = _build_settings_payload(65535)

    var conn = Http2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )

    var preface = conn.drain()
    assert_true(
        len(preface) >= 9, "server preface must include a SETTINGS frame"
    )
    # Frame type at offset 3 must be 0x4 (SETTINGS).
    assert_equal(Int(preface[3]), 0x4)


def test_from_h2c_upgrade_rejects_misaligned_settings_payload() raises:
    """A SETTINGS payload whose length isn't a multiple of 6 is
    a protocol error per RFC 7540 paragraph 3.2.1."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    # 5-byte payload is invalid (must be multiple of 6).
    var bad = List[UInt8]()
    for _ in range(5):
        bad.append(UInt8(0))

    var raised = False
    try:
        var _conn = Http2Connection.from_h2c_upgrade(Http2Config(), req, bad^)
    except:
        raised = True
    assert_true(
        raised, "from_h2c_upgrade must raise on misaligned SETTINGS payload"
    )


def test_from_h2c_upgrade_stream_1_state_is_half_closed_remote() raises:
    """Stream id 1 is implicitly half-closed from the client side
    after the upgrade (RFC 7540 paragraph 3.2: 'Stream 1 is implicitly
    half-closed from the client toward the server')."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    var settings_payload = _build_settings_payload(65535)

    var conn = Http2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )
    var s = conn.conn.streams[1].copy()
    assert_equal(s.state.value, StreamState.HALF_CLOSED_REMOTE().value)
    assert_true(s.headers_complete, "headers_complete must be True")
    assert_true(s.data_complete, "data_complete must be True")


def test_from_h2c_upgrade_carries_request_body() raises:
    """A POST body on the h1 upgrade request is carried over as
    stream 1's data."""
    var req = Request(method="POST", url="/echo", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    req.headers.set("Content-Type", "application/octet-stream")
    var body_str = String("hello upgrade body")
    var bb = body_str.as_bytes()
    for i in range(len(bb)):
        req.body.append(bb[i])

    var settings_payload = _build_settings_payload(65535)
    var conn = Http2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )

    var ready = conn.take_completed_streams()
    assert_equal(len(ready), 1)
    var seen = conn.take_request(1)
    assert_equal(seen.method, "POST")
    assert_equal(seen.url, "/echo")
    assert_equal(len(seen.body), body_str.byte_length())


def test_h2c_upgrade_header_decoder_accepts_well_formed_request() raises:
    """A request with ``Upgrade: h2c`` + valid base64url
    ``HTTP2-Settings`` is recognised as an h2c upgrade by the
    inline detector + base64url decoder used in
    ``ConnHandle.on_readable`` (verified by inspecting the
    public-surface helpers from
    :mod:`flare.crypto.hmac` + the headers API)."""
    var headers = HeaderMap()
    headers.set("Upgrade", "h2c")
    headers.set("Connection", "Upgrade, HTTP2-Settings")
    var raw = _build_settings_payload(65536)
    var b64 = base64url_encode(raw)
    headers.set("HTTP2-Settings", b64)

    # The h1 ConnHandle uses ``flare.http2.server.detect_h2c_upgrade``;
    # this test asserts the *inputs* the detector relies on parse +
    # decode cleanly. The detector itself is under
    # ``test_h2_server::test_detect_h2c_upgrade``; here we only
    # verify the base64url round-trip the upgrade decoder consumes.
    from flare.crypto.hmac import base64url_decode

    var decoded = base64url_decode(b64)
    assert_equal(len(decoded), len(raw))
    for i in range(len(decoded)):
        assert_equal(decoded[i], raw[i])


def _setting(id: Int, v: Int) -> List[UInt8]:
    var p = List[UInt8]()
    p.append(UInt8((id >> 8) & 0xFF))
    p.append(UInt8(id & 0xFF))
    p.append(UInt8((v >> 24) & 0xFF))
    p.append(UInt8((v >> 16) & 0xFF))
    p.append(UInt8((v >> 8) & 0xFF))
    p.append(UInt8(v & 0xFF))
    return p^


def test_from_h2c_upgrade_rejects_out_of_range_settings() raises:
    """MAX_FRAME_SIZE=0 in the HTTP2-Settings header used to be applied
    as is, after which any response body looped forever emitting empty
    DATA frames. The header gets the same bounds as a SETTINGS frame."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    for pair in [
        (0x5, 0),
        (0x5, 16383),
        (0x5, 16777216),
        (0x4, 0x80000000),
        (0x2, 2),
    ]:
        var raised = False
        try:
            _ = Http2Connection.from_h2c_upgrade(
                Http2Config(), req, _setting(pair[0], pair[1])
            )
        except:
            raised = True
        assert_true(
            raised,
            "accepted setting " + String(pair[0]) + "=" + String(pair[1]),
        )
    # In range is fine.
    _ = Http2Connection.from_h2c_upgrade(
        Http2Config(), req, _setting(0x5, 32768)
    )


def _ok(req: Request) raises -> Response:
    return Response(status=200)


def test_h2c_upgrade_101_flushed_on_a_writable_edge_migrates() raises:
    """APP-47: a 101 that only flushes on a writable edge must still
    migrate the connection to HTTP/2. The handle is driven to the
    "101 queued, nothing written" state by calling ``on_readable``
    directly, so the first socket write happens on the writable edge
    itself -- no dependence on kernel buffer sizes."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var accepted = listener.accept()
    accepted._socket.set_nonblocking(True)
    var fd = Int(accepted._socket.fd)

    var reactor = Reactor()
    reactor.register(c_int(fd), UInt64(fd), INTEREST_READ)
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()
    var wheel = TimerWheel(now_ms=UInt64(0))
    conns[fd] = _pack(KIND_H1, _conn_alloc_addr(accepted^))
    var handler = FnHandler(_ok)
    var config = ServerConfig()
    var h2 = Http2Config()

    var req = String(
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\n"
        "Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
    )
    client.write_all(req.as_bytes())
    ref ch = _conn_ptr_from_int(_addr(conns[fd]))[]
    ch.h2c_upgrade_allowed = True
    # Wait (bounded by the socket, not a sleep) for the request bytes.
    var step = ch.on_readable(handler, config)
    for _ in range(1000):
        if ch._h2c_upgrade_pending:
            break
        step = ch.on_readable(handler, config)
    assert_true(ch._h2c_upgrade_pending, "upgrade request was not queued")
    assert_true(len(ch.write_buf) > ch.write_pos, "101 should be unwritten")
    assert_true(step.want_write)

    # The writable edge flushes the 101 and must migrate to HTTP/2.
    _unified_handle_conn_event[FnHandler](
        fd,
        conns[fd],
        False,
        True,
        handler,
        config,
        h2,
        conns,
        reactor,
        wheel,
        timers,
    )
    assert_true(fd in conns)
    assert_equal(_kind(conns[fd]), KIND_H2)

    # The client sees the 101 and then the server's SETTINGS frame.
    client.set_recv_timeout(2000)
    var buf = List[UInt8](length=4096, fill=UInt8(0))
    var got = 0
    for _ in range(8):
        var n = client.read(buf.unsafe_ptr(), len(buf))
        if n <= 0:
            break
        got += n
        if got > 71:
            break
    assert_true(got > 71, "no HTTP/2 SETTINGS after the 101")


def main() raises:
    test_from_h2c_upgrade_creates_stream_1_with_request_headers()
    test_from_h2c_upgrade_applies_settings_payload()
    test_from_h2c_upgrade_seeds_outbox_with_server_settings()
    test_from_h2c_upgrade_rejects_misaligned_settings_payload()
    test_from_h2c_upgrade_stream_1_state_is_half_closed_remote()
    test_from_h2c_upgrade_carries_request_body()
    test_from_h2c_upgrade_rejects_out_of_range_settings()
    test_h2c_upgrade_header_decoder_accepts_well_formed_request()
    test_h2c_upgrade_101_flushed_on_a_writable_edge_migrates()
    print("test_h2c_upgrade: 9 passed")
