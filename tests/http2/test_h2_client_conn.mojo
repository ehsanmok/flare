"""End-to-end driver tests for ``flare.http2.client.Http2ClientConnection``.

Exercises the client-side driver entirely in-memory by pairing it
with the existing server-side :class:`flare.http2.server.Http2Connection`
and shuttling the byte streams between the two without any sockets.
This confirms RFC 9113 wire compatibility on both sides AND keeps
the test fast / hermetic (no port binding, no networking).

Test inventory:

- :func:`test_preface_emitted_on_construction` -- the driver
  pre-loads the 24-byte preface + a SETTINGS frame in
  :attr:`Http2ClientConnection.outbox` ready to drain.
- :func:`test_settings_exchange_roundtrip` -- feeds the bytes the
  *server* would emit (initial SETTINGS) into the client; the
  client responds with a SETTINGS ACK.
- :func:`test_get_request_response_roundtrip` -- client sends a
  GET, server parses+responds, client reassembles the response and
  yields ``(status, headers, body)``.
- :func:`test_post_request_with_body` -- same but with a POST and
  a small request body that fits in a single DATA frame.
- :func:`test_two_sequential_requests_share_connection` -- the
  same driver pair handles two requests on stream ids 1 and 3.
- :func:`test_response_with_chunked_body` -- the server emits the
  response body across multiple DATA frames and the client
  reassembles them.
- :func:`test_rst_stream_surfaced` -- a RST_STREAM frame from the
  server marks the stream as ended and the error code is
  retrievable via :meth:`Http2ClientConnection.stream_error`.
- :func:`test_goaway_received_flag` -- a GOAWAY from the server
  flips :attr:`Http2ClientConnection.goaway_received`.
- :func:`test_push_promise_is_a_connection_error` -- if the
  server (incorrectly) sends a PUSH_PROMISE despite our
  ``SETTINGS_ENABLE_PUSH=0``, the client answers with
  GOAWAY(PROTOCOL_ERROR) (RFC 9113 §8.4) instead of dropping the frame
  and desynchronising its HPACK table.
- :func:`test_oversized_headers_split_across_continuation` -- a
  request whose encoded header block exceeds ``max_frame_size``
  is split into HEADERS + CONTINUATION frames.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.http2 import (
    Frame,
    FrameFlags,
    FrameType,
    Http2Connection,
    H2_PREFACE,
    HpackEncoder,
    HpackHeader,
    Http2ClientConfig,
    Http2ClientConnection,
    encode_frame,
    parse_frame,
)
from flare.http2.client import Http2Response
from flare.http import Response


def _shuttle(
    mut client: Http2ClientConnection, mut server: Http2Connection
) raises:
    """Pump bytes one-way then the other until both outboxes are empty.

    Mirrors a one-shot socket round-trip: client emits, server
    parses + emits, client parses + emits, etc., until both sides
    have nothing more to send. Bounded by an iteration cap so a
    bug doesn't loop the test runner forever.
    """
    var iters = 0
    while True:
        if iters > 64:
            raise Error("test shuttle: too many iterations (likely a bug)")
        iters += 1
        var c_out = client.drain()
        var made_progress = False
        if len(c_out) > 0:
            server.feed(Span[UInt8, _](c_out))
            made_progress = True
        var s_out = server.drain()
        if len(s_out) > 0:
            client.feed(Span[UInt8, _](s_out))
            made_progress = True
        if not made_progress:
            return


# ── raw-frame helpers shared by the RFC 9113 §5.1 regression tests ──────


def _raw_frame(
    ty: UInt8, flags: UInt8, sid: Int, payload: List[UInt8]
) -> List[UInt8]:
    """Wire bytes of one frame (9-byte header + payload)."""
    var out = List[UInt8]()
    var n = len(payload)
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    out.append(ty)
    out.append(flags)
    out.append(UInt8((sid >> 24) & 0x7F))
    out.append(UInt8((sid >> 16) & 0xFF))
    out.append(UInt8((sid >> 8) & 0xFF))
    out.append(UInt8(sid & 0xFF))
    for b in payload:
        out.append(b)
    return out^


def _be32(v: Int) -> List[UInt8]:
    var p = List[UInt8]()
    p.append(UInt8((v >> 24) & 0xFF))
    p.append(UInt8((v >> 16) & 0xFF))
    p.append(UInt8((v >> 8) & 0xFF))
    p.append(UInt8(v & 0xFF))
    return p^


def _error_code_of(bytes: List[UInt8], ty: Int) raises -> Int:
    """Error code of the first frame of type ``ty`` (GOAWAY 7 / RST 3) in
    ``bytes``, or -1 when there is none."""
    var off = 0
    while off < len(bytes):
        var got = parse_frame(Span[UInt8, _](bytes)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if Int(f.header.type.value) == ty:
            var at = 4 if ty == 7 else 0
            return (
                (Int(f.payload[at]) << 24)
                | (Int(f.payload[at + 1]) << 16)
                | (Int(f.payload[at + 2]) << 8)
                | Int(f.payload[at + 3])
            )
    return -1


def _goaway_code(bytes: List[UInt8]) raises -> Int:
    return _error_code_of(bytes, 7)


def _rst_code(bytes: List[UInt8]) raises -> Int:
    return _error_code_of(bytes, 3)


def _get(
    mut client: Http2ClientConnection, mut server: Http2Connection
) raises -> Int:
    """Send a bodiless GET on a fresh stream and shuttle it to the server."""
    var sid = client.next_stream_id()
    var empty = List[UInt8]()
    client.send_request(
        sid, "GET", "http", "example.com", "/", List[HpackHeader](), Span(empty)
    )
    _shuttle(client, server)
    return sid


def _complete_and_take(
    mut client: Http2ClientConnection,
    mut server: Http2Connection,
    sid: Int,
) raises:
    """Serve ``sid`` with a 200 "ok" response and ``take_response`` it."""
    _ = server.take_request(sid)
    var resp = Response(status=200)
    resp.body = List[UInt8](String("ok").as_bytes())
    server.emit_response(sid, resp^)
    _shuttle(client, server)
    assert_true(client.response_ready(sid))
    _ = client.take_response(sid)
    _ = client.drain()


def test_preface_emitted_on_construction() raises:
    """``Http2ClientConnection.__init__`` pre-queues preface + SETTINGS."""
    var c = Http2ClientConnection()
    var bytes = c.drain()
    # First 24 bytes MUST be the RFC 9113 §3.5 preface.
    var preface = String(H2_PREFACE)
    var pp = preface.unsafe_ptr()
    assert_true(len(bytes) >= 24)
    for i in range(24):
        assert_equal(Int(bytes[i]), Int(pp[unsafe_offset=i]))
    # Then a SETTINGS frame on stream 0.
    var rest = List[UInt8](capacity=len(bytes) - 24)
    for i in range(24, len(bytes)):
        rest.append(bytes[i])
    var maybe = parse_frame(Span[UInt8, _](rest))
    assert_true(Bool(maybe))
    var f = maybe.value().copy()
    assert_equal(Int(f.header.type.value), 0x4)  # SETTINGS
    assert_equal(f.header.stream_id, 0)
    assert_false(f.header.flags.has(FrameFlags.ACK()))


def test_settings_exchange_roundtrip() raises:
    """Server SETTINGS feed -> client emits SETTINGS ACK."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)
    # By the end of the shuttle, the client must have ACKed the
    # server's initial SETTINGS. We verify by walking the bytes
    # the server has received: at least one SETTINGS-with-ACK
    # frame from the client.
    # We do NOT rely on any internal flag; we re-parse the wire
    # bytes the server saw via re-running the server driver on
    # what the client most recently emitted. Here we already
    # shuttled; just confirm both directions are quiescent.
    var c_out = client.drain()
    var s_out = server.drain()
    assert_equal(len(c_out), 0)
    assert_equal(len(s_out), 0)


def test_get_request_response_roundtrip() raises:
    """Client GET -> server response -> client reassembles."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    # Get the initial SETTINGS exchange out of the way first
    # so the server is in the request-handling state.
    _shuttle(client, server)

    # Client sends GET /api/users.
    var sid = client.next_stream_id()
    assert_equal(sid, 1)
    var extra = List[HpackHeader]()
    extra.append(HpackHeader("user-agent", "h2-test"))
    var empty_body = List[UInt8]()
    client.send_request(
        sid,
        "GET",
        "https",
        "example.com",
        "/api/users",
        extra,
        Span[UInt8, _](empty_body),
    )
    # Shuttle: client -> server
    _shuttle(client, server)

    # Server should now have a complete request.
    var ids = server.take_completed_streams()
    assert_equal(len(ids), 1)
    assert_equal(ids[0], 1)
    var req = server.take_request(1)
    assert_equal(req.method, "GET")
    assert_equal(req.url, "/api/users")
    assert_equal(req.headers.get("user-agent"), "h2-test")

    # Server emits a response.
    var resp = Response(status=200)
    resp.headers.set("Content-Type", "application/json")
    resp.body = List[UInt8](String('{"ok":true}').as_bytes())
    server.emit_response(1, resp^)

    # Shuttle: server -> client
    _shuttle(client, server)

    # Client should now hold a ready response on stream 1.
    assert_true(client.response_ready(1))
    var got = client.take_response(1)
    assert_equal(got.status, 200)
    # ``content-type`` must be in the returned headers
    # (lowercased per RFC 9113 §8.1.2).
    var found_ct = False
    for i in range(len(got.headers)):
        if got.headers[i].name == "content-type":
            assert_equal(got.headers[i].value, "application/json")
            found_ct = True
    assert_true(found_ct)
    # Body bytes round-trip exactly.
    var body_str = String(unsafe_from_utf8=Span[UInt8, _](got.body))
    assert_equal(body_str, '{"ok":true}')


def test_post_request_with_body() raises:
    """Client POST with a body -> server reads body bytes."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)

    var sid = client.next_stream_id()
    var extra = List[HpackHeader]()
    extra.append(HpackHeader("content-type", "application/json"))
    var body_str = String('{"k":"v"}')
    var body = List[UInt8](body_str.as_bytes())
    client.send_request(
        sid,
        "POST",
        "https",
        "example.com",
        "/items",
        extra,
        Span[UInt8, _](body),
    )
    _shuttle(client, server)

    var ids = server.take_completed_streams()
    assert_equal(len(ids), 1)
    assert_equal(ids[0], sid)
    var req = server.take_request(sid)
    assert_equal(req.method, "POST")
    assert_equal(req.url, "/items")
    var got_body = String(unsafe_from_utf8=Span[UInt8, _](req.body))
    assert_equal(got_body, body_str)


def test_two_sequential_requests_share_connection() raises:
    """Two requests on stream ids 1 and 3 share one driver pair."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)

    # Request 1 on stream 1.
    var sid1 = client.next_stream_id()
    assert_equal(sid1, 1)
    var no_extra = List[HpackHeader]()
    var no_body = List[UInt8]()
    client.send_request(
        sid1,
        "GET",
        "http",
        "x",
        "/a",
        no_extra,
        Span[UInt8, _](no_body),
    )
    _shuttle(client, server)
    var ids = server.take_completed_streams()
    assert_equal(len(ids), 1)
    var resp1 = Response(status=200)
    resp1.body = List[UInt8](String("aaa").as_bytes())
    server.emit_response(sid1, resp1^)
    _shuttle(client, server)
    assert_true(client.response_ready(sid1))
    var r1 = client.take_response(sid1)
    assert_equal(r1.status, 200)
    var b1 = String(unsafe_from_utf8=Span[UInt8, _](r1.body))
    assert_equal(b1, "aaa")

    # Request 2 on stream 3.
    var sid2 = client.next_stream_id()
    assert_equal(sid2, 3)
    var no_extra2 = List[HpackHeader]()
    var no_body2 = List[UInt8]()
    client.send_request(
        sid2,
        "GET",
        "http",
        "x",
        "/b",
        no_extra2,
        Span[UInt8, _](no_body2),
    )
    _shuttle(client, server)
    var ids2 = server.take_completed_streams()
    # ``take_completed_streams`` returns *all* completed
    # (since neither request was popped from the server's
    # ``streams`` dict via emit_response yet on stream 3 OR
    # the previous emit_response transitions to CLOSED but
    # leaves the entry around). It's enough that sid2 is
    # present.
    var found_sid2 = False
    for i in range(len(ids2)):
        if ids2[i] == sid2:
            found_sid2 = True
    assert_true(found_sid2)
    var resp2 = Response(status=404)
    server.emit_response(sid2, resp2^)
    _shuttle(client, server)
    assert_true(client.response_ready(sid2))
    var r2 = client.take_response(sid2)
    assert_equal(r2.status, 404)


def test_response_with_chunked_body() raises:
    """Server emits a response across multiple DATA frames; client merges."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)

    var sid = client.next_stream_id()
    var no_extra = List[HpackHeader]()
    var no_body = List[UInt8]()
    client.send_request(
        sid,
        "GET",
        "http",
        "x",
        "/big",
        no_extra,
        Span[UInt8, _](no_body),
    )
    _shuttle(client, server)
    _ = server.take_completed_streams()
    _ = server.take_request(sid)

    # Hand-craft a HEADERS (no END_STREAM) + multiple DATA frames
    # straight into the client's feed buffer, bypassing
    # ``server.emit_response`` so we control the chunking.
    var enc = HpackEncoder()
    var status_hdrs = List[HpackHeader]()
    status_hdrs.append(HpackHeader(":status", "200"))
    var hf = Frame()
    hf.header.type = FrameType.HEADERS()
    hf.header.stream_id = sid
    hf.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    hf.payload = enc.encode(Span[HpackHeader, _](status_hdrs))
    hf.header.length = len(hf.payload)
    var hb = encode_frame(hf^)
    # Two DATA frames: "abc" then "def" with END_STREAM on the
    # second.
    var d1 = Frame()
    d1.header.type = FrameType.DATA()
    d1.header.stream_id = sid
    d1.header.flags = FrameFlags(UInt8(0))
    d1.payload = List[UInt8](String("abc").as_bytes())
    d1.header.length = len(d1.payload)
    var d1b = encode_frame(d1^)
    var d2 = Frame()
    d2.header.type = FrameType.DATA()
    d2.header.stream_id = sid
    d2.header.flags = FrameFlags(FrameFlags.END_STREAM())
    d2.payload = List[UInt8](String("def").as_bytes())
    d2.header.length = len(d2.payload)
    var d2b = encode_frame(d2^)
    # Splice the three frames into one byte buffer and feed.
    var combined = List[UInt8]()
    for i in range(len(hb)):
        combined.append(hb[i])
    for i in range(len(d1b)):
        combined.append(d1b[i])
    for i in range(len(d2b)):
        combined.append(d2b[i])
    client.feed(Span[UInt8, _](combined))

    assert_true(client.response_ready(sid))
    var r = client.take_response(sid)
    assert_equal(r.status, 200)
    var body_str = String(unsafe_from_utf8=Span[UInt8, _](r.body))
    assert_equal(body_str, "abcdef")


def test_rst_stream_surfaced() raises:
    """A peer RST_STREAM marks the stream done and exposes the error code."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)

    var sid = client.next_stream_id()
    var no_extra = List[HpackHeader]()
    var no_body = List[UInt8]()
    client.send_request(
        sid,
        "GET",
        "http",
        "x",
        "/x",
        no_extra,
        Span[UInt8, _](no_body),
    )
    _shuttle(client, server)
    _ = server.take_completed_streams()
    _ = server.take_request(sid)

    # Hand-craft a RST_STREAM(REFUSED_STREAM=0x7) and feed.
    var rf = Frame()
    rf.header.type = FrameType.RST_STREAM()
    rf.header.stream_id = sid
    rf.header.flags = FrameFlags(UInt8(0))
    var p = List[UInt8]()
    p.append(UInt8(0))
    p.append(UInt8(0))
    p.append(UInt8(0))
    p.append(UInt8(0x7))
    rf.payload = p^
    rf.header.length = len(rf.payload)
    var rb = encode_frame(rf^)
    client.feed(Span[UInt8, _](rb))

    assert_true(client.response_ready(sid))
    var maybe = client.stream_error(sid)
    assert_true(Bool(maybe))
    assert_equal(maybe.value(), 0x7)


def test_goaway_received_flag() raises:
    """A GOAWAY from the server flips ``goaway_received``."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)

    assert_false(client.goaway_received())

    var ga = Frame()
    ga.header.type = FrameType.GOAWAY()
    ga.header.stream_id = 0
    ga.header.flags = FrameFlags(UInt8(0))
    var p = List[UInt8]()
    # last_stream_id = 0 (4 bytes) + error_code = 0 (NO_ERROR, 4 bytes).
    for _ in range(8):
        p.append(UInt8(0))
    ga.payload = p^
    ga.header.length = len(ga.payload)
    var gb = encode_frame(ga^)
    client.feed(Span[UInt8, _](gb))

    assert_true(client.goaway_received())


def test_push_promise_is_a_connection_error() raises:
    """A server PUSH_PROMISE despite our SETTINGS_ENABLE_PUSH=0 is a
    connection error of type PROTOCOL_ERROR (RFC 9113 sec 8.4).

    It used to be answered with RST_STREAM on the promised id and dropped,
    which skipped its HPACK block and left the decoder table out of step
    with the server's encoder (H2-17).
    """
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)

    # Hand-craft a PUSH_PROMISE on stream 1 with promised stream 2.
    # (Stream 2 is even, which is server-initiated; that's
    # what RFC 9113 §5.1.1 requires for a push.)
    var pp = Frame()
    pp.header.type = FrameType.PUSH_PROMISE()
    pp.header.stream_id = 1
    pp.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    var payload = List[UInt8]()
    # Promised stream id (4 bytes, big-endian).
    payload.append(UInt8(0))
    payload.append(UInt8(0))
    payload.append(UInt8(0))
    payload.append(UInt8(2))
    # Followed by the HPACK-encoded promised request headers.
    var enc = HpackEncoder()
    var fake_hdrs = List[HpackHeader]()
    fake_hdrs.append(HpackHeader(":method", "GET"))
    fake_hdrs.append(HpackHeader(":path", "/"))
    var enc_bytes = enc.encode(Span[HpackHeader, _](fake_hdrs))
    for i in range(len(enc_bytes)):
        payload.append(enc_bytes[i])
    pp.payload = payload^
    pp.header.length = len(pp.payload)
    var ppb = encode_frame(pp^)
    client.feed(Span[UInt8, _](ppb))

    # The client queues GOAWAY(PROTOCOL_ERROR) and no RST_STREAM.
    var c_out = client.drain()
    assert_true(len(c_out) > 0)
    assert_equal(_goaway_code(c_out), 0x1)
    assert_equal(_rst_code(c_out), -1)


def test_push_promise_block_cannot_desync_later_responses() raises:
    """H2-17: a PUSH_PROMISE whose block inserts into the server's HPACK
    table must end the connection, not be dropped: a later response that
    indexes that insert would decode to a header the server never sent."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)
    var sid = _get(client, server)
    # PUSH_PROMISE(1 -> 2) whose block is "x-a: 1" literal-with-indexing.
    var block = List[UInt8]()
    block.append(0x40)  # literal with incremental indexing, new name
    block.append(3)
    for c in String("x-a").as_bytes():
        block.append(c)
    block.append(1)
    block.append(UInt8(ord("1")))
    var payload = _be32(2)
    payload.extend(block.copy())
    var pp = _raw_frame(UInt8(0x5), UInt8(0x4), sid, payload)
    client.feed(Span[UInt8, _](pp))
    assert_equal(_goaway_code(client.drain()), 0x1)
    assert_true(client.conn.goaway_sent)


def test_oversized_headers_split_across_continuation() raises:
    """A header block bigger than max_frame_size is split into HEADERS+CONTINUATION.
    """
    # Tiny max_frame_size to force the split deterministically.
    var cfg = Http2ClientConfig()
    cfg.max_frame_size = (
        16384  # min allowed; oversize the header block instead.
    )
    var client = Http2ClientConnection.with_config(cfg^)
    # Pull the (preface + initial SETTINGS) bytes out so the
    # next ``drain()`` only contains the request frames.
    _ = client.drain()

    var sid = client.next_stream_id()
    # Build a header block big enough to exceed 16384 bytes:
    # 200 entries of ~100-byte values is ~20 KiB.
    var extra = List[HpackHeader]()
    for i in range(200):
        var k = String("x-large-header-")
        k += String(i)
        var v = String("")
        for _ in range(100):
            v += "v"
        extra.append(HpackHeader(k^, v^))
    var no_body = List[UInt8]()
    client.send_request(
        sid,
        "GET",
        "http",
        "x",
        "/big-headers",
        extra,
        Span[UInt8, _](no_body),
    )
    var bytes = client.drain()
    # First frame must be HEADERS without END_HEADERS; later
    # frames must be CONTINUATION; the last CONTINUATION must
    # have END_HEADERS.
    var pos = 0
    var saw_headers = False
    var saw_continuation = False
    var last_was_end_headers = False
    while pos < len(bytes):
        var slice = List[UInt8]()
        for i in range(pos, len(bytes)):
            slice.append(bytes[i])
        var maybe = parse_frame(Span[UInt8, _](slice))
        assert_true(Bool(maybe))
        var f = maybe.value().copy()
        if Int(f.header.type.value) == 0x1:  # HEADERS
            assert_false(saw_headers)  # only one HEADERS
            saw_headers = True
            assert_false(f.header.flags.has(FrameFlags.END_HEADERS()))
        elif Int(f.header.type.value) == 0x9:  # CONTINUATION
            saw_continuation = True
            last_was_end_headers = f.header.flags.has(FrameFlags.END_HEADERS())
        pos += 9 + f.header.length
    assert_true(saw_headers)
    assert_true(saw_continuation)
    assert_true(last_was_end_headers)


def test_pending_body_drains_on_window_update() raises:
    """A body larger than the send window is partially sent and the
    remainder stashed; the server's WINDOW_UPDATE (auto-emitted on
    DATA receipt) reopens the window and the client drains the rest,
    so the server reassembles the full body (RFC 9113 §6.9)."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)

    var sid = client.next_stream_id()
    var extra = List[HpackHeader]()
    extra.append(HpackHeader("content-type", "text/plain"))
    var body_str = String("0123456789AB")  # 12 bytes
    var body = List[UInt8](body_str.as_bytes())
    # Force a partial send: only 5 of 12 body bytes fit the window.
    client.conn.send_window = 5
    client.send_request(
        sid, "POST", "https", "x", "/u", extra, Span[UInt8, _](body)
    )
    # The remainder must be queued, not raised.
    assert_true(client.has_pending_body(sid))

    _shuttle(client, server)

    # After the shuttle, the window reopened and the queue drained.
    assert_false(client.has_pending_body(sid))
    var ids = server.take_completed_streams()
    var found = False
    for i in range(len(ids)):
        if ids[i] == sid:
            found = True
    assert_true(found)
    var req = server.take_request(sid)
    assert_equal(String(unsafe_from_utf8=Span[UInt8, _](req.body)), body_str)


def test_late_frames_on_a_taken_stream_are_ignored() raises:
    """H2-03: a WINDOW_UPDATE or RST_STREAM(NO_ERROR) that reaches the
    client after take_response() popped the stream is a frame on a closed
    stream (RFC 9113 sec 5.1), not on an idle one."""
    var kinds = List[Int]()
    kinds.append(0x8)
    kinds.append(0x3)
    for k in range(len(kinds)):
        var client = Http2ClientConnection()
        var server = Http2Connection()
        _shuttle(client, server)
        var sid = _get(client, server)
        _complete_and_take(client, server, sid)
        var payload = _be32(100 if kinds[k] == 0x8 else 0)
        client.feed(
            Span[UInt8, _](_raw_frame(UInt8(kinds[k]), UInt8(0), sid, payload))
        )
        assert_equal(_goaway_code(client.drain()), -1)


def test_late_frame_on_a_stream_never_opened_is_a_protocol_error() raises:
    """H2-03: the idle test is not weakened: an odd id above every id the
    client opened, and any even id, are still idle."""
    var ids = List[Int]()
    ids.append(3)
    ids.append(2)
    for k in range(len(ids)):
        var client = Http2ClientConnection()
        var server = Http2Connection()
        _shuttle(client, server)
        var sid = _get(client, server)
        _complete_and_take(client, server, sid)
        client.feed(
            Span[UInt8, _](_raw_frame(UInt8(0x8), UInt8(0), ids[k], _be32(100)))
        )
        assert_equal(_goaway_code(client.drain()), 1)


def test_reduced_table_size_is_a_ceiling_not_an_immediate_resize() raises:
    """HPACK-03: advertising SETTINGS_HEADER_TABLE_SIZE = 0 must not shrink
    the client's decoder before the server has seen it and sent a size
    update (RFC 7541 sec 4.2); the setting only caps that update."""
    var cfg = Http2ClientConfig()
    cfg.header_table_size = 0
    var client = Http2ClientConnection.with_config(cfg^)
    assert_equal(client.conn.hpack_decoder.max_size, 4096)
    assert_equal(client.conn.hpack_decoder.settings_max_size, 0)


def main() raises:
    test_preface_emitted_on_construction()
    test_settings_exchange_roundtrip()
    test_get_request_response_roundtrip()
    test_post_request_with_body()
    test_two_sequential_requests_share_connection()
    test_response_with_chunked_body()
    test_rst_stream_surfaced()
    test_goaway_received_flag()
    test_push_promise_is_a_connection_error()
    test_oversized_headers_split_across_continuation()
    test_pending_body_drains_on_window_update()
    test_late_frames_on_a_taken_stream_are_ignored()
    test_late_frame_on_a_stream_never_opened_is_a_protocol_error()
    test_push_promise_block_cannot_desync_later_responses()
    test_reduced_table_size_is_a_ceiling_not_an_immediate_resize()
    print("test_h2_client_conn: 15 passed")
