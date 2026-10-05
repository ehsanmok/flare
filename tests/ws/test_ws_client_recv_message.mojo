"""``WsClient.recv_message`` returns whole messages (WS-02).

RFC 6455 sec 5.4: a message is a TEXT or BINARY frame followed by
CONTINUATION frames up to one with FIN set, and its payload is their
concatenation. Control frames may be interleaved (sec 5.4, 5.5), and an
unsolicited PONG is allowed and is not a message (sec 5.5.3).

Each test serves a scripted frame sequence over an in-process loopback
TCP pair (ephemeral port) and reads it through ``recv_message``.
"""

from std.testing import assert_equal, assert_false, assert_true, TestSuite

from flare.net import NetworkError, SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.ws import WsFrame, WsOpcode
from flare.ws.client import WsClient, _WsStream


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _frame(
    opcode: UInt8, payload: List[UInt8], fin: Bool
) raises -> List[UInt8]:
    return WsFrame(opcode=opcode, payload=payload.copy(), fin=fin).encode(
        mask=False
    )


def _dummy() raises -> TcpStream:
    """A placeholder stream for ``_client`` to overwrite."""
    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(ln.local_addr().port))
    var s = ln.accept()
    c.close()
    ln.close()
    return s^


def _client(wire: List[UInt8], mut server: TcpStream) raises -> WsClient:
    """A client whose server end has already been sent ``wire``."""
    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var port = ln.local_addr().port
    var c = TcpStream.connect(SocketAddr.localhost(port))
    c.set_recv_timeout(3000)
    server = ln.accept()
    server.write_all(Span[UInt8, _](wire))
    ln.close()
    return WsClient(_WsStream(c^), "k")


def _fails(var ws: WsClient) -> String:
    """The error text of the next ``recv_message``, or "" if it returned."""
    try:
        _ = ws.recv_message()
    except e:
        return String(e)
    return ""


def test_fragmented_text_is_one_message() raises:
    var wire = _frame(WsOpcode.TEXT, _bytes("hel"), False)
    wire.extend(
        Span[UInt8, _](_frame(WsOpcode.CONTINUATION, _bytes("l"), False))
    )
    wire.extend(
        Span[UInt8, _](_frame(WsOpcode.CONTINUATION, _bytes("o"), True))
    )
    wire.extend(Span[UInt8, _](_frame(WsOpcode.TEXT, _bytes("next"), True)))
    var srv = _dummy()
    var ws = _client(wire, srv)
    var first = ws.recv_message()
    assert_true(first.is_text)
    assert_equal(first.as_text(), "hello")
    assert_equal(ws.recv_message().as_text(), "next")
    srv.close()


def test_fragmented_binary_is_one_message() raises:
    var parts = List[UInt8]()
    parts.append(0)
    parts.append(255)
    var wire = _frame(WsOpcode.BINARY, parts, False)
    var tail = List[UInt8]()
    tail.append(7)
    wire.extend(Span[UInt8, _](_frame(WsOpcode.CONTINUATION, tail, True)))
    var srv = _dummy()
    var ws = _client(wire, srv)
    var m = ws.recv_message()
    assert_false(m.is_text)
    var got = m.as_binary()
    assert_equal(len(got), 3)
    assert_equal(Int(got[0]), 0)
    assert_equal(Int(got[1]), 255)
    assert_equal(Int(got[2]), 7)
    srv.close()


def test_unsolicited_pong_is_not_a_message() raises:
    var wire = WsFrame.pong(_bytes("x")).encode(mask=False)
    wire.extend(Span[UInt8, _](WsFrame.text("a").encode(mask=False)))
    var srv = _dummy()
    var ws = _client(wire, srv)
    assert_equal(ws.recv_message().as_text(), "a")
    srv.close()


def test_control_frames_between_fragments() raises:
    var wire = _frame(WsOpcode.TEXT, _bytes("he"), False)
    wire.extend(Span[UInt8, _](WsFrame.pong(_bytes("p")).encode(mask=False)))
    wire.extend(Span[UInt8, _](WsFrame.ping(_bytes("q")).encode(mask=False)))
    wire.extend(
        Span[UInt8, _](_frame(WsOpcode.CONTINUATION, _bytes("llo"), True))
    )
    var srv = _dummy()
    var ws = _client(wire, srv)
    assert_equal(ws.recv_message().as_text(), "hello")
    srv.close()


def test_utf8_split_across_fragments_is_valid() raises:
    # U+00E9 is C3 A9; the two bytes arrive in different frames.
    var a = List[UInt8]()
    a.append(0xC3)
    var b = List[UInt8]()
    b.append(0xA9)
    var wire = _frame(WsOpcode.TEXT, a, False)
    wire.extend(Span[UInt8, _](_frame(WsOpcode.CONTINUATION, b, True)))
    var srv = _dummy()
    var ws = _client(wire, srv)
    assert_equal(ws.recv_message().as_text(), "\u00e9")
    srv.close()


def test_invalid_utf8_across_fragments_is_refused() raises:
    var a = List[UInt8]()
    a.append(0xC3)
    var b = List[UInt8]()
    b.append(0x28)
    var wire = _frame(WsOpcode.TEXT, a, False)
    wire.extend(Span[UInt8, _](_frame(WsOpcode.CONTINUATION, b, True)))
    var srv = _dummy()
    var msg = _fails(_client(wire, srv))
    assert_true("UTF-8" in msg, msg)
    srv.close()


def test_continuation_without_a_start_is_a_protocol_error() raises:
    var wire = _frame(WsOpcode.CONTINUATION, _bytes("lo"), True)
    var srv = _dummy()
    var msg = _fails(_client(wire, srv))
    assert_true("continuation" in msg.lower(), msg)
    srv.close()


def test_new_data_frame_inside_a_fragmented_message_is_refused() raises:
    var wire = _frame(WsOpcode.TEXT, _bytes("hel"), False)
    wire.extend(Span[UInt8, _](_frame(WsOpcode.TEXT, _bytes("x"), True)))
    var srv = _dummy()
    var msg = _fails(_client(wire, srv))
    assert_true("fragment" in msg.lower(), msg)
    srv.close()


def test_close_inside_a_fragmented_message_raises() raises:
    var wire = _frame(WsOpcode.TEXT, _bytes("hel"), False)
    wire.extend(Span[UInt8, _](WsFrame.close().encode(mask=False)))
    var srv = _dummy()
    var msg = _fails(_client(wire, srv))
    assert_true("CLOSE" in msg, msg)
    srv.close()


def test_reassembled_message_is_bounded_by_max_frame_size() raises:
    var wire = _frame(WsOpcode.TEXT, _bytes("aaaa"), False)
    wire.extend(
        Span[UInt8, _](_frame(WsOpcode.CONTINUATION, _bytes("bbbb"), False))
    )
    wire.extend(
        Span[UInt8, _](_frame(WsOpcode.CONTINUATION, _bytes("cccc"), True))
    )
    var srv = _dummy()
    var ws = _client(wire, srv)
    ws.max_frame_size = 8
    var msg = _fails(ws^)
    assert_true("too big" in msg, msg)
    srv.close()


def test_client_refuses_a_masked_server_frame() raises:
    """WS-03: RFC 6455 sec 5.1 -- a client MUST close on a masked frame.

    ``WsClient._recv_one`` unmasked the frame and returned it. Both
    ``recv()`` and ``recv_message()`` go through it.
    """
    var key = SIMD[DType.uint8, 4](0x11, 0x22, 0x33, 0x44)
    var masked = WsFrame.text("hi").encode_with_key(True, key)
    var srv = _dummy()
    var ws = _client(masked, srv)
    var recv_err = String("")
    try:
        _ = ws.recv()
    except e:
        recv_err = String(e)
    assert_true("masked" in recv_err, "recv() must refuse: '" + recv_err + "'")
    assert_true("WsProtocolError" in recv_err or "RFC 6455" in recv_err)

    var srv2 = _dummy()
    var msg_err = _fails(_client(masked, srv2))
    assert_true("masked" in msg_err, "recv_message: '" + msg_err + "'")

    # A masked frame after valid ones is refused as well.
    var wire = _frame(WsOpcode.TEXT, _bytes("ok"), True)
    wire.extend(Span[UInt8, _](masked))
    var srv3 = _dummy()
    var ws3 = _client(wire, srv3)
    assert_equal(ws3.recv().text_payload(), "ok")
    var second = String("")
    try:
        _ = ws3.recv()
    except e:
        second = String(e)
    assert_true("masked" in second, "second frame: '" + second + "'")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
