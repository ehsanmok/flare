"""``WsConnection`` takes part in the closing handshake (WS-06).

RFC 6455 sec 5.5.1: an endpoint that receives a CLOSE and has not sent one
MUST send a CLOSE in response, and after sending a CLOSE it MUST NOT send
more data. Sec 7.4.1 and 7.1.7: a 1-byte body, an invalid code or a
non-UTF-8 reason is a protocol error, answered with 1002.

The server end is a ``WsConnection`` over an in-process loopback TCP pair
(ephemeral port); the test plays the client with raw masked frames and
reads back everything the server wrote up to EOF.
"""

from std.testing import assert_equal, assert_false, assert_true, TestSuite

from flare.net import NetworkError, SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.ws import WsFrame, WsOpcode
from flare.ws.server import WsConnection


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _close_body(code: Int, reason: String = "") -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8(code >> 8))
    out.append(UInt8(code & 0xFF))
    for b in reason.as_bytes():
        out.append(b)
    return out^


struct _Pair(Movable):
    var server: WsConnection
    var client: TcpStream

    def __init__(out self) raises:
        var ln = TcpListener.bind(SocketAddr.localhost(0))
        var port = ln.local_addr().port
        self.client = TcpStream.connect(SocketAddr.localhost(port))
        self.client.set_recv_timeout(3000)
        var s = ln.accept()
        var peer = s.peer_addr()
        self.server = WsConnection(s^, peer)
        ln.close()

    def finish(mut self) raises -> List[List[UInt8]]:
        """Close the server end, then read its output to EOF.

        Returns the frames as ``[opcode, payload...]`` lists.
        """
        self.server._stream.close()
        var got = List[UInt8]()
        var tmp = List[UInt8](capacity=4096)
        tmp.resize(4096, 0)
        while True:
            var n = self.client.read(tmp.unsafe_ptr(), 4096)
            if n == 0:
                break
            for i in range(n):
                got.append(tmp[i])
        var frames = List[List[UInt8]]()
        var pos = 0
        while pos < len(got):
            var r = WsFrame.decode_one(
                Span[UInt8, _](got[pos:]), max_payload=1 << 20
            )
            var f = List[UInt8]()
            f.append(r.frame.opcode)
            for b in r.frame.payload:
                f.append(b)
            frames.append(f^)
            pos += r.consumed
        return frames^

    def send(mut self, opcode: UInt8, payload: List[UInt8]) raises:
        var wire = WsFrame(opcode=opcode, payload=payload.copy()).encode(
            mask=True
        )
        self.client.write_all(Span[UInt8, _](wire))


def _is_close(f: List[UInt8], code: Int) -> Bool:
    return (
        len(f) >= 3
        and f[0] == WsOpcode.CLOSE
        and Int(f[1]) * 256 + Int(f[2]) == code
    )


def _answers_1002(body: List[UInt8]) raises:
    var p = _Pair()
    p.send(WsOpcode.CLOSE, body)
    var frame = p.server.recv()
    assert_equal(Int(frame.opcode), Int(WsOpcode.CLOSE))
    var out = p.finish()
    assert_equal(len(out), 1)
    assert_true(_is_close(out[0], 1002), "expected one CLOSE 1002")


def test_close_is_echoed_with_its_code() raises:
    var p = _Pair()
    p.send(WsOpcode.CLOSE, _close_body(1001, "bye"))
    var frame = p.server.recv()
    assert_equal(Int(frame.opcode), Int(WsOpcode.CLOSE))
    var out = p.finish()
    assert_equal(len(out), 1)
    assert_true(_is_close(out[0], 1001), "expected one CLOSE 1001")


def test_empty_close_gets_an_empty_close() raises:
    var p = _Pair()
    p.send(WsOpcode.CLOSE, List[UInt8]())
    _ = p.server.recv()
    var out = p.finish()
    assert_equal(len(out), 1)
    assert_equal(Int(out[0][0]), Int(WsOpcode.CLOSE))
    assert_equal(len(out[0]), 1)


def test_one_byte_close_body_is_answered_with_1002() raises:
    var b = List[UInt8]()
    b.append(3)
    _answers_1002(b)


def test_invalid_close_code_is_answered_with_1002() raises:
    _answers_1002(_close_body(1005))
    _answers_1002(_close_body(999))
    _answers_1002(_close_body(5000))


def test_non_utf8_close_reason_is_answered_with_1002() raises:
    var b = _close_body(1000)
    b.append(0xFF)
    _answers_1002(b)


def test_close_then_peer_close_sends_only_one_close() raises:
    var p = _Pair()
    p.server.close()
    p.send(WsOpcode.CLOSE, _close_body(1000))
    var frame = p.server.recv()
    assert_equal(Int(frame.opcode), Int(WsOpcode.CLOSE))
    var out = p.finish()
    assert_equal(len(out), 1)
    assert_true(_is_close(out[0], 1000), "expected exactly the first CLOSE")


def test_close_twice_sends_one_close() raises:
    var p = _Pair()
    p.server.close()
    p.server.close()
    var out = p.finish()
    assert_equal(len(out), 1)


def test_no_data_frame_after_close() raises:
    var p = _Pair()
    p.server.close()
    var refused = 0
    try:
        p.server.send_text("late")
    except:
        refused += 1
    try:
        p.server.send_binary(_bytes("late"))
    except:
        refused += 1
    try:
        p.server.send_frame(WsFrame.text("late"))
    except:
        refused += 1
    assert_equal(refused, 3)
    var out = p.finish()
    assert_equal(len(out), 1)
    assert_equal(Int(out[0][0]), Int(WsOpcode.CLOSE))


def test_no_data_frame_after_replying_to_a_close() raises:
    var p = _Pair()
    p.send(WsOpcode.CLOSE, _close_body(1000))
    _ = p.server.recv()
    var refused = False
    try:
        p.server.send_text("late")
    except:
        refused = True
    assert_true(refused, "send_text after the CLOSE reply must raise")
    var out = p.finish()
    assert_equal(len(out), 1)


def test_data_and_ping_before_close_still_work() raises:
    var p = _Pair()
    p.server.send_text("hi")
    p.send(WsOpcode.PING, _bytes("x"))
    p.send(WsOpcode.TEXT, _bytes("t"))
    var frame = p.server.recv()
    assert_equal(Int(frame.opcode), Int(WsOpcode.TEXT))
    var out = p.finish()
    assert_equal(len(out), 2)
    assert_equal(Int(out[0][0]), Int(WsOpcode.TEXT))
    assert_equal(Int(out[1][0]), Int(WsOpcode.PONG))


def _recv_raises(mut p: _Pair) -> Bool:
    try:
        _ = p.server.recv()
    except:
        return True
    return False


def test_unmasked_client_frame_is_refused_with_close_1002() raises:
    """DOC-02: the refusal of an unmasked frame carries CLOSE 1002."""
    var p = _Pair()
    var wire = WsFrame(opcode=WsOpcode.TEXT, payload=_bytes("hi")).encode(
        mask=False
    )
    p.client.write_all(Span[UInt8, _](wire))
    assert_true(_recv_raises(p), "an unmasked frame must raise")
    var out = p.finish()
    assert_equal(len(out), 1)
    assert_true(_is_close(out[0], 1002), "expected one CLOSE 1002")
    var refused = False
    try:
        p.server.send_text("late")
    except:
        refused = True
    assert_true(refused, "no data may follow the CLOSE")


def test_invalid_utf8_text_frame_is_refused_with_close_1007() raises:
    """DOC-01: a final TEXT frame that is not UTF-8 fails with CLOSE 1007."""
    var p = _Pair()
    var good = List[UInt8]()
    good.append(0x68)
    good.append(0x69)
    p.send(WsOpcode.TEXT, good)
    var first = p.server.recv()
    assert_equal(Int(first.opcode), Int(WsOpcode.TEXT))
    assert_equal(len(first.payload), 2)

    var bad = List[UInt8]()
    bad.append(0xC3)
    bad.append(0x28)
    p.send(WsOpcode.TEXT, bad)
    assert_true(_recv_raises(p), "invalid UTF-8 must raise, not be delivered")
    var out = p.finish()
    assert_equal(len(out), 1)
    assert_true(_is_close(out[0], 1007), "expected one CLOSE 1007")


def test_binary_frame_with_non_utf8_bytes_is_delivered() raises:
    var p = _Pair()
    var bad = List[UInt8]()
    bad.append(0xC3)
    bad.append(0x28)
    p.send(WsOpcode.BINARY, bad)
    var f = p.server.recv()
    assert_equal(Int(f.opcode), Int(WsOpcode.BINARY))
    var out = p.finish()
    assert_equal(len(out), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
