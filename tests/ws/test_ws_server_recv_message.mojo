"""``WsConnection.recv_message`` reassembles fragmented messages
(RFC 6455 sec 5.4) on the server side, the gap behind every remaining
Autobahn section 5, 6, 7.1.5, 9.3/9.4 and 10 failure.

The server end is a ``WsConnection`` over a loopback TCP pair; the test
plays the client with raw masked frames.
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.ws import WsFrame, WsOpcode
from flare.ws.server import WsConnection


struct _Pair(Movable):
    var server: WsConnection
    var client: TcpStream

    def __init__(out self) raises:
        var ln = TcpListener.bind(SocketAddr.localhost(0))
        self.client = TcpStream.connect(
            SocketAddr.localhost(ln.local_addr().port)
        )
        self.client.set_recv_timeout(3000)
        var s = ln.accept()
        var peer = s.peer_addr()
        self.server = WsConnection(s^, peer)
        ln.close()

    def send(
        mut self, opcode: UInt8, payload: List[UInt8], fin: Bool = True
    ) raises:
        var wire = WsFrame(opcode=opcode, payload=payload, fin=fin).encode(
            mask=True
        )
        self.client.write_all(Span[UInt8, _](wire))

    def close_code(mut self) raises -> Int:
        """The code of the CLOSE the server wrote (0 if none)."""
        self.server._stream.close()
        var got = List[UInt8]()
        var tmp = List[UInt8](length=4096, fill=0)
        while True:
            var n = self.client.read(tmp.unsafe_ptr(), 4096)
            if n == 0:
                break
            got.extend(Span[UInt8, _](tmp)[:n])
        if len(got) < 4 or (got[0] & 0x0F) != WsOpcode.CLOSE:
            return 0
        return Int(got[2]) * 256 + Int(got[3])


def _b(s: String) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def test_fragmented_text_is_reassembled_across_a_split_code_point() raises:
    var p = _Pair()
    var hello = _b("héllo")  # 0xC3 0xA9 split across fragments
    p.send(WsOpcode.TEXT, List[UInt8](Span[UInt8, _](hello)[:2]), fin=False)
    p.send(WsOpcode.PING, _b("p"))
    p.send(WsOpcode.CONTINUATION, List[UInt8](Span[UInt8, _](hello)[2:]))
    var msg = p.server.recv_message()
    assert_true(msg.is_text)
    assert_equal(msg.as_text(), "héllo")


def test_fragmented_binary_is_reassembled() raises:
    var p = _Pair()
    p.send(WsOpcode.BINARY, _b("ab"), fin=False)
    p.send(WsOpcode.CONTINUATION, _b("cd"), fin=False)
    p.send(WsOpcode.CONTINUATION, _b("ef"))
    var msg = p.server.recv_message()
    assert_false(msg.is_text)
    assert_equal(len(msg.as_binary()), 6)


def test_stray_continuation_fails_with_1002() raises:
    var p = _Pair()
    p.send(WsOpcode.CONTINUATION, _b("x"))
    var raised = False
    try:
        _ = p.server.recv_message()
    except:
        raised = True
    assert_true(raised)
    assert_equal(p.close_code(), 1002)


def test_new_message_inside_a_fragmented_one_fails_with_1002() raises:
    var p = _Pair()
    p.send(WsOpcode.TEXT, _b("a"), fin=False)
    p.send(WsOpcode.TEXT, _b("b"))
    var raised = False
    try:
        _ = p.server.recv_message()
    except:
        raised = True
    assert_true(raised)
    assert_equal(p.close_code(), 1002)


def test_invalid_utf8_across_fragments_fails_with_1007() raises:
    var p = _Pair()
    var bad = List[UInt8]()
    bad.append(0xC3)
    p.send(WsOpcode.TEXT, bad, fin=False)
    var bad2 = List[UInt8]()
    bad2.append(0x28)
    p.send(WsOpcode.CONTINUATION, bad2)
    var raised = False
    try:
        _ = p.server.recv_message()
    except:
        raised = True
    assert_true(raised)
    assert_equal(p.close_code(), 1007)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
