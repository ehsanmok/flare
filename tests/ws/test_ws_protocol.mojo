"""Tests for the sans-I/O WebSocket protocol core (``flare.ws.protocol``)."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true
from std.time import perf_counter_ns

from flare.ws import WsFrame, WsOpcode
from flare.ws.frame import ws_frame_length
from flare.ws.protocol import (
    WS_EVENT_CLOSED,
    WS_EVENT_MESSAGE,
    WsProtocol,
)


def _masked(
    op: UInt8, var payload: List[UInt8], fin: Bool = True
) raises -> List[UInt8]:
    var f = WsFrame(opcode=op, payload=payload^)
    f.fin = fin
    return f.encode(mask=True)


def _bytes(s: String) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def _sent_close_code(p: WsProtocol) raises -> Int:
    """The code of the CLOSE frame at the end of ``p.outbox``."""
    var off = 0
    var code = -1
    while off < len(p.outbox):
        var n = ws_frame_length(Span[UInt8, _](p.outbox)[off : len(p.outbox)])
        var r = WsFrame.decode_one(Span[UInt8, _](p.outbox)[off : off + n])
        var f = r^.take_frame()
        if f.opcode == WsOpcode.CLOSE:
            code = 0 if len(f.payload) < 2 else Int(f.payload[0]) * 256 + Int(
                f.payload[1]
            )
        off += n
    return code


def _closed_with(mut p: WsProtocol, code: Int) raises:
    var ev = p.next_event()
    assert_true(Bool(ev))
    assert_equal(ev.value().kind, WS_EVENT_CLOSED)
    assert_equal(ev.value().code, code)
    assert_equal(_sent_close_code(p), code)
    assert_true(p.finished())


def test_text_message_and_ping() raises:
    var p = WsProtocol()
    p.inbox.extend(Span[UInt8, _](_masked(WsOpcode.PING, _bytes("hi"))))
    p.inbox.extend(Span[UInt8, _](_masked(WsOpcode.TEXT, _bytes("hello"))))
    var ev = p.next_event()
    assert_equal(ev.value().kind, WS_EVENT_MESSAGE)
    assert_true(ev.value().is_text)
    assert_equal(String(unsafe_from_utf8=ev.value().payload), "hello")
    var pong = WsFrame.decode_one(Span[UInt8, _](p.outbox)).take_frame()
    assert_equal(Int(pong.opcode), Int(WsOpcode.PONG))
    assert_false(Bool(p.next_event()))


def test_fragments_split_byte_by_byte_reassemble() raises:
    var e = "é".as_bytes()
    var a = _masked(WsOpcode.TEXT, [UInt8(0x61), e[0]], fin=False)
    var b = _masked(WsOpcode.CONTINUATION, [e[1], UInt8(0x62)])
    var wire = a.copy()
    wire.extend(Span[UInt8, _](b))
    var p = WsProtocol()
    var got = 0
    for i in range(len(wire)):
        p.inbox.append(wire[i])
        var ev = p.next_event()
        if ev:
            got += 1
            assert_equal(String(unsafe_from_utf8=ev.value().payload), "aéb")
    assert_equal(got, 1)


def test_a_burst_of_small_frames_is_decoded_in_linear_time() raises:
    """Every decoded frame used to copy the rest of the inbox, so a burst
    of small frames cost time quadratic in its size: 200000 frames took
    seconds."""
    var p = WsProtocol()
    var frame = _masked(WsOpcode.BINARY, _bytes("abcd"))
    for _ in range(200000):
        p.inbox.extend(Span[UInt8, _](frame))
    var t0 = perf_counter_ns()
    var n = 0
    while True:
        var ev = p.next_event()
        if not ev:
            break
        n += 1
    var ms = (perf_counter_ns() - t0) // 1_000_000
    assert_equal(n, 200000)
    assert_true(ms < 1000, "200000 frames took " + String(ms) + " ms")


def test_orphan_continuation_is_1002() raises:
    var p = WsProtocol()
    p.inbox.extend(Span[UInt8, _](_masked(WsOpcode.CONTINUATION, _bytes("x"))))
    _closed_with(p, 1002)


def test_data_frame_inside_a_message_is_1002() raises:
    var p = WsProtocol()
    p.inbox.extend(
        Span[UInt8, _](_masked(WsOpcode.TEXT, _bytes("a"), fin=False))
    )
    p.inbox.extend(Span[UInt8, _](_masked(WsOpcode.BINARY, _bytes("b"))))
    _closed_with(p, 1002)


def test_unmasked_frame_is_1002() raises:
    var p = WsProtocol()
    p.inbox.extend(Span[UInt8, _](WsFrame.text("x").encode(mask=False)))
    _closed_with(p, 1002)


def test_invalid_utf8_is_1007() raises:
    var p = WsProtocol()
    p.inbox.extend(
        Span[UInt8, _](_masked(WsOpcode.TEXT, [UInt8(0xC3), UInt8(0x28)]))
    )
    _closed_with(p, 1007)


def test_oversized_frame_is_1009_before_its_payload() raises:
    var p = WsProtocol(max_message=16)
    var wire = _masked(WsOpcode.BINARY, List[UInt8](length=64, fill=UInt8(1)))
    p.inbox.extend(Span[UInt8, _](wire)[:8])
    _closed_with(p, 1009)


def test_oversized_reassembly_is_1009() raises:
    var p = WsProtocol(max_message=16)
    p.inbox.extend(
        Span[UInt8, _](
            _masked(
                WsOpcode.BINARY,
                List[UInt8](length=10, fill=UInt8(1)),
                fin=False,
            )
        )
    )
    p.inbox.extend(
        Span[UInt8, _](
            _masked(
                WsOpcode.CONTINUATION, List[UInt8](length=10, fill=UInt8(1))
            )
        )
    )
    _closed_with(p, 1009)


def test_close_is_answered_once() raises:
    var p = WsProtocol()
    p.inbox.extend(
        Span[UInt8, _](_masked(WsOpcode.CLOSE, [UInt8(0x03), UInt8(0xE8)]))
    )
    _closed_with(p, 1000)
    var raised = False
    try:
        p.send_text("late")
    except:
        raised = True
    assert_true(raised)


def test_reserved_close_code_is_answered_with_1002() raises:
    var p = WsProtocol()
    p.inbox.extend(
        Span[UInt8, _](_masked(WsOpcode.CLOSE, [UInt8(0x03), UInt8(0xEC)]))
    )
    var ev = p.next_event()
    assert_equal(ev.value().kind, WS_EVENT_CLOSED)
    assert_equal(_sent_close_code(p), 1002)


def test_unread_outbox_fails_with_1008() raises:
    var p = WsProtocol(max_outbox=64)
    var raised = False
    try:
        for _ in range(10):
            p.send_binary(List[UInt8](length=16, fill=UInt8(2)))
    except:
        raised = True
    assert_true(raised)
    assert_true(p.failed)
    assert_false(p.wants_input())
    assert_equal(_sent_close_code(p), 1008)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
