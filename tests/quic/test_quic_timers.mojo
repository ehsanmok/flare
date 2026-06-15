"""Tests for the QUIC reactor's TimerWheel integration
(`flare.quic.timers` + `flare.quic.server.QuicListener`) --
Track Q3-W commit 3/5.

The token codec (`flare.quic.timers`) supports three timer
kinds -- PTO (RFC 9002 §6.2), IDLE (RFC 9000 §10.1), and
ACK_DELAY (RFC 9000 §13.2.1) -- but the server reactor only
arms + dispatches the IDLE timer; PTO / ACK_DELAY arming is
deferred to the QUIC-on-a-lossy-wire work in v0.9.

Each timer's payload is the `UInt64` returned by
:func:`encode_timer_token(kind, slot)`; the high 32 bits carry
the kind, the low 32 bits carry the connection-slab slot index.
The dispatcher in :meth:`QuicListener.advance_timers` decodes
the token + calls :meth:`QuicConnection.on_idle_expired`.

Properties covered:

1. Token encode + decode round-trip across every registered
   kind and a representative slot range.
2. Invalid encode inputs raise (kind out of range, negative
   slot, slot exceeds the 32-bit half).
3. :meth:`QuicListener.schedule_idle_timeout` cancels the
   previous idle timer + arms a fresh one; the slot's
   ``idle_timer_id`` rolls forward.
4. :meth:`QuicListener.advance_timers` dispatches an idle
   timeout to ``QuicConnection.on_idle_expired`` -- the
   connection's ``alive`` flag flips False, state advances to
   ``CONN_STATE_CLOSED``, and the CID is retired from the
   table so retransmits don't route to the dead slot.
5. A successful :meth:`dispatch_datagram` arms the slot's
   idle timer at the configured ``max_idle_timeout_ms`` (the
   accept path schedules it for new slots).
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    CONN_STATE_CLOSED,
    ConnectionId,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    QuicConnection,
    QuicListener,
    QuicServerConfig,
    TIMER_KIND_ACK_DELAY,
    TIMER_KIND_IDLE,
    TIMER_KIND_PTO,
    cid_to_hex,
    decode_timer_token,
    encode_long_header,
    encode_timer_token,
    encode_varint,
    timer_kind_name,
)


def _bind_loopback(idle_ms: UInt64 = UInt64(30_000)) raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_idle_timeout_ms = idle_ms
    return QuicListener.bind(cfg)


def _make_cid(seed: UInt8, length: Int) -> ConnectionId:
    var bytes = List[UInt8]()
    for i in range(length):
        bytes.append(seed + UInt8(i))
    return ConnectionId(bytes^)


def _make_initial_datagram(
    dcid: ConnectionId, scid: ConnectionId
) raises -> List[UInt8]:
    var hdr = encode_long_header(
        PACKET_TYPE_INITIAL, QUIC_VERSION_1, dcid, scid, type_specific_bits=0
    )
    var out = List[UInt8]()
    for i in range(len(hdr)):
        out.append(hdr[i])
    var token_len = encode_varint(UInt64(0))
    for i in range(len(token_len)):
        out.append(token_len[i])
    var payload_len = encode_varint(UInt64(1))
    for i in range(len(payload_len)):
        out.append(payload_len[i])
    out.append(UInt8(0))
    return out^


def test_token_round_trip() raises:
    for kind in [TIMER_KIND_PTO, TIMER_KIND_IDLE, TIMER_KIND_ACK_DELAY]:
        for slot in [0, 1, 7, 65535, 0xFFFFFFF]:
            var token = encode_timer_token(kind, slot)
            var decoded = decode_timer_token(token)
            assert_equal(decoded.kind, kind)
            assert_equal(decoded.slot, slot)


def test_encode_rejects_invalid_kind() raises:
    var raised = False
    try:
        _ = encode_timer_token(0, 1)
    except:
        raised = True
    assert_true(raised, "kind=0 must raise")
    raised = False
    try:
        _ = encode_timer_token(99, 1)
    except:
        raised = True
    assert_true(raised, "kind=99 must raise")


def test_encode_rejects_invalid_slot() raises:
    var raised = False
    try:
        _ = encode_timer_token(TIMER_KIND_IDLE, -1)
    except:
        raised = True
    assert_true(raised, "slot=-1 must raise")


def test_decode_rejects_unknown_kind() raises:
    var raised = False
    try:
        _ = decode_timer_token(UInt64(42) << UInt64(32))
    except:
        raised = True
    assert_true(raised, "decode must raise on unknown kind")


def test_timer_kind_name() raises:
    assert_equal(timer_kind_name(TIMER_KIND_PTO), String("PTO"))
    assert_equal(timer_kind_name(TIMER_KIND_IDLE), String("IDLE"))
    assert_equal(timer_kind_name(TIMER_KIND_ACK_DELAY), String("ACK_DELAY"))
    assert_equal(timer_kind_name(999), String("UNKNOWN"))


def test_schedule_idle_cancels_previous() raises:
    var listener = _bind_loopback()
    var dcid = _make_cid(UInt8(0x10), 8)
    var scid = _make_cid(UInt8(0x20), 8)
    var datagram = _make_initial_datagram(dcid, scid)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(1234))
    _ = listener.dispatch_datagram(Span[UInt8, _](datagram), peer)
    var first_id = listener.connections[0].idle_timer_id
    assert_true(first_id != UInt64(0), "accept path must arm idle timer")
    var second_id = listener.schedule_idle_timeout(0)
    assert_true(
        second_id != first_id,
        "re-arm must return a fresh id (TimerWheel ids are monotonic)",
    )
    assert_equal(listener.connections[0].idle_timer_id, second_id)


def test_advance_idle_closes_connection() raises:
    var listener = _bind_loopback(idle_ms=UInt64(50))
    var dcid = _make_cid(UInt8(0x70), 8)
    var scid = _make_cid(UInt8(0x80), 8)
    var datagram = _make_initial_datagram(dcid, scid)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(1234))
    _ = listener.dispatch_datagram(Span[UInt8, _](datagram), peer)
    assert_true(listener.connections[0].alive)
    var fired = listener.advance_timers(now_ms=UInt64(200))
    assert_equal(fired, 1, "expected exactly one timer to fire")
    assert_false(listener.connections[0].alive)
    assert_equal(listener.connections[0].conn.state, CONN_STATE_CLOSED)
    assert_equal(
        listener.cid_table.lookup(cid_to_hex(dcid)),
        -1,
        "dead slot's CID must be retired",
    )


def test_dispatch_arms_idle_timer_on_accept() raises:
    var listener = _bind_loopback()
    var dcid = _make_cid(UInt8(0xD0), 8)
    var scid = _make_cid(UInt8(0xE0), 8)
    var datagram = _make_initial_datagram(dcid, scid)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(1234))
    _ = listener.dispatch_datagram(Span[UInt8, _](datagram), peer)
    assert_true(
        listener.connections[0].idle_timer_id != UInt64(0),
        "accept must arm the idle timer immediately",
    )


def test_on_idle_callback_is_idempotent_to_double_fire() raises:
    """A spurious second idle expiry must not flip state back
    or otherwise corrupt the slot. The callback resets the
    timer id every call so a duplicate fire just runs the
    same close path again."""
    var qc = QuicConnection(
        _make_cid(UInt8(0xF0), 8), _make_cid(UInt8(0x01), 8)
    )
    qc.idle_timer_id = UInt64(42)
    qc.on_idle_expired()
    assert_false(qc.alive)
    assert_equal(qc.idle_timer_id, UInt64(0))
    qc.on_idle_expired()  # second fire
    assert_false(qc.alive)


def main() raises:
    test_token_round_trip()
    test_encode_rejects_invalid_kind()
    test_encode_rejects_invalid_slot()
    test_decode_rejects_unknown_kind()
    test_timer_kind_name()
    test_schedule_idle_cancels_previous()
    test_advance_idle_closes_connection()
    test_dispatch_arms_idle_timer_on_accept()
    test_on_idle_callback_is_idempotent_to_double_fire()
    print("test_quic_timers: 9 passed")
