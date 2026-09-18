"""Server-side RFC 9002 loss recovery: the per-slot slab and its wiring.

Before this, the QUIC server never read an inbound ACK frame. The
decoder had always produced them -- ``flare.quic.state.handle_frame_buf``
fills ``ConnectionEvents.acked_packets`` for both peers -- but the
server dropped the field on the floor. On a lossless loopback that is
invisible; on a real path a dropped response was never retransmitted and
the connection stalled until the RFC 9000 sec 10.1 idle timeout, 30 s by
default, killed it.

These cover the parts that do not need a completed TLS handshake: that
the ``loss`` slab stays in lockstep with ``connections``, that the state
machine behind it behaves per RFC 9002 when driven through the slab, and
that ``max_pto_count`` is wired. The live retransmit path over a real
handshake is exercised by the h3 client suite.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import QuicListener, QuicServerConfig
from flare.quic._loss_recovery import LossRecovery


def _bind_listener() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    return QuicListener.bind(cfg)


def _frames(tag: UInt8) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(tag)
    out.append(tag)
    return out^


def test_loss_slab_starts_empty_and_parallels_connections() raises:
    var listener = _bind_listener()
    assert_equal(len(listener.loss), 0)
    assert_equal(len(listener.loss), listener.connection_count())
    listener.close()


def test_max_pto_count_has_a_bounded_default() raises:
    """A dark peer must not be probed forever.

    LossRecovery caps the backoff at 64x the base interval but nothing
    caps the attempt count, so without this the server would keep
    re-arming against a peer that has gone silent.
    """
    var cfg = QuicServerConfig()
    assert_equal(cfg.max_pto_count, 10)
    assert_true(
        cfg.max_pto_count > 6,
        (
            "must sit past the 6-shift backoff cap so a slow-but-live path"
            " is not punished"
        ),
    )


def test_slab_tracks_sent_packets_and_retires_them_on_ack() raises:
    """The slab is live state, not a placeholder.

    LossRecovery is Movable but not Copyable, so every other per-slot
    slab's `.copy()` idiom is unavailable here; this also pins that
    reading through the subscript works.
    """
    var listener = _bind_listener()
    listener.loss.append(LossRecovery())

    listener.loss[0].on_sent(UInt64(0), _frames(0xA0), UInt64(1000))
    listener.loss[0].on_sent(UInt64(1), _frames(0xA1), UInt64(1001))
    assert_equal(listener.loss[0].outstanding(), 2)

    var acked = List[UInt64]()
    acked.append(UInt64(0))
    _ = listener.loss[0].on_ack(acked, UInt64(1010))
    assert_equal(listener.loss[0].outstanding(), 1)

    # A PTO is owed while anything is still in flight.
    assert_true(listener.loss[0].pto_deadline() != UInt64(0))
    listener.close()


def test_pto_fires_frames_for_retransmission() raises:
    """fire_pto hands back the frames of the oldest unacked packet.

    That list is what _on_pto_expired re-sends, under a fresh packet
    number: RFC 9002 retransmits frames, not packets.
    """
    var listener = _bind_listener()
    listener.loss.append(LossRecovery())
    listener.loss[0].on_sent(UInt64(7), _frames(0xC3), UInt64(1000))

    var probe = listener.loss[0].fire_pto()
    assert_equal(len(probe), 2)
    assert_equal(probe[0], UInt8(0xC3))
    assert_equal(listener.loss[0].pto_count, 1)
    listener.close()


def test_ack_of_everything_disarms_the_timer() raises:
    """With nothing in flight there is no deadline to arm.

    _rearm_pto_timer reads exactly this to decide whether to schedule.
    """
    var listener = _bind_listener()
    listener.loss.append(LossRecovery())
    listener.loss[0].on_sent(UInt64(0), _frames(0x11), UInt64(1000))
    var acked = List[UInt64]()
    acked.append(UInt64(0))
    _ = listener.loss[0].on_ack(acked, UInt64(1005))
    assert_equal(listener.loss[0].outstanding(), 0)
    assert_equal(listener.loss[0].pto_deadline(), UInt64(0))
    listener.close()


def main() raises:
    test_loss_slab_starts_empty_and_parallels_connections()
    test_max_pto_count_has_a_bounded_default()
    test_slab_tracks_sent_packets_and_retires_them_on_ack()
    test_pto_fires_frames_for_retransmission()
    test_ack_of_everything_disarms_the_timer()
    print("test_quic_server_loss_recovery: 5 passed")
