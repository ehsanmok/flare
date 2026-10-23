"""ACK_FREQUENCY and IMMEDIATE_ACK (draft-ietf-quic-ack-frequency).

Both frames were FRAME_ENCODING_ERRORs, and neither end advertised
``min_ack_delay``, so a peer could not ask flare to acknowledge less
often (fewer ACKs on a bulk upload). Now both ends advertise it and
honour the peer's threshold and delay; IMMEDIATE_ACK is answered at
once.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.quic.client import QuicClientConnection
from flare.quic.frame import (
    AckFrequencyFrame,
    encode_ack_frequency,
    encode_immediate_ack,
    encode_ping,
)
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import (
    MIN_ACK_DELAY_US,
    ack_due,
    empty_events,
    handle_frame_buf,
    new_connection,
    note_ack_eliciting,
)
from flare.quic.transport_params import (
    decode_transport_parameters,
    empty_transport_parameters,
    encode_transport_parameters,
)
from flare.quic._server_support import _monotonic_ms
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _freq(seq: Int, threshold: Int, delay_us: Int) raises -> List[UInt8]:
    var out = List[UInt8]()
    encode_ack_frequency(
        AckFrequencyFrame(UInt64(seq), UInt64(threshold), UInt64(delay_us), 1),
        out,
    )
    return out^


def test_min_ack_delay_round_trips() raises:
    var tp = empty_transport_parameters()
    tp.min_ack_delay = Optional(UInt64(1000))
    var back = decode_transport_parameters(
        Span[UInt8, _](encode_transport_parameters(tp))
    )
    assert_equal(back.min_ack_delay.value(), UInt64(1000))


def test_state_applies_the_request() raises:
    var conn = new_connection()
    var events = empty_events()
    var f = _freq(5, 3, 50_000)
    _ = handle_frame_buf(conn, Span[UInt8, _](f), UInt64(0), events)
    assert_true(conn.ack_freq_set)
    assert_equal(conn.ack_threshold, UInt64(3))
    for i in range(3):
        note_ack_eliciting(conn, UInt64(i))
        assert_false(ack_due(conn, UInt64(i)), "under the threshold")
    note_ack_eliciting(conn, UInt64(10))
    assert_true(ack_due(conn, UInt64(10)), "past the threshold")
    var older = _freq(4, 99, 50_000)
    _ = handle_frame_buf(conn, Span[UInt8, _](older), UInt64(0), events)
    assert_equal(conn.ack_threshold, UInt64(3), "an older request is ignored")
    var imm = List[UInt8]()
    encode_immediate_ack(imm)
    _ = handle_frame_buf(conn, Span[UInt8, _](imm), UInt64(0), events)
    assert_true(conn.ack_immediate)
    var low = _freq(6, 3, Int(MIN_ACK_DELAY_US) - 1)
    var raised = False
    try:
        _ = handle_frame_buf(conn, Span[UInt8, _](low), UInt64(0), events)
    except:
        raised = True
    assert_true(raised, "a delay below min_ack_delay is refused")


def _ms_to_ack(
    mut listener: QuicListener,
    mut quic: QuicClientConnection,
    var frames: List[UInt8],
) raises -> Int:
    """Send ``frames`` (ack-eliciting) and time the server's ACK."""
    quic._send_padded_1rtt(frames^, ack_eliciting=True)
    var t0 = _monotonic_ms()
    while _monotonic_ms() - t0 < 2_000:
        _ = listener.tick(timeout_ms=5)
        _ = listener.drain_all_egress()
        _ = listener.advance_timers(_monotonic_ms())
        if len(quic.poll(timeout_ms=5).acked_ranges) > 0:
            return Int(_monotonic_ms() - t0)
    return -1


def test_server_holds_acks_as_asked() raises:
    var alpn = List[String]()
    alpn.append(String("h3"))
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = alpn.copy()
    var listener = QuicListener.bind(cfg)
    var quic = QuicClientConnection.start(
        listener.local_addr(),
        RustlsQuicConnector(Path(_FIXDIR + "ca.pem").read_text(), alpn^),
        String("localhost"),
    )
    for _ in range(60):
        _ = listener.tick(timeout_ms=10)
        _ = listener.drain_all_egress()
        _ = quic.poll(timeout_ms=10)
    assert_true(quic.is_established())
    # Ask for an ACK only every 100 packets or 300 ms.
    var held = _ms_to_ack(listener, quic, _freq(0, 100, 300_000))
    assert_true(held >= 250, "acked after " + String(held) + " ms")
    var imm = List[UInt8]()
    encode_immediate_ack(imm)
    var now = _ms_to_ack(listener, quic, imm^)
    assert_true(now >= 0 and now < 100, "IMMEDIATE_ACK took " + String(now))
    listener.close()
    quic.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
