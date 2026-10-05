"""The QUIC client connection driver end to end.

Drives :class:`flare.quic.client.QuicClientConnection` against the
real :class:`flare.quic.server.QuicListener` over loopback UDP. The
two sides run in lockstep on one thread -- each ``server.tick`` /
``client.poll`` does a short blocking recv then processes + flushes
egress, so a queued datagram is consumed on the next step without
threads. This proves the full client handshake: client-chosen
Initial DCID, padded ClientHello, server Initial/Handshake decrypt
through rustls, the client Finished flight, 1-RTT promotion, and
``h3`` ALPN negotiation.

Reuses the 2-cert fixture chain from
``tests/tls/fixtures/rustls-quic-client/`` (CA trust anchor +
``localhost`` leaf) so certificate validation passes exactly as in
``test_rustls_quic_client.mojo``.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from std.collections.span import Span

from flare.quic.client import QuicClientConnection
from flare.quic._server_support import _monotonic_ms
from flare.quic.state import (
    CONN_STATE_CLOSED,
    empty_events,
    handle_frame_buf,
    new_connection,
)
from flare.quic._loss_recovery import LossRecovery
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConfig, RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _read_file(path: String) raises -> String:
    return Path(path).read_text()


def _h3_alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _make_connector() raises -> RustlsQuicConnector:
    var ca = _read_file(_FIXDIR + "ca.pem")
    return RustlsQuicConnector(ca^, _h3_alpn())


def _bind_server() raises -> QuicListener:
    var cert = _read_file(_FIXDIR + "cert.pem")
    var key = _read_file(_FIXDIR + "key.pem")
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = cert^
    cfg.rustls_config.private_key_pem = key^
    cfg.rustls_config.alpn_protocols = _h3_alpn()
    return QuicListener.bind(cfg^)


def test_client_handshake_completes() raises:
    """Full loopback QUIC handshake: client driver vs QuicListener,
    h3 negotiated, server tracks exactly one connection."""
    var server = _bind_server()
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )

    var done = False
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            done = True
            break

    assert_true(done, "client handshake should complete over loopback UDP")
    assert_true(client.is_established(), "client must report established")
    assert_equal(client.alpn(), String("h3"))
    assert_equal(server.connection_count(), 1)

    server.close()
    client.close()


def test_client_send_stream_after_handshake() raises:
    """Once established the client can open a bidi stream and ship a
    1-RTT STREAM frame; the server tick consumes it without error.

    The payload here is opaque bytes (real H3/QPACK framing is tested
    separately); this asserts the 1-RTT egress + server ingress path is
    wired, not the H3 semantics."""
    var server = _bind_server()
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete first")

    var sid = client.open_bidi_stream()
    assert_equal(sid, UInt64(0))
    var body = List[UInt8]()
    for b in String("hello-h3c1").as_bytes():
        body.append(b)
    client.send_stream(sid, body, fin=True)

    # Pump a few rounds so the server ingests the STREAM datagram and
    # the client drains the resulting ACK; neither side should raise.
    for _ in range(4):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)

    assert_equal(server.connection_count(), 1)
    server.close()
    client.close()


def _bind_validating_server() raises -> QuicListener:
    var cert = _read_file(_FIXDIR + "cert.pem")
    var key = _read_file(_FIXDIR + "key.pem")
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = cert^
    cfg.rustls_config.private_key_pem = key^
    cfg.rustls_config.alpn_protocols = _h3_alpn()
    cfg.require_address_validation = True
    return QuicListener.bind(cfg^)


def test_client_handshake_through_retry() raises:
    """With server address validation on, the first Initial draws a
    Retry; the client re-sends with the token + server-chosen DCID and
    the handshake still completes (RFC 9000 sec 8.1 both sides)."""
    var server = _bind_validating_server()
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )

    var done = False
    for _ in range(60):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            done = True
            break

    assert_true(done, "handshake must complete through a Retry round-trip")
    assert_true(client.retried, "client must have consumed a Retry")
    assert_equal(client.alpn(), String("h3"))
    assert_equal(server.connection_count(), 1)
    server.close()
    client.close()


def test_stream_control_frames_are_retransmitted_on_pto() raises:
    var server = _bind_server()
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            break
    assert_true(client.is_established())
    var sid = client.open_bidi_stream()
    client.send_stream(sid, List[UInt8](), False)
    for cancel in [False, True]:
        client._loss = LossRecovery()
        var pn = client.tx_1rtt_pn
        if cancel:
            client.cancel_stream(sid)
        else:
            client.release_stream_credit(sid, 1024)
        assert_equal(client.tx_1rtt_pn, pn + 1)
        assert_equal(client._loss.outstanding(), 1)
        var original = client._loss.sent[0].frames.copy()
        # Drop the original datagram and expire its timer without sleeping.
        var dropped = List[UInt8]()
        dropped.resize(2048, 0)
        for _ in range(16):
            try:
                if server._socket.try_recv_from(Span(dropped))[0] <= 0:
                    break
            except:
                break
        client._loss.sent[0].time_ms = 1
        client._check_pto()
        assert_equal(client.tx_1rtt_pn, pn + 2)
        assert_equal(client._loss.pto_count, 1)
        assert_equal(client._loss.outstanding(), 1)
        assert_equal(client._loss.sent[0].pn, pn + 1)
        assert_equal(client._loss.sent[0].frames, original)
    server.close()
    client.close()


def test_cancel_stream_forbids_further_stream_frames() raises:
    """RFC 9000 sec 3.1: no STREAM frames after the sender resets.

    cancel_stream sent RESET_STREAM but changed nothing locally, so a
    later send_stream on the same id happily emitted more data and kept
    advancing send_offsets. A PTO retransmit of that RESET_STREAM would
    then carry a final size different from the one the peer first saw,
    which is a FINAL_SIZE_ERROR on their side.
    """
    var server = _bind_server()
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete first")

    var sid = client.open_bidi_stream()
    var body = List[UInt8]()
    for b in String("partial").as_bytes():
        body.append(b)
    client.send_stream(sid, body, fin=False)
    client.cancel_stream(sid)

    var raised = False
    try:
        var more = List[UInt8]()
        more.append(120)
        client.send_stream(sid, more, fin=True)
    except:
        raised = True
    assert_true(raised, "send_stream after cancel_stream must raise")

    server.close()
    client.close()


def _established_client_with_stream(
    mut server: QuicListener, connector: RustlsQuicConnector
) raises -> Tuple[QuicClientConnection, UInt64]:
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete first")
    var sid = client.open_bidi_stream()
    var body: List[UInt8] = [0x41]
    client.send_stream(sid, body, fin=False)
    return (client^, sid)


def _feed_frames(
    mut client: QuicClientConnection, var payload: List[UInt8]
) raises:
    var ev = empty_events()
    client._dispatch_frames(Span[UInt8, _](payload), ev)


def test_stream_reset_survives_a_following_stop_sending() raises:
    """QUIC-18 case A: a server abandoning a request sends RESET_STREAM and
    STOP_SENDING; stream_reset (polled by the H3 client to fail the
    response) must stay true after the STOP_SENDING."""
    var server = _bind_server()
    var connector = _make_connector()
    var pair = _established_client_with_stream(server, connector)
    ref client = pair[0]
    var sid = pair[1]
    assert_true(not client.stream_reset(sid))
    # RESET_STREAM(sid, err 0, final size 0), STOP_SENDING(sid, err 0).
    var frames: List[UInt8] = [
        0x04,
        UInt8(sid),
        0x00,
        0x00,
        0x05,
        UInt8(sid),
        0x00,
    ]
    _feed_frames(client, frames^)
    assert_true(client.stream_reset(sid), "RESET_STREAM hidden by STOP_SENDING")
    server.close()
    client.close()


def test_send_stays_refused_after_cancel_then_peer_reset() raises:
    """QUIC-18 case B: after cancel_stream the peer's RESET_STREAM must not
    re-open the send half (RFC 9000 sec 3.1)."""
    var server = _bind_server()
    var connector = _make_connector()
    var pair = _established_client_with_stream(server, connector)
    ref client = pair[0]
    var sid = pair[1]
    client.cancel_stream(sid)
    var frames: List[UInt8] = [0x04, UInt8(sid), 0x00, 0x00]
    _feed_frames(client, frames^)
    var raised = False
    try:
        var more: List[UInt8] = [0x42]
        client.send_stream(sid, more, fin=False)
    except e:
        raised = "reset stream" in String(e)
    assert_true(raised, "send_stream must stay refused after our reset")
    assert_true(client.stream_reset(sid))
    server.close()
    client.close()


def _client_with_idle(
    mut server: QuicListener,
    connector: RustlsQuicConnector,
    idle_ms: UInt64,
) raises -> QuicClientConnection:
    var client = QuicClientConnection.start(
        server.local_addr(),
        connector,
        String("localhost"),
        max_idle_timeout_ms=idle_ms,
    )
    for _ in range(60):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete first")
    for _ in range(4):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
    return client^


def _poll_until_closed(
    mut client: QuicClientConnection, within_ms: UInt64
) raises -> Bool:
    var start = _monotonic_ms()
    while _monotonic_ms() - start < within_ms:
        var ev = client.poll(timeout_ms=50)
        if ev.connection_closed:
            return True
    return False


def test_client_closes_after_its_idle_timeout() raises:
    """QUIC-21 (RFC 9000 sec 10.1): a client whose peer went silent closes
    the connection once the idle timeout has elapsed, reporting it through
    ``connection_closed``; before this poll never checked a timer."""
    var server = _bind_server()
    var connector = _make_connector()
    var client = _client_with_idle(server, connector, UInt64(1_000))
    # The server stops running: nothing more arrives.
    assert_true(
        _poll_until_closed(client, UInt64(4_000)),
        "client never closed the idle connection",
    )
    assert_false(client.is_established())
    assert_equal(client.conn.state, CONN_STATE_CLOSED)
    server.close()
    client.close()


def test_client_uses_the_servers_shorter_idle_timeout() raises:
    """The effective timeout is the minimum of both advertised values: the
    client asks for 30 s, the server for 1 s."""
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_idle_timeout_ms = UInt64(1_000)
    cfg.rustls_config.cert_chain_pem = _read_file(_FIXDIR + "cert.pem")
    cfg.rustls_config.private_key_pem = _read_file(_FIXDIR + "key.pem")
    cfg.rustls_config.alpn_protocols = _h3_alpn()
    var server = QuicListener.bind(cfg^)
    var connector = _make_connector()
    var client = _client_with_idle(server, connector, UInt64(30_000))
    assert_true(
        _poll_until_closed(client, UInt64(4_000)),
        "the server's 1000 ms idle timeout was ignored",
    )
    server.close()
    client.close()


def test_client_idle_timer_restarts_on_processed_packets() raises:
    """Traffic the peer answers keeps the connection open: a PING every
    300 ms (answered by an ACK) holds a 1000 ms timeout open for 2.5 s."""
    var server = _bind_server()
    var connector = _make_connector()
    var client = _client_with_idle(server, connector, UInt64(1_000))
    var start = _monotonic_ms()
    var last_ping = start
    while _monotonic_ms() - start < UInt64(2_500):
        if _monotonic_ms() - last_ping >= UInt64(300):
            client.keepalive()
            last_ping = _monotonic_ms()
        _ = server.tick(timeout_ms=20)
        var ev = client.poll(timeout_ms=20)
        assert_false(ev.connection_closed, "closed while the peer answered")
    assert_true(client.is_established())
    server.close()
    client.close()


def _server_stream_peer_reset(server: QuicListener, sid: UInt64) raises -> Bool:
    for i in range(len(server.connections)):
        if server.slot_free[i]:
            continue
        if sid in server.connections[i].conn.streams:
            return server.connections[i].conn.streams[sid].peer_reset
    return False


def test_stop_sending_is_answered_with_reset_stream() raises:
    """QUIC-19, RFC 9000 sec 3.5: STOP_SENDING for a stream in the Send
    state must be answered with RESET_STREAM; the server sees the reset,
    and a repeated STOP_SENDING does not produce a second one."""
    var server = _bind_server()
    var connector = _make_connector()
    var pair = _established_client_with_stream(server, connector)
    ref client = pair[0]
    var sid = pair[1]
    for _ in range(4):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
    assert_false(
        _server_stream_peer_reset(server, sid), "no reset before STOP_SENDING"
    )
    # STOP_SENDING(sid, error 0x33).
    var stop: List[UInt8] = [0x05, UInt8(sid), 0x33]
    _feed_frames(client, stop.copy())
    for _ in range(6):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
    assert_true(
        _server_stream_peer_reset(server, sid),
        "the server must receive RESET_STREAM after STOP_SENDING",
    )
    var more: List[UInt8] = [120]
    var raised = False
    try:
        client.send_stream(sid, more, fin=False)
    except:
        raised = True
    assert_true(raised, "no STREAM data after the reset")
    server.close()
    client.close()


def test_stop_sending_reply_is_listed_once_per_stream() raises:
    """The state machine lists a STOP_SENDING that needs a RESET_STREAM
    (stream in Send or not yet seen) and stays silent once the send half
    is reset (RFC 9000 sec 3.1: the reply is sent once)."""
    var conn = new_connection()
    var ev = empty_events()
    var data: List[UInt8] = [
        0x0A,
        0x04,
        0x01,
        0x41,
    ]  # STREAM id 4, len 1, no FIN
    _ = handle_frame_buf(conn, Span[UInt8, _](data), UInt64(1_000), ev)
    var stop: List[UInt8] = [0x05, 0x04, 0x07]
    var ev1 = empty_events()
    _ = handle_frame_buf(conn, Span[UInt8, _](stop), UInt64(2_000), ev1)
    assert_equal(len(ev1.stop_sending_resets), 1)
    assert_equal(ev1.stop_sending_resets[0].stream_id, UInt64(4))
    assert_equal(ev1.stop_sending_resets[0].application_error_code, UInt64(7))
    var ev2 = empty_events()
    _ = handle_frame_buf(conn, Span[UInt8, _](stop), UInt64(3_000), ev2)
    assert_equal(len(ev2.stop_sending_resets), 0)
    # A stream not seen yet is in Ready: the reply is required there too.
    var other: List[UInt8] = [0x05, 0x08, 0x01]
    var ev3 = empty_events()
    _ = handle_frame_buf(conn, Span[UInt8, _](other), UInt64(4_000), ev3)
    assert_equal(len(ev3.stop_sending_resets), 1)


def main() raises:
    test_client_handshake_completes()
    test_client_send_stream_after_handshake()
    test_client_handshake_through_retry()
    test_stream_control_frames_are_retransmitted_on_pto()
    test_cancel_stream_forbids_further_stream_frames()
    test_stream_reset_survives_a_following_stop_sending()
    test_send_stays_refused_after_cancel_then_peer_reset()
    test_client_closes_after_its_idle_timeout()
    test_client_uses_the_servers_shorter_idle_timeout()
    test_client_idle_timer_restarts_on_processed_packets()
    test_stop_sending_is_answered_with_reset_stream()
    test_stop_sending_reply_is_listed_once_per_stream()
    print("test_quic_client: 12 passed")
