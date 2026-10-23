"""Path-MTU discovery (RFC 9000 sec 14.3, RFC 8899).

Both ends used to fill datagrams to their configured 1452 bytes from
the first packet, unvalidated, and the server ignored the client's
``max_udp_payload_size``; a path with a smaller MTU black-holed every
full-size packet. Now a path starts at 1200 and grows only as probes
are acknowledged, up to the smaller of the two ends' limits.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true

from flare.quic._pmtud import PMTU_BASE, PmtuDiscovery, _Split, split_frames
from flare.quic.frame import (
    StreamFrame,
    encode_max_data,
    MaxDataFrame,
    encode_stream,
    parse_frame_into,
)
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _acked(pn: UInt64) -> List[UInt64]:
    var r = List[UInt64]()
    r.append(pn)
    r.append(pn)
    return r^


def test_search_tries_the_ceiling_then_bisects() raises:
    var pm = PmtuDiscovery()
    assert_equal(pm.want_probe(0), 0, "nothing to probe before the ceiling")
    pm.set_ceiling(1452)
    assert_equal(pm.want_probe(0), 1452)
    for i in range(3):  # three unanswered probes rule 1452 out
        pm.on_probe_sent(UInt64(i), 1452, 0)
        pm.check_lost(1000, 100)
    assert_equal(pm.current, PMTU_BASE)
    var mid = pm.want_probe(0)
    assert_equal(mid, (1200 + 1451 + 1) // 2)
    pm.on_probe_sent(9, mid, 0)
    pm.on_acked(_acked(8))
    assert_equal(pm.current, PMTU_BASE, "another packet's ACK")
    pm.on_acked(_acked(9))
    assert_equal(pm.current, mid)
    while pm.want_probe(0) != 0:  # bisect down to under 20 bytes
        var s = pm.want_probe(0)
        pm.on_probe_sent(10, s, 0)
        pm.on_acked(_acked(10))
    assert_true(pm.ceiling - pm.current < 20 + 1)


def test_a_black_hole_falls_back_and_retries_later() raises:
    var pm = PmtuDiscovery()
    pm.set_ceiling(1452)
    pm.on_probe_sent(1, 1452, 0)
    pm.on_acked(_acked(1))
    assert_equal(pm.current, 1452)
    pm.on_black_hole(1000)
    assert_equal(pm.current, PMTU_BASE)
    assert_equal(pm.want_probe(1000), 0, "no probing right after")
    assert_equal(pm.want_probe(1000 + 60_000), 1452)


def test_lost_frames_are_split_to_the_smaller_size() raises:
    """A 3000-byte STREAM frame lost at a 3100-byte path is re-sent as
    pieces that fit 1136 bytes, in order, FIN on the last only; PADDING is
    dropped, other frames ride along whole."""
    var lost = List[UInt8]()
    encode_max_data(MaxDataFrame(maximum_data=99), lost)
    encode_stream(
        StreamFrame(
            stream_id=4,
            offset=100,
            data=List[UInt8](length=3000, fill=7),
            fin=True,
        ),
        lost,
    )
    lost.resize(len(lost) + 50, 0)  # PADDING
    var parts = split_frames(Span[UInt8, _](lost), 1136)
    var next_off = UInt64(100)
    var fins = 0
    var frames = 0
    for i in range(len(parts)):
        assert_true(len(parts[i]) <= 1136)
        var pos = 0
        while pos < len(parts[i]):
            var h = _Split()
            pos += parse_frame_into(Span[UInt8, _](parts[i])[pos:], h)
            assert_true(not h.padding, "padding is not re-sent")
            frames += 1
            if h.stream:
                ref sf = h.stream.value()
                assert_equal(sf.offset, next_off)
                next_off += UInt64(len(sf.data))
                fins += 1 if sf.fin else 0
    assert_equal(next_off, UInt64(3100), "every byte, in order")
    assert_equal(fins, 1)
    assert_equal(frames, 4, "MAX_DATA and three STREAM pieces")


def test_both_ends_validate_up_to_the_smaller_limit() raises:
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
        max_udp_payload_size=1350,
    )
    for _ in range(60):
        _ = listener.tick(timeout_ms=10)
        _ = listener.drain_all_egress()
        _ = quic.poll(timeout_ms=10)
        if (
            quic.is_established()
            and listener.connections[0].pmtu.probe_size == 0
            and listener.connections[0].pmtu.current > PMTU_BASE
            and quic._pmtu.current > PMTU_BASE
        ):
            break
    # The server keeps to the client's advertised 1350; the client may
    # use the server's 1452.
    assert_equal(listener.connections[0].pmtu.ceiling, 1350)
    assert_true(listener.connections[0].pmtu.current > 1330)
    assert_true(quic._pmtu.current > 1330)
    assert_true(quic._pmtu.current <= 1350, "client limited by its own 1350")
    listener.close()
    quic.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
