"""Version Negotiation (RFC 9000 sec 6).

A long-header packet of an unknown version gets a Version Negotiation
listing QUIC v1, with the client's CIDs echoed swapped; a short one (an
amplification vector) and a Version Negotiation packet get nothing.
"""

from std.testing import TestSuite, assert_equal, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic.server import QuicListener, QuicServerConfig
from flare.udp import UdpSocket


def _listener() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    return QuicListener.bind(cfg)


def _probe(version: UInt32, size: Int) -> List[UInt8]:
    """Long header: version, an 8-byte DCID of 0xAA, a 4-byte SCID of
    0xBB, padded to ``size``."""
    var d = List[UInt8]()
    d.append(UInt8(0xC0))
    for shift in [24, 16, 8, 0]:
        d.append(UInt8((Int(version) >> shift) & 0xFF))
    d.append(UInt8(8))
    for _ in range(8):
        d.append(UInt8(0xAA))
    d.append(UInt8(4))
    for _ in range(4):
        d.append(UInt8(0xBB))
    d.resize(size, UInt8(0))
    return d^


def _exchange(version: UInt32, size: Int) raises -> List[UInt8]:
    var server = _listener()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    _ = client.send_to(
        Span[UInt8, _](_probe(version, size)), server.local_addr()
    )
    _ = server.tick(timeout_ms=50)
    client.set_recv_timeout(50)
    var buf = List[UInt8](length=1500, fill=0)
    var got = 0
    try:
        got = client.recv_from(Span[UInt8, _](buf))[0]
    except:
        pass
    server.close()
    buf.resize(got, 0)
    return buf^


def test_unknown_version_gets_version_negotiation() raises:
    var vn = _exchange(UInt32(0x0A0A0A0A), 1200)
    assert_true(len(vn) >= 7 + 4 + 8 + 4, "no Version Negotiation")
    assert_equal(Int(vn[1]) | Int(vn[2]) | Int(vn[3]) | Int(vn[4]), 0)
    assert_equal(Int(vn[5]), 4)  # DCID = the client's SCID
    assert_equal(Int(vn[6]), 0xBB)
    assert_equal(Int(vn[10]), 8)  # SCID = the client's DCID
    assert_equal(Int(vn[11]), 0xAA)
    var has_v1 = False
    var pos = 19
    while pos + 4 <= len(vn):
        if vn[pos] == 0 and vn[pos + 1] == 0 and vn[pos + 2] == 0:
            has_v1 = has_v1 or vn[pos + 3] == 1
        pos += 4
    assert_true(has_v1, "QUIC v1 not offered")


def test_short_or_vn_datagrams_get_nothing() raises:
    assert_equal(len(_exchange(UInt32(0x0A0A0A0A), 600)), 0)
    assert_equal(len(_exchange(UInt32(0), 1200)), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
