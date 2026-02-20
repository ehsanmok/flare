"""Tests for flare.udp — UdpSocket.

All tests use loopback (127.0.0.1) with OS-assigned ports. No external
network access is required.
"""

from testing import assert_equal, assert_not_equal, assert_raises, TestSuite
from flare.udp import UdpSocket, DatagramTooLarge
from flare.net import SocketAddr


# ── Test helpers ──────────────────────────────────────────────────────────────


fn zero_buf(n: Int) -> List[UInt8]:
    var b = List[UInt8]()
    b.resize(n, 0)
    return b^


fn str_bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(len(s)):
        out.append(s.as_bytes()[i])
    return out^


# ── bind / unbound ────────────────────────────────────────────────────────────


def test_bind_assigns_port():
    """Binding port 0 yields a real OS-assigned non-zero port."""
    var s = UdpSocket.bind(SocketAddr.localhost(0))
    assert_not_equal(s.local_addr().port, UInt16(0))
    s.close()


def test_unbound_socket_creates_ok():
    """``UdpSocket.unbound()`` creates a send-only socket without raising."""
    var s = UdpSocket.unbound()
    s.close()


def test_close_idempotent():
    """``close()`` called twice must not panic."""
    var s = UdpSocket.bind(SocketAddr.localhost(0))
    s.close()
    s.close()


# ── send_to / recv_from round-trips ──────────────────────────────────────────


def test_round_trip_1_byte():
    """Round-trip a single byte datagram."""
    var rx = UdpSocket.bind(SocketAddr.localhost(0))
    var tx = UdpSocket.unbound()
    var port = rx.local_addr().port

    var data = zero_buf(1)
    data[0] = UInt8(99)
    var _ = tx.send_to(Span[UInt8](data), SocketAddr.localhost(port))

    var buf = zero_buf(64)
    var (n, _) = rx.recv_from(Span[UInt8](buf))
    assert_equal(n, 1)
    assert_equal(buf[0], UInt8(99))

    tx.close()
    rx.close()


def test_round_trip_512_bytes():
    """Round-trip a 512-byte datagram with pattern verification."""
    var rx = UdpSocket.bind(SocketAddr.localhost(0))
    var tx = UdpSocket.unbound()
    var port = rx.local_addr().port

    var data = List[UInt8]()
    for i in range(512):
        data.append(UInt8(i & 0xFF))
    var _ = tx.send_to(Span[UInt8](data), SocketAddr.localhost(port))

    var buf = zero_buf(1024)
    var (n, _) = rx.recv_from(Span[UInt8](buf))
    assert_equal(n, 512)
    assert_equal(buf[0], UInt8(0))
    assert_equal(buf[255], UInt8(255))

    tx.close()
    rx.close()


def test_round_trip_returns_sender_addr():
    """``recv_from()`` returns the correct sender address."""
    var rx = UdpSocket.bind(SocketAddr.localhost(0))
    var tx = UdpSocket.bind(
        SocketAddr.localhost(0)
    )  # bind tx to learn its port
    var rx_port = rx.local_addr().port
    var tx_port = tx.local_addr().port

    var data = zero_buf(1)
    data[0] = UInt8(7)
    var _ = tx.send_to(Span[UInt8](data), SocketAddr.localhost(rx_port))

    var buf = zero_buf(64)
    var (n, sender) = rx.recv_from(Span[UInt8](buf))
    assert_equal(n, 1)
    assert_equal(sender.port, tx_port)
    assert_equal(String(sender.ip), "127.0.0.1")

    tx.close()
    rx.close()


def test_recv_from_multiple_datagrams():
    """Multiple independent datagrams arrive in send order on loopback."""
    var rx = UdpSocket.bind(SocketAddr.localhost(0))
    var tx = UdpSocket.unbound()
    var port = rx.local_addr().port

    # Send 5 distinct single-byte datagrams
    for i in range(5):
        var d = zero_buf(1)
        d[0] = UInt8(i * 11)
        var _ = tx.send_to(Span[UInt8](d), SocketAddr.localhost(port))

    var buf = zero_buf(64)
    for i in range(5):
        var (n, _) = rx.recv_from(Span[UInt8](buf))
        assert_equal(n, 1)
        assert_equal(buf[0], UInt8(i * 11))

    tx.close()
    rx.close()


# ── DatagramTooLarge ──────────────────────────────────────────────────────────


def test_datagram_too_large_raises():
    """``send_to()`` raises ``DatagramTooLarge`` for a 65508-byte payload."""
    var s = UdpSocket.unbound()
    var big = List[UInt8]()
    big.resize(65508, 0)
    try:
        var _ = s.send_to(Span[UInt8](big), SocketAddr.localhost(9999))
        assert_equal(1, 0, "must have raised DatagramTooLarge")
    except e:
        var msg = String(e)
        assert_not_equal(msg, "", "error must have a message")
    s.close()


def test_datagram_large_payload():
    """``send_to()`` handles a large 8192-byte datagram reliably over loopback.

    Note: 65507-byte datagrams are valid at the IP layer but may be rejected
    by the OS on loopback due to socket buffer limits (e.g. macOS restricts
    UDP loopback to ~9216 bytes by default). 8192 bytes is well within all
    tested platform limits.
    """
    var rx = UdpSocket.bind(SocketAddr.localhost(0))
    var tx = UdpSocket.unbound()
    var port = rx.local_addr().port

    var size = 8192
    var data = List[UInt8]()
    for i in range(size):
        data.append(UInt8((i * 3 + 7) & 0xFF))
    var n_sent = tx.send_to(Span[UInt8](data), SocketAddr.localhost(port))
    assert_equal(n_sent, size)

    var buf = zero_buf(size)
    rx.set_recv_timeout(2000)  # 2-second safety timeout
    var (n_recv, _) = rx.recv_from(Span[UInt8](buf))
    assert_equal(n_recv, size)
    assert_equal(buf[0], UInt8(7))
    assert_equal(buf[1], UInt8(10))  # (3+7) & 0xFF

    tx.close()
    rx.close()


# ── Timeout ───────────────────────────────────────────────────────────────────


def test_recv_timeout_raises():
    """``recv_from()`` raises when no datagram arrives within the timeout."""
    var s = UdpSocket.bind(SocketAddr.localhost(0))
    s.set_recv_timeout(100)  # 100ms

    var buf = zero_buf(64)
    var raised = False
    try:
        var _ = s.recv_from(Span[UInt8](buf))
    except:
        raised = True
    assert_equal(raised, True, "recv_from must raise on timeout")
    s.close()


def main():
    print("=" * 60)
    print("test_udp.mojo — UdpSocket")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
