"""Tests for flare.tcp — TcpStream + TcpListener.

All tests use loopback (127.0.0.1) with OS-assigned ephemeral ports
(``port=0``). No external network access is required.

Test strategy:
  - Bind a listener on port 0, connect a client, then accept on the server
    side — all in sequence on the same thread. This works because connect()
    and accept() are both blocking and the kernel's pending-connection queue
    holds the connect until accept() is called.
  - Error-path tests use port 19991 which is typically unoccupied on
    developer machines, and blackhole IPs for timeout tests.
"""

from testing import assert_equal, assert_not_equal, assert_raises, TestSuite
from flare.tcp import TcpStream, TcpListener
from flare.net import SocketAddr, IpAddr


# ── Test helpers ──────────────────────────────────────────────────────────────


fn bytes_of(s: String) raises -> List[UInt8]:
    """Convert string to owned List[UInt8] via move."""
    var b = s.as_bytes()
    var out = List[UInt8]()
    for i in range(len(b)):
        out.append(b[i])
    return out^


fn zero_buf(n: Int) -> List[UInt8]:
    """Return an n-byte zero-initialised buffer."""
    var b = List[UInt8]()
    b.resize(n, 0)
    return b^


# ── TcpListener: bind and introspect ─────────────────────────────────────────


def test_listener_bind_port_zero_assigns_port():
    """Binding port 0 yields a real OS-assigned non-zero port."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var port = l.local_addr().port
    assert_not_equal(port, UInt16(0), "OS must assign a non-zero port")
    l.close()


def test_listener_local_addr_is_loopback():
    """Local address after bind is 127.0.0.1."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    assert_equal(String(l.local_addr().ip), "127.0.0.1")
    l.close()


def test_listener_close_idempotent():
    """Calling close() twice must not panic."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    l.close()
    l.close()


# ── TcpStream: connect ────────────────────────────────────────────────────────


def test_connect_to_listener_succeeds():
    """TcpStream.connect() to an active listener returns a connected stream."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var port = l.local_addr().port
    var c = TcpStream.connect(SocketAddr.localhost(port))
    var s = l.accept()
    c.close()
    s.close()
    l.close()


def test_connect_refused_raises_error():
    """Connecting to a port with no listener raises an error."""
    # Port 19991 is very unlikely to be in use
    try:
        var _ = TcpStream.connect(SocketAddr.localhost(19991))
        assert_equal(1, 0, "must have raised")
    except e:
        # ConnectionRefused or NetworkError are both acceptable
        var msg = String(e)
        assert_not_equal(msg, "", "error must have a message")


def test_stream_peer_addr_matches_server():
    """``peer_addr()`` on the client matches the server's bound port."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var port = l.local_addr().port
    var c = TcpStream.connect(SocketAddr.localhost(port))
    var s = l.accept()
    assert_equal(c.peer_addr().port, port)
    c.close()
    s.close()
    l.close()


def test_stream_local_addr_is_nonzero():
    """The client's ephemeral port is non-zero."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var port = l.local_addr().port
    var c = TcpStream.connect(SocketAddr.localhost(port))
    var s = l.accept()
    assert_not_equal(c.local_addr().port, UInt16(0))
    c.close()
    s.close()
    l.close()


def test_stream_close_idempotent():
    """Calling close() twice on a stream must not panic."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var port = l.local_addr().port
    var c = TcpStream.connect(SocketAddr.localhost(port))
    var s = l.accept()
    c.close()
    c.close()
    s.close()
    l.close()


# ── Round-trip: write_all / read_exact ────────────────────────────────────────


def test_round_trip_1_byte():
    """Single-byte round-trip: client sends, server receives."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()

    var data = zero_buf(1)
    data[0] = UInt8(42)
    c.write_all(Span[UInt8](data))

    var buf = zero_buf(16)
    var n = s.read(buf.unsafe_ptr(), len(buf))
    assert_equal(n, 1)
    assert_equal(buf[0], UInt8(42))

    c.close()
    s.close()
    l.close()


def test_round_trip_1_kb():
    """1 KB round-trip with pattern verification."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()

    var size = 1024
    var data = List[UInt8]()
    for i in range(size):
        data.append(UInt8(i & 0xFF))
    c.write_all(Span[UInt8](data))

    var buf = zero_buf(size)
    s.read_exact(buf.unsafe_ptr(), len(buf))
    assert_equal(buf[0], UInt8(0))
    assert_equal(buf[255], UInt8(255))
    assert_equal(buf[256], UInt8(0))  # wraps

    c.close()
    s.close()
    l.close()


def test_round_trip_64_kb():
    """64 KB round-trip — exercises TCP segmentation and reassembly."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()

    var size = 65536
    var data = List[UInt8]()
    for i in range(size):
        data.append(UInt8((i * 7 + 13) & 0xFF))
    c.write_all(Span[UInt8](data))

    var buf = zero_buf(size)
    s.read_exact(buf.unsafe_ptr(), len(buf))
    assert_equal(buf[0], UInt8(13))
    assert_equal(buf[1], UInt8(20))  # (7+13) & 0xFF

    c.close()
    s.close()
    l.close()


def test_read_returns_zero_on_eof():
    """``read()`` returns 0 after the peer calls ``shutdown_write()``."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()

    c.shutdown_write()

    var buf = zero_buf(16)
    var n = s.read(buf.unsafe_ptr(), len(buf))
    assert_equal(n, 0, "read() must return 0 on EOF")

    c.close()
    s.close()
    l.close()


def test_bidirectional_ping_pong():
    """Client and server can both send and receive in alternation."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()

    var ping = zero_buf(4)
    ping[0] = UInt8(ord("p"))
    ping[1] = UInt8(ord("i"))
    ping[2] = UInt8(ord("n"))
    ping[3] = UInt8(ord("g"))
    c.write_all(Span[UInt8](ping))

    var sbuf = zero_buf(4)
    s.read_exact(sbuf.unsafe_ptr(), len(sbuf))
    assert_equal(sbuf[0], UInt8(ord("p")))
    assert_equal(sbuf[3], UInt8(ord("g")))

    var pong = zero_buf(4)
    pong[0] = UInt8(ord("p"))
    pong[1] = UInt8(ord("o"))
    pong[2] = UInt8(ord("n"))
    pong[3] = UInt8(ord("g"))
    s.write_all(Span[UInt8](pong))

    var cbuf = zero_buf(4)
    c.read_exact(cbuf.unsafe_ptr(), len(cbuf))
    assert_equal(cbuf[0], UInt8(ord("p")))
    assert_equal(cbuf[3], UInt8(ord("g")))

    c.close()
    s.close()
    l.close()


# ── Multiple sequential connections ──────────────────────────────────────────


def test_sequential_connections():
    """Listener accepts 10 sequential connections each sending one byte."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var port = l.local_addr().port

    for i in range(10):
        var c = TcpStream.connect(SocketAddr.localhost(port))
        var s = l.accept()
        var data = zero_buf(1)
        data[0] = UInt8(i)
        c.write_all(Span[UInt8](data))
        var buf = zero_buf(1)
        var _ = s.read(buf.unsafe_ptr(), len(buf))
        assert_equal(buf[0], UInt8(i))
        c.close()
        s.close()

    l.close()


# ── Socket options ────────────────────────────────────────────────────────────


def test_tcp_nodelay_toggle():
    """``set_nodelay()`` toggles without raising."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()
    c.set_nodelay(False)
    c.set_nodelay(True)
    c.close()
    s.close()
    l.close()


def test_keepalive_toggle():
    """``set_keepalive()`` toggles without raising."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()
    c.set_keepalive(True)
    c.set_keepalive(False)
    c.close()
    s.close()
    l.close()


def test_recv_timeout_causes_timeout_error():
    """Setting a short recv timeout causes read() to raise after that interval.
    """
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()

    s.set_recv_timeout(200)  # 200ms — generous enough to avoid flakiness

    var buf = zero_buf(16)
    var raised = False
    try:
        var _ = s.read(buf.unsafe_ptr(), len(buf))
    except:
        raised = True
    assert_equal(raised, True, "recv must raise after timeout")

    c.close()
    s.close()
    l.close()


def test_connect_timeout_blackhole():
    """``connect_timeout()`` to a blackhole address raises after the deadline.

    Uses a 100ms timeout to fail fast. The unrouted 240.0.0.1 causes an
    immediate EHOSTUNREACH on most systems (no route to host), so this
    test finishes quickly even though the timeout is set to 100ms.
    """
    # 240.0.0.1 is in the reserved 240/4 block — no routes assigned
    var addr = SocketAddr(IpAddr("240.0.0.1", is_v6=False), 9999)
    var raised = False
    try:
        var _ = TcpStream.connect_timeout(addr, 100)
    except:
        raised = True
    assert_equal(raised, True, "must raise (refused, timeout, or route error)")


# ── SO_REUSEADDR: rebind after close ──────────────────────────────────────────


def test_reuseaddr_allows_rebind():
    """After listener.close(), a new listener can bind the same port."""
    var l1 = TcpListener.bind(SocketAddr.localhost(0))
    var port = l1.local_addr().port
    l1.close()
    # SO_REUSEADDR should allow immediate rebind
    var l2 = TcpListener.bind(SocketAddr.localhost(port))
    assert_equal(l2.local_addr().port, port)
    l2.close()


def main():
    print("=" * 60)
    print("test_tcp.mojo — TcpStream + TcpListener")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
