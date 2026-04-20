"""Tests for ``ConnHandle`` state machine (Phase 1.4).

Drives the state machine with real non-blocking socket pairs on loopback.
Each test sets up a (client, server) pair, makes the server's fd
non-blocking, wraps it in a ``ConnHandle``, and drives the event handlers
with pre-composed client writes.
"""

from std.testing import (
    assert_equal,
    assert_not_equal,
    assert_true,
    assert_false,
    TestSuite,
)
from std.ffi import c_int

from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ServerConfig
from flare.http._server_reactor_impl import (
    ConnHandle,
    StepResult,
    STATE_READING,
    STATE_WRITING,
    STATE_CLOSING,
)
from flare.runtime import (
    Reactor,
    Event,
    INTEREST_READ,
    INTEREST_WRITE,
)


# ── Test helpers ──────────────────────────────────────────────────────────────


def _echo_handler(req: Request) raises -> Response:
    """Return a canned 200 OK with a short plaintext body."""
    var b = List[UInt8]()
    var s = "Hello, World!"
    var sb = s.as_bytes()
    for i in range(len(sb)):
        b.append(sb[i])
    var r = Response(status=200, reason="OK", body=b^)
    r.headers.set("Content-Type", "text/plain")
    return r^


def _raising_handler(req: Request) raises -> Response:
    raise Error("boom")


def _bytes_of(s: String) raises -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8]()
    for i in range(len(b)):
        out.append(b[i])
    return out^


def _default_config() raises -> ServerConfig:
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    cfg.write_timeout_ms = 0
    return cfg^


def _drive_readable(
    mut ch: ConnHandle,
    mut r: Reactor,
    handler: def(Request) raises thin -> Response,
    config: ServerConfig,
    timeout_ms: Int = 500,
) raises -> StepResult:
    """Wait for the conn's fd to be readable via a loopback Reactor, then
    drive on_readable once.

    Tests operate on real loopback sockets, so there is a race between
    the client's write() and the arrival of data in the server's recv
    queue. We use the Reactor (which wraps epoll/kqueue) to wait for the
    kernel to signal readiness, exactly like the real server will.
    """
    from flare.http.handler import FnHandler

    var fd = ch.fd()
    r.register(fd, UInt64(1), INTEREST_READ)
    var events = List[Event]()
    var got_readable = False
    # poll up to timeout_ms in small chunks so we can surface the readable
    # event reliably even if kqueue trickles events.
    var waited = 0
    var slice_ms = 50
    while waited < timeout_ms and not got_readable:
        events.clear()
        _ = r.poll(slice_ms, events)
        for i in range(len(events)):
            if events[i].token == UInt64(1) and events[i].is_readable():
                got_readable = True
                break
        waited += slice_ms
    # Whether or not we observed readable, always drive the state
    # machine at least once — kqueue sometimes delivers the event on a
    # later poll but the data is already in the queue.
    var h = FnHandler(handler)
    var result = ch.on_readable(h, config)
    try:
        r.unregister(fd)
    except:
        pass
    return result


def _drive_writable(
    mut ch: ConnHandle, config: ServerConfig
) raises -> StepResult:
    """Drive on_writable; a freshly-connected socket is typically writable
    immediately so no poll dance is needed."""
    return ch.on_writable(config)


# ── Basic lifecycle ───────────────────────────────────────────────────────────


def test_fresh_connhandle_is_in_reading_state() raises:
    """A newly-constructed ConnHandle starts in STATE_READING."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    assert_equal(ch.state, STATE_READING)
    assert_equal(ch.headers_end, -1)
    assert_equal(ch.keepalive_count, 0)
    client.close()


# ── Full request / response round-trip ────────────────────────────────────────


def test_simple_get_reaches_writing_state() raises:
    """A complete GET with empty body drives the state machine to WRITING."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    var req = _bytes_of("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    _ = client.write(Span[UInt8](req))
    var cfg = _default_config()
    var step = _drive_readable(ch, r, _echo_handler, cfg)
    assert_equal(ch.state, STATE_WRITING)
    assert_true(step.want_write)
    assert_false(step.want_read)
    assert_false(step.done)
    assert_true(len(ch.write_buf) > 0)
    client.close()


def test_full_round_trip_writes_response() raises:
    """After WRITING, on_writable drains the buffer and goes back to READING
    or CLOSING."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    var req = _bytes_of("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    _ = client.write(Span[UInt8](req))
    var cfg = _default_config()
    _ = _drive_readable(ch, r, _echo_handler, cfg)
    var step = ch.on_writable(cfg)
    # Keep-alive default: server should be ready to read another request.
    assert_equal(ch.state, STATE_READING)
    assert_true(step.want_read)
    assert_false(step.want_write)
    # Client should receive the response bytes.
    var rbuf = List[UInt8]()
    rbuf.resize(2048, 0)
    var n = client.read(rbuf.unsafe_ptr(), 2048)
    assert_true(n > 0)
    # Body "Hello, World!" should be present.
    var s = String(unsafe_from_utf8=Span[UInt8](rbuf)[:n])
    assert_true(s.find("Hello, World!") >= 0)
    client.close()


# ── Partial reads ─────────────────────────────────────────────────────────────


def test_partial_header_stays_in_reading() raises:
    """A header split across two reads stays in STATE_READING until the full
    \\r\\n\\r\\n arrives."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    # First chunk: not yet a full request (missing final \r\n).
    _ = client.write(Span[UInt8](_bytes_of("GET / HTTP/1.1\r\nHost: x\r\n")))
    var cfg = _default_config()
    var s1 = _drive_readable(ch, r, _echo_handler, cfg)
    assert_equal(ch.state, STATE_READING)
    assert_true(s1.want_read)
    assert_false(s1.want_write)
    # Send the terminator.
    _ = client.write(Span[UInt8](_bytes_of("\r\n")))
    var s2 = _drive_readable(ch, r, _echo_handler, cfg)
    assert_equal(ch.state, STATE_WRITING)
    assert_true(s2.want_write)
    client.close()


def test_partial_body_waits_for_content_length() raises:
    """A request with Content-Length but incomplete body waits for more bytes.
    """
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    _ = client.write(
        Span[UInt8](
            _bytes_of(
                "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nabc"
            )
        )
    )
    var cfg = _default_config()
    var s1 = _drive_readable(ch, r, _echo_handler, cfg)
    # Only 3 of 5 body bytes; still reading.
    assert_equal(ch.state, STATE_READING)
    assert_true(s1.want_read)
    _ = client.write(Span[UInt8](_bytes_of("de")))
    var s2 = _drive_readable(ch, r, _echo_handler, cfg)
    # All 5 body bytes now; should have run the handler and be writing.
    assert_equal(ch.state, STATE_WRITING)
    assert_true(s2.want_write)
    client.close()


# ── Error responses ──────────────────────────────────────────────────────────


def test_malformed_request_produces_400() raises:
    """Garbage that terminates with \\r\\n\\r\\n gets rejected with 400."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    # Only one token on the request line — parser must reject.
    _ = client.write(Span[UInt8](_bytes_of("GARBAGE\r\n\r\n")))
    var cfg = _default_config()
    _ = _drive_readable(ch, r, _echo_handler, cfg)
    assert_equal(ch.state, STATE_WRITING)
    assert_true(ch.should_close)
    _ = ch.on_writable(cfg)
    # The client should see "400 Bad Request" in the reply.
    var rbuf = List[UInt8]()
    rbuf.resize(2048, 0)
    var n = client.read(rbuf.unsafe_ptr(), 2048)
    assert_true(n > 0)
    var s = String(unsafe_from_utf8=Span[UInt8](rbuf)[:n])
    assert_true(s.find("400") >= 0)
    client.close()


def test_handler_exception_becomes_500() raises:
    """When the handler throws, we queue a 500 and close."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    _ = client.write(
        Span[UInt8](_bytes_of("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    )
    var cfg = _default_config()
    _ = _drive_readable(ch, r, _raising_handler, cfg)
    assert_true(ch.should_close)
    _ = ch.on_writable(cfg)
    var rbuf = List[UInt8]()
    rbuf.resize(2048, 0)
    var n = client.read(rbuf.unsafe_ptr(), 2048)
    assert_true(n > 0)
    var s = String(unsafe_from_utf8=Span[UInt8](rbuf)[:n])
    assert_true(s.find("500") >= 0)
    client.close()


def test_oversized_body_returns_413() raises:
    """A Content-Length beyond max_body_size triggers 413 without reading body.
    """
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    var cfg = ServerConfig()
    cfg.max_body_size = 10
    cfg.idle_timeout_ms = 0
    cfg.write_timeout_ms = 0
    _ = client.write(
        Span[UInt8](
            _bytes_of(
                "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 1000\r\n\r\n"
            )
        )
    )
    _ = _drive_readable(ch, r, _echo_handler, cfg)
    assert_true(ch.should_close)
    _ = ch.on_writable(cfg)
    var rbuf = List[UInt8]()
    rbuf.resize(2048, 0)
    var n = client.read(rbuf.unsafe_ptr(), 2048)
    assert_true(n > 0)
    var s = String(unsafe_from_utf8=Span[UInt8](rbuf)[:n])
    assert_true(s.find("413") >= 0)
    client.close()


# ── Keep-alive ────────────────────────────────────────────────────────────────


def test_keep_alive_serves_two_requests() raises:
    """After the first response flushes, a second request on the same conn
    also reaches WRITING."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    var cfg = _default_config()
    # Request 1
    _ = client.write(
        Span[UInt8](_bytes_of("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    )
    _ = _drive_readable(ch, r, _echo_handler, cfg)
    _ = ch.on_writable(cfg)
    assert_equal(ch.state, STATE_READING)
    assert_equal(ch.keepalive_count, 1)
    # Drain client-side bytes before sending next request so we don't
    # intermix them.
    var rbuf = List[UInt8]()
    rbuf.resize(2048, 0)
    _ = client.read(rbuf.unsafe_ptr(), 2048)
    # Request 2
    _ = client.write(
        Span[UInt8](_bytes_of("GET /second HTTP/1.1\r\nHost: x\r\n\r\n"))
    )
    _ = _drive_readable(ch, r, _echo_handler, cfg)
    assert_equal(ch.state, STATE_WRITING)
    assert_equal(ch.keepalive_count, 2)
    client.close()


def test_connection_close_header_closes_after_response() raises:
    """Connection: close in the request -> done=True after on_writable."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    var cfg = _default_config()
    _ = client.write(
        Span[UInt8](
            _bytes_of("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        )
    )
    _ = _drive_readable(ch, r, _echo_handler, cfg)
    assert_true(ch.should_close)
    var step = ch.on_writable(cfg)
    assert_true(step.done)
    client.close()


def test_http_1_0_defaults_to_close() raises:
    """HTTP/1.0 without explicit Keep-Alive should close after one response."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    var cfg = _default_config()
    _ = client.write(
        Span[UInt8](_bytes_of("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
    )
    _ = _drive_readable(ch, r, _echo_handler, cfg)
    assert_true(ch.should_close)
    client.close()


def test_max_keepalive_requests_closes_conn() raises:
    """Hitting max_keepalive_requests flips should_close even if client wants
    keep-alive."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    var cfg = _default_config()
    cfg.max_keepalive_requests = 1
    _ = client.write(
        Span[UInt8](_bytes_of("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    )
    _ = _drive_readable(ch, r, _echo_handler, cfg)
    assert_true(ch.should_close)
    client.close()


# ── Timeout handling ─────────────────────────────────────────────────────────


def test_on_timeout_marks_closing() raises:
    """On_timeout flips state to CLOSING and returns done=True."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    var ch = ConnHandle(server^)
    var step = ch.on_timeout()
    assert_equal(ch.state, STATE_CLOSING)
    assert_true(step.done)
    assert_true(ch.should_close)
    client.close()


# ── Peer close detection ──────────────────────────────────────────────────────


def test_peer_close_marks_done() raises:
    """When the peer closes before sending a full request, on_readable
    reports done."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()
    client.close()  # peer disconnects immediately
    var ch = ConnHandle(server^)
    var cfg = _default_config()
    var step = _drive_readable(ch, r, _echo_handler, cfg)
    assert_true(step.done)


# ── Step result helpers ───────────────────────────────────────────────────────


def test_step_result_defaults() raises:
    """StepResult with all defaults has every field at sensible 'no-op' value.
    """
    var sr = StepResult()
    assert_false(sr.want_read)
    assert_false(sr.want_write)
    assert_false(sr.done)
    assert_equal(sr.idle_timeout_ms, -1)


def main() raises:
    print("=" * 60)
    print("test_server_reactor_state.mojo — Phase 1.4 state machine")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
