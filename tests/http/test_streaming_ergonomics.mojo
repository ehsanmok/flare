"""Ergonomic streaming surface: no fd, no Span, no per-connection table.

Covers the high-level abstractions that hide the low-level details a
front should not have to handle:

- ``StreamConn.send`` byte-type overloads -- a front sends a
  ``StringSlice`` or a ``List[UInt8]`` directly, no ``Span[UInt8, _]``
  wrapping at the call site (in-process loopback pair).
- ``UpstreamChunkSource.connect`` + ``StreamConn.attach_upstream(source)``
  + ``StreamConn.relay_upstream`` -- the framework owns the source
  (watches its fd, closes it on teardown) and drains it, so the relay
  front carries no ``Dict``, no descriptor, and no manual close
  (forked-backend e2e, mirrors examples/advanced/streaming_proxy.mojo).
"""

from std.testing import assert_equal, assert_true

from flare.http import HttpServer, UpstreamChunkSource
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.uds import FrameMux, UnixListener
from flare.uds._libc import unlink_path
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


# ── send() byte-type overloads ───────────────────────────────────────────────


def _test_send_overloads() raises:
    """A front queues a String then a List[UInt8] with no Span wrap; the
    bytes arrive in order on the client."""
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var conn = StreamConn(lis.accept(), 1)

    conn.send("hello ")  # StringSlice overload

    var world = String("world")
    var wb = world.as_bytes()
    var bytes = List[UInt8](capacity=len(wb))
    for i in range(len(wb)):
        bytes.append(wb[i])
    conn.send(bytes)  # List[UInt8] overload

    conn.flush_blocking()

    var buf = List[UInt8](capacity=64)
    buf.resize(64, 0)
    var n = client.read(buf.unsafe_ptr(), 64)
    var got = String(unsafe_from_utf8=Span[UInt8, _](buf)[0:n])
    client.close()
    _ = conn^  # drop closes the server side

    assert_equal(got, String("hello world"))
    print("test_streaming_ergonomics: send overloads passed")


# ── Framework-owned upstream + relay_upstream (e2e) ──────────────────────────


struct RelayFront(Movable, StreamHandler):
    """The whole relay: attach a source, drain it. No fd, no Span, no
    table, no manual close -- the framework owns the source."""

    var backend_path: String

    def __init__(out self, backend_path: String):
        self.backend_path = backend_path

    def on_open(mut self, mut conn: StreamConn) raises:
        conn.attach_upstream(UpstreamChunkSource.connect(self.backend_path))
        assert_true(conn.has_attached_source())
        conn.set_watermarks(hi=64 * 1024, lo=16 * 1024)

    def on_upstream(mut self, mut conn: StreamConn) raises:
        conn.relay_upstream()

    def on_writable(mut self, mut conn: StreamConn) raises:
        pass

    def on_close(mut self, mut conn: StreamConn) raises:
        pass


def _run_backend(mut listener: UnixListener, n_tokens: Int) raises:
    var conn = listener.accept()
    var mux = FrameMux(conn^)
    for i in range(n_tokens):
        mux.send_chunk(1, ("tok" + String(i) + " ").as_bytes())
        mux.flush()
        usleep(10_000)
    mux.done(1)
    mux.flush()
    usleep(150_000)


def _read_all(mut s: TcpStream) raises -> String:
    var out = List[UInt8]()
    var chunk = List[UInt8](capacity=4096)
    while True:
        chunk.resize(4096, 0)
        var n = s.read(chunk.unsafe_ptr(), 4096)
        if n == 0:
            break
        for i in range(n):
            out.append(chunk[i])
    return String(unsafe_from_utf8=Span[UInt8, _](out))


def _test_relay_e2e() raises:
    var n_tokens = 6
    var backend_path = String("/tmp/flare_streaming_ergonomics_backend.sock")
    _ = unlink_path(backend_path)

    var backend = UnixListener.bind_with_options(
        backend_path, cleanup_path=False
    )
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var backend_pid = fork()
    if backend_pid == 0:
        try:
            _run_backend(backend, n_tokens)
        except:
            pass
        exit()
    usleep(120_000)

    var front_pid = fork()
    if front_pid == 0:
        try:
            srv.serve_streaming(RelayFront(backend_path))
        except:
            pass
        exit()
    usleep(200_000)

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var got = _read_all(client)
    client.close()

    _ = kill(front_pid, SIGKILL)
    waitpid(front_pid)
    _ = kill(backend_pid, SIGKILL)
    waitpid(backend_pid)
    _ = unlink_path(backend_path)

    var expected = String("tok0 tok1 tok2 tok3 tok4 tok5 ")
    assert_equal(got, expected)
    print("test_streaming_ergonomics: relay e2e passed (", n_tokens, "tokens)")


def main() raises:
    _test_send_overloads()
    _test_relay_e2e()
