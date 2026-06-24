"""Example — streaming proxy (pump an external producer to a client).

A front that pumps an external producer's framed output to a client,
with end-to-end backpressure, in a handful of safe lines on top of
flare. Zero ``UnsafePointer``, zero ``alloc`` slot tables, zero
``external_call`` clock, zero manual reactor-token math -- and zero
file descriptors, byte ``Span`` wrapping, or per-connection tables in
the front itself.

The composable pieces, all from ``flare``:

- ``StreamHandler`` / ``StreamConn`` — typed streaming server. The
  handler is a struct whose fields are its shared state; the framework
  owns the reactor and the per-connection lifecycle and hands the front
  a ``StreamConn`` per event.
- ``UpstreamChunkSource.connect(path)`` — a response body whose chunks
  arrive over a Unix-domain socket to a backend; one call dials it.
- ``conn.attach_upstream(source)`` — hand the source to the framework;
  it watches the fd, owns the source's lifetime, and fires
  ``on_upstream`` when a chunk is ready. No descriptors, no token math.
- ``conn.relay_upstream()`` — the standard drain loop: ready chunks to
  the client with backpressure, close on EOF, park on pending.
- watermark backpressure — if the client is slow, the reactor
  stops reading the upstream until the relay buffer drains, so a slow
  consumer cannot force unbounded buffering.
- ``HttpServer.serve_streaming(front)`` — the streaming entry point.

The example is self-contained: it forks a backend worker that emits
framed CHUNK frames (with gaps, like a token generator), forks the
streaming server, then connects a plain TCP client and prints the
relayed stream. The backend speaks ``FrameMux``; the front never
reconnects per request.

Run:
    pixi run example-streaming-proxy
"""

from flare.http import HttpServer, UpstreamChunkSource
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.uds import FrameMux, UnixListener, UnixStream
from flare.uds._libc import unlink_path
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


# ── The front: a handful of safe lines ──────────────────────────────────────


struct ProxyFront(Movable, StreamHandler):
    """Relay a backend's framed token stream to the client.

    Shared state is just the backend socket path. The per-connection
    upstream is framework-owned -- ``attach_upstream`` moves the source
    into the connection and ``relay_upstream`` drains it, so the front
    keeps no table, names no file descriptor, and closes nothing by hand.
    """

    var backend_path: String

    def __init__(out self, backend_path: String):
        self.backend_path = backend_path

    def on_open(mut self, mut conn: StreamConn) raises:
        # Dial the backend and hand the source to the framework. It
        # watches the fd and owns the source for the connection.
        conn.attach_upstream(UpstreamChunkSource.connect(self.backend_path))
        # Size the relay pipe: pause the upstream once 64 KiB is queued
        # for a slow client, resume at 16 KiB (hysteresis).
        conn.set_watermarks(hi=64 * 1024, lo=16 * 1024)

    def on_upstream(mut self, mut conn: StreamConn) raises:
        # A chunk is ready: drain ready chunks into the client with
        # backpressure, close on EOF, park on pending. The whole loop.
        conn.relay_upstream()

    def on_writable(mut self, mut conn: StreamConn) raises:
        pass  # the framework drains conn's buffer; nothing to hand-roll

    def on_close(mut self, mut conn: StreamConn) raises:
        pass  # framework closes the upstream source on teardown


# ── A toy backend over FrameMux (stands in for a token generator) ────────────


def _run_backend(mut listener: UnixListener, n_tokens: Int) raises:
    """Accept one connection and emit ``n_tokens`` CHUNK frames with
    small gaps, then DONE — the shape a generation backend produces."""
    var conn = listener.accept()
    var mux = FrameMux(conn^)
    for i in range(n_tokens):
        mux.send_chunk(1, ("token-" + String(i) + " ").as_bytes())
        mux.flush()
        usleep(20_000)  # gap between tokens; the front parks, no spin
    mux.done(1)
    mux.flush()
    usleep(200_000)


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


def main() raises:
    var n_tokens = 8
    var backend_path = String("/tmp/flare_streaming_proxy_backend.sock")
    _ = unlink_path(backend_path)

    print("[streaming-proxy] starting backend at", backend_path)
    # cleanup_path=False: the socket path outlives the fork; the parent
    # unlinks it at the end (the bound fd is inherited by the child).
    var backend = UnixListener.bind_with_options(
        backend_path, cleanup_path=False
    )
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    print("[streaming-proxy] front listening on 127.0.0.1:", port)

    var backend_pid = fork()
    if backend_pid == 0:
        try:
            _run_backend(backend, n_tokens)
        except:
            pass
        exit()

    usleep(150_000)

    var front_pid = fork()
    if front_pid == 0:
        try:
            srv.serve_streaming(ProxyFront(backend_path))
        except:
            pass
        exit()

    usleep(200_000)

    print("[streaming-proxy] client connecting; reading relayed stream...")
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var got = _read_all(client)
    client.close()

    _ = kill(front_pid, SIGKILL)
    waitpid(front_pid)
    _ = kill(backend_pid, SIGKILL)
    waitpid(backend_pid)
    _ = backend.local_path()
    _ = unlink_path(backend_path)

    print("[streaming-proxy] received:", got)
    print(
        "[streaming-proxy] done — relayed",
        n_tokens,
        "backend tokens to the client with end-to-end backpressure.",
    )
