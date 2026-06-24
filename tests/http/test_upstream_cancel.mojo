"""Upstream-cancel propagation (v0.9 B6).

A backend worker streams framed tokens with gaps and watches its inbound
side for a CANCEL frame. A flare streaming front relays the tokens to the
client over an ``UpstreamChunkSource``. The client disconnects mid-stream;
the reactor flips the connection's cancel, and the front's ``on_close``
calls ``send_cancel`` -- emitting a CANCEL frame to the backend so it
stops generating tokens nobody will read.

Observable: the worker writes a sentinel file when it reads the CANCEL
frame for the request id. The test asserts the sentinel appears (the
backend was told to stop).
"""

from std.collections import Dict
from std.os import path as os_path
from std.testing import assert_true

from flare.http import HttpServer, UpstreamChunkSource
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.uds import FrameKind, FrameMux, UnixListener, UnixStream
from flare.uds._libc import unlink_path
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


struct CancelRelay(Movable, StreamHandler):
    """Relays a framed upstream to the client and, on teardown after a
    client disconnect, propagates a CANCEL frame to the backend."""

    var worker_path: String
    var sources: Dict[Int, UpstreamChunkSource]

    def __init__(out self, worker_path: String):
        self.worker_path = worker_path
        self.sources = Dict[Int, UpstreamChunkSource]()

    def on_open(mut self, mut conn: StreamConn) raises:
        var up = UnixStream.connect(self.worker_path)
        var src = UpstreamChunkSource(up^, 1)
        conn.attach_upstream(Int(src.fd()))
        self.sources[conn.id()] = src^

    def on_upstream(mut self, mut conn: StreamConn) raises:
        ref src = self.sources[conn.id()]
        var p = src.poll(conn.cancel())
        if p.is_ready():
            var c = p.take_chunk()
            conn.send(Span[UInt8, _](c))
        elif p.is_eof():
            conn.request_close()

    def on_writable(mut self, mut conn: StreamConn) raises:
        pass

    def on_close(mut self, mut conn: StreamConn) raises:
        if conn.id() in self.sources:
            ref src = self.sources[conn.id()]
            if conn.cancel().cancelled():
                try:
                    src.send_cancel()
                except:
                    pass
            _ = self.sources.pop(conn.id())


def main() raises:
    var sentinel = String("/tmp/flare_upstream_cancel_seen")
    _ = unlink_path(sentinel)
    var wpath = String("/tmp/flare_upcancel_worker.sock")
    _ = unlink_path(wpath)
    var worker = UnixListener.bind_with_options(wpath, cleanup_path=False)
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var wpid = fork()
    if wpid == 0:
        try:
            var conn = worker.accept()
            conn._socket.set_nonblocking(True)
            var mux = FrameMux(conn^)
            var saw_cancel = False
            for _i in range(60):
                # Watch the inbound side for a CANCEL frame FIRST, so a
                # CANCEL buffered just before the peer FIN is seen before a
                # send to the now-closing peer fails.
                try:
                    _ = mux.pump(4096)
                except:
                    pass
                var f = mux.poll(1)
                if f.__bool__():
                    var fr = f.value().copy()
                    if fr.kind == FrameKind.CANCEL:
                        saw_cancel = True
                if saw_cancel:
                    with open(sentinel, "w") as fh:
                        fh.write(String("CANCELLED"))
                    break
                # Produce a token; a send to a closed peer is non-fatal.
                try:
                    mux.send_chunk(1, String("tok").as_bytes())
                    mux.flush()
                except:
                    pass
                usleep(40_000)
        except:
            pass
        exit()

    usleep(150_000)

    var spid = fork()
    if spid == 0:
        try:
            srv.serve_streaming(CancelRelay(wpath))
        except:
            pass
        exit()

    usleep(200_000)

    # Client reads a little (mid-generation), then disconnects.
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var buf = List[UInt8](capacity=64)
    buf.resize(64, 0)
    _ = client.read(buf.unsafe_ptr(), 64)
    client.close()

    # Give the cancel one round trip to reach the backend.
    usleep(400_000)

    var seen = os_path.exists(sentinel)

    _ = kill(spid, SIGKILL)
    waitpid(spid)
    _ = kill(wpid, SIGKILL)
    waitpid(wpid)
    _ = worker.local_path()
    _ = unlink_path(wpath)
    _ = unlink_path(sentinel)

    assert_true(
        seen, "backend did not receive a CANCEL frame after client disconnect"
    )
    print("test_upstream_cancel: passed (CANCEL reached backend)")
