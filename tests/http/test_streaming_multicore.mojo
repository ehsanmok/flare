"""Multi-worker ``HttpServer.serve_streaming(handler, num_workers=N)``.

Forks a child running the streaming reactor across 4 pthreads (each
worker owns its own copy of the ``StreamHandler`` + its own connection
table) and drives it from the parent with several client connections.
Every connection -- whichever worker's SO_REUSEPORT listener the kernel
routes it to -- must see the full lifecycle output, proving the
per-worker fan-out mirrors the single-worker reactor.
"""

from std.collections import Dict
from std.testing import assert_equal

from flare.http import HttpServer
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


struct PushFront(Copyable, Movable, StreamHandler):
    """Copyable streaming handler: one copy per worker. Per-connection
    write counters live in a worker-local dict keyed by conn id."""

    var n_chunks: Int
    var writes: Dict[Int, Int]

    def __init__(out self, n_chunks: Int):
        self.n_chunks = n_chunks
        self.writes = Dict[Int, Int]()

    def on_open(mut self, mut conn: StreamConn) raises:
        self.writes[conn.id()] = 0
        conn.send("HELLO\n".as_bytes())

    def on_upstream(mut self, mut conn: StreamConn) raises:
        pass

    def on_writable(mut self, mut conn: StreamConn) raises:
        var w = self.writes[conn.id()]
        if w < self.n_chunks:
            conn.send(("chunk " + String(w) + "\n").as_bytes())
            self.writes[conn.id()] = w + 1
        else:
            conn.request_close()

    def on_close(mut self, mut conn: StreamConn) raises:
        if conn.id() in self.writes:
            _ = self.writes.pop(conn.id())


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
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    var handler = PushFront(3)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_streaming(handler^, num_workers=4, pin_cores=False)
        except:
            pass
        exit()
    usleep(300_000)

    var expected = String("HELLO\nchunk 0\nchunk 1\nchunk 2\n")

    # Several connections; the kernel spreads them across the 4 workers.
    var ok = 0
    for _i in range(8):
        var c = TcpStream.connect(SocketAddr.localhost(port))
        var got = _read_all(c)
        c.close()
        if got == expected:
            ok += 1

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_equal(ok, 8)
    print("test_streaming_multicore: 1 passed")
