"""End-to-end test for upstream attachment (v0.9 A4).

Exercises ``StreamConn.attach_upstream`` + the reactor's ``on_upstream``
dispatch with a real OS pipe standing in for a front-owned upstream
socket. The front, in ``on_open``, opens a pipe, writes a payload into
the write end, closes the write end, and attaches the read end. The
reactor then registers the read end, fires ``on_upstream`` on
readability (the front forwards the bytes to the client), and on the EOF
read (write end already closed) the front requests close. This proves
the upstream fd is registered, routed to the right connection, pumped,
and unregistered on teardown -- with the front owning the upstream's
lifetime (it closes the read fd in ``on_close``).
"""

from std.collections import Dict
from std.ffi import c_int, external_call
from std.memory import stack_allocation
from std.testing import assert_equal

from flare.http import HttpServer
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.net._libc import _close, _read_fd, _write_fd
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


struct PipeFront(Movable, StreamHandler):
    """Forwards bytes from a per-connection upstream pipe to the client."""

    var payload: String
    var up_read: Dict[Int, Int]

    def __init__(out self, payload: String):
        self.payload = payload
        self.up_read = Dict[Int, Int]()

    def on_open(mut self, mut conn: StreamConn) raises:
        var fds = stack_allocation[2, c_int]()
        fds[0] = c_int(-1)
        fds[1] = c_int(-1)
        if external_call["pipe", c_int](fds) != 0:
            raise Error("pipe() failed")
        var rfd = Int(fds[0])
        var wfd = Int(fds[1])
        # Push the whole payload, then close the write end so a later
        # read sees EOF.
        var bytes = self.payload.as_bytes()
        _ = _write_fd(c_int(wfd), bytes.unsafe_ptr(), UInt(len(bytes)))
        _ = _close(c_int(wfd))
        self.up_read[conn.id()] = rfd
        conn.attach_upstream(rfd)

    def on_upstream(mut self, mut conn: StreamConn) raises:
        var rfd = self.up_read[conn.id()]
        var buf = List[UInt8](capacity=4096)
        buf.resize(4096, 0)
        var n = _read_fd(c_int(rfd), buf.unsafe_ptr(), UInt(4096))
        if n > 0:
            conn.send(Span[UInt8, _](buf)[0:n])
        else:
            # EOF: upstream done, finish the response.
            conn.detach_upstream()
            conn.request_close()

    def on_writable(mut self, mut conn: StreamConn) raises:
        pass

    def on_close(mut self, mut conn: StreamConn) raises:
        if conn.id() in self.up_read:
            var rfd = self.up_read.pop(conn.id())
            _ = _close(c_int(rfd))


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
    var handler = PipeFront("STREAM-FROM-UPSTREAM")

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_streaming(handler^)
        except:
            pass
        exit()
    usleep(250_000)

    var expected = String("STREAM-FROM-UPSTREAM")

    var c1 = TcpStream.connect(SocketAddr.localhost(port))
    var got1 = _read_all(c1)
    c1.close()

    # Second connection: upstream attach/detach/teardown repeats cleanly.
    var c2 = TcpStream.connect(SocketAddr.localhost(port))
    var got2 = _read_all(c2)
    c2.close()

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_equal(got1, expected)
    assert_equal(got2, expected)
    print("test_streaming_upstream: 2 passed")
