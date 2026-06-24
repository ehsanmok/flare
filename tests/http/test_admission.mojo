"""Admission control at capacity for the streaming reactor (v0.9 B4).

A server runs ``serve_streaming(handler, max_in_flight=2)``. The handler
greets every admitted connection ("HELLO") and holds it open. The test:

- opens two connections -> both admitted (read "HELLO");
- opens a third while at capacity -> refused with a canned
  ``503 Service Unavailable`` + ``Retry-After`` (a graceful overload
  signal, not a hang), and ``on_open`` is never run for it;
- closes one admitted connection to free a slot, then opens a fourth ->
  admitted again (cap releases as connections drain).

The 503 the over-capacity client reads *is* the load-shed signal.
"""

from std.testing import assert_equal, assert_true

from flare.http import HttpServer
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


struct HoldHandler(Movable, StreamHandler):
    """Greets each admitted connection and holds it open (never closes),
    so the live-connection count stays at the admitted set -- exercising
    the admission cap deterministically."""

    def __init__(out self):
        pass

    def on_open(mut self, mut conn: StreamConn) raises:
        conn.send(String("HELLO").as_bytes())

    def on_upstream(mut self, mut conn: StreamConn) raises:
        pass

    def on_writable(mut self, mut conn: StreamConn) raises:
        pass

    def on_close(mut self, mut conn: StreamConn) raises:
        pass


def _read_once(mut s: TcpStream) raises -> String:
    var buf = List[UInt8](capacity=512)
    buf.resize(512, 0)
    var n = s.read(buf.unsafe_ptr(), 512)
    if n <= 0:
        return String("")
    return String(unsafe_from_utf8=Span[UInt8, _](buf)[0:n])


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_streaming(HoldHandler(), max_in_flight=2, retry_after_s=3)
        except:
            pass
        exit()

    usleep(200_000)

    # Two admitted connections, each greeted and held open.
    var c1 = TcpStream.connect(SocketAddr.localhost(port))
    var g1 = _read_once(c1)
    usleep(50_000)
    var c2 = TcpStream.connect(SocketAddr.localhost(port))
    var g2 = _read_once(c2)
    usleep(50_000)

    # Third connection is over capacity -> 503 + Retry-After.
    var c3 = TcpStream.connect(SocketAddr.localhost(port))
    var shed = _read_once(c3)
    c3.close()

    # Free a slot, then a fourth connection is admitted again.
    c1.close()
    usleep(150_000)
    var c4 = TcpStream.connect(SocketAddr.localhost(port))
    var g4 = _read_once(c4)

    c2.close()
    c4.close()
    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_equal(g1, "HELLO")
    assert_equal(g2, "HELLO")
    assert_true(
        shed.find("503") != -1,
        "expected 503 status in shed response, got: " + shed,
    )
    assert_true(
        shed.find("Retry-After: 3") != -1,
        "expected Retry-After header in shed response, got: " + shed,
    )
    assert_equal(g4, "HELLO")
    print("test_admission: passed (cap=2, 1 shed with 503+Retry-After)")
