"""Accept-path admission cap for the plain HTTP/1.1 Handler path (D8).

A server runs the normal ``serve(handler)`` reactor with
``ServerConfig(max_connections=2)`` and a large idle timeout so the two
admitted keep-alive connections stay live for the test window. The test:

- opens two keep-alive connections, each gets a ``200`` (both slots used
  and held open);
- opens a third while at capacity -> the accept drainer stops pulling it
  in, so it sits in the kernel backlog and gets NO response within a
  short window (backpressure, not a drop);
- closes one admitted connection to free a slot -> the third is then
  accepted and served (the cap releases as connections drain).

Unlike the streaming path (which sheds with 503 + Retry-After), the plain
path backpressures: surplus connections wait in the listen backlog.
"""

from std.testing import assert_true

from flare.http import HttpServer, Handler, Request, Response, ok
from flare.http.server import ServerConfig
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


@fieldwise_init
struct OkHandler(Copyable, Handler, Movable):
    def serve(self, req: Request) raises -> Response:
        return ok("OK")


def _send_get(mut s: TcpStream) raises:
    var req = String("GET / HTTP/1.1\r\nHost: t\r\n\r\n")
    _ = s.write(req.as_bytes())


def _read_resp(mut s: TcpStream) raises -> String:
    var buf = List[UInt8](capacity=1024)
    buf.resize(1024, 0)
    var n = s.read(buf.unsafe_ptr(), 1024)
    if n <= 0:
        return String("")
    return String(unsafe_from_utf8=Span[UInt8, _](buf)[0:n])


def _try_read(mut s: TcpStream) -> String:
    """Best-effort single read; empty on EAGAIN (Timeout) or error."""
    var buf = List[UInt8](capacity=1024)
    buf.resize(1024, 0)
    try:
        var n = s.read(buf.unsafe_ptr(), 1024)
        if n <= 0:
            return String("")
        return String(unsafe_from_utf8=Span[UInt8, _](buf)[0:n])
    except:
        return String("")


def _timed_read(mut s: TcpStream, max_ms: Int) -> String:
    """Poll a non-blocking stream up to ``max_ms`` for any bytes."""
    var waited = 0
    while waited < max_ms:
        var got = _try_read(s)
        if got.byte_length() > 0:
            return got
        usleep(20_000)
        waited += 20
    return String("")


def main() raises:
    var cfg = ServerConfig(idle_timeout_ms=30_000, max_connections=2)
    var srv = HttpServer.bind(SocketAddr.localhost(0), config=cfg^)
    var port = srv.local_addr().port

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(OkHandler())
        except:
            pass
        exit()

    usleep(250_000)

    # Two admitted keep-alive connections; both served, both held open.
    var c1 = TcpStream.connect(SocketAddr.localhost(port))
    _send_get(c1)
    var r1 = _read_resp(c1)
    var c2 = TcpStream.connect(SocketAddr.localhost(port))
    _send_get(c2)
    var r2 = _read_resp(c2)
    usleep(50_000)

    # Third connection is over capacity: the accept drainer refuses to
    # pull it in, so it stays in the backlog with no response.
    var c3 = TcpStream.connect(SocketAddr.localhost(port))
    c3._socket.set_nonblocking(True)
    _send_get(c3)
    var capped = _timed_read(c3, 400)

    # Free a slot; the third connection is now admitted and served.
    c1.close()
    var recovered = _timed_read(c3, 3000)

    c2.close()
    c3.close()
    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_true(r1.find("200") != -1, "c1 expected 200, got: " + r1)
    assert_true(r2.find("200") != -1, "c2 expected 200, got: " + r2)
    assert_true(
        capped.byte_length() == 0,
        "c3 should be backpressured while at cap, got: " + capped,
    )
    assert_true(
        recovered.find("200") != -1,
        "c3 expected 200 after a slot freed, got: " + recovered,
    )
    print("test_admission_h1: passed (cap=2, backpressure + recovery)")
