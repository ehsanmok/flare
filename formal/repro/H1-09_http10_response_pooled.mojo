# PLATFORM: any
"""H1-09: the pooled client keeps a connection open after an HTTP/1.0
response that did not ask for keep-alive.

Lean: Flare.Bugs.H1_09.counterexample (canReuse is true for an
"HTTP/1.0" response with no Connection field) and
Flare.L3.H1.ClientResponse.canReuseFixed_ok (fix meets spec).
flare/http/_client/parse.mojo:836-884 (`can_reuse = clean and not
conn_close`; the response version is never read) @59bda50. Callers:
the pooled paths in flare/http/client.mojo:1275, 1316, 2551, 2584.

Expected (RFC 9112 §9.3): an HTTP/1.0 response without
"Connection: keep-alive" closes the connection after the response; the
client must not send another request on it.
Actual: `_read_http_response_framed_tcp` sets can_reuse = True, so the
pool hands the connection to the next request, which the HTTP/1.0 server
(or the proxy in between) then drops or misreads.

Minimal fix: in _read_http_response_framed, set conn_close = True unless
the status line starts with "HTTP/1.1 " (HTTP/1.0 keep-alive can be
added on top by also accepting a "keep-alive" Connection token).
"""

from flare.http._client.parse import _read_http_response_framed_tcp
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def _serve(var lis: TcpListener):
    try:
        var s = lis.accept()
        var buf = List[UInt8](capacity=4096)
        buf.resize(4096, 0)
        _ = s.read(buf.unsafe_ptr(), 4096)
        s.write_all(
            String("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi").as_bytes()
        )
        usleep(3_000_000)
        _ = s^
    except:
        pass
    exit()


def main() raises:
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var pid = fork()
    if pid == 0:
        _serve(lis^)
    usleep(100_000)
    var reuse = False
    var verdict: String
    try:
        var s = TcpStream.connect(SocketAddr.localhost(port))
        s.write_all(
            String("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()
        )
        var resp = _read_http_response_framed_tcp(s, reuse)
        verdict = (
            "status=" + String(resp.status) + " body=" + resp.text()
            + " can_reuse=" + String(reuse)
        )
        if resp.text() != "hi":
            _ = kill(pid, SIGKILL)
            waitpid(pid)
            print("inconclusive: unexpected response: " + verdict)
            raise Error("inconclusive")
    except e:
        _ = kill(pid, SIGKILL)
        waitpid(pid)
        print("inconclusive: setup failed: " + String(e))
        raise Error("inconclusive")
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    print(verdict)
    if reuse:
        print(
            "BUG REPRODUCED: HTTP/1.0 response without keep-alive marked"
            " reusable (" + verdict + ")"
        )
        raise Error("H1-09")
    print("OK: HTTP/1.0 response closes the connection (" + verdict + ")")
