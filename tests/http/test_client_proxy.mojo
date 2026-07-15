"""HTTP client proxy support (CONNECT tunnel via with_proxy).

Forks a minimal proxy that speaks the ``CONNECT`` handshake and then
acts as the origin: it reads ``CONNECT host:port``, replies
``200 Connection Established``, reads the tunneled ``GET``, and answers
with a body. The client -- pointed at the proxy via ``with_proxy`` --
must tunnel the origin request through it and return the body, proving
the CONNECT dial + env/explicit proxy policy wiring.
"""

from std.testing import assert_equal, assert_true

from flare.http import HttpClient
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def _read_head(mut c: TcpStream) raises -> String:
    """Read until CRLFCRLF; return the accumulated head as text."""
    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    var acc = List[UInt8]()
    while True:
        var n = c.read(buf.unsafe_ptr(), 4096)
        if n == 0:
            break
        for i in range(n):
            acc.append(buf[i])
        var m = len(acc)
        if m >= 4:
            for j in range(m - 3):
                if (
                    acc[j] == 13
                    and acc[j + 1] == 10
                    and acc[j + 2] == 13
                    and acc[j + 3] == 10
                ):
                    return String(unsafe_from_utf8=Span[UInt8, _](acc))
    return String(unsafe_from_utf8=Span[UInt8, _](acc))


def _serve_proxy(mut listener: TcpListener) raises -> None:
    var c = listener.accept()
    # 1) CONNECT handshake.
    var connect_head = _read_head(c)
    if not connect_head.startswith("CONNECT "):
        c.close()
        return
    var ok = String("HTTP/1.1 200 Connection Established\r\n\r\n")
    c.write_all(Span[UInt8, _](ok.as_bytes()))
    # 2) Tunneled origin request -> canned response.
    _ = _read_head(c)
    var body = String("via-proxy")
    var resp = String("HTTP/1.1 200 OK\r\nContent-Length: ")
    resp += String(body.byte_length()) + "\r\n\r\n" + body
    c.write_all(Span[UInt8, _](resp.as_bytes()))
    c.close()


def main() raises:
    print("test_client_proxy")
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            _serve_proxy(listener)
        except:
            pass
        exit()
    usleep(150_000)

    var proxy_url = String("http://127.0.0.1:") + String(Int(port))
    var status = -1
    var text = String("")
    try:
        with HttpClient().with_proxy(proxy_url) as c:
            var r = c.get("http://example.test/path")
            status = r.status
            text = r.text()
    except e:
        print("proxy request raised:", e)

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_equal(status, 200)
    assert_equal(text, "via-proxy")
    print("test_client_proxy: 1 passed")
