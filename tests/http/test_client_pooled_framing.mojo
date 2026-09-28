"""The pooled HTTP/1.1 reader frames responses by method, status and
chunk structure.

Every request made with ``with_pool()`` goes through
``_read_http_response_framed``. It used to find the end of a chunked
body by searching for ``\\r\\n0\\r\\n``, which (a) stopped early when the
payload itself contained that pattern, returning the connection to the
pool with body bytes still in it, and (b) never matched an empty
chunked body, so the read blocked until EOF. It also ignored the
method, so a HEAD response's Content-Length made it wait for a body
that never comes.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import SocketAddr
from flare.tcp import TcpListener
from flare.testing import fork_server, kill_forked_server
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def _hello(req: Request) raises -> Response:
    return ok("hello")


def _canned_server(var responses: List[String]) raises -> Tuple[Int, UInt16]:
    """Fork a server that, per connection, reads one request and writes
    the next canned response verbatim; connections stay open."""
    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(ln.local_addr().port)
    var pid = fork()
    if pid == 0:
        # Serve the responses in order on whichever connection sends a
        # request; a connection that closes without one is skipped.
        var i = 0
        var buf = List[UInt8](length=4096, fill=UInt8(0))
        while i < len(responses):
            try:
                var conn = ln.accept()
                while i < len(responses):
                    var n = conn.read(buf.unsafe_ptr(), 4096)
                    if n <= 0:
                        break
                    # "|PAUSE|" splits a response into separate writes
                    # with a gap, so the reader sees it arrive in parts.
                    var parts = responses[i].split("|PAUSE|")
                    for k in range(len(parts)):
                        if k > 0:
                            usleep(150000)
                        var r = String(parts[k]).as_bytes()
                        conn.write_all(Span[UInt8, _](r))
                    i += 1
                if i >= len(responses):
                    usleep(2000000)
            except:
                pass
        exit()
    usleep(200000)
    return (Int(pid), port)


def test_head_through_the_pool_does_not_wait_for_a_body() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _hello)
    var url = "http://127.0.0.1:" + String(Int(port)) + "/"
    var status = -1
    var get_body = String("")
    try:
        var c = HttpClient().with_pool().with_read_timeout(1500)
        var r = c.head(url)
        status = r.status
        assert_equal(len(r.body), 0)
        # The same pooled connection must still be at a message
        # boundary for the next request.
        get_body = c.get(url).text()
    except:
        pass
    kill_forked_server(pid)
    assert_equal(status, 200)
    assert_equal(get_body, "hello")


def test_chunk_payload_containing_the_terminator_pattern() raises:
    # The 12-byte payload "\r\n0\r\nX:y\r\n\r\n" looks like a zero chunk
    # plus trailers; the old scan stopped inside it and returned the
    # connection to the pool with the real terminator still unread.
    var first = String(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "c\r\n\r\n0\r\nX:y\r\n\r\n|PAUSE|\r\n0\r\n\r\n"
    )
    var second = String("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond")
    var responses = List[String]()
    responses.append(first)
    responses.append(second)
    var srv = _canned_server(responses^)
    var url = "http://127.0.0.1:" + String(Int(srv[1])) + "/"
    var b1 = -1
    var t2 = String("")
    try:
        var c = HttpClient().with_pool().with_read_timeout(1500)
        b1 = len(c.get(url).body)
        t2 = c.get(url).text()
    except e:
        print("request failed:", e)
    _ = kill(srv[0], SIGKILL)
    waitpid(srv[0])
    assert_equal(b1, 12)
    assert_equal(t2, "second")


def test_empty_chunked_body_returns_at_once() raises:
    var responses = List[String]()
    responses.append(
        String("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    )
    var srv = _canned_server(responses^)
    var url = "http://127.0.0.1:" + String(Int(srv[1])) + "/"
    var status = -1
    try:
        var c = HttpClient().with_pool().with_read_timeout(1000)
        var r = c.get(url)
        status = r.status
        assert_equal(len(r.body), 0)
    except:
        pass
    _ = kill(srv[0], SIGKILL)
    waitpid(srv[0])
    assert_equal(status, 200)


def test_informational_response_is_read_past() raises:
    var responses = List[String]()
    responses.append(
        String(
            "HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n"
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        )
    )
    var srv = _canned_server(responses^)
    var url = "http://127.0.0.1:" + String(Int(srv[1])) + "/"
    var status = -1
    var text = String("")
    try:
        var c = HttpClient().with_pool().with_read_timeout(1000)
        var r = c.get(url)
        status = r.status
        text = r.text()
    except:
        pass
    _ = kill(srv[0], SIGKILL)
    waitpid(srv[0])
    assert_equal(status, 200)
    assert_equal(text, "ok")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
