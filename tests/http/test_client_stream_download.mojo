"""Streaming response-body download over HTTP/1.1.

:meth:`flare.http.HttpClient.get_streaming` parses only the response head
up front and hands the body back one chunk at a time via
:meth:`HttpDownload.read_chunk`, so a large download stays in bounded
memory. This test forks a raw-TCP server that replies with a big body
under each of the three framings the reader decodes -- Content-Length,
chunked, and close-delimited -- and asserts the client reassembles the
exact bytes.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http import HttpClient
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def _read_request_head(mut c: TcpStream) raises:
    """Drain the request until the CRLFCRLF terminator."""
    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    var acc = List[UInt8]()
    while True:
        var n = c.read(buf.unsafe_ptr(), 4096)
        if n == 0:
            return
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
                    return


def _body(n: Int) -> List[UInt8]:
    """``n`` bytes cycling 'A'..'Z' so order/corruption is detectable."""
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(65 + (i % 26)))
    return out^


def _serve(mut listener: TcpListener, response: List[UInt8]) raises:
    var c = listener.accept()
    _read_request_head(c)
    c.write_all(Span[UInt8, _](response))
    c.close()


def _content_length_response(body: List[UInt8]) -> List[UInt8]:
    var head = String("HTTP/1.1 200 OK\r\nContent-Length: ")
    head += String(len(body)) + "\r\n\r\n"
    var out = List[UInt8](List[UInt8](head.as_bytes()))
    for i in range(len(body)):
        out.append(body[i])
    return out^


def _chunked_response(body: List[UInt8], chunk: Int) -> List[UInt8]:
    var out = List[UInt8](
        List[UInt8](
            String(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            ).as_bytes()
        )
    )
    var pos = 0
    while pos < len(body):
        var take = chunk if pos + chunk <= len(body) else len(body) - pos
        var size_line = _hex(take) + "\r\n"
        for b in size_line.as_bytes():
            out.append(b)
        for i in range(take):
            out.append(body[pos + i])
        out.append(13)
        out.append(10)
        pos += take
    for b in String("0\r\n\r\n").as_bytes():
        out.append(b)
    return out^


def _close_response(body: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8](
        List[UInt8](
            String("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").as_bytes()
        )
    )
    for i in range(len(body)):
        out.append(body[i])
    return out^


def _hex(n: Int) -> String:
    if n == 0:
        return "0"
    var digits = String("0123456789abcdef").as_bytes()
    var out = String("")
    var x = n
    var rev = List[Int]()
    while x > 0:
        rev.append(x & 0xF)
        x >>= 4
    for i in range(len(rev) - 1, -1, -1):
        out += chr(Int(digits[rev[i]]))
    return out^


def _download_matches(port: UInt16, expected: List[UInt8]) raises -> Bool:
    var got = List[UInt8]()
    with HttpClient() as c:
        var url = String("http://127.0.0.1:") + String(Int(port)) + "/big"
        var dl = c.get_streaming(url)
        if dl.status != 200:
            return False
        # Pull in small chunks to prove incremental framing works.
        while True:
            var part = dl.read_chunk(1024)
            if len(part) == 0:
                break
            for i in range(len(part)):
                got.append(part[i])
    if len(got) != len(expected):
        return False
    for i in range(len(got)):
        if got[i] != expected[i]:
            return False
    return True


def _run_case(response: List[UInt8], body: List[UInt8]) raises -> Bool:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            _serve(listener, response)
        except:
            pass
        exit()
    usleep(150_000)
    var ok: Bool
    try:
        ok = _download_matches(port, body)
    except:
        ok = False
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    return ok


def main() raises:
    print("test_client_stream_download")
    var body = _body(200_000)  # ~195 KiB, spans many read buffers

    var ok_cl = _run_case(_content_length_response(body), body)
    assert_true(ok_cl, "content-length download mismatch")

    var ok_chunked = _run_case(_chunked_response(body, 4096), body)
    assert_true(ok_chunked, "chunked download mismatch")

    var ok_close = _run_case(_close_response(body), body)
    assert_true(ok_close, "close-delimited download mismatch")

    print("test_client_stream_download: 3 passed")
