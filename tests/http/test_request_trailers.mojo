"""Request trailers reach ``Request.trailers`` on h1, h2 and h3.

h1 skipped them, h2 merged them into the headers (a trailing
``authorization`` became a request header), h3 dropped them. Fields a
trailer may not carry (RFC 9110 sec 6.5.1) are dropped.
"""

from std.testing import TestSuite, assert_equal, assert_true

from flare.http import HttpServer, Request, Response, ok
from flare.http.headers import HeaderMap
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.testing import fork_server, kill_forked_server
from flare.http.proto.chunked import decode_chunked_trailers
from flare.http2 import (
    Frame,
    FrameFlags,
    FrameType,
    H2_PREFACE,
    HpackEncoder,
    HpackHeader,
    Http2Connection,
    encode_frame,
)
from flare.http3 import (
    Http3Connection,
    encode_request_data,
    encode_request_headers,
    encode_request_trailers,
)
from flare.qpack import QpackHeader


def _b(s: String) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def test_h1_chunked_trailers() raises:
    var buf = _b(
        "3\r\nabc\r\n0\r\nX-Checksum:  sha \r\nContent-Length: 9\r\n\r\n"
    )
    var trailers = HeaderMap()
    decode_chunked_trailers(Span[UInt8, _](buf), 0, trailers)
    assert_equal(trailers.get("x-checksum"), "sha")
    assert_equal(trailers.get("content-length"), "")
    var bad = _b("0\r\nno-colon\r\n\r\n")
    var raised = False
    try:
        decode_chunked_trailers(Span[UInt8, _](bad), 0, trailers)
    except:
        raised = True
    assert_true(raised, "a trailer line without a colon is malformed")


def _checksum(req: Request) raises -> Response:
    return ok(req.trailers.get("x-checksum"))


def _post(port: UInt16, trailer: String) raises -> String:
    var c = TcpStream.connect(SocketAddr.localhost(port))
    c.set_recv_timeout(3000)
    var wire = _b(
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n3\r\nabc\r\n0\r\n"
        + trailer
        + "\r\n\r\n"
    )
    c.write_all(Span[UInt8, _](wire))
    var got = List[UInt8]()
    var tmp = List[UInt8](length=4096, fill=0)
    while True:
        var n = c.read(tmp.unsafe_ptr(), 4096)
        if n <= 0:
            break
        got.extend(Span[UInt8, _](tmp)[:n])
    return String(unsafe_from_utf8=Span[UInt8, _](got))


def test_h1_trailers_reach_the_handler() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    var pid = fork_server(srv^, _checksum)
    var good = _post(port, "X-Checksum: sha")
    var bad = _post(port, "no-colon")
    kill_forked_server(pid)
    assert_true(good.startswith("HTTP/1.1 200") and good.endswith("sha"), good)
    assert_true(bad.startswith("HTTP/1.1 400"), bad)


def _h2_headers(
    sid: Int, hdrs: List[HpackHeader], end_stream: Bool, mut enc: HpackEncoder
) raises -> List[UInt8]:
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = sid
    var flags = FrameFlags.END_HEADERS()
    if end_stream:
        flags = flags | FrameFlags.END_STREAM()
    f.header.flags = FrameFlags(flags)
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    return encode_frame(f)


def test_h2_trailers_are_not_headers() raises:
    var c = Http2Connection()
    var wire = List[UInt8](String(H2_PREFACE).as_bytes())
    var st = Frame()
    st.header.type = FrameType.SETTINGS()
    wire.extend(Span[UInt8, _](encode_frame(st)))
    var enc = HpackEncoder()
    var h = List[HpackHeader]()
    h.append(HpackHeader(":method", "POST"))
    h.append(HpackHeader(":scheme", "https"))
    h.append(HpackHeader(":path", "/"))
    h.append(HpackHeader(":authority", "example.com"))
    wire.extend(Span[UInt8, _](_h2_headers(1, h, False, enc)))
    var d = Frame()
    d.header.type = FrameType.DATA()
    d.header.stream_id = 1
    d.payload = _b("hi")
    wire.extend(Span[UInt8, _](encode_frame(d)))
    var t = List[HpackHeader]()
    t.append(HpackHeader("x-checksum", "sha"))
    t.append(HpackHeader("authorization", "Bearer x"))
    wire.extend(Span[UInt8, _](_h2_headers(1, t, True, enc)))
    c.feed(Span[UInt8, _](wire))
    var req = c.take_request(1)
    assert_equal(req.trailers.get("x-checksum"), "sha")
    assert_equal(req.headers.get("x-checksum"), "")
    assert_equal(req.headers.get("authorization"), "")
    assert_equal(req.trailers.get("authorization"), "")


def test_h3_trailers() raises:
    var h3 = Http3Connection()
    var wire = List[UInt8]()
    encode_request_headers(
        "POST", "https", "example.com", "/", List[QpackHeader](), wire
    )
    encode_request_data(_b("hi"), wire)
    var t = List[QpackHeader]()
    t.append(QpackHeader("x-checksum", "sha"))
    t.append(QpackHeader("host", "evil"))
    encode_request_trailers(t, wire)
    h3.feed_stream_frame(0, 0, Span[UInt8, _](wire), True)
    var req = h3.take_request(0)
    assert_equal(req.trailers.get("x-checksum"), "sha")
    assert_equal(req.trailers.get("host"), "")
    assert_equal(String(unsafe_from_utf8=Span[UInt8, _](req.body)), "hi")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
