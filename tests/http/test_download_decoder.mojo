"""Incremental HTTP/1 response framing and bounded-reading contracts."""

from std.testing import assert_equal, assert_raises, TestSuite
from std.ffi import external_call
from flare.io.buf_reader import Readable
from flare.http import HttpDownload


struct Pieces(Movable, Readable):
    var bytes: List[UInt8]
    var pos: Int
    var cap: Int

    def __init__(out self, text: String, cap: Int = 1):
        self.bytes = List[UInt8](text.as_bytes())
        self.pos = 0
        self.cap = cap

    def read(mut self, buf: Pointer[UInt8, _], size: Int) raises -> Int:
        var n = min(self.cap, min(size, len(self.bytes) - self.pos))
        if n > 0:
            _ = external_call["memcpy", NoneType, Int, Int, Int](
                Int(buf),
                Int(self.bytes.unsafe_ptr().unsafe_offset(self.pos)),
                n,
            )
        self.pos += n
        return n


def test_h1_informationals_duplicates_and_trailers() raises:
    var wire = String(
        "HTTP/1.1 103 Early Hints\r\nLink: x\r\n\r\nHTTP/1.1 200"
        " OK\r\nTransfer-Encoding: chunked\r\nX-Value: a\r\nX-Value:"
        " b\r\n\r\n3\r\nabc\r\n0\r\nX-End: one\r\nX-End: two\r\n\r\n"
    )
    for cap in [1, 2, 17, 65536]:
        var dl = HttpDownload(Pieces(wire, cap))
        assert_equal(dl.status, 200)
        assert_equal(len(dl.headers.get_all("X-Value")), 2)
        assert_equal(dl.header("Link"), "")
        var body = dl.read_all(2)
        assert_equal(String(unsafe_from_utf8=Span(body)), "abc")
        assert_equal(len(dl.trailers.get_all("X-End")), 2)


def test_h1_yields_data_before_chunk_terminator_arrives() raises:
    var dl = HttpDownload(
        Pieces(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc",
            65536,
        )
    )
    assert_equal(len(dl.read_chunk(3)), 3)
    with assert_raises():
        _ = dl.read_chunk()


def test_h1_bodyless_and_invalid_framing() raises:
    var head = HttpDownload(
        Pieces("HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n"), "HEAD"
    )
    assert_equal(len(head.read_chunk()), 0)
    for status in [204, 304]:
        var dl = HttpDownload(
            Pieces(
                "HTTP/1.1 "
                + String(status)
                + " Empty\r\nContent-Length: 123\r\n\r\n"
            )
        )
        assert_equal(len(dl.read_chunk()), 0)
    for framing in [
        "Content-Length: -1",
        "Content-Length: 4\r\nContent-Length: 3",
        "Content-Length: 3\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: gzip",
    ]:
        with assert_raises():
            _ = HttpDownload(
                Pieces("HTTP/1.1 200 OK\r\n" + framing + "\r\n\r\n")
            )
    for wire in [
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab",
        (
            "HTTP/1.1 200 OK\r\nTransfer-Encoding:"
            " chunked\r\n\r\n1\r\naXX0\r\n\r\n"
        ),
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: y\r\n",
    ]:
        with assert_raises():
            var dl = HttpDownload(Pieces(wire))
            _ = dl.read_all()


def test_h1_header_limit_and_invalid_cap() raises:
    with assert_raises():
        _ = HttpDownload(
            Pieces("HTTP/1.1 200 OK\r\nX: " + "a" * 80 + "\r\n\r\n"),
            max_header_bytes=64,
        )
    var dl = HttpDownload(
        Pieces("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    )
    with assert_raises():
        _ = dl.read_chunk(0)


def test_h1_rejects_smuggling_shaped_heads() raises:
    """Field-line shapes that let two parsers disagree are refused.

    Each of these is a request-smuggling primitive rather than a
    cosmetic defect: they are the cases where this reader and the origin
    could come away with different ideas about where the message ends.
    The server side of the tree refuses all of them by default, via the
    matching flags in ``flare.http.proto.h1_leniency``.
    """
    for head in [
        # obs-fold continuation: the folded line must not surface as a
        # header field of its own.
        "X-Foo: bar\r\n evil: value",
        "X-Foo: bar\r\n\tevil: value",
        # Whitespace between field name and colon.
        "Content-Length : 5",
        "Content-Length\t: 5",
        # Duplicate Content-Length, agreeing. Refused like the server.
        "Content-Length: 4\r\nContent-Length: 4",
        # chunked must be the final coding, and nothing else is decoded.
        "Transfer-Encoding: chunked, gzip",
        "Transfer-Encoding: gzip, chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
    ]:
        with assert_raises():
            _ = HttpDownload(Pieces("HTTP/1.1 200 OK\r\n" + head + "\r\n\r\n"))


def test_h1_rejects_whitespace_in_chunk_size() raises:
    """ " 3" and "3 " must not both mean a chunk of three bytes."""
    for size_line in [" 3", "3 ", "\t3", "3\t"]:
        with assert_raises():
            var dl = HttpDownload(
                Pieces(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + size_line
                    + "\r\nabc\r\n0\r\n\r\n"
                )
            )
            _ = dl.read_all()


def test_h1_connect_2xx_has_no_body() raises:
    """RFC 9110 sec 9.3.6: a 2xx to CONNECT is a tunnel, not a body.

    Without the CONNECT arm this response has neither Content-Length nor
    Transfer-Encoding, so it falls through to the read-until-close mode
    and the reader hands tunnel bytes back as though they were a body.
    """
    var dl = HttpDownload(
        Pieces("HTTP/1.1 200 Connection Established\r\n\r\nTUNNELBYTES"),
        "CONNECT",
    )
    assert_equal(len(dl.read_chunk()), 0)


def test_h1_eof_delimited_body() raises:
    """No Content-Length and no Transfer-Encoding: body ends at EOF.

    The whole of the read-until-close mode, which nothing else covers.
    """
    var dl = HttpDownload(
        Pieces("HTTP/1.1 200 OK\r\nX: y\r\n\r\nhello world", 65536)
    )
    var body = dl.read_all()
    assert_equal(String(unsafe_from_utf8=Span(body)), "hello world")


def test_h1_rejects_upgrade_and_out_of_range_status() raises:
    with assert_raises():
        _ = HttpDownload(
            Pieces("HTTP/1.1 101 Switching Protocols\r\nUpgrade: ws\r\n\r\n")
        )
    for code in ["099", "600"]:
        with assert_raises():
            _ = HttpDownload(Pieces("HTTP/1.1 " + code + " Odd\r\n\r\n"))


def test_h1_rejects_oversized_chunk_size_and_bad_trailers() raises:
    # Hex that overflows Int rather than merely being large.
    with assert_raises():
        var dl = HttpDownload(
            Pieces(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + "f" * 32
                + "\r\nabc\r\n"
            )
        )
        _ = dl.read_all()
    # A trailer section may not carry framing or routing fields.
    for trailer in ["Content-Length: 3", "Host: evil"]:
        with assert_raises():
            var dl2 = HttpDownload(
                Pieces(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding:"
                    " chunked\r\n\r\n3\r\nabc\r\n0\r\n"
                    + trailer
                    + "\r\n\r\n"
                )
            )
            _ = dl2.read_all()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
