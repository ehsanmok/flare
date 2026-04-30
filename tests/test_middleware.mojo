"""Tests for ``flare.http.middleware`` (v0.6 — track G).

Covers:

- ``negotiate_encoding`` happy path + q-value tie-breaking +
  brotli gating + identity fallback + wildcard + zero-q rejection.
- ``Logger`` wraps an inner handler without altering the response.
- ``RequestId`` echoes inbound id + generates on absence.
- ``Compress`` transforms a large body to gzip when accepted, leaves
  small bodies untouched, leaves already-encoded responses alone,
  sets ``Vary``.
- ``CatchPanic`` turns inner ``raise`` into a 500.
"""

from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.http import (
    CatchPanic,
    Compress,
    Handler,
    HeaderMap,
    Logger,
    Method,
    Request,
    RequestId,
    Response,
    decompress_gzip,
    negotiate_encoding,
    ok,
)


# ── A minimal Handler that returns a fixed body ───────────────────────────


@fieldwise_init
struct _Echo(Copyable, Defaultable, Handler, Movable):
    var status: Int
    var body: String

    def __init__(out self):
        self.status = 200
        self.body = "ok"

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=self.status)
        resp.body = List[UInt8](self.body.as_bytes())
        resp.headers.set("Content-Type", "text/plain")
        resp.headers.set("Content-Length", String(len(resp.body)))
        return resp^


@fieldwise_init
struct _BigEcho(Copyable, Defaultable, Handler, Movable):
    """Returns a 4 KiB body so Compress will actually compress it."""

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        var body = String("")
        for _ in range(4096):
            body += "x"
        resp.body = List[UInt8](body.as_bytes())
        resp.headers.set("Content-Type", "text/plain")
        resp.headers.set("Content-Length", String(len(resp.body)))
        return resp^


@fieldwise_init
struct _Boom(Copyable, Defaultable, Handler, Movable):
    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        raise Error("boom")


@fieldwise_init
struct _PreEncoded(Copyable, Defaultable, Handler, Movable):
    """Returns a 2 KiB body already tagged ``Content-Encoding: br``."""

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        var body = String("")
        for _ in range(2048):
            body += "y"
        resp.body = List[UInt8](body.as_bytes())
        resp.headers.set("Content-Encoding", "br")
        return resp^


# ── negotiate_encoding ────────────────────────────────────────────────────


def test_negotiate_empty_header_identity() raises:
    var p = negotiate_encoding("", True)
    assert_equal(p.encoding, "identity")
    assert_equal(p.quality, 1000)


def test_negotiate_gzip_only() raises:
    var p = negotiate_encoding("gzip", True)
    assert_equal(p.encoding, "gzip")


def test_negotiate_brotli_preferred() raises:
    var p = negotiate_encoding("gzip, br", True)
    assert_equal(p.encoding, "br")


def test_negotiate_brotli_unavailable_falls_back_to_gzip() raises:
    var p = negotiate_encoding("gzip, br", False)
    assert_equal(p.encoding, "gzip")


def test_negotiate_q_values() raises:
    var p = negotiate_encoding("gzip;q=0.5, br;q=0.9", True)
    assert_equal(p.encoding, "br")


def test_negotiate_q_zero_rejects_encoding() raises:
    var p = negotiate_encoding("gzip;q=0", False)
    assert_equal(p.quality, 0)


def test_negotiate_wildcard_falls_back_to_identity() raises:
    var p = negotiate_encoding("*", False)
    assert_equal(p.encoding, "identity")


# ── Logger / RequestId ────────────────────────────────────────────────────


def test_logger_passthrough() raises:
    var inner = _Echo(status=200, body="hi")
    var lg = Logger(inner^, prefix="[t]")
    var req = Request(method=Method.GET, url="/")
    var resp = lg.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "hi")


def test_logger_propagates_raise() raises:
    var lg = Logger(_Boom())
    var req = Request(method=Method.GET, url="/")
    with assert_raises():
        _ = lg.serve(req)


def test_request_id_echoes_inbound() raises:
    var rid = RequestId(_Echo(status=200, body="hi"))
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-Request-Id", "abc-123")
    var resp = rid.serve(req)
    assert_equal(resp.headers.get("x-request-id"), "abc-123")


def test_request_id_generates_when_absent() raises:
    var rid = RequestId(_Echo(status=200, body="hi"))
    var req = Request(method=Method.GET, url="/")
    var resp = rid.serve(req)
    var generated = resp.headers.get("x-request-id")
    assert_true(generated.byte_length() > 0)
    assert_true(generated.startswith("req-"))


# ── Compress ──────────────────────────────────────────────────────────────


def test_compress_small_body_passthrough() raises:
    var c = Compress(_Echo(status=200, body="hi"), min_size_bytes=1024)
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Accept-Encoding", "gzip")
    var resp = c.serve(req)
    assert_false(resp.headers.contains("content-encoding"))
    assert_equal(resp.text(), "hi")


def test_compress_large_body_gzipped() raises:
    var c = Compress(_BigEcho(), min_size_bytes=1024)
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Accept-Encoding", "gzip")
    var resp = c.serve(req)
    assert_equal(resp.headers.get("content-encoding"), "gzip")
    assert_equal(resp.headers.get("vary"), "Accept-Encoding")
    var roundtrip = decompress_gzip(Span[UInt8, _](resp.body))
    assert_equal(len(roundtrip), 4096)


def test_compress_no_acceptable_encoding_skips() raises:
    var c = Compress(_BigEcho(), min_size_bytes=1024)
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Accept-Encoding", "gzip;q=0")
    var resp = c.serve(req)
    assert_false(resp.headers.contains("content-encoding"))


def test_compress_already_encoded_skipped() raises:
    var c = Compress(_PreEncoded(), min_size_bytes=1024)
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Accept-Encoding", "gzip")
    var resp = c.serve(req)
    assert_equal(resp.headers.get("content-encoding"), "br")


# ── CatchPanic ────────────────────────────────────────────────────────────


def test_catch_panic_returns_500() raises:
    var c = CatchPanic(_Boom())
    var req = Request(method=Method.GET, url="/")
    var resp = c.serve(req)
    assert_equal(resp.status, 500)


def test_catch_panic_passthrough_when_ok() raises:
    var c = CatchPanic(_Echo(status=200, body="hi"))
    var req = Request(method=Method.GET, url="/")
    var resp = c.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "hi")


def main() raises:
    test_negotiate_empty_header_identity()
    test_negotiate_gzip_only()
    test_negotiate_brotli_preferred()
    test_negotiate_brotli_unavailable_falls_back_to_gzip()
    test_negotiate_q_values()
    test_negotiate_q_zero_rejects_encoding()
    test_negotiate_wildcard_falls_back_to_identity()
    test_logger_passthrough()
    test_logger_propagates_raise()
    test_request_id_echoes_inbound()
    test_request_id_generates_when_absent()
    test_compress_small_body_passthrough()
    test_compress_large_body_gzipped()
    test_compress_no_acceptable_encoding_skips()
    test_compress_already_encoded_skipped()
    test_catch_panic_returns_500()
    test_catch_panic_passthrough_when_ok()
    print("test_middleware: 17 passed")
