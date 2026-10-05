"""Tests for ``flare.http.middleware`` (— track G).

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
struct _Echo(Copyable, Defaultable, Handler):
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
struct _BigEcho(Copyable, Defaultable, Handler):
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
struct _Boom(Copyable, Defaultable, Handler):
    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        raise Error("boom")


@fieldwise_init
struct _PreEncoded(Copyable, Defaultable, Handler):
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


@fieldwise_init
struct _Partial(Copyable, Defaultable, Handler):
    """Returns what ``FileServer`` returns for ``Range: bytes=0-2047``: a 206
    with 2048 identity bytes and the matching ``Content-Range``."""

    var status: Int

    def __init__(out self):
        self.status = 206

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=self.status)
        resp.body = List[UInt8](length=2048, fill=UInt8(65))
        resp.headers.set("Content-Range", "bytes 0-2047/10000")
        resp.headers.set("Content-Length", "2048")
        resp.headers.set("Accept-Ranges", "bytes")
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


def test_negotiate_wildcard_alone_selects_best_available_coding() raises:
    """``*`` gives every coding without its own entry the wildcard weight
    (RFC 9110 sec 12.5.3), so a bare ``*`` is acceptable for gzip / br and
    the usual tie-break (br > gzip > identity) picks the coding. It used to
    be pinned to identity, which was the APP-20 wildcard bug (Decision:
    expectation updated with the fix)."""
    var p = negotiate_encoding("*", False)
    assert_equal(p.encoding, "gzip")
    assert_equal(p.quality, 1000)
    var b = negotiate_encoding("*", True)
    assert_equal(b.encoding, "br")


def test_negotiate_wildcard_weight_applies_to_unlisted_codings() raises:
    """APP-20: ``gzip;q=0.5, *`` gives br weight 1 through ``*``."""
    var p = negotiate_encoding("gzip;q=0.5, *", True)
    assert_equal(p.encoding, "br")
    assert_equal(p.quality, 1000)
    var g = negotiate_encoding("gzip;q=0.5, *;q=0.2", False)
    assert_equal(g.encoding, "gzip")
    assert_equal(g.quality, 500)


def test_negotiate_wildcard_is_order_independent() raises:
    """APP-20: the same entries in another order give the same pick."""
    for brotli in [True, False]:
        var a = negotiate_encoding("gzip;q=0.5, *", brotli)
        var b = negotiate_encoding("*, gzip;q=0.5", brotli)
        assert_equal(a.encoding, b.encoding)
        assert_equal(a.quality, b.quality)
    var c = negotiate_encoding("*;q=0.3, br;q=0.4, gzip;q=0.1", True)
    var d = negotiate_encoding("gzip;q=0.1, *;q=0.3, br;q=0.4", True)
    assert_equal(c.encoding, "br")
    assert_equal(d.encoding, "br")


def test_negotiate_identity_refused_with_wildcard() raises:
    """APP-20: ``identity;q=0, *`` must not select the refused identity."""
    var p = negotiate_encoding("identity;q=0, *", False)
    assert_equal(p.encoding, "gzip")
    assert_equal(p.quality, 1000)
    var q = negotiate_encoding("*, identity;q=0", False)
    assert_equal(q.encoding, "gzip")
    var r = negotiate_encoding("*;q=0", True)
    assert_equal(r.quality, 0)
    var t = negotiate_encoding("gzip;q=0, identity;q=0, *;q=0.5", False)
    assert_equal(t.quality, 0)


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


def test_compress_partial_content_passthrough() raises:
    """APP-26: a 206 keeps its identity body, Content-Range and
    Content-Length; the offsets refer to the unencoded representation."""
    var c = Compress(_Partial(), min_size_bytes=1024)
    var req = Request(method=Method.GET, url="/big.bin")
    req.headers.set("Range", "bytes=0-2047")
    req.headers.set("Accept-Encoding", "gzip, br")
    var resp = c.serve(req)
    assert_equal(resp.status, 206)
    assert_false(resp.headers.contains("content-encoding"))
    assert_equal(len(resp.body), 2048)
    assert_equal(resp.headers.get("content-range"), "bytes 0-2047/10000")
    assert_equal(resp.headers.get("content-length"), "2048")


def test_compress_content_range_header_passthrough() raises:
    """APP-26: any response carrying Content-Range is passed through, even
    when its status is not 206."""
    var c = Compress(_Partial(status=200), min_size_bytes=1024)
    var req = Request(method=Method.GET, url="/big.bin")
    req.headers.set("Accept-Encoding", "gzip")
    var resp = c.serve(req)
    assert_false(resp.headers.contains("content-encoding"))
    assert_equal(len(resp.body), 2048)
    assert_equal(resp.headers.get("content-range"), "bytes 0-2047/10000")


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


struct _NoDefault(Copyable, Handler):
    """A handler with required state and no default constructor.

    Before middleware dropped its ``Defaultable`` bound, a handler like
    this could not be wrapped by any of the stock middleware, and the
    workaround was a dummy ``var _placeholder: UInt8`` field.
    """

    var greeting: String

    def __init__(out self, greeting: String):
        self.greeting = greeting

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting)


def test_middleware_wraps_a_handler_without_a_default() raises:
    var stack = CatchPanic(Logger(RequestId(_NoDefault("hi there"))))
    var req = Request(method=String("GET"), url=String("/"))
    var resp = stack.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(String(unsafe_from_utf8=Span(resp.body)), "hi there")


def main() raises:
    test_negotiate_empty_header_identity()
    test_negotiate_gzip_only()
    test_negotiate_brotli_preferred()
    test_negotiate_brotli_unavailable_falls_back_to_gzip()
    test_negotiate_q_values()
    test_negotiate_q_zero_rejects_encoding()
    test_negotiate_wildcard_alone_selects_best_available_coding()
    test_negotiate_wildcard_weight_applies_to_unlisted_codings()
    test_negotiate_wildcard_is_order_independent()
    test_negotiate_identity_refused_with_wildcard()
    test_logger_passthrough()
    test_logger_propagates_raise()
    test_request_id_echoes_inbound()
    test_request_id_generates_when_absent()
    test_compress_small_body_passthrough()
    test_compress_large_body_gzipped()
    test_compress_no_acceptable_encoding_skips()
    test_compress_already_encoded_skipped()
    test_compress_partial_content_passthrough()
    test_compress_content_range_header_passthrough()
    test_catch_panic_returns_500()
    test_catch_panic_passthrough_when_ok()
    test_middleware_wraps_a_handler_without_a_default()
    print("test_middleware: 20 passed")
