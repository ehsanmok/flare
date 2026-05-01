"""Tests for :mod:`flare.http.conditional` — RFC 9110 §13.

Covers the full precedence ordering (If-Match > If-Unmodified-Since
> If-None-Match > If-Modified-Since), strong vs weak ETag
comparison, the wildcard-``*`` matcher, the 304 / 412 rewrite shape
(body + Content-Length must be dropped on 304), the auto-ETag
opt-in, and the HTTP-date parser's recognition of the IMF-fixdate
shape.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from flare.http.conditional import (
    Conditional,
    fnv1a_etag,
)
from flare.http.handler import Handler
from flare.http.headers import HeaderMap
from flare.http.request import Request
from flare.http.response import Response


# ── Reusable inner handler that emits a fixed ETag + Last-Modified ────────


struct _Etag200(Copyable, Defaultable, Handler, Movable):
    """Inner handler that always returns 200 with a configured ETag
    + Last-Modified pair. Body is the literal ``"hello"`` (5 bytes)
    so we can assert the 304 path drops it."""

    var etag: String
    var last_modified: String

    def __init__(out self):
        self.etag = String('"v1"')
        self.last_modified = String("Sun, 06 Nov 1994 08:49:37 GMT")

    def __init__(out self, etag: String, last_modified: String):
        self.etag = etag
        self.last_modified = last_modified

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8](String("hello").as_bytes())
        if self.etag.byte_length() > 0:
            resp.headers.set("ETag", self.etag)
        if self.last_modified.byte_length() > 0:
            resp.headers.set("Last-Modified", self.last_modified)
        resp.headers.set("Content-Type", "text/plain")
        resp.headers.set("Content-Length", String(len(resp.body)))
        return resp^


struct _NoMetadata200(Copyable, Defaultable, Handler, Movable):
    """Inner handler that returns 200 without ETag / Last-Modified.
    Drives the auto-ETag path."""

    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8](String("body-bytes").as_bytes())
        resp.headers.set("Content-Type", "text/plain")
        return resp^


# ── Helpers ───────────────────────────────────────────────────────────────


def _req(method: String) -> Request:
    """Build a bare Request with no precondition headers."""
    return Request(method=method, url=String("/x"))


# ── Pass-through (no precondition) ─────────────────────────────────────────


def test_passthrough_when_no_precondition_headers() raises:
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("GET")
    var resp = c.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), 5)
    assert_equal(resp.headers.get("etag"), '"v1"')


# ── If-None-Match → 304 (GET) ─────────────────────────────────────────────


def test_if_none_match_exact_returns_304_for_get() raises:
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("GET")
    req.headers.set("If-None-Match", '"v1"')
    var resp = c.serve(req)
    assert_equal(resp.status, 304)
    assert_equal(resp.reason, "Not Modified")
    # Body MUST be empty per RFC 9110 §15.4.5.
    assert_equal(len(resp.body), 0)
    # Content-Length / Content-Type stripped; ETag preserved.
    assert_false(resp.headers.contains("content-length"))
    assert_false(resp.headers.contains("content-type"))
    assert_equal(resp.headers.get("etag"), '"v1"')


def test_if_none_match_wildcard_returns_304_for_get() raises:
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("GET")
    req.headers.set("If-None-Match", "*")
    var resp = c.serve(req)
    assert_equal(resp.status, 304)


def test_if_none_match_csv_with_match_returns_304() raises:
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("GET")
    req.headers.set("If-None-Match", '"v0", "v1", "v2"')
    var resp = c.serve(req)
    assert_equal(resp.status, 304)


def test_if_none_match_no_match_passes_through() raises:
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("GET")
    req.headers.set("If-None-Match", '"v9"')
    var resp = c.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), 5)


# ── If-None-Match → 412 (state-changing methods) ──────────────────────────


def test_if_none_match_match_returns_412_for_put() raises:
    """Per RFC 9110 §13.1.2: state-changing methods that match
    If-None-Match get 412 Precondition Failed instead of 304."""
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("PUT")
    req.headers.set("If-None-Match", '"v1"')
    var resp = c.serve(req)
    assert_equal(resp.status, 412)
    assert_equal(resp.reason, "Precondition Failed")


# ── Weak vs strong ETag comparison ────────────────────────────────────────


def test_weak_etag_matches_strong_for_safe_method() raises:
    """If-None-Match (GET) uses weak comparison: W/"v1" matches "v1"."""
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("GET")
    req.headers.set("If-None-Match", 'W/"v1"')
    var resp = c.serve(req)
    assert_equal(resp.status, 304)


def test_weak_etag_does_not_match_strong_for_if_match() raises:
    """If-Match always uses strong comparison; W/"v1" never matches."""
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("GET")
    req.headers.set("If-Match", 'W/"v1"')
    var resp = c.serve(req)
    assert_equal(resp.status, 412)


# ── If-Match → 412 ────────────────────────────────────────────────────────


def test_if_match_no_match_returns_412() raises:
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("PUT")
    req.headers.set("If-Match", '"v9"')
    var resp = c.serve(req)
    assert_equal(resp.status, 412)


def test_if_match_wildcard_passes_when_resource_exists() raises:
    """``If-Match: *`` matches any current representation."""
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("PUT")
    req.headers.set("If-Match", "*")
    var resp = c.serve(req)
    assert_equal(resp.status, 200)


def test_if_match_match_passes_through() raises:
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("PUT")
    req.headers.set("If-Match", '"v1"')
    var resp = c.serve(req)
    assert_equal(resp.status, 200)


# ── If-Modified-Since → 304 ───────────────────────────────────────────────


def test_if_modified_since_not_modified_returns_304() raises:
    """Server Last-Modified <= client If-Modified-Since → 304."""
    var c = Conditional[_Etag200](
        _Etag200(String(""), String("Sun, 06 Nov 1994 08:49:37 GMT"))
    )
    var req = _req("GET")
    req.headers.set("If-Modified-Since", "Mon, 07 Nov 1994 00:00:00 GMT")
    var resp = c.serve(req)
    assert_equal(resp.status, 304)


def test_if_modified_since_modified_passes_through() raises:
    var c = Conditional[_Etag200](
        _Etag200(String(""), String("Sun, 06 Nov 1994 08:49:37 GMT"))
    )
    var req = _req("GET")
    req.headers.set("If-Modified-Since", "Sat, 05 Nov 1994 00:00:00 GMT")
    var resp = c.serve(req)
    assert_equal(resp.status, 200)


def test_if_modified_since_ignored_when_if_none_match_present() raises:
    """RFC 9110 §13.1.3: a recipient MUST ignore IMS when INM is
    present. Here INM doesn't match → 200 from INM-non-match;
    the (would-be 304) IMS is ignored."""
    var c = Conditional[_Etag200](_Etag200())
    var req = _req("GET")
    req.headers.set("If-None-Match", '"v9"')
    req.headers.set("If-Modified-Since", "Mon, 07 Nov 1994 00:00:00 GMT")
    var resp = c.serve(req)
    assert_equal(resp.status, 200)


# ── If-Unmodified-Since → 412 ─────────────────────────────────────────────


def test_if_unmodified_since_modified_returns_412() raises:
    """Server Last-Modified > client If-Unmodified-Since → 412."""
    var c = Conditional[_Etag200](
        _Etag200(String(""), String("Sun, 06 Nov 1994 08:49:37 GMT"))
    )
    var req = _req("PUT")
    req.headers.set("If-Unmodified-Since", "Sat, 05 Nov 1994 00:00:00 GMT")
    var resp = c.serve(req)
    assert_equal(resp.status, 412)


def test_if_unmodified_since_not_modified_passes_through() raises:
    var c = Conditional[_Etag200](
        _Etag200(String(""), String("Sun, 06 Nov 1994 08:49:37 GMT"))
    )
    var req = _req("PUT")
    req.headers.set("If-Unmodified-Since", "Mon, 07 Nov 1994 00:00:00 GMT")
    var resp = c.serve(req)
    assert_equal(resp.status, 200)


# ── Auto-ETag ─────────────────────────────────────────────────────────────


def test_auto_etag_off_by_default() raises:
    """Default Conditional does NOT synthesise an ETag."""
    var c = Conditional[_NoMetadata200](_NoMetadata200())
    var req = _req("GET")
    var resp = c.serve(req)
    assert_false(resp.headers.contains("etag"))


def test_auto_etag_synthesises_weak_tag() raises:
    var c = Conditional[_NoMetadata200].with_auto_etag(_NoMetadata200())
    var req = _req("GET")
    var resp = c.serve(req)
    var et = resp.headers.get("etag")
    assert_true(et.byte_length() >= 4)
    assert_equal(chr(Int(et.unsafe_ptr()[0])), "W")


def test_fnv1a_etag_is_deterministic() raises:
    var b1 = String("hello").as_bytes()
    var b2 = String("hello").as_bytes()
    var t1 = fnv1a_etag(Span[UInt8, _](b1))
    var t2 = fnv1a_etag(Span[UInt8, _](b2))
    assert_equal(t1, t2)


def test_fnv1a_etag_changes_with_body() raises:
    var b1 = String("hello").as_bytes()
    var b2 = String("hellp").as_bytes()
    var t1 = fnv1a_etag(Span[UInt8, _](b1))
    var t2 = fnv1a_etag(Span[UInt8, _](b2))
    assert_true(t1 != t2)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
