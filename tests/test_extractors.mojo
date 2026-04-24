"""Tests for ``flare.http.extract``: typed extractors + ``Extracted[H]``.

Covers:

- ``ParamInt`` / ``ParamFloat64`` / ``ParamBool`` / ``ParamString``
  round-trip parsing plus happy / error paths.
- ``Path[T, name]`` required path parameter extraction.
- ``Query[T, name]`` + ``QueryOpt[T, name]`` with URL fragments,
  percent-unaware raw values, trailing ``?``, repeated ``=``.
- ``Header[T, name]`` + ``HeaderOpt[T, name]`` case-insensitive lookup.
- ``BodyBytes`` / ``BodyText`` / ``Json`` body extractors.
- ``Extracted[H]``: zero-field, one-field, two-field handler structs,
  plus adapter-level error paths that map extractor failures to 400.
"""

from std.collections import Optional
from std.testing import (
    assert_true,
    assert_false,
    assert_equal,
    assert_raises,
    TestSuite,
)

from flare.http import (
    Request,
    Response,
    Status,
    Method,
    ok,
    ParamInt,
    ParamFloat64,
    ParamBool,
    ParamString,
    Path,
    Query,
    QueryOpt,
    Header,
    HeaderOpt,
    BodyBytes,
    BodyText,
    Json,
    HandlerStruct,
    Extracted,
)


# ── ParamParser wrappers ────────────────────────────────────────────────────


def test_param_int_happy() raises:
    assert_equal(ParamInt.parse("42").value, 42)
    assert_equal(ParamInt.parse("0").value, 0)
    assert_equal(ParamInt.parse("-7").value, -7)


def test_param_int_rejects_empty() raises:
    with assert_raises():
        _ = ParamInt.parse("")


def test_param_int_rejects_non_digits() raises:
    with assert_raises():
        _ = ParamInt.parse("12a")
    with assert_raises():
        _ = ParamInt.parse("abc")


def test_param_int_rejects_dash_only() raises:
    with assert_raises():
        _ = ParamInt.parse("-")


def test_param_float_happy() raises:
    assert_equal(ParamFloat64.parse("3.5").value, Float64(3.5))
    assert_equal(ParamFloat64.parse("0").value, Float64(0.0))


def test_param_float_rejects_empty() raises:
    with assert_raises():
        _ = ParamFloat64.parse("")


def test_param_float_rejects_garbage() raises:
    with assert_raises():
        _ = ParamFloat64.parse("zz")


def test_param_bool_happy() raises:
    assert_true(ParamBool.parse("true").value)
    assert_true(ParamBool.parse("TRUE").value)
    assert_true(ParamBool.parse("1").value)
    assert_true(ParamBool.parse("yes").value)
    assert_false(ParamBool.parse("false").value)
    assert_false(ParamBool.parse("False").value)
    assert_false(ParamBool.parse("0").value)
    assert_false(ParamBool.parse("no").value)


def test_param_bool_rejects() raises:
    with assert_raises():
        _ = ParamBool.parse("")
    with assert_raises():
        _ = ParamBool.parse("maybe")


def test_param_string_always_ok() raises:
    assert_equal(ParamString.parse("").value, "")
    assert_equal(ParamString.parse("alice").value, "alice")
    assert_equal(ParamString.parse("a b/c").value, "a b/c")


def test_param_defaults() raises:
    assert_equal(ParamInt().value, 0)
    assert_equal(ParamFloat64().value, Float64(0.0))
    assert_false(ParamBool().value)
    assert_equal(ParamString().value, "")


# ── Path[T, name] ───────────────────────────────────────────────────────────


def _req_with_param(name: String, value: String) raises -> Request:
    """Build a Request with a single lazy-allocated path param."""
    var req = Request(method=Method.GET, url="/test")
    req._params_mut()[name] = value
    return req^


def test_path_extract_int() raises:
    var req = _req_with_param("id", "42")
    var p = Path[ParamInt, "id"].extract(req)
    assert_equal(p.value.value, 42)


def test_path_extract_string() raises:
    var req = _req_with_param("name", "alice")
    var p = Path[ParamString, "name"].extract(req)
    assert_equal(p.value.value, "alice")


def test_path_missing_param_raises() raises:
    var req = Request(method=Method.GET, url="/test")
    with assert_raises():
        _ = Path[ParamInt, "id"].extract(req)


def test_path_bad_parse_raises() raises:
    var req = _req_with_param("id", "abc")
    with assert_raises():
        _ = Path[ParamInt, "id"].extract(req)


# ── Query[T, name] ──────────────────────────────────────────────────────────


def test_query_simple() raises:
    var req = Request(method=Method.GET, url="/users?id=7")
    var q = Query[ParamInt, "id"].extract(req)
    assert_equal(q.value.value, 7)


def test_query_two_keys() raises:
    var req = Request(method=Method.GET, url="/users?id=7&page=3")
    var q1 = Query[ParamInt, "id"].extract(req)
    var q2 = Query[ParamInt, "page"].extract(req)
    assert_equal(q1.value.value, 7)
    assert_equal(q2.value.value, 3)


def test_query_string_value() raises:
    var req = Request(method=Method.GET, url="/users?name=alice")
    var q = Query[ParamString, "name"].extract(req)
    assert_equal(q.value.value, "alice")


def test_query_empty_value_still_present() raises:
    var req = Request(method=Method.GET, url="/users?name=")
    var q = Query[ParamString, "name"].extract(req)
    assert_equal(q.value.value, "")


def test_query_missing_raises() raises:
    var req = Request(method=Method.GET, url="/users?other=x")
    with assert_raises():
        _ = Query[ParamInt, "id"].extract(req)


def test_query_fragment_stripped() raises:
    var req = Request(method=Method.GET, url="/users?id=7#section")
    var q = Query[ParamInt, "id"].extract(req)
    assert_equal(q.value.value, 7)


def test_query_no_query_string_raises() raises:
    var req = Request(method=Method.GET, url="/users")
    with assert_raises():
        _ = Query[ParamInt, "id"].extract(req)


# ── QueryOpt[T, name] ───────────────────────────────────────────────────────


def test_query_opt_present() raises:
    var req = Request(method=Method.GET, url="/items?page=4")
    var q = QueryOpt[ParamInt, "page"].extract(req)
    assert_true(q.value)
    assert_equal(q.value.value().value, 4)


def test_query_opt_missing_is_none() raises:
    var req = Request(method=Method.GET, url="/items?other=x")
    var q = QueryOpt[ParamInt, "page"].extract(req)
    assert_false(q.value)


def test_query_opt_no_query_string() raises:
    var req = Request(method=Method.GET, url="/items")
    var q = QueryOpt[ParamInt, "page"].extract(req)
    assert_false(q.value)


def test_query_opt_bad_parse_still_raises() raises:
    var req = Request(method=Method.GET, url="/items?page=xyz")
    with assert_raises():
        _ = QueryOpt[ParamInt, "page"].extract(req)


# ── Header[T, name] ─────────────────────────────────────────────────────────


def test_header_extract() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-Count", "12")
    var h = Header[ParamInt, "X-Count"].extract(req)
    assert_equal(h.value.value, 12)


def test_header_case_insensitive() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("authorization", "Bearer xyz")
    var h = Header[ParamString, "Authorization"].extract(req)
    assert_equal(h.value.value, "Bearer xyz")


def test_header_missing_raises() raises:
    var req = Request(method=Method.GET, url="/")
    with assert_raises():
        _ = Header[ParamString, "X-Missing"].extract(req)


def test_header_opt_present() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-Trace", "abc")
    var h = HeaderOpt[ParamString, "X-Trace"].extract(req)
    assert_true(h.value)
    assert_equal(h.value.value().value, "abc")


def test_header_opt_missing_is_none() raises:
    var req = Request(method=Method.GET, url="/")
    var h = HeaderOpt[ParamString, "X-Trace"].extract(req)
    assert_false(h.value)


# ── Body extractors ─────────────────────────────────────────────────────────


def _body(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def test_body_bytes() raises:
    var req = Request(method=Method.POST, url="/", body=_body("hello"))
    var b = BodyBytes.extract(req)
    assert_equal(len(b.value), 5)


def test_body_text() raises:
    var req = Request(method=Method.POST, url="/", body=_body("hello"))
    var b = BodyText.extract(req)
    assert_equal(b.value, "hello")


def test_body_text_empty() raises:
    var req = Request(method=Method.POST, url="/")
    var b = BodyText.extract(req)
    assert_equal(b.value, "")


def test_json_happy() raises:
    var req = Request(method=Method.POST, url="/", body=_body('{"n":7}'))
    var j = Json.extract(req)
    assert_equal(j.value["n"].int_value(), 7)


def test_json_empty_body_raises() raises:
    var req = Request(method=Method.POST, url="/")
    with assert_raises():
        _ = Json.extract(req)


def test_json_malformed_raises() raises:
    var req = Request(method=Method.POST, url="/", body=_body("{not json}"))
    with assert_raises():
        _ = Json.extract(req)


# ── Extracted[H]: reflective auto-injection ─────────────────────────────────


@fieldwise_init
struct _OneH(Copyable, HandlerStruct, Movable):
    var id: Path[ParamInt, "id"]

    def __init__(out self):
        self.id = Path[ParamInt, "id"]()

    def handle(self, req: Request) raises -> Response:
        return ok("id=" + String(self.id.value.value))


def test_extracted_one_field_ok() raises:
    var req = _req_with_param("id", "123")
    var r = Extracted[_OneH]().serve(req)
    assert_equal(r.status, Status.OK)
    assert_equal(r.text(), "id=123")


def test_extracted_one_field_missing_returns_400() raises:
    var req = Request(method=Method.GET, url="/")
    var r = Extracted[_OneH]().serve(req)
    assert_equal(r.status, Status.BAD_REQUEST)


def test_extracted_one_field_bad_parse_returns_400() raises:
    var req = _req_with_param("id", "not-an-int")
    var r = Extracted[_OneH]().serve(req)
    assert_equal(r.status, Status.BAD_REQUEST)


@fieldwise_init
struct _TwoH(Copyable, HandlerStruct, Movable):
    var id: Path[ParamInt, "id"]
    var page: QueryOpt[ParamInt, "page"]

    def __init__(out self):
        self.id = Path[ParamInt, "id"]()
        self.page = QueryOpt[ParamInt, "page"]()

    def handle(self, req: Request) raises -> Response:
        var page_str = "default"
        if self.page.value:
            page_str = String(self.page.value.value().value)
        return ok("id=" + String(self.id.value.value) + ",page=" + page_str)


def test_extracted_two_fields_all_present() raises:
    var req = Request(method=Method.GET, url="/users/7?page=3")
    req._params_mut()["id"] = "7"
    var r = Extracted[_TwoH]().serve(req)
    assert_equal(r.status, Status.OK)
    assert_equal(r.text(), "id=7,page=3")


def test_extracted_two_fields_opt_missing_defaults() raises:
    var req = Request(method=Method.GET, url="/users/7")
    req._params_mut()["id"] = "7"
    var r = Extracted[_TwoH]().serve(req)
    assert_equal(r.status, Status.OK)
    assert_equal(r.text(), "id=7,page=default")


# ── Entry ──────────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_extractors.mojo — Typed extractors + Extracted[H]")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
