"""Tests for ``flare.http.extract`` body extractors + ``Extracted[H]``.

The path/query/header concrete extractors are exercised in
``tests/http/test_extractors_concrete.mojo`` — this file focuses on
the orthogonal surface: body extractors (``BodyBytes``,
``BodyText``, ``Json``) and the reflective ``Extracted[H]`` adapter
that turns a handler struct into a single request handler.

The v0.7 parametric ``Path[T: ParamParser, name]`` layer was deleted
in v0.8 (the wrappers added a ``.value.value`` chain at every call
site and never carried a custom ``ParamParser`` impl in practice);
the equivalent test coverage now lives in the concrete-extractor
file.
"""

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
    PathInt,
    OptionalQueryInt,
    BodyBytes,
    BodyText,
    Json,
    Handler,
    Extracted,
)


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
struct _OneH(Copyable, Defaultable, Handler, Movable):
    var id: PathInt["id"]

    def __init__(out self):
        self.id = PathInt["id"]()

    def serve(self, req: Request) raises -> Response:
        return ok("id=" + String(self.id.value))


def _req_with_param(name: String, value: String) raises -> Request:
    var req = Request(method=Method.GET, url="/test")
    req.params_mut()[name] = value
    return req^


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
struct _TwoH(Copyable, Defaultable, Handler, Movable):
    var id: PathInt["id"]
    var page: OptionalQueryInt["page"]

    def __init__(out self):
        self.id = PathInt["id"]()
        self.page = OptionalQueryInt["page"]()

    def serve(self, req: Request) raises -> Response:
        var page_str = "default"
        if self.page.value:
            page_str = String(self.page.value.value())
        return ok("id=" + String(self.id.value) + ",page=" + page_str)


def test_extracted_two_fields_all_present() raises:
    var req = Request(method=Method.GET, url="/users/7?page=3")
    req.params_mut()["id"] = "7"
    var r = Extracted[_TwoH]().serve(req)
    assert_equal(r.status, Status.OK)
    assert_equal(r.text(), "id=7,page=3")


def test_extracted_two_fields_opt_missing_defaults() raises:
    var req = Request(method=Method.GET, url="/users/7")
    req.params_mut()["id"] = "7"
    var r = Extracted[_TwoH]().serve(req)
    assert_equal(r.status, Status.OK)
    assert_equal(r.text(), "id=7,page=default")


# ── Entry ──────────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_extractors.mojo — Body extractors + Extracted[H]")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
