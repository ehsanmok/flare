"""Tests for the concrete primitive extractors (v0.5.0 Step 2 /
Track 1.3).

The parametric ``Path[T: ParamParser, name]`` etc. wrap parsed
values in a ``ParamParser`` (``ParamInt``, ``ParamString``, ...)
which itself wraps a primitive — the v0.4.x ``.value.value``
chain. These concrete types collapse the chain by exposing
``.value`` as the primitive directly.

Covers:

- Each concrete returns the right primitive on a happy path.
- Missing required parameter / header raises (``Path*``,
  ``Query*``, ``Header*``).
- Missing optional parameter / header gives ``None`` without
  raising (``OptionalQuery*``, ``OptionalHeader*``).
- Parse failures on present values raise (the same shape the
  parametric extractors gave).
- Each concrete is registerable as a field of a Handler struct
  driven through ``Extracted[H]`` — the primary use case from
  the README and example 19.
- Re-exports from ``flare.http`` and the root ``flare`` package
  resolve.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)

from flare.http import (
    Request,
    Response,
    Method,
    Status,
    ok,
    Handler,
    Extracted,
    PathInt,
    PathStr,
    PathFloat,
    PathBool,
    QueryInt,
    QueryStr,
    QueryFloat,
    QueryBool,
    OptionalQueryInt,
    OptionalQueryStr,
    OptionalQueryFloat,
    OptionalQueryBool,
    HeaderInt,
    HeaderStr,
    HeaderFloat,
    HeaderBool,
    OptionalHeaderInt,
    OptionalHeaderStr,
    OptionalHeaderFloat,
    OptionalHeaderBool,
)


# ── Path concretes ──────────────────────────────────────────────────────────


def test_path_int_happy() raises:
    var req = Request(method=Method.GET, url="/users/42")
    req.params_mut()["id"] = "42"
    var x = PathInt["id"].extract(req)
    assert_equal(x.value, 42)


def test_path_int_negative() raises:
    var req = Request(method=Method.GET, url="/x/-7")
    req.params_mut()["id"] = "-7"
    assert_equal(PathInt["id"].extract(req).value, -7)


def test_path_int_missing_raises() raises:
    var req = Request(method=Method.GET, url="/users/42")
    with assert_raises():
        _ = PathInt["id"].extract(req)


def test_path_int_bad_parse_raises() raises:
    var req = Request(method=Method.GET, url="/users/abc")
    req.params_mut()["id"] = "abc"
    with assert_raises():
        _ = PathInt["id"].extract(req)


def test_path_str_happy() raises:
    var req = Request(method=Method.GET, url="/u/alice")
    req.params_mut()["name"] = "alice"
    assert_equal(PathStr["name"].extract(req).value, "alice")


def test_path_float_happy() raises:
    var req = Request(method=Method.GET, url="/x/3.14")
    req.params_mut()["v"] = "3.14"
    var got = PathFloat["v"].extract(req).value
    # Compare with a tiny epsilon since float-parsing is not
    # bit-exact across architectures.
    assert_true(got > 3.139 and got < 3.141)


def test_path_bool_happy() raises:
    var req = Request(method=Method.GET, url="/x/true")
    req.params_mut()["flag"] = "true"
    assert_true(PathBool["flag"].extract(req).value)


# ── Query concretes ─────────────────────────────────────────────────────────


def test_query_int_happy() raises:
    var req = Request(method=Method.GET, url="/list?page=3")
    assert_equal(QueryInt["page"].extract(req).value, 3)


def test_query_str_happy() raises:
    var req = Request(method=Method.GET, url="/search?q=mojo")
    assert_equal(QueryStr["q"].extract(req).value, "mojo")


def test_query_float_happy() raises:
    var req = Request(method=Method.GET, url="/x?lat=37.5")
    var got = QueryFloat["lat"].extract(req).value
    assert_true(got > 37.49 and got < 37.51)


def test_query_bool_happy() raises:
    var req = Request(method=Method.GET, url="/x?on=yes")
    assert_true(QueryBool["on"].extract(req).value)


def test_query_int_missing_raises() raises:
    var req = Request(method=Method.GET, url="/list")
    with assert_raises():
        _ = QueryInt["page"].extract(req)


# ── OptionalQuery concretes ─────────────────────────────────────────────────


def test_optional_query_int_present() raises:
    var req = Request(method=Method.GET, url="/x?n=10")
    var x = OptionalQueryInt["n"].extract(req).value
    assert_true(Bool(x))
    if x:
        assert_equal(x.value(), 10)


def test_optional_query_int_absent() raises:
    var req = Request(method=Method.GET, url="/x")
    var x = OptionalQueryInt["n"].extract(req).value
    assert_false(Bool(x))


def test_optional_query_str_absent() raises:
    var req = Request(method=Method.GET, url="/x")
    var x = OptionalQueryStr["q"].extract(req).value
    assert_false(Bool(x))


def test_optional_query_str_present() raises:
    var req = Request(method=Method.GET, url="/x?q=hi")
    var x = OptionalQueryStr["q"].extract(req).value
    assert_true(Bool(x))
    if x:
        assert_equal(x.value(), "hi")


def test_optional_query_float_present() raises:
    var req = Request(method=Method.GET, url="/x?f=2.5")
    var x = OptionalQueryFloat["f"].extract(req).value
    assert_true(Bool(x))
    if x:
        var v = x.value()
        assert_true(v > 2.49 and v < 2.51)


def test_optional_query_bool_present() raises:
    var req = Request(method=Method.GET, url="/x?b=false")
    var x = OptionalQueryBool["b"].extract(req).value
    assert_true(Bool(x))
    if x:
        assert_false(x.value())


# ── Header concretes ────────────────────────────────────────────────────────


def test_header_int_happy() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-Count", "7")
    assert_equal(HeaderInt["X-Count"].extract(req).value, 7)


def test_header_str_happy() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Authorization", "Bearer secret")
    assert_equal(HeaderStr["Authorization"].extract(req).value, "Bearer secret")


def test_header_float_happy() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-Rate", "1.5")
    var got = HeaderFloat["X-Rate"].extract(req).value
    assert_true(got > 1.49 and got < 1.51)


def test_header_bool_happy() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-Debug", "1")
    assert_true(HeaderBool["X-Debug"].extract(req).value)


def test_header_int_missing_raises() raises:
    var req = Request(method=Method.GET, url="/")
    with assert_raises():
        _ = HeaderInt["X-Missing"].extract(req)


# ── OptionalHeader concretes ────────────────────────────────────────────────


def test_optional_header_int_present() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-N", "42")
    var x = OptionalHeaderInt["X-N"].extract(req).value
    assert_true(Bool(x))
    if x:
        assert_equal(x.value(), 42)


def test_optional_header_int_absent() raises:
    var req = Request(method=Method.GET, url="/")
    var x = OptionalHeaderInt["X-N"].extract(req).value
    assert_false(Bool(x))


def test_optional_header_str_present() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-Trace", "abc")
    var x = OptionalHeaderStr["X-Trace"].extract(req).value
    assert_true(Bool(x))
    if x:
        assert_equal(x.value(), "abc")


def test_optional_header_float_present() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-F", "9.0")
    var x = OptionalHeaderFloat["X-F"].extract(req).value
    assert_true(Bool(x))
    if x:
        var v = x.value()
        assert_true(v > 8.99 and v < 9.01)


def test_optional_header_bool_present() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-B", "yes")
    var x = OptionalHeaderBool["X-B"].extract(req).value
    assert_true(Bool(x))
    if x:
        assert_true(x.value())


# ── Single-dot access through Extracted[H] ─────────────────────────────────


@fieldwise_init
struct GetUserSingleDot(Copyable, Defaultable, Handler, Movable):
    """Handler whose extractors expose primitive ``.value`` directly
    — no ``.value.value`` chain. The headline use case for the
    concrete extractors.
    """

    var id: PathInt["id"]
    var page: OptionalQueryInt["page"]
    var auth: HeaderStr["Authorization"]

    def __init__(out self):
        self.id = PathInt["id"]()
        self.page = OptionalQueryInt["page"]()
        self.auth = HeaderStr["Authorization"]()

    def serve(self, req: Request) raises -> Response:
        var page_str = "1"
        if self.page.value:
            page_str = String(self.page.value.value())
        # Single-dot access: self.id.value is `Int` directly.
        return ok(
            "user="
            + String(self.id.value)
            + " page="
            + page_str
            + " auth="
            + self.auth.value
        )


def test_extracted_with_concrete_extractors() raises:
    """``Extracted[H]`` works when ``H``'s fields are concrete
    primitive extractors (``.value`` is the primitive directly)."""
    var req = Request(method=Method.GET, url="/users/77?page=4")
    req.params_mut()["id"] = "77"
    req.headers.set("Authorization", "Bearer t")
    var resp = Extracted[GetUserSingleDot]().serve(req)
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "user=77 page=4 auth=Bearer t")


def test_extracted_concrete_optional_missing_yields_default() raises:
    var req = Request(method=Method.GET, url="/users/9")
    req.params_mut()["id"] = "9"
    req.headers.set("Authorization", "Bearer t")
    var resp = Extracted[GetUserSingleDot]().serve(req)
    assert_equal(resp.text(), "user=9 page=1 auth=Bearer t")


def test_extracted_concrete_missing_required_returns_400() raises:
    """A missing required field still flows through the standard
    ``_bad_request_from_error`` path; sanitised body in default
    config."""
    var req = Request(method=Method.GET, url="/users/abc")
    req.params_mut()["id"] = "abc"
    req.headers.set("Authorization", "Bearer t")
    var resp = Extracted[GetUserSingleDot]().serve(req)
    assert_equal(resp.status, Status.BAD_REQUEST)
    assert_equal(resp.text(), "Bad Request")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
