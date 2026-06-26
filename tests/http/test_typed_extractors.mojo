"""Tests for the v0.9 typed extractors: ``OptionalPath*`` + ``JsonAs[T]``.

- ``OptionalPath{Int,Str,Float,Bool}`` yield ``None`` when the route did
  not capture the parameter, the parsed value when it did, and propagate
  a parse error on a present-but-malformed capture.
- ``JsonAs[T: FromJson]`` deserializes the request body into a typed
  struct and surfaces failures (empty body, invalid JSON, field errors)
  so ``Extracted[H]`` maps them to 400.
"""

from json import Value

from std.testing import assert_equal, assert_false, assert_raises, TestSuite

from flare.http import (
    Extracted,
    FromJson,
    Handler,
    JsonAs,
    Method,
    OptionalPathInt,
    OptionalPathStr,
    Request,
    Response,
    ok,
)


def _body(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


# ── OptionalPath* ───────────────────────────────────────────────────────────


def test_optional_path_int_absent_is_none() raises:
    var req = Request(method=Method.GET, url="/items")
    var x = OptionalPathInt["id"].extract(req)
    assert_false(Bool(x.value))


def test_optional_path_int_present_parses() raises:
    var req = Request(method=Method.GET, url="/items/7")
    req.params_mut()["id"] = "7"
    var x = OptionalPathInt["id"].extract(req)
    assert_equal(x.value.value(), 7)


def test_optional_path_int_present_malformed_raises() raises:
    var req = Request(method=Method.GET, url="/items/abc")
    req.params_mut()["id"] = "abc"
    with assert_raises():
        _ = OptionalPathInt["id"].extract(req)


def test_optional_path_str_present() raises:
    var req = Request(method=Method.GET, url="/u/ada")
    req.params_mut()["name"] = "ada"
    var x = OptionalPathStr["name"].extract(req)
    assert_equal(x.value.value(), String("ada"))


# ── JsonAs[T] ───────────────────────────────────────────────────────────────


@fieldwise_init
struct _CreateUser(Copyable, Defaultable, FromJson, Movable):
    var name: String
    var age: Int

    def __init__(out self):
        self.name = ""
        self.age = 0

    def parse_json(mut self, value: Value) raises:
        self.name = value["name"].string_value()
        self.age = Int(value["age"].int_value())


def test_json_as_happy() raises:
    var req = Request(
        method=Method.POST, url="/", body=_body('{"name":"ada","age":36}')
    )
    var j = JsonAs[_CreateUser].extract(req)
    assert_equal(j.value.name, String("ada"))
    assert_equal(j.value.age, 36)


def test_json_as_empty_body_raises() raises:
    var req = Request(method=Method.POST, url="/")
    with assert_raises():
        _ = JsonAs[_CreateUser].extract(req)


def test_json_as_malformed_raises() raises:
    var req = Request(method=Method.POST, url="/", body=_body("{not json}"))
    with assert_raises():
        _ = JsonAs[_CreateUser].extract(req)


# ── JsonAs[T] through Extracted[H] -> 400 on bad body ───────────────────────


@fieldwise_init
struct _CreateHandler(Copyable, Defaultable, Handler, Movable):
    var body: JsonAs[_CreateUser]

    def __init__(out self):
        self.body = JsonAs[_CreateUser]()

    def serve(self, req: Request) raises -> Response:
        return ok("hello " + self.body.value.name)


def test_json_as_extracted_happy() raises:
    var h = Extracted[_CreateHandler]()
    var req = Request(
        method=Method.POST, url="/", body=_body('{"name":"grace","age":1}')
    )
    var resp = h.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), String("hello grace"))


def test_json_as_extracted_bad_body_is_400() raises:
    var h = Extracted[_CreateHandler]()
    var req = Request(method=Method.POST, url="/", body=_body("{nope}"))
    var resp = h.serve(req)
    assert_equal(resp.status, 400)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
