"""Typed ``ok_json_value`` response builder (v0.7 Track 2a).

Verifies that :func:`flare.http.ok_json_value` accepts a typed
:class:`json.Value` and produces a 200 OK Response with
``Content-Type: application/json`` and the serialised body. The
symmetric output mirror of the :class:`flare.http.Json[T]` input
extractor.
"""

from std.testing import assert_equal, assert_true

from json import loads, Value as JsonValue

from flare.http import ok_json, ok_json_of, ok_json_value


@fieldwise_init
struct _User(Copyable, Movable):
    var id: Int
    var name: String
    var tags: List[String]


def test_ok_json_value_object_round_trip() raises:
    """A JSON object value serialises to its canonical text form."""
    var v = loads('{"id":42,"name":"alice"}')
    var resp = ok_json_value(v)
    assert_equal(resp.status, 200)
    assert_equal(resp.headers.get("content-type"), "application/json")
    var body = resp.text()
    assert_true('"id":42' in body, "body missing id field; got: " + body)
    assert_true(
        '"name":"alice"' in body, "body missing name field; got: " + body
    )


def test_ok_json_value_array() raises:
    """A JSON array value serialises with elements in order."""
    var arr = loads("[1,2,3]")
    var resp = ok_json_value(arr)
    assert_equal(resp.text(), "[1,2,3]")


def test_ok_json_value_primitive_string() raises:
    """A bare JSON string serialises with surrounding quotes."""
    var v = JsonValue("hello")
    var resp = ok_json_value(v)
    assert_equal(resp.text(), '"hello"')


def test_ok_json_value_primitive_int() raises:
    """A bare JSON number serialises numerically."""
    var v = JsonValue(123)
    var resp = ok_json_value(v)
    assert_equal(resp.text(), "123")


def test_ok_json_value_primitive_bool() raises:
    """A bare JSON bool serialises as ``true`` / ``false``."""
    var t = JsonValue(True)
    var resp = ok_json_value(t)
    assert_equal(resp.text(), "true")
    var f = JsonValue(False)
    var resp_f = ok_json_value(f)
    assert_equal(resp_f.text(), "false")


def test_ok_json_string_overload_still_works() raises:
    """The pre-existing ``ok_json(body: String)`` overload accepts
    a pre-serialised JSON string verbatim; both overloads coexist."""
    var resp = ok_json('{"ok":true}')
    assert_equal(resp.status, 200)
    assert_equal(resp.headers.get("content-type"), "application/json")
    assert_equal(resp.text(), '{"ok":true}')


def test_ok_json_value_sets_content_type() raises:
    """The Content-Type header is unconditionally
    ``application/json`` (case-insensitive lookup matches
    ``content-type`` in the HeaderMap)."""
    var v = loads('{"k":"v"}')
    var resp = ok_json_value(v)
    var ct = resp.headers.get("Content-Type")
    assert_equal(ct, "application/json")


def test_ok_json_of_struct() raises:
    """A struct serialises by reflection, escaping string fields."""
    var resp = ok_json_of(_User(7, 'a"b', ["x"]))
    assert_equal(resp.status, 200)
    assert_equal(resp.headers.get("content-type"), "application/json")
    assert_equal(resp.text(), '{"id":7,"name":"a\\"b","tags":["x"]}')


def test_ok_json_value_parsed_with_escapes() raises:
    """A parsed value keeps its escapes when written back out."""
    var v = loads('{"k\\n":"\\u00e9\\"","n":[1,{"a":null}]}')
    assert_equal(
        ok_json_value(v).text(), '{"k\\n":"\u00e9\\"","n":[1,{"a":null}]}'
    )


def main() raises:
    test_ok_json_value_object_round_trip()
    test_ok_json_value_array()
    test_ok_json_value_primitive_string()
    test_ok_json_value_primitive_int()
    test_ok_json_value_primitive_bool()
    test_ok_json_string_overload_still_works()
    test_ok_json_value_sets_content_type()
    test_ok_json_of_struct()
    test_ok_json_value_parsed_with_escapes()
    print("test_ok_json_typed: 9 passed")
