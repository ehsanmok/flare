"""Tests for ``flare.http.form`` (v0.6 — track B).

Covers:

- ``urldecode`` happy path + ``+``→space + invalid escape raises.
- ``urlencode`` round-trips the unreserved set + encodes the rest.
- ``parse_form_urlencoded`` empty body + single pair + multipair +
  duplicate keys + missing ``=`` + percent-encoded keys/values +
  ``;`` separator + bad escape raises.
- ``Form`` extractor returns the same ``FormData``.
"""

from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.http import (
    Form,
    FormData,
    Method,
    Request,
    parse_form_urlencoded,
    urldecode,
    urlencode,
)


def test_urldecode_plain() raises:
    assert_equal(urldecode("hello"), "hello")


def test_urldecode_plus_to_space() raises:
    assert_equal(urldecode("a+b"), "a b")


def test_urldecode_percent() raises:
    assert_equal(urldecode("%20"), " ")
    assert_equal(urldecode("a%2Bb"), "a+b")
    assert_equal(urldecode("hello%20world"), "hello world")


def test_urldecode_uppercase_hex() raises:
    assert_equal(urldecode("%2F"), "/")


def test_urldecode_lowercase_hex() raises:
    assert_equal(urldecode("%2f"), "/")


def test_urldecode_truncated_raises() raises:
    with assert_raises():
        _ = urldecode("%2")


def test_urldecode_bad_hex_raises() raises:
    with assert_raises():
        _ = urldecode("%ZZ")


def test_urlencode_unreserved() raises:
    assert_equal(urlencode("abcXYZ-._~123"), "abcXYZ-._~123")


def test_urlencode_space() raises:
    assert_equal(urlencode("a b"), "a+b")


def test_urlencode_special() raises:
    assert_equal(urlencode("a/b"), "a%2Fb")
    assert_equal(urlencode("&"), "%26")


def test_urlencode_decode_roundtrip() raises:
    var inputs = List[String]()
    inputs.append("hello world")
    inputs.append("a&b=c")
    inputs.append("ünïcødé")
    for s in inputs:
        var enc = urlencode(s)
        var dec = urldecode(enc)
        assert_equal(dec, s)


def test_parse_empty_body() raises:
    var f = parse_form_urlencoded("")
    assert_equal(f.len(), 0)


def test_parse_single_pair() raises:
    var f = parse_form_urlencoded("name=alice")
    assert_equal(f.len(), 1)
    assert_equal(f.get("name"), "alice")
    assert_true(f.contains("name"))


def test_parse_multi_pair() raises:
    var f = parse_form_urlencoded("a=1&b=2&c=3")
    assert_equal(f.len(), 3)
    assert_equal(f.get("a"), "1")
    assert_equal(f.get("b"), "2")
    assert_equal(f.get("c"), "3")


def test_parse_duplicate_keys() raises:
    var f = parse_form_urlencoded("k=1&k=2&k=3")
    var all = f.get_all("k")
    assert_equal(len(all), 3)
    assert_equal(all[0], "1")
    assert_equal(all[2], "3")


def test_parse_missing_equals() raises:
    var f = parse_form_urlencoded("flag&name=alice")
    assert_equal(f.len(), 2)
    assert_equal(f.get("flag"), "")
    assert_equal(f.get("name"), "alice")


def test_parse_empty_value() raises:
    var f = parse_form_urlencoded("k=")
    assert_equal(f.get("k"), "")
    assert_true(f.contains("k"))


def test_parse_percent_encoded() raises:
    var f = parse_form_urlencoded("name=alice%20smith&q=a%26b")
    assert_equal(f.get("name"), "alice smith")
    assert_equal(f.get("q"), "a&b")


def test_parse_plus_in_value() raises:
    var f = parse_form_urlencoded("greeting=hello+world")
    assert_equal(f.get("greeting"), "hello world")


def test_parse_semicolon_separator() raises:
    var f = parse_form_urlencoded("a=1;b=2")
    assert_equal(f.get("a"), "1")
    assert_equal(f.get("b"), "2")


def test_parse_bad_escape_raises() raises:
    with assert_raises():
        _ = parse_form_urlencoded("a=%2")


def test_form_to_urlencoded_roundtrip() raises:
    var f = parse_form_urlencoded("name=alice+smith&age=30")
    var enc = f.to_urlencoded()
    var f2 = parse_form_urlencoded(enc)
    assert_equal(f2.get("name"), "alice smith")
    assert_equal(f2.get("age"), "30")


def test_form_extractor() raises:
    var req = Request(method=Method.POST, url="/login")
    req.body = List[UInt8]("user=alice&pw=secret".as_bytes())
    var f = Form.extract(req)
    assert_equal(f.value.get("user"), "alice")
    assert_equal(f.value.get("pw"), "secret")


def test_form_extractor_empty_raises() raises:
    var req = Request(method=Method.POST, url="/login")
    with assert_raises():
        _ = Form.extract(req)


def test_form_get_optional() raises:
    var f = parse_form_urlencoded("k=v")
    var opt = f.get_optional("k")
    assert_true(Bool(opt))
    assert_equal(opt.value(), "v")
    assert_false(Bool(f.get_optional("missing")))


def main() raises:
    test_urldecode_plain()
    test_urldecode_plus_to_space()
    test_urldecode_percent()
    test_urldecode_uppercase_hex()
    test_urldecode_lowercase_hex()
    test_urldecode_truncated_raises()
    test_urldecode_bad_hex_raises()
    test_urlencode_unreserved()
    test_urlencode_space()
    test_urlencode_special()
    test_urlencode_decode_roundtrip()
    test_parse_empty_body()
    test_parse_single_pair()
    test_parse_multi_pair()
    test_parse_duplicate_keys()
    test_parse_missing_equals()
    test_parse_empty_value()
    test_parse_percent_encoded()
    test_parse_plus_in_value()
    test_parse_semicolon_separator()
    test_parse_bad_escape_raises()
    test_form_to_urlencoded_roundtrip()
    test_form_extractor()
    test_form_extractor_empty_raises()
    test_form_get_optional()
    print("test_form: 25 passed")
