"""Tests for ``flare.http.intern``.

Exercises:

1. The 9 RFC 7231 method names round-trip through
   :func:`intern_method_bytes` / :func:`intern_method_string`
   and produce ``Optional[String]`` values that are byte-identical
   to the input.
2. Unknown method bytes (``"FOO"`` / empty / lowercased ``"get"``)
   return ``None``.
3. The common-value table covers Content-Type, Content-Encoding,
   Connection, and HTTP-version literals.
4. Length-first dispatch is *case-sensitive* — HTTP wire forms
   are case-sensitive for both methods and the values we intern,
   so ``"GET"`` interns but ``"Get"`` does not.
5. ``MethodIntern`` / ``ValueIntern`` constants surface the
   correct comptime literals (sanity-pinning the table against
   accidental edits).
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http.intern import (
    MethodIntern,
    ValueIntern,
    intern_method_bytes,
    intern_method_string,
    intern_common_value,
    intern_common_value_string,
)


def test_method_intern_get() raises:
    var m = String("GET")
    var r = intern_method_string(m)
    assert_true(Bool(r))
    assert_equal(r.value(), String("GET"))


def test_method_intern_all_nine_rfc_7231_methods() raises:
    var names = List[String]()
    names.append(String("GET"))
    names.append(String("POST"))
    names.append(String("PUT"))
    names.append(String("PATCH"))
    names.append(String("DELETE"))
    names.append(String("HEAD"))
    names.append(String("OPTIONS"))
    names.append(String("CONNECT"))
    names.append(String("TRACE"))
    for i in range(len(names)):
        var got = intern_method_string(names[i])
        assert_true(Bool(got))
        assert_equal(got.value(), names[i])


def test_method_intern_rejects_unknown() raises:
    var got = intern_method_string(String("FOO"))
    assert_false(Bool(got))


def test_method_intern_rejects_empty() raises:
    var got = intern_method_string(String(""))
    assert_false(Bool(got))


def test_method_intern_is_case_sensitive() raises:
    """HTTP method names are uppercase per RFC 7231 §4.1; lowercase
    forms must not intern (the parser will reject them at the
    request-line validation step downstream).
    """
    var got = intern_method_string(String("get"))
    assert_false(Bool(got))
    var got2 = intern_method_string(String("Post"))
    assert_false(Bool(got2))


def test_method_intern_handles_long_inputs() raises:
    """A method name of any length other than 3 / 4 / 5 / 6 / 7 must
    fall through to ``None`` quickly without comparing per-byte.
    """
    var got = intern_method_string(String("VERYLONGMETHODNAME"))
    assert_false(Bool(got))
    var got2 = intern_method_string(String("XX"))
    assert_false(Bool(got2))


def test_method_intern_byte_slice_form() raises:
    """``intern_method_bytes`` is the lower-level entry point used
    by the parser — verify it accepts a raw byte slice and produces
    the same Optional[String] as the String wrapper.
    """
    var src = String("DELETE")
    var bytes = src.as_bytes()
    var got = intern_method_bytes(bytes)
    assert_true(Bool(got))
    assert_equal(got.value(), String("DELETE"))


def test_method_intern_round_trip_byte_identical() raises:
    """The interned String must be byte-identical to the input
    method bytes. Whether the underlying storage shares the
    StaticString backing or sits in a fresh SSO buffer is an
    implementation detail; the invariant tested here is that the
    bytes match exactly.
    """
    var src = String("POST")
    var got = intern_method_string(src)
    assert_true(Bool(got))
    var out = got.value()
    assert_equal(out.byte_length(), src.byte_length())
    var op = out.unsafe_ptr()
    var sp = src.unsafe_ptr()
    for i in range(out.byte_length()):
        assert_equal(Int(op[i]), Int(sp[i]))


def test_value_intern_common_content_types() raises:
    var cases = List[String]()
    cases.append(String("text/html"))
    cases.append(String("text/plain"))
    cases.append(String("application/json"))
    cases.append(String("application/octet-stream"))
    for i in range(len(cases)):
        var got = intern_common_value_string(cases[i])
        assert_true(Bool(got))
        assert_equal(got.value(), cases[i])


def test_value_intern_common_encodings() raises:
    var cases = List[String]()
    cases.append(String("gzip"))
    cases.append(String("br"))
    cases.append(String("deflate"))
    cases.append(String("identity"))
    for i in range(len(cases)):
        var got = intern_common_value_string(cases[i])
        assert_true(Bool(got))
        assert_equal(got.value(), cases[i])


def test_value_intern_connection_values() raises:
    var ka = intern_common_value_string(String("keep-alive"))
    assert_true(Bool(ka))
    assert_equal(ka.value(), String("keep-alive"))
    var cl = intern_common_value_string(String("close"))
    assert_true(Bool(cl))
    assert_equal(cl.value(), String("close"))


def test_value_intern_http_version_literals() raises:
    var v10 = intern_common_value_string(String("HTTP/1.0"))
    assert_true(Bool(v10))
    assert_equal(v10.value(), String("HTTP/1.0"))
    var v11 = intern_common_value_string(String("HTTP/1.1"))
    assert_true(Bool(v11))
    assert_equal(v11.value(), String("HTTP/1.1"))


def test_value_intern_rejects_unknown() raises:
    var got = intern_common_value_string(String("text/markdown"))
    assert_false(Bool(got))
    var got2 = intern_common_value_string(String("HTTP/2.0"))
    assert_false(Bool(got2))
    var got3 = intern_common_value_string(String(""))
    assert_false(Bool(got3))


def test_value_intern_case_sensitive() raises:
    """Header values like Content-Type are case-sensitive at the
    byte level; ``GZIP`` does not match ``gzip``. The intern table
    must preserve the original case so a downstream
    ``encode_to(buf)`` writes the canonical lowercase form.
    """
    var got = intern_common_value_string(String("GZIP"))
    assert_false(Bool(got))
    var got2 = intern_common_value_string(String("Keep-Alive"))
    assert_false(Bool(got2))


def test_method_intern_constants_match_rfc_7231() raises:
    """Sanity-pin the ``MethodIntern`` constants against
    accidental edits.
    """
    assert_equal(String(MethodIntern.GET), String("GET"))
    assert_equal(String(MethodIntern.POST), String("POST"))
    assert_equal(String(MethodIntern.PUT), String("PUT"))
    assert_equal(String(MethodIntern.PATCH), String("PATCH"))
    assert_equal(String(MethodIntern.DELETE), String("DELETE"))
    assert_equal(String(MethodIntern.HEAD), String("HEAD"))
    assert_equal(String(MethodIntern.OPTIONS), String("OPTIONS"))
    assert_equal(String(MethodIntern.CONNECT), String("CONNECT"))
    assert_equal(String(MethodIntern.TRACE), String("TRACE"))


def test_value_intern_constants_match_table() raises:
    """Sanity-pin the ``ValueIntern`` constants."""
    assert_equal(
        String(ValueIntern.CONTENT_TYPE_TEXT_HTML), String("text/html")
    )
    assert_equal(
        String(ValueIntern.CONTENT_TYPE_TEXT_PLAIN), String("text/plain")
    )
    assert_equal(
        String(ValueIntern.CONTENT_TYPE_JSON), String("application/json")
    )
    assert_equal(
        String(ValueIntern.CONTENT_TYPE_OCTET),
        String("application/octet-stream"),
    )
    assert_equal(String(ValueIntern.ENCODING_GZIP), String("gzip"))
    assert_equal(String(ValueIntern.ENCODING_BR), String("br"))
    assert_equal(String(ValueIntern.ENCODING_DEFLATE), String("deflate"))
    assert_equal(String(ValueIntern.ENCODING_IDENTITY), String("identity"))
    assert_equal(
        String(ValueIntern.CONNECTION_KEEP_ALIVE), String("keep-alive")
    )
    assert_equal(String(ValueIntern.CONNECTION_CLOSE), String("close"))
    assert_equal(String(ValueIntern.VERSION_1_0), String("HTTP/1.0"))
    assert_equal(String(ValueIntern.VERSION_1_1), String("HTTP/1.1"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
