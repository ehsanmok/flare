"""Tests for :mod:`flare.http.auth_extract`.

Coverage:

1. ``parse_bearer_token`` — happy path, leading whitespace,
   case-insensitive scheme match, missing scheme / token /
   header. Failure paths assert the typed :class:`AuthError`
   variant directly.
2. ``parse_basic_credentials`` — happy path, empty password,
   passwords containing ``:``, base64 padding variants,
   malformed inputs (typed-error asserted per failure mode).
3. ``BearerExtract`` / ``BasicExtract`` — Extractor trait
   round-trip via ``apply`` and the static ``extract`` factory.
   The ``Extractor`` trait is bare-``raises`` so the caller
   catches ``Error`` at the compile-time type level; we assert
   on ``String(e)`` substring matching the typed error's
   :func:`AuthError.write_to` rendering (which the Mojo runtime
   preserves through bare-raises propagation per the typed-
   errors docs § "Avoid bare raises with typed errors").
4. ``csrf_token_b64url`` — deterministic encoder; matches a
   known-vector for ``[0..32)`` byte input.
5. ``csrf_token_compare`` — constant-time XOR fold; returns
   False on length mismatch and on differing bytes; True on
   exact match.
6. ``CsrfToken.verify`` — ties the comparator to a struct shape
   suitable for double-submit cookie pattern.
7. ``AuthError`` — equality on ``_variant`` only;
   :func:`AuthError.write_to` rendering with and without
   ``detail``.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from flare.http.auth_extract import (
    AuthError,
    BasicCredentials,
    BasicExtract,
    BearerExtract,
    CsrfToken,
    csrf_token_b64url,
    csrf_token_compare,
    parse_basic_credentials,
    parse_bearer_token,
)
from flare.http.request import Request


# ── parse_bearer_token ───────────────────────────────────────────────────


def test_bearer_happy_path() raises:
    var t = parse_bearer_token(String("Bearer abc.def.ghi"))
    assert_equal(t, String("abc.def.ghi"))


def test_bearer_case_insensitive_scheme() raises:
    var t = parse_bearer_token(String("bearer xyz"))
    assert_equal(t, String("xyz"))


def test_bearer_leading_whitespace() raises:
    var t = parse_bearer_token(String("   Bearer xyz"))
    assert_equal(t, String("xyz"))


def test_bearer_extra_space_between_scheme_and_token() raises:
    var t = parse_bearer_token(String("Bearer    long-token"))
    assert_equal(t, String("long-token"))


def test_bearer_empty_value_raises_empty_value() raises:
    var got = 0
    try:
        var _t = parse_bearer_token(String(""))
    except e:
        got = e._variant
    assert_true(got == AuthError.EMPTY_VALUE._variant)


def test_bearer_wrong_scheme_raises_wrong_scheme() raises:
    var got = 0
    try:
        var _t = parse_bearer_token(String("Basic abc"))
    except e:
        got = e._variant
    assert_true(got == AuthError.WRONG_SCHEME._variant)


def test_bearer_too_short_raises_too_short() raises:
    var got = 0
    try:
        var _t = parse_bearer_token(String("Bear"))
    except e:
        got = e._variant
    assert_true(got == AuthError.TOO_SHORT._variant)


def test_bearer_missing_token_raises_empty_token() raises:
    var got = 0
    try:
        var _t = parse_bearer_token(String("Bearer "))
    except e:
        got = e._variant
    assert_true(got == AuthError.EMPTY_TOKEN._variant)


# ── parse_basic_credentials ──────────────────────────────────────────────


def test_basic_happy_path() raises:
    # alice:s3cr3t → YWxpY2U6czNjcjN0
    var c = parse_basic_credentials(String("Basic YWxpY2U6czNjcjN0"))
    assert_equal(c.username, String("alice"))
    assert_equal(c.password, String("s3cr3t"))


def test_basic_case_insensitive_scheme() raises:
    var c = parse_basic_credentials(String("basic YWxpY2U6czNjcjN0"))
    assert_equal(c.username, String("alice"))


def test_basic_password_with_colon() raises:
    # alice:s3:cr3t → YWxpY2U6czM6Y3IzdA== (alice:s3:cr3t)
    var c = parse_basic_credentials(String("Basic YWxpY2U6czM6Y3IzdA=="))
    assert_equal(c.username, String("alice"))
    assert_equal(c.password, String("s3:cr3t"))


def test_basic_empty_password() raises:
    # alice: → YWxpY2U6
    var c = parse_basic_credentials(String("Basic YWxpY2U6"))
    assert_equal(c.username, String("alice"))
    assert_equal(c.password, String(""))


def test_basic_no_separator_raises_missing_separator() raises:
    # base64 of "no-colon-here"
    var got = 0
    try:
        var _c = parse_basic_credentials(String("Basic bm8tY29sb24taGVyZQ=="))
    except e:
        got = e._variant
    assert_true(got == AuthError.MISSING_SEPARATOR._variant)


def test_basic_invalid_base64_char_raises_invalid_char() raises:
    # length-12 to satisfy mod-4 check, with '!' which is not in
    # the alphabet.
    var got = 0
    try:
        # 12-char b64 payload (mod-4 OK) with '!' which is not in
        # the alphabet, so we hit B64_INVALID_CHAR not
        # B64_BAD_LENGTH.
        var _c = parse_basic_credentials(String("Basic !!!!aaaaaaaa"))
    except e:
        got = e._variant
    assert_true(got == AuthError.B64_INVALID_CHAR._variant)


def test_basic_bad_length_raises_bad_length() raises:
    var got = 0
    try:
        var _c = parse_basic_credentials(String("Basic abc"))
    except e:
        got = e._variant
    assert_true(got == AuthError.B64_BAD_LENGTH._variant)


def test_basic_wrong_scheme_raises_wrong_scheme() raises:
    var got = 0
    try:
        var _c = parse_basic_credentials(String("Bearer abc"))
    except e:
        got = e._variant
    assert_true(got == AuthError.WRONG_SCHEME._variant)


def test_basic_empty_value_raises_empty_value() raises:
    var got = 0
    try:
        var _c = parse_basic_credentials(String(""))
    except e:
        got = e._variant
    assert_true(got == AuthError.EMPTY_VALUE._variant)


# ── BearerExtract / BasicExtract ─────────────────────────────────────────


def test_bearer_extractor_apply_succeeds() raises:
    var req = Request(method=String("GET"), url=String("/"))
    req.headers.set("Authorization", "Bearer my-token")
    var e = BearerExtract.extract(req)
    assert_equal(e.token, String("my-token"))


def test_bearer_extractor_missing_header_raises_typed() raises:
    """``Extractor.apply`` is bare-raises so the caller sees an
    ``Error``-typed catch — but the Mojo runtime preserves the
    AuthError's ``Writable`` identity, observable via
    ``String(e)``."""
    var req = Request(method=String("GET"), url=String("/"))
    var msg = String("")
    try:
        var _e = BearerExtract.extract(req)
    except e:
        msg = String(e)
    assert_true(msg.find("AuthError(MISSING_HEADER)") >= 0)


def test_basic_extractor_apply_succeeds() raises:
    var req = Request(method=String("GET"), url=String("/"))
    req.headers.set("Authorization", "Basic YWxpY2U6czNjcjN0")
    var e = BasicExtract.extract(req)
    assert_equal(e.username, String("alice"))
    assert_equal(e.password, String("s3cr3t"))


def test_basic_extractor_missing_header_raises_typed() raises:
    var req = Request(method=String("GET"), url=String("/"))
    var msg = String("")
    try:
        var _e = BasicExtract.extract(req)
    except e:
        msg = String(e)
    assert_true(msg.find("AuthError(MISSING_HEADER)") >= 0)


def test_basic_extractor_invalid_b64_propagates_typed() raises:
    """The B64_BAD_LENGTH variant raised inside
    ``parse_basic_credentials`` should propagate through
    ``BasicExtract.apply``'s bare-raises signature with its
    ``Writable`` rendering intact."""
    var req = Request(method=String("GET"), url=String("/"))
    req.headers.set("Authorization", "Basic abc")
    var msg = String("")
    try:
        var _e = BasicExtract.extract(req)
    except e:
        msg = String(e)
    assert_true(msg.find("AuthError(B64_BAD_LENGTH)") >= 0)


# ── CSRF ─────────────────────────────────────────────────────────────────


def test_csrf_b64url_known_vector() raises:
    """[0,1,2,...,31] → AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8."""
    var v = List[UInt8]()
    for i in range(32):
        v.append(UInt8(i))
    var got = csrf_token_b64url(v)
    var want = String("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
    assert_equal(got, want)


def test_csrf_b64url_empty_input() raises:
    var v = List[UInt8]()
    assert_equal(csrf_token_b64url(v), String(""))


def test_csrf_b64url_handles_one_byte_tail() raises:
    var v = List[UInt8]()
    v.append(UInt8(0xFF))
    assert_equal(csrf_token_b64url(v), String("_w"))


def test_csrf_b64url_handles_two_byte_tail() raises:
    var v = List[UInt8]()
    v.append(UInt8(0xFF))
    v.append(UInt8(0xEE))
    assert_equal(csrf_token_b64url(v), String("_-4"))


def test_csrf_compare_equal_returns_true() raises:
    assert_true(csrf_token_compare(String("abc123"), String("abc123")))


def test_csrf_compare_unequal_same_length_returns_false() raises:
    assert_false(csrf_token_compare(String("abc123"), String("xyz999")))


def test_csrf_compare_length_mismatch_returns_false() raises:
    assert_false(csrf_token_compare(String("abc"), String("abcd")))


def test_csrf_compare_empty_pair_returns_true() raises:
    assert_true(csrf_token_compare(String(""), String("")))


def test_csrf_token_verify_pair() raises:
    var t = CsrfToken(String("tok-cookie"), String("tok-cookie"))
    assert_true(t.verify())
    var bad = CsrfToken(String("tok-cookie"), String("tok-form"))
    assert_false(bad.verify())


# ── AuthError shape ──────────────────────────────────────────────────────


def test_auth_error_eq_compares_on_variant_only() raises:
    var a = AuthError(_variant=1, detail=String("x"))
    var b = AuthError(_variant=1, detail=String("y"))
    var c = AuthError(_variant=2, detail=String("x"))
    assert_true(a == b)
    assert_true(a != c)


def test_auth_error_write_to_renders_variant_and_detail() raises:
    var e = AuthError(_variant=4, detail=String("expected Bearer"))
    assert_equal(String(e), String("AuthError(WRONG_SCHEME): expected Bearer"))


def test_auth_error_write_to_omits_empty_detail() raises:
    var e = AuthError(_variant=5, detail=String(""))
    assert_equal(String(e), String("AuthError(EMPTY_TOKEN)"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
