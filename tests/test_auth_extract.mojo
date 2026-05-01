"""Tests for :mod:`flare.http.auth_extract`.

Coverage:

1. ``parse_bearer_token`` — happy path, leading whitespace,
   case-insensitive scheme match, missing scheme / token /
   header.
2. ``parse_basic_credentials`` — happy path, empty password,
   passwords containing ``:``, base64 padding variants,
   malformed inputs.
3. ``BearerExtract`` / ``BasicExtract`` — Extractor trait
   round-trip via ``apply`` and the static ``extract`` factory.
4. ``csrf_token_b64url`` — deterministic encoder; matches a
   known-vector for ``[0..32)`` byte input.
5. ``csrf_token_compare`` — constant-time XOR fold; returns
   False on length mismatch and on differing bytes; True on
   exact match.
6. ``CsrfToken.verify`` — ties the comparator to a struct shape
   suitable for double-submit cookie pattern.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from flare.http.auth_extract import (
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


def test_bearer_empty_value_raises() raises:
    var raised = False
    try:
        var _t = parse_bearer_token(String(""))
    except:
        raised = True
    assert_true(raised)


def test_bearer_wrong_scheme_raises() raises:
    var raised = False
    try:
        var _t = parse_bearer_token(String("Basic abc"))
    except:
        raised = True
    assert_true(raised)


def test_bearer_missing_token_raises() raises:
    var raised = False
    try:
        var _t = parse_bearer_token(String("Bearer "))
    except:
        raised = True
    assert_true(raised)


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


def test_basic_no_separator_raises() raises:
    # base64 of "no-colon-here"
    var raised = False
    try:
        var _c = parse_basic_credentials(String("Basic bm8tY29sb24taGVyZQ=="))
    except:
        raised = True
    assert_true(raised)


def test_basic_invalid_base64_raises() raises:
    var raised = False
    try:
        var _c = parse_basic_credentials(String("Basic !!notb64!!"))
    except:
        raised = True
    assert_true(raised)


def test_basic_wrong_scheme_raises() raises:
    var raised = False
    try:
        var _c = parse_basic_credentials(String("Bearer abc"))
    except:
        raised = True
    assert_true(raised)


def test_basic_empty_value_raises() raises:
    var raised = False
    try:
        var _c = parse_basic_credentials(String(""))
    except:
        raised = True
    assert_true(raised)


# ── BearerExtract / BasicExtract ─────────────────────────────────────────


def test_bearer_extractor_apply_succeeds() raises:
    var req = Request(method=String("GET"), url=String("/"))
    req.headers.set("Authorization", "Bearer my-token")
    var e = BearerExtract.extract(req)
    assert_equal(e.token, String("my-token"))


def test_bearer_extractor_missing_header_raises() raises:
    var req = Request(method=String("GET"), url=String("/"))
    var raised = False
    try:
        var _e = BearerExtract.extract(req)
    except:
        raised = True
    assert_true(raised)


def test_basic_extractor_apply_succeeds() raises:
    var req = Request(method=String("GET"), url=String("/"))
    req.headers.set("Authorization", "Basic YWxpY2U6czNjcjN0")
    var e = BasicExtract.extract(req)
    assert_equal(e.username, String("alice"))
    assert_equal(e.password, String("s3cr3t"))


def test_basic_extractor_missing_header_raises() raises:
    var req = Request(method=String("GET"), url=String("/"))
    var raised = False
    try:
        var _e = BasicExtract.extract(req)
    except:
        raised = True
    assert_true(raised)


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
    """[0xFF] → /w (no padding)."""
    var v = List[UInt8]()
    v.append(UInt8(0xFF))
    assert_equal(csrf_token_b64url(v), String("_w"))


def test_csrf_b64url_handles_two_byte_tail() raises:
    """[0xFF, 0xEE] → /+4 → URL-safe '_-4'."""
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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
