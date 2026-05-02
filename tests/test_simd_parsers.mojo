"""Tests for ``flare.http.simd_parsers`` (Track B10)."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http import (
    HttpParseError,
    simd_memmem,
    simd_percent_decode,
    simd_cookie_scan,
)


def _to_bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var b = s.as_bytes()
    for i in range(s.byte_length()):
        out.append(b[i])
    return out^


def _to_string(b: List[UInt8]) -> String:
    var out = String("")
    for i in range(len(b)):
        out += chr(Int(b[i]))
    return out


# ── simd_memmem ─────────────────────────────────────────────────────────────


def test_memmem_finds_at_start() raises:
    var hay = _to_bytes(String("abcdef"))
    var nee = _to_bytes(String("abc"))
    assert_equal(simd_memmem(hay, nee), 0)


def test_memmem_finds_at_middle() raises:
    var hay = _to_bytes(String("abcdef"))
    var nee = _to_bytes(String("cd"))
    assert_equal(simd_memmem(hay, nee), 2)


def test_memmem_finds_at_end() raises:
    var hay = _to_bytes(String("abcdef"))
    var nee = _to_bytes(String("ef"))
    assert_equal(simd_memmem(hay, nee), 4)


def test_memmem_no_match_returns_neg_one() raises:
    var hay = _to_bytes(String("abcdef"))
    var nee = _to_bytes(String("xyz"))
    assert_equal(simd_memmem(hay, nee), -1)


def test_memmem_empty_needle_returns_zero() raises:
    """POSIX ``memmem(3)`` convention — empty needle matches at
    offset 0.
    """
    var hay = _to_bytes(String("abcdef"))
    var nee = List[UInt8]()
    assert_equal(simd_memmem(hay, nee), 0)


def test_memmem_needle_longer_than_haystack() raises:
    var hay = _to_bytes(String("abc"))
    var nee = _to_bytes(String("abcdef"))
    assert_equal(simd_memmem(hay, nee), -1)


def test_memmem_partial_prefix_match() raises:
    """``aaab`` searched for ``ab`` — first ``a`` is a partial
    prefix that fails, scan continues to position 2.
    """
    var hay = _to_bytes(String("aaab"))
    var nee = _to_bytes(String("ab"))
    assert_equal(simd_memmem(hay, nee), 2)


def test_memmem_multipart_boundary_in_body() raises:
    """The dominant motivating use case: scan a multipart body
    chunk for the boundary marker ``--<boundary>``.
    """
    var body = _to_bytes(
        String(
            "Content-Type: text/plain\r\n\r\nhello world\r\n--myboundary--\r\n"
        )
    )
    var bound = _to_bytes(String("--myboundary"))
    var off = simd_memmem(body, bound)
    assert_true(off > 0)
    # Offset should land exactly at the boundary delimiter.
    var expected = String("hello world\r\n--myboundary--\r\n").byte_length()
    var prefix_len = String(
        "Content-Type: text/plain\r\n\r\nhello world\r\n"
    ).byte_length()
    assert_equal(off, prefix_len)


def test_memmem_finds_only_first_occurrence() raises:
    var hay = _to_bytes(String("ababab"))
    var nee = _to_bytes(String("ab"))
    assert_equal(simd_memmem(hay, nee), 0)


# ── simd_percent_decode ─────────────────────────────────────────────────────


def test_percent_decode_pure_ascii_unchanged() raises:
    var input = _to_bytes(String("hello-world"))
    var out = List[UInt8]()
    simd_percent_decode(input, out)
    assert_equal(_to_string(out), String("hello-world"))


def test_percent_decode_simple_escape() raises:
    var input = _to_bytes(String("a%20b"))
    var out = List[UInt8]()
    simd_percent_decode(input, out)
    assert_equal(_to_string(out), String("a b"))


def test_percent_decode_full_uppercase_hex() raises:
    var input = _to_bytes(String("%48%65%6C%6C%6F"))
    var out = List[UInt8]()
    simd_percent_decode(input, out)
    assert_equal(_to_string(out), String("Hello"))


def test_percent_decode_full_lowercase_hex() raises:
    var input = _to_bytes(String("%48%65%6c%6c%6f"))
    var out = List[UInt8]()
    simd_percent_decode(input, out)
    assert_equal(_to_string(out), String("Hello"))


def test_percent_decode_plus_to_space() raises:
    """``+`` decodes to space per
    application/x-www-form-urlencoded.
    """
    var input = _to_bytes(String("hello+world"))
    var out = List[UInt8]()
    simd_percent_decode(input, out)
    assert_equal(_to_string(out), String("hello world"))


def test_percent_decode_query_fragment() raises:
    """Realistic: ``q=hello+world%21`` decodes to
    ``q=hello world!``.
    """
    var input = _to_bytes(String("q=hello+world%21"))
    var out = List[UInt8]()
    simd_percent_decode(input, out)
    assert_equal(_to_string(out), String("q=hello world!"))


def test_percent_decode_trailing_percent_raises() raises:
    var input = _to_bytes(String("foo%"))
    var out = List[UInt8]()
    var raised = False
    try:
        simd_percent_decode(input, out)
    except e:
        raised = True
    assert_true(raised)


def test_percent_decode_partial_escape_raises() raises:
    var input = _to_bytes(String("foo%2"))
    var out = List[UInt8]()
    var raised = False
    try:
        simd_percent_decode(input, out)
    except e:
        raised = True
    assert_true(raised)


def test_percent_decode_invalid_hex_raises() raises:
    var input = _to_bytes(String("foo%XY"))
    var out = List[UInt8]()
    var raised = False
    try:
        simd_percent_decode(input, out)
    except e:
        raised = True
    assert_true(raised)


def test_percent_decode_empty_input() raises:
    var input = List[UInt8]()
    var out = List[UInt8]()
    simd_percent_decode(input, out)
    assert_equal(len(out), 0)


# ── simd_cookie_scan ────────────────────────────────────────────────────────


def test_cookie_scan_finds_all_separators() raises:
    var input = _to_bytes(String("a=1; b=2; c=3"))
    var offsets = List[Int]()
    simd_cookie_scan(input, offsets)
    assert_equal(len(offsets), 2)
    assert_equal(offsets[0], 3)
    assert_equal(offsets[1], 8)


def test_cookie_scan_no_separators_empty_result() raises:
    var input = _to_bytes(String("only-one-cookie=1"))
    var offsets = List[Int]()
    simd_cookie_scan(input, offsets)
    assert_equal(len(offsets), 0)


def test_cookie_scan_empty_input() raises:
    var input = List[UInt8]()
    var offsets = List[Int]()
    simd_cookie_scan(input, offsets)
    assert_equal(len(offsets), 0)


def test_cookie_scan_appends_to_existing_offsets() raises:
    """Existing offsets are preserved — the function only
    appends.
    """
    var input = _to_bytes(String("a; b"))
    var offsets = List[Int]()
    offsets.append(99)
    simd_cookie_scan(input, offsets)
    assert_equal(len(offsets), 2)
    assert_equal(offsets[0], 99)
    assert_equal(offsets[1], 1)


def test_cookie_scan_back_to_back_separators() raises:
    """Two adjacent ``;`` are both reported."""
    var input = _to_bytes(String("a;;b"))
    var offsets = List[Int]()
    simd_cookie_scan(input, offsets)
    assert_equal(len(offsets), 2)
    assert_equal(offsets[0], 1)
    assert_equal(offsets[1], 2)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
