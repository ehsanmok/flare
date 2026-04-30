"""Tests for ``flare.http._scan``: SIMD-parametric header scanners.

Covers correctness of:

- ``find_crlfcrlf[W]`` at every byte position of interest around SIMD
  chunk boundaries (``W-1``, ``W``, ``W+1``, plus ``W+3`` and ``2W``).
- ``scan_content_length[W]`` with mixed-case header names, leading
  whitespace after the colon, and absent headers.
- Width parametricity — the ``W=32`` and ``W=64`` variants must agree
  with each other and with the scalar reference.

The SIMD path is only reachable when ``(n - start) >= W``, so tests
also exercise inputs shorter than ``W`` that must cleanly fall through
to the scalar tail.
"""

from std.testing import (
    assert_true,
    assert_equal,
    TestSuite,
)

from flare.http._scan import find_crlfcrlf, scan_content_length


@always_inline
def _bytes(s: String) -> List[UInt8]:
    """Build a ``List[UInt8]`` from a ``String``."""
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


@always_inline
def _pad(prefix: String, total: Int, suffix: String) -> List[UInt8]:
    """Build ``prefix`` + ``x`` padding so the total pre-suffix length is
    ``total`` + ``suffix``.

    Used to drop the CRLFCRLF terminator at a specific byte offset so we
    can test chunk-boundary cases.
    """
    var out = List[UInt8]()
    for b in prefix.as_bytes():
        out.append(b)
    while len(out) < total:
        out.append(UInt8(ord("x")))
    for b in suffix.as_bytes():
        out.append(b)
    return out^


# ── find_crlfcrlf correctness ───────────────────────────────────────────────


def test_find_crlfcrlf_minimal() raises:
    var buf = _bytes("\r\n\r\n")
    assert_equal(find_crlfcrlf(buf, 0), 4)


def test_find_crlfcrlf_with_prefix() raises:
    var buf = _bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\nbody")
    # Expected: end of headers is at byte 27 (after the second \r\n\r\n).
    assert_equal(find_crlfcrlf(buf, 0), 27)


def test_find_crlfcrlf_absent() raises:
    var buf = _bytes("GET / HTTP/1.1\r\nHost: x\r\n")
    assert_equal(find_crlfcrlf(buf, 0), -1)


def test_find_crlfcrlf_empty_is_minus_one() raises:
    var buf = List[UInt8]()
    assert_equal(find_crlfcrlf(buf, 0), -1)


def test_find_crlfcrlf_short_buffer_scalar_path() raises:
    """Buffers shorter than SIMD_W must fall through to the scalar tail."""
    var buf = _bytes("\r\n\r\n")  # n=4 < 32
    assert_equal(find_crlfcrlf(buf, 0), 4)


def test_find_crlfcrlf_start_offset() raises:
    var buf = _bytes("xxxx\r\n\r\nyy")
    # Start at 4 skips prefix and finds terminator.
    assert_equal(find_crlfcrlf(buf, 4), 8)
    # Start past terminator misses it.
    assert_equal(find_crlfcrlf(buf, 9), -1)


# ── find_crlfcrlf at SIMD chunk boundaries ──────────────────────────────────


def test_find_crlfcrlf_at_byte_29() raises:
    """Terminator straddles the end of the first 32-byte chunk."""
    var buf = _pad("", 29, "\r\n\r\n")
    assert_equal(find_crlfcrlf(buf, 0), 33)


def test_find_crlfcrlf_at_byte_30() raises:
    var buf = _pad("", 30, "\r\n\r\n")
    assert_equal(find_crlfcrlf(buf, 0), 34)


def test_find_crlfcrlf_at_byte_31() raises:
    var buf = _pad("", 31, "\r\n\r\n")
    assert_equal(find_crlfcrlf(buf, 0), 35)


def test_find_crlfcrlf_at_byte_32() raises:
    """Terminator starts exactly on a chunk boundary."""
    var buf = _pad("", 32, "\r\n\r\n")
    assert_equal(find_crlfcrlf(buf, 0), 36)


def test_find_crlfcrlf_at_byte_63() raises:
    var buf = _pad("", 63, "\r\n\r\n")
    assert_equal(find_crlfcrlf(buf, 0), 67)


def test_find_crlfcrlf_at_byte_64() raises:
    var buf = _pad("", 64, "\r\n\r\n")
    assert_equal(find_crlfcrlf(buf, 0), 68)


def test_find_crlfcrlf_width_parametricity() raises:
    """W=32 and W=64 must agree for all input shapes."""
    for n in [4, 16, 32, 33, 63, 64, 65, 128]:
        var buf = _pad("", n, "\r\n\r\n")
        assert_equal(find_crlfcrlf[W=32](buf, 0), n + 4)
        assert_equal(find_crlfcrlf[W=64](buf, 0), n + 4)


def test_find_crlfcrlf_false_cr_before_terminator() raises:
    """A stray CR that is NOT followed by LF\\r\\n must not fool the scanner."""
    var buf = _bytes("GET / HTTP/1.1\rX-Bad: cr-only\r\n\r\n")
    # The actual terminator is near the end.
    var end = find_crlfcrlf(buf, 0)
    assert_true(end > 0)
    # Exactly 4 bytes of CRLFCRLF precede ``end``.
    assert_equal(buf[end - 4], 13)
    assert_equal(buf[end - 3], 10)
    assert_equal(buf[end - 2], 13)
    assert_equal(buf[end - 1], 10)


# ── scan_content_length correctness ─────────────────────────────────────────


def test_scan_content_length_present() raises:
    var buf = _bytes("POST / HTTP/1.1\r\nContent-Length: 42\r\n\r\nbody")
    var end = find_crlfcrlf(buf, 0)
    assert_equal(scan_content_length(buf, end), 42)


def test_scan_content_length_mixed_case() raises:
    var buf = _bytes("POST / HTTP/1.1\r\ncoNtEnT-LeNgTh: 17\r\n\r\nbody")
    var end = find_crlfcrlf(buf, 0)
    assert_equal(scan_content_length(buf, end), 17)


def test_scan_content_length_leading_tabs() raises:
    var buf = _bytes("POST / HTTP/1.1\r\nContent-Length:\t 123\r\n\r\n")
    var end = find_crlfcrlf(buf, 0)
    assert_equal(scan_content_length(buf, end), 123)


def test_scan_content_length_absent_returns_zero() raises:
    var buf = _bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    var end = find_crlfcrlf(buf, 0)
    assert_equal(scan_content_length(buf, end), 0)


def test_scan_content_length_width_parametricity() raises:
    var buf = _bytes(
        "POST / HTTP/1.1\r\nX-Pad: "
        + "y" * 64
        + "\r\nContent-Length: 999\r\n\r\n"
    )
    var end = find_crlfcrlf(buf, 0)
    assert_equal(scan_content_length[W=32](buf, end), 999)
    assert_equal(scan_content_length[W=64](buf, end), 999)


# ── Entry ──────────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_header_scan.mojo — SIMD header scanners")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
