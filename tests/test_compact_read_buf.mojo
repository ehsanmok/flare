"""Unit tests for ``_compact_read_buf_drop_prefix`` in
:mod:`flare.http._server_reactor_impl`.

Phase 1D (throughput parity with Rust libs): the per-request
read-buffer compaction at the end of every on_readable_*
state-machine iteration used to be 5 inlined ``for i in range(...)
leftover.append(...)`` byte-loops. Replaced with a single
``memcpy`` shift through this helper. Helpful under HTTP/1.1
keep-alive pipelining where a single recv can carry multiple
requests' worth of bytes.

Test cases
----------

1. drop everything (drop_n == len) -> empty result.
2. drop prefix shorter than buffer -> trailing bytes preserved.
3. drop with empty trailing -> empty result + no crash.
4. drop_n == 1 -> 1-byte shift, trailing bytes preserved.
5. drop_n large enough to be defensive (>= len) -> empty result.
6. defensive over-shoot (drop_n > len) -> empty result, no crash.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http._server_reactor_impl import _compact_read_buf_drop_prefix


def test_drop_zero_keeps_full_buffer() raises:
    """Edge case: callers should skip drop_n=0 themselves, but
    if they don't the helper must not corrupt."""
    var buf = List[UInt8]()
    buf.append(UInt8(ord("a")))
    buf.append(UInt8(ord("b")))
    buf.append(UInt8(ord("c")))
    _compact_read_buf_drop_prefix(buf, 0)
    assert_equal(len(buf), 3)
    assert_equal(Int(buf[0]), ord("a"))
    assert_equal(Int(buf[1]), ord("b"))
    assert_equal(Int(buf[2]), ord("c"))


def test_drop_one_shifts_remaining() raises:
    var buf = List[UInt8]()
    for c in [ord("X"), ord("a"), ord("b"), ord("c")]:
        buf.append(UInt8(c))
    _compact_read_buf_drop_prefix(buf, 1)
    assert_equal(len(buf), 3)
    assert_equal(Int(buf[0]), ord("a"))
    assert_equal(Int(buf[1]), ord("b"))
    assert_equal(Int(buf[2]), ord("c"))


def test_drop_prefix_keeps_trailing() raises:
    """Pipelined-next-request shape: drop the consumed request's
    bytes, keep the next request's prefix."""
    var data = String("GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n")
    var buf = List[UInt8]()
    var p = data.unsafe_ptr()
    for i in range(data.byte_length()):
        buf.append(p[i])
    var first_end = 19  # length of "GET /a HTTP/1.1\r\n\r\n"
    _compact_read_buf_drop_prefix(buf, first_end)
    assert_equal(len(buf), data.byte_length() - first_end)
    # First byte of leftover should be 'G' (start of next request).
    assert_equal(Int(buf[0]), ord("G"))


def test_drop_all_clears_buffer() raises:
    """drop_n == len -> empty buffer, no crash."""
    var buf = List[UInt8]()
    for c in [ord("a"), ord("b"), ord("c")]:
        buf.append(UInt8(c))
    _compact_read_buf_drop_prefix(buf, 3)
    assert_equal(len(buf), 0)


def test_drop_more_than_len_clears_buffer() raises:
    """Defensive: over-shoot drop_n -> empty buffer, no crash."""
    var buf = List[UInt8]()
    for c in [ord("a"), ord("b"), ord("c")]:
        buf.append(UInt8(c))
    _compact_read_buf_drop_prefix(buf, 999)
    assert_equal(len(buf), 0)


def test_drop_from_empty_is_noop() raises:
    """Empty input + any drop_n -> still empty, no crash."""
    var buf = List[UInt8]()
    _compact_read_buf_drop_prefix(buf, 0)
    assert_equal(len(buf), 0)
    _compact_read_buf_drop_prefix(buf, 5)
    assert_equal(len(buf), 0)


def test_drop_long_buffer_preserves_byte_order() raises:
    """64-byte payload, drop 16-byte prefix, verify the remaining
    48 bytes match the original tail exactly. Catches any
    off-by-one in the memcpy bounds.
    """
    var n = 64
    var buf = List[UInt8]()
    for i in range(n):
        buf.append(UInt8(i & 0xFF))
    _compact_read_buf_drop_prefix(buf, 16)
    assert_equal(len(buf), n - 16)
    for i in range(len(buf)):
        assert_equal(Int(buf[i]), (i + 16) & 0xFF)


def main() raises:
    var suite = TestSuite()
    suite.test[test_drop_zero_keeps_full_buffer]()
    suite.test[test_drop_one_shifts_remaining]()
    suite.test[test_drop_prefix_keeps_trailing]()
    suite.test[test_drop_all_clears_buffer]()
    suite.test[test_drop_more_than_len_clears_buffer]()
    suite.test[test_drop_from_empty_is_noop]()
    suite.test[test_drop_long_buffer_preserves_byte_order]()
    suite^.run()
