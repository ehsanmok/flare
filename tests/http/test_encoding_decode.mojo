"""Decompression succeeds only at the end of the compressed stream.

The wrapper called inflate() once into a caller-sized buffer and took
Z_OK / Z_BUF_ERROR for success, so a truncated gzip body decoded to a
partial one with no error, and the Mojo side re-inflated the whole
input each time it doubled its buffer. ``flare_inflate_all`` feeds the
input once, grows its own buffer, and requires Z_STREAM_END.
"""

from std.testing import assert_equal, assert_true, TestSuite
from flare.utils.dylib import pinned_flare_lib

from flare.http.encoding import (
    compress_brotli,
    compress_gzip,
    decode_content,
    decompress_deflate,
    decompress_brotli,
    decompress_gzip,
)


def _text(n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(97 + (i * 7) % 26))
    return out^


def _mixed(n: Int, seed: Int) -> List[UInt8]:
    """Text with enough variety that the encoder builds real tables."""
    var out = List[UInt8](capacity=n)
    var x = seed
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(UInt8(97 + (x >> 16) % 13))
    return out^


def test_brotli_is_deterministic_across_reused_scratch() raises:
    """The brotli encoder's work buffers are reused between calls on a
    thread. Output must depend on the input alone: compressing the same
    bytes again, on buffers that still hold another input's scratch,
    gives the same stream, and it decodes back to the input."""
    for q in [0, 1, 5]:
        for n in [100, 20_000, 300_000]:
            var src = _mixed(n, n + q)
            var first = compress_brotli(Span[UInt8, _](src), q)
            var other = _mixed(n, 7 * n + 1)
            _ = compress_brotli(Span[UInt8, _](other), q)
            var again = compress_brotli(Span[UInt8, _](src), q)
            assert_equal(len(again), len(first))
            for i in range(len(first)):
                assert_equal(again[i], first[i])
            var back = decompress_brotli(Span[UInt8, _](again))
            assert_equal(len(back), n)
            for i in range(n):
                assert_equal(back[i], src[i])


def test_gzip_is_deterministic_across_reused_scratch() raises:
    """As for brotli: deflate's reused work buffers leave the output a
    function of the input alone."""
    for level in [1, 6, 9]:
        for n in [100, 20_000, 300_000]:
            var src = _mixed(n, n + level)
            var first = compress_gzip(Span[UInt8, _](src), level)
            var other = _mixed(n, 7 * n + 1)
            _ = compress_gzip(Span[UInt8, _](other), level)
            var again = compress_gzip(Span[UInt8, _](src), level)
            assert_equal(len(again), len(first))
            for i in range(len(first)):
                assert_equal(again[i], first[i])
            var back = decompress_gzip(Span[UInt8, _](again))
            assert_equal(len(back), n)
            for i in range(n):
                assert_equal(back[i], src[i])


def test_round_trip() raises:
    var src = _text(10_000)
    var z = compress_gzip(Span[UInt8, _](src))
    var back = decompress_gzip(Span[UInt8, _](z))
    assert_equal(len(back), len(src))
    for i in range(len(src)):
        assert_equal(back[i], src[i])


def test_truncated_gzip_is_an_error() raises:
    var src = _text(10_000)
    var z = compress_gzip(Span[UInt8, _](src))
    var cut = List[UInt8](Span[UInt8, _](z)[: len(z) - 12])
    var raised = False
    try:
        _ = decompress_gzip(Span[UInt8, _](cut))
    except:
        raised = True
    assert_true(raised, "a truncated body decoded as if complete")


def test_high_ratio_body_decodes_whole() raises:
    # 4 MiB of one byte compresses ~1000:1, far past the old 4x first
    # guess, so the buffer grows many times inside one inflate pass.
    var src = List[UInt8](length=4 * 1024 * 1024, fill=UInt8(120))
    var z = compress_gzip(Span[UInt8, _](src))
    var back = decompress_gzip(Span[UInt8, _](z))
    assert_equal(len(back), len(src))


def test_output_exactly_at_the_cap_is_allowed() raises:
    var src = _text(5000)
    var z = compress_gzip(Span[UInt8, _](src))
    assert_equal(len(decompress_gzip(Span[UInt8, _](z), 5000)), 5000)
    var raised = False
    try:
        _ = decompress_gzip(Span[UInt8, _](z), 4999)
    except:
        raised = True
    assert_true(raised, "output over the cap was accepted")


def test_garbage_deflate_is_an_error() raises:
    var junk = List[UInt8](String("definitely not deflate").as_bytes())
    var raised = False
    try:
        _ = decompress_deflate(Span[UInt8, _](junk))
    except:
        raised = True
    assert_true(raised)


def test_codec_libraries_are_opened_once() raises:
    """Every call shares one handle per shim instead of a dlopen each."""
    var data = List[UInt8](length=4096, fill=UInt8(97))
    _ = compress_gzip(Span[UInt8, _](data))
    _ = compress_brotli(Span[UInt8, _](data))
    var z = Int(pinned_flare_lib["zlib"]())
    var b = Int(pinned_flare_lib["brotli"]())
    _ = compress_gzip(Span[UInt8, _](data))
    _ = compress_brotli(Span[UInt8, _](data))
    assert_equal(Int(pinned_flare_lib["zlib"]()), z)
    assert_equal(Int(pinned_flare_lib["brotli"]()), b)
    assert_true(z != b)
    var round = decode_content(
        Span[UInt8, _](compress_brotli(Span[UInt8, _](data))), "br"
    )
    assert_equal(len(round), 4096)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
