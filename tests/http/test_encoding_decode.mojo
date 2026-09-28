"""Decompression succeeds only at the end of the compressed stream.

The wrapper called inflate() once into a caller-sized buffer and took
Z_OK / Z_BUF_ERROR for success, so a truncated gzip body decoded to a
partial one with no error, and the Mojo side re-inflated the whole
input each time it doubled its buffer. ``flare_inflate_all`` feeds the
input once, grows its own buffer, and requires Z_STREAM_END.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http.encoding import (
    compress_gzip,
    decompress_deflate,
    decompress_gzip,
)


def _text(n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(97 + (i * 7) % 26))
    return out^


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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
