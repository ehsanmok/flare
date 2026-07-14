"""Tests for the K1 streaming foundation: ChunkSourceBox + chunk framing.

Covers the type-erased chunk-source box (drive to end-of-stream, clean
free) and the RFC 9112 sec 7.1 chunk framing helpers. No reactor
coupling -- this is the source-side foundation the reactor adoption
builds on.
"""

from std.collections import Optional
from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.response_stream import (
    ChunkSourceBox,
    frame_chunk_into,
    frame_terminator_into,
)


struct _ListSource(ChunkSource, Movable):
    """A ChunkSource that yields a fixed set of string chunks, then None."""

    var chunks: List[String]
    var i: Int

    def __init__(out self, var chunks: List[String]):
        self.chunks = chunks^
        self.i = 0

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.i >= len(self.chunks):
            return Optional[List[UInt8]]()
        var s = self.chunks[self.i]
        self.i += 1
        var out = List[UInt8]()
        for b in s.as_bytes():
            out.append(b)
        return Optional[List[UInt8]](out^)


def _to_str(buf: List[UInt8]) -> String:
    var out = String(capacity=len(buf) + 1)
    for b in buf:
        out += chr(Int(b))
    return out^


def test_box_drives_source_to_end() raises:
    var chunks = List[String]()
    chunks.append("a")
    chunks.append("bc")
    var box = ChunkSourceBox.create[_ListSource](_ListSource(chunks^))
    var c1 = box.next(Cancel.never())
    assert_true(Bool(c1))
    assert_equal(_to_str(c1.value()), "a")
    var c2 = box.next(Cancel.never())
    assert_true(Bool(c2))
    assert_equal(_to_str(c2.value()), "bc")
    var c3 = box.next(Cancel.never())
    assert_false(Bool(c3))  # end-of-stream
    _ = box^  # box drops here; boxed source freed exactly once


def test_box_move_frees_once() raises:
    """Moving the box transfers ownership; only the final owner frees."""
    var chunks = List[String]()
    chunks.append("x")
    var box = ChunkSourceBox.create[_ListSource](_ListSource(chunks^))
    var moved = box^
    var c = moved.next(Cancel.never())
    assert_true(Bool(c))
    assert_equal(_to_str(c.value()), "x")
    _ = moved^


def test_frame_chunk_hex_len() raises:
    var buf = List[UInt8]()
    var one = List[UInt8]()
    one.append(ord("a"))
    frame_chunk_into(buf, one)
    assert_equal(_to_str(buf), "1\r\na\r\n")


def test_frame_chunk_multibyte() raises:
    var buf = List[UInt8]()
    var chunk = List[UInt8]()
    for b in String("hello").as_bytes():
        chunk.append(b)
    frame_chunk_into(buf, chunk)
    assert_equal(_to_str(buf), "5\r\nhello\r\n")


def test_frame_chunk_large_hex() raises:
    # 255 bytes -> "ff"; 4096 -> "1000".
    var buf = List[UInt8]()
    var c255 = List[UInt8]()
    for _ in range(255):
        c255.append(ord("z"))
    frame_chunk_into(buf, c255)
    assert_true(_to_str(buf).startswith("ff\r\n"))

    var buf2 = List[UInt8]()
    var c4096 = List[UInt8]()
    for _ in range(4096):
        c4096.append(ord("y"))
    frame_chunk_into(buf2, c4096)
    assert_true(_to_str(buf2).startswith("1000\r\n"))


def test_frame_terminator() raises:
    var buf = List[UInt8]()
    frame_terminator_into(buf)
    assert_equal(_to_str(buf), "0\r\n\r\n")


def test_full_chunked_stream_bytes() raises:
    """End-to-end: drive a box through frame helpers into a wire buffer
    and assert the exact chunked-encoded bytes a client would de-chunk."""
    var chunks = List[String]()
    chunks.append("data: 1\n\n")
    chunks.append("data: 2\n\n")
    var box = ChunkSourceBox.create[_ListSource](_ListSource(chunks^))
    var wire = List[UInt8]()
    while True:
        var c = box.next(Cancel.never())
        if not c:
            break
        frame_chunk_into(wire, c.value())
    frame_terminator_into(wire)
    _ = box^
    assert_equal(
        _to_str(wire),
        "9\r\ndata: 1\n\n\r\n9\r\ndata: 2\n\n\r\n0\r\n\r\n",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
