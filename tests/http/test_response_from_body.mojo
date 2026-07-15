"""Opt-in Response[B: Body] ergonomics via response_from_body.

Proves the additive parametric-body bridge without touching the concrete
hot-path Response: a known-length Body buffers (Content-Length semantics,
byte-identical to today) and an open-ended Body lowers onto the K1
body_stream (chunked). This is the usable Response[B] shape -- a handler
returns response_from_body[MyBody](my_body, 200) from the normal Handler
path -- without a generic Response[B] type that would erase to InlineBody
at every thunk boundary anyway.
"""

from std.collections import Optional
from std.testing import assert_equal, assert_false, assert_true

from flare.http import (
    Body,
    Cancel,
    ChunkedBody,
    ChunkSource,
    InlineBody,
    Response,
    response_from_body,
)


struct _CountSource(ChunkSource, Copyable, Movable):
    """Yields ``n`` single-byte ``x`` chunks then end-of-stream."""

    var n: Int

    def __init__(out self, n: Int):
        self.n = n

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.n == 0:
            return Optional[List[UInt8]]()
        self.n -= 1
        var b = List[UInt8]()
        b.append(UInt8(ord("x")))
        return Optional[List[UInt8]](b^)


def _b(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var bs = s.as_bytes()
    for i in range(len(bs)):
        out.append(bs[i])
    return out^


def _drain_stream(mut resp: Response) raises -> List[UInt8]:
    var box = resp.body_stream.take()
    var cancel = Cancel.never()
    var out = List[UInt8]()
    while True:
        var c = box.next(cancel)
        if not c:
            break
        var cb = c.value().copy()
        for i in range(len(cb)):
            out.append(cb[i])
    return out^


def test_inline_body_buffers() raises:
    var body = InlineBody(_b("hello"))
    var resp = response_from_body[InlineBody](body^, 200, "OK")
    assert_false(Bool(resp.body_stream), "known-length body must buffer")
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "hello")


def test_chunked_body_streams() raises:
    var body = ChunkedBody[_CountSource](_CountSource(3))
    var resp = response_from_body[ChunkedBody[_CountSource]](body^, 200)
    assert_true(Bool(resp.body_stream), "open-ended body must stream")
    var drained = _drain_stream(resp)
    assert_equal(len(drained), 3)
    assert_equal(drained[0], UInt8(ord("x")))


def test_reason_carried_on_stream() raises:
    var body = ChunkedBody[_CountSource](_CountSource(1))
    var resp = response_from_body[ChunkedBody[_CountSource]](
        body^, 202, "Accepted"
    )
    assert_true(Bool(resp.body_stream))
    assert_equal(resp.status, 202)
    assert_equal(resp.reason, "Accepted")


def main() raises:
    print("test_response_from_body")
    test_inline_body_buffers()
    test_chunked_body_streams()
    test_reason_carried_on_stream()
    print("test_response_from_body: 3 passed")
