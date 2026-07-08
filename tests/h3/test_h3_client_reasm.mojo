"""Out-of-order STREAM reassembly in the H3 client.

Drives :class:`flare.http3.client._StreamReasm` directly with a real
response wire (built by the shipped server writer) split into
several STREAM chunks delivered out of order, duplicated, and with a
gap-then-fill, asserting:

* the response reader assembles the bytes in the correct order
  regardless of arrival order,
* a duplicate chunk is not double-delivered (no body corruption),
* FIN is only effective once every byte up to the final offset has
  arrived (the response is not complete while a gap remains).
"""

from std.collections import List
from std.memory import Span
from std.testing import assert_equal, assert_false, assert_true

from flare.http3 import encode_response_data, encode_response_headers
from flare.http3.client import _StreamReasm
from flare.http3.response_reader import Http3ResponseReader
from flare.qpack import QpackHeader


def _build_response_wire() raises -> List[UInt8]:
    """A 200 response with one header + a multi-byte body."""
    var hdrs = List[QpackHeader]()
    hdrs.append(QpackHeader("content-type", "text/plain"))
    var wire = List[UInt8]()
    encode_response_headers(200, hdrs, wire)
    var body = List[UInt8]()
    for b in String("reassembled-body-across-three-quic-packets").as_bytes():
        body.append(b)
    encode_response_data(Span[UInt8, _](body), wire)
    return wire^


def _slice(data: List[UInt8], start: Int, end: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=end - start)
    for i in range(start, end):
        out.append(data[i])
    return out^


def test_out_of_order_with_dup_and_gap() raises:
    var wire = _build_response_wire()
    var n = len(wire)
    var a = n // 3
    var b = (2 * n) // 3
    var seg0 = _slice(wire, 0, a)
    var seg1 = _slice(wire, a, b)
    var seg2 = _slice(wire, b, n)

    var reader = Http3ResponseReader.new()
    var reasm = _StreamReasm()

    # Deliver the LAST segment first (carries FIN). It is ahead of
    # the frontier -> stashed; nothing delivered, not complete.
    reasm.push(reader, UInt64(b), Span[UInt8, _](seg2), True)
    assert_false(reader.is_complete(), "must not complete with a leading gap")

    # Deliver seg0 (contiguous from 0). Still a gap [a, b) -> not
    # complete even though FIN's end offset is known.
    reasm.push(reader, UInt64(0), Span[UInt8, _](seg0), False)
    assert_false(reader.is_complete(), "gap [a,b) still open")

    # Duplicate seg0 (retransmit) -- already fully delivered, must be
    # a no-op (no double feed, no corruption).
    reasm.push(reader, UInt64(0), Span[UInt8, _](seg0), False)
    assert_false(reader.is_complete(), "dup must not advance or complete")

    # Fill the gap with seg1: frontier jumps to b, then the stashed
    # seg2 drains -> reaches the FIN offset -> complete.
    reasm.push(reader, UInt64(a), Span[UInt8, _](seg1), False)
    assert_true(reader.is_complete(), "complete once all bytes delivered")

    var resp = reader.take_response()
    assert_equal(resp.status, 200)
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](resp.body)),
        String("reassembled-body-across-three-quic-packets"),
    )
    assert_equal(len(resp.headers), 1)
    assert_equal(resp.headers[0].name, String("content-type"))


def test_overlapping_chunk_trimmed() raises:
    """A chunk that overlaps the delivered frontier is trimmed to
    its fresh suffix, not re-delivered from the start."""
    var wire = _build_response_wire()
    var n = len(wire)
    var mid = n // 2
    var first = _slice(wire, 0, mid)
    # Overlapping second chunk starts BEFORE mid (re-sends a few
    # already-delivered bytes) and runs to the end with FIN.
    var overlap_start = mid - 4
    var second = _slice(wire, overlap_start, n)

    var reader = Http3ResponseReader.new()
    var reasm = _StreamReasm()
    reasm.push(reader, UInt64(0), Span[UInt8, _](first), False)
    reasm.push(reader, UInt64(overlap_start), Span[UInt8, _](second), True)
    assert_true(reader.is_complete(), "overlap must still complete")
    var resp = reader.take_response()
    assert_equal(resp.status, 200)
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](resp.body)),
        String("reassembled-body-across-three-quic-packets"),
    )


def test_in_order_fast_path() raises:
    """The common case: in-order chunks, FIN on the last, completes
    exactly when expected."""
    var wire = _build_response_wire()
    var n = len(wire)
    var mid = n // 2
    var reader = Http3ResponseReader.new()
    var reasm = _StreamReasm()
    reasm.push(reader, UInt64(0), Span[UInt8, _](_slice(wire, 0, mid)), False)
    assert_false(reader.is_complete())
    reasm.push(reader, UInt64(mid), Span[UInt8, _](_slice(wire, mid, n)), True)
    assert_true(reader.is_complete())
    var resp = reader.take_response()
    assert_equal(resp.status, 200)


def main() raises:
    test_out_of_order_with_dup_and_gap()
    test_overlapping_chunk_trimmed()
    test_in_order_fast_path()
    print("test_h3_client_reasm: 3 passed")
