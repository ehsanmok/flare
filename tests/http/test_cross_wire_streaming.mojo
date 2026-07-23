"""Shared handler-level cross-wire streaming test.

Asserts that the *same* streaming source produces byte-correct framing on
every server wire and reassembles to the identical application body:

  - h1 / https: ``Transfer-Encoding: chunked`` framing
    (``frame_chunk_into`` + ``frame_terminator_into``), which the TLS
    path (:func:`flare.http.tls_server.handle_tls_h1_connection`) writes
    verbatim through ``SSL_write``.
  - h2: one DATA frame per chunk (RFC 9113 §6.1), ``END_STREAM`` on the
    last.
  - h3: one DATA frame per chunk (RFC 9114 §7.2.1), then FIN.

Each wire's framing is round-tripped back to the concatenated payload and
compared against the golden body, so a divergence in any single wire's
DATA/chunk framing (or a source that yields different bytes when drained
twice) fails loudly. This is the wire-agnostic guarantee behind
``stream_response(source)``: pick your source once, get correct framing
everywhere.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.response_stream import (
    ChunkSourceBox,
    frame_chunk_into,
    frame_terminator_into,
)
from flare.http.response import stream_response
from flare.http2.frame import (
    Frame,
    FrameType,
    FrameFlags,
    encode_frame,
    parse_frame,
)
from flare.http3.response_writer import encode_response_data
from flare.quic.varint import decode_varint


comptime _H3_FRAME_TYPE_DATA: Int = 0x00


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


@fieldwise_init
struct _ListSource(ChunkSource, Copyable, Movable):
    """Canonical source: yields a fixed list of chunks, then EOS."""

    var chunks: List[List[UInt8]]
    var idx: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self.idx >= len(self.chunks):
            return None
        var out = self.chunks[self.idx].copy()
        self.idx += 1
        return out^


def _canonical_chunks() -> List[List[UInt8]]:
    var chunks = List[List[UInt8]]()
    chunks.append(_bytes("Hello, "))
    chunks.append(_bytes("cross-"))
    chunks.append(_bytes("wire "))
    chunks.append(_bytes("streaming!"))
    return chunks^


comptime _GOLDEN_BODY: String = "Hello, cross-wire streaming!"


def _drain(var box: ChunkSourceBox) raises -> List[List[UInt8]]:
    """Pull every chunk out of a source box (skipping empty)."""
    var cancel = Cancel.never()
    var out = List[List[UInt8]]()
    while True:
        var c = box.next(cancel)
        if not c:
            break
        var chunk = c.value().copy()
        if len(chunk) == 0:
            continue
        out.append(chunk^)
    return out^


# ── h1 / https: chunked framing round-trip ───────────────────────────────


def _decode_chunked(buf: List[UInt8]) raises -> List[UInt8]:
    """Minimal RFC 9112 §7.1 chunked-body decoder: returns the reassembled
    payload from ``{hexlen}\\r\\n{bytes}\\r\\n ... 0\\r\\n\\r\\n``."""
    var out = List[UInt8]()
    var i = 0
    while i < len(buf):
        # Parse the hex length line up to CRLF.
        var size = 0
        while i < len(buf) and buf[i] != UInt8(ord("\r")):
            var d = buf[i]
            var v: Int
            if d >= UInt8(ord("0")) and d <= UInt8(ord("9")):
                v = Int(d) - ord("0")
            elif d >= UInt8(ord("a")) and d <= UInt8(ord("f")):
                v = Int(d) - ord("a") + 10
            elif d >= UInt8(ord("A")) and d <= UInt8(ord("F")):
                v = Int(d) - ord("A") + 10
            else:
                raise Error("bad hex digit in chunk size")
            size = size * 16 + v
            i += 1
        i += 2  # skip CRLF after the size line
        if size == 0:
            break  # terminator
        for j in range(size):
            out.append(buf[i + j])
        i += size + 2  # skip payload + trailing CRLF
    return out^


def test_h1_chunked_roundtrip() raises:
    """The chunked framing of the canonical source decodes to the golden
    body (this is byte-identical to what the https path writes)."""
    var box = ChunkSourceBox.create(_ListSource(_canonical_chunks(), 0))
    var chunks = _drain(box^)

    var wire = List[UInt8]()
    for i in range(len(chunks)):
        frame_chunk_into(wire, chunks[i])
    frame_terminator_into(wire)

    var decoded = _decode_chunked(wire)
    assert_equal(String(unsafe_from_utf8=Span[UInt8, _](decoded)), _GOLDEN_BODY)
    # The terminator must be present and last.
    assert_true(len(wire) >= 5, "framed chunked body too short")


# ── h2: DATA frame per chunk ─────────────────────────────────────────────


def test_h2_data_frames_roundtrip() raises:
    """One h2 DATA frame per chunk, END_STREAM on the last; parsing them
    back yields the golden body."""
    var box = ChunkSourceBox.create(_ListSource(_canonical_chunks(), 0))
    var chunks = _drain(box^)

    var wire = List[UInt8]()
    for i in range(len(chunks)):
        var f = Frame()
        f.header.type = FrameType.DATA()
        f.header.stream_id = 1
        if i == len(chunks) - 1:
            f.header.flags = FrameFlags(UInt8(0x1))  # END_STREAM
        f.payload = chunks[i].copy()
        var enc = encode_frame(f)
        for b in enc:
            wire.append(b)

    # Parse the frames back out.
    var body = List[UInt8]()
    var off = 0
    var saw_end = False
    while off < len(wire):
        var parsed = parse_frame(Span[UInt8, _](wire)[off:])
        if not parsed:
            break
        var fr = parsed.value().copy()
        assert_equal(fr.header.type.value, FrameType.DATA().value)
        assert_equal(fr.header.stream_id, 1)
        for b in fr.payload:
            body.append(b)
        if (fr.header.flags.bits & UInt8(0x1)) != 0:
            saw_end = True
        off += 9 + fr.header.length

    assert_true(saw_end, "last h2 DATA frame must carry END_STREAM")
    assert_equal(String(unsafe_from_utf8=Span[UInt8, _](body)), _GOLDEN_BODY)


# ── h3: DATA frame per chunk ─────────────────────────────────────────────


def _decode_h3_data(buf: List[UInt8]) raises -> List[UInt8]:
    """Concatenate the payloads of the DATA frames in ``buf``."""
    var out = List[UInt8]()
    var i = 0
    while i < len(buf):
        var t = decode_varint(Span[UInt8, _](buf)[i:])
        i += t.consumed
        var ln = decode_varint(Span[UInt8, _](buf)[i:])
        i += ln.consumed
        var length = Int(ln.value)
        if Int(t.value) == _H3_FRAME_TYPE_DATA:
            for j in range(length):
                out.append(buf[i + j])
        i += length
    return out^


def test_h3_data_frames_roundtrip() raises:
    """One h3 DATA frame per chunk; decoding them yields the golden body."""
    var box = ChunkSourceBox.create(_ListSource(_canonical_chunks(), 0))
    var chunks = _drain(box^)

    var wire = List[UInt8]()
    for i in range(len(chunks)):
        encode_response_data(Span[UInt8, _](chunks[i]), wire)

    var decoded = _decode_h3_data(wire)
    assert_equal(String(unsafe_from_utf8=Span[UInt8, _](decoded)), _GOLDEN_BODY)


# ── Cross-wire equivalence ───────────────────────────────────────────────


def test_all_wires_reassemble_identically() raises:
    """The h1, h2, and h3 framings of one source all reassemble to the
    exact same application body."""
    var chunks = _canonical_chunks()

    var h1_wire = List[UInt8]()
    for i in range(len(chunks)):
        frame_chunk_into(h1_wire, chunks[i])
    frame_terminator_into(h1_wire)
    var h1_body = _decode_chunked(h1_wire)

    var h3_wire = List[UInt8]()
    for i in range(len(chunks)):
        encode_response_data(Span[UInt8, _](chunks[i]), h3_wire)
    var h3_body = _decode_h3_data(h3_wire)

    var h2_wire = List[UInt8]()
    for i in range(len(chunks)):
        var f = Frame()
        f.header.type = FrameType.DATA()
        f.header.stream_id = 1
        f.payload = chunks[i].copy()
        var enc = encode_frame(f)
        for b in enc:
            h2_wire.append(b)
    var h2_body = List[UInt8]()
    var off = 0
    while off < len(h2_wire):
        var parsed = parse_frame(Span[UInt8, _](h2_wire)[off:])
        if not parsed:
            break
        var fr = parsed.value().copy()
        for b in fr.payload:
            h2_body.append(b)
        off += 9 + fr.header.length

    var s1 = String(unsafe_from_utf8=Span[UInt8, _](h1_body))
    var s2 = String(unsafe_from_utf8=Span[UInt8, _](h2_body))
    var s3 = String(unsafe_from_utf8=Span[UInt8, _](h3_body))
    assert_equal(s1, _GOLDEN_BODY)
    assert_equal(s1, s2)
    assert_equal(s1, s3)


def main() raises:
    print("=" * 60)
    print("test_cross_wire_streaming.mojo — one source, every wire")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
