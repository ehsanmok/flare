# PLATFORM: any
"""H3-01: the HTTP/3 request reader buffers unknown frames without bound.

Lean: Flare.Bugs.H3_01.unknown_needs_unbounded_buffer (impl),
      Flare.Bugs.H3_01.feedFixed_bounded (fix).
flare/http3/request_reader.mojo:240-259 @59bda50.

Expected: like HEADERS (max_field_section_bytes) and DATA (max_body_bytes),
a frame whose declared length can never be accepted is acted on from its
header alone (rejected, or its payload discarded as it arrives), so the
caller never has to hold more than a bounded number of bytes.
Actual: for an unknown / grease frame type, feed_into returns 0
(NEEDS_MORE) until the whole declared payload (up to 2^62-1 bytes) sits in
the caller's buffer. Http3Connection.feed_stream_chunk keeps appending to
the per-stream inbox; only QUIC flow control bounds it (1 MiB per stream,
64 MiB connection window in the shipped server).

Minimal fix: in feed_into, next to the HEADERS / DATA header checks, reject
(or skip incrementally) an unknown frame whose flen exceeds a cap, e.g.
`max_field_section_bytes`.
"""

from std.collections import List
from std.collections.span import Span

from flare.http3 import Http3RequestEventHandler, Http3RequestReader, feed_into
from flare.qpack import QpackHeader
from flare.quic.varint import encode_varint


@fieldwise_init
struct _Rec(Http3RequestEventHandler, Movable):
    var events: Int

    def on_headers(mut self, headers: List[QpackHeader]) raises:
        self.events += 1

    def on_data(mut self, data: List[UInt8]) raises:
        self.events += 1

    def on_trailers(mut self, trailers: List[QpackHeader]) raises:
        self.events += 1

    def on_unknown_frame(mut self, type_id: UInt64) raises:
        self.events += 1

    def on_protocol_error(mut self, message: String) raises:
        self.events += 1


def main() raises:
    var reader = Http3RequestReader.new()  # max_field_section_bytes = 8192
    var rec = _Rec(events=0)
    # Grease frame type 0x21, declared length 2^62 - 1.
    var buf = encode_varint(UInt64(0x21))
    var l = encode_varint(UInt64((1 << 62) - 1))
    for i in range(len(l)):
        buf.append(l[i])
    # 1 MiB of payload already buffered: 128x the field-section cap.
    for _ in range(1 << 20):
        buf.append(0)
    var consumed = feed_into(reader, Span[UInt8, _](buf), rec)
    if consumed == 0 and rec.events == 0:
        print(
            "BUG REPRODUCED: feed_into returned NEEDS_MORE with",
            len(buf),
            "bytes buffered for an unknown frame declaring 2^62-1 bytes;"
            " the caller must keep buffering",
        )
        raise Error("H3-01")
    print("OK: reader acted on the oversized unknown frame from its header")
