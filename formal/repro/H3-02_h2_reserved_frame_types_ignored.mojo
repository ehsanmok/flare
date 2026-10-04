# PLATFORM: any
"""H3-02: HTTP/2-reserved frame types are ignored on request streams.

Lean: Flare.Bugs.H3_02.impl_ignores_reserved (impl),
      Flare.Bugs.H3_02.runFixed_spec (fix meets the RFC 9114 §4.1 grammar).
flare/http3/request_reader.mojo:308-327 @59bda50.

RFC 9114 §7.2.8 / §11.2.1: frame types 0x02, 0x06, 0x08 and 0x09 (HTTP/2
PRIORITY, PING, WINDOW_UPDATE, CONTINUATION) "MUST NOT be sent, and their
receipt MUST be treated as a connection error of type H3_FRAME_UNEXPECTED".
Expected: on_protocol_error. Actual: the reader classifies them as unknown /
grease and fires on_unknown_frame, so the stream continues.

Minimal fix: add 0x02, 0x06, 0x08, 0x09 to the rejected set next to the
control-stream frame types in feed_into.
"""

from std.collections import List
from std.collections.span import Span

from flare.http3 import Http3RequestEventHandler, Http3RequestReader, feed_into
from flare.qpack import QpackHeader


@fieldwise_init
struct _Rec(Http3RequestEventHandler, Movable):
    var unknown: Int
    var errors: Int

    def on_headers(mut self, headers: List[QpackHeader]) raises:
        pass

    def on_data(mut self, data: List[UInt8]) raises:
        pass

    def on_trailers(mut self, trailers: List[QpackHeader]) raises:
        pass

    def on_unknown_frame(mut self, type_id: UInt64) raises:
        self.unknown += 1

    def on_protocol_error(mut self, message: String) raises:
        self.errors += 1


def main() raises:
    var ignored = List[Int]()
    for t in [0x02, 0x06, 0x08, 0x09]:
        var reader = Http3RequestReader.new()
        var rec = _Rec(unknown=0, errors=0)
        var buf = List[UInt8]()
        buf.append(UInt8(t))  # frame type
        buf.append(0)  # length 0
        _ = feed_into(reader, Span[UInt8, _](buf), rec)
        if rec.errors == 0:
            ignored.append(t)
    if len(ignored) > 0:
        var s = String("")
        for t in ignored:
            s += hex(t) + " "
        print(
            "BUG REPRODUCED: HTTP/2-reserved frame types accepted as unknown"
            " (no H3_FRAME_UNEXPECTED):",
            s,
        )
        raise Error("H3-02")
    print("OK: all HTTP/2-reserved frame types rejected")
