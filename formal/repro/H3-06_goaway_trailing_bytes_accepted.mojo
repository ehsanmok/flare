# PLATFORM: any
"""H3-06: bytes after the GOAWAY stream id are accepted.

Lean: Flare.Bugs.H3_06.impl_accepts_trailing (impl),
      Flare.Bugs.H3_06.goawayFixed_spec (fix).
flare/http3/server.mojo:1197-1211 @59bda50 (`_dispatch_control_frame`).

RFC 9114 §7.2.6: the GOAWAY payload is one variable-length integer; §7.1:
additional bytes after the identified fields MUST be treated as a
connection error of type H3_FRAME_ERROR. Expected: feeding GOAWAY with
payload `00 ff` raises. Actual: `decode_varint(payload)` reads the id 0
and `goaway_id.consumed` is never compared with `len(payload)`, so the
frame is accepted and `peer_goaway_max_stream_id` becomes 0.

Minimal fix: after `decode_varint(payload)`, raise when
`goaway_id.consumed != len(payload)`.
"""

from std.collections import List
from std.collections.span import Span

from flare.http3 import (
    H3_FRAME_TYPE_GOAWAY,
    H3_FRAME_TYPE_SETTINGS,
    H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
    Http3Connection,
    Http3Setting,
    encode_http3_frame,
    encode_http3_settings,
)


def _control_prefix() raises -> List[UInt8]:
    var out = List[UInt8]()
    out.append(0x00)  # stream type: control
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE, value=8192)
    )
    var payload = List[UInt8]()
    encode_http3_settings(settings, payload)
    encode_http3_frame(H3_FRAME_TYPE_SETTINGS, Span[UInt8, _](payload), out)
    return out^


def main() raises:
    var c = Http3Connection()
    c.feed_uni_stream_chunk(2, _control_prefix())
    var payload = List[UInt8]()
    payload.append(0x00)  # stream id 0
    payload.append(0xFF)  # trailing byte
    var frame = List[UInt8]()
    encode_http3_frame(H3_FRAME_TYPE_GOAWAY, Span[UInt8, _](payload), frame)
    var accepted = True
    try:
        c.feed_uni_stream_chunk(2, frame^)
    except e:
        accepted = False
        print("raised:", e)
    if accepted:
        print(
            "BUG REPRODUCED: GOAWAY payload 00 ff accepted (no H3_FRAME_ERROR);"
            " peer_goaway_max_stream_id =",
            c.peer_goaway_max_stream_id,
        )
        raise Error("H3-06")
    print("OK: GOAWAY with trailing bytes rejected")
