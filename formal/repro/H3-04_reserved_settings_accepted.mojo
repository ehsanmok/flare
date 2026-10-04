# PLATFORM: any
"""H3-04: HTTP/2-reserved SETTINGS identifiers are accepted.

Lean: Flare.Bugs.H3_04.impl_accepts_reserved_setting (impl),
      Flare.Bugs.H3_04.applyFixed_spec (fix).
flare/http3/server.mojo:1213-1228 @59bda50 (`_apply_peer_settings`).

RFC 9114 §7.2.4.1 / §11.2.2: setting identifiers 0x02, 0x03, 0x04, 0x05
(HTTP/2 ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE,
MAX_FRAME_SIZE) "MUST NOT be sent, and their receipt MUST be treated as a
connection error of type H3_SETTINGS_ERROR". Expected: raise. Actual: the
identifiers fall through as unknown and are ignored.

Minimal fix: in `_apply_peer_settings`, raise H3_SETTINGS_ERROR when
`2 <= id <= 5`.
"""

from std.collections import List
from std.collections.span import Span

from flare.http3 import (
    H3_FRAME_TYPE_SETTINGS,
    Http3Connection,
    Http3Setting,
    encode_http3_frame,
    encode_http3_settings,
)


def main() raises:
    var accepted = String("")
    for sid in [0x02, 0x03, 0x04, 0x05]:
        var c = Http3Connection()
        var out = List[UInt8]()
        out.append(0x00)  # control stream
        var settings = List[Http3Setting]()
        settings.append(Http3Setting(identifier=UInt64(sid), value=1))
        var payload = List[UInt8]()
        encode_http3_settings(settings, payload)
        encode_http3_frame(H3_FRAME_TYPE_SETTINGS, Span[UInt8, _](payload), out)
        try:
            c.feed_uni_stream_chunk(2, out^)
            if c.peer_settings_received:
                accepted += hex(sid) + " "
        except:
            pass
    if accepted != "":
        print(
            "BUG REPRODUCED: SETTINGS with HTTP/2-reserved identifiers accepted"
            " (no H3_SETTINGS_ERROR):",
            accepted,
        )
        raise Error("H3-04")
    print("OK: reserved SETTINGS identifiers rejected")
