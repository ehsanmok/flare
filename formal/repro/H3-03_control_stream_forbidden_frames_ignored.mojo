# PLATFORM: any
# RESOLVED: H3-03 fixed on fix/formal-findings
"""H3-03: frames forbidden on the control stream are silently ignored.

Lean: Flare.Bugs.H3_03.implOld_accepts_data_on_control (pre-fix),
      Flare.Bugs.H3_03.dispatchFixed_spec (fix).
flare/http3/server.mojo:1170-1211 @59bda50 (`_dispatch_control_frame`).

RFC 9114 §7.2.1 (DATA), §7.2.2 (HEADERS), §7.2.5 (PUSH_PROMISE): receipt on
a control stream MUST be treated as a connection error of type
H3_FRAME_UNEXPECTED; §7.2.8: the HTTP/2-reserved types 0x02/0x06/0x08/0x09
likewise. Expected: feed_uni_stream_chunk raises. Before the fix: Actual: after SETTINGS,
`_dispatch_control_frame` handles only SETTINGS and GOAWAY and returns
for every other type, so these frames are dropped without error.

Minimal fix: in `_dispatch_control_frame`, after the SETTINGS-first check,
raise H3_FRAME_UNEXPECTED for types 0x00, 0x01, 0x05, 0x02, 0x06, 0x08, 0x09.
"""

from std.collections import List
from std.collections.span import Span

from flare.http3 import (
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
    var accepted = String("")
    for t in [0x00, 0x01, 0x05, 0x02, 0x06, 0x08, 0x09]:
        var c = Http3Connection()
        c.feed_uni_stream_chunk(2, _control_prefix())
        var frame = List[UInt8]()
        frame.append(UInt8(t))
        frame.append(0)  # empty payload
        try:
            c.feed_uni_stream_chunk(2, frame^)
            accepted += hex(t) + " "
        except:
            pass
    if accepted != "":
        print(
            (
                "BUG REPRODUCED: control stream accepted forbidden frame types"
                " (no H3_FRAME_UNEXPECTED):"
            ),
            accepted,
        )
        raise Error("H3-03")
    print("OK: forbidden control-stream frame types rejected")
