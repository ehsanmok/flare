# PLATFORM: any
# RESOLVED: H2-11 fixed on fix/formal-findings
"""H2-11: SETTINGS_MAX_CONCURRENT_STREAMS = 0 is advertised but enforced as
"unlimited".

Lean: Flare.Bugs.H2_11.bug (counterexample) and Flare.Bugs.H2_11.fixed.
flare/http2/state.mojo:497 (advertises the value) and 1291-1298 @59bda50:
    and self.max_concurrent_streams > 0
    and self._active_stream_count() >= self.max_concurrent_streams
Http2Config.validate accepts max_concurrent_streams >= 0.

RFC 9113 sec 6.5.2: "A value of 0 for SETTINGS_MAX_CONCURRENT_STREAMS
SHOULD NOT be treated as special by endpoints. A zero value does prevent
the creation of new streams". sec 5.1.2: "An endpoint that receives a
HEADERS frame that causes its advertised concurrent stream limit to be
exceeded MUST treat this as a stream error (Section 5.4.2) of type
PROTOCOL_ERROR or REFUSED_STREAM."

Trace: Http2Config with max_concurrent_streams = 0; the server's initial
SETTINGS carries (0x3, 0); a valid GET HEADERS arrives on stream 1.

Expected: RST_STREAM(REFUSED_STREAM). Before the fix: the request is accepted and
becomes ready for dispatch.

Minimal fix: drop the `self.max_concurrent_streams > 0 and` conjunct.
"""

from flare.http2 import Http2Config, Http2Connection
from flare.http2.frame import Frame, FrameFlags, FrameType


def main() raises:
    var cfg = Http2Config()
    cfg.max_concurrent_streams = 0
    var srv = Http2Connection.with_config(cfg^)
    var s = srv.conn.initial_settings()
    var advertised = -1
    var i = 0
    while i + 6 <= len(s.payload):
        var id = (Int(s.payload[i]) << 8) | Int(s.payload[i + 1])
        if id == 0x3:
            advertised = (
                (Int(s.payload[i + 2]) << 24)
                | (Int(s.payload[i + 3]) << 16)
                | (Int(s.payload[i + 4]) << 8)
                | Int(s.payload[i + 5])
            )
        i += 6
    if advertised != 0:
        raise Error("setup: SETTINGS_MAX_CONCURRENT_STREAMS=0 not advertised")
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.header.stream_id = 1
    f.payload = [UInt8(0x82), UInt8(0x86), UInt8(0x84)]
    f.header.length = 3
    var refused = False
    for g in srv.conn.handle_frame(f^):
        if g.header.type.value == FrameType.RST_STREAM().value and Int(g.payload[3]) == 7:
            refused = True
    if not refused:
        var ids = srv.take_completed_streams()
        print(
            "BUG REPRODUCED: SETTINGS_MAX_CONCURRENT_STREAMS = 0 advertised,"
            " yet HEADERS on stream 1 was accepted (no REFUSED_STREAM);"
            " completed streams ready for dispatch:",
            len(ids),
        )
        raise Error("H2-11")
    print("OK: stream 1 refused with RST_STREAM(REFUSED_STREAM) under limit 0")
