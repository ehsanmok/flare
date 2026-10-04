# PLATFORM: any
"""H2-05: the server's content-length parser wraps on overflow and ignores
a second, different content-length.

Lean: Flare.Bugs.H2_05.bug (counterexample, Int64 wrap) and
Flare.Bugs.H2_05.fixed.
flare/http2/state.mojo:749-765 (_declared_content_length) @59bda50:
`acc = acc * 10 + (c - 48)` in 64-bit Int with no overflow check, and the
loop returns the first content-length field it finds.

RFC 9113 sec 8.1.1: "A request or response is also malformed if the value
of a content-length header field does not equal the sum of the DATA frame
payload lengths"; malformed requests are a stream error PROTOCOL_ERROR.
RFC 9110 sec 8.6: content-length is a decimal number of octets; a list of
differing values is invalid. flare's own client path
(state.mojo:904-928) already rejects both overflow and disagreeing
duplicates.

Trace A: POST on stream 1 with content-length 18446744073709551621
(2^64 + 5), then DATA "hello" with END_STREAM. The parser yields 5.
Trace B: POST on stream 3 with content-length 5 and content-length 10,
then DATA "hello" with END_STREAM.

Expected: RST_STREAM(PROTOCOL_ERROR) on both. Actual: both are accepted as
complete requests (data_complete, no RST).

Minimal fix: reject (treat as malformed) a content-length whose value
overflows, and one that disagrees with an earlier content-length.
"""

from flare.http2.frame import Frame, FrameFlags, FrameType
from flare.http2.state import Connection


def _post_with_cl(sid: Int, values: List[String]) -> Frame:
    var b = List[UInt8]()
    b.append(0x83)  # :method POST
    b.append(0x86)  # :scheme http
    b.append(0x84)  # :path /
    for v in values:
        # Literal without indexing, name = static index 28
        # (content-length): 4-bit prefix 15, then 13.
        b.append(0x0F)
        b.append(0x0D)
        b.append(UInt8(v.byte_length()))
        for c in v.as_bytes():
            b.append(c)
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    f.header.stream_id = sid
    f.header.length = len(b)
    f.payload = b^
    return f^


def _data(sid: Int) -> Frame:
    var f = Frame()
    f.header.type = FrameType.DATA()
    f.header.flags = FrameFlags(FrameFlags.END_STREAM())
    f.header.stream_id = sid
    for c in String("hello").as_bytes():
        f.payload.append(c)
    f.header.length = len(f.payload)
    return f^


def _accepted(mut c: Connection, sid: Int, var values: List[String]) raises -> Bool:
    var rst = False
    for f in c.handle_frame(_post_with_cl(sid, values)):
        if f.header.type.value == FrameType.RST_STREAM().value:
            rst = True
    if not rst:
        for f in c.handle_frame(_data(sid)):
            if f.header.type.value == FrameType.RST_STREAM().value:
                rst = True
    if rst or sid not in c.streams:
        return False
    return c.streams[sid].copy().data_complete


def main() raises:
    var c = Connection()
    var a = _accepted(c, 1, [String("18446744073709551621")])
    var b = _accepted(c, 3, [String("5"), String("10")])
    if a or b:
        print(
            "BUG REPRODUCED: 5-byte body accepted as complete with"
            " content-length 2^64+5:",
            a,
            "; with content-length 5 and 10:",
            b,
        )
        raise Error("H2-05")
    print("OK: both malformed content-length requests were reset")
