# PLATFORM: any
# RESOLVED: HPACK-01 fixed on fix/formal-findings
"""HPACK-01: non-UTF-8 header octets are stored lossily, so flare's HPACK
dynamic table counts more bytes than the peer's and evicts entries the
peer still references.

Lean: Flare.Bugs.HPACK_01.bug (counterexample) and
Flare.Bugs.HPACK_01.fixed (byte-exact storage keeps the tables in sync).
flare/http2/hpack.mojo:49-63 (_octets_to_string) and 287-316
(_entry_size / _insert) @59bda50.

RFC 7541 sec 4.1: an entry's size is the length of its name and value in
octets plus 32, and the decoder must evict exactly as the encoder does.
RFC 9113 sec 8.2.1 allows any octet in a field value except NUL, CR, LF,
so a value made of 0xFF octets is legal.

Trace (default 4096-byte table). Stream 1: a GET whose block inserts
"x-1: <500 x 'a'>" (535 bytes) and then "x-2: <1300 x 0xFF>" (1335 bytes)
with incremental indexing. The peer's table holds both (1870 <= 4096).
flare turns each 0xFF into U+FFFD (EF BF BD), stores a 3900-byte value,
counts the entry as 3935 bytes and evicts "x-1". Stream 3: a GET that
references index 63, which is "x-1" for the peer.

Expected: stream 3 decodes with "x-1: aaa...". Before the fix: index 63 is out of
range for flare's table, and the connection is torn down with
GOAWAY(COMPRESSION_ERROR). The stored value of "x-2" is also mangled
(3900 bytes instead of 1300).

Minimal fix: keep header octets byte-exact (_octets_to_string returns
String(unsafe_from_utf8=b)), or account the table in raw octet lengths.
"""

from flare.http2.frame import Frame, FrameFlags, FrameType
from flare.http2.state import Connection


def _int(mut out: List[UInt8], value: Int, prefix_bits: Int, high: UInt8):
    var maxp = (1 << prefix_bits) - 1
    if value < maxp:
        out.append(high | UInt8(value))
        return
    out.append(high | UInt8(maxp))
    var v = value - maxp
    while v >= 128:
        out.append(UInt8(0x80 | (v & 0x7F)))
        v >>= 7
    out.append(UInt8(v))


def _str(mut out: List[UInt8], s: List[UInt8]):
    _int(out, len(s), 7, UInt8(0))  # H=0
    for b in s:
        out.append(b)


def _ascii(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _headers(sid: Int, var block: List[UInt8]) -> Frame:
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.header.stream_id = sid
    f.header.length = len(block)
    f.payload = block^
    return f^


def _goaway_code(frames: List[Frame]) -> Int:
    for f in frames:
        if f.header.type.value == FrameType.GOAWAY().value:
            return (
                (Int(f.payload[4]) << 24)
                | (Int(f.payload[5]) << 16)
                | (Int(f.payload[6]) << 8)
                | Int(f.payload[7])
            )
    return -1


def main() raises:
    var c = Connection()

    # Stream 1: :method GET, :scheme http, :path /, then two inserts.
    var b1 = List[UInt8]()
    b1.append(0x82)
    b1.append(0x86)
    b1.append(0x84)
    var v1 = List[UInt8]()
    for _ in range(500):
        v1.append(UInt8(ord("a")))
    b1.append(0x40)  # literal with incremental indexing, new name
    _str(b1, _ascii("x-1"))
    _str(b1, v1)
    var v2 = List[UInt8]()
    for _ in range(1300):
        v2.append(0xFF)
    b1.append(0x40)
    _str(b1, _ascii("x-2"))
    _str(b1, v2)
    var r1 = c.handle_frame(_headers(1, b1^))
    if _goaway_code(r1) >= 0:
        raise Error("setup: stream 1 rejected with GOAWAY")
    var stored = -1
    if 1 in c.streams:
        var s1 = c.streams[1].copy()
        for h in s1.headers:
            if h.name == "x-2":
                stored = h.value.byte_length()

    # Reference model of the peer's table (RFC 7541 sec 4): newest first,
    # sizes in raw octets. Index 62 = x-2, index 63 = x-1, total 1870.
    var peer_size = (3 + 500 + 32) + (3 + 1300 + 32)
    if peer_size > 4096:
        raise Error("setup: reference table would evict")

    # Stream 3: GET referencing dynamic index 63 (0x80 | 63).
    var b3 = List[UInt8]()
    b3.append(0x82)
    b3.append(0x86)
    b3.append(0x84)
    b3.append(UInt8(0x80 | 63))
    var r3 = c.handle_frame(_headers(3, b3^))
    var code = _goaway_code(r3)
    var got_x1 = False
    if 3 in c.streams:
        var s3 = c.streams[3].copy()
        for h in s3.headers:
            if h.name == "x-1" and h.value.byte_length() == 500:
                got_x1 = True
    if code >= 0 or not got_x1:
        print(
            "BUG REPRODUCED: index 63 should be x-1 (peer table 1870/4096"
            " bytes) but flare answered GOAWAY code",
            code,
            "(9 = COMPRESSION_ERROR); stored x-2 value is",
            stored,
            "bytes, the peer sent 1300",
        )
        raise Error("HPACK-01")
    print(
        "OK: stream 3 decoded x-1 from dynamic index 63; x-2 stored as",
        stored,
        "bytes",
    )
