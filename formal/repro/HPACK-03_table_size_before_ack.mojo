# PLATFORM: any
# RESOLVED: HPACK-03 fixed on fix/formal-findings
"""HPACK-03: a reduced SETTINGS_HEADER_TABLE_SIZE is applied to flare's
HPACK decoder before the peer has acknowledged it.

Lean: Flare.Bugs.HPACK_03.bug (counterexample) and
Flare.Bugs.HPACK_03.fixed (keeping the 4096 default until the peer's size
update keeps the tables in sync).
flare/http2/server.mojo:200-203 @59bda50 (same pattern in
flare/http2/client.mojo:291-294).

RFC 7541 sec 4.2: a change of the maximum table size is signalled by a
dynamic table size update, which "MUST occur at the beginning of the first
header block following the change to the dynamic table size. In HTTP/2,
this follows a settings acknowledgment." Until then the peer's encoder
still works with the default 4096-byte table. A client may send requests
right after its preface, before it has even seen the server's SETTINGS.

Trace: Http2Config with header_table_size = 0. In one read the client
sends preface, SETTINGS, a GET on stream 1 that inserts "x-a: b" with
incremental indexing, and a GET on stream 3 that references index 62.

Expected: stream 3 decodes with "x-a: b". Before the fix: flare's decoder runs at
max_size 0 from construction, the insert empties the table, and index 62
draws GOAWAY(COMPRESSION_ERROR).

Minimal fix: keep the decoder at the larger of the advertised size and
4096 until the peer's first dynamic table size update (or until the
SETTINGS ACK is followed by that update), and only then shrink.
"""

from flare.http2 import Http2Config, Http2Connection, H2_PREFACE, parse_frame


def _frame(
    mut out: List[UInt8], ty: UInt8, flags: UInt8, sid: Int, payload: List[UInt8]
):
    var n = len(payload)
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    out.append(ty)
    out.append(flags)
    out.append(UInt8((sid >> 24) & 0x7F))
    out.append(UInt8((sid >> 16) & 0xFF))
    out.append(UInt8((sid >> 8) & 0xFF))
    out.append(UInt8(sid & 0xFF))
    for b in payload:
        out.append(b)


def _goaway_code(bytes: List[UInt8]) raises -> Int:
    var off = 0
    while off < len(bytes):
        var got = parse_frame(Span[UInt8, _](bytes)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if f.header.type.value == 7:
            return (
                (Int(f.payload[4]) << 24)
                | (Int(f.payload[5]) << 16)
                | (Int(f.payload[6]) << 8)
                | Int(f.payload[7])
            )
    return -1


def main() raises:
    var cfg = Http2Config()
    cfg.header_table_size = 0
    var srv = Http2Connection.with_config(cfg^)

    var wire = List[UInt8]()
    for b in String(H2_PREFACE).as_bytes():
        wire.append(b)
    _frame(wire, 0x4, 0x0, 0, List[UInt8]())  # client SETTINGS (empty)
    # Stream 1: GET http / plus "x-a: b" with incremental indexing.
    var b1 = List[UInt8]()
    b1.append(0x82)
    b1.append(0x86)
    b1.append(0x84)
    b1.append(0x40)
    b1.append(0x03)
    b1.append(UInt8(ord("x")))
    b1.append(UInt8(ord("-")))
    b1.append(UInt8(ord("a")))
    b1.append(0x01)
    b1.append(UInt8(ord("b")))
    _frame(wire, 0x1, 0x5, 1, b1)  # END_STREAM | END_HEADERS
    # Stream 3: GET http / plus dynamic index 62 (0x80 | 62).
    var b3 = List[UInt8]()
    b3.append(0x82)
    b3.append(0x86)
    b3.append(0x84)
    b3.append(UInt8(0x80 | 62))
    _frame(wire, 0x1, 0x5, 3, b3)
    srv.feed(Span[UInt8, _](wire))

    var out = srv.drain()
    var code = _goaway_code(out)
    var got = False
    if 3 in srv.conn.streams:
        var s3 = srv.conn.streams[3].copy()
        for h in s3.headers:
            if h.name == "x-a" and h.value == "b":
                got = True
    if code >= 0 or not got:
        print(
            "BUG REPRODUCED: index 62 sent before the SETTINGS ACK should be"
            " x-a: b (peer table still 4096) but flare answered GOAWAY code",
            code,
            "(9 = COMPRESSION_ERROR)",
        )
        raise Error("HPACK-03")
    print("OK: stream 3 decoded x-a: b from index 62 before the ACK")
