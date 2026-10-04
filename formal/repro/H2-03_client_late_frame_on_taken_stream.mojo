# PLATFORM: any
"""H2-03: the HTTP/2 client tears the connection down with
GOAWAY(PROTOCOL_ERROR) when a WINDOW_UPDATE or RST_STREAM arrives for a
stream whose response it has already taken.

Lean: Flare.Bugs.H2_03.bug (counterexample) and Flare.Bugs.H2_03.fixed.
flare/http2/state.mojo:1099 and 1238 @59bda50, with
flare/http2/client.mojo:1021 (take_response pops the stream). On the
client, last_peer_stream_id stays 0 (it is only advanced for server-role
HEADERS, state.mojo:1120-1126), so every client stream that has left
conn.streams looks "idle".

RFC 9113 sec 6.9: "WINDOW_UPDATE can be sent by a peer that has sent a
frame with the END_STREAM flag set. This means that a receiver could
receive a WINDOW_UPDATE frame on a "half-closed (remote)" or "closed"
stream. A receiver MUST NOT treat this as an error." sec 8.1 lets a server
send RST_STREAM(NO_ERROR) after a complete response; sec 5.1 makes
RST_STREAM on a closed stream legal to receive.

Trace: GET on stream 1 against flare's own server; the response is
complete; take_response(1) pops the stream; then the server's
WINDOW_UPDATE(stream 1) arrives in a later read. Second connection: same,
then RST_STREAM(stream 1, NO_ERROR).

Expected: both frames are ignored. Actual: both draw GOAWAY(PROTOCOL_ERROR)
and kill every other stream on the connection.

Minimal fix: track the highest client-initiated stream id (or treat an
unknown odd id at or below it as closed) and use it, not
last_peer_stream_id, for the idle test in client role.
"""

from flare.http import Response
from flare.http2 import (
    HpackHeader,
    Http2ClientConnection,
    Http2Connection,
    parse_frame,
)


def _shuttle(
    mut client: Http2ClientConnection, mut server: Http2Connection
) raises:
    for _ in range(64):
        var progress = False
        var c_out = client.drain()
        if len(c_out) > 0:
            server.feed(Span[UInt8, _](c_out))
            progress = True
        var s_out = server.drain()
        if len(s_out) > 0:
            client.feed(Span[UInt8, _](s_out))
            progress = True
        if not progress:
            return
    raise Error("shuttle did not settle")


def _frame(ty: UInt8, sid: Int, payload: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    var n = len(payload)
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    out.append(ty)
    out.append(0)
    out.append(UInt8((sid >> 24) & 0x7F))
    out.append(UInt8((sid >> 16) & 0xFF))
    out.append(UInt8((sid >> 8) & 0xFF))
    out.append(UInt8(sid & 0xFF))
    for b in payload:
        out.append(b)
    return out^


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


def _late_frame_code(ty: UInt8, payload: List[UInt8]) raises -> Int:
    """Complete one GET, take the response, then feed one late frame."""
    var client = Http2ClientConnection()
    var server = Http2Connection()
    _shuttle(client, server)
    var sid = client.next_stream_id()
    var empty = List[UInt8]()
    client.send_request(
        sid, "GET", "http", "example.com", "/", List[HpackHeader](), Span(empty)
    )
    _shuttle(client, server)
    _ = server.take_request(sid)
    var resp = Response(status=200)
    resp.body = List[UInt8](String("ok").as_bytes())
    server.emit_response(sid, resp^)
    _shuttle(client, server)
    if not client.response_ready(sid):
        raise Error("setup: response not ready")
    var got = client.take_response(sid)
    if got.status != 200:
        raise Error("setup: bad status")
    _ = client.drain()
    client.feed(Span[UInt8, _](_frame(ty, sid, payload)))
    return _goaway_code(client.drain())


def main() raises:
    var wu: List[UInt8] = [UInt8(0), UInt8(0), UInt8(0), UInt8(100)]
    var rst: List[UInt8] = [UInt8(0), UInt8(0), UInt8(0), UInt8(0)]  # NO_ERROR
    var wu_code = _late_frame_code(0x8, wu)
    var rst_code = _late_frame_code(0x3, rst)
    if wu_code >= 0 or rst_code >= 0:
        print(
            "BUG REPRODUCED: after take_response(1), a late WINDOW_UPDATE"
            " drew GOAWAY code",
            wu_code,
            "and a late RST_STREAM(NO_ERROR) drew GOAWAY code",
            rst_code,
            "(1 = PROTOCOL_ERROR; -1 = none)",
        )
        raise Error("H2-03")
    print("OK: late WINDOW_UPDATE and RST_STREAM on a taken stream ignored")
