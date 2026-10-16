"""Difftest driver: HTTP/2 connection state machine (flare.http2.state).

Targets (input layout as in formal/Oracle/H2.lean):
  h2_conn.frames  records [type, flags, sid, len, payload(len)] until the
                  input runs out (a short last record is dropped); each is
                  fed to a fresh server-role Connection() via handle_frame,
                  stopping after the first raise ("X") or GOAWAY. Output:
                  each frame's queued frames ("|"-separated), ";", then
                  sid=<state>/<send_window>/<recv_window> for every nonzero
                  sid in the trace (ascending, "-" if not in the table),
                  ";", then the connection send/recv windows

Run: pixi run mojo -I . formal/difftest/drivers/dt_h2.mojo IN OUT
"""

from std.sys import argv

from flare.http2 import Connection, Frame, FrameFlags, FrameType

from _dtio import be_take, read_cases, write_lines


def _word(f: Frame, off: Int) -> Int:
    var w = List[UInt8]()
    for i in range(off, off + 4):
        w.append(f.payload[i])
    return Int(be_take(4, w)) & 0x7FFFFFFF


def _tok(f: Frame) -> String:
    var t = Int(f.header.type.value)
    var sid = f.header.stream_id
    if t == 7:
        return "G" + String(_word(f, 0)) + "," + String(_word(f, 4))
    if t == 3:
        return "R" + String(sid) + "," + String(_word(f, 0))
    if t == 8:
        return "W" + String(sid) + "," + String(_word(f, 0))
    if t == 4 and f.header.flags.has(FrameFlags.ACK()):
        return "S"
    if t == 6 and f.header.flags.has(FrameFlags.ACK()):
        return "P"
    if t == 0:
        return "D" + String(sid) + "," + String(len(f.payload))
    return "?" + String(t)


def _state(v: Int) -> String:
    var t = ["i", "o", "l", "r", "c"]
    return t[v] if 0 <= v < 5 else "?"


def _frames(data: List[UInt8]) raises -> String:
    var frames = List[Frame]()
    var sids = List[Int]()
    var i = 0
    while i + 4 <= len(data):
        var n = Int(data[i + 3])
        if i + 4 + n > len(data):
            break
        var f = Frame()
        f.header.type = FrameType(data[i])
        f.header.flags = FrameFlags(data[i + 1])
        f.header.stream_id = Int(data[i + 2])
        f.header.length = n
        for j in range(n):
            f.payload.append(data[i + 4 + j])
        i += 4 + n
        var sid = f.header.stream_id
        if sid != 0 and sid not in sids:
            sids.append(sid)
        frames.append(f^)
    var conn = Connection()
    var toks = List[String]()
    for fi in range(len(frames)):
        var out: List[Frame]
        try:
            out = conn.handle_frame(frames[fi].copy())
        except:
            toks.append("X")
            break
        var tok = String("")
        var goaway = False
        for k in range(len(out)):
            if k > 0:
                tok += " "
            tok += _tok(out[k])
            if Int(out[k].header.type.value) == 7:
                goaway = True
        toks.append(tok)
        if goaway:
            break
    sort(sids)
    var st = List[String]()
    for k in sids:
        if k in conn.streams:
            var s = conn.streams[k]
            st.append(
                String(k)
                + "="
                + _state(s.state.value)
                + "/"
                + String(s.send_window)
                + "/"
                + String(s.recv_window)
            )
        else:
            st.append(String(k) + "=-")
    return (
        "OK:"
        + "|".join(toks)
        + ";"
        + " ".join(st)
        + ";"
        + String(conn.send_window)
        + "/"
        + String(conn.recv_window)
    )


def main() raises:
    var args = argv()
    var lines = List[String]()
    for c in read_cases(String(args[1])):
        if c.target == "h2_conn.frames":
            lines.append(_frames(c.data))
        else:
            lines.append("BAD:unknown target " + c.target)
    write_lines(String(args[2]), lines)
