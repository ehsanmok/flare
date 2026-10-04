# PLATFORM: any
"""WS-06: WsConnection does not take part in the closing handshake: a
received CLOSE is never answered, an invalid CLOSE payload is not refused
with 1002, and data can still be sent after close().

Lean: Flare.Bugs.WS_06.counterexample_no_echo,
Flare.Bugs.WS_06.counterexample_invalid_payload,
Flare.Bugs.WS_06.counterexample_data_after_close (the shipped endpoint
violates CloseOK) and Flare.L3.Ws.Close.fixed_closeOK (fix meets spec).
flare/ws/server.mojo:514-536 (recv returns CLOSE to the caller without
replying), 600-616 (close() sends CLOSE, keeps no state, does not wait
although its docstring says it does), 473-512 (send_* have no closed
check), 660-671 (the documented handler breaks on CLOSE, so the socket
is closed by __deinit__ with no CLOSE reply) @59bda50. WsClient is not
part of this: its close() writes CLOSE and then closes the transport, so
nothing can follow it.

Expected (RFC 6455 §5.5.1, §7.1.5, §7.4.1): an endpoint that receives a
CLOSE and has not sent one MUST send a CLOSE in response (echoing the
code); a CLOSE payload of 1 byte, a code outside 1000-1003/1007-1014/
3000-4999, or a reason that is not UTF-8 is a protocol error answered
with 1002; after sending a CLOSE an endpoint MUST NOT send data frames.
Actual: the client's CLOSE gets EOF and no CLOSE, a 1-byte CLOSE payload
gets EOF and no 1002, and close() followed by send_text puts a TEXT frame
on the wire after the CLOSE.

Minimal fix: keep a `_close_sent` flag; in recv(), on CLOSE, reply with
CLOSE(code) (or CLOSE(1002) for an invalid payload) unless one was
already sent, and set the flag; set it in close(); make send_* raise
once it is set.
"""

from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.ws import WsConnection, WsOpcode
from flare.ws.server import _handle_ws_connection


def _documented_handler(mut conn: WsConnection) raises -> None:
    # The WsServer docstring example (server.mojo:660-671).
    while True:
        var frame = conn.recv()
        if frame.opcode == WsOpcode.CLOSE:
            break
        conn.send_text(frame.text_payload())


def _close_then_send(mut conn: WsConnection) raises -> None:
    conn.close()
    try:
        conn.send_text("late")
    except:
        pass


def _serve(var lis: TcpListener, which: Int):
    try:
        var s = lis.accept()
        var peer = s.peer_addr()
        if which == 0:
            _handle_ws_connection(s^, peer, _documented_handler)
        else:
            _handle_ws_connection(s^, peer, _close_then_send)
    except:
        pass
    exit()


def _session(which: Int, close_payload: List[UInt8]) raises -> List[UInt8]:
    """Handshake, optionally send a masked CLOSE (zero mask key), return
    every byte the server sent after the 101 head, up to EOF."""
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var pid = fork()
    if pid == 0:
        _serve(lis^, which)
    usleep(100_000)
    var after = List[UInt8]()
    try:
        var s = TcpStream.connect(SocketAddr.localhost(port))
        s.write_all(
            String(
                "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Key:"
                " dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ).as_bytes()
        )
        if which == 0:
            var f = List[UInt8]()
            f.append(0x88)
            f.append(UInt8(0x80 | len(close_payload)))
            for _ in range(4):
                f.append(0)
            for b in close_payload:
                f.append(b)
            s.write_all(Span[UInt8, _](f))
        var got = List[UInt8]()
        var tmp = List[UInt8](capacity=4096)
        tmp.resize(4096, 0)
        while True:
            var n = s.read(tmp.unsafe_ptr(), 4096)
            if n == 0:
                break
            for i in range(n):
                got.append(tmp[i])
        var head_end = -1
        for i in range(3, len(got)):
            if got[i - 3] == 13 and got[i - 2] == 10 and got[i - 1] == 13 and got[i] == 10:
                head_end = i + 1
                break
        if head_end < 0 or len(got) < 12 or got[9] != 49 or got[10] != 48 or got[11] != 49:
            raise Error("no 101 from the server")
        for i in range(head_end, len(got)):
            after.append(got[i])
        s.close()
    except e:
        _ = kill(pid, SIGKILL)
        waitpid(pid)
        print("inconclusive: " + String(e))
        raise Error("inconclusive")
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    return after^


def _frames(b: List[UInt8]) -> String:
    """Opcode list of unmasked server frames (payload < 126 bytes)."""
    var out = String("")
    var i = 0
    while i + 1 < len(b):
        var op = Int(b[i] & 0x0F)
        var n = Int(b[i + 1] & 0x7F)
        var desc = "op=" + String(op)
        if op == 8 and n >= 2 and i + 3 < len(b):
            desc += " code=" + String(Int(b[i + 2]) * 256 + Int(b[i + 3]))
        out += "[" + desc + "]"
        i += 2 + n
    return out


def main() raises:
    var valid = List[UInt8]()
    valid.append(0x03)
    valid.append(0xE8)  # 1000
    var r1 = _frames(_session(0, valid))
    var one = List[UInt8]()
    one.append(0x03)
    var r2 = _frames(_session(0, one))
    var r3 = _frames(_session(1, List[UInt8]()))
    print("client CLOSE 1000 -> server sent:", r1 if r1 != "" else "(nothing)")
    print("client CLOSE 1-byte payload -> server sent:", r2 if r2 != "" else "(nothing)")
    print("close() then send_text -> server sent:", r3)
    var no_echo = not r1.startswith("[op=8")
    var no_1002 = not r2.startswith("[op=8 code=1002]")
    var late = "[op=8" in r3 and "[op=1]" in r3
    if no_echo or no_1002 or late:
        print(
            "BUG REPRODUCED: closing handshake violated (echo missing: "
            + String(no_echo) + "; 1002 missing: " + String(no_1002)
            + "; data after CLOSE: " + String(late) + ")"
        )
        raise Error("WS-06")
    print("OK: CLOSE echoed, invalid payload answered with 1002, no data after CLOSE")
