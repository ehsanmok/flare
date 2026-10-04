# PLATFORM: any (kqueue or epoll, level-triggered writability)
"""APP-47: an h2c upgrade whose 101 response finishes on a writable edge is
never migrated; the connection spins on writability forever.

Lean: Flare.L4.ConnExt.H2c.route (model of the reactor's H1 dispatch),
Flare.Bugs.APP_47.violates_spec (counterexample) and
Flare.Bugs.APP_47.fixed_meets_spec (fix meets spec).
flare/http/_unified_reactor_impl.mojo:243-258 @59bda50 (`_drive_h1_writable`
applies the StepResult of on_writable and ignores `h2c_upgrade`);
flare/http/_unified_reactor_impl.mojo:812-855 (a writable edge on a
KIND_H1 connection goes to `_drive_h1_writable`); only `_drive_h1`
(:174-215) migrates. flare/http/_reactor/conn_handle.mojo:1353-1362
(`on_writable` reports `h2c_upgrade=True` with want_read = want_write =
False after the 101 has flushed, and keeps reporting it on every later
call because `_h2c_upgrade_pending` stays set).

RFC 7540 sec 3.2: after the 101, the server's first bytes are its HTTP/2
connection preface (a SETTINGS frame), and the request that carried the
upgrade is answered as stream 1.

Scenario: the server's send buffer is full when the upgrade request is
handled (here filled directly; in production, a large earlier response the
client has not read yet), so the inline `on_writable` in `_drive_h1` gets
EAGAIN and the connection is armed for writability. When the client drains,
the writable edge flushes the 101 through `_drive_h1_writable`.

Expected: the connection migrates to KIND_H2 and the server sends its
SETTINGS frame after the 101.
Actual: the connection stays KIND_H1; `_apply_step` sees no interest bits,
so the old write interest stays armed and every poll returns another
writable edge that re-reports the upgrade; no SETTINGS frame is ever sent
and the stream-1 request is never answered.

Determinism: both socket buffers are pinned small (SO_SNDBUF on the server
side, SO_RCVBUF on the client), which turns off kernel autotuning, and an
attempt counts only if the 101 is still queued in the handle after the
first event (otherwise the inline write flushed it and the writable-edge
path was never exercised). Up to five attempts; none valid is inconclusive.

Minimal fix: route a writable edge to `_drive_h1` (which migrates) when the
handle has an upgrade pending, as is already done for TLS cross-interest:
`if is_readable or (tls_cross and is_writable) or h1_ptr[]._h2c_upgrade_pending:`.
"""

from std.collections import Dict
from std.ffi import c_int, c_size_t

from flare.http import Request, Response, ServerConfig
from flare.http.handler import FnHandler
from flare.http2.server import Http2Config
from flare.http._reactor.tagged_dispatch import KIND_H1, KIND_H2, _pack, _kind, _addr
from flare.http._server_reactor_epoll import _conn_alloc_addr
from flare.http._unified_reactor_impl import (
    _unified_handle_conn_event,
    _conn_ptr_from_int,
)
from flare.net import SocketAddr
from flare.net._libc import _send
from flare.runtime import Reactor, TimerWheel, Event, INTEREST_READ
from flare.runtime._libc_time import libc_nanosleep_ms
from flare.tcp import TcpListener, TcpStream


def _ok(req: Request) raises -> Response:
    return Response(status=200)


struct Attempt(Copyable, Movable):
    var valid: Bool
    var kind_after: Int
    var writable_edges: Int
    var after: Int

    def __init__(
        out self, valid: Bool, kind_after: Int, writable_edges: Int, after: Int
    ):
        self.valid = valid
        self.kind_after = kind_after
        self.writable_edges = writable_edges
        self.after = after


def _attempt() raises -> Attempt:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    client._socket.set_recv_buffer(16384)
    var accepted = listener.accept()
    accepted._socket.set_send_buffer(16384)
    accepted._socket.set_nonblocking(True)
    var fd = Int(accepted._socket.fd)

    var reactor = Reactor()
    reactor.register(c_int(fd), UInt64(fd), INTEREST_READ)
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()
    var wheel = TimerWheel(now_ms=UInt64(0))
    conns[fd] = _pack(KIND_H1, _conn_alloc_addr(accepted^))
    _conn_ptr_from_int(_addr(conns[fd]))[].h2c_upgrade_allowed = True
    var handler = FnHandler(_ok)
    var config = ServerConfig()
    var h2 = Http2Config()

    var req = String(
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\n"
        "Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
    )
    client.write_all(req.as_bytes())
    _ = libc_nanosleep_ms(50)
    # Fill the server-to-client direction until the kernel refuses more,
    # and keep refilling until a pass after a pause sends nothing (loopback
    # ACKs free send-buffer space after the first EAGAIN).
    var junk = List[UInt8](length=65536, fill=UInt8(120))
    var filled = 0
    for _ in range(50):
        var sent = 0
        var size = 65536
        while size > 0:
            var n = _send(
                c_int(fd), junk.unsafe_ptr(), c_size_t(size), c_int(0)
            )
            if n > 0:
                sent += Int(n)
            else:
                size = size // 2
        filled += sent
        if sent == 0 and filled > 0:
            break
        _ = libc_nanosleep_ms(20)
    _unified_handle_conn_event[FnHandler](
        fd, conns[fd], True, False, handler, config, h2, conns, reactor, wheel, timers
    )
    # Precondition: the 101 is still queued behind the backlog.
    if fd not in conns or _kind(conns[fd]) != KIND_H1:
        return Attempt(False, -1, 0, 0)
    ref ch = _conn_ptr_from_int(_addr(conns[fd]))[]
    if len(ch.write_buf) <= ch.write_pos:
        return Attempt(False, -1, 0, 0)

    # The client drains the backlog; the socket becomes writable.
    client.set_recv_timeout(2000)
    var buf = List[UInt8](length=65536, fill=UInt8(0))
    var got = 0
    while got < filled:
        var want = min(len(buf), filled - got)
        var n = client.read(buf.unsafe_ptr(), want)
        if n <= 0:
            break
        got += n
    _ = libc_nanosleep_ms(50)

    # Deliver real reactor events for a few polls.
    var writable_edges = 0
    var events = List[Event]()
    for _ in range(5):
        _ = reactor.poll(100, events)
        for i in range(len(events)):
            var ev = events[i]
            if Int(ev.token) != fd or fd not in conns:
                continue
            if ev.is_writable():
                writable_edges += 1
            _unified_handle_conn_event[FnHandler](
                fd,
                conns[fd],
                ev.is_readable(),
                ev.is_writable(),
                handler,
                config,
                h2,
                conns,
                reactor,
                wheel,
                timers,
            )

    var kind_after = -1
    if fd in conns:
        kind_after = _kind(conns[fd])

    # What the client sees after the backlog: the 101, then (if migrated)
    # the server's SETTINGS frame.
    client.set_recv_timeout(300)
    var after = 0
    for _ in range(64):
        var n: Int
        try:
            n = client.read(buf.unsafe_ptr(), len(buf))
        except:
            break
        if n <= 0:
            break
        after += n
    return Attempt(True, kind_after, writable_edges, after)


def main() raises:
    for _ in range(5):
        var a = _attempt()
        if not a.valid:
            continue
        if a.kind_after == KIND_H1:
            print(
                "BUG REPRODUCED: 101 flushed on a writable edge but the"
                + " connection was never migrated: still KIND_H1 after 5"
                + " polls, "
                + String(a.writable_edges)
                + " writable edges delivered, client received "
                + String(a.after)
                + " bytes after the backlog (101 is 71 bytes; no SETTINGS"
                + " frame)"
            )
            raise Error("APP-47")
        print(
            "OK: connection migrated (kind "
            + String(a.kind_after)
            + "), client received "
            + String(a.after)
            + " bytes after the backlog (101 + SETTINGS)"
        )
        return
    print("inconclusive: the 101 never stayed queued behind the backlog")
    raise Error("APP-47 inconclusive")
