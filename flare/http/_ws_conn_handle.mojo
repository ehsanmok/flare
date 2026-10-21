"""Reactor handle for an HTTP/1.1 connection upgraded to WebSocket.

The unified reactor migrates a ``KIND_H1`` connection here once its 101
has flushed. The handle owns the socket and a
:class:`flare.ws.server_reactor.WsSession`: readable edges append to the
session's inbox and run it to completion of whatever events the bytes
make, writable edges drain its outbox. The handler copy it owns is told
about the end of the connection exactly once, whichever path ends it --
closing handshake, protocol violation, peer drop, idle timeout, or server
drain -- because :func:`_ws_conn_free_addr` does it before freeing.
"""

from std.collections import Dict
from std.ffi import ErrNo, c_int, c_size_t, get_errno
from std.memory import Pointer

from flare.net import RawSocket, SocketAddr
from flare.net._libc import AF_INET, MSG_NOSIGNAL, SOCK_STREAM, _recv, _send
from flare.runtime import INTEREST_READ, INTEREST_WRITE, Reactor, TimerWheel
from flare.runtime.pool import Pool
from flare.tcp import TcpStream
from flare.ws.client import WsMessage
from flare.ws.frame import WsCloseCode
from flare.ws.protocol import WS_EVENT_MESSAGE
from flare.ws.server_reactor import WsReactorHooks, WsSession

from ._reactor.keepalive_scan import StepResult
from ._reactor.lifecycle import _conn_free_addr, _conn_ptr_from_int
from ._reactor.tagged_dispatch import KIND_WS, _addr, _pack

comptime _READ_CHUNK: Int = 16 * 1024
comptime _READ_PER_EDGE: Int = 256 * 1024
"""Bytes one readable edge takes from a connection before yielding."""


struct WsConnHandle(Movable):
    var _stream: TcpStream
    var session: WsSession
    var hooks: WsReactorHooks
    var handler_addr: Int
    var close_code: Int
    """Code the session ended with; 1006 until a closing handshake or a
    violation sets one."""
    var notified: Bool
    var peer_gone: Bool
    var last_interest: Int
    var armed_at_ms: UInt64
    """When the idle timer was last scheduled (wheel time)."""

    def __init__(
        out self,
        var stream: TcpStream,
        peer: SocketAddr,
        var prebuf: List[UInt8],
        var origin: String,
        hooks: WsReactorHooks,
    ) raises:
        self._stream = stream^
        self.session = WsSession(
            peer, origin^, hooks.max_message, hooks.max_outbox
        )
        self.session.proto.inbox = prebuf^
        self.hooks = hooks.copy()
        self.handler_addr = hooks.clone_handler()
        self.close_code = Int(WsCloseCode.ABNORMAL)
        self.notified = False
        self.peer_gone = False
        self.last_interest = INTEREST_READ
        self.armed_at_ms = 0

    def fd(self) -> c_int:
        return self._stream._socket.fd

    def start(mut self) -> StepResult:
        """Run ``on_open``, then whatever frames came with the handshake."""
        try:
            self.hooks.open_thunk(self.handler_addr, self.session)
        except:
            self._fail_handler()
        return self._pump()

    def _fail_handler(mut self):
        """A handler that raised ends the session with 1011."""
        self.session.proto.close(WsCloseCode.INTERNAL_ERROR)
        self.close_code = Int(WsCloseCode.INTERNAL_ERROR)

    def on_readable(mut self) -> StepResult:
        var taken = 0
        var fd = self.fd()
        while taken < _READ_PER_EDGE and self.session.proto.wants_input():
            ref inbox = self.session.proto.inbox
            var have = len(inbox)
            inbox.resize(unsafe_uninit_length=have + _READ_CHUNK)
            var got = _recv(
                fd,
                inbox.unsafe_ptr().unsafe_offset(have),
                c_size_t(_READ_CHUNK),
                c_int(0),
            )
            # Only what recv wrote stays in the buffer.
            inbox.resize(unsafe_uninit_length=have + max(Int(got), 0))
            if got > 0:
                taken += Int(got)
                if Int(got) < _READ_CHUNK:
                    break
                continue
            if got == 0:
                self.peer_gone = True
                break
            var e = get_errno()
            if e == ErrNo.EINTR:
                continue
            if e != ErrNo.EAGAIN and e != ErrNo.EWOULDBLOCK:
                self.peer_gone = True
            break
        return self._pump()

    def on_writable(mut self) -> StepResult:
        return self._step()

    def _pump(mut self) -> StepResult:
        while True:
            var next = self.session.proto.next_event()
            if not next:
                break
            var ev = next.take()
            if ev.kind != WS_EVENT_MESSAGE:
                self.close_code = ev.code
                break
            var msg = WsMessage(
                String(unsafe_from_utf8=ev.payload)
            ) if ev.is_text else WsMessage(ev.payload^)
            try:
                self.hooks.msg_thunk(self.handler_addr, self.session, msg^)
            except:
                self._fail_handler()
                break
        return self._step()

    def _flush(mut self) -> Bool:
        """Send what the socket takes; False on a hard send error."""
        ref out = self.session.proto.outbox
        var fd = self.fd()
        var sent = 0
        while sent < len(out):
            var n = _send(
                fd,
                out.unsafe_ptr().unsafe_offset(sent),
                c_size_t(len(out) - sent),
                c_int(MSG_NOSIGNAL),
            )
            if n > 0:
                sent += Int(n)
                continue
            var e = get_errno()
            if e == ErrNo.EINTR:
                continue
            if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                break
            self.session.proto.consumed(sent)
            return False
        self.session.proto.consumed(sent)
        return True

    def _step(mut self) -> StepResult:
        if not self._flush():
            return StepResult(done=True)
        ref proto = self.session.proto
        var pending = len(proto.outbox) > 0
        var over = proto.close_sent or proto.finished()
        if self.peer_gone or (over and not pending):
            return StepResult(done=True)
        # Re-armed on every step, closing or not: a peer that neither
        # sends nor drains what it was sent is dropped once it expires.
        return StepResult(
            want_read=proto.wants_input() and not over,
            want_write=pending,
            idle_timeout_ms=self.hooks.idle_timeout_ms,
        )

    def teardown(mut self):
        """Tell the handler the connection ended and drop its copy."""
        if self.notified:
            return
        self.notified = True
        self.hooks.close_thunk(self.handler_addr, self.session, self.close_code)
        self.hooks.destroy_thunk(self.handler_addr)


def _ws_conn_alloc_addr(var h: WsConnHandle) raises -> Int:
    return Pool[WsConnHandle].alloc_move(h^)


def _ws_conn_ptr_from_int(
    addr: Int,
) -> Pointer[WsConnHandle, MutUntrackedOrigin]:
    return Pool[WsConnHandle].get_ptr(addr)


def _ws_conn_free_addr(addr: Int):
    if addr == 0:
        return
    _ws_conn_ptr_from_int(addr)[].teardown()
    Pool[WsConnHandle].free(addr)


def _apply_step_ws(
    fd: Int,
    step: StepResult,
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
    h: Pointer[WsConnHandle, MutUntrackedOrigin],
) raises:
    var interest: Int = 0
    if step.want_read:
        interest |= INTEREST_READ
    if step.want_write:
        interest |= INTEREST_WRITE
    if interest != 0 and interest != h[].last_interest:
        try:
            reactor.modify(c_int(fd), interest)
            h[].last_interest = interest
        except:
            pass
    if step.idle_timeout_ms > 0:
        # Re-armed only once the deadline has moved by an eighth of the
        # timeout (at most a second): the timer never fires later than
        # the timeout after the last activity, at most that much
        # earlier, and a busy connection no longer cancels and
        # schedules a timer per message.
        var now = wheel.now_ms()
        var slack = UInt64(min(step.idle_timeout_ms // 8, 1000))
        var old = timers.get(fd)
        if old and now - h[].armed_at_ms <= slack:
            return
        if old:
            _ = wheel.cancel(old.value())
        timers[fd] = wheel.schedule(step.idle_timeout_ms, UInt64(fd))
        h[].armed_at_ms = now


def _drive_ws(
    fd: Int,
    addr: Int,
    is_readable: Bool,
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
) -> Bool:
    """One reactor event for a WebSocket connection; True when done."""
    var h = _ws_conn_ptr_from_int(addr)
    var step: StepResult
    if is_readable:
        step = h[].on_readable()
    else:
        step = h[].on_writable()
    if not step.done:
        try:
            _apply_step_ws(fd, step, reactor, wheel, timers, h)
        except:
            return True
    return step.done


def _migrate_h1_to_ws(
    fd: Int,
    hooks: WsReactorHooks,
    mut conns: Dict[Int, Int],
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
) raises -> Bool:
    """Swap ``conns[fd]`` from the h1 handle that sent the 101 to a
    ``WsConnHandle`` and run its first step. True when the connection is
    already done (the caller cleans up, or found it gone)."""
    if fd not in conns:
        return True
    var h1_addr = _addr(conns[fd])
    var h1 = _conn_ptr_from_int(h1_addr)
    var prebuf = List[UInt8]()
    var origin = String("")
    h1[].take_ws_upgrade(prebuf, origin)
    var peer = h1[].peer
    var inherited = h1[]._stream._socket.fd
    h1[]._stream._socket.fd = c_int(-1)
    _conn_free_addr(h1_addr)
    _ = conns.pop(fd)
    var raw = RawSocket(inherited, AF_INET, SOCK_STREAM, _wrap=True)
    var ws = WsConnHandle(TcpStream(raw^, peer), peer, prebuf^, origin^, hooks)
    var addr = _ws_conn_alloc_addr(ws^)
    conns[fd] = _pack(KIND_WS, addr)
    var h = _ws_conn_ptr_from_int(addr)
    var step = h[].start()
    if step.done:
        return True
    _apply_step_ws(fd, step, reactor, wheel, timers, h)
    return False
