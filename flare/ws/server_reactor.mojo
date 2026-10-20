"""Event-driven WebSocket handlers for HTTP/1.1 upgrades on the reactor.

``WsUpgrade.on_reactor(handler)`` keeps an upgraded connection on the
reactor worker that accepted it: the worker reads it without blocking,
runs the RFC 6455 rules in :class:`flare.ws.protocol.WsProtocol`, and
calls the handler once per event. No thread is spawned per connection,
and a client that stops reading is cut off at the session's outbox
bound instead of growing memory.

Each connection gets its own copy of the handler, made from the one the
server was configured with, so per-connection state can live on
``self``; the copy is destroyed when the connection ends.
"""

from .client import WsMessage
from .frame import DEFAULT_MAX_FRAME_BYTES, WsCloseCode
from .protocol import DEFAULT_MAX_OUTBOX_BYTES, WsProtocol
from ..net import SocketAddr
from ..runtime.pool import Pool


struct WsSession(Movable):
    """One upgraded connection as a handler sees it."""

    var proto: WsProtocol
    var peer: SocketAddr
    var origin: String
    """The handshake's ``Origin`` (the last one if repeated), or ``""``."""

    def __init__(
        out self,
        peer: SocketAddr,
        var origin: String,
        max_message: Int,
        max_outbox: Int,
    ):
        self.proto = WsProtocol(max_message, max_outbox)
        self.peer = peer
        self.origin = origin^

    def send_text(mut self, msg: String) raises:
        """Queue a TEXT message. Raises after a CLOSE, and when the peer
        is too far behind (the session then closes with 1008)."""
        self.proto.send_text(msg)

    def send_binary(mut self, data: List[UInt8]) raises:
        """Queue a BINARY message; raises as :meth:`send_text` does."""
        self.proto.send_binary(data)

    def close(mut self, code: UInt16 = WsCloseCode.NORMAL):
        """Start the closing handshake."""
        self.proto.close(code)


trait WsReactorHandler(Copyable, Deinitable):
    """Edge-driven handler for HTTP/1.1 WebSocket connections."""

    def on_open(mut self, mut ws: WsSession) raises -> None:
        """Called once, right after the upgrade."""
        ...

    def on_message(
        mut self, mut ws: WsSession, var msg: WsMessage
    ) raises -> None:
        """Called per complete message (fragments already reassembled,
        text already validated as UTF-8)."""
        ...

    def on_close(mut self, mut ws: WsSession, code: Int) -> None:
        """Called once when the connection ends, whichever side ended it:
        the code from the closing handshake, or 1006 when the connection
        dropped without one."""
        ...


comptime _OpenThunk = def(Int, mut WsSession) raises thin -> None
comptime _MsgThunk = def(Int, mut WsSession, var WsMessage) raises thin -> None
comptime _CloseThunk = def(Int, mut WsSession, Int) thin -> None
comptime _DestroyThunk = def(Int) thin -> None
comptime _CloneThunk = def(Int) raises thin -> Int


def _open_thunk[W: WsReactorHandler](addr: Int, mut ws: WsSession) raises:
    Pool[W].get_ptr(addr)[].on_open(ws)


def _msg_thunk[
    W: WsReactorHandler
](addr: Int, mut ws: WsSession, var msg: WsMessage) raises:
    Pool[W].get_ptr(addr)[].on_message(ws, msg^)


def _close_thunk[W: WsReactorHandler](addr: Int, mut ws: WsSession, code: Int):
    Pool[W].get_ptr(addr)[].on_close(ws, code)


def _destroy_thunk[W: WsReactorHandler](addr: Int):
    Pool[W].free(addr)


def _clone_thunk[W: WsReactorHandler](addr: Int) raises -> Int:
    return Pool[W].alloc_move(Pool[W].get_ptr(addr)[].copy())


struct WsReactorHooks(Copyable):
    """A boxed handler prototype and its monomorphised thunks.

    The prototype is never called; each connection gets a clone
    (:meth:`clone_handler`) and destroys it on teardown. The prototype
    lives as long as the server configuration that holds it.
    """

    var addr: Int
    var open_thunk: _OpenThunk
    var msg_thunk: _MsgThunk
    var close_thunk: _CloseThunk
    var destroy_thunk: _DestroyThunk
    var clone_thunk: _CloneThunk
    var max_message: Int
    var max_outbox: Int
    var idle_timeout_ms: Int

    def __init__(
        out self,
        addr: Int,
        open_thunk: _OpenThunk,
        msg_thunk: _MsgThunk,
        close_thunk: _CloseThunk,
        destroy_thunk: _DestroyThunk,
        clone_thunk: _CloneThunk,
        max_message: Int,
        max_outbox: Int,
        idle_timeout_ms: Int,
    ):
        self.addr = addr
        self.open_thunk = open_thunk
        self.msg_thunk = msg_thunk
        self.close_thunk = close_thunk
        self.destroy_thunk = destroy_thunk
        self.clone_thunk = clone_thunk
        self.max_message = max_message
        self.max_outbox = max_outbox
        self.idle_timeout_ms = idle_timeout_ms

    def clone_handler(self) raises -> Int:
        return self.clone_thunk(self.addr)


def make_ws_reactor_hooks[
    W: WsReactorHandler
](
    var handler: W,
    max_message: Int = DEFAULT_MAX_FRAME_BYTES,
    max_outbox: Int = DEFAULT_MAX_OUTBOX_BYTES,
    idle_timeout_ms: Int = 60_000,
) raises -> WsReactorHooks:
    """Box ``handler`` as the prototype for every connection's copy."""
    return WsReactorHooks(
        addr=Pool[W].alloc_move(handler^),
        open_thunk=_open_thunk[W],
        msg_thunk=_msg_thunk[W],
        close_thunk=_close_thunk[W],
        destroy_thunk=_destroy_thunk[W],
        clone_thunk=_clone_thunk[W],
        max_message=max_message,
        max_outbox=max_outbox,
        idle_timeout_ms=idle_timeout_ms,
    )
