"""Single-threaded reactor loop for the typed streaming surface (A2).

``run_stream_reactor_loop`` is the multi-connection driver behind
``HttpServer.serve_streaming``. It owns the reactor and the connection
table; it dispatches the four ``StreamHandler`` lifecycle callbacks on
the right edges and owns the outbound drain (EPOLLOUT re-arm) so a
front never blocks the event loop.

Connection state lives in a ``Dict[Int, StreamConn]`` keyed by client
fd, accessed by mutable ``ref`` -- no heap-address-as-``Int`` smuggling
(``StreamConn`` is non-copyable and stays put in the dict). The reactor
token for a connection is its fd; the listener fd is its own token, and
a token is a connection iff it is a key in ``conns``.

Scope (A2): the outbound streaming path -- accept, ``on_open``, and
``on_writable``-driven chunking with backpressure-correct draining, plus
peer-FIN / error teardown via ``on_close``. ``on_upstream`` is wired to a
real upstream fd in A4/B1; inbound request-body consumption is B5.

ponytail: while a connection is open and not closing, ``INTEREST_WRITE``
stays armed, so a front that stalls without producing or closing will
busy-spin on level-triggered writable edges. That is the exact ceiling
B1/B2 lift (park on the upstream fd + hi/lo watermark deregistration);
until then a streaming front is expected to produce on every writable
edge until it calls ``request_close``.
"""

from std.collections import Dict
from std.ffi import c_int

from flare.runtime import Reactor, Event, INTEREST_READ, INTEREST_WRITE
from flare.tcp import TcpListener, TcpStream, accept_fd

from .cancel import CancelReason
from .streaming_server import StreamConn, StreamHandler


@always_inline
def _desired_interest(conn: StreamConn) -> Int:
    """Interest bits for an open connection: always READ (to see peer
    FIN); WRITE while there is pending output or the stream is still
    live (producing)."""
    var interest = INTEREST_READ
    if conn.has_pending_out() or not conn.is_closing():
        interest |= INTEREST_WRITE
    return interest


def _close_conn[
    H: StreamHandler
](
    mut reactor: Reactor,
    mut conns: Dict[Int, StreamConn],
    mut interests: Dict[Int, Int],
    fd: Int,
    mut handler: H,
):
    """Tear one connection down: unregister, fire ``on_close``, drop
    (which closes the socket). Never raises -- teardown is best-effort.
    """
    if fd not in conns:
        return
    try:
        var conn = conns.pop(fd)
        if fd in interests:
            _ = interests.pop(fd)
        try:
            reactor.unregister(c_int(fd))
        except:
            pass
        try:
            handler.on_close(conn)
        except:
            pass
        # ``conn`` drops here -> client socket closed.
    except:
        pass


def run_stream_reactor_loop[
    H: StreamHandler
](
    mut listener: TcpListener,
    mut handler: H,
    ref stopping: Bool,
    poll_timeout_ms: Int = 100,
) raises:
    """Run the streaming reactor loop until ``stopping`` flips.

    Args:
        listener: Bound, listening ``TcpListener``. Borrowed for accept;
            the caller retains ownership.
        handler: The streaming front (typed shared state). One instance
            services every connection via ``mut self``.
        stopping: External stop flag, checked each iteration.
        poll_timeout_ms: Reactor poll timeout; bounds how often
            ``stopping`` is re-checked when idle.
    """
    listener._socket.set_nonblocking(True)
    var listen_fd = Int(listener._socket.fd)

    var reactor = Reactor()
    reactor.register(c_int(listen_fd), UInt64(listen_fd), INTEREST_READ)

    var conns = Dict[Int, StreamConn]()
    var interests = Dict[Int, Int]()
    var next_id = 1
    var events = List[Event]()

    while not stopping:
        var n = reactor.poll(poll_timeout_ms, events)
        for i in range(n):
            var ev = events[i]
            if ev.is_wakeup():
                continue
            var tok = Int(ev.token)

            # ── Listener: drain the accept queue ───────────────────
            if tok == listen_fd:
                while True:
                    var client: TcpStream
                    try:
                        client = accept_fd(c_int(listen_fd))
                    except:
                        break  # EAGAIN / no more pending this round
                    try:
                        client._socket.set_nonblocking(True)
                    except:
                        pass
                    var cfd = Int(client._socket.fd)
                    var id = next_id
                    next_id += 1
                    var conn = StreamConn(client^, id)
                    var open_ok = True
                    try:
                        handler.on_open(conn)
                        _ = conn.drain_nonblocking()
                    except:
                        open_ok = False
                    if not open_ok or (
                        conn.is_closing() and not conn.has_pending_out()
                    ):
                        try:
                            handler.on_close(conn)
                        except:
                            pass
                        continue  # conn drops -> socket closed
                    var interest = _desired_interest(conn)
                    try:
                        reactor.register(c_int(cfd), UInt64(cfd), interest)
                    except:
                        try:
                            handler.on_close(conn)
                        except:
                            pass
                        continue
                    interests[cfd] = interest
                    conns[cfd] = conn^
                continue

            if tok not in conns:
                continue

            # ── Peer error / hangup: tear down ─────────────────────
            if ev.is_error() or ev.is_hup():
                conns[tok].flip_cancel(CancelReason.PEER_CLOSED)
                _close_conn(reactor, conns, interests, tok, handler)
                continue

            var drop_it = False

            # ── Readable: detect peer FIN (inbound body is B5) ─────
            if ev.is_readable():
                var got: Int
                ref c = conns[tok]
                try:
                    var scratch = List[UInt8]()
                    got = c.recv(scratch, 4096)
                except:
                    got = 0
                if got == 0:
                    conns[tok].flip_cancel(CancelReason.PEER_CLOSED)
                    drop_it = True

            # ── Writable: pump next chunk, drain, decide teardown ──
            if not drop_it and ev.is_writable():
                ref c = conns[tok]
                try:
                    handler.on_writable(c)
                    _ = c.drain_nonblocking()
                except:
                    drop_it = True
                if not drop_it:
                    if (
                        conns[tok].is_closing()
                        and not conns[tok].has_pending_out()
                    ):
                        drop_it = True

            if drop_it:
                _close_conn(reactor, conns, interests, tok, handler)
                continue

            # Re-arm interest only when it actually changed.
            var want = _desired_interest(conns[tok])
            if interests[tok] != want:
                try:
                    reactor.modify(c_int(tok), want)
                    interests[tok] = want
                except:
                    _close_conn(reactor, conns, interests, tok, handler)

    # Drain remaining connections on shutdown (interests keys mirror
    # conns keys; interests is copyable so it is safe to iterate).
    var live = List[Int]()
    for fd_key in interests.keys():
        live.append(fd_key)
    for fd_key in live:
        _close_conn(reactor, conns, interests, fd_key, handler)
