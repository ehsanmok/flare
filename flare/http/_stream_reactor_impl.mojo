"""Single-threaded reactor loop for the typed streaming surface (A2/A4).

``run_stream_reactor_loop`` is the multi-connection driver behind
``HttpServer.serve_streaming``. It owns the reactor and the connection
table; it dispatches the four ``StreamHandler`` lifecycle callbacks on
the right edges and owns the outbound drain (EPOLLOUT re-arm) so a
front never blocks the event loop.

Connection state lives in a ``Dict[Int, StreamConn]`` keyed by client
fd, accessed by mutable ``ref`` -- no heap-address-as-``Int`` smuggling
(``StreamConn`` is non-copyable and stays put in the dict). A connection
may also attach one upstream fd (``StreamConn.attach_upstream``); the
reactor registers it for read, routes its readiness through
``up_to_client`` to fire ``on_upstream`` on the owning connection, and
unregisters it on teardown. The reactor token for a connection is its
client fd; an attached upstream fd is its own token; the listener fd is
its own token. A token routes by membership: listener, then
``up_to_client`` (upstream), then ``conns`` (client).

Scope (A2/A4): the outbound streaming path -- accept, ``on_open``,
``on_writable``-driven chunking with backpressure-correct draining, and
upstream pumping via ``on_upstream`` -- plus peer-FIN / error teardown
via ``on_close``. The front owns the upstream fd's lifetime (open in
``on_open``, close in ``on_close``); the reactor only watches it.
Inbound request-body consumption is B5.

Backpressure (B2): a connection's attached upstream fd is read only
while its client relay buffer is below the high watermark. ``_reconcile_after``
calls ``StreamConn.apply_backpressure`` (hi/lo hysteresis) and toggles the
upstream's ``INTEREST_READ`` accordingly, so a slow client throttles the
upstream instead of forcing unbounded token buffering. The buffer is
bounded by the high watermark plus at most one upstream read; a relay
front should also check ``conn.write_buffer_full()`` in its drain loop to
avoid overshooting within a single readable edge.

ponytail: while a connection is open and not closing, ``INTEREST_WRITE``
stays armed, so a front *without an upstream* that stalls without
producing or closing still busy-spins on level-triggered writable edges.
The upstream-relay shape (the inference-front case) is fully gated by the
B1 park + B2 watermark; the residual spin is the no-upstream stalled
front, expected to produce on every writable edge until ``request_close``.
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
    mut up_to_client: Dict[Int, Int],
    fd: Int,
    mut handler: H,
):
    """Tear one connection down: unregister the client fd (and any
    attached upstream fd), fire ``on_close``, drop (which closes the
    client socket). Never raises -- teardown is best-effort.
    """
    if fd not in conns:
        return
    try:
        var conn = conns.pop(fd)
        if fd in interests:
            _ = interests.pop(fd)
        var ufd = conn.reg_upstream_fd()
        if ufd != -1:
            try:
                reactor.unregister(c_int(ufd))
            except:
                pass
            if ufd in up_to_client:
                _ = up_to_client.pop(ufd)
        try:
            reactor.unregister(c_int(fd))
        except:
            pass
        try:
            handler.on_close(conn)
        except:
            pass
        # ``conn`` drops here -> client socket closed. The upstream fd
        # is the front's to close (it owns the upstream stream).
    except:
        pass


def _reconcile_after(
    mut reactor: Reactor,
    mut conns: Dict[Int, StreamConn],
    mut interests: Dict[Int, Int],
    mut up_to_client: Dict[Int, Int],
    fd: Int,
) raises:
    """After a lifecycle callback, reconcile the connection's upstream
    registration (the front may have called ``attach_upstream`` /
    ``detach_upstream``) and re-arm its client write interest.

    Diffs desired (``upstream_fd``) against registered
    (``reg_upstream_fd``) so a no-op call costs only two lookups.
    """
    ref c = conns[fd]
    # Upstream reconcile (fd attach/detach) + B2 backpressure gating: the
    # upstream read interest is armed only while the client relay buffer
    # is below the high watermark, so a slow client throttles the upstream
    # instead of forcing unbounded token buffering.
    var want = c.upstream_fd()
    var have = c.reg_upstream_fd()
    if want != have:
        if have != -1:
            try:
                reactor.unregister(c_int(have))
            except:
                pass
            if have in up_to_client:
                _ = up_to_client.pop(have)
        if want != -1:
            var up_int = INTEREST_READ if c.apply_backpressure() else 0
            try:
                reactor.register(c_int(want), UInt64(want), up_int)
                up_to_client[want] = fd
            except:
                pass
            c._set_reg_upstream_interest(up_int)
        else:
            c._set_reg_upstream_interest(-1)
        c._set_reg_upstream_fd(want)
    elif want != -1:
        # Same upstream fd: toggle its read interest across watermarks.
        var up_int = INTEREST_READ if c.apply_backpressure() else 0
        if up_int != c.reg_upstream_interest():
            try:
                reactor.modify(c_int(want), up_int)
                c._set_reg_upstream_interest(up_int)
            except:
                pass
    # Client write-interest reconcile.
    var desired = _desired_interest(c)
    if interests[fd] != desired:
        try:
            reactor.modify(c_int(fd), desired)
            interests[fd] = desired
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
    # Maps an attached upstream fd -> its owning client fd, so an
    # upstream readiness event routes to the right connection.
    var up_to_client = Dict[Int, Int]()
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
                    # Pick up any upstream the front attached in on_open.
                    _reconcile_after(
                        reactor, conns, interests, up_to_client, cfd
                    )
                continue

            # ── Upstream readiness: pump via on_upstream ───────────
            if tok in up_to_client:
                var client_fd = up_to_client[tok]
                if client_fd not in conns:
                    try:
                        reactor.unregister(c_int(tok))
                    except:
                        pass
                    _ = up_to_client.pop(tok)
                    continue
                var up_drop = False
                ref uc = conns[client_fd]
                try:
                    handler.on_upstream(uc)
                    _ = uc.drain_nonblocking()
                except:
                    up_drop = True
                if not up_drop:
                    if (
                        conns[client_fd].is_closing()
                        and not conns[client_fd].has_pending_out()
                    ):
                        up_drop = True
                if up_drop:
                    _close_conn(
                        reactor,
                        conns,
                        interests,
                        up_to_client,
                        client_fd,
                        handler,
                    )
                else:
                    _reconcile_after(
                        reactor, conns, interests, up_to_client, client_fd
                    )
                continue

            if tok not in conns:
                continue

            # ── Peer error / hangup: tear down ─────────────────────
            if ev.is_error() or ev.is_hup():
                conns[tok].flip_cancel(CancelReason.PEER_CLOSED)
                _close_conn(
                    reactor, conns, interests, up_to_client, tok, handler
                )
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
                _close_conn(
                    reactor, conns, interests, up_to_client, tok, handler
                )
                continue

            # Reconcile upstream registration + re-arm write interest.
            _reconcile_after(reactor, conns, interests, up_to_client, tok)

    # Drain remaining connections on shutdown. ``conns`` keys are the
    # client fds; the upstream entries in ``up_to_client`` are cleaned up
    # by ``_close_conn`` as each owning connection is torn down.
    var live = List[Int]()
    for fd_key in interests.keys():
        live.append(fd_key)
    for fd_key in live:
        _close_conn(reactor, conns, interests, up_to_client, fd_key, handler)
