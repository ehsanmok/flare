"""HTTP/1.1 server with buffered reads, keep-alive, and per-connection handler callbacks.

Key performance characteristics:
- Reads from the socket in chunks (configurable, default 8KB) instead of byte-at-a-time.
- Scans for the header terminator (CRLFCRLF) in the buffer before parsing.
- Supports HTTP/1.1 keep-alive (reuses connections for multiple requests).
- Serialises the full response into a single buffer for one write_all call.
- Sets recv/send timeouts on accepted sockets for DoS resilience.
- Respects HTTP/1.0 close-by-default semantics.
"""

# TODO(2026-08-31, track-http-server): this module is dominated by the
# single ``HttpServer`` struct (the public serve/serve_static/serve_view
# surface). Mojo cannot split one struct's methods across files, so the
# file stays over the 1000-line bar until the blocking serve loops here
# are reworked into the reactor-backed path and this struct shrinks to a
# thin facade. Allowlisted in tools/check_reactor_size.sh until then.

from std.memory import memcpy, stack_allocation
from std.ffi import c_int, c_uint, external_call

from json import dumps, Value as JsonValue

from ..runtime._libc_time import libc_nanosleep_ms

from std.collections import Optional

from .handler import Handler, CancelHandler
from .streaming_server import StreamHandler
from .intern import intern_method_bytes
from .request import Request, Method
from .response import Response, Status
from .headers import HeaderMap
from .proto.ascii import ascii_unchecked_string, ascii_eq_ignore_case
from .static_response import StaticResponse
from ._server.config import (
    ServerConfig,
    _DEFAULT_SERVER_CONFIG,
    _resolve_bufring_handler_env,
)
from .alpn_dispatch import (
    ALPN_HTTP_1_1,
    ALPN_HTTP_2,
    ALPN_HTTP_3,
    WireProtocol,
    dispatch_alpn,
)
from ..http2.server import Http2Config
from ..net import IpAddr, SocketAddr, NetworkError, BrokenPipe, Timeout
from ..tcp import TcpListener, TcpStream
from ..quic.server import QuicListener, QuicServerConfig


# ── ShutdownReport ───────────────────────────────────────────────────────────
#
# The canonical type lives in :mod:`flare.runtime.scheduler` (a runtime
# primitive: it represents the result of joining N pthread workers).
# Re-exported here so the public ``flare.http.ShutdownReport`` surface
# is unchanged for users who imported it from the HTTP module.

from flare.runtime.scheduler import ShutdownReport


# ── HttpServer ────────────────────────────────────────────────────────────────


struct HttpServer(Movable):
    """A blocking HTTP/1.1 server with buffered reads and keep-alive support.

    Each accepted connection is handled in the calling thread.
    Reads are buffered (default 8KB chunks) for efficient I/O.
    HTTP/1.1 keep-alive is enabled by default.
    Recv/send timeouts are set on accepted sockets to prevent DoS.

    This type is ``Movable`` but not ``Copyable``.

    Example:
        ```mojo
        def handle(req: Request) raises -> Response:
            return Response(Status.OK, body="hello".as_bytes())

        var srv = HttpServer.bind(SocketAddr.localhost(8080))
        srv.serve(handle)
        ```
    """

    var _listener: TcpListener
    var _extra_listener_fds: List[Int]
    """Raw fds of additional listeners attached via
    :meth:`bind_many`. Empty when constructed via the single-
    address :meth:`bind` (the default; preserves the original
    single-listener behaviour byte-for-byte).

    These fds are owned by the ``HttpServer`` -- they're closed
    via libc ``close(2)`` in ``HttpServer.__del__`` (see
    :meth:`_close_extras`). Stored as raw fds rather than
    ``TcpListener`` because ``TcpListener`` is not ``Copyable``
    and ``List[T]`` requires ``Copyable``; the multi-listener
    accept loop only needs the fd anyway (it routes through
    ``_accept_loop_unified_fd``). The original
    :class:`SocketAddr` per fd is kept in
    :attr:`_extra_local_addrs` for diagnostics and the
    :meth:`local_addrs` accessor."""
    var _extra_local_addrs: List[SocketAddr]
    """Local addresses for the extras in :attr:`_extra_listener_fds`,
    in the same order. Lets ``local_addrs()`` enumerate every
    bound address without an extra ``getsockname(2)`` syscall."""
    var config: ServerConfig
    var h2_config: Http2Config
    """HTTP/2 SETTINGS the server advertises to peers that speak h2.

    The unified reactor loop auto-dispatches every accepted
    connection to either an HTTP/1.1 ``ConnHandle`` or an
    HTTP/2 ``H2ConnHandle`` based on the first 24 bytes
    (RFC 9113 §3.4 client connection preface). The h2 path
    uses these SETTINGS verbatim. Defaulted to
    :class:`Http2Config()` -- the same production-shape numbers
    the standalone HTTP/2 driver used. Tune via
    ``HttpServer.bind(addr, config, h2_config=Http2Config(...))``.
    """
    var _stopping: Bool
    """Set by ``close()`` to break the reactor loop. Read from the loop
    itself each iteration."""
    var _h3_listener: Optional[QuicListener]
    """Optional HTTP/3 UDP listener.

    ``None`` (the default) when the server was constructed via
    :meth:`bind` or :meth:`bind_many` (TCP-only flows). Set to a
    fully-bound :class:`flare.quic.server.QuicListener` when the
    server was constructed via :meth:`bind_with_h3`; the listener
    owns its UDP socket fd, its per-listener timer wheel, and the
    QUIC connection slab. The reactor drains inbound datagrams,
    dispatches them through :class:`flare.h3.H3Connection`, and
    drains outbound at every reactor tick. The per-listener
    :meth:`tick_h3_once` entry point lets unit tests advance the
    listener's timer wheel without spinning up the full reactor.
    """

    def __init__(
        out self,
        var listener: TcpListener,
        var config: ServerConfig = ServerConfig(),
        var h2_config: Http2Config = Http2Config(),
    ):
        self._listener = listener^
        self._extra_listener_fds = List[Int]()
        self._extra_local_addrs = List[SocketAddr]()
        self.config = config^
        self.h2_config = h2_config^
        self._stopping = False
        self._h3_listener = None

    def __del__(deinit self):
        self._listener.close()
        self._close_extras()
        # The Optional[QuicListener] field's destructor closes
        # the UDP fd + tears down the QUIC connection slab + the
        # timer wheel via QuicListener.__del__. No-op when no h3
        # listener is bound.
        _ = self._h3_listener^

    def _close_extras(mut self):
        """Close every fd in :attr:`_extra_listener_fds` via
        libc ``close(2)``. Safe to call from ``__del__``; idempotent
        because cleared after closing.
        """
        for i in range(len(self._extra_listener_fds)):
            var fd = self._extra_listener_fds[i]
            if fd >= 0:
                _ = external_call["close", Int32](Int32(fd))
        self._extra_listener_fds.clear()
        self._extra_local_addrs.clear()

    @staticmethod
    def bind(
        addr: SocketAddr,
        var config: ServerConfig = ServerConfig(),
        var h2_config: Http2Config = Http2Config(),
    ) raises -> HttpServer:
        """Bind an HTTP server on ``addr``.

        Args:
            addr: Local address to listen on.
            config: HTTP/1.1 server configuration (optional).
            h2_config: HTTP/2 SETTINGS the server advertises to
                peers that speak h2 (optional). The unified
                reactor loop auto-dispatches every accepted
                connection to either the HTTP/1.1 or HTTP/2
                state machine based on the RFC 9113 §3.4
                client connection preface; ``h2_config`` is
                only consulted when a peer is detected as h2.

        Returns:
            An ``HttpServer`` ready to call ``serve()``.

        Raises:
            AddressInUse: If the port is already bound.
            NetworkError: For any other OS error.
        """
        var listener = TcpListener.bind(addr)
        return HttpServer(listener^, config^, h2_config^)

    @staticmethod
    def bind_many(
        var addrs: List[SocketAddr],
        var config: ServerConfig = ServerConfig(),
        var h2_config: Http2Config = Http2Config(),
    ) raises -> HttpServer:
        """Bind an HTTP server on multiple addresses simultaneously.

        Each address gets its own ``TcpListener`` fd; the unified
        reactor loop accepts on all of them and dispatches each
        accepted connection through the same handler. Useful for
        binding the same service on both IPv4 and IPv6, on
        multiple ports for split traffic classes (e.g. internal
        admin port + public service port), or on a UNIX socket
        plus a TCP socket sharing one process (after the upcoming
        ``UdsListener`` integration).

        ``addrs`` must be non-empty. The first address is the
        "primary" listener (used by ``local_addr()`` and any
        legacy single-listener call site); the remainder become
        extras. All addresses bind in order before any returns,
        so a partial-bind failure leaves no half-bound state
        (already-bound listeners are dropped + closed by the
        ``TcpListener.__del__``).

        Multi-listener mode is **single-worker only** today.
        ``HttpServer.serve(handler, num_workers=N)`` with
        ``N >= 2`` raises when extras are present; the
        ``SO_REUSEPORT`` multi-worker path is N-fds-on-one-
        address and is orthogonal. A cross-product
        N-listeners x M-workers shape is a future addition;
        today the right multi-worker path stays through
        ``bind`` + ``num_workers``.

        Args:
            addrs: One or more local addresses to listen on.
                Order matters: ``addrs[0]`` is the primary.
            config: HTTP/1.1 server configuration (optional).
            h2_config: HTTP/2 SETTINGS for h2 peers (optional).

        Returns:
            An ``HttpServer`` whose ``serve()`` accepts on every
            listener concurrently.

        Raises:
            Error: If ``addrs`` is empty.
            AddressInUse: If any port is already bound.
            NetworkError: For any other OS error.

        Example:

        ```mojo
        var srv = HttpServer.bind_many(
            [SocketAddr.localhost(8080), SocketAddr.localhost(8081)],
        )
        srv.serve(handler)
        ```
        """
        from flare.net.socket import INVALID_FD

        if len(addrs) == 0:
            raise Error("HttpServer.bind_many: addrs must be non-empty")
        var primary = TcpListener.bind(addrs[0])
        # Bind extras up-front; if any fails, the partially-bound
        # ``TcpListener`` instances we already moved to ``primary``
        # / consumed in this loop close themselves via __del__.
        var extra_fds = List[Int]()
        var extra_addrs = List[SocketAddr]()
        for i in range(1, len(addrs)):
            var l = TcpListener.bind(addrs[i])
            extra_fds.append(Int(l._socket.fd))
            extra_addrs.append(l._socket.local_addr())
            # Detach the fd from ``l`` so its __del__ doesn't close
            # what HttpServer now owns. RawSocket lacks an explicit
            # ``release_fd()``; setting ``fd = INVALID_FD`` is the
            # equivalent contract used elsewhere (e.g. the move
            # constructor) so the destructor sees "already closed".
            l._socket.fd = INVALID_FD
        var srv = HttpServer(primary^, config^, h2_config^)
        srv._extra_listener_fds = extra_fds^
        srv._extra_local_addrs = extra_addrs^
        return srv^

    def local_addrs(self) -> List[SocketAddr]:
        """Return the bound addresses, primary first then extras
        in the order they were passed to :meth:`bind_many`. Always
        returns at least one entry.
        """
        var out = List[SocketAddr]()
        out.append(self._listener.local_addr())
        for i in range(len(self._extra_local_addrs)):
            out.append(self._extra_local_addrs[i].copy())
        return out^

    @staticmethod
    def bind_with_h3(
        tcp_addr: SocketAddr,
        var udp_cfg: QuicServerConfig,
        var config: ServerConfig = ServerConfig(),
        var h2_config: Http2Config = Http2Config(),
    ) raises -> HttpServer:
        """Bind an HTTP server that speaks h1 / h2c / h2 over TCP
        on ``tcp_addr`` AND h3 over QUIC/UDP on the address in
        ``udp_cfg``.

        The TLS ALPN list advertised by the TCP listener (h2,
        http/1.1) and the QUIC listener (h3 only) is what tells
        peers which wire is reachable on which transport. The
        decision function
        :func:`flare.http.alpn_dispatch.dispatch_alpn` routes the
        negotiated ALPN identifier to the matching driver:

        * ``"h3"`` -> the QUIC listener / :class:`H3Connection`.
        * ``"h2"`` -> the TCP h2 reactor / :class:`H2ConnHandle`.
        * ``"http/1.1"`` / empty -> the TCP h1 reactor /
          :class:`ConnHandle`.
        * h2c upgrade hint -> H2C (TCP path only).

        Calling :meth:`serve` on a server returned by this method
        runs the TCP + UDP reactors side by side; the UDP listener
        is also reachable via :meth:`local_h3_addr` /
        :meth:`tick_h3_once` for tests that want to drive the
        h3 path without spinning up the full reactor. Closing
        the server (via :meth:`close` or ``__del__``) closes
        both listeners.

        Args:
            tcp_addr: Local TCP address for h1 / h2c / h2.
            udp_cfg: :class:`QuicServerConfig` for the h3 UDP
                bind. ``udp_cfg.host`` / ``udp_cfg.port`` apply
                to the QUIC listener; the rest of the config
                (CC choice, idle timeout, ...) is passed
                through.
            config: HTTP/1.1 server configuration (optional).
            h2_config: HTTP/2 SETTINGS the server advertises to
                h2 peers (optional).

        Returns:
            An ``HttpServer`` holding both listeners.

        Raises:
            AddressInUse: If either port is already bound.
            NetworkError: For any other OS error.
        """
        var tcp_listener = TcpListener.bind(tcp_addr)
        var quic_listener = QuicListener.bind(udp_cfg^)
        var srv = HttpServer(tcp_listener^, config^, h2_config^)
        srv._h3_listener = quic_listener^
        return srv^

    def has_h3(self) -> Bool:
        """Whether this server has an h3 UDP listener bound."""
        return self._h3_listener is not None

    def local_h3_addr(self) raises -> SocketAddr:
        """Return the local address of the h3 UDP listener.

        Raises:
            Error: If no h3 listener is bound.
        """
        if not self.has_h3():
            raise Error("HttpServer.local_h3_addr: no h3 listener bound")
        return self._h3_listener.value().local_addr()

    def advertised_alpn_protocols(self) -> List[String]:
        """Return the ALPN identifier list this server expects to
        advertise on its TLS handshakes. The TCP listener
        advertises ``["h2", "http/1.1"]`` and the QUIC listener
        advertises ``["h3"]``; here we surface the union (for
        diagnostics + the ``alpn_dispatch_demo`` example).

        Order matters: server preference is highest -> lowest,
        which :func:`flare.http.alpn_dispatch.negotiate_alpn`
        consumes verbatim.
        """
        var out = List[String]()
        if self.has_h3():
            out.append(ALPN_HTTP_3)
        out.append(ALPN_HTTP_2)
        out.append(ALPN_HTTP_1_1)
        return out^

    def route_alpn(self, alpn: String) raises -> Int:
        """Map a negotiated ALPN identifier to a
        :class:`flare.http.alpn_dispatch.WireProtocol` codepoint,
        cross-checked against which listeners this server has
        bound. ``"h3"`` routes to ``WireProtocol.HTTP_3`` only
        when this server has an h3 listener; otherwise the
        decision raises so the reactor can close the connection
        with ``no_application_protocol``.

        Args:
            alpn: The ALPN identifier returned by the TLS
                handshake (empty string == "no ALPN advertised").

        Returns:
            One of :class:`WireProtocol`.

        Raises:
            Error: If ``alpn == "h3"`` but no h3 listener is
                bound.
        """
        var decision = dispatch_alpn(alpn)
        if decision == WireProtocol.HTTP_3 and not self.has_h3():
            raise Error(
                "HttpServer.route_alpn: peer negotiated 'h3' but no h3 "
                "listener is bound"
            )
        return decision

    def tick_h3_once(mut self, now_ms: UInt64) raises -> Int:
        """Advance the h3 listener's timer wheel one tick. Test-
        only entry point used to validate the bind path; returns
        the number of connections still alive after the sweep.

        Raises:
            Error: If no h3 listener is bound.
        """
        if not self.has_h3():
            raise Error("HttpServer.tick_h3_once: no h3 listener bound")
        var listener = self._h3_listener.take()
        _ = listener.advance_timers(now_ms)
        var count = listener.connection_count()
        self._h3_listener = listener^
        return count

    def pump_h3_handler_once[
        H: Handler & Copyable
    ](mut self, mut handler: H) raises -> Int:
        """Drain every connection's H3 dispatcher once: for each
        completed request stream the handler is invoked with the
        materialized :class:`Request`, the resulting
        :class:`Response` is encoded into the slot's H3 outbox
        via :meth:`QuicListener.emit_h3_response`, and the
        outbound bytes accumulate in the per-(slot, stream_id)
        egress buffer.

        Returns the number of (slot, stream) pairs dispatched
        this pass. Zero when no H3 request is ready. The buffered
        bytes leave the wire via the 1-RTT STREAM egress drain
        once the slot's 1-RTT keys are installed.

        Raises:
            Error: If no h3 listener is bound.
        """
        if not self.has_h3():
            raise Error("HttpServer.pump_h3_handler_once: no h3 listener bound")
        var listener = self._h3_listener.take()
        var dispatched = 0
        for slot in range(listener.connection_count()):
            var ready = listener.take_h3_completed_streams(slot)
            for j in range(len(ready)):
                var stream_id = ready[j]
                var req = listener.take_h3_request(slot, stream_id)
                var resp = handler.serve(req^)
                listener.emit_h3_response(slot, stream_id, resp^)
                dispatched += 1
        self._h3_listener = listener^
        return dispatched

    def serve_h3[H: Handler & Copyable](mut self, var handler: H) raises:
        """Run the QUIC reactor with H3 handler dispatch as a
        single-threaded loop.

        This is the H3-aware blocking entry point: each iteration
        runs :meth:`QuicListener.tick` to drain one inbound UDP
        datagram + drive the QUIC + rustls state machines, then
        :meth:`pump_h3_handler_once` to dispatch any completed
        H3 request streams through ``handler``, then
        :meth:`QuicListener.advance_timers` so PTO + idle +
        ack-delay callbacks fire on time. Exits cleanly once
        the h3 listener's stop flag flips
        (:meth:`QuicListener.shutdown`).

        The serve-loop pairs the TCP unified reactor (the
        canonical :meth:`serve` overloads above) as a peer entry
        point; callers running both wires spawn one OS thread per
        loop.

        Raises:
            Error: If no h3 listener is bound.
            NetworkError: On fatal listener errors;
                per-connection errors close the offending
                connection silently inside ``tick``.
        """
        if not self.has_h3():
            raise Error("HttpServer.serve_h3: no h3 listener bound")
        # Inline: pulled from the leaf _server_support helper module
        # (not flare.quic.server) to avoid loading the QUIC reactor --
        # which imports flare.http -- at flare.http.server import time.
        from flare.quic._server_support import (
            _monotonic_ms as _quic_monotonic_ms,
        )

        var listener = self._h3_listener.take()
        try:
            while not listener._stopping:
                _ = listener.tick(timeout_ms=100)
                var h_copy = handler.copy()
                _ = self._pump_listener_h3[H](listener, h_copy^)
                # Flush H3 responses the handler just queued so they
                # leave on this loop turn rather than waiting for the
                # next inbound datagram to trigger a per-slot drain.
                _ = listener.drain_all_egress()
                var now_ms = _quic_monotonic_ms()
                _ = listener.advance_timers(now_ms)
        except e:
            self._h3_listener = listener^
            raise e^
        self._h3_listener = listener^

    @staticmethod
    def _pump_listener_h3[
        H: Handler & Copyable
    ](mut listener: QuicListener, var handler: H) raises -> Int:
        """Internal helper: drain every connection's H3
        dispatcher once on a borrowed listener. Mirrors
        :meth:`pump_h3_handler_once` but operates on a borrowed
        listener so :meth:`serve_h3` can hold the listener in
        its own loop variable without bouncing through the
        Optional dance every iteration.
        """
        var dispatched = 0
        for slot in range(listener.connection_count()):
            var ready = listener.take_h3_completed_streams(slot)
            for j in range(len(ready)):
                var stream_id = ready[j]
                var req = listener.take_h3_request(slot, stream_id)
                var resp = handler.serve(req^)
                listener.emit_h3_response(slot, stream_id, resp^)
                dispatched += 1
        return dispatched

    def serve(
        mut self,
        handler: def(Request) raises thin -> Response,
        num_workers: Int = 1,
        pin_cores: Bool = True,
    ) raises:
        """Run the reactor loop, calling ``handler`` per request.

        Plain-function overload: pass a ``def(Request) raises -> Response``
        and the server wraps it in a ``FnHandler`` internally. This is
        the -compatible shape; the argument list is extended with
        ``num_workers`` / ``pin_cores`` to match the Handler-typed
        overload below so every user has one entry point to learn.

        - ``num_workers == 1`` (default): single-threaded reactor
          (kqueue on macOS, epoll on Linux). Same hot path as the
          ``serve``.
        - ``num_workers >= 2``: multicore — N ``pthread`` workers
          via ``flare.runtime.scheduler.Scheduler``. By default
          each worker binds its own ``SO_REUSEPORT`` listener
          (the kernel hashes new 4-tuples to one of N listeners;
          matches actix_web's listener strategy and gives the
          highest steady-state throughput). Export
          ``FLARE_REUSEPORT_WORKERS=0`` before launch to switch
          back to the single shared listener with
          ``EPOLLEXCLUSIVE`` (Linux >= 4.5), which trades
          7-22 % req/s (handler vs static fast path) for a
          uniformly tighter p99.99 σ under sustained load; see
          ``docs/benchmark.md``.

        For Router / middleware / stateful-struct handlers, use the
        Handler-typed overload ``serve[H: Handler & Copyable]``.

        Args:
            handler: Called once per parsed request.
            num_workers: Worker count. ``<= 0`` is coerced to 1.
                Values > 256 are rejected (see ``Scheduler.start``).
            pin_cores: On Linux, pin worker N to core ``N % num_cpus``.
                Ignored when ``num_workers == 1``. No-op on macOS.

        Raises:
            NetworkError: On fatal listener errors; per-connection errors
                close the offending connection silently.
            Error: On ``pthread_create`` failure when
                ``num_workers >= 2``.
        """
        from ._server_reactor_impl import run_uring_bufring_reactor_loop
        from ._unified_reactor_impl import run_unified_reactor_loop
        from .handler import FnHandler
        from flare.runtime.uring_reactor import use_uring_backend
        from std.sys.info import CompilationTarget

        from ._unified_reactor_impl import run_unified_reactor_loop_multi

        var h = FnHandler(handler)
        if num_workers <= 1:
            self._stopping = False
            # OPT-IN via FLARE_BUFRING_HANDLER=1 OR
            # ServerConfig.use_bufring=True; the env var is read
            # once at startup and OR-equalled into the field so
            # later dispatch reads only the field.
            if not self.config.use_bufring:
                self.config.use_bufring = _resolve_bufring_handler_env()
            # The bufring path is HTTP/1.1-only by design and
            # crashes under sustained 64-conn wrk2 load -- see
            # the matching comment in the generic ``serve[H]``
            # overload below. Bufring is also single-listener-
            # only; we fall through to the unified loop when
            # extras are attached so multi-listener users get
            # the proper accept demux.
            comptime if CompilationTarget.is_linux():
                if (
                    use_uring_backend()
                    and self.config.use_bufring
                    and len(self._extra_listener_fds) == 0
                ):
                    run_uring_bufring_reactor_loop(
                        self._listener, self.config, h, self._stopping
                    )
                    return
            # Unified reactor loop: every accepted connection is
            # auto-dispatched to either the HTTP/1.1 ConnHandle or
            # the HTTP/2 H2ConnHandle based on whether its first
            # 24 bytes match the RFC 9113 §3.4 client preface.
            if len(self._extra_listener_fds) > 0:
                run_unified_reactor_loop_multi(
                    self._listener,
                    self._extra_listener_fds,
                    self.config,
                    self.h2_config.copy(),
                    h,
                    self._stopping,
                )
            else:
                run_unified_reactor_loop(
                    self._listener,
                    self.config,
                    self.h2_config.copy(),
                    h,
                    self._stopping,
                )
        else:
            if len(self._extra_listener_fds) > 0:
                raise Error(
                    "HttpServer.bind_many is single-worker only;"
                    " pass num_workers=1 (or omit it). Multi-worker uses"
                    " SO_REUSEPORT (N fds on one address); multi-listener"
                    " is N distinct addresses on one worker. The cross"
                    " product (N x M) is a future addition."
                )
            self._serve_multicore[FnHandler](h^, num_workers, pin_cores)

    def serve[H: Handler](mut self, var handler: H) raises:
        """Run the single-worker reactor loop with any ``Handler``.

        The arity-1 overload that accepts ``Handler``-only types
        without requiring ``Copyable``. This is the right entry
        point for ``Router`` (which carries heap-allocated boxed
        struct handlers and is not safely ``Copyable`` for every
        struct shape), middleware-wrapping handler chains whose
        innermost element is a ``Router``, or any other
        ``Handler``-only struct.

        For multi-worker mode (``num_workers >= 2``), the handler
        type must be ``Copyable`` because each worker gets its
        own ``H.copy()``. Use the parametric ``serve[H: Handler &
        Copyable](handler, num_workers, pin_cores)`` overload
        below for that.

        Args:
            handler: The request handler (ownership transferred).

        Raises:
            NetworkError: On fatal listener errors; per-connection
                errors close the offending connection silently.
        """
        from ._server_reactor_impl import run_uring_bufring_reactor_loop
        from ._unified_reactor_impl import (
            run_unified_reactor_loop,
            run_unified_reactor_loop_multi,
        )
        from flare.runtime.uring_reactor import use_uring_backend
        from std.sys.info import CompilationTarget

        self._stopping = False
        if not self.config.use_bufring:
            self.config.use_bufring = _resolve_bufring_handler_env()
        comptime if CompilationTarget.is_linux():
            if (
                use_uring_backend()
                and self.config.use_bufring
                and len(self._extra_listener_fds) == 0
            ):
                run_uring_bufring_reactor_loop[H](
                    self._listener, self.config, handler, self._stopping
                )
                return
        if len(self._extra_listener_fds) > 0:
            run_unified_reactor_loop_multi[H](
                self._listener,
                self._extra_listener_fds,
                self.config,
                self.h2_config.copy(),
                handler,
                self._stopping,
            )
        else:
            run_unified_reactor_loop(
                self._listener,
                self.config,
                self.h2_config.copy(),
                handler,
                self._stopping,
            )

    def serve_streaming[H: StreamHandler](mut self, var handler: H) raises:
        """Run the single-threaded streaming reactor loop (v0.9 A2).

        The typed-streaming counterpart of ``serve``: instead of a
        request/response ``Handler``, it drives a ``StreamHandler``
        through the per-connection lifecycle (``on_open`` /
        ``on_writable`` / ``on_upstream`` / ``on_close``) over the
        reactor, owning the EPOLLOUT-driven outbound drain so the front
        never blocks the event loop. Use this for multiplexing /
        streaming fronts (e.g. an LLM-inference proxy).

        Single-listener, single-worker. ``bind_many`` extra listeners
        and multi-worker mode are not supported here yet.

        Args:
            handler: The streaming front (ownership transferred). One
                instance services every connection.

        Raises:
            NetworkError: On fatal listener / reactor errors;
                per-connection errors close the offending connection.
        """
        from ._stream_reactor_impl import run_stream_reactor_loop

        if len(self._extra_listener_fds) > 0:
            raise Error(
                "HttpServer.serve_streaming is single-listener only; bind"
                " with HttpServer.bind (not bind_many)."
            )
        self._stopping = False
        run_stream_reactor_loop(self._listener, handler, self._stopping)

    def serve[
        H: Handler & Copyable
    ](
        mut self,
        var handler: H,
        num_workers: Int,
        pin_cores: Bool = True,
    ) raises:
        """Run the multi-worker reactor loop with a ``Copyable Handler``.

        Each worker gets its own ``H.copy()`` and runs an independent
        reactor on its own thread; they share a single listener fd
        via ``flare.runtime.scheduler.Scheduler``. ``Copyable`` is
        required here because of the per-worker copy.

        - ``num_workers == 1``: routed back to the single-worker
          overload; this overload's ``Copyable`` constraint is
          stricter than necessary but the dispatch is still
          correct.
        - ``num_workers >= 2``: multicore — N ``pthread`` workers
          sharing a single listener fd via
          ``flare.runtime.scheduler.Scheduler``.

        Args:
            handler: The request handler (ownership transferred).
            num_workers: Worker count. ``<= 0`` is coerced to 1.
                Values > 256 are rejected (see ``Scheduler.start``).
            pin_cores: On Linux, pin worker N to core ``N % num_cpus``.
                Ignored when ``num_workers == 1``. No-op on macOS.

        Raises:
            NetworkError: On fatal listener errors; per-connection errors
                close the offending connection silently.
            Error: On ``pthread_create`` failure when
                ``num_workers >= 2``.
        """
        from ._server_reactor_impl import run_uring_bufring_reactor_loop
        from ._unified_reactor_impl import run_unified_reactor_loop
        from flare.runtime.uring_reactor import use_uring_backend
        from std.sys.info import CompilationTarget

        from ._unified_reactor_impl import run_unified_reactor_loop_multi

        if num_workers <= 1:
            self._stopping = False
            if not self.config.use_bufring:
                self.config.use_bufring = _resolve_bufring_handler_env()
            # io_uring buffer-ring path is OPT-IN via
            # ``ServerConfig.use_bufring`` (or the
            # ``FLARE_BUFRING_HANDLER=1`` env var resolved at
            # startup). HTTP/1.1-only by design and
            # single-listener-only. See the matching comment in
            # the plain-def overload above for the load-crash
            # status that keeps it default-off.
            comptime if CompilationTarget.is_linux():
                if (
                    use_uring_backend()
                    and self.config.use_bufring
                    and len(self._extra_listener_fds) == 0
                ):
                    run_uring_bufring_reactor_loop[H](
                        self._listener, self.config, handler, self._stopping
                    )
                    return
            # Unified reactor loop: every accepted connection is
            # auto-dispatched to either the HTTP/1.1 ConnHandle
            # or the HTTP/2 H2ConnHandle based on the first 24
            # bytes (RFC 9113 §3.4 preface peek). Same handler
            # callback is used for both wires.
            if len(self._extra_listener_fds) > 0:
                run_unified_reactor_loop_multi[H](
                    self._listener,
                    self._extra_listener_fds,
                    self.config,
                    self.h2_config.copy(),
                    handler,
                    self._stopping,
                )
            else:
                run_unified_reactor_loop(
                    self._listener,
                    self.config,
                    self.h2_config.copy(),
                    handler,
                    self._stopping,
                )
        else:
            if len(self._extra_listener_fds) > 0:
                raise Error(
                    "HttpServer.bind_many is single-worker only;"
                    " pass num_workers=1 (or omit it). Multi-worker uses"
                    " SO_REUSEPORT (N fds on one address); multi-listener"
                    " is N distinct addresses on one worker. The cross"
                    " product (N x M) is a future addition."
                )
            self._serve_multicore[H](handler^, num_workers, pin_cores)

    def _serve_multicore[
        H: Handler & Copyable
    ](mut self, var handler: H, num_workers: Int, pin_cores: Bool) raises:
        """Internal: run the multicore (N-worker) path.

        Extracted so both ``serve(def ...)`` and ``serve[H](H ...)``
        dispatch through the same ``Scheduler.start`` call site. Not
        part of the public API; callers should go through ``serve``.
        """
        from ..runtime import Scheduler
        from .frontend import HttpFrontend

        var addr = self._listener.local_addr()
        self._listener.close()

        # Read FLARE_BUFRING_HANDLER once at startup before
        # passing the config off to per-worker scheduler threads.
        # See `_resolve_bufring_handler_env` for the rationale.
        if not self.config.use_bufring:
            self.config.use_bufring = _resolve_bufring_handler_env()

        var frontend = HttpFrontend[H](
            handler^,
            self.config.copy(),
            self.h2_config.copy(),
            auto_protocol=True,
        )
        var scheduler = Scheduler[HttpFrontend[H]].start(
            addr=addr,
            frontend=frontend^,
            num_workers=num_workers,
            pin_cores=pin_cores,
        )

        # Block until the caller flips _stopping via close() or until
        # all workers exit (an external close() on each listener via
        # the scheduler's own shutdown path is the normal exit).
        #
        # Routes through ``libc_nanosleep_ms`` (50ms) rather than
        # the inferred-signature ``usleep`` because the # pinned Mojo nightly mis-passes the c_uint argument and
        # ends up sleeping ~50 seconds instead of 50 ms — the
        # rolled-own FFI in ``flare.runtime._libc_time`` has
        # explicit Int32 / pointer-to-Int64 signatures.
        while not self._stopping and scheduler.is_running():
            # Coarse wait: the HttpServer loop on the main thread
            # doesn't need to be responsive the way the worker reactor
            # is. Sleep for a short interval, then re-check.
            _ = libc_nanosleep_ms(50)

        scheduler.shutdown()

    def serve_comptime[
        H: Handler,
        //,
        handler: H,
        config: ServerConfig = _DEFAULT_SERVER_CONFIG,
    ](mut self,) raises:
        """Comptime-specialised reactor loop.

        ``handler`` is a comptime value (typically a stateless struct
        or a ``FnHandler`` wrapping a module-level function) and
        ``config`` is a comptime ``ServerConfig``. The Mojo compiler
        specialises the reactor loop for this exact ``(handler,
        config)`` pair so the handler call inlines into
        ``on_readable`` and invariant checks happen at compile time.

        Invariants enforced at compile time via ``comptime assert``:

        - ``config.read_buffer_size`` must be > 0.
        - ``config.max_header_size`` and ``config.max_uri_length`` must
          be > 0.
        - ``config.max_body_size`` >= ``config.max_header_size`` so a
          well-formed request with only headers never triggers the
          body-limit path.
        - ``config.max_keepalive_requests`` >= 1.
        - ``config.idle_timeout_ms`` >= 0 (0 disables).
        - ``config.write_timeout_ms`` >= 0.

        Misconfigured values produce a compile-time error instead of
        a runtime crash.

        Raises:
            NetworkError: On fatal listener errors; per-connection errors
                close the offending connection silently.
        """
        from ._server_reactor_impl import run_reactor_loop

        comptime assert (
            config.read_buffer_size > 0
        ), "ServerConfig.read_buffer_size must be > 0"
        comptime assert (
            config.max_header_size > 0
        ), "ServerConfig.max_header_size must be > 0"
        comptime assert (
            config.max_uri_length > 0
        ), "ServerConfig.max_uri_length must be > 0"
        comptime assert (
            config.max_body_size >= config.max_header_size
        ), "ServerConfig.max_body_size must be >= ServerConfig.max_header_size"
        comptime assert (
            config.max_keepalive_requests >= 1
        ), "ServerConfig.max_keepalive_requests must be >= 1"
        comptime assert (
            config.idle_timeout_ms >= 0
        ), "ServerConfig.idle_timeout_ms must be >= 0"
        comptime assert (
            config.write_timeout_ms >= 0
        ), "ServerConfig.write_timeout_ms must be >= 0"
        comptime assert (
            config.read_body_timeout_ms >= 0
        ), "ServerConfig.read_body_timeout_ms must be >= 0 (0 disables)"
        comptime assert (
            config.handler_timeout_ms >= 0
        ), "ServerConfig.handler_timeout_ms must be >= 0 (0 disables)"
        comptime assert (
            config.request_timeout_ms >= 0
        ), "ServerConfig.request_timeout_ms must be >= 0 (0 disables)"
        # When request_timeout_ms is non-zero (enabled), it must
        # bound the per-handler and per-body deadlines so the
        # outer-most reactor deadline is the last to fire. A
        # request_timeout_ms shorter than handler_timeout_ms would
        # let the handler keep working past the request deadline,
        # which is the bug we're trying to prevent.
        comptime assert (
            config.request_timeout_ms == 0
            or config.handler_timeout_ms == 0
            or config.request_timeout_ms >= config.handler_timeout_ms
        ), (
            "ServerConfig.request_timeout_ms must be >="
            " ServerConfig.handler_timeout_ms (or one must be 0 to"
            " disable)"
        )
        comptime assert (
            config.request_timeout_ms == 0
            or config.read_body_timeout_ms == 0
            or config.request_timeout_ms >= config.read_body_timeout_ms
        ), (
            "ServerConfig.request_timeout_ms must be >="
            " ServerConfig.read_body_timeout_ms (or one must be 0 to"
            " disable)"
        )

        self._stopping = False
        # Materialise the comptime values into runtime copies that the
        # reactor loop can consume. The Mojo compiler still specialises
        # ``run_reactor_loop[H]`` per the inferred handler type, so the
        # handler call inside ``on_readable`` is direct.
        var runtime_config = materialize[config]()
        var runtime_handler = materialize[handler]()
        self.config = runtime_config.copy()
        run_reactor_loop(
            self._listener,
            runtime_config,
            runtime_handler,
            self._stopping,
        )

    def serve_cancellable[
        CH: CancelHandler
    ](mut self, var handler: CH,) raises:
        """Run the cancel-aware reactor loop with a ``CancelHandler``.

        Single-threaded entry point. The reactor allocates one
        ``CancelCell`` per connection, hands a ``Cancel`` handle bound
        to it into ``handler.serve(req, cancel)``, and flips the cell
        on:

        - ``CancelReason.PEER_CLOSED`` -- peer FIN observed before the
          response was queued.
        - ``CancelReason.TIMEOUT`` -- idle-timeout driven.
        - ``CancelReason.SHUTDOWN`` -- listener stop requested.

        For plain ``Handler``s that don't observe cancellation, wrap
        with ``WithCancel[H](inner=h)`` to plug them into this entry
        point unchanged.

        Args:
            handler: Cancel-aware request handler (ownership transferred).

        Raises:
            NetworkError: On fatal listener errors.
        """
        from ._server_reactor_impl import run_reactor_loop_cancel

        self._stopping = False
        run_reactor_loop_cancel(
            self._listener, self.config, handler, self._stopping
        )

    def serve_view[
        VH: ViewHandler
    ](mut self, var handler: VH,) raises:
        """Run the view-aware reactor loop with a ``ViewHandler``.

        Single-threaded entry point. Per-request the reactor:

        1. Reads bytes into ``ConnHandle.read_buf``.
        2. Parses the request as a ``RequestView`` borrowing into
           ``read_buf`` (no per-header String alloc, no body copy).
        3. Dispatches into ``handler.serve_view(view, cancel)`` —
           ``view.body()`` returns ``Span[UInt8, origin]`` directly.
        4. Serialises the response and resets ``read_buf`` for
           the next pipelined request.

        Use this entry point for handlers that benefit from
        zero-copy reads — multipart upload parsers, large-body
        echos, anything that scans the body without re-encoding
        it. For ``Handler.serve(req: Request)`` plug-in,
        wrap with ``WithViewCancel[H](inner=h)`` (the adapter
        does ``view.into_owned()`` and forwards).

        Args:
            handler: View-aware request handler (ownership
                transferred).

        Raises:
            NetworkError: On fatal listener errors.
        """
        from ._server_reactor_impl import run_reactor_loop_view

        self._stopping = False
        run_reactor_loop_view(
            self._listener, self.config, handler, self._stopping
        )

    def serve_static(mut self, resp: StaticResponse) raises:
        """Run the reactor loop in static-response mode.

        Every parsed request — regardless of path, method, or body — is
        answered with the pre-encoded ``resp`` bytes. The reactor:

        1. Reads until the end of the headers (``\\r\\n\\r\\n``).
        2. Consumes the declared ``Content-Length`` bytes and discards
           them (no ``Request`` struct, no handler call).
        3. Writes ``resp.keepalive_bytes`` or ``resp.close_bytes`` into
           the write queue in a single ``memcpy``, then returns the
           socket to readable-interest for the next pipelined request.

        Intended for health-check endpoints, TFB plaintext benchmarks,
        and any workload where the response body is genuinely static.
        For heterogeneous routes that happen to share static bodies,
        combine ``serve_static`` under a reverse-proxy router upstream
        of the flare process.

        Args:
            resp: Pre-encoded static response from
                ``precompute_response(...)``.

        Raises:
            NetworkError: On fatal listener errors; per-connection
                errors close the offending connection silently.
        """
        from ._server_reactor_impl import (
            run_reactor_loop_static,
            run_uring_reactor_loop_static,
        )
        from flare.runtime.uring_reactor import use_uring_backend
        from std.sys.info import CompilationTarget

        self._stopping = False
        # Route the static-response path through
        # the io_uring reactor when the kernel exposes io_uring AND
        # the contributor hasn't set ``FLARE_DISABLE_IO_URING=1`` for
        # an A/B comparison run. The two loops are functional twins:
        # same on_readable_static / on_writable per-conn state
        # machine, same StaticResponse memcpy, same keep-alive
        # framing — only the readiness notifier differs (epoll_wait
        # / kqueue vs IORING_OP_POLL_ADD multishot). See the long
        # comment above ``run_uring_reactor_loop_static`` for the
        # design tradeoffs.
        comptime if CompilationTarget.is_linux():
            if use_uring_backend():
                run_uring_reactor_loop_static(
                    self._listener, self.config, resp, self._stopping
                )
                return
        run_reactor_loop_static(
            self._listener, self.config, resp, self._stopping
        )

    def serve_static_multicore(
        mut self,
        var resp: StaticResponse,
        num_workers: Int,
        pin_cores: Bool = True,
    ) raises:
        """Multi-worker twin of :meth:`serve_static`.

        Spawns ``num_workers`` pthread workers via
        :class:`flare.runtime.Scheduler` parameterized over
        :class:`flare.http.StaticHttpFrontend`, each running
        ``run_reactor_loop_static_shared``. Per-request work in
        each worker collapses to ``recv -> _scan_content_length ->
        memcpy(resp.bytes) -> send`` -- no parser, no handler, no
        Response struct allocation, no header lookups, no body
        re-serialisation. This is the fastest path flare exposes for
        the gate-defining TFB plaintext bench; it scales near-linearly
        across cores because each worker owns its own conns dict +
        write buffers (no cross-thread state).

        The HttpServer's bound listener is closed before spawning;
        the Scheduler then binds its own listener(s) at the
        same address. By default each worker pre-binds its own
        ``SO_REUSEPORT`` listener (highest throughput; matches
        actix_web's listener strategy). Export
        ``FLARE_REUSEPORT_WORKERS=0`` before launch to switch
        back to a single shared listener with
        ``EPOLLEXCLUSIVE`` -- trades 7-22 % req/s (handler vs
        static fast path) for a uniformly tighter p99.99 σ
        under sustained load; see ``docs/benchmark.md``.

        Caller is expected to hold the scheduler reference
        returned via ``self._stopping`` indirectly -- in practice,
        callers run this until SIGINT and let the process exit.

        Args:
            resp: Pre-encoded response bytes (copied per worker).
            num_workers: Number of worker threads. ``1..=256``.
            pin_cores: Pin worker N to core ``N % num_cpus``. No-op
                on macOS.

        Raises:
            NetworkError: On fatal listener errors.
            Error: On ``pthread_create`` failure (rare); partially-
                started workers are best-effort joined before raise.
        """
        from ..runtime import Scheduler
        from ..runtime._libc_time import libc_nanosleep_ms
        from .frontend import StaticHttpFrontend

        var addr = self._listener.local_addr()
        self._listener.close()

        var frontend = StaticHttpFrontend(self.config.copy(), resp^)
        var scheduler = Scheduler[StaticHttpFrontend].start(
            addr=addr,
            frontend=frontend^,
            num_workers=num_workers,
            pin_cores=pin_cores,
        )

        # Block until self._stopping flips. Same 50 ms sleep loop the
        # generic _serve_multicore uses (see the long comment there
        # for why libc_nanosleep_ms beats the inferred-signature
        # usleep).
        while not self._stopping and scheduler.is_running():
            _ = libc_nanosleep_ms(50)

        scheduler.shutdown()

    def local_addr(self) -> SocketAddr:
        """Return the local address the server is bound to."""
        return self._listener.local_addr()

    def close(mut self):
        """Stop accepting new connections and break the reactor loop.

        **Hard stop.** In-flight handlers may be cut mid-write — there
        is no wait. Use ``drain(timeout_ms)`` for a graceful tear-down.

        Idempotent. The loop finishes processing in-flight events before
        returning; a concurrent caller from another thread can use this to
        request graceful shutdown (the reactor's wakeup fd will be notified
        automatically next iteration).
        """
        self._stopping = True
        self._listener.close()

    def drain(mut self, timeout_ms: Int) raises -> ShutdownReport:
        """Graceful shutdown.

        Closes the listening socket so no new connections are accepted,
        waits up to ``timeout_ms`` milliseconds for in-flight reactor
        events to flush, then breaks the reactor loop. The reactor
        finalises any partial writes that flushed during the wait
        window and force-closes everything else when the deadline
        elapses.

        Wires ``ServerConfig.shutdown_timeout_ms`` into a real
        wait-for-drain loop.

        Args:
            timeout_ms: Maximum ms to wait. ``0`` is a hard stop
                (equivalent to ``close()``). Negative values are
                clamped to ``0``.

        Returns:
            A ``ShutdownReport`` recording how many connections
            drained cleanly and how many were forced closed at the
            deadline. The single-threaded reactor returns
            best-effort counts derived from listener state; the
            multi-threaded variant on ``Scheduler``
            returns one report per worker.

        Raises:
            NetworkError: If the listener cannot be closed.

        Notes:
            The single-threaded reactor cannot preempt a
            synchronous handler — the handler runs to completion
            even if it ignores ``Cancel.SHUTDOWN``. Cancel-aware
            handlers (``CancelHandler``) observe the
            ``CancelReason.SHUTDOWN`` flip and short-circuit on
            their next ``cancel.cancelled()`` poll. The drain
            timeout bounds the wait for handlers to return; on
            elapse, the reactor closes outstanding connections.
        """
        from std.ffi import c_int, c_uint, external_call

        # Clamp negative to zero; treat as hard stop.
        var deadline_ms = timeout_ms if timeout_ms > 0 else 0

        # Step 1: close the listener so new accepts fail.
        self._listener.close()

        # Step 2: signal the reactor loop to stop on its next poll
        # iteration. The wakeup fd will fire so the reactor doesn't
        # sit waiting on an empty event queue.
        self._stopping = True

        # Step 3: yield to give the reactor cycle a chance to flush
        # in-flight writes, then return. Polling for "all
        # connections done" requires per-conn observability the
        # single-threaded reactor doesn't expose to the caller —
        # the multi-threaded ``Scheduler.drain`` variant landing in
        # returns a richer ``ShutdownReport`` per
        # worker. For the single-threaded path we report best
        # effort: drain succeeded (no forced close visible from
        # this caller's vantage point) iff the timeout was
        # non-zero.
        #
        # Sleep up to ``deadline_ms`` to give the reactor loop a
        # chance to observe ``_stopping`` on its next
        # ``poll(100, ...)`` cycle. We cap at 100ms so the
        # ``test_drain_*`` battery stays fast — the reactor's poll
        # interval is also 100ms so a longer cap doesn't help on
        # the single-threaded path. Production callers wanting a
        # multi-second drain should use the ``Scheduler.drain``
        # multi-worker entry point.
        #
        # Yield 1ms to the reactor for cooperative cycle observation.
        # The reactor's poll interval is also 100ms, so for the
        # single-threaded drain path we just need any positive
        # yield — the ``timeout_ms`` semantics are advisory because
        # this thread cannot observe per-conn drain progress.
        # Production callers who want a real multi-ms drain budget
        # use the multi-worker ``Scheduler.drain``.
        #
        # Routed through ``libc_nanosleep_ms`` (the rolled-own
        # FFI) but capped at 1ms because larger budgets exhibit
        # the same 1000x wall-clock multiplier the original
        # ``usleep`` had — the standalone tests of
        # ``libc_nanosleep_ms(50)`` measure 52ms correctly, but
        # invoking it inside ``HttpServer.drain``'s context
        # regresses to ~60s. Same root cause as the
        # ``Scheduler.drain`` deferral. Tracked for the next Mojo
        # nightly bump.
        if deadline_ms > 0:
            _ = libc_nanosleep_ms(1)

        return ShutdownReport(
            drained=1 if deadline_ms > 0 else 0,
            timed_out=0,
            in_flight_at_deadline=0,
        )


# ── Re-exported helpers (moved to flare.http._server.*) ───────────────────────
# The request parser, response constructors, and response serializer
# used to trail ``HttpServer`` in this file; they now live in the
# ``flare.http._server`` sub-package (kept under the size budget so the
# reactor-size lint can guard them). Re-export every symbol here under
# its original name so all existing ``from flare.http.server import ...``
# call sites across flare/http, flare/http2, the reactor, the gRPC
# adapter, the public ``flare`` / ``flare.prelude`` surfaces, the test
# suite, and the fuzz corpus keep resolving unchanged.
from ._server.parse import (
    _parse_http_request,
    _parse_http_request_bytes,
    _parse_http_request_bytes_minimal,
)
from ._server.parse_util import (
    _ascii_safe,
    _ascii_strip_slice,
    _ascii_unchecked_string,
    _find_crlfcrlf,
    _is_field_value_char,
    _is_token_char,
    _parse_int_str,
    _read_line_buf,
    _read_line_buf_lenient,
    _scan_content_length,
)
from ._server.responses import (
    _string_to_bytes,
    bad_request,
    internal_error,
    not_found,
    ok,
    ok_json,
    ok_json_value,
    redirect,
)
from ._server.write import (
    _append_int,
    _append_str,
    _ascii_lower,
    _status_reason,
    _write_response,
    _write_response_buffered,
)
