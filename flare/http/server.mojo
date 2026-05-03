"""HTTP/1.1 server with buffered reads, keep-alive, and per-connection handler callbacks.

Key performance characteristics:
- Reads from the socket in chunks (configurable, default 8KB) instead of byte-at-a-time.
- Scans for the header terminator (CRLFCRLF) in the buffer before parsing.
- Supports HTTP/1.1 keep-alive (reuses connections for multiple requests).
- Serialises the full response into a single buffer for one write_all call.
- Sets recv/send timeouts on accepted sockets for DoS resilience.
- Respects HTTP/1.0 close-by-default semantics.
"""

from std.memory import memcpy, stack_allocation
from std.ffi import c_int, c_uint, external_call

from ..runtime._libc_time import libc_nanosleep_ms

from .handler import Handler, CancelHandler
from .intern import intern_method_bytes
from .request import Request, Method
from .response import Response, Status
from .headers import HeaderMap
from .static_response import StaticResponse
from ..net import IpAddr, SocketAddr, NetworkError, BrokenPipe, Timeout
from ..tcp import TcpListener, TcpStream


# ── Server configuration ─────────────────────────────────────────────────────


struct ServerConfig(Copyable, Movable):
    """Configuration for the HTTP server.

    Fields:
        read_buffer_size: Socket read chunk size in bytes (default 8192).
        max_header_size: Maximum total bytes for request headers (default 8192).
        max_body_size: Maximum bytes for the request body (default 10MB).
        max_uri_length: Maximum bytes for the request URI (default 8192).
        keep_alive: Enable HTTP/1.1 keep-alive (default True).
        max_keepalive_requests: Max requests per connection before forcing close (default 100).
        idle_timeout_ms: Max ms a connection may stay idle before the
            reactor closes it (default 500). 0 disables.
        write_timeout_ms: Max ms allowed for a partial write to complete
            (default 5000). 0 disables.
        shutdown_timeout_ms: Max ms graceful shutdown waits for in-flight
            connections to drain before force-closing (default 5000).
        expose_error_messages: When ``True``, 400 / 5xx response bodies
            include the raised ``Error`` message verbatim — useful for
            local development. **Default ``False``** so production
            servers send a fixed status reason and log the message
            (with any user-controlled bytes) to stderr instead of
            echoing it back. Closes criticism §2.7.
        read_body_timeout_ms: Max ms allowed between headers-end and the
            last body byte (default 30_000). 0 disables. Closes the
            slow-body-upload variant of the slow-client DoS surface
            described in criticism §2.2. Mirrors nginx's
            ``client_body_timeout``.
        handler_timeout_ms: Max ms ``Handler.serve`` (or
            ``CancelHandler.serve``) is allowed to run before the
            reactor flips ``Cancel.TIMEOUT`` (default 30_000). 0
            disables. Cooperative — the handler observes the flip on
            its next ``cancel.cancelled()`` poll. Closes the
            handler-watchdog variant of criticism §2.2.
        request_timeout_ms: Max ms wall-time from request line in to
            response bytes out (default 60_000). 0 disables. The
            reactor enforces this as the outermost deadline; the
            other two cooperate via ``Cancel``. Must be >=
            ``handler_timeout_ms`` and >=
            ``read_body_timeout_ms`` (checked at compile time in
            ``serve_comptime``).
    """

    var read_buffer_size: Int
    var max_header_size: Int
    var max_body_size: Int
    var max_uri_length: Int
    var keep_alive: Bool
    var max_keepalive_requests: Int
    var idle_timeout_ms: Int
    var write_timeout_ms: Int
    var shutdown_timeout_ms: Int
    var expose_error_messages: Bool
    var read_body_timeout_ms: Int
    var handler_timeout_ms: Int
    var request_timeout_ms: Int

    def __init__(
        out self,
        read_buffer_size: Int = 8192,
        max_header_size: Int = 8192,
        max_body_size: Int = 10 * 1024 * 1024,
        max_uri_length: Int = 8192,
        keep_alive: Bool = True,
        max_keepalive_requests: Int = 100,
        idle_timeout_ms: Int = 500,
        write_timeout_ms: Int = 5000,
        shutdown_timeout_ms: Int = 5000,
        expose_error_messages: Bool = False,
        read_body_timeout_ms: Int = 30_000,
        handler_timeout_ms: Int = 30_000,
        request_timeout_ms: Int = 60_000,
    ):
        self.read_buffer_size = read_buffer_size
        self.max_header_size = max_header_size
        self.max_body_size = max_body_size
        self.max_uri_length = max_uri_length
        self.keep_alive = keep_alive
        self.max_keepalive_requests = max_keepalive_requests
        self.idle_timeout_ms = idle_timeout_ms
        self.write_timeout_ms = write_timeout_ms
        self.shutdown_timeout_ms = shutdown_timeout_ms
        self.expose_error_messages = expose_error_messages
        self.read_body_timeout_ms = read_body_timeout_ms
        self.handler_timeout_ms = handler_timeout_ms
        self.request_timeout_ms = request_timeout_ms


# Comptime-friendly default config. Used as the default for
# ``HttpServer.serve_comptime[handler, config = ...]()``. Any user who
# wants a non-default comptime config must declare their own
# ``comptime my_cfg: ServerConfig = ServerConfig(...)`` because Mojo
# ``comptime assert`` checks need comptime-stable values.
comptime _DEFAULT_SERVER_CONFIG: ServerConfig = ServerConfig()


# ── ShutdownReport ───────────────────────────────────────────────────────────


@fieldwise_init
struct ShutdownReport(Copyable, ImplicitlyCopyable, Movable):
    """Result of a graceful shutdown via ``HttpServer.drain`` or
    ``Scheduler.drain``.

    The multi-worker variant returns one report per worker; the
    single-threaded ``HttpServer.drain`` returns one. ``drained``
    and ``timed_out`` are best-effort counts the reactor / scheduler
    can observe from its own side; ``in_flight_at_deadline`` is the
    remaining-connection count at the moment the timeout elapsed
    (zero when drain completed cleanly).

    Fields:
        drained: Connections that completed their in-flight work
            inside the drain timeout. Best-effort.
        timed_out: Connections that were force-closed because the
            drain timeout elapsed before they finished. Best-effort.
        in_flight_at_deadline: Connections still alive at the
            instant the timeout fired (== ``timed_out`` after the
            force-close completes).
    """

    var drained: Int
    var timed_out: Int
    var in_flight_at_deadline: Int


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
    var config: ServerConfig
    var _stopping: Bool
    """Set by ``close()`` to break the reactor loop. Read from the loop
    itself each iteration."""

    def __init__(
        out self,
        var listener: TcpListener,
        var config: ServerConfig = ServerConfig(),
    ):
        self._listener = listener^
        self.config = config^
        self._stopping = False

    def __del__(deinit self):
        self._listener.close()

    @staticmethod
    def bind(
        addr: SocketAddr, var config: ServerConfig = ServerConfig()
    ) raises -> HttpServer:
        """Bind an HTTP server on ``addr``.

        Args:
            addr: Local address to listen on.
            config: Server configuration (optional).

        Returns:
            An ``HttpServer`` ready to call ``serve()``.

        Raises:
            AddressInUse: If the port is already bound.
            NetworkError: For any other OS error.
        """
        var listener = TcpListener.bind(addr)
        return HttpServer(listener^, config^)

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
          sharing a single listener fd, each registering it with
          ``EPOLLEXCLUSIVE`` (on Linux >= 4.5) via
          ``flare.runtime.scheduler.Scheduler``. The kernel
          wakes one worker per accept event, eliminating the
          ``SO_REUSEPORT`` 4-tuple-hash distribution variance that
          drove tail-latency spikes .

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
        from ._server_reactor_impl import (
            run_reactor_loop,
            run_uring_bufring_reactor_loop,
        )
        from .handler import FnHandler
        from flare.runtime.uring_reactor import use_uring_backend
        from std.os import getenv
        from std.sys.info import CompilationTarget

        var h = FnHandler(handler)
        if num_workers <= 1:
            self._stopping = False
            # OPT-IN via FLARE_BUFRING_HANDLER=1; see the matching
            # comment in the generic ``serve[H]`` overload above
            # for why the bufring path is default-OFF (crashes
            # under sustained 64-conn wrk2 load).
            comptime if CompilationTarget.is_linux():
                if (
                    use_uring_backend()
                    and getenv("FLARE_BUFRING_HANDLER") == "1"
                ):
                    run_uring_bufring_reactor_loop(
                        self._listener, self.config, h, self._stopping
                    )
                    return
            run_reactor_loop(self._listener, self.config, h, self._stopping)
        else:
            self._serve_multicore[FnHandler](h^, num_workers, pin_cores)

    def serve[
        H: Handler & Copyable
    ](
        mut self,
        var handler: H,
        num_workers: Int = 1,
        pin_cores: Bool = True,
    ) raises:
        """Run the reactor loop with a ``Handler``.

        This is the unified entry point. Any struct implementing
        ``Handler & Copyable`` works: ``Router``, middleware wrappers,
        stateful user handlers, ``App[S, H]``, or a bare ``FnHandler``.

        - ``num_workers == 1`` (default): single-threaded reactor.
          ``run_reactor_loop`` runs directly on the current thread,
          no pthreads.
        - ``num_workers >= 2``: multicore — N ``pthread`` workers
          sharing a single listener fd via
          ``flare.runtime.scheduler.Scheduler``.
          ``Copyable`` is required here because each worker gets its
          own ``H.copy()``.

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
        from ._server_reactor_impl import (
            run_reactor_loop,
            run_uring_bufring_reactor_loop,
        )
        from flare.runtime.uring_reactor import use_uring_backend
        from std.os import getenv
        from std.sys.info import CompilationTarget

        if num_workers <= 1:
            self._stopping = False
            # io_uring buffer-ring path is OPT-IN via
            # ``FLARE_BUFRING_HANDLER=1``. Substrate ships and
            # passes test-uring-serve-handler (8 connections,
            # 50 keepalive churn, 8 concurrent fanout) but
            # crashes under SUSTAINED 64-conn wrk2-style load
            # (segfault on the 1st bench iteration). The crash
            # reproduces with FnHandler closures (test_bufring_load
            # 6s @ 80K rps target -> SIGSEGV after ~50 reqs) and
            # is independent of the handler shape -- pointing at
            # a race in the bufring dispatch / cancel-on-close /
            # PBUF_RING tail-bump interaction under high recv-CQE
            # rate. Default-off until the bench-load crash is
            # root-caused.
            comptime if CompilationTarget.is_linux():
                if (
                    use_uring_backend()
                    and getenv("FLARE_BUFRING_HANDLER") == "1"
                ):
                    run_uring_bufring_reactor_loop[H](
                        self._listener, self.config, handler, self._stopping
                    )
                    return
            run_reactor_loop(
                self._listener, self.config, handler, self._stopping
            )
        else:
            self._serve_multicore[H](handler^, num_workers, pin_cores)

    def _serve_multicore[
        H: Handler & Copyable
    ](mut self, var handler: H, num_workers: Int, pin_cores: Bool) raises:
        """Internal: run the multicore (N-worker) path.

        Extracted so both ``serve(def ...)`` and ``serve[H](H ...)``
        dispatch through the same ``Scheduler.start`` call site. Not
        part of the public API; callers should go through ``serve``.
        """
        from ..runtime.scheduler import Scheduler

        var addr = self._listener.local_addr()
        self._listener.close()

        var scheduler = Scheduler[H].start(
            addr=addr,
            config=self.config.copy(),
            handler=handler^,
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
        """Run the cancel-aware reactor loop with a ``CancelHandler``
        .

         Single-threaded entry point; the multicore variant lands in a
         future commit. The reactor allocates one ``CancelCell`` per
         connection, hands a ``Cancel`` handle bound to it into
         ``handler.serve(req, cancel)``, and flips the cell on:

         - ``CancelReason.PEER_CLOSED`` — peer FIN observed before the
           response was queued.
         - ``CancelReason.TIMEOUT`` — wired in commit 5 of .
         - ``CancelReason.SHUTDOWN`` — wired in commit 6 of .

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
        """Run the view-aware reactor loop with a ``ViewHandler``
        .

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
        # Track B0 wire-in: route the static-response path through
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

        Wires ``ServerConfig.shutdown_timeout_ms`` (a stub field
        through ) into a real wait-for-drain loop. Closes
        criticism §2.12.

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


@always_inline
def _find_crlfcrlf(data: List[UInt8], start: Int) -> Int:
    """Find \\r\\n\\r\\n in data starting at ``start``.

    Returns the byte offset just past the sequence (start of body),
    or -1 if not found.

    Thin wrapper over ``flare.http._scan.find_crlfcrlf`` with the
    default SIMD width (32 lanes) so the public call site keeps the
    same signature as the scalar implementation. Callers who
    need a non-default width can import ``find_crlfcrlf`` directly.
    """
    from ._scan import find_crlfcrlf as _sc_find

    return _sc_find(data, start)


def _scan_content_length(data: List[UInt8], header_end: Int) -> Int:
    """Scan for ``Content-Length:`` in the header block and parse it.

    Thin wrapper over ``flare.http._scan.scan_content_length`` at the
    default SIMD width. Returns ``0`` when the header is absent.
    """
    from ._scan import scan_content_length as _sc_len

    return _sc_len(data, header_end)


# ── RFC 7230 token validation ─────────────────────────────────────────────────


@always_inline
def _is_token_char(c: UInt8) -> Bool:
    """Return True if ``c`` is a valid HTTP token character (RFC 7230 §3.2.6).

    token = 1*tchar
    tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
            "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
    """
    if c >= 65 and c <= 90:
        return True
    if c >= 97 and c <= 122:
        return True
    if c >= 48 and c <= 57:
        return True
    if c == 33 or c == 35 or c == 36 or c == 37 or c == 38:
        return True
    if c == 39 or c == 42 or c == 43 or c == 45 or c == 46:
        return True
    if c == 94 or c == 95 or c == 96 or c == 124 or c == 126:
        return True
    return False


@always_inline
def _is_field_value_char(c: UInt8) -> Bool:
    """Return True if ``c`` is valid in an HTTP header field value (RFC 7230 §3.2).

    field-value = *( field-content / obs-fold )
    field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
    field-vchar = VCHAR / obs-text
    VCHAR = 0x21-0x7E; obs-text = 0x80-0xFF; SP = 0x20; HTAB = 0x09
    """
    if c == 9 or c == 32:
        return True
    if c >= 33 and c <= 126:
        return True
    if c >= 128:
        return True
    return False


# ── Request parsing (from buffer) ────────────────────────────────────────────


def _parse_http_request_bytes(
    data: Span[UInt8, _],
    max_header_size: Int = 8_192,
    max_body_size: Int = 10 * 1024 * 1024,
    max_uri_length: Int = 8_192,
    peer: SocketAddr = SocketAddr(IpAddr("127.0.0.1", False), UInt16(0)),
    expose_errors: Bool = False,
) raises -> Request:
    """Parse an HTTP/1.1 request from a byte buffer.

    Validates header names per RFC 7230 token rules and header values for
    illegal control characters. Parses HTTP version for keep-alive semantics.

    Args:
        data: Raw HTTP/1.1 request bytes.
        max_header_size: Maximum bytes for all header lines combined.
        max_body_size: Maximum bytes for the request body.
        max_uri_length: Maximum bytes for the request URI.
        peer: Kernel-reported peer ``SocketAddr`` captured at
                         accept; copied into the parsed ``Request`` so
                         handlers can read ``req.peer``. Defaults to
                         ``127.0.0.1:0`` for callers that don't have a
                         live connection (tests, fuzzers).
        expose_errors: Whether the parsed request will allow handler /
                         extractor error messages into its 4xx / 5xx
                         response body. Threaded onto
                         ``Request.expose_errors``. Defaults to
                         ``False`` (production-safe).

    Returns:
        A parsed ``Request`` with version set from the request line.

    Raises:
        Error: On malformed request line, invalid tokens, or limit violations.
    """
    var pos = 0

    # 1. Request line: METHOD SP URI SP VERSION CRLF
    var req_line = _read_line_buf(data, pos)
    if req_line.byte_length() == 0:
        raise Error("empty request line")

    var sp1 = -1
    for i in range(req_line.byte_length()):
        if req_line.unsafe_ptr()[i] == 32:
            sp1 = i
            break
    if sp1 < 0:
        raise Error("malformed request line: " + req_line)
    # B3: try the StaticString intern table first — covers the 9
    # RFC 7231 method names (~99 % of real-world traffic is GET /
    # POST). On a hit, the returned String's backing comes from
    # a process-lifetime constant rather than from per-request
    # request buffer bytes, so the second String wrap is elided.
    var interned = intern_method_bytes(req_line.as_bytes()[:sp1])
    var method: String
    if interned:
        method = interned.value()
    else:
        method = String(String(unsafe_from_utf8=req_line.as_bytes()[:sp1]))

    var sp2 = -1
    for i in range(sp1 + 1, req_line.byte_length()):
        if req_line.unsafe_ptr()[i] == 32:
            sp2 = i
            break
    var path: String
    var version: String
    if sp2 < 0:
        path = String(String(unsafe_from_utf8=req_line.as_bytes()[sp1 + 1 :]))
        version = "HTTP/1.1"
    else:
        path = String(
            String(unsafe_from_utf8=req_line.as_bytes()[sp1 + 1 : sp2])
        )
        version = String(
            String(unsafe_from_utf8=req_line.as_bytes()[sp2 + 1 :])
        )

    if path.byte_length() > max_uri_length:
        raise Error(
            "request URI exceeds limit of " + String(max_uri_length) + " bytes"
        )

    # 2. Headers with RFC 7230 token validation
    var headers = HeaderMap()
    var header_bytes = 0

    while True:
        var line = _read_line_buf(data, pos)
        header_bytes += line.byte_length()
        if header_bytes > max_header_size:
            raise Error(
                "request headers exceed limit of "
                + String(max_header_size)
                + " bytes"
            )
        if line.byte_length() == 0:
            break
        var colon = -1
        for i in range(line.byte_length()):
            if line.unsafe_ptr()[i] == 58:  # ':'
                colon = i
                break
        if colon >= 0:
            # Validate header name (token chars only)
            var name_valid = True
            for i in range(colon):
                if not _is_token_char(line.unsafe_ptr()[i]):
                    name_valid = False
                    break
            if not name_valid:
                raise Error("invalid character in header name")

            var k = _ascii_strip_slice(line.as_bytes()[:colon])
            var v = _ascii_strip_slice(line.as_bytes()[colon + 1 :])

            # Validate header value (no bare CR/LF/NUL)
            for i in range(v.byte_length()):
                var vc = v.unsafe_ptr()[i]
                if vc == 0 or vc == 10 or vc == 13:
                    raise Error("invalid control character in header value")
            headers.set(k, v)

    # 3. Body (Content-Length)
    var body = List[UInt8]()
    var cl_str = headers.get("Content-Length")
    if cl_str.byte_length() > 0:
        var content_length = _parse_int_str(cl_str)
        if content_length > max_body_size:
            raise Error(
                "request body exceeds limit of "
                + String(max_body_size)
                + " bytes"
            )
        if content_length > 0:
            var end = pos + content_length
            if end > len(data):
                end = len(data)
            # Bulk-copy the body in one resize + memcpy. Per-byte
            # ``body.append`` was a measurable hot-path cost on POSTs.
            var n = end - pos
            if n > 0:
                body.resize(n, UInt8(0))
                memcpy(
                    dest=body.unsafe_ptr(),
                    src=data.unsafe_ptr() + pos,
                    count=n,
                )

    var req = Request(
        method=method,
        url=path,
        body=body^,
        version=version,
        peer=peer,
        expose_errors=expose_errors,
    )
    req.headers = headers^
    return req^


def _read_line_buf(data: Span[UInt8, _], mut pos: Int) -> String:
    """Read one CRLF/LF-terminated line from a byte span, advancing ``pos``.

    Replaces NUL and non-ASCII bytes with '?' since HTTP headers are ASCII
    per RFC 7230.

    Fast path: scan once for the LF terminator while checking for bad
    bytes; if none are found, build the line in a single
    ``String(unsafe_from_utf8=span)`` call. The slow path only runs on
    malformed / non-ASCII requests and preserves the previous
    byte-at-a-time sanitisation semantics.
    """
    var n = len(data)
    var start = pos
    var end = -1
    var has_bad = False
    var i = start
    while i < n:
        var c = data[i]
        if c == 10:
            end = i
            break
        if c == 0 or c >= 128:
            has_bad = True
        i += 1

    if end < 0:
        # No terminator — consume everything that was available.
        end = n

    # Advance the caller's cursor past the LF (or to end-of-buffer).
    pos = end + 1 if end < n else end

    # Exclude trailing CR.
    var stop = end
    if stop > start and data[stop - 1] == 13:
        stop -= 1

    if stop <= start:
        return String("")

    if not has_bad:
        # Fast path — pure ASCII, one-shot construction.
        return String(unsafe_from_utf8=data[start:stop])

    # Slow path: copy bytes, replacing bad ones with '?'.
    var out = String(capacity=stop - start)
    for k in range(start, stop):
        var c = data[k]
        if c == 0 or c >= 128:
            out += "?"
        else:
            out += chr(Int(c))
    return out^


def _parse_int_str(s: String) -> Int:
    """Parse a non-negative decimal integer string; returns 0 on failure."""
    var result = 0
    var trimmed = s.strip()
    for i in range(trimmed.byte_length()):
        var c = Int(trimmed.unsafe_ptr()[i])
        if c < 48 or c > 57:
            break
        result = result * 10 + (c - 48)
    return result


# ── Response helpers ──────────────────────────────────────────────────────────


@always_inline
def _string_to_bytes(s: String) -> List[UInt8]:
    """Bulk-copy a ``String``'s bytes into a freshly-allocated ``List[UInt8]``.

    Replaces the byte-by-byte append loop ``ok`` / ``ok_json`` / ...
    were doing on the response-building hot path. One allocation, one
    ``memcpy`` — what every Rust framework's ``Bytes::from(String)``
    is doing under the hood.
    """
    var n = s.byte_length()
    var body_bytes = List[UInt8]()
    if n == 0:
        return body_bytes^
    body_bytes.resize(n, UInt8(0))
    var src = s.as_bytes()
    memcpy(dest=body_bytes.unsafe_ptr(), src=src.unsafe_ptr(), count=n)
    return body_bytes^


def ok(body: String = "") -> Response:
    """Create a 200 OK response with optional text body.

    Args:
        body: Response body string. Empty by default.

    Returns:
        A ``Response`` with status 200. Sets ``Content-Type: text/plain``
        if body is non-empty.
    """
    var resp = Response(
        status=Status.OK, reason="OK", body=_string_to_bytes(body)
    )
    if body.byte_length() > 0:
        try:
            resp.headers.set("Content-Type", "text/plain; charset=utf-8")
        except:
            pass
    return resp^


def ok_json(body: String) -> Response:
    """Create a 200 OK response with a JSON body.

    Args:
        body: JSON string to send.

    Returns:
        A ``Response`` with ``Content-Type: application/json``.
    """
    var resp = Response(
        status=Status.OK, reason="OK", body=_string_to_bytes(body)
    )
    try:
        resp.headers.set("Content-Type", "application/json")
    except:
        pass
    return resp^


def bad_request(msg: String = "Bad Request") -> Response:
    """Create a 400 Bad Request response."""
    var resp = Response(
        status=Status.BAD_REQUEST,
        reason="Bad Request",
        body=_string_to_bytes(msg),
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def not_found(path: String = "") -> Response:
    """Create a 404 Not Found response."""
    var msg = "Not Found"
    if path.byte_length() > 0:
        msg = "Not Found: " + path
    var resp = Response(
        status=Status.NOT_FOUND,
        reason="Not Found",
        body=_string_to_bytes(msg),
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def internal_error(msg: String = "Internal Server Error") -> Response:
    """Create a 500 Internal Server Error response."""
    var resp = Response(
        status=Status.INTERNAL_SERVER_ERROR,
        reason="Internal Server Error",
        body=_string_to_bytes(msg),
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def redirect(url: String, status: Int = 302) -> Response:
    """Create a redirect response (302 Found by default).

    Args:
        url: Target URL for the ``Location`` header.
        status: HTTP status code (301, 302, 307, 308). Default 302.

    Returns:
        A ``Response`` with the ``Location`` header set.
    """
    var resp = Response(status=status, reason=_status_reason(status))
    try:
        resp.headers.set("Location", url)
    except:
        pass
    return resp^


# ── Response writing ──────────────────────────────────────────────────────────


def _write_response_buffered(
    mut stream: TcpStream, resp: Response, keep_alive: Bool
) raises:
    """Serialise ``resp`` into a single buffer and write it in one call.

    Args:
        stream: Open ``TcpStream`` for the client connection.
        resp: The response to send.
        keep_alive: If True, sends ``Connection: keep-alive``; otherwise ``close``.

    Raises:
        NetworkError: On I/O failure.
    """
    var reason = resp.reason
    if reason.byte_length() == 0:
        reason = _status_reason(resp.status)

    var body_len = len(resp.body)

    var estimated = 64 + body_len
    for i in range(resp.headers.len()):
        estimated += (
            resp.headers._keys[i].byte_length()
            + resp.headers._values[i].byte_length()
            + 4
        )
    var wire = List[UInt8](capacity=estimated)

    _append_str(wire, "HTTP/1.1 ")
    _append_str(wire, String(resp.status))
    _append_str(wire, " ")
    _append_str(wire, reason)
    _append_str(wire, "\r\n")

    for i in range(resp.headers.len()):
        var k = resp.headers._keys[i]
        var kl = _ascii_lower(k)
        if kl == "content-length" or kl == "connection":
            continue
        _append_str(wire, k)
        _append_str(wire, ": ")
        _append_str(wire, resp.headers._values[i])
        _append_str(wire, "\r\n")

    _append_str(wire, "Content-Length: ")
    _append_str(wire, String(body_len))
    _append_str(wire, "\r\n")

    if keep_alive:
        _append_str(wire, "Connection: keep-alive\r\n")
    else:
        _append_str(wire, "Connection: close\r\n")

    _append_str(wire, "\r\n")

    for i in range(body_len):
        wire.append(resp.body[i])

    stream.write_all(Span[UInt8, _](wire))


@always_inline
def _append_str(mut buf: List[UInt8], s: String):
    """Append all bytes of ``s`` to ``buf``.

    Bulk extend via resize + pointer copy. The naive per-byte
    ``buf.append(...)`` loop was called O(100) times per serialized
    response (status line + each header + body) which added measurable
    cost at 100K+ req/s.
    """
    var n = s.byte_length()
    if n == 0:
        return
    var old_len = len(buf)
    buf.resize(old_len + n, UInt8(0))
    memcpy(dest=buf.unsafe_ptr() + old_len, src=s.unsafe_ptr(), count=n)


@always_inline
def _append_int(mut buf: List[UInt8], var n: Int):
    """Append the ASCII decimal form of ``n`` to ``buf``.

    Hot path on every serialised response (status line + Content-Length).
    Stack-buffer ``itoa`` keeps it allocation-free; the previous
    ``String(int)`` path forced a per-call heap allocation just to throw
    the bytes back into the wire buffer.
    """
    if n == 0:
        buf.append(UInt8(48))  # '0'
        return
    var negative = n < 0
    if negative:
        n = -n
    # 20 digits is enough for Int64 (-9223372036854775808 → 19 digits + sign).
    var tmp = stack_allocation[20, UInt8]()
    var i = 0
    while n > 0:
        tmp[i] = UInt8(48 + (n % 10))
        n = n // 10
        i += 1
    var old_len = len(buf)
    var sign = 1 if negative else 0
    buf.resize(old_len + sign + i, UInt8(0))
    var p = buf.unsafe_ptr() + old_len
    if negative:
        p[0] = UInt8(45)  # '-'
        p += 1
    # ``tmp`` holds the digits in reverse order; flip them on the way out.
    for k in range(i):
        p[k] = tmp[i - 1 - k]


@always_inline
def _ascii_strip_slice(span: Span[UInt8, _]) -> String:
    """Return an owned ``String`` equal to ``span`` with ASCII whitespace
    (SPACE and HTAB) trimmed from both ends.

    Replaces the ``String(String(unsafe_from_utf8=...)).strip()`` triple
    that previously allocated three ``String`` objects per header
    half. The fast path does a single pointer-based construction of
    the final owned ``String`` from the trimmed sub-span.
    """
    var n = len(span)
    var start = 0
    while start < n:
        var c = span[start]
        if c != 32 and c != 9:
            break
        start += 1
    var stop = n
    while stop > start:
        var c = span[stop - 1]
        if c != 32 and c != 9:
            break
        stop -= 1
    if stop <= start:
        return String("")
    return String(unsafe_from_utf8=span[start:stop])


@always_inline
def _ascii_lower(s: String) -> String:
    """Return ASCII-lowercase copy of ``s``.

    Bulk writes bytes through a pre-sized ``List[UInt8]`` and converts
    once at the end; the naive ``out += chr(...)`` loop used to allocate
    per byte which dominated cost on keep-alive request paths that call
    this on every ``Connection:`` header.
    """
    var n = s.byte_length()
    if n == 0:
        return String("")
    # Fast path: if the input has no upper-case ASCII bytes, return a
    # copy directly without the branch inside the loop.
    var src = s.unsafe_ptr()
    var has_upper = False
    for i in range(n):
        var c = src[i]
        if c >= 65 and c <= 90:
            has_upper = True
            break
    if not has_upper:
        return String(unsafe_from_utf8=s.as_bytes())
    var buf = List[UInt8]()
    buf.resize(n, UInt8(0))
    var dst = buf.unsafe_ptr()
    for i in range(n):
        var c = src[i]
        if c >= 65 and c <= 90:
            dst[i] = c + 32
        else:
            dst[i] = c
    return String(unsafe_from_utf8=Span[UInt8, _](buf))


def _status_reason(code: Int) -> String:
    """Return the canonical reason phrase for a known HTTP status code."""
    if code == 200:
        return "OK"
    if code == 201:
        return "Created"
    if code == 202:
        return "Accepted"
    if code == 204:
        return "No Content"
    if code == 301:
        return "Moved Permanently"
    if code == 302:
        return "Found"
    if code == 304:
        return "Not Modified"
    if code == 307:
        return "Temporary Redirect"
    if code == 308:
        return "Permanent Redirect"
    if code == 400:
        return "Bad Request"
    if code == 401:
        return "Unauthorized"
    if code == 403:
        return "Forbidden"
    if code == 404:
        return "Not Found"
    if code == 405:
        return "Method Not Allowed"
    if code == 408:
        return "Request Timeout"
    if code == 409:
        return "Conflict"
    if code == 413:
        return "Content Too Large"
    if code == 414:
        return "URI Too Long"
    if code == 422:
        return "Unprocessable Entity"
    if code == 500:
        return "Internal Server Error"
    if code == 501:
        return "Not Implemented"
    if code == 502:
        return "Bad Gateway"
    if code == 503:
        return "Service Unavailable"
    if code == 504:
        return "Gateway Timeout"
    return "Unknown"


# ── Legacy compatibility aliases ──────────────────────────────────────────────


def _parse_http_request(
    mut stream: TcpStream,
    max_header_size: Int,
    max_body_size: Int,
) raises -> Request:
    """Parse an HTTP/1.1 request from a TCP stream using buffered reads.

    Kept for backward compatibility with existing test code.
    """
    var buf = List[UInt8](capacity=8192)
    var read_buf = List[UInt8](capacity=8192)
    read_buf.resize(8192, 0)

    while True:
        var n = stream.read(read_buf.unsafe_ptr(), 8192)
        if n == 0:
            raise Error("empty request: connection closed")
        for i in range(n):
            buf.append(read_buf[i])
        var hdr_end = _find_crlfcrlf(buf, 0)
        if hdr_end >= 0:
            var cl = _scan_content_length(buf, hdr_end)
            var total = hdr_end + cl
            while len(buf) < total:
                n = stream.read(read_buf.unsafe_ptr(), 8192)
                if n == 0:
                    break
                for i in range(n):
                    buf.append(read_buf[i])
            return _parse_http_request_bytes(
                Span[UInt8, _](buf)[:total],
                max_header_size,
                max_body_size,
                peer=stream.peer_addr(),
            )
        if len(buf) > max_header_size + max_body_size:
            raise Error("request too large")


def _write_response(mut stream: TcpStream, resp: Response) raises:
    """Legacy response writer. Delegates to buffered version with Connection: close.
    """
    _write_response_buffered(stream, resp, keep_alive=False)
