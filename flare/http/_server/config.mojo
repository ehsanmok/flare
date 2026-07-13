"""``flare.http._server.config`` -- HTTP server configuration carrier.

The :class:`ServerConfig` value type (read/buffer sizing, timeouts,
keep-alive policy, leniency + bufring toggles) plus the startup
``FLARE_BUFRING_HANDLER`` env read and the comptime default used by
``HttpServer.serve_comptime``. Extracted from ``flare.http.server`` to
keep the reactor module within the file-size budget;
``flare.http.server`` re-exports every name so existing
``from flare.http.server import ServerConfig`` call sites keep
resolving unchanged.
"""

from std.os import getenv

from ..proto.h1_leniency import H1LeniencyConfig


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
            echoing it back.
        read_body_timeout_ms: Max ms allowed between headers-end and the
            last body byte (default 30_000). 0 disables. Guards the
            slow-body-upload variant of the slow-client DoS surface.
            Mirrors nginx's ``client_body_timeout``.
        handler_timeout_ms: Max ms ``Handler.serve`` (or
            ``CancelHandler.serve``) is allowed to run before the
            reactor flips ``Cancel.TIMEOUT`` (default 30_000). 0
            disables. Cooperative — the handler observes the flip on
            its next ``cancel.cancelled()`` poll. Guards the
            handler-watchdog variant of the slow-client DoS surface.
        request_timeout_ms: Max ms wall-time from request line in to
            response bytes out (default 60_000). 0 disables. The
            reactor enforces this as the outermost deadline; the
            other two cooperate via ``Cancel``. Must be >=
            ``handler_timeout_ms`` and >=
            ``read_body_timeout_ms`` (checked at compile time in
            ``serve_comptime``).
        use_bufring: Opt into the io_uring buffer-ring single-worker
            reactor (HTTP/1.1-only, single-listener-only) on Linux
            ``>= 6.0``. When ``False`` (default), every entry point
            consults the ``FLARE_BUFRING_HANDLER=1`` env var **once
            at startup** and OR-equals the result into this field;
            subsequent dispatch decisions read this field directly.
            That guarantees a runtime flip of the env var mid-flight
            cannot reroute live connections.
        h1_leniency: HTTP/1.1 parser leniency configuration. Strict
            by default (every flag off); each named flag relaxes a
            specific RFC 9112 grammar branch. See
            :class:`flare.http.proto.H1LeniencyConfig` for the per-
            flag contract. The strict default is the production-safe
            pick; flip individual flags only when a trusted upstream
            cannot avoid the corresponding relaxation.
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
    var skip_header_decode_for_short_requests: Bool
    """When True, the parser skips the per-request ``HeaderMap``
    build for requests whose handler doesn't read headers.
    Header bytes are still scanned (RAW) for ``Content-Length``
    (so body framing stays correct) and for ``Connection: close``
    (so keep-alive policy stays correct), but per-header
    ``String`` allocations + the ``HeaderMap`` itself are elided.
    ``Request.headers`` is an empty ``HeaderMap`` -- handlers
    that read headers will see an empty map and silently break,
    so this opt-in is appropriate ONLY for handlers known to
    ignore headers (TFB plaintext, fixed health-checks,
    low-latency micro-services).

    Default ``False`` -- the standard full-parse behaviour.
    Set ``True`` on production servers whose handler shape
    doesn't depend on headers."""
    var use_bufring: Bool
    """Opt into the io_uring buffer-ring single-worker reactor.

    Defaults to ``False``. ``HttpServer.serve`` and
    ``Scheduler.start`` consult ``FLARE_BUFRING_HANDLER=1``
    once at startup and ``or``-equal the result into this
    field; downstream dispatch reads this field directly so
    a mid-flight env-var flip cannot reroute live connections.
    Linux-only, HTTP/1.1-only, single-listener-only -- the
    field is silently ignored on macOS / for HTTP/2 / for
    ``HttpServer.bind_many``."""
    var h1_leniency: H1LeniencyConfig
    """HTTP/1.1 parser leniency configuration. Strict by default
    (every flag off); each named flag relaxes a specific RFC 9112
    grammar branch. See :class:`flare.http.proto.H1LeniencyConfig`
    for the per-flag contract."""
    var max_connections: Int
    """Accept-path admission cap: the maximum number of concurrent
    connections a single reactor worker will hold. ``0`` (default)
    means unlimited. When the live count reaches the cap the accept
    drainer stops pulling new connections (kernel backpressure via
    the listen backlog) rather than growing the per-worker table
    without bound; accepting resumes as slots free. Bounds the
    file-descriptor-exhaustion / connection-flood DoS surface on the
    plain Handler path, mirroring what the streaming path already
    does with its own 503 + Retry-After shed."""

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
        skip_header_decode_for_short_requests: Bool = False,
        use_bufring: Bool = False,
        var h1_leniency: H1LeniencyConfig = H1LeniencyConfig(),
        max_connections: Int = 0,
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
        self.skip_header_decode_for_short_requests = (
            skip_header_decode_for_short_requests
        )
        self.use_bufring = use_bufring
        self.h1_leniency = h1_leniency^
        self.max_connections = max_connections


def _resolve_bufring_handler_env() -> Bool:
    """Read ``FLARE_BUFRING_HANDLER`` once at startup.

    The env-var read lives at the entry point of every reactor
    loop overload; consumers (the reactor loops, the scheduler
    workers) then read ``ServerConfig.use_bufring`` directly so
    a mid-flight ``setenv`` cannot reroute live connections.
    """
    return getenv("FLARE_BUFRING_HANDLER") == "1"


# Comptime-friendly default config. Used as the default for
# ``HttpServer.serve_comptime[handler, config = ...]()``. Any user who
# wants a non-default comptime config must declare their own
# ``comptime my_cfg: ServerConfig = ServerConfig(...)`` because Mojo
# ``comptime assert`` checks need comptime-stable values.
comptime _DEFAULT_SERVER_CONFIG: ServerConfig = ServerConfig()
