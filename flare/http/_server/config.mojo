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
from std.collections import Optional

from ..proto.h1_leniency import H1LeniencyConfig
from ..proto.h2_config import Http2Config

# WebSocket upgrade seam. ``WsConnection`` is named here so
# :attr:`WsUpgrade.handler` can carry the per-connection callback.
# No import cycle: ``flare.ws.server`` reaches into ``flare.http`` only
# for ``flare.http.response`` (a leaf) -- never for the server or this
# package.
from ...ws.server import WsConnection

comptime WsHandlerFn = def(mut WsConnection) raises thin -> None
"""The opt-in WebSocket handler signature. Identical to
``WsServer.serve``'s callback, so a handler written for a standalone
``WsServer`` plugs into ``HttpServer.serve_ws_upgrade`` unchanged."""


@fieldwise_init
struct WsUpgrade(Copyable, Defaultable):
    """Opt-in WebSocket upgrade handling on the same port as HTTP.

    Set ``handler`` and any request arriving with a valid RFC 6455
    upgrade is routed to it, while everything else goes to the ordinary
    ``Handler``. ``offload`` moves each upgraded socket onto its own
    detached thread, which suits long-lived connections that would
    otherwise hold a reactor slot for their whole lifetime.

    Grouped into one struct in v0.11: these were two loose fields on
    ``ServerConfig``, which made it easy to set the handler and forget
    the offload flag existed.
    """

    var handler: Optional[WsHandlerFn]
    """The upgrade handler, or ``None`` to serve HTTP only."""

    var offload: Bool
    """Run each upgraded socket on its own detached thread."""

    def __init__(out self):
        """No WebSocket handling."""
        self.handler = None
        self.offload = False

    def __init__(out self, handler: WsHandlerFn, offload: Bool = False):
        """Handle WebSocket upgrades with ``handler``.

        Args:
            handler: Called once per upgraded connection.
            offload: Give each socket its own detached thread.
        """
        self.handler = Optional[WsHandlerFn](handler)
        self.offload = offload


struct ServerConfig(Copyable):
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
    var ws: WsUpgrade
    """WebSocket-on-the-same-port configuration. Default: HTTP only.

    Replaces the loose ``ws_handler`` / ``ws_offload`` fields in v0.11.
    ``HttpServer.serve_ws_upgrade`` sets this for you."""

    var h2: Http2Config
    """HTTP/2 SETTINGS and per-stream limits, applied when a connection
    negotiates h2 by ALPN or upgrades via h2c.

    Replaces the ``h2_config`` argument that every ``bind*`` used to
    take separately in v0.11."""

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
        var ws: WsUpgrade = WsUpgrade(),
        var h2: Http2Config = Http2Config(),
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
        self.ws = ws^
        self.h2 = h2^

    @staticmethod
    def check[cfg: ServerConfig]() -> None:
        """Validate a comptime ``ServerConfig`` at compile time.

        Every invariant is a ``comptime assert``, so a configuration
        that violates one fails the build with the message below rather
        than misbehaving at run time. The deadline ordering is the one
        worth stating out loud: when ``request_timeout_ms`` is enabled it
        must bound both ``handler_timeout_ms`` and
        ``read_body_timeout_ms``, or the handler could keep working past
        the request deadline -- the bug these checks exist to prevent.

        Added in v0.11. These lived inside ``HttpServer.serve_comptime``,
        which meant the only way to get them was to also accept that
        method's single-worker, single-listener, no-TLS reactor. They are
        reusable now.

        Parameters:
            cfg: The configuration to validate.

        Example:
            ```mojo
            comptime CFG = ServerConfig(max_body_size=1 << 20)
            ServerConfig.check[CFG]()
            ```
        """
        comptime assert (
            cfg.read_buffer_size > 0
        ), "ServerConfig.read_buffer_size must be > 0"
        comptime assert (
            cfg.max_header_size > 0
        ), "ServerConfig.max_header_size must be > 0"
        comptime assert (
            cfg.max_uri_length > 0
        ), "ServerConfig.max_uri_length must be > 0"
        comptime assert (
            cfg.max_body_size >= cfg.max_header_size
        ), "ServerConfig.max_body_size must be >= ServerConfig.max_header_size"
        comptime assert (
            cfg.max_keepalive_requests >= 1
        ), "ServerConfig.max_keepalive_requests must be >= 1"
        comptime assert (
            cfg.idle_timeout_ms >= 0
        ), "ServerConfig.idle_timeout_ms must be >= 0"
        comptime assert (
            cfg.write_timeout_ms >= 0
        ), "ServerConfig.write_timeout_ms must be >= 0"
        comptime assert (
            cfg.read_body_timeout_ms >= 0
        ), "ServerConfig.read_body_timeout_ms must be >= 0 (0 disables)"
        comptime assert (
            cfg.handler_timeout_ms >= 0
        ), "ServerConfig.handler_timeout_ms must be >= 0 (0 disables)"
        comptime assert (
            cfg.request_timeout_ms >= 0
        ), "ServerConfig.request_timeout_ms must be >= 0 (0 disables)"
        # When request_timeout_ms is non-zero (enabled), it must
        # bound the per-handler and per-body deadlines so the
        # outer-most reactor deadline is the last to fire. A
        # request_timeout_ms shorter than handler_timeout_ms would
        # let the handler keep working past the request deadline,
        # which is the bug we're trying to prevent.
        comptime assert (
            cfg.request_timeout_ms == 0
            or cfg.handler_timeout_ms == 0
            or cfg.request_timeout_ms >= cfg.handler_timeout_ms
        ), (
            "ServerConfig.request_timeout_ms must be >="
            " ServerConfig.handler_timeout_ms (or one must be 0 to"
            " disable)"
        )
        comptime assert (
            cfg.request_timeout_ms == 0
            or cfg.read_body_timeout_ms == 0
            or cfg.request_timeout_ms >= cfg.read_body_timeout_ms
        ), (
            "ServerConfig.request_timeout_ms must be >="
            " ServerConfig.read_body_timeout_ms (or one must be 0 to"
            " disable)"
        )


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
