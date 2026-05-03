"""HTTP/2 server glue (RFC 9113).

Connects :mod:`flare.http2.frame` + :mod:`flare.http2.hpack` +
:mod:`flare.http2.state` to flare's existing ``Handler`` interface.

The high-level surface:

- :class:`H2Connection` — a synchronous, buffer-driven driver. The
  caller feeds it inbound bytes (``feed``) and pulls outbound bytes
  (``drain``). When a stream's request is complete, :meth:`take_request`
  yields a :class:`flare.http.Request` ready for a normal Handler.
  After the handler produces a :class:`flare.http.Response`,
  :meth:`emit_response` schedules the appropriate ``HEADERS [+ DATA]``
  frames.

- :func:`detect_h2c_upgrade` — sniff an inbound HTTP/1.1 request for
  ``Connection: Upgrade, HTTP2-Settings`` + ``Upgrade: h2c`` and
  return ``True`` when the connection should switch protocols. The
  caller is responsible for emitting the 101 response and then
  driving the connection through :class:`H2Connection`.

- :func:`is_h2_alpn` — string match for ``"h2"`` so TLS code paths
  can dispatch from ALPN.

This is enough to ship a working server today while preserving the
plumbing for a future async / reactor integration: the driver does
not own its sockets, so the same code works in a unit test that
shoves bytes through it directly *and* in the reactor's per-fd
callback.
"""

from std.collections import Dict, Optional
from std.memory import stack_allocation

from flare.http import HeaderMap, Method, Request, Response
from flare.http.handler import Handler
from flare.tcp import TcpListener, TcpStream
from flare.net import SocketAddr

from .frame import (
    Frame,
    FrameFlags,
    FrameType,
    H2_DEFAULT_FRAME_SIZE,
    H2_PREFACE,
    encode_frame,
    parse_frame,
)
from .hpack import HpackHeader
from .state import Connection, Stream, StreamState


# ── Http2Config ─────────────────────────────────────────────────────────────


comptime _H2_DEFAULT_MAX_CONCURRENT_STREAMS: Int = 100
"""RFC 9113 §5.1.2 has no protocol default; flare ships 100 to bound
per-connection memory under adversarial peers without breaking
common interactive workloads (a browser tab opening ~6 parallel
sub-requests sits well below this)."""

comptime _H2_DEFAULT_INITIAL_WINDOW_SIZE: Int = 65535
"""RFC 9113 §6.5.2 mandates 65535 as the default for new streams
until SETTINGS negotiates a different value. ``Http2Config`` ships
the same number so the default ``Http2Config()`` is observably
identical to the v0.6 ``H2Connection()`` shape."""

comptime _H2_DEFAULT_MAX_FRAME_SIZE: Int = 16384
"""RFC 9113 §6.5.2 mandates 16384 (2^14) as both the protocol
default and the minimum any peer must accept."""

comptime _H2_DEFAULT_MAX_HEADER_LIST_SIZE: Int = 8192
"""RFC 9113 §6.5.2 default is unbounded; flare ships 8192 (8 KiB)
because every production proxy / origin we'd reasonably ship behind
caps the header list aggressively to defang request smuggling +
header pollution shaped at h2."""

comptime _H2_DEFAULT_HEADER_TABLE_SIZE: Int = 4096
"""RFC 7541 §4.2 default for the HPACK dynamic table size."""


@fieldwise_init
struct Http2Config(Copyable, Defaultable, Movable):
    """Tunable HTTP/2 SETTINGS for an :class:`H2Connection`.

    All five fields map 1:1 to RFC 9113 §6.5.2 SETTINGS identifiers
    (plus the RFC 7541 HPACK header-table size). Defaults are the
    production-shape numbers flare's reactor wiring uses for both
    the inline test driver in :mod:`tests.test_h2_server` and the
    reactor-attached driver.

    The ``allow_huffman_decode`` flag gates HPACK Huffman decoding
    on the inbound HEADERS path. The H=0-only encoder + raw-literal
    decoder is CRIME-class-side-channel-free by construction; the
    scalar Huffman decoder is gated behind this flag (default
    ``False``) until soak data justifies flipping it default-on.

    Example:

    ```mojo
    from flare.http2 import H2Connection, Http2Config

    var cfg = Http2Config(
        max_concurrent_streams=200,
        initial_window_size=131072,
        max_frame_size=32768,
        max_header_list_size=16384,
        header_table_size=8192,
        allow_huffman_decode=False,
    )
    var conn = H2Connection.with_config(cfg)
    ```

    Fields:
        max_concurrent_streams: SETTINGS_MAX_CONCURRENT_STREAMS
            (RFC 9113 §6.5.2). Bounds the per-connection live-stream
            count.
        initial_window_size: SETTINGS_INITIAL_WINDOW_SIZE
            (RFC 9113 §6.5.2). Per-stream flow-control receive
            window the server advertises on inbound connections.
            Must be ``<= 2^31 - 1`` per RFC 9113 §6.9.2.
        max_frame_size: SETTINGS_MAX_FRAME_SIZE (RFC 9113 §6.5.2).
            Largest frame payload the server is willing to accept.
            Must be in ``[16384, 16777215]`` per RFC 9113 §6.5.2.
        max_header_list_size: SETTINGS_MAX_HEADER_LIST_SIZE
            (RFC 9113 §6.5.2). Header-list size cap (uncompressed,
            including 32-byte per-entry overhead).
        header_table_size: SETTINGS_HEADER_TABLE_SIZE (RFC 7541
            §4.2). HPACK dynamic-table size budget.
        allow_huffman_decode: When ``True``, the HPACK decoder
            accepts H=1 literals (Huffman-encoded). Defaults to
            ``False`` -- reject-by-default until soak data
            justifies flipping it on.
    """

    var max_concurrent_streams: Int
    var initial_window_size: Int
    var max_frame_size: Int
    var max_header_list_size: Int
    var header_table_size: Int
    var allow_huffman_decode: Bool

    def __init__(out self):
        """Default to the production-shape SETTINGS pinned in
        the design doc: 100 concurrent streams, 64 KiB-1 initial
        window, 16 KiB max frame, 8 KiB max header list, 4 KiB
        HPACK dynamic table, Huffman-decode disabled (v0.6 safe
        default).
        """
        self.max_concurrent_streams = _H2_DEFAULT_MAX_CONCURRENT_STREAMS
        self.initial_window_size = _H2_DEFAULT_INITIAL_WINDOW_SIZE
        self.max_frame_size = _H2_DEFAULT_MAX_FRAME_SIZE
        self.max_header_list_size = _H2_DEFAULT_MAX_HEADER_LIST_SIZE
        self.header_table_size = _H2_DEFAULT_HEADER_TABLE_SIZE
        self.allow_huffman_decode = False

    def validate(self) raises -> None:
        """Raise if any field violates the RFC 9113 / RFC 7541 bounds.

        The reactor-side wiring calls this once at acceptor handoff
        so a misconfigured server fails fast at boot rather than
        emitting malformed SETTINGS frames mid-handshake.
        """
        if self.max_concurrent_streams < 0:
            raise Error("Http2Config: max_concurrent_streams must be >= 0")
        if self.initial_window_size < 0:
            raise Error("Http2Config: initial_window_size must be >= 0")
        if self.initial_window_size > 0x7FFFFFFF:
            raise Error(
                "Http2Config: initial_window_size must be <= 2^31-1"
                " (RFC 9113 §6.9.2)"
            )
        if self.max_frame_size < H2_DEFAULT_FRAME_SIZE:
            raise Error(
                "Http2Config: max_frame_size must be >= 16384 (RFC 9113 §6.5.2)"
            )
        if self.max_frame_size > 16777215:
            raise Error(
                "Http2Config: max_frame_size must be <= 2^24-1"
                " (RFC 9113 §6.5.2)"
            )
        if self.max_header_list_size < 0:
            raise Error("Http2Config: max_header_list_size must be >= 0")
        if self.header_table_size < 0:
            raise Error("Http2Config: header_table_size must be >= 0")


# ── ALPN / h2c detection ────────────────────────────────────────────────


def is_h2_alpn(alpn: String) -> Bool:
    """Return True when the negotiated ALPN protocol is HTTP/2."""
    return alpn == "h2"


def detect_h2c_upgrade(headers: HeaderMap) -> Bool:
    """RFC 9113 §3.2 — detect inbound ``Upgrade: h2c`` request.

    The full RFC requires ``HTTP2-Settings: <base64>``
    too; we accept the upgrade as long as both ``Upgrade: h2c``
    and ``HTTP2-Settings`` are present. The decoded ``HTTP2-Settings``
    payload is fed into the connection during initialisation by the
    caller via :meth:`H2Connection.feed_settings_payload`.
    """
    var upg = headers.get("upgrade")
    if upg.byte_length() == 0:
        return False
    if upg != "h2c":
        return False
    var s = headers.get("http2-settings")
    return s.byte_length() > 0


# ── H2Connection driver ─────────────────────────────────────────────────


struct H2Connection(Defaultable, Movable):
    """Synchronous HTTP/2 driver with separate I/O sides.

    A pure state object: the caller drives I/O. It exposes:

    - :meth:`feed` — push inbound bytes; returns any reply frames
      (already encoded) that the state machine generated.
    - :meth:`drain` — pull queued outbound frames as bytes.
    - :meth:`take_completed_streams` — pop ids whose request is
      ready for handler dispatch.
    - :meth:`take_request` — convert one stream into a plain
      ``Request`` (a :class:`flare.http.Request`).
    - :meth:`emit_response` — schedule the response frames for a
      finished handler invocation.
    """

    var conn: Connection
    var inbox: List[UInt8]
    var outbox: List[UInt8]
    var greeted: Bool
    var config: Http2Config
    """The :class:`Http2Config` the driver was constructed with.
    Kept on the driver so the reactor wiring can re-read
    individual fields per-stream (e.g. the
    ``max_header_list_size`` cap when applying inbound HEADERS)
    without threading it through every per-frame call site."""

    def __init__(out self):
        """Default-construct with :class:`Http2Config` defaults.

        Equivalent to ``H2Connection.with_config(Http2Config())``;
        kept as a separate ``__init__`` so callers (``H2Connection()``
        in tests + the inline driver) work byte-for-byte without
        an explicit config argument.
        """
        self.conn = Connection()
        self.inbox = List[UInt8]()
        self.outbox = List[UInt8]()
        self.greeted = False
        self.config = Http2Config()

    @staticmethod
    def with_config(var config: Http2Config) raises -> H2Connection:
        """Construct an :class:`H2Connection` whose underlying
        :class:`Connection` SETTINGS are populated from ``config``.

        Validates ``config`` first (RFC 9113 / RFC 7541 bounds);
        raises if any field is out of range. The resulting driver's
        first-emitted SETTINGS frame advertises
        ``max_concurrent_streams`` per the config; later inbound
        SETTINGS from the peer can lower the negotiated values per
        RFC 9113 §6.5.

        The HPACK dynamic-table size budget is propagated to the
        decoder. The ``allow_huffman_decode`` flag is stored on
        the driver but not yet acted on at the inbound HEADERS
        path -- Huffman-encoded literals on the inbound side
        currently raise reject-by-default until the scalar
        Huffman decoder is wired in.
        """
        config.validate()
        var out = H2Connection()
        out.config = config^
        out.conn.max_concurrent_streams = out.config.max_concurrent_streams
        out.conn.initial_window_size = out.config.initial_window_size
        out.conn.send_window = out.config.initial_window_size
        out.conn.recv_window = out.config.initial_window_size
        out.conn.max_frame_size = out.config.max_frame_size
        out.conn.max_header_list_size = out.config.max_header_list_size
        out.conn.hpack_decoder.max_size = out.config.header_table_size
        # The ``HpackEncoder`` is stateless (always emits H=0
        # raw literals; no dynamic table). The ``header_table_size``
        # field on ``Http2Config`` is consumed by the decoder side
        # only until the encoder grows a dynamic table. The peer's
        # announced HEADER_TABLE_SIZE is still honoured on inbound
        # SETTINGS via ``Connection.handle_frame``.
        return out^

    def _emit_initial_settings(mut self):
        """Server-side handshake: send our SETTINGS once."""
        if self.greeted:
            return
        var f = self.conn.initial_settings()
        var bytes = encode_frame(f)
        for i in range(len(bytes)):
            self.outbox.append(bytes[i])
        self.greeted = True

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Push ``data`` (bytes from the socket) into the driver."""
        for i in range(len(data)):
            self.inbox.append(data[i])

        # Strip the 24-byte preface once.
        if not self.conn.preface_seen:
            if len(self.inbox) < 24:
                return
            var preface = String(H2_PREFACE)
            var pp = preface.unsafe_ptr()
            for i in range(24):
                if self.inbox[i] != pp[i]:
                    raise Error("h2: bad preface")
            # Drop the preface from the inbox.
            var rest = List[UInt8](capacity=len(self.inbox) - 24)
            for i in range(24, len(self.inbox)):
                rest.append(self.inbox[i])
            self.inbox = rest^
            self.conn.preface_seen = True
            self._emit_initial_settings()

        # Drain frames until we run out of complete ones.
        while True:
            var span = Span[UInt8, _](self.inbox)
            var got = parse_frame(span)
            if not got:
                return
            var frame = got.value().copy()
            var consumed = 9 + frame.header.length
            var rest = List[UInt8](capacity=len(self.inbox) - consumed)
            for i in range(consumed, len(self.inbox)):
                rest.append(self.inbox[i])
            self.inbox = rest^
            var reply = self.conn.handle_frame(frame^)
            for i in range(len(reply)):
                var rb = encode_frame(reply[i])
                for j in range(len(rb)):
                    self.outbox.append(rb[j])

    def drain(mut self) -> List[UInt8]:
        """Return all queued outbound bytes and clear the buffer."""
        var out = self.outbox.copy()
        self.outbox = List[UInt8]()
        return out^

    def take_completed_streams(self) -> List[Int]:
        """Return stream ids whose request is fully buffered."""
        var ids = List[Int]()
        for entry in self.conn.streams.items():
            var s = entry.value.copy()
            if s.headers_complete and s.data_complete:
                ids.append(s.id)
        return ids^

    def take_request(mut self, sid: Int) raises -> Request:
        """Convert stream ``sid`` into a :class:`flare.http.Request`."""
        if sid not in self.conn.streams:
            raise Error("h2: take_request on unknown stream")
        var s = self.conn.streams[sid].copy()
        var req = Request(method="GET", url="/", version="HTTP/2")
        # Pseudo headers come first per RFC 9113 §8.1.2.1.
        for i in range(len(s.headers)):
            var n = s.headers[i].name
            var v = s.headers[i].value
            if n == ":method":
                req.method = v
            elif n == ":path":
                req.url = v
            elif n == ":authority":
                req.headers.set("Host", v)
            elif n == ":scheme":
                pass  # the reactor knows the scheme already
            else:
                req.headers.set(n, v)
        for i in range(len(s.data)):
            req.body.append(s.data[i])
        return req^

    def emit_response(mut self, sid: Int, var resp: Response) raises:
        """Encode + queue the response for ``sid``.

        The connection's stream state is advanced to ``CLOSED`` after
        the response is queued, mirroring HTTP/1.1's per-request
        lifetime in the server (no trailers, no streaming
        responses on h2 yet — those come with the reactor wiring).
        """
        if sid not in self.conn.streams:
            raise Error("h2: emit_response on unknown stream")
        # Build HpackHeader list from the response's HeaderMap.
        # HTTP/2 forbids ``Connection`` / ``Transfer-Encoding`` / ``Keep-Alive``
        # / ``Proxy-Connection`` / ``Upgrade`` per RFC 9113 §8.2.2.
        var hdrs = List[HpackHeader]()
        for i in range(len(resp.headers._keys)):
            var k = resp.headers._keys[i]
            var v = resp.headers._values[i]
            var lk = String(capacity=k.byte_length() + 1)
            var kp = k.unsafe_ptr()
            for j in range(k.byte_length()):
                var c = Int(kp[j])
                if c >= 65 and c <= 90:
                    lk += chr(c + 32)
                else:
                    lk += chr(c)
            if (
                lk == "connection"
                or lk == "transfer-encoding"
                or lk == "keep-alive"
                or lk == "proxy-connection"
                or lk == "upgrade"
            ):
                continue
            hdrs.append(HpackHeader(lk, v))
        var frames = self.conn.make_response(
            sid,
            resp.status,
            Span[HpackHeader, _](hdrs),
            Span[UInt8, _](resp.body),
        )
        for i in range(len(frames)):
            var bytes = encode_frame(frames[i])
            for j in range(len(bytes)):
                self.outbox.append(bytes[j])
        var s = self.conn.streams[sid].copy()
        s.state = StreamState.CLOSED()
        self.conn.streams[sid] = s^


# ── Http2Server (high-level handler-driven facade) ───────────────────────


comptime _H2_SERVER_READ_BUF_SIZE: Int = 16384
"""Per-syscall recv buffer size for the HTTP/2 server read loop.
16 KiB matches the RFC 9113 §6.5.2 default ``max_frame_size``."""


struct Http2Server(Movable):
    """A blocking HTTP/2 (h2c) server bound to one local address.

    The high-level handler-driven entry point that mirrors
    :class:`flare.http.HttpServer` for HTTP/2. Construct via
    :meth:`bind`, then call :meth:`serve` with any
    :class:`flare.http.Handler` (a plain ``def`` function, a
    :class:`flare.http.Router`, an :class:`flare.http.App[S]`, a
    middleware-wrapped handler, anything that satisfies the
    trait):

    ```mojo
    from flare.http2 import Http2Server
    from flare.http import Router, ok, Request, Response
    from flare.net import SocketAddr

    def hello(req: Request) raises -> Response:
        return ok("hello h2")

    def main() raises:
        var r = Router()
        r.get("/", hello)
        var srv = Http2Server.bind(SocketAddr.localhost(8080))
        srv.serve(r^)  # blocks; one connection at a time
    ```

    Scope (deliberately minimal cleartext-only h2c shape; the
    full reactor-integrated multi-worker variant is a follow-up):

    * **h2c via prior knowledge.** The client MUST send the
      RFC 9113 §3.5 connection preface immediately; the server
      does not implement the HTTP/1.1 ``Upgrade: h2c`` dance.
      For the upgrade dance, drive :class:`H2Connection`
      yourself inside an :class:`flare.http.HttpServer`
      handler that detects the upgrade and pivots.
    * **Single accept loop, blocking, one connection at a time.**
      Each connection runs to completion (peer closes) before
      the next is accepted. This is the symmetric counterpart
      to :meth:`flare.http.HttpServer.serve` *without*
      ``num_workers >= 2`` -- multi-worker + reactor
      integration lands in a follow-up that wires this through
      :class:`flare.runtime.Reactor` for non-blocking I/O.
    * **No TLS / ALPN.** ``https://`` h2 needs the same TLS
      acceptor wiring the existing :class:`flare.tls.TlsAcceptor`
      provides; for now route TLS through that and dispatch on
      ALPN via :func:`is_h2_alpn`.

    All of the request/response hot path (Router, App[S],
    typed extractors, middleware, Cookies, Sessions, content
    negotiation, Conditional middleware, structured logging,
    Prometheus metrics, auth extractors, templates, CSRF, ...)
    works unchanged because every higher-level construct
    operates on :class:`flare.http.Request` /
    :class:`flare.http.Response`, which is exactly what
    :meth:`H2Connection.take_request` /
    :meth:`H2Connection.emit_response` produces and consumes.
    """

    var _listener: TcpListener
    var _config: Http2Config
    var _stopping: Bool
    """Flag the caller can flip to stop the accept loop. The
    serve loop checks it between connections (not mid-request);
    a hard ``shutdown(SIGTERM)`` is the appropriate way to stop
    a blocking serve mid-request for now."""

    def __init__(
        out self,
        var listener: TcpListener,
        var config: Http2Config = Http2Config(),
    ):
        self._listener = listener^
        self._config = config^
        self._stopping = False

    @staticmethod
    def bind(
        addr: SocketAddr, var config: Http2Config = Http2Config()
    ) raises -> Http2Server:
        """Bind a TCP listener at ``addr`` and validate ``config``.

        Args:
            addr: Local address to bind (use
                :func:`flare.net.SocketAddr.localhost(port)` for a
                loopback-only server).
            config: HTTP/2 SETTINGS the server advertises to peers.
                Defaults to the same production-shape numbers
                :class:`H2Connection` uses.

        Returns:
            A bound :class:`Http2Server` ready to call
            :meth:`serve` on.

        Raises:
            Error: When the listener bind fails (port in use,
                permission denied, ...) or ``config`` is
                out-of-range.
        """
        config.validate()
        var l = TcpListener.bind(addr)
        return Http2Server(l^, config^)

    def serve(mut self, handler: def(Request) raises thin -> Response) raises:
        """Plain-function overload of :meth:`serve`.

        Pass any ``def(Request) raises -> Response`` and it will
        be wrapped in an :class:`flare.http.handler.FnHandler` so
        the :class:`flare.http.Handler` trait is satisfied. This
        is the symmetric counterpart to
        :meth:`flare.http.HttpServer.serve` for HTTP/2.

        Use the generic :meth:`serve[H]` overload below for
        :class:`flare.http.Router`, middleware-wrapped handlers,
        :class:`flare.http.App[S]`, or any other struct that
        implements :class:`flare.http.Handler` directly.
        """
        from flare.http.handler import FnHandler

        var h = FnHandler(handler)
        self.serve(h^)

    def serve[H: Handler](mut self, var handler: H) raises:
        """Run the accept loop, dispatching each request through ``handler``.

        Blocks until :attr:`_stopping` is set (or the process is
        signalled). One connection at a time:

        1. Accept.
        2. Construct an :class:`H2Connection` from
           :attr:`_config`.
        3. Read bytes from the socket, feed into the H2
           driver.
        4. For every completed stream: call
           ``handler.serve(req)``, hand the resulting
           :class:`flare.http.Response` to
           :meth:`H2Connection.emit_response`.
        5. Drain outbound bytes, write to the socket.
        6. Loop until ``read`` returns 0 (peer closed).
        """
        while not self._stopping:
            var stream = self._listener.accept()
            try:
                self._serve_one(stream^, handler)
            except:
                # A misbehaving connection MUST NOT take the
                # whole server down; log the error (eventually)
                # and accept the next one.
                pass

    def _serve_one[
        H: Handler
    ](mut self, var stream: TcpStream, ref handler: H) raises:
        """Drive one HTTP/2 connection until the peer closes.

        Helper for :meth:`serve`; factored out so the per-conn
        ``try / except`` boundary is easy to extend with
        per-request error reporting later.
        """
        var h2 = H2Connection.with_config(self._config.copy())
        var buf = stack_allocation[_H2_SERVER_READ_BUF_SIZE, UInt8]()
        while True:
            var n = stream.read(buf, _H2_SERVER_READ_BUF_SIZE)
            if n == 0:
                # Peer closed cleanly.
                return
            var slice = List[UInt8](capacity=n)
            for i in range(n):
                slice.append(buf[i])
            h2.feed(Span[UInt8, _](slice))
            # Drain every completed stream into the user's handler.
            var ids = h2.take_completed_streams()
            for i in range(len(ids)):
                var sid = ids[i]
                var req = h2.take_request(sid)
                var resp: Response
                try:
                    resp = handler.serve(req^)
                except:
                    # Convert an unhandled handler error into
                    # a 500 response with no body so the
                    # connection keeps multiplexing the
                    # rest of its streams.
                    resp = Response(status=500, reason="Internal Server Error")
                h2.emit_response(sid, resp^)
            # Push all queued outbound bytes (responses, plus
            # auto-emitted SETTINGS / SETTINGS-ACK / PING-ACK /
            # WINDOW_UPDATE) onto the wire.
            var out = h2.drain()
            if len(out) > 0:
                stream.write_all(Span[UInt8, _](out))

    def shutdown(mut self):
        """Set :attr:`_stopping` so the accept loop exits after the
        current connection completes."""
        self._stopping = True
