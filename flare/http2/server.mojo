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

from flare.http import HeaderMap, Method, Request, Response

from .frame import (
    Frame,
    FrameFlags,
    FrameType,
    H2_PREFACE,
    encode_frame,
    parse_frame,
)
from .hpack import HpackHeader
from .state import Connection, Stream, StreamState


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

    def __init__(out self):
        self.conn = Connection()
        self.inbox = List[UInt8]()
        self.outbox = List[UInt8]()
        self.greeted = False

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
        lifetime in the v0.6 server (no trailers, no streaming
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
