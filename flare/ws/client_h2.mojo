"""WebSocket-over-HTTP/2 stream <-> frame adapter (RFC 8441).

This module bolts the WebSocket framing layer (`flare.ws.frame`) on
top of a single HTTP/2 stream driven by
`flare.http2.client.Http2ClientConnection`. It ships the *primitive*
for WS-over-h2 -- the high-level ALPN-driven
`WsClient.prefer_h2 = True` dispatcher, the Extended CONNECT
200-response wait, and the nghttp2/browser-interop test suite are
tracked as follow-up work in `docs/features.md`.

Design constraints (RFC 8441 §5):

- The HTTP/2 stream replaces the HTTP/1.1 socket; WS frames travel
  inside DATA frames, never spanning HEADERS frames.
- A WS frame may be split across multiple DATA frames; conversely
  a single DATA frame may carry multiple WS frames. The adapter
  buffers receive bytes and pulls frames as they complete.
- The Extended CONNECT stream stays in the OPEN state for the
  whole tunnel lifetime. END_STREAM closes the WS connection
  cleanly; RST_STREAM maps to an abnormal WS close.
- Masking: RFC 6455 §5.3 mandates client->server masking *for the
  WS protocol*. RFC 8441 does not relax that requirement. We
  preserve it so the adapter is interchangeable with a plain
  HTTP/1.1 WS client at the frame layer.

Public surface:

- :class:`WsOverH2Stream` -- stateful wrapper around one h2 stream.
- :func:`bootstrap_ws_over_h2` -- helper to queue the Extended
  CONNECT request (HEADERS without END_STREAM) on a brand-new
  stream id.
"""

from std.testing import assert_true

from .frame import (
    WsFrame,
    WsOpcode,
    WsCloseCode,
    WsProtocolError,
    _DecodeResult,
)
from ..http2.client import Http2ClientConnection
from ..http2.hpack import HpackHeader


def bootstrap_ws_over_h2(
    mut conn: Http2ClientConnection,
    sid: Int,
    authority: String,
    path: String,
    sec_ws_key_b64: String,
    sec_ws_protocol: String = "",
    sec_ws_extensions: String = "",
    scheme: String = "https",
) raises -> None:
    """Open an Extended CONNECT stream for a WebSocket tunnel.

    Wraps :meth:`Http2ClientConnection.send_extended_connect` with
    the WebSocket-specific extra headers (RFC 8441 §5.1):

    - ``sec-websocket-version: 13`` (RFC 6455 §11.6)
    - ``sec-websocket-key: <base64 16-byte nonce>`` (RFC 6455 §11.3.1).
      Note: per RFC 8441 §5.1 the key is informational over h2 --
      the server is *not* required to compute the
      ``Sec-WebSocket-Accept`` hash. Provide one anyway for parity
      with HTTP/1.1 servers reused as h2 backends.
    - ``sec-websocket-protocol`` and ``sec-websocket-extensions``
      (optional sub-protocol / extension negotiation).

    The stream is left in OPEN state so the caller can pump WS
    frames via :class:`WsOverH2Stream` once the peer's HEADERS
    response (status :status = 200) has been received.

    The peer MUST have advertised
    ``SETTINGS_ENABLE_CONNECT_PROTOCOL = 1``; gate this call on
    :meth:`Http2ClientConnection.peer_supports_extended_connect`.

    Args:
        conn: The HTTP/2 client connection.
        sid: Stream id allocated via
            :meth:`Http2ClientConnection.next_stream_id`.
        authority: ``Host``-equivalent (e.g. ``"example.com"``).
        path: WebSocket resource path (e.g. ``"/chat"``).
        sec_ws_key_b64: Pre-computed base64 ``Sec-WebSocket-Key``.
        sec_ws_protocol: Optional sub-protocol token list.
        sec_ws_extensions: Optional extension offer list (e.g.
            ``"permessage-deflate"``).
        scheme: ``"http"`` or ``"https"`` (RFC 8441 §5.1).
    """
    if not conn.peer_supports_extended_connect():
        raise Error(
            "WS-over-h2: peer did not advertise"
            " SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (RFC 8441 §3)"
        )
    var extra = List[HpackHeader]()
    extra.append(HpackHeader("sec-websocket-version", "13"))
    extra.append(HpackHeader("sec-websocket-key", sec_ws_key_b64))
    if sec_ws_protocol.byte_length() > 0:
        extra.append(HpackHeader("sec-websocket-protocol", sec_ws_protocol))
    if sec_ws_extensions.byte_length() > 0:
        extra.append(HpackHeader("sec-websocket-extensions", sec_ws_extensions))
    conn.send_extended_connect(sid, scheme, authority, path, "websocket", extra)


struct WsOverH2Stream(Movable):
    """Stream-keyed adapter that turns an h2 stream into a WS tunnel.

    Owns the per-stream receive buffer (DATA frames are appended,
    WS frames are pulled out as they complete) and the outgoing
    masking-key state (a deterministic monotonic counter is fine
    here -- the over-the-wire mask is moot when h2 is itself
    over TLS, but we still emit it so the adapter is symmetrical
    with the h1 path).

    Lifetime: one instance per Extended CONNECT stream. The
    adapter does *not* drive the underlying h2 connection; the
    caller is responsible for feeding bytes into / draining bytes
    out of the connection. The adapter only reads
    ``conn.conn.streams[sid].data`` (and clears it after each
    successful decode) and pushes outgoing WS frames into
    ``conn.send_data``.
    """

    var stream_id: Int
    """The h2 stream id (must match the id used in
    :func:`bootstrap_ws_over_h2`)."""
    var read_buffer: List[UInt8]
    """Accumulated, undecoded receive bytes from
    :attr:`Stream.data`. Refilled on every :meth:`pull_frames`."""
    var mask_counter: UInt32
    """Monotonic counter used to derive a 4-byte masking key per
    outbound frame; sufficient when TLS already protects the
    wire. A future iteration will swap this for a CSPRNG-derived
    key."""
    var closed: Bool
    """Set to ``True`` after a CLOSE frame is sent or received.
    Subsequent send/recv attempts raise."""

    def __init__(out self, stream_id: Int):
        """Create an adapter bound to ``stream_id``.

        Args:
            stream_id: The h2 stream id for the Extended CONNECT
                tunnel; allocate via
                :meth:`Http2ClientConnection.next_stream_id`.
        """
        self.stream_id = stream_id
        self.read_buffer = List[UInt8]()
        self.mask_counter = 1
        self.closed = False

    # ── Send path ────────────────────────────────────────────────

    def send_frame(
        mut self, mut conn: Http2ClientConnection, frame: WsFrame
    ) raises -> None:
        """Encode ``frame`` and queue it as a DATA frame on this
        stream.

        Per RFC 6455 §5.3 we mask the payload (mandatory on the
        client side); the masking key is a 32-bit counter rotated
        on every send. The ``end_stream`` flag is set IFF the
        frame is a CLOSE frame, which mirrors RFC 8441 §5.5
        ("close handshake completion translates to half-close").

        Args:
            conn: The HTTP/2 client connection.
            frame: The WS frame to send.
        """
        if self.closed:
            raise Error("WsOverH2Stream: send on closed stream")
        var k0 = UInt8((self.mask_counter >> 24) & 0xFF)
        var k1 = UInt8((self.mask_counter >> 16) & 0xFF)
        var k2 = UInt8((self.mask_counter >> 8) & 0xFF)
        var k3 = UInt8(self.mask_counter & 0xFF)
        self.mask_counter += 1
        var key = SIMD[DType.uint8, 4](k0, k1, k2, k3)
        var wire = frame.encode_with_key(True, key)
        var end = frame.opcode == WsOpcode.CLOSE
        conn.send_data(self.stream_id, Span[UInt8, _](wire), end)
        if end:
            self.closed = True

    # ── Receive path ─────────────────────────────────────────────

    def _drain_stream_data(
        mut self, mut conn: Http2ClientConnection
    ) raises -> None:
        """Move any bytes accumulated in ``Stream.data`` for our
        stream into :attr:`read_buffer` and clear the source.
        """
        if self.stream_id not in conn.conn.streams:
            return
        var s = conn.conn.streams[self.stream_id].copy()
        var n = len(s.data)
        if n == 0:
            return
        for i in range(n):
            self.read_buffer.append(s.data[i])
        s.data = List[UInt8]()
        conn.conn.streams[self.stream_id] = s^

    def try_pull_frame(
        mut self, mut conn: Http2ClientConnection
    ) raises -> Optional[WsFrame]:
        """Drain the stream's DATA buffer and decode at most one
        complete WS frame.

        Returns ``None`` if the buffer doesn't yet hold a full
        frame (call again once more bytes have been fed). Returns
        the next ``WsFrame`` otherwise; callers loop until ``None``
        to flush all frames waiting in this stream.

        RFC 6455 §5.5 CLOSE frames flip :attr:`closed` so the
        caller can treat the next outbound send as illegal and
        the next inbound poll as EOF.

        Args:
            conn: The HTTP/2 client connection.
        """
        self._drain_stream_data(conn)
        if len(self.read_buffer) == 0:
            return None
        var slice = Span[UInt8, _](self.read_buffer)
        var dr: _DecodeResult
        try:
            dr = WsFrame.decode_one(slice)
        except e:
            # Distinguish "short read" (need more bytes -- bail and
            # wait) from "protocol violation" (re-raise).
            var msg = String(e)
            if msg.find("decode_one: need") >= 0 or msg.find("truncated") >= 0:
                return None
            raise e^
        var consumed = dr.consumed
        var got = dr^.take_frame()
        if got.opcode == WsOpcode.CLOSE:
            self.closed = True
        # Compact: drop the consumed prefix.
        var rest = List[UInt8]()
        for i in range(consumed, len(self.read_buffer)):
            rest.append(self.read_buffer[i])
        self.read_buffer = rest^
        return got^

    def is_closed(imm self) -> Bool:
        """Return ``True`` once a CLOSE frame has been sent or
        received on this stream. Used by the caller to stop
        pumping after the close handshake completes."""
        return self.closed

    def close(
        mut self,
        mut conn: Http2ClientConnection,
        code: UInt16 = WsCloseCode.NORMAL,
        reason: String = "",
    ) raises -> None:
        """Send a WS CLOSE frame and END_STREAM the h2 stream
        atomically.

        After this call :attr:`closed` is ``True`` and further
        :meth:`send_frame` invocations raise. The caller is still
        responsible for draining any in-flight CLOSE response
        from the peer (RFC 6455 §5.5.1: the responder echoes the
        code + reason when it acknowledges).

        Args:
            conn: The HTTP/2 client connection.
            code: Close status code (default
                :attr:`WsCloseCode.NORMAL`).
            reason: UTF-8 reason phrase (<= 123 bytes).
        """
        if self.closed:
            return
        var f = WsFrame.close(code, reason)
        self.send_frame(conn, f)
