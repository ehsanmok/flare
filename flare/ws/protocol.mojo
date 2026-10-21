"""Sans-I/O WebSocket server protocol core (RFC 6455).

``WsProtocol`` takes the bytes a client sent and hands back complete
messages and the bytes to send in reply. Every carrier -- HTTP/1.1 on
the reactor, HTTP/2 and HTTP/3 tunnels -- drives the same state machine,
so they enforce the same rules:

- client frames must be masked (1002, sec 5.1);
- a frame's declared length is checked against the cap before its
  payload is buffered, and a reassembled message against the same cap
  before each fragment is appended (1009);
- a CONTINUATION needs a message to continue, and a new data frame may
  not start inside one (1002, sec 5.4);
- a text message must be UTF-8 as a whole (1007, sec 8.1);
- a PING is answered with a PONG; a PONG is ignored (sec 5.5.2-5.5.3);
- a CLOSE is answered once, echoing a valid code and replacing an
  invalid body with 1002 (sec 5.5.1, 7.4.1), and nothing is sent after
  a CLOSE;
- the queue of bytes waiting for the peer is bounded: past
  ``max_outbox`` the connection fails with 1008 rather than buffer
  without limit for a client that does not read.

A protocol violation does not raise. The core queues the CLOSE the RFC
calls for and reports a ``WS_EVENT_CLOSED`` event carrying that code;
the carrier flushes ``outbox`` and drops the connection.
"""

from .frame import (
    DEFAULT_MAX_FRAME_BYTES,
    WS_TOO_BIG_MARKER,
    WsCloseCode,
    WsFrame,
    WsOpcode,
    _is_valid_utf8,
    ws_frame_length,
)

comptime WS_EVENT_MESSAGE: Int = 1
comptime WS_EVENT_CLOSED: Int = 2

comptime DEFAULT_MAX_OUTBOX_BYTES: Int = 4 * 1024 * 1024
"""Bytes a connection may hold for a peer that is not reading."""


def _valid_close_code(code: Int) -> Bool:
    """Whether ``code`` may appear in a received CLOSE frame.

    RFC 6455 sec 7.4.1 defines 1000-1003 and 1007-1011, the IANA registry
    adds 1012-1014, and 3000-4999 are for libraries and applications. The
    reserved 1004, 1005, 1006 and 1015 must never be sent on the wire.
    """
    return (
        (code >= 1000 and code <= 1003)
        or (code >= 1007 and code <= 1014)
        or (code >= 3000 and code <= 4999)
    )


def _close_reply_payload(body: List[UInt8]) -> List[UInt8]:
    """The body of the CLOSE that answers a received CLOSE with ``body``.

    An empty body is echoed empty and a valid one echoes its status code
    (RFC 6455 sec 5.5.1). A 1-byte body, an invalid code or a reason that
    is not UTF-8 is a protocol error (sec 7.1.7, 7.4.1) and is answered
    with 1002.
    """
    var out = List[UInt8]()
    if len(body) == 0:
        return out^
    var valid = len(body) >= 2
    if valid:
        valid = _valid_close_code(Int(body[0]) * 256 + Int(body[1]))
    if valid:
        var reason = List[UInt8]()
        for i in range(2, len(body)):
            reason.append(body[i])
        valid = _is_valid_utf8(reason)
    if valid:
        out.append(body[0])
        out.append(body[1])
    else:
        var code = Int(WsCloseCode.PROTOCOL_ERROR)
        out.append(UInt8(code >> 8))
        out.append(UInt8(code & 0xFF))
    return out^


struct WsEvent(Copyable, Movable):
    """A complete message, or the end of the session."""

    var kind: Int
    """``WS_EVENT_MESSAGE`` or ``WS_EVENT_CLOSED``."""
    var is_text: Bool
    """For a message: TEXT (validated UTF-8) rather than BINARY."""
    var payload: List[UInt8]
    """For a message: the reassembled payload."""
    var code: Int
    """For a close: the code the session ended with (1005 when the peer
    sent none)."""

    def __init__(
        out self, kind: Int, is_text: Bool, var payload: List[UInt8], code: Int
    ):
        self.kind = kind
        self.is_text = is_text
        self.payload = payload^
        self.code = code


struct WsProtocol(Copyable, Movable):
    """One server-side WebSocket session, without I/O."""

    var inbox: List[UInt8]
    """Received bytes; those from ``_in_pos`` on are not decoded yet.
    Carriers append to it."""
    var _in_pos: Int
    var outbox: List[UInt8]
    """Encoded frames waiting to be sent. Carriers send from the front
    and call ``consumed``."""
    var max_message: Int
    """Largest frame payload, and largest reassembled message."""
    var max_outbox: Int
    """Largest ``outbox`` before the session fails with 1008."""
    var close_sent: Bool
    var close_received: Bool
    var failed: Bool
    var _frag_opcode: UInt8
    var _frag: List[UInt8]

    def __init__(
        out self,
        max_message: Int = DEFAULT_MAX_FRAME_BYTES,
        max_outbox: Int = DEFAULT_MAX_OUTBOX_BYTES,
    ):
        self.inbox = List[UInt8]()
        self._in_pos = 0
        self.outbox = List[UInt8]()
        self.max_message = max_message
        self.max_outbox = max_outbox
        self.close_sent = False
        self.close_received = False
        self.failed = False
        self._frag_opcode = 0
        self._frag = List[UInt8]()

    def finished(self) -> Bool:
        """No further event will come: closed by either side or failed."""
        return self.failed or self.close_received

    def wants_input(self) -> Bool:
        """Whether reading more is useful: the session is live and the
        peer is draining what it was sent."""
        return not self.finished() and len(self.outbox) <= self.max_outbox // 2

    def consumed(mut self, n: Int):
        """Drop the first ``n`` bytes of ``outbox`` once they are sent."""
        if n >= len(self.outbox):
            self.outbox.clear()
            return
        var rest = List[UInt8](capacity=len(self.outbox) - n)
        rest.extend(Span[UInt8, _](self.outbox)[n : len(self.outbox)])
        self.outbox = rest^

    def send_text(mut self, msg: String) raises:
        self._send(WsFrame.text(msg))

    def send_binary(mut self, data: List[UInt8]) raises:
        self._send(WsFrame.binary(data))

    def send_frame(mut self, frame: WsFrame) raises:
        """Queue any server frame; a CLOSE goes through :meth:`close` so at
        most one is ever sent."""
        if frame.opcode == WsOpcode.CLOSE:
            var code = WsCloseCode.NORMAL
            if len(frame.payload) >= 2:
                code = UInt16(
                    Int(frame.payload[0]) * 256 + Int(frame.payload[1])
                )
            self.close(code)
            return
        self._send(frame)

    def event_frame(self, ev: WsEvent) -> WsFrame:
        """``ev`` as the frame a frame-level handler expects: a whole TEXT
        or BINARY message, or a CLOSE carrying the code the session ended
        with."""
        if ev.kind == WS_EVENT_MESSAGE:
            return WsFrame(
                opcode=WsOpcode.TEXT if ev.is_text else WsOpcode.BINARY,
                payload=ev.payload.copy(),
            )
        var body = List[UInt8]()
        body.append(UInt8(ev.code >> 8))
        body.append(UInt8(ev.code & 0xFF))
        return WsFrame(opcode=WsOpcode.CLOSE, payload=body^)

    def close(mut self, code: UInt16 = WsCloseCode.NORMAL):
        """Start the closing handshake; a no-op once a CLOSE was sent."""
        if self.close_sent:
            return
        self.close_sent = True
        try:
            self.outbox.extend(
                Span[UInt8, _](WsFrame.close(code).encode(mask=False))
            )
        except:
            pass

    def _send(mut self, frame: WsFrame) raises:
        if self.close_sent:
            raise Error(
                "WebSocket: CLOSE already sent; no more frames may be sent"
                " (RFC 6455 sec 5.5.1)"
            )
        self.outbox.extend(Span[UInt8, _](frame.encode(mask=False)))
        if len(self.outbox) > self.max_outbox:
            self._fail(Int(WsCloseCode.POLICY_VIOLATION))
            raise Error("WebSocket: peer is not reading; closed with 1008")

    def _fail(mut self, code: Int):
        self.failed = True
        self.close(UInt16(code))

    def _closed_event(self, code: Int) -> WsEvent:
        return WsEvent(WS_EVENT_CLOSED, False, List[UInt8](), code)

    def next_event(mut self) -> Optional[WsEvent]:
        """Decode buffered frames until a message completes, the session
        ends, or more bytes are needed (``None``)."""
        while not self.finished():
            var pending = Span[UInt8, _](self.inbox)[self._in_pos :]
            var need = ws_frame_length(pending)
            if need < 0:
                return None
            if need > len(pending) and need <= self.max_message + 14:
                return None
            var frame: WsFrame
            try:
                var r = WsFrame.decode_one(
                    pending, max_payload=self.max_message
                )
                self._drop_inbox(r.consumed)
                frame = r^.take_frame()
            except e:
                var code = Int(WsCloseCode.PROTOCOL_ERROR)
                if WS_TOO_BIG_MARKER in String(e):
                    code = Int(WsCloseCode.MESSAGE_TOO_BIG)
                self._fail(code)
                return self._closed_event(code)
            if not frame.masked:
                self._fail(Int(WsCloseCode.PROTOCOL_ERROR))
                return self._closed_event(Int(WsCloseCode.PROTOCOL_ERROR))
            var event = self._on_frame(frame^)
            if event:
                return event^
        return None

    def _on_frame(mut self, var frame: WsFrame) -> Optional[WsEvent]:
        var op = frame.opcode
        if op == WsOpcode.PING:
            if not self.close_sent:
                try:
                    self._send(WsFrame.pong(frame.payload))
                except:
                    return self._closed_event(Int(WsCloseCode.POLICY_VIOLATION))
            return None
        if op == WsOpcode.PONG:
            return None
        if op == WsOpcode.CLOSE:
            self.close_received = True
            var code = Int(WsCloseCode.NO_STATUS)
            if len(frame.payload) >= 2:
                code = Int(frame.payload[0]) * 256 + Int(frame.payload[1])
            if not self.close_sent:
                self.close_sent = True
                try:
                    var reply = WsFrame(
                        opcode=WsOpcode.CLOSE,
                        payload=_close_reply_payload(frame.payload),
                    )
                    self.outbox.extend(Span[UInt8, _](reply.encode(mask=False)))
                except:
                    pass
            return self._closed_event(code)
        if op == WsOpcode.CONTINUATION:
            if self._frag_opcode == 0:
                self._fail(Int(WsCloseCode.PROTOCOL_ERROR))
                return self._closed_event(Int(WsCloseCode.PROTOCOL_ERROR))
            if len(self._frag) + len(frame.payload) > self.max_message:
                self._fail(Int(WsCloseCode.MESSAGE_TOO_BIG))
                return self._closed_event(Int(WsCloseCode.MESSAGE_TOO_BIG))
            self._frag.extend(Span[UInt8, _](frame.payload))
            if not frame.fin:
                return None
            var payload = List[UInt8]()
            swap(payload, self._frag)
            var is_text = self._frag_opcode == WsOpcode.TEXT
            self._frag_opcode = 0
            return self._message(is_text, payload^)
        # TEXT or BINARY
        if self._frag_opcode != 0:
            self._fail(Int(WsCloseCode.PROTOCOL_ERROR))
            return self._closed_event(Int(WsCloseCode.PROTOCOL_ERROR))
        if not frame.fin:
            self._frag_opcode = op
            swap(self._frag, frame.payload)
            return None
        var payload = List[UInt8]()
        swap(payload, frame.payload)
        return self._message(op == WsOpcode.TEXT, payload^)

    def _message(
        mut self, is_text: Bool, var payload: List[UInt8]
    ) -> Optional[WsEvent]:
        if is_text and not _is_valid_utf8(payload):
            self._fail(Int(WsCloseCode.INVALID_PAYLOAD))
            return self._closed_event(Int(WsCloseCode.INVALID_PAYLOAD))
        return WsEvent(WS_EVENT_MESSAGE, is_text, payload^, 0)

    def _drop_inbox(mut self, n: Int):
        """Mark ``n`` more bytes decoded. The undecoded tail is moved to
        the front only once it is at most half the buffer, so each byte
        is copied a bounded number of times however many frames it
        arrived with."""
        self._in_pos += n
        if self._in_pos >= len(self.inbox):
            self.inbox.clear()
            self._in_pos = 0
        elif self._in_pos * 2 >= len(self.inbox):
            var rest = List[UInt8](capacity=len(self.inbox) - self._in_pos)
            rest.extend(Span[UInt8, _](self.inbox)[self._in_pos :])
            self.inbox = rest^
            self._in_pos = 0
