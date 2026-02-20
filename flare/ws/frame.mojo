"""WebSocket frame codec (RFC 6455 §5).

Frame wire format (§5.2):

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-------+-+-------------+-------------------------------+
   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
   | |1|2|3|       |K|             |                               |
   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - -+
   |     Extended payload length continued, if payload len == 127  |
   + - - - - - - - - - - - - - - -+-------------------------------+
   |                               |Masking-key, if MASK set to 1  |
   +-------------------------------+-------------------------------+
   | Masking-key (continued)       |          Payload Data         |
   +-------------------------------- - - - - - - - - - - - - - - -+
   :                     Payload Data continued ...                :
   +---------------------------------------------------------------+

Masking (§5.3):
    Every client→server frame payload byte is XOR'd with a rotating
    4-byte masking key.  Server→client frames MUST NOT be masked.
    This implementation uses SIMD-32 masking for payloads ≥ 64 bytes.
"""

from format import Writable, Writer
from memory import UnsafePointer

# SIMD chunk width for XOR masking (matches bench_ws_mask.mojo)
comptime _SIMD_W: Int = 32


struct WsOpcode:
    """WebSocket opcode byte constants (RFC 6455 §5.2)."""

    comptime CONTINUATION: UInt8 = 0x0
    comptime TEXT: UInt8 = 0x1
    comptime BINARY: UInt8 = 0x2
    comptime CLOSE: UInt8 = 0x8
    comptime PING: UInt8 = 0x9
    comptime PONG: UInt8 = 0xA


struct WsCloseCode:
    """WebSocket close status code constants (RFC 6455 §7.4.1)."""

    comptime NORMAL: UInt16 = 1000
    """Clean, normal closure."""

    comptime GOING_AWAY: UInt16 = 1001
    """Endpoint going away (e.g. server restart)."""

    comptime PROTOCOL_ERROR: UInt16 = 1002
    """Protocol violation."""

    comptime UNSUPPORTED_DATA: UInt16 = 1003
    """Received unsupported data type."""

    comptime NO_STATUS: UInt16 = 1005
    """Reserved — must not be sent; used when code is absent in Close frame."""

    comptime ABNORMAL: UInt16 = 1006
    """Reserved — must not be sent; used when connection drops without Close."""

    comptime INVALID_PAYLOAD: UInt16 = 1007
    """Text frame contained invalid UTF-8."""

    comptime POLICY_VIOLATION: UInt16 = 1008
    """Message violates server policy."""

    comptime MESSAGE_TOO_BIG: UInt16 = 1009
    """Message exceeded configured size limit."""

    comptime INTERNAL_ERROR: UInt16 = 1011
    """Server encountered an internal error."""


struct WsProtocolError(Copyable, Movable, Stringable, Writable):
    """Raised when an incoming frame violates RFC 6455."""

    var message: String

    fn __init__(out self, message: String):
        self.message = message

    fn write_to[W: Writer](self, mut writer: W):
        writer.write("WsProtocolError: ", self.message)

    fn __str__(self) -> String:
        return "WsProtocolError: " + self.message


struct _DecodeResult(Movable):
    var frame: WsFrame
    var consumed: Int

    fn __init__(out self, var frame: WsFrame, consumed: Int):
        self.frame = frame^
        self.consumed = consumed

    fn __moveinit__(out self, deinit take: _DecodeResult):
        self.frame = take.frame^
        self.consumed = take.consumed

    fn take_frame(deinit self) -> WsFrame:
        """Consume this result and return the decoded frame."""
        return self.frame^


struct WsFrame(Movable, Stringable, Writable):
    """A single WebSocket frame.

    Represents the decoded wire form: header fields extracted and
    ``payload`` already de-masked (clients unmask on receive).

    Owns the payload buffer.

    Fields:
        fin:     True if this is the final fragment of a message.
        rsv1:    Extension bit RSV1 (must be False unless extension negotiated).
        opcode:  Frame opcode (see ``WsOpcode.*``).
        masked:  True if the payload was masked on the wire (client→server only).
        payload: The unmasked payload bytes.

    Example:
        ```mojo
        var frame = WsFrame.text("hello")
        var wire = frame.encode(mask=True)  # client sending to server
        ```
    """

    var fin: Bool
    var rsv1: Bool
    var opcode: UInt8
    var masked: Bool
    var payload: List[UInt8]

    fn __init__(
        out self,
        opcode: UInt8,
        payload: List[UInt8],
        fin: Bool = True,
        rsv1: Bool = False,
        masked: Bool = False,
    ):
        self.opcode = opcode
        self.payload = payload.copy()
        self.fin = fin
        self.rsv1 = rsv1
        self.masked = masked

    fn __moveinit__(out self, deinit take: WsFrame):
        self.fin = take.fin
        self.rsv1 = take.rsv1
        self.opcode = take.opcode
        self.masked = take.masked
        self.payload = take.payload^

    # ── Factory helpers ───────────────────────────────────────────────────────

    @staticmethod
    fn text(msg: String) -> WsFrame:
        """Create a text (UTF-8) frame.

        Args:
            msg: The UTF-8 text payload.

        Returns:
            A ``WsFrame`` with opcode ``TEXT`` and ``fin=True``.
        """
        return WsFrame(
            opcode=WsOpcode.TEXT, payload=List[UInt8](msg.as_bytes())
        )

    @staticmethod
    fn binary(data: List[UInt8]) -> WsFrame:
        """Create a binary frame.

        Args:
            data: The raw binary payload.

        Returns:
            A ``WsFrame`` with opcode ``BINARY`` and ``fin=True``.
        """
        return WsFrame(opcode=WsOpcode.BINARY, payload=data)

    @staticmethod
    fn ping(data: List[UInt8] = List[UInt8]()) -> WsFrame:
        """Create a PING control frame (max 125 bytes payload).

        Args:
            data: Optional PING payload (echo'd back in PONG, ≤125 bytes).

        Returns:
            A ``WsFrame`` with opcode ``PING``.
        """
        return WsFrame(opcode=WsOpcode.PING, payload=data)

    @staticmethod
    fn pong(data: List[UInt8] = List[UInt8]()) -> WsFrame:
        """Create a PONG control frame.

        Args:
            data: The payload from the corresponding PING.

        Returns:
            A ``WsFrame`` with opcode ``PONG``.
        """
        return WsFrame(opcode=WsOpcode.PONG, payload=data)

    @staticmethod
    fn close(code: UInt16 = WsCloseCode.NORMAL, reason: String = "") -> WsFrame:
        """Create a CLOSE control frame.

        Args:
            code:   Close status code (see ``WsCloseCode.*``).
            reason: UTF-8 reason phrase (≤123 bytes after encoding).

        Returns:
            A ``WsFrame`` with opcode ``CLOSE``.
        """
        var payload = List[UInt8](capacity=2 + len(reason))
        payload.append(UInt8(code >> 8))
        payload.append(UInt8(code & 0xFF))
        for b in reason.as_bytes():
            payload.append(b)
        return WsFrame(opcode=WsOpcode.CLOSE, payload=payload^)

    # ── Wire encoding ─────────────────────────────────────────────────────────

    fn encode(self, mask: Bool = False) raises -> List[UInt8]:
        """Encode this frame to its RFC 6455 wire representation.

        Masking is applied with a deterministic all-zero key when ``mask=True``
        in test builds; production code should pass a cryptographically random
        4-byte key via ``encode_with_key``.

        Args:
            mask: True to apply a zero mask key (for testing; use
                  ``encode_with_key`` for real client→server frames).

        Returns:
            The complete frame bytes ready to write to the socket.

        Raises:
            WsProtocolError: If ``rsv1`` is set without a negotiated extension,
                             or if a control frame payload exceeds 125 bytes.
        """
        if self.rsv1:
            raise WsProtocolError(
                "RSV1 bit requires an extension negotiation (e.g. per-message"
                " deflate)"
            )
        if self.is_control() and len(self.payload) > 125:
            raise WsProtocolError(
                "Control frame payload must be ≤ 125 bytes (got "
                + String(len(self.payload))
                + ")"
            )
        var key = SIMD[DType.uint8, 4](0, 0, 0, 0)
        return self.encode_with_key(mask, key)

    fn encode_with_key(
        self, mask: Bool, key: SIMD[DType.uint8, 4]
    ) raises -> List[UInt8]:
        """Encode this frame with an explicit 4-byte masking key.

        Args:
            mask: True to apply the masking key.
            key:  The 4-byte masking key (ignored when ``mask=False``).

        Returns:
            The complete frame bytes.

        Raises:
            WsProtocolError: If a control frame payload exceeds 125 bytes.
        """
        var plen = len(self.payload)

        # ── Header byte 0: FIN | RSV1 | RSV2 | RSV3 | opcode ─────────────────
        var byte0 = UInt8(self.opcode)
        if self.fin:
            byte0 |= 0x80
        if self.rsv1:
            byte0 |= 0x40

        # ── Header byte 1: MASK | payload_len(7) ─────────────────────────────
        var byte1 = UInt8(0)
        if mask:
            byte1 |= 0x80

        # Pre-compute header size for capacity estimate
        var header_size: Int
        if plen < 126:
            byte1 |= UInt8(plen)
            header_size = 2
        elif plen < 65536:
            byte1 |= 126
            header_size = 4  # 2 + 2 extended
        else:
            byte1 |= 127
            header_size = 10  # 2 + 8 extended

        if mask:
            header_size += 4

        var out = List[UInt8](capacity=header_size + plen)
        out.append(byte0)
        out.append(byte1)

        # ── Extended length ───────────────────────────────────────────────────
        if plen >= 65536:
            # 8-byte big-endian uint64
            var n = UInt64(plen)
            out.append(UInt8((n >> 56) & 0xFF))
            out.append(UInt8((n >> 48) & 0xFF))
            out.append(UInt8((n >> 40) & 0xFF))
            out.append(UInt8((n >> 32) & 0xFF))
            out.append(UInt8((n >> 24) & 0xFF))
            out.append(UInt8((n >> 16) & 0xFF))
            out.append(UInt8((n >> 8) & 0xFF))
            out.append(UInt8(n & 0xFF))
        elif plen >= 126:
            # 2-byte big-endian uint16
            out.append(UInt8((plen >> 8) & 0xFF))
            out.append(UInt8(plen & 0xFF))

        # ── Masking key ───────────────────────────────────────────────────────
        if mask:
            out.append(key[0])
            out.append(key[1])
            out.append(key[2])
            out.append(key[3])

        # ── Payload (with optional SIMD masking) ──────────────────────────────
        if not mask or (
            key[0] == 0 and key[1] == 0 and key[2] == 0 and key[3] == 0
        ):
            # No masking: copy payload bytes directly
            for b in self.payload:
                out.append(b)
        else:
            _append_masked(out, self.payload, key)

        return out^

    # ── Wire decoding ─────────────────────────────────────────────────────────

    @staticmethod
    fn decode_one(data: Span[UInt8]) raises -> _DecodeResult:
        """Parse one frame from ``data``.

        Args:
            data: Raw bytes from the socket (may contain more than one frame).

        Returns:
            A ``_DecodeResult`` with the parsed frame and bytes consumed.

        Raises:
            WsProtocolError: If the frame violates RFC 6455 (bad RSV bits,
                             fragmented control frame, etc.).
            Error:           If ``data`` is too short to contain a complete frame.
        """
        var n = len(data)
        if n < 2:
            raise Error(
                "WsFrame.decode_one: need at least 2 bytes, got " + String(n)
            )

        var byte0 = data[0]
        var byte1 = data[1]

        var fin = (byte0 & 0x80) != 0
        var rsv1 = (byte0 & 0x40) != 0
        var rsv2 = (byte0 & 0x20) != 0
        var rsv3 = (byte0 & 0x10) != 0
        var opcode = byte0 & 0x0F
        var is_masked = (byte1 & 0x80) != 0
        var plen7 = Int(byte1 & 0x7F)

        if rsv2 or rsv3:
            raise WsProtocolError("RSV2/RSV3 must be zero without extension")

        # ── Parse extended payload length ─────────────────────────────────────
        var pos = 2
        var plen: Int
        if plen7 < 126:
            plen = plen7
        elif plen7 == 126:
            if n < pos + 2:
                raise Error("WsFrame.decode_one: truncated 16-bit length")
            plen = (Int(data[pos]) << 8) | Int(data[pos + 1])
            pos += 2
        else:  # plen7 == 127
            if n < pos + 8:
                raise Error("WsFrame.decode_one: truncated 64-bit length")
            var lo = (
                (Int(data[pos + 4]) << 24)
                | (Int(data[pos + 5]) << 16)
                | (Int(data[pos + 6]) << 8)
                | Int(data[pos + 7])
            )
            plen = lo  # restrict to lower 32 bits for safety
            pos += 8

        # ── Parse masking key ─────────────────────────────────────────────────
        var key = SIMD[DType.uint8, 4](0, 0, 0, 0)
        if is_masked:
            if n < pos + 4:
                raise Error("WsFrame.decode_one: truncated masking key")
            key[0] = data[pos]
            key[1] = data[pos + 1]
            key[2] = data[pos + 2]
            key[3] = data[pos + 3]
            pos += 4

        # ── Validate control frame constraints ────────────────────────────────
        if (opcode & 0x8) != 0:
            if not fin:
                raise WsProtocolError("Control frames must not be fragmented")
            if plen > 125:
                raise WsProtocolError(
                    "Control frame payload exceeds 125 bytes: " + String(plen)
                )

        if n < pos + plen:
            raise Error(
                "WsFrame.decode_one: need "
                + String(pos + plen)
                + " bytes, got "
                + String(n)
            )

        # ── Extract and unmask payload ────────────────────────────────────────
        var payload = List[UInt8](capacity=plen)
        if is_masked:
            for i in range(plen):
                payload.append(data[pos + i] ^ key[i & 3])
        else:
            for i in range(plen):
                payload.append(data[pos + i])

        var consumed = pos + plen
        var frame = WsFrame(
            opcode=opcode,
            payload=payload^,
            fin=fin,
            rsv1=rsv1,
            masked=is_masked,
        )
        return _DecodeResult(frame^, consumed)

    # ── Helpers ───────────────────────────────────────────────────────────────

    fn is_control(self) -> Bool:
        """Return True if this is a control frame (CLOSE, PING, or PONG).

        Control frames MUST NOT be fragmented (RFC 6455 §5.5).

        Returns:
            True for CLOSE (0x8), PING (0x9), and PONG (0xA) opcodes.
        """
        return (self.opcode & 0x8) != 0

    fn text_payload(self) -> String:
        """Decode the payload as a UTF-8 string.

        Returns:
            Payload bytes decoded as a ``String``.
        """
        var s = String(capacity=len(self.payload) + 1)
        for b in self.payload:
            s += chr(Int(b))
        return s^

    fn write_to[W: Writer](self, mut writer: W):
        writer.write(
            "WsFrame(opcode=",
            Int(self.opcode),
            ", fin=",
            self.fin,
            ", payload_len=",
            len(self.payload),
            ")",
        )

    fn __str__(self) -> String:
        return (
            "WsFrame(opcode="
            + String(Int(self.opcode))
            + ", fin="
            + String(self.fin)
            + ", payload_len="
            + String(len(self.payload))
            + ")"
        )


# ── SIMD masking helper ───────────────────────────────────────────────────────


fn _append_masked(
    mut out: List[UInt8],
    payload: List[UInt8],
    key: SIMD[DType.uint8, 4],
):
    """Append ``payload`` bytes XOR'd with ``key`` into ``out``.

    Uses SIMD-32 for chunks ≥ ``_SIMD_W`` bytes; scalar for the tail.

    Args:
        out:     Destination list to append masked bytes into.
        payload: Unmasked payload bytes.
        key:     4-byte masking key.
    """
    var n = len(payload)
    var src = payload.unsafe_ptr()

    # Pre-tile the 4-byte key into a 32-byte SIMD vector
    var tiled = SIMD[DType.uint8, _SIMD_W]()

    @parameter
    for i in range(_SIMD_W):
        tiled[i] = key[i & 3]

    # SIMD path for large chunks
    var i = 0
    while i + _SIMD_W <= n:
        var chunk = (src + i).load[width=_SIMD_W]()
        var masked = chunk ^ tiled
        for j in range(_SIMD_W):
            out.append(masked[j])
        i += _SIMD_W

    # Scalar tail
    while i < n:
        out.append(src[i] ^ key[i & 3])
        i += 1
