"""WebSocket client (RFC 6455).

Opening handshake (§4.1):
  1. Parse ``ws://`` / ``wss://`` URL.
  2. Open TCP (ws) or TLS (wss) stream.
  3. Generate a random 16-byte nonce, base64-encode it as ``Sec-WebSocket-Key``.
  4. Send HTTP/1.1 GET with ``Upgrade: websocket`` headers.
  5. Parse the 101 Switching Protocols response.
  6. Verify ``Sec-WebSocket-Accept = base64(SHA-1(key + GUID))``.

SHA-1 is computed via libcrypto (OpenSSL) FFI — the same library already
bundled by the TLS FFI build step.  Base64 is a pure Mojo implementation.
"""

from ffi import OwnedDLHandle, c_int
from .frame import (
    WsFrame,
    WsOpcode,
    WsCloseCode,
    WsProtocolError,
    _DecodeResult,
)
from ..http.url import Url
from ..tls import TlsStream, TlsConfig
from ..tcp import TcpStream
from ..net import SocketAddr, NetworkError
from ..net.socket import RawSocket, AF_INET, SOCK_STREAM
from ..net.address import IpAddr
from ..net._libc import INVALID_FD
from ..dns import resolve_v4

# RFC 6455 §1.3 magic GUID concatenated with the Sec-WebSocket-Key for SHA-1
comptime _WS_GUID: String = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# OpenSSL SHA-1 digest length (20 bytes)
comptime _SHA1_LEN: Int = 20

# Path to libcrypto shared library (part of the pixi openssl dependency)
comptime _CRYPTO_LIB: String = "build/libflare_tls.so"


struct WsHandshakeError(Copyable, Movable, Stringable, Writable):
    """Raised when the WebSocket opening handshake fails."""

    var message: String

    fn __init__(out self, message: String):
        self.message = message

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write("WsHandshakeError: ", self.message)

    fn __str__(self) -> String:
        return "WsHandshakeError: " + self.message


# ── Base64 encoder ────────────────────────────────────────────────────────────

comptime _B64_TABLE: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


fn _base64_encode(data: Span[UInt8]) -> String:
    """Encode ``data`` to standard RFC 4648 base64.

    Args:
        data: Input bytes.

    Returns:
        Base64-encoded string (with ``=`` padding).
    """
    var n = len(data)
    var out = String(capacity=((n + 2) // 3) * 4 + 1)
    var tbl = _B64_TABLE.unsafe_ptr()
    var i = 0
    while i + 3 <= n:
        var a = Int(data[i])
        var b = Int(data[i + 1])
        var c = Int(data[i + 2])
        out += chr(Int(tbl[a >> 2]))
        out += chr(Int(tbl[((a & 3) << 4) | (b >> 4)]))
        out += chr(Int(tbl[((b & 0xF) << 2) | (c >> 6)]))
        out += chr(Int(tbl[c & 0x3F]))
        i += 3
    if n - i == 1:
        var a = Int(data[i])
        out += chr(Int(tbl[a >> 2]))
        out += chr(Int(tbl[(a & 3) << 4]))
        out += "=="
    elif n - i == 2:
        var a = Int(data[i])
        var b = Int(data[i + 1])
        out += chr(Int(tbl[a >> 2]))
        out += chr(Int(tbl[((a & 3) << 4) | (b >> 4)]))
        out += chr(Int(tbl[(b & 0xF) << 2]))
        out += "="
    return out^


# ── SHA-1 via libcrypto FFI ───────────────────────────────────────────────────


fn _sha1(data: String) raises -> List[UInt8]:
    """Compute SHA-1 of ``data`` using OpenSSL via the TLS shared library.

    Uses the ``SHA1`` function from libcrypto (available via the bundled
    ``libflare_tls.so`` which links both libssl and libcrypto).

    Args:
        data: Input bytes to hash.

    Returns:
        20-byte SHA-1 digest.

    Raises:
        NetworkError: If the SHA-1 function cannot be loaded.
    """
    var lib = OwnedDLHandle(_CRYPTO_LIB)
    # SHA1(const unsigned char *d, size_t n, unsigned char *md) -> unsigned char*
    var fn_sha1 = lib.get_function[fn(Int, Int, Int) -> Int]("SHA1")
    var digest_buf = List[UInt8](capacity=_SHA1_LEN)
    digest_buf.resize(_SHA1_LEN, 0)
    var data_bytes = data.as_bytes()
    _ = fn_sha1(
        Int(data_bytes.unsafe_ptr()),
        Int(len(data_bytes)),
        Int(digest_buf.unsafe_ptr()),
    )
    return digest_buf^


# ── HTTP upgrade helpers ──────────────────────────────────────────────────────


fn _generate_ws_key() -> String:
    """Generate a random 16-byte nonce encoded as base64.

    Uses a deterministic seed in v0.1.0 (proper CSPRNG in v0.2.0).

    Returns:
        24-character base64 string suitable for ``Sec-WebSocket-Key``.
    """
    # Simple deterministic 16 bytes for v0.1.0
    # TODO: replace with CSPRNG in v0.2.0
    var nonce = List[UInt8](capacity=16)
    for i in range(16):
        nonce.append(UInt8((i * 37 + 0x42) & 0xFF))
    return _base64_encode(Span[UInt8](nonce))


fn _compute_accept(key: String) raises -> String:
    """Compute the expected ``Sec-WebSocket-Accept`` header value.

    Per RFC 6455 §4.2.2: base64(SHA-1(key + GUID)).

    Args:
        key: The ``Sec-WebSocket-Key`` value sent in the upgrade request.

    Returns:
        Base64-encoded SHA-1 digest for comparison with the server response.
    """
    var combined = key + _WS_GUID
    var digest = _sha1(combined)
    return _base64_encode(Span[UInt8](digest))


fn _ws_url_to_http(url: String) raises -> String:
    """Convert ``ws://`` or ``wss://`` URL to ``http://`` or ``https://``.

    Args:
        url: WebSocket URL.

    Returns:
        HTTP URL for use with ``Url.parse()``.

    Raises:
        WsHandshakeError: If the scheme is not ``ws`` or ``wss``.
    """
    if url.startswith("ws://"):
        return "http://" + String(url[5:])
    elif url.startswith("wss://"):
        return "https://" + String(url[6:])
    raise WsHandshakeError("URL must start with ws:// or wss://: " + url)


fn _read_line_tls(mut stream: TlsStream, mut buf: List[UInt8]) raises -> String:
    """Read one ``\\r\\n``-terminated line from a TLS stream.

    Args:
        stream: Open TLS stream.
        buf:    Scratch buffer (single-byte reads).

    Returns:
        Line content without the trailing ``\\r\\n``.

    Raises:
        NetworkError: On I/O error.
    """
    var line = String(capacity=256)
    var b_buf = List[UInt8](capacity=1)
    b_buf.append(UInt8(0))
    while True:
        var n = stream.read(b_buf.unsafe_ptr(), len(b_buf))
        if n == 0:
            break
        var c = b_buf[0]
        if c == 13:  # CR
            continue
        if c == 10:  # LF
            break
        line += chr(Int(c))
    return line^


fn _read_line_tcp(mut stream: TcpStream, mut buf: List[UInt8]) raises -> String:
    """Read one ``\\r\\n``-terminated line from a TCP stream.

    Args:
        stream: Open TCP stream.
        buf:    Scratch buffer (single-byte reads).

    Returns:
        Line content without the trailing ``\\r\\n``.

    Raises:
        NetworkError: On I/O error.
    """
    var line = String(capacity=256)
    var b_buf = List[UInt8](capacity=1)
    b_buf.append(UInt8(0))
    while True:
        var n = stream.read(b_buf.unsafe_ptr(), len(b_buf))
        if n == 0:
            break
        var c = b_buf[0]
        if c == 13:
            continue
        if c == 10:
            break
        line += chr(Int(c))
    return line^


fn _str_find_local(s: String, sub: String) -> Int:
    """Return the index of the first ``sub`` in ``s``, or -1."""
    var n = len(s)
    var m = len(sub)
    if m == 0:
        return 0
    for i in range(n - m + 1):
        var ok = True
        for j in range(m):
            if s.unsafe_ptr()[i + j] != sub.unsafe_ptr()[j]:
                ok = False
                break
        if ok:
            return i
    return -1


fn _lower_local(s: String) -> String:
    """Return ASCII-lowercase copy of ``s``."""
    var out = String(capacity=len(s))
    for i in range(len(s)):
        var c = s.unsafe_ptr()[i]
        if c >= 65 and c <= 90:
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out^


# ── Internal stream union for WebSocket I/O ───────────────────────────────────
# Mojo doesn't have enum variants with payloads, so we use a tagged struct.


struct _WsStream(Movable):
    """Holds either a TLS or plain TCP stream for WebSocket I/O."""

    var _is_tls: Bool
    var _tls: TlsStream
    var _tcp: TcpStream

    fn __init__(out self, var tls: TlsStream):
        self._is_tls = True
        self._tls = tls^
        self._tcp = _dummy_tcp_stream()

    fn __init__(out self, var tcp: TcpStream):
        self._is_tls = False
        self._tls = _dummy_tls_stream()
        self._tcp = tcp^

    fn __moveinit__(out self, deinit take: _WsStream):
        self._is_tls = take._is_tls
        self._tls = take._tls^
        self._tcp = take._tcp^

    fn write_all(self, data: Span[UInt8]) raises:
        """Write all bytes to the underlying stream.

        Args:
            data: Bytes to transmit.

        Raises:
            NetworkError: On I/O failure.
        """
        if self._is_tls:
            self._tls.write_all(data)
        else:
            self._tcp.write_all(data)

    fn read(mut self, buf: UnsafePointer[UInt8], size: Int) raises -> Int:
        """Read up to ``size`` bytes from the underlying stream.

        Args:
            buf:  Destination buffer (at least ``size`` bytes of storage).
            size: Maximum bytes to read.

        Returns:
            Bytes written to ``buf``, or 0 on clean EOF.

        Raises:
            NetworkError: On I/O failure.
        """
        if self._is_tls:
            return self._tls.read(buf, size)
        else:
            return self._tcp.read(buf, size)

    fn close(mut self):
        """Close the underlying stream."""
        if self._is_tls:
            self._tls.close()
        else:
            self._tcp.close()


fn _dummy_tcp_stream() -> TcpStream:
    """Return a TCP stream with a sentinel fd (INVALID_FD = -1).

    ``RawSocket.close()`` checks ``fd >= 0`` so this never calls ``close(2)``.
    Used to populate the inactive branch of ``_WsStream``.
    """
    var sock = RawSocket(
        c_int(INVALID_FD), c_int(AF_INET), c_int(SOCK_STREAM), True
    )
    return TcpStream(sock^, SocketAddr(IpAddr.localhost(), 0))


fn _dummy_tls_stream() -> TlsStream:
    """Return a sentinel TLS stream (for use in the inactive branch).

    With ``_ssl=0``, ``TlsStream.__del__`` is a no-op.
    This is never called on an active ``_WsStream`` of TLS type.
    """
    var tcp = _dummy_tcp_stream()
    return TlsStream(tcp^, 0, 0)


struct WsMessage(Movable):
    """A high-level WebSocket message (Text or Binary).

    Produced by ``WsClient.recv_message()``.  Use ``is_text`` to
    discriminate between message kinds.

    Fields:
        is_text: ``True`` for a UTF-8 text message; ``False`` for binary.

    Example:
        ```mojo
        var msg = ws.recv_message()
        if msg.is_text:
            print(msg.as_text())
        else:
            print("binary:", len(msg.as_binary()), "bytes")
        ```
    """

    var is_text: Bool
    var _text: String
    var _binary: List[UInt8]

    fn __init__(out self, text: String):
        """Initialise a text ``WsMessage``.

        Args:
            text: The UTF-8 text payload.
        """
        self.is_text = True
        self._text = text
        self._binary = List[UInt8]()

    fn __init__(out self, binary: List[UInt8]):
        """Initialise a binary ``WsMessage``.

        Args:
            binary: The raw binary payload.
        """
        self.is_text = False
        self._text = ""
        self._binary = binary.copy()

    fn __moveinit__(out self, deinit take: WsMessage):
        self.is_text = take.is_text
        self._text = take._text^
        self._binary = take._binary^

    fn as_text(self) -> String:
        """Return the message payload as a UTF-8 string.

        Returns:
            The text payload when ``is_text`` is ``True``; an empty string
            otherwise.
        """
        return self._text

    fn as_binary(self) -> List[UInt8]:
        """Return the message payload as raw bytes.

        Returns:
            A copy of the binary payload when ``is_text`` is ``False``;
            an empty list otherwise.
        """
        return self._binary.copy()


struct WsClient(Movable):
    """A WebSocket client connection established via HTTP Upgrade.

    Handles the opening handshake, frame encoding/decoding, masking
    (client→server frames MUST be masked per RFC 6455 §5.3), and
    automatic PONG replies to PING frames.

    This type is ``Movable`` but not ``Copyable``.  It supports the context
    manager protocol (``__enter__`` / ``__exit__``) for use with ``with``.

    Fields:
        _stream:      Underlying transport (TLS or TCP).
        _key:         The ``Sec-WebSocket-Key`` used for this connection.

    Example:
        ```mojo
        with WsClient.connect("wss://echo.websocket.events") as ws:
            ws.send_text("hello")
            var msg = ws.recv_message()
            print(msg.as_text())
        ```
    """

    var _stream: _WsStream
    var _key: String

    fn __init__(out self, var stream: _WsStream, key: String):
        self._stream = stream^
        self._key = key

    fn __moveinit__(out self, deinit take: WsClient):
        self._stream = take._stream^
        self._key = take._key^

    fn __del__(deinit self):
        self._stream.close()

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    fn connect(url: String) raises -> WsClient:
        """Connect to a WebSocket server using default TLS configuration.

        Equivalent to ``WsClient.connect(url, TlsConfig())``.

        Args:
            url: WebSocket URL (``ws://`` or ``wss://``).

        Returns:
            A ``WsClient`` with the handshake complete.

        Raises:
            NetworkError:     If the TCP/TLS connection fails.
            WsHandshakeError: If the server's Upgrade response is invalid.
        """
        return WsClient._connect_impl(url, TlsConfig())

    @staticmethod
    fn connect(url: String, config: TlsConfig) raises -> WsClient:
        """Connect to a WebSocket server with custom TLS configuration.

        For ``wss://`` URLs, wraps the connection in TLS using ``config``.

        Args:
            url:    WebSocket URL (``ws://`` or ``wss://``).
            config: TLS configuration (only used for ``wss://``).

        Returns:
            A ``WsClient`` with the handshake complete.

        Raises:
            NetworkError:     If the TCP/TLS connection fails.
            WsHandshakeError: If the server's Upgrade response is invalid or
                              ``Sec-WebSocket-Accept`` does not match.
        """
        return WsClient._connect_impl(url, config)

    @staticmethod
    fn _connect_impl(url: String, config: TlsConfig) raises -> WsClient:
        """Internal implementation shared by both ``connect`` overloads."""
        var http_url = _ws_url_to_http(url)
        var u = Url.parse(http_url)
        var key = _generate_ws_key()
        var expected_accept = _compute_accept(key)

        # ── 1. Build upgrade request ──────────────────────────────────────────
        var host_header = u.host
        if (u.scheme == "http" and u.port != 80) or (
            u.scheme == "https" and u.port != 443
        ):
            host_header = host_header + ":" + String(Int(u.port))

        var req = (
            "GET "
            + u.request_target()
            + " HTTP/1.1\r\n"
            + "Host: "
            + host_header
            + "\r\n"
            + "Upgrade: websocket\r\n"
            + "Connection: Upgrade\r\n"
            + "Sec-WebSocket-Key: "
            + key
            + "\r\n"
            + "Sec-WebSocket-Version: 13\r\n"
            + "\r\n"
        )

        # ── 2. Connect and send ───────────────────────────────────────────────
        var scratch = List[UInt8](capacity=1)
        scratch.append(UInt8(0))

        if u.is_tls():
            var tls = TlsStream.connect(u.host, u.port, config)
            var req_bytes = req.as_bytes()
            tls.write_all(Span[UInt8](req_bytes))

            # ── 3. Read response headers ──────────────────────────────────────
            var status_line = _read_line_tls(tls, scratch)
            if not status_line.startswith("HTTP/1.1 101"):
                raise WsHandshakeError(
                    "Expected 101 Switching Protocols, got: " + status_line
                )

            var accept_header = String("")
            while True:
                var line = _read_line_tls(tls, scratch)
                if len(line) == 0:
                    break
                var colon = _str_find_local(line, ":")
                if colon >= 0:
                    var hk = _lower_local(String(String(line[:colon]).strip()))
                    var hv = String(String(line[colon + 1 :]).strip())
                    if hk == "sec-websocket-accept":
                        accept_header = hv

            # ── 4. Verify Sec-WebSocket-Accept ────────────────────────────────
            if accept_header != expected_accept:
                raise WsHandshakeError(
                    "Sec-WebSocket-Accept mismatch: got '"
                    + accept_header
                    + "', expected '"
                    + expected_accept
                    + "'"
                )

            var ws_stream = _WsStream(tls^)
            return WsClient(ws_stream^, key)
        else:
            var addrs = resolve_v4(u.host)
            if len(addrs) == 0:
                raise NetworkError("DNS resolution failed for: " + u.host)
            var tcp = TcpStream.connect(SocketAddr(addrs[0], u.port))
            var req_bytes = req.as_bytes()
            tcp.write_all(Span[UInt8](req_bytes))

            var status_line = _read_line_tcp(tcp, scratch)
            if not status_line.startswith("HTTP/1.1 101"):
                raise WsHandshakeError(
                    "Expected 101 Switching Protocols, got: " + status_line
                )

            var accept_header = String("")
            while True:
                var line = _read_line_tcp(tcp, scratch)
                if len(line) == 0:
                    break
                var colon = _str_find_local(line, ":")
                if colon >= 0:
                    var hk = _lower_local(String(String(line[:colon]).strip()))
                    var hv = String(String(line[colon + 1 :]).strip())
                    if hk == "sec-websocket-accept":
                        accept_header = hv

            if accept_header != expected_accept:
                raise WsHandshakeError(
                    "Sec-WebSocket-Accept mismatch: got '"
                    + accept_header
                    + "', expected '"
                    + expected_accept
                    + "'"
                )

            var ws_stream = _WsStream(tcp^)
            return WsClient(ws_stream^, key)

    # ── Sending ───────────────────────────────────────────────────────────────

    fn send_text(self, msg: String) raises:
        """Send a UTF-8 text message (client→server, masked).

        Args:
            msg: The message string. Must be valid UTF-8.

        Raises:
            NetworkError: On I/O failure.
        """
        var frame = WsFrame.text(msg)
        var wire = frame.encode(mask=True)
        self._stream.write_all(Span[UInt8](wire))

    fn send_binary(self, data: List[UInt8]) raises:
        """Send a binary message (client→server, masked).

        Args:
            data: The raw binary payload.

        Raises:
            NetworkError: On I/O failure.
        """
        var frame = WsFrame.binary(data)
        var wire = frame.encode(mask=True)
        self._stream.write_all(Span[UInt8](wire))

    fn send_frame(self, frame: WsFrame) raises:
        """Send an already-constructed frame.

        Args:
            frame: The frame to send (masked automatically).

        Raises:
            NetworkError: On I/O failure.
        """
        var wire = frame.encode(mask=True)
        self._stream.write_all(Span[UInt8](wire))

    # ── Receiving ─────────────────────────────────────────────────────────────

    fn recv(mut self) raises -> WsFrame:
        """Receive the next data frame, handling PING transparently.

        Automatically replies to PING frames with a PONG and continues
        reading. CLOSE frames are returned to the caller.

        Returns:
            The next ``WsFrame`` (TEXT, BINARY, or CLOSE).

        Raises:
            NetworkError:    On I/O failure.
            WsProtocolError: On protocol violation.
            Error:           On truncated frame data.
        """
        while True:
            var frame = self._recv_one()
            if frame.opcode == WsOpcode.PING:
                # RFC 6455 §5.5.3: respond with PONG carrying same payload
                var pong = WsFrame.pong(frame.payload)
                var wire = pong.encode(mask=True)
                self._stream.write_all(Span[UInt8](wire))
                continue
            return frame^

    fn _recv_one(mut self) raises -> WsFrame:
        """Read raw bytes from the stream and decode one frame."""
        # Read bytes incrementally until we have a full frame
        var buf = List[UInt8](capacity=4096)
        var tmp = List[UInt8](capacity=4096)
        tmp.resize(4096, 0)

        while True:
            try:
                var result = WsFrame.decode_one(Span[UInt8](buf))
                return result^.take_frame()
            except e:
                var msg = String(e)
                if (
                    "need at least" in msg
                    or "need " in msg
                    or "truncated" in msg
                ):
                    # Read more bytes and retry
                    var n = self._stream.read(tmp.unsafe_ptr(), len(tmp))
                    if n == 0:
                        raise NetworkError(
                            "WebSocket connection closed unexpectedly"
                        )
                    for i in range(n):
                        buf.append(tmp[i])
                else:
                    raise e^

    fn recv_message(mut self) raises -> WsMessage:
        """Receive the next complete message as a ``WsMessage``.

        A higher-level alternative to ``recv()`` that returns a
        ``WsMessage`` (Text or Binary) instead of a raw ``WsFrame``.
        PING frames are handled transparently (PONG sent automatically).
        CLOSE frames raise a ``NetworkError``.

        Returns:
            A ``WsMessage`` with ``is_text=True`` for text frames and
            ``is_text=False`` for binary frames.

        Raises:
            NetworkError:    If a CLOSE frame is received or I/O fails.
            WsProtocolError: On protocol violation.

        Example:
            ```mojo
            var msg = ws.recv_message()
            if msg.is_text:
                print(msg.as_text())
            ```
        """
        var frame = self.recv()
        if frame.opcode == WsOpcode.CLOSE:
            raise NetworkError("WebSocket CLOSE received")
        if frame.opcode == WsOpcode.BINARY:
            return WsMessage(frame.payload)
        # TEXT or anything else: return as text
        return WsMessage(frame.text_payload())

    # ── Context manager ───────────────────────────────────────────────────────

    fn __enter__(var self) -> WsClient:
        """Transfer ownership of ``self`` into the ``with`` block.

        Returns:
            This ``WsClient`` (moved).
        """
        return self^

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    fn close(mut self):
        """Send a CLOSE frame and close the underlying transport.

        Idempotent — safe to call multiple times.
        """
        try:
            var close_frame = WsFrame.close()
            var wire = close_frame.encode(mask=True)
            self._stream.write_all(Span[UInt8](wire))
        except:
            pass  # best-effort
        self._stream.close()
