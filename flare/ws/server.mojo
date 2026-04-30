"""WebSocket server: upgrades HTTP connections to WebSocket (RFC 6455).

Server-to-client frames MUST NOT be masked (RFC 6455 §5.3).
Client-to-server frames MUST be masked; ``WsConnection.recv`` un-masks
them automatically.

The upgrade handshake (§4.2):
    1. Accept TCP connection.
    2. Read the HTTP GET request and locate ``Sec-WebSocket-Key``.
    3. Compute ``Sec-WebSocket-Accept = base64(SHA-1(key + GUID))``.
    4. Send ``101 Switching Protocols``.
    5. Hand off to ``WsConnection``.
"""

from std.ffi import OwnedDLHandle
from .frame import WsFrame, WsOpcode, WsCloseCode, WsProtocolError
from ..http.response import Status
from ..tcp import TcpListener, TcpStream
from ..net import SocketAddr, NetworkError, _find_flare_lib

# RFC 6455 §1.3 magic GUID
comptime _WS_GUID: String = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
comptime _SHA1_LEN: Int = 20


# ── SHA-1 helper (same approach as ws/client.mojo) ───────────────────────────


def _sha1_srv(data: String) raises -> List[UInt8]:
    """Compute SHA-1 via the bundled libflare_tls shared library.

    Opens the library, retrieves the ``SHA1`` function pointer, then
    delegates to ``_do_sha1_srv`` which takes ``lib`` as a ``read``
    (borrow). A borrow cannot be ASAP-destroyed, so the library stays
    mapped for the entire C call. Without this, Mojo's ASAP policy
    calls ``dlclose`` right after ``get_function`` — before the pointer
    is ever invoked — unmapping the library and crashing on macOS ARM64.
    See MSTDL-2334.

    Args:
        data: Input string to hash.

    Returns:
        20-byte SHA-1 digest.

    Raises:
        NetworkError: If the SHA-1 function cannot be loaded.
    """
    var lib = OwnedDLHandle(_find_flare_lib())
    var fn_sha1 = lib.get_function[def(Int, Int, Int) thin abi("C") -> Int](
        "SHA1"
    )
    return _do_sha1_srv(fn_sha1, data.as_bytes(), lib)


def _do_sha1_srv(
    fn_sha1: def(Int, Int, Int) thin abi("C") -> Int,
    data_bytes: Span[UInt8, _],
    read lib: OwnedDLHandle,
) -> List[UInt8]:
    """Invoke the SHA-1 C function with ``lib`` kept alive via borrow.

    ``lib`` is a ``read`` (borrow) parameter: Mojo cannot ASAP-destroy
    it while this function is executing, ensuring the shared library
    remains mapped across the FFI call.

    Args:
        fn_sha1: Function pointer to ``SHA1`` from libflare_tls.
        data_bytes: Input bytes to hash.
        lib: Borrowed handle to the shared library (keeps it mapped).

    Returns:
        20-byte SHA-1 digest as ``List[UInt8]``.
    """
    var digest = List[UInt8](capacity=_SHA1_LEN)
    digest.resize(_SHA1_LEN, 0)
    _ = fn_sha1(
        Int(data_bytes.unsafe_ptr()),
        Int(len(data_bytes)),
        Int(digest.unsafe_ptr()),
    )
    return digest^


# ── Base64 encoder (same implementation as ws/client.mojo) ───────────────────

comptime _B64: String = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


def _b64_encode_srv(data: Span[UInt8, _]) -> String:
    """Encode bytes to standard RFC 4648 base64.

    Args:
        data: Input bytes.

    Returns:
        Base64-encoded string.
    """
    var n = len(data)
    var out = String(capacity=((n + 2) // 3) * 4 + 1)
    var tbl = _B64.unsafe_ptr()
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


def _compute_accept_srv(key: String) raises -> String:
    """Compute ``Sec-WebSocket-Accept`` for ``key``.

    Args:
        key: The ``Sec-WebSocket-Key`` value from the client.

    Returns:
        Base64-encoded SHA-1 of key + RFC 6455 GUID.
    """
    var combined = key + _WS_GUID
    var digest = _sha1_srv(combined)
    return _b64_encode_srv(Span[UInt8, _](digest))


# ── Handshake request reader ──────────────────────────────────────────────────


def _read_line_srv(mut stream: TcpStream) raises -> String:
    """Read one CRLF-terminated line from ``stream``.

    Args:
        stream: Open TCP stream.

    Returns:
        Line content without the terminator.
    """
    var line = String(capacity=256)
    var buf = List[UInt8](capacity=1)
    buf.append(UInt8(0))
    while True:
        var n = stream.read(buf.unsafe_ptr(), 1)
        if n == 0:
            return line^
        var c = buf[0]
        if c == 13:
            continue
        if c == 10:
            return line^
        line += chr(Int(c))


def _lower_srv(s: String) -> String:
    """Return ASCII-lowercase of ``s``."""
    var out = String(capacity=s.byte_length())
    for i in range(s.byte_length()):
        var c = s.unsafe_ptr()[i]
        if c >= 65 and c <= 90:
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out^


def _str_find_srv(s: String, sub: String) -> Int:
    """Return the index of the first ``sub`` in ``s``, or -1."""
    var n = s.byte_length()
    var m = sub.byte_length()
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


def _parse_ws_upgrade_bytes(data: Span[UInt8, _]) raises -> String:
    """Parse an HTTP WebSocket Upgrade request from a byte buffer.

    Identical logic to ``_read_upgrade_request`` but reads from a
    ``Span[UInt8, _]`` instead of a ``TcpStream``. Suitable for fuzz
    harnesses and unit tests that operate on raw bytes.

    Args:
        data: Raw HTTP/1.1 Upgrade request bytes.

    Returns:
        The ``Sec-WebSocket-Key`` header value.

    Raises:
        NetworkError: If the request is malformed or missing required headers.
    """
    var pos = 0

    def read_line(data: Span[UInt8, _], mut pos: Int) -> String:
        var line = String(capacity=256)
        while pos < len(data):
            var c = data[pos]
            pos += 1
            if c == 13:
                continue
            if c == 10:
                return line^
            line += chr(Int(c))
        return line^

    # Skip request line
    _ = read_line(data, pos)

    var ws_key = String("")
    var found_upgrade = False
    var found_connection = False

    while True:
        var line = read_line(data, pos)
        if line.byte_length() == 0:
            break
        var colon = _str_find_srv(line, ":")
        if colon < 0:
            continue
        var k = _lower_srv(
            String(
                String(String(unsafe_from_utf8=line.as_bytes()[:colon])).strip()
            )
        )
        var v = String(
            String(
                String(unsafe_from_utf8=line.as_bytes()[colon + 1 :])
            ).strip()
        )
        if k == "sec-websocket-key":
            ws_key = v
        elif k == "upgrade" and _lower_srv(v) == "websocket":
            found_upgrade = True
        elif k == "connection" and "upgrade" in _lower_srv(v):
            found_connection = True

    if not found_upgrade or not found_connection:
        raise NetworkError(
            "WebSocket upgrade request missing Upgrade: websocket or"
            " Connection: Upgrade headers"
        )
    if ws_key.byte_length() == 0:
        raise NetworkError(
            "WebSocket upgrade request missing Sec-WebSocket-Key"
        )
    return ws_key^


def _read_upgrade_request(mut stream: TcpStream) raises -> String:
    """Read an HTTP upgrade request and return the ``Sec-WebSocket-Key``.

    Reads until the blank line terminating HTTP headers.

    Args:
        stream: Accepted TCP stream.

    Returns:
        The ``Sec-WebSocket-Key`` header value.

    Raises:
        NetworkError: If the upgrade request is malformed or missing the key.
    """
    # Skip request line
    _ = _read_line_srv(stream)

    var ws_key = String("")
    var found_upgrade = False
    var found_connection = False

    while True:
        var line = _read_line_srv(stream)
        if line.byte_length() == 0:
            break
        var colon = _str_find_srv(line, ":")
        if colon < 0:
            continue
        var k = _lower_srv(
            String(
                String(String(unsafe_from_utf8=line.as_bytes()[:colon])).strip()
            )
        )
        var v = String(
            String(
                String(unsafe_from_utf8=line.as_bytes()[colon + 1 :])
            ).strip()
        )
        if k == "sec-websocket-key":
            ws_key = v
        elif k == "upgrade" and _lower_srv(v) == "websocket":
            found_upgrade = True
        elif k == "connection" and "upgrade" in _lower_srv(v):
            found_connection = True

    if not found_upgrade or not found_connection:
        raise NetworkError(
            "WebSocket upgrade request missing Upgrade: websocket or"
            " Connection: Upgrade headers"
        )
    if ws_key.byte_length() == 0:
        raise NetworkError(
            "WebSocket upgrade request missing Sec-WebSocket-Key"
        )
    return ws_key^


def _send_upgrade_response(mut stream: TcpStream, accept: String) raises:
    """Send the 101 Switching Protocols response.

    Args:
        stream: TCP stream for the client connection.
        accept: The computed ``Sec-WebSocket-Accept`` value.
    """
    var resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Accept: "
        + accept
        + "\r\n"
        + "\r\n"
    )
    var resp_bytes = resp.as_bytes()
    stream.write_all(Span[UInt8, _](resp_bytes))


# ── WsConnection ──────────────────────────────────────────────────────────────


struct WsConnection(Movable):
    """An accepted WebSocket connection (server side).

    Server-side frames MUST NOT be masked (RFC 6455 §5.3).
    Client-side frames MUST be masked; ``recv`` unmasks them automatically.

    This type is ``Movable`` but not ``Copyable``.

    Fields:
        _stream: The underlying TCP stream.
        _peer: The remote socket address.

    Example:
        ```mojo
        def on_connect(conn: WsConnection) raises:
            var frame = conn.recv()
            conn.send_text(frame.text_payload()) # echo back

        var srv = WsServer.bind(SocketAddr.localhost(9001))
        srv.serve(on_connect)
        ```
    """

    var _stream: TcpStream
    var _peer: SocketAddr

    def __init__(out self, var stream: TcpStream, peer: SocketAddr):
        self._stream = stream^
        self._peer = peer

    def __del__(deinit self):
        self._stream.close()

    def send_text(self, msg: String) raises:
        """Send a UTF-8 text message to the client.

        Server-to-client frames are NOT masked (RFC 6455 §5.3).

        Args:
            msg: The UTF-8 string to send.

        Raises:
            NetworkError: On I/O failure.
        """
        var frame = WsFrame.text(msg)
        var wire = frame.encode(mask=False)
        self._stream.write_all(Span[UInt8, _](wire))

    def send_binary(self, data: List[UInt8]) raises:
        """Send a binary message to the client.

        Server-to-client frames are NOT masked (RFC 6455 §5.3).

        Args:
            data: The raw binary payload.

        Raises:
            NetworkError: On I/O failure.
        """
        var frame = WsFrame.binary(data)
        var wire = frame.encode(mask=False)
        self._stream.write_all(Span[UInt8, _](wire))

    def send_frame(self, frame: WsFrame) raises:
        """Send an already-constructed frame (server, no masking).

        Args:
            frame: Frame to send. The ``mask`` bit is always ``False``.

        Raises:
            NetworkError: On I/O failure.
        """
        var wire = frame.encode(mask=False)
        self._stream.write_all(Span[UInt8, _](wire))

    def recv(mut self) raises -> WsFrame:
        """Receive the next data frame from the client.

        Automatically replies to PING frames with an unmasked PONG and
        continues reading. Returns TEXT or BINARY frames. Client frames
        are unmasked by ``WsFrame.decode_one`` automatically.

        Returns:
            The next complete data frame (TEXT, BINARY, or CLOSE).

        Raises:
            WsProtocolError: If the client sends an unmasked frame.
            NetworkError: On I/O failure.
        """
        while True:
            var frame = self._recv_one()
            if frame.opcode == WsOpcode.PING:
                # RFC 6455 §5.5.3: respond with unmasked PONG
                var pong = WsFrame.pong(frame.payload)
                var wire = pong.encode(mask=False)
                self._stream.write_all(Span[UInt8, _](wire))
                continue
            return frame^

    def _recv_one(mut self) raises -> WsFrame:
        """Read bytes from stream and decode one complete frame."""
        var buf = List[UInt8](capacity=4096)
        var tmp = List[UInt8](capacity=4096)
        tmp.resize(4096, 0)

        while True:
            try:
                var result = WsFrame.decode_one(Span[UInt8, _](buf))
                # RFC 6455 §5.1: server MUST close conn if client sends unmasked frame
                if not result.frame.masked:
                    raise WsProtocolError(
                        "client sent unmasked frame (RFC 6455 §5.1)"
                    )
                return result^.take_frame()
            except e:
                var msg = String(e)
                if (
                    "need at least" in msg
                    or "need " in msg
                    or "truncated" in msg
                ):
                    var n = self._stream.read(tmp.unsafe_ptr(), len(tmp))
                    if n == 0:
                        raise NetworkError(
                            "WebSocket connection closed unexpectedly"
                        )
                    for i in range(n):
                        buf.append(tmp[i])
                else:
                    raise e^

    def close(
        mut self,
        code: UInt16 = WsCloseCode.NORMAL,
        reason: String = "",
    ) raises:
        """Send a CLOSE frame and wait for the client's CLOSE response.

        Args:
            code: Close status code (see ``WsCloseCode.*``).
            reason: Optional UTF-8 reason phrase (≤123 bytes).
        """
        var close_frame = WsFrame.close(code, reason)
        var wire = close_frame.encode(mask=False)
        try:
            self._stream.write_all(Span[UInt8, _](wire))
        except:
            pass  # best-effort

    def peer_addr(self) -> SocketAddr:
        """Return the remote socket address.

        Returns:
            The client's ``SocketAddr``.
        """
        return self._peer


# ── WsServer ──────────────────────────────────────────────────────────────────


struct WsServer(Movable):
    """A WebSocket server that upgrades incoming HTTP connections.

    Accepts TCP connections, performs the HTTP Upgrade handshake, and
    calls ``handler`` once per established WebSocket connection.

    This type is ``Movable`` but not ``Copyable``.

    Fields:
        _listener: The bound TCP listener.

    Example:
        ```mojo
        def handle(conn: WsConnection) raises:
            while True:
                var frame = conn.recv()
                if frame.opcode == WsOpcode.CLOSE:
                    break
                conn.send_text(frame.text_payload())

        var srv = WsServer.bind(SocketAddr.localhost(9001))
        srv.serve(handle)
        ```
    """

    var _listener: TcpListener

    def __init__(out self, var listener: TcpListener):
        self._listener = listener^

    def __del__(deinit self):
        self._listener.close()

    @staticmethod
    def bind(addr: SocketAddr) raises -> WsServer:
        """Bind a WebSocket server on ``addr``.

        Args:
            addr: Local address to accept connections on.

        Returns:
            A ``WsServer`` ready to call ``serve()``.

        Raises:
            AddressInUse: If the port is already bound.
            NetworkError: For any other OS error.
        """
        var listener = TcpListener.bind(addr)
        return WsServer(listener^)

    def serve(self, handler: def(WsConnection) raises thin -> None) raises:
        """Accept WebSocket connections in a loop.

        For each accepted TCP connection:
            1. Read the HTTP Upgrade request.
            2. Compute ``Sec-WebSocket-Accept``.
            3. Send ``101 Switching Protocols``.
            4. Call ``handler(conn)``.

        Upgrade errors for individual connections are silently skipped;
        only fatal accept-loop errors propagate.

        Args:
            handler: Callback invoked once per successfully upgraded connection.

        Raises:
            NetworkError: On fatal accept-loop errors.
        """
        while True:
            var stream = self._listener.accept()
            var peer = stream.peer_addr()
            _handle_ws_connection(stream^, peer, handler)

    def local_addr(self) -> SocketAddr:
        """Return the local address the server is bound to.

        Returns:
            The bound ``SocketAddr``.
        """
        return self._listener.local_addr()

    def close(mut self):
        """Stop accepting connections. Idempotent."""
        self._listener.close()


def _handle_ws_connection(
    var stream: TcpStream,
    peer: SocketAddr,
    handler: def(WsConnection) raises thin -> None,
):
    """Perform the WebSocket handshake and call handler.

    Upgrade errors are swallowed so the accept loop continues.
    """
    try:
        var key = _read_upgrade_request(stream)
        var accept = _compute_accept_srv(key)
        _send_upgrade_response(stream, accept)
        var conn = WsConnection(stream^, peer)
        handler(conn^)
    except e:
        print("[ws] connection error: " + String(e))
