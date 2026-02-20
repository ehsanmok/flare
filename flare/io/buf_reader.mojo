"""Buffered reader for stream I/O.

Wraps any type that implements the ``Readable`` trait and provides
line-oriented reading (``readline``, ``read_until``, ``read_exact``).
All reads go through an internal buffer so that the underlying stream is
called as infrequently as possible.

Example:
    ```mojo
    from flare.tcp import TcpStream
    from flare.io import BufReader

    var stream = TcpStream.connect("example.com", 80)
    var reader = BufReader(stream^)
    var line = reader.readline()     # Read one HTTP header line
    ```
"""

from ..net import NetworkError


# ── Readable trait ────────────────────────────────────────────────────────────


trait Readable(ImplicitlyDestructible, Movable):
    """A byte stream that can be read into a mutable buffer.

    Extends ``Movable`` so that streams can be transferred into ``BufReader``.
    Implementors must provide ``read`` — all other helpers (``read_exact``,
    etc.) are layered on top by ``BufReader``.

    Example:
        ```mojo
        struct MyStream(Readable):
            fn read(mut self, buf: UnsafePointer[UInt8], size: Int) raises -> Int:
                ...
        ```
    """

    fn read(mut self, buf: UnsafePointer[UInt8], size: Int) raises -> Int:
        """Read up to ``size`` bytes into the buffer at ``buf``.

        Args:
            buf:  Destination pointer. The caller must own at least ``size``
                  bytes of initialised storage at this address.
            size: Maximum number of bytes to read.

        Returns:
            Number of bytes written into ``buf``. ``0`` means EOF.

        Raises:
            NetworkError: On any I/O error.
        """
        ...


# ── BufReader ─────────────────────────────────────────────────────────────────

comptime _BUF_READER_DEFAULT_SIZE: Int = 8192


struct BufReader[S: Readable](Movable):
    """A buffered byte reader wrapping any ``Readable`` stream.

    Reduces the number of syscalls by reading ahead into an internal
    buffer and serving ``readline`` / ``read_until`` / ``read_exact``
    from that buffer.

    Parameters:
        S: Any type implementing the ``Readable`` trait (e.g. ``TcpStream``).

    Fields:
        _stream:    The underlying stream (owned).
        _buf:       Internal ring buffer.
        _pos:       Byte offset of the next unread byte in ``_buf``.
        _len:       Number of valid bytes in ``_buf`` starting at ``_pos``.

    Example:
        ```mojo
        from flare.tcp import TcpStream
        from flare.io import BufReader

        var s = TcpStream.connect("example.com", 80)
        var r = BufReader(s^)
        s.write_all("GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n".as_bytes())
        while True:
            var line = r.readline()
            if len(line) == 0:
                break
            print(line)
        ```
    """

    var _stream: Self.S
    var _buf: List[UInt8]
    var _pos: Int
    var _len: Int

    fn __init__(
        out self, var stream: Self.S, capacity: Int = _BUF_READER_DEFAULT_SIZE
    ):
        """Wrap ``stream`` with a read buffer of ``capacity`` bytes.

        Args:
            stream:   The underlying ``Readable`` stream (ownership taken).
            capacity: Internal buffer size in bytes (default 8192).
        """
        self._stream = stream^
        var cap = capacity if capacity > 0 else _BUF_READER_DEFAULT_SIZE
        self._buf = List[UInt8](capacity=cap)
        self._buf.resize(cap, 0)
        self._pos = 0
        self._len = 0

    fn __moveinit__(out self, deinit take: BufReader[Self.S]):
        self._stream = take._stream^
        self._buf = take._buf^
        self._pos = take._pos
        self._len = take._len

    # ── Internal helpers ──────────────────────────────────────────────────────

    fn _fill(mut self) raises -> Bool:
        """Refill the internal buffer from the stream.

        Resets the ring buffer to the beginning before reading.

        Returns:
            ``True`` if at least one byte was read; ``False`` on EOF.

        Raises:
            NetworkError: On any I/O error.
        """
        self._pos = 0
        self._len = 0
        var cap = len(self._buf)
        var n = self._stream.read(self._buf.unsafe_ptr(), cap)
        self._len = n
        return n > 0

    fn _peek_byte(mut self) raises -> Optional[UInt8]:
        """Return the next byte without consuming it, filling buffer as needed.

        Returns:
            The next byte wrapped in ``Optional``, or ``None`` on EOF.

        Raises:
            NetworkError: On any I/O error.
        """
        if self._len == 0:
            if not self._fill():
                return None
        return Optional[UInt8](self._buf[self._pos])

    fn _consume_byte(mut self) raises -> Optional[UInt8]:
        """Read and return the next byte, filling buffer as needed.

        Returns:
            The byte wrapped in ``Optional``, or ``None`` on EOF.

        Raises:
            NetworkError: On any I/O error.
        """
        if self._len == 0:
            if not self._fill():
                return None
        var b = self._buf[self._pos]
        self._pos += 1
        self._len -= 1
        return Optional[UInt8](b)

    # ── Public API ────────────────────────────────────────────────────────────

    fn readline(mut self) raises -> String:
        """Read one line terminated by ``\\n`` (LF) from the stream.

        The newline character is stripped from the returned string.
        ``\\r\\n`` (CRLF) is also handled — the ``\\r`` is stripped too.

        Returns:
            The line without the trailing newline.  An empty string
            signals EOF — the stream is exhausted.

        Raises:
            NetworkError: On any I/O error.

        Example:
            ```mojo
            var line = reader.readline()  # e.g. "HTTP/1.1 200 OK"
            ```
        """
        var out = String(capacity=256)
        while True:
            var mb = self._consume_byte()
            if not mb:
                break
            var b = mb.value()
            if b == 10:  # LF
                break
            if b == 13:  # CR — peek ahead for LF
                var next = self._peek_byte()
                if next and next.value() == 10:
                    _ = self._consume_byte()  # consume LF
                break
            out += chr(Int(b))
        return out^

    fn read_until(mut self, delimiter: UInt8) raises -> String:
        """Read bytes until ``delimiter`` is encountered.

        The delimiter itself is consumed but not included in the result.

        Args:
            delimiter: The byte value to stop at.

        Returns:
            All bytes before the delimiter as a ``String``.  Empty string
            on immediate EOF.

        Raises:
            NetworkError: On any I/O error.

        Example:
            ```mojo
            var field = reader.read_until(ord(","))
            ```
        """
        var out = String(capacity=256)
        while True:
            var mb = self._consume_byte()
            if not mb:
                break
            var b = mb.value()
            if b == delimiter:
                break
            out += chr(Int(b))
        return out^

    fn read_exact(mut self, n: Int) raises -> List[UInt8]:
        """Read exactly ``n`` bytes from the stream.

        Loops until ``n`` bytes have been accumulated or EOF/error.

        Args:
            n: Number of bytes to read.

        Returns:
            A ``List[UInt8]`` of length exactly ``n``.

        Raises:
            NetworkError: If EOF is reached before ``n`` bytes are available.

        Example:
            ```mojo
            var header = reader.read_exact(4)
            ```
        """
        var out = List[UInt8](capacity=n)
        var remaining = n
        while remaining > 0:
            var mb = self._consume_byte()
            if not mb:
                raise NetworkError(
                    "read_exact: EOF after "
                    + String(n - remaining)
                    + "/"
                    + String(n)
                    + " bytes"
                )
            out.append(mb.value())
            remaining -= 1
        return out^
