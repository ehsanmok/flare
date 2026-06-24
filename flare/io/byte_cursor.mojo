"""Safe, bounds-checked byte cursors.

``ByteReader`` and ``ByteWriter`` are the v0.9 replacement for the
hand-rolled big-endian readers and unchecked ``String(unsafe_from_utf8=...)``
construction that a custom protocol front otherwise reaches for. Every
read is bounds-checked (a short buffer raises rather than reading out
of bounds); ``read_utf8`` validates UTF-8 before constructing the
``String``.

These are sans-I/O value types over an in-memory buffer -- they import
nothing from the reactor / socket layers -- so they are equally usable
in a parser, a fuzz harness, or the multiplexed frame codec
(``flare.uds.frame_mux``) that builds on them.

## ByteReader

Borrows a ``Span[UInt8, origin]``; the ``origin`` parameter ties the
reader's lifetime to the buffer it reads from, so the borrow checker
prevents the reader (and any ``read_bytes`` sub-span) from outliving
the buffer.

```mojo
from flare.io import ByteReader

var raw = List[UInt8](0x00, 0x00, 0x00, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F)
var r = ByteReader(Span[UInt8, _](raw))
var n = r.read_u32_be()      # 5
var s = r.read_utf8(Int(n))  # "hello" (validated)
```

## ByteWriter

Owns a growable ``List[UInt8]``; the inverse of ``ByteReader``. Both
big-endian and little-endian integer widths are provided on each side.

```mojo
from flare.io import ByteWriter

var w = ByteWriter()
w.write_u32_be(5)
w.write_str("hello")
var frame = w.take()  # List[UInt8]
```
"""

from std.memory import memcpy


# ── UTF-8 validation ───────────────────────────────────────────────────────


@always_inline
def _is_valid_utf8(data: Span[UInt8, _]) -> Bool:
    """Validate that ``data`` is well-formed UTF-8 (RFC 3629).

    Rejects overlong encodings, UTF-16 surrogates (U+D800..U+DFFF),
    and codepoints above U+10FFFF. Mirrors the WebSocket text-frame
    validator (``flare/ws/frame.mojo``) but operates over a borrowed
    span so it never copies.
    """
    var n = len(data)
    var i = 0
    while i < n:
        var b = data[i]
        if b <= 0x7F:
            i += 1
        elif b >= 0xC2 and b <= 0xDF:
            if i + 1 >= n:
                return False
            if data[i + 1] < 0x80 or data[i + 1] > 0xBF:
                return False
            i += 2
        elif b >= 0xE0 and b <= 0xEF:
            if i + 2 >= n:
                return False
            var b1 = data[i + 1]
            var b2 = data[i + 2]
            if b1 < 0x80 or b1 > 0xBF or b2 < 0x80 or b2 > 0xBF:
                return False
            if b == 0xE0 and b1 < 0xA0:
                return False
            if b == 0xED and b1 > 0x9F:
                return False
            i += 3
        elif b >= 0xF0 and b <= 0xF4:
            if i + 3 >= n:
                return False
            var b1 = data[i + 1]
            var b2 = data[i + 2]
            var b3 = data[i + 3]
            if (
                b1 < 0x80
                or b1 > 0xBF
                or b2 < 0x80
                or b2 > 0xBF
                or b3 < 0x80
                or b3 > 0xBF
            ):
                return False
            if b == 0xF0 and b1 < 0x90:
                return False
            if b == 0xF4 and b1 > 0x8F:
                return False
            i += 4
        else:
            return False
    return True


# ── ByteReader ─────────────────────────────────────────────────────────────


struct ByteReader[origin: Origin](Movable):
    """Bounds-checked cursor over a borrowed byte span.

    Holds the borrowed ``buf`` and a read position ``pos``. Every
    ``read_*`` advances ``pos`` and raises ``Error`` if the buffer is
    too short, so a malformed/truncated input can never read out of
    bounds. ``read_utf8`` additionally validates UTF-8.
    """

    var buf: Span[UInt8, Self.origin]
    """Borrowed source buffer. Lifetime tied to ``origin``."""
    var pos: Int
    """Number of bytes already consumed from the front of ``buf``."""

    @always_inline
    def __init__(out self, buf: Span[UInt8, Self.origin]):
        """Construct a reader positioned at the start of ``buf``."""
        self.buf = buf
        self.pos = 0

    @always_inline
    def remaining(self) -> Int:
        """Bytes left to read (``len(buf) - pos``)."""
        return len(self.buf) - self.pos

    @always_inline
    def position(self) -> Int:
        """Current read offset from the start of ``buf``."""
        return self.pos

    @always_inline
    def _need(self, n: Int) raises:
        """Raise unless ``n`` more bytes are available."""
        if n < 0 or self.pos + n > len(self.buf):
            raise Error(
                "ByteReader: read of "
                + String(n)
                + " bytes past end (pos="
                + String(self.pos)
                + ", len="
                + String(len(self.buf))
                + ")"
            )

    @always_inline
    def read_u8(mut self) raises -> UInt8:
        """Read one byte."""
        self._need(1)
        var v = self.buf[self.pos]
        self.pos += 1
        return v

    @always_inline
    def read_u16_be(mut self) raises -> UInt16:
        """Read a big-endian ``u16``."""
        self._need(2)
        var p = self.pos
        var v = (UInt16(self.buf[p]) << 8) | UInt16(self.buf[p + 1])
        self.pos += 2
        return v

    @always_inline
    def read_u16_le(mut self) raises -> UInt16:
        """Read a little-endian ``u16``."""
        self._need(2)
        var p = self.pos
        var v = UInt16(self.buf[p]) | (UInt16(self.buf[p + 1]) << 8)
        self.pos += 2
        return v

    @always_inline
    def read_u32_be(mut self) raises -> UInt32:
        """Read a big-endian ``u32``."""
        self._need(4)
        var p = self.pos
        var v = (
            (UInt32(self.buf[p]) << 24)
            | (UInt32(self.buf[p + 1]) << 16)
            | (UInt32(self.buf[p + 2]) << 8)
            | UInt32(self.buf[p + 3])
        )
        self.pos += 4
        return v

    @always_inline
    def read_u32_le(mut self) raises -> UInt32:
        """Read a little-endian ``u32``."""
        self._need(4)
        var p = self.pos
        var v = (
            UInt32(self.buf[p])
            | (UInt32(self.buf[p + 1]) << 8)
            | (UInt32(self.buf[p + 2]) << 16)
            | (UInt32(self.buf[p + 3]) << 24)
        )
        self.pos += 4
        return v

    @always_inline
    def read_u64_be(mut self) raises -> UInt64:
        """Read a big-endian ``u64``."""
        self._need(8)
        var p = self.pos
        var v: UInt64 = 0
        for k in range(8):
            v = (v << 8) | UInt64(self.buf[p + k])
        self.pos += 8
        return v

    @always_inline
    def read_u64_le(mut self) raises -> UInt64:
        """Read a little-endian ``u64``."""
        self._need(8)
        var p = self.pos
        var v: UInt64 = 0
        for k in range(8):
            v |= UInt64(self.buf[p + k]) << (UInt64(k) * 8)
        self.pos += 8
        return v

    def read_bytes(mut self, n: Int) raises -> Span[UInt8, Self.origin]:
        """Borrow the next ``n`` bytes as a sub-span (no copy).

        The returned span shares ``origin`` with this reader's buffer.
        """
        self._need(n)
        var s = self.buf[self.pos : self.pos + n]
        self.pos += n
        return s

    def read_utf8(mut self, n: Int) raises -> String:
        """Read ``n`` bytes and return them as a validated ``String``.

        Raises if fewer than ``n`` bytes remain or the bytes are not
        well-formed UTF-8.
        """
        self._need(n)
        var s = self.buf[self.pos : self.pos + n]
        if not _is_valid_utf8(s):
            raise Error("ByteReader: invalid UTF-8 in read_utf8")
        self.pos += n
        if n == 0:
            return String("")
        var out = String(unsafe_uninit_length=n)
        memcpy(dest=out.unsafe_ptr_mut(), src=s.unsafe_ptr(), count=n)
        return out^

    def skip(mut self, n: Int) raises:
        """Advance the cursor by ``n`` bytes without reading them."""
        self._need(n)
        self.pos += n


# ── ByteWriter ─────────────────────────────────────────────────────────────


struct ByteWriter(Movable):
    """Owns a growable byte buffer; the inverse of ``ByteReader``.

    Integer writers are infallible (the backing ``List`` grows as
    needed). Call ``take()`` to move the accumulated bytes out, or
    ``bytes()`` to copy them.
    """

    var buf: List[UInt8]
    """Accumulated output bytes."""

    @always_inline
    def __init__(out self):
        """Construct an empty writer."""
        self.buf = List[UInt8]()

    @always_inline
    def __init__(out self, var buf: List[UInt8]):
        """Construct a writer that appends onto an existing buffer."""
        self.buf = buf^

    @always_inline
    def len(self) -> Int:
        """Number of bytes written so far."""
        return len(self.buf)

    @always_inline
    def write_u8(mut self, v: UInt8):
        """Append one byte."""
        self.buf.append(v)

    @always_inline
    def write_u16_be(mut self, v: UInt16):
        """Append a big-endian ``u16``."""
        self.buf.append(UInt8((v >> 8) & 0xFF))
        self.buf.append(UInt8(v & 0xFF))

    @always_inline
    def write_u16_le(mut self, v: UInt16):
        """Append a little-endian ``u16``."""
        self.buf.append(UInt8(v & 0xFF))
        self.buf.append(UInt8((v >> 8) & 0xFF))

    @always_inline
    def write_u32_be(mut self, v: UInt32):
        """Append a big-endian ``u32``."""
        self.buf.append(UInt8((v >> 24) & 0xFF))
        self.buf.append(UInt8((v >> 16) & 0xFF))
        self.buf.append(UInt8((v >> 8) & 0xFF))
        self.buf.append(UInt8(v & 0xFF))

    @always_inline
    def write_u32_le(mut self, v: UInt32):
        """Append a little-endian ``u32``."""
        self.buf.append(UInt8(v & 0xFF))
        self.buf.append(UInt8((v >> 8) & 0xFF))
        self.buf.append(UInt8((v >> 16) & 0xFF))
        self.buf.append(UInt8((v >> 24) & 0xFF))

    @always_inline
    def write_u64_be(mut self, v: UInt64):
        """Append a big-endian ``u64``."""
        for k in range(8):
            var shift = UInt64(56 - k * 8)
            self.buf.append(UInt8((v >> shift) & 0xFF))

    @always_inline
    def write_u64_le(mut self, v: UInt64):
        """Append a little-endian ``u64``."""
        for k in range(8):
            var shift = UInt64(k * 8)
            self.buf.append(UInt8((v >> shift) & 0xFF))

    def write_bytes(mut self, b: Span[UInt8, _]):
        """Append every byte of ``b`` (single resize + memcpy)."""
        var n = len(b)
        if n == 0:
            return
        var old = len(self.buf)
        self.buf.resize(old + n, UInt8(0))
        memcpy(dest=self.buf.unsafe_ptr() + old, src=b.unsafe_ptr(), count=n)

    def write_str(mut self, s: StringSlice):
        """Append the UTF-8 bytes of ``s``."""
        self.write_bytes(s.as_bytes())

    def bytes(self) -> List[UInt8]:
        """Return a copy of the accumulated bytes."""
        return self.buf.copy()

    def take(mut self) -> List[UInt8]:
        """Move the accumulated bytes out, leaving the writer empty."""
        var out = self.buf^
        self.buf = List[UInt8]()
        return out^
