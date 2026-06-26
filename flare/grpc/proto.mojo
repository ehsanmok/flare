"""``flare.grpc.proto`` -- proto3 wire-format codec.

gRPC payloads are protobuf messages. Until now handler bodies had to
hand-roll ``List[UInt8]`` payloads with no serializer; this module is
that serializer -- the runtime the generated code (or a hand-written
message struct) targets.

proto3 binary wire format (https://protobuf.dev/programming-guides/encoding/):
a message is a flat sequence of ``(tag, value)`` records. The tag is a
varint ``(field_number << 3) | wire_type``:

* 0 ``VARINT``  -- int32/64, uint32/64, sint32/64 (zigzag), bool, enum
* 1 ``I64``     -- fixed64, sfixed64, double
* 2 ``LEN``     -- string, bytes, embedded message, packed repeated
* 5 ``I32``     -- fixed32, sfixed32, float

:class:`ProtoWriter` appends typed fields to an owned buffer;
:class:`ProtoReader` walks a buffer field by field and decodes by wire
type, with :meth:`ProtoReader.skip` for unknown fields (proto3 forward
compatibility). proto3 omits scalar fields equal to their default
(``0`` / ``false`` / empty) on the wire -- the writers here are
low-level (they always emit), so the caller / codegen applies the
default-skip policy.

This is a sans-I/O codec: bytes in, bytes out. No reflection, no
descriptors -- those live in :mod:`flare.grpc.reflection`.
"""

from std.collections import List
from std.memory import Span, stack_allocation


# ── Wire types ────────────────────────────────────────────────────────────────
comptime WIRE_VARINT: Int = 0
comptime WIRE_I64: Int = 1
comptime WIRE_LEN: Int = 2
comptime WIRE_I32: Int = 5


@always_inline
def _zigzag_encode(v: Int64) -> UInt64:
    """ZigZag map a signed 64-bit int to an unsigned varint payload
    (proto3 ``sint32`` / ``sint64``): ``(n << 1) ^ (n >> 63)``."""
    return UInt64((v << 1) ^ (v >> 63))


@always_inline
def _zigzag_decode(v: UInt64) -> Int64:
    """Inverse of :func:`_zigzag_encode`."""
    return Int64(v >> 1) ^ -Int64(v & UInt64(1))


@always_inline
def _f64_from_bits(bits: UInt64) -> Float64:
    """Reinterpret a 64-bit pattern as a ``Float64`` (IEEE-754).

    The stdlib exposes ``Float64.to_bits()`` but no inverse, so we
    round-trip through a 1-cell stack slot and a pointer bitcast.
    """
    var p = stack_allocation[1, UInt64]()
    p[0] = bits
    return p.bitcast[Float64]()[0]


@always_inline
def _f32_from_bits(bits: UInt32) -> Float32:
    """Reinterpret a 32-bit pattern as a ``Float32`` (IEEE-754)."""
    var p = stack_allocation[1, UInt32]()
    p[0] = bits
    return p.bitcast[Float32]()[0]


# ── Writer ─────────────────────────────────────────────────────────────────────


struct ProtoWriter(Copyable, Movable):
    """Accumulates proto3-encoded fields into an owned byte buffer.

    Example:
        ```mojo
        var w = ProtoWriter()
        w.write_string(1, "hello")     # field 1: string
        w.write_int64(2, 42)           # field 2: int64
        w.write_bool(3, True)          # field 3: bool
        var payload = w.take()         # List[UInt8] ready for LPM framing
        ```
    """

    var buf: List[UInt8]

    def __init__(out self):
        self.buf = List[UInt8]()

    def __len__(self) -> Int:
        return len(self.buf)

    def take(mut self) -> List[UInt8]:
        """Move the accumulated bytes out, leaving the writer empty."""
        var out = self.buf^
        self.buf = List[UInt8]()
        return out^

    def bytes(self) -> List[UInt8]:
        """Copy the accumulated bytes (writer stays usable)."""
        return self.buf.copy()

    def _raw_varint(mut self, value: UInt64):
        var v = value
        while True:
            var byte = UInt8(Int(v & UInt64(0x7F)))
            v = v >> UInt64(7)
            if v != UInt64(0):
                self.buf.append(byte | UInt8(0x80))
            else:
                self.buf.append(byte)
                break

    def _tag(mut self, field: Int, wire: Int):
        self._raw_varint(UInt64((field << 3) | wire))

    def write_uint64(mut self, field: Int, value: UInt64):
        self._tag(field, WIRE_VARINT)
        self._raw_varint(value)

    def write_int64(mut self, field: Int, value: Int64):
        # int32/int64 are encoded as their two's-complement in a varint
        # (always 10 bytes for negatives, per spec).
        self._tag(field, WIRE_VARINT)
        self._raw_varint(UInt64(value))

    def write_sint64(mut self, field: Int, value: Int64):
        self._tag(field, WIRE_VARINT)
        self._raw_varint(_zigzag_encode(value))

    def write_bool(mut self, field: Int, value: Bool):
        self._tag(field, WIRE_VARINT)
        self._raw_varint(UInt64(1) if value else UInt64(0))

    def write_enum(mut self, field: Int, value: Int):
        self._tag(field, WIRE_VARINT)
        self._raw_varint(UInt64(value))

    def write_fixed64(mut self, field: Int, value: UInt64):
        self._tag(field, WIRE_I64)
        for k in range(8):
            self.buf.append(UInt8(Int((value >> UInt64(k * 8)) & UInt64(0xFF))))

    def write_fixed32(mut self, field: Int, value: UInt32):
        self._tag(field, WIRE_I32)
        for k in range(4):
            self.buf.append(UInt8(Int((value >> UInt32(k * 8)) & UInt32(0xFF))))

    def write_double(mut self, field: Int, value: Float64):
        self.write_fixed64(field, UInt64(value.to_bits()))

    def write_float(mut self, field: Int, value: Float32):
        self.write_fixed32(field, UInt32(value.to_bits()))

    def write_bytes(mut self, field: Int, value: Span[UInt8, _]):
        self._tag(field, WIRE_LEN)
        self._raw_varint(UInt64(len(value)))
        for i in range(len(value)):
            self.buf.append(value[i])

    def write_string(mut self, field: Int, value: String):
        self.write_bytes(field, value.as_bytes())

    def write_message(mut self, field: Int, sub: Span[UInt8, _]):
        """Embed a pre-encoded sub-message (its own proto3 bytes)."""
        self.write_bytes(field, sub)


# ── Reader ─────────────────────────────────────────────────────────────────────


struct ProtoReader(Copyable, Movable):
    """Walks a proto3-encoded buffer field by field.

    Typical loop::

        var r = ProtoReader(payload)
        while r.has_more():
            var tw = r.read_tag()       # (field_number, wire_type)
            if tw[0] == 1 and tw[1] == WIRE_LEN:
                var name = r.read_string()
            elif tw[0] == 2 and tw[1] == WIRE_VARINT:
                var age = r.read_int64()
            else:
                r.skip(tw[1])           # unknown field: forward-compat
    """

    var data: List[UInt8]
    var pos: Int

    def __init__(out self, buf: Span[UInt8, _]):
        self.data = List[UInt8](capacity=len(buf))
        for i in range(len(buf)):
            self.data.append(buf[i])
        self.pos = 0

    def has_more(self) -> Bool:
        return self.pos < len(self.data)

    def _raw_varint(mut self) raises -> UInt64:
        var result = UInt64(0)
        var shift = 0
        while True:
            if self.pos >= len(self.data):
                raise Error("proto: truncated varint")
            if shift >= 64:
                raise Error("proto: varint overflow")
            var byte = self.data[self.pos]
            self.pos += 1
            result = result | (UInt64(Int(byte & UInt8(0x7F))) << UInt64(shift))
            if (byte & UInt8(0x80)) == UInt8(0):
                break
            shift += 7
        return result

    def read_tag(mut self) raises -> Tuple[Int, Int]:
        var key = self._raw_varint()
        var field = Int(key >> UInt64(3))
        var wire = Int(key & UInt64(0x07))
        if field <= 0:
            raise Error("proto: invalid field number " + String(field))
        return Tuple(field, wire)

    def read_uint64(mut self) raises -> UInt64:
        return self._raw_varint()

    def read_int64(mut self) raises -> Int64:
        return Int64(self._raw_varint())

    def read_sint64(mut self) raises -> Int64:
        return _zigzag_decode(self._raw_varint())

    def read_bool(mut self) raises -> Bool:
        return self._raw_varint() != UInt64(0)

    def read_enum(mut self) raises -> Int:
        return Int(self._raw_varint())

    def _raw_fixed(mut self, width: Int) raises -> UInt64:
        if self.pos + width > len(self.data):
            raise Error("proto: truncated fixed field")
        var v = UInt64(0)
        for k in range(width):
            v = v | (UInt64(Int(self.data[self.pos + k])) << UInt64(k * 8))
        self.pos += width
        return v

    def read_fixed64(mut self) raises -> UInt64:
        return self._raw_fixed(8)

    def read_fixed32(mut self) raises -> UInt32:
        return UInt32(self._raw_fixed(4))

    def read_double(mut self) raises -> Float64:
        return _f64_from_bits(self._raw_fixed(8))

    def read_float(mut self) raises -> Float32:
        return _f32_from_bits(UInt32(self._raw_fixed(4)))

    def read_bytes(mut self) raises -> List[UInt8]:
        var n = Int(self._raw_varint())
        if n < 0 or self.pos + n > len(self.data):
            raise Error("proto: truncated length-delimited field")
        var out = List[UInt8](capacity=n)
        for i in range(n):
            out.append(self.data[self.pos + i])
        self.pos += n
        return out^

    def read_string(mut self) raises -> String:
        var b = self.read_bytes()
        return String(unsafe_from_utf8=Span[UInt8, _](b))

    def skip(mut self, wire: Int) raises:
        """Advance past one field's value of the given wire type
        (proto3 unknown-field forward compatibility)."""
        if wire == WIRE_VARINT:
            _ = self._raw_varint()
        elif wire == WIRE_I64:
            _ = self._raw_fixed(8)
        elif wire == WIRE_I32:
            _ = self._raw_fixed(4)
        elif wire == WIRE_LEN:
            var n = Int(self._raw_varint())
            if n < 0 or self.pos + n > len(self.data):
                raise Error("proto: truncated skipped field")
            self.pos += n
        else:
            raise Error("proto: cannot skip wire type " + String(wire))
