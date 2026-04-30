"""HPACK header compression (RFC 7541).

This is a complete-but-pragmatic decoder + encoder:

- Static table from RFC 7541 Appendix A.
- Dynamic table with size-eviction (RFC 7541 §4).
- Integer codec (RFC 7541 §5.1) — 7-bit / 6-bit / 5-bit / 4-bit
  prefixes are all handled by :func:`decode_integer` /
  :func:`encode_integer`.
- String literal codec (RFC 7541 §5.2) **without Huffman**: we
  emit ``H=0`` (raw) on the encode side and tolerate ``H=1`` on
  the decode side by raising — flare's encoder always sends raw
  literals so this is consistent. Adding Huffman is an optional
  optimisation.
- ``Indexed Header Field`` (§6.1), ``Literal Header Field with
  Incremental Indexing`` (§6.2.1), ``Literal Header Field without
  Indexing`` (§6.2.2), ``Literal Header Field Never Indexed``
  (§6.2.3), and ``Dynamic Table Size Update`` (§6.3).

The dynamic table eviction policy follows §4.2: a header that
exceeds the current ``max_size`` triggers full eviction; smaller
inserts evict the oldest entry until ``size <= max_size``.
"""

from std.collections import Optional


# ── Integer codec (§5.1) ─────────────────────────────────────────────────


struct StringPair(Copyable, Defaultable, Movable):
    """Tuple of (string, new_offset)."""

    var value: String
    var offset: Int

    def __init__(out self):
        self.value = ""
        self.offset = 0

    def __init__(out self, var value: String, offset: Int):
        self.value = value^
        self.offset = offset


struct IntPair(Copyable, Defaultable, Movable):
    """Tuple of (value, new_offset) used by :func:`decode_integer`."""

    var value: Int
    var offset: Int

    def __init__(out self):
        self.value = 0
        self.offset = 0

    def __init__(out self, value: Int, offset: Int):
        self.value = value
        self.offset = offset


def decode_integer(
    buf: Span[UInt8, _], offset: Int, prefix_bits: Int
) raises -> IntPair:
    """Decode an integer with ``prefix_bits``-bit prefix at ``offset``.

    Returns an :class:`IntPair` of ``(value, new_offset)``.
    ``prefix_bits`` is one of 4, 5, 6, 7. Raises on truncated input
    or pathologically large values (we cap at 2**31 to stop
    allocation amplification).
    """
    if offset >= len(buf):
        raise Error("hpack: integer truncated")
    var max_prefix = (1 << prefix_bits) - 1
    var b0 = Int(buf[offset]) & max_prefix
    var off = offset + 1
    if b0 < max_prefix:
        return IntPair(b0, off)
    var value = b0
    var m = 0
    while True:
        if off >= len(buf):
            raise Error("hpack: integer continuation truncated")
        var b = Int(buf[off])
        off += 1
        value += (b & 0x7F) << m
        if value > (1 << 31):
            raise Error("hpack: integer overflow")
        if (b & 0x80) == 0:
            return IntPair(value, off)
        m += 7
        if m >= 35:
            raise Error("hpack: integer prefix too long")


def encode_integer(
    mut out_buf: List[UInt8],
    value: Int,
    prefix_bits: Int,
    prefix_byte: UInt8,
):
    """Append ``value`` to ``out_buf`` using ``prefix_bits`` prefix.

    The high bits of ``prefix_byte`` (above ``prefix_bits``) are
    preserved; the prefix-bit slot is overwritten.
    """
    var max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        out_buf.append((prefix_byte & UInt8(0xFF - max_prefix)) | UInt8(value))
        return
    out_buf.append((prefix_byte & UInt8(0xFF - max_prefix)) | UInt8(max_prefix))
    var v = value - max_prefix
    while v >= 128:
        out_buf.append(UInt8(0x80 | (v & 0x7F)))
        v >>= 7
    out_buf.append(UInt8(v))


# ── HpackHeader ─────────────────────────────────────────────────────────


struct HpackHeader(Copyable, Defaultable, Movable):
    """A decoded ``(name, value)`` header pair."""

    var name: String
    var value: String

    def __init__(out self):
        self.name = ""
        self.value = ""

    def __init__(out self, var name: String, var value: String):
        self.name = name^
        self.value = value^


# ── Static table (RFC 7541 Appendix A) ──────────────────────────────────


def _static_table() -> List[HpackHeader]:
    var t = List[HpackHeader](capacity=62)
    t.append(HpackHeader("", ""))  # 0 — unused; HPACK indices are 1-based
    t.append(HpackHeader(":authority", ""))
    t.append(HpackHeader(":method", "GET"))
    t.append(HpackHeader(":method", "POST"))
    t.append(HpackHeader(":path", "/"))
    t.append(HpackHeader(":path", "/index.html"))
    t.append(HpackHeader(":scheme", "http"))
    t.append(HpackHeader(":scheme", "https"))
    t.append(HpackHeader(":status", "200"))
    t.append(HpackHeader(":status", "204"))
    t.append(HpackHeader(":status", "206"))
    t.append(HpackHeader(":status", "304"))
    t.append(HpackHeader(":status", "400"))
    t.append(HpackHeader(":status", "404"))
    t.append(HpackHeader(":status", "500"))
    t.append(HpackHeader("accept-charset", ""))
    t.append(HpackHeader("accept-encoding", "gzip, deflate"))
    t.append(HpackHeader("accept-language", ""))
    t.append(HpackHeader("accept-ranges", ""))
    t.append(HpackHeader("accept", ""))
    t.append(HpackHeader("access-control-allow-origin", ""))
    t.append(HpackHeader("age", ""))
    t.append(HpackHeader("allow", ""))
    t.append(HpackHeader("authorization", ""))
    t.append(HpackHeader("cache-control", ""))
    t.append(HpackHeader("content-disposition", ""))
    t.append(HpackHeader("content-encoding", ""))
    t.append(HpackHeader("content-language", ""))
    t.append(HpackHeader("content-length", ""))
    t.append(HpackHeader("content-location", ""))
    t.append(HpackHeader("content-range", ""))
    t.append(HpackHeader("content-type", ""))
    t.append(HpackHeader("cookie", ""))
    t.append(HpackHeader("date", ""))
    t.append(HpackHeader("etag", ""))
    t.append(HpackHeader("expect", ""))
    t.append(HpackHeader("expires", ""))
    t.append(HpackHeader("from", ""))
    t.append(HpackHeader("host", ""))
    t.append(HpackHeader("if-match", ""))
    t.append(HpackHeader("if-modified-since", ""))
    t.append(HpackHeader("if-none-match", ""))
    t.append(HpackHeader("if-range", ""))
    t.append(HpackHeader("if-unmodified-since", ""))
    t.append(HpackHeader("last-modified", ""))
    t.append(HpackHeader("link", ""))
    t.append(HpackHeader("location", ""))
    t.append(HpackHeader("max-forwards", ""))
    t.append(HpackHeader("proxy-authenticate", ""))
    t.append(HpackHeader("proxy-authorization", ""))
    t.append(HpackHeader("range", ""))
    t.append(HpackHeader("referer", ""))
    t.append(HpackHeader("refresh", ""))
    t.append(HpackHeader("retry-after", ""))
    t.append(HpackHeader("server", ""))
    t.append(HpackHeader("set-cookie", ""))
    t.append(HpackHeader("strict-transport-security", ""))
    t.append(HpackHeader("transfer-encoding", ""))
    t.append(HpackHeader("user-agent", ""))
    t.append(HpackHeader("vary", ""))
    t.append(HpackHeader("via", ""))
    t.append(HpackHeader("www-authenticate", ""))
    return t^


comptime STATIC_TABLE_LEN = 61


# ── HpackDecoder ─────────────────────────────────────────────────────────


struct HpackDecoder(Copyable, Defaultable, Movable):
    """Stateful HPACK decoder.

    A decoder must be reused across all HEADERS frames on a single
    connection so the dynamic table tracks the peer's encoder.
    """

    var dynamic: List[HpackHeader]
    var dynamic_size: Int
    var max_size: Int

    def __init__(out self):
        self.dynamic = List[HpackHeader]()
        self.dynamic_size = 0
        self.max_size = 4096

    def _entry_size(self, h: HpackHeader) -> Int:
        return h.name.byte_length() + h.value.byte_length() + 32

    def _evict_to_fit(mut self, room: Int):
        while self.dynamic_size + room > self.max_size and (
            len(self.dynamic) > 0
        ):
            var last = self.dynamic[len(self.dynamic) - 1].copy()
            var sz = self._entry_size(last)
            self.dynamic_size -= sz
            self.dynamic.resize(len(self.dynamic) - 1, HpackHeader())

    def _insert(mut self, h: HpackHeader):
        var sz = self._entry_size(h)
        if sz > self.max_size:
            self.dynamic = List[HpackHeader]()
            self.dynamic_size = 0
            return
        self._evict_to_fit(sz)
        # HPACK §2.3.3: index 1 is the most recent entry, so we
        # prepend.
        var ins = h.copy()
        var n = len(self.dynamic)
        self.dynamic.append(HpackHeader())
        var i = n
        while i > 0:
            self.dynamic[i] = self.dynamic[i - 1].copy()
            i -= 1
        self.dynamic[0] = ins^
        self.dynamic_size += sz

    def _lookup(
        self, idx: Int, static: Span[HpackHeader, _]
    ) raises -> HpackHeader:
        if idx <= 0:
            raise Error("hpack: index 0")
        if idx <= STATIC_TABLE_LEN:
            return static[idx].copy()
        var d = idx - STATIC_TABLE_LEN - 1
        if d >= len(self.dynamic):
            raise Error("hpack: dynamic index out of range")
        return self.dynamic[d].copy()

    def _decode_string(
        self, buf: Span[UInt8, _], offset: Int
    ) raises -> StringPair:
        if offset >= len(buf):
            raise Error("hpack: string header byte missing")
        var b0 = Int(buf[offset])
        var huffman = (b0 & 0x80) != 0
        var lenpair = decode_integer(buf, offset, 7)
        var slen = lenpair.value
        var off = lenpair.offset
        if off + slen > len(buf):
            raise Error("hpack: literal string truncated")
        if huffman:
            raise Error("hpack: Huffman-coded string not supported ")
        var s = String(capacity=slen + 1)
        for i in range(slen):
            s += chr(Int(buf[off + i]))
        return StringPair(s^, off + slen)

    def decode(mut self, buf: Span[UInt8, _]) raises -> List[HpackHeader]:
        """Decode a HEADERS / CONTINUATION block into header pairs."""
        var static = _static_table()
        var headers = List[HpackHeader]()
        var off = 0
        while off < len(buf):
            var b0 = Int(buf[off])
            if (b0 & 0x80) != 0:
                # 6.1 Indexed Header Field
                var pair = decode_integer(buf, off, 7)
                off = pair.offset
                var h = self._lookup(pair.value, Span[HpackHeader, _](static))
                headers.append(h^)
            elif (b0 & 0x40) != 0:
                # 6.2.1 Literal w/ Incremental Indexing
                var pair = decode_integer(buf, off, 6)
                off = pair.offset
                var idx = pair.value
                var name: String
                if idx == 0:
                    var p = self._decode_string(buf, off)
                    name = p.value.copy()
                    off = p.offset
                else:
                    name = self._lookup(
                        idx, Span[HpackHeader, _](static)
                    ).name.copy()
                var v = self._decode_string(buf, off)
                off = v.offset
                var h = HpackHeader(name, v.value.copy())
                self._insert(h)
                headers.append(h^)
            elif (b0 & 0x20) != 0:
                # 6.3 Dynamic Table Size Update
                var pair = decode_integer(buf, off, 5)
                off = pair.offset
                if pair.value > self.max_size:
                    raise Error("hpack: size update exceeds settings cap")
                self.max_size = pair.value
                self._evict_to_fit(0)
            else:
                # 6.2.2 / 6.2.3 Literal w/o or Never Indexing
                var pair = decode_integer(buf, off, 4)
                off = pair.offset
                var idx = pair.value
                var name: String
                if idx == 0:
                    var p = self._decode_string(buf, off)
                    name = p.value.copy()
                    off = p.offset
                else:
                    name = self._lookup(
                        idx, Span[HpackHeader, _](static)
                    ).name.copy()
                var v = self._decode_string(buf, off)
                off = v.offset
                headers.append(HpackHeader(name, v.value.copy()))
        return headers^


# ── HpackEncoder ─────────────────────────────────────────────────────────


struct HpackEncoder(Copyable, Defaultable, Movable):
    """Stateless-ish HPACK encoder.

    For we emit every header as a Literal-without-Indexing
    field (§6.2.2). The dynamic table on the encoder side is then
    always empty, which is RFC-legal: HPACK explicitly allows the
    encoder to choose not to use the dynamic table at all
    (RFC 7541 §2.3.3 / §4.1). This trades a little wire bandwidth
    for a much simpler encoder + zero risk of CRIME-class
    information leaks across requests.

    A future follow-up can teach the encoder to look up the static
    table for the most common headers (``:status``, ``:method``,
    etc.) without touching the dynamic table.
    """

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def _encode_string(self, mut out_buf: List[UInt8], s: String):
        var n = s.byte_length()
        encode_integer(out_buf, n, 7, UInt8(0))  # H=0
        var src = s.unsafe_ptr()
        for i in range(n):
            out_buf.append(src[i])

    def encode(self, headers: Span[HpackHeader, _]) -> List[UInt8]:
        var out = List[UInt8]()
        var static = _static_table()
        for i in range(len(headers)):
            var h = headers[i].copy()
            # Try a static-table lookup for the *name only*. If the
            # name is in the static table we use index N for the
            # name; otherwise we send the name as a literal.
            var name_idx = 0
            for j in range(1, STATIC_TABLE_LEN + 1):
                if static[j].name == h.name:
                    name_idx = j
                    break
            # 6.2.2: ``0000 xxxx`` prefix (4-bit prefix, top bit 0).
            encode_integer(out, name_idx, 4, UInt8(0))
            if name_idx == 0:
                self._encode_string(out, h.name)
            self._encode_string(out, h.value)
        return out^
