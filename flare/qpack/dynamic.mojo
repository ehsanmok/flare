"""QPACK dynamic table + encoder/decoder stream instructions (RFC 9204).

The static-only codec in :mod:`flare.qpack.codec` covers field sections
that reference the RFC 9204 Appendix A static table or carry literals.
This module adds the **dynamic table**: the per-connection insert log a
peer streams over the unidirectional QPACK *encoder stream* (type 0x02),
the *decoder stream* (type 0x03) acknowledgements that flow back, and the
field-section wire shapes that reference dynamic entries by relative /
post-base index.

Sans-I/O: pure state + pure byte-in/byte-out functions. The h3 layer
owns the QUIC streams and feeds the instruction bytes here; this module
never touches a socket.

Pieces:

- :struct:`QpackDynamicTable` -- the insert-ordered entry log with
  capacity-bounded eviction and absolute / relative index resolution
  (RFC 9204 section 3.2).
- Encoder-stream instruction codec (section 4.3): Set Dynamic Table
  Capacity, Insert With Name Reference (static or dynamic), Insert With
  Literal Name, Duplicate. :func:`apply_encoder_instructions` replays a
  byte stream into a table.
- Decoder-stream instruction codec (section 4.4): Section
  Acknowledgment, Stream Cancellation, Insert Count Increment.
- Field-section dynamic codec (section 4.5):
  :func:`encode_field_section_dynamic` /
  :func:`decode_field_section_dynamic`, including the Required Insert
  Count encoding of section 4.5.1.1.
- :struct:`QpackEncoder` / :struct:`QpackDecoder` -- thin owners that
  pair a table with the stream bookkeeping (Known Received Count, the
  Insert Count Increment to emit).

ponytail: eviction follows the encoder (evict the oldest entry to make
room) and does not track per-entry reference counts -- a decoder mirror
trusts the peer encoder not to evict an entry a not-yet-acknowledged
field section still references (RFC 9204 section 2.2 makes that the
encoder's responsibility). Blocked-stream handling (a field section
referencing inserts that have not arrived) is surfaced as a decode error
for the caller to treat as "needs more inserts"; full stream-parking is
the upgrade path.

References: RFC 9204 sections 2-4; RFC 7541 Appendix B (Huffman).
"""

from std.collections import List
from std.memory import Span

from flare.http2.hpack import (
    HpackHeader as QpackHeader,
    decode_integer,
    encode_integer,
)

from .codec import _decode_string_literal, _encode_string_literal
from .static_table import QPACK_STATIC_TABLE_SIZE, _qpack_static_table


comptime _ENTRY_OVERHEAD: UInt64 = 32
"""RFC 9204 section 3.2.1: each entry's size is name + value + 32."""


def entry_size(h: QpackHeader) -> UInt64:
    """RFC 9204 section 3.2.1 entry size in bytes."""
    return (
        UInt64(h.name.byte_length())
        + UInt64(h.value.byte_length())
        + _ENTRY_OVERHEAD
    )


# -- Dynamic table ------------------------------------------------------------


struct QpackDynamicTable(Copyable, Movable):
    """Insert-ordered, capacity-bounded dynamic table (RFC 9204 3.2).

    ``entries[0]`` is the oldest live entry. ``dropped`` counts entries
    evicted over the table's lifetime, so the absolute index of
    ``entries[0]`` is ``dropped`` and the next insert lands at absolute
    index ``insert_count()`` (== ``dropped + len(entries)``).
    """

    var entries: List[QpackHeader]
    var capacity: UInt64
    var size: UInt64
    var dropped: UInt64

    def __init__(out self, capacity: UInt64 = 0):
        self.entries = List[QpackHeader]()
        self.capacity = capacity
        self.size = 0
        self.dropped = 0

    def insert_count(self) -> UInt64:
        """Total inserts ever (the absolute index of the next insert)."""
        return self.dropped + UInt64(len(self.entries))

    def max_entries(self) -> UInt64:
        """RFC 9204 section 3.2.2 MaxEntries = floor(capacity / 32)."""
        return self.capacity // _ENTRY_OVERHEAD

    def set_capacity(mut self, cap: UInt64):
        """Set the table capacity, evicting the oldest entries until the
        size fits (RFC 9204 section 4.3.1)."""
        self.capacity = cap
        self._evict_to(cap)

    def _evict_to(mut self, target: UInt64):
        while self.size > target and len(self.entries) > 0:
            self.size -= entry_size(self.entries[0])
            # Drop the oldest entry (shift). ponytail: O(n) shift on a
            # List; a ring buffer is the upgrade path if eviction shows
            # up in a profile, but inserts dominate and tables are small.
            var rest = List[QpackHeader](capacity=len(self.entries) - 1)
            for i in range(1, len(self.entries)):
                rest.append(self.entries[i].copy())
            self.entries = rest^
            self.dropped += 1

    def insert(mut self, var h: QpackHeader) -> Bool:
        """Insert ``h`` after evicting to make room. Returns False if the
        entry cannot fit even in an empty table (RFC 9204 section 3.2.2 --
        such an insert is a no-op the caller treats as an error)."""
        var sz = entry_size(h)
        if sz > self.capacity:
            return False
        self._evict_to(self.capacity - sz)
        self.size += sz
        self.entries.append(h^)
        return True

    def get_abs(self, abs_index: UInt64) raises -> QpackHeader:
        """Resolve an absolute index to its entry."""
        if abs_index < self.dropped or abs_index >= self.insert_count():
            raise Error(
                "qpack: dynamic abs index "
                + String(abs_index)
                + " evicted or not yet inserted"
            )
        return self.entries[Int(abs_index - self.dropped)].copy()

    def find(self, h: QpackHeader) -> Int:
        """Absolute index of a full (name, value) match, or -1."""
        for i in range(len(self.entries)):
            if (
                self.entries[i].name == h.name
                and self.entries[i].value == h.value
            ):
                return Int(self.dropped + UInt64(i))
        return -1

    def find_name(self, name: String) -> Int:
        """Absolute index of a name match, or -1."""
        for i in range(len(self.entries)):
            if self.entries[i].name == name:
                return Int(self.dropped + UInt64(i))
        return -1


# -- Required Insert Count (RFC 9204 section 4.5.1.1) -------------------------


def encode_required_insert_count(ric: UInt64, max_entries: UInt64) -> UInt64:
    """Encode the Required Insert Count for the field-section prefix."""
    if ric == 0:
        return 0
    return (ric % (2 * max_entries)) + 1


def decode_required_insert_count(
    enc: UInt64, total_inserts: UInt64, max_entries: UInt64
) raises -> UInt64:
    """Decode the Required Insert Count given the wire value, the
    decoder's current insert count, and MaxEntries (RFC 9204 4.5.1.1)."""
    if enc == 0:
        return 0
    if max_entries == 0:
        raise Error("qpack: dynamic reference with zero table capacity")
    var full_range = 2 * max_entries
    if enc > full_range:
        raise Error("qpack: required_insert_count out of range")
    var max_value = total_inserts + max_entries
    var max_wrapped = (max_value // full_range) * full_range
    var ric = max_wrapped + enc - 1
    if ric > max_value:
        if ric <= full_range:
            raise Error("qpack: required_insert_count underflow")
        ric -= full_range
    if ric == 0:
        raise Error("qpack: required_insert_count resolved to zero")
    return ric


# -- Encoder-stream instructions (RFC 9204 section 4.3) -----------------------


def encode_set_capacity(mut out: List[UInt8], cap: UInt64):
    """Set Dynamic Table Capacity: ``001xxxxx`` (5-bit prefix)."""
    encode_integer(out, Int(cap), 5, UInt8(0x20))


def encode_insert_with_name_ref(
    mut out: List[UInt8], is_static: Bool, name_index: Int, value: String
):
    """Insert With Name Reference: ``1Txxxxxx`` (T static flag, 6-bit
    name index) followed by the value string literal."""
    var prefix = UInt8(0x80)
    if is_static:
        prefix |= UInt8(0x40)
    encode_integer(out, name_index, 6, prefix)
    _encode_string_literal(out, value, UInt8(0x00), 7, UInt8(0x80))


def encode_insert_with_literal_name(
    mut out: List[UInt8], name: String, value: String
):
    """Insert With Literal Name: ``01Hxxxxx`` (5-bit name length) then
    the name + value string literals."""
    _encode_string_literal(out, name, UInt8(0x40), 5, UInt8(0x20))
    _encode_string_literal(out, value, UInt8(0x00), 7, UInt8(0x80))


def encode_duplicate(mut out: List[UInt8], rel_index: Int):
    """Duplicate: ``000xxxxx`` (5-bit relative index)."""
    encode_integer(out, rel_index, 5, UInt8(0x00))


def apply_encoder_instructions(
    mut table: QpackDynamicTable, buf: Span[UInt8, _]
) raises -> Int:
    """Replay a complete encoder-stream byte buffer into ``table``.
    Returns the number of inserts applied (for the Insert Count Increment
    the decoder owes back). Raises on a malformed / truncated
    instruction; use :func:`apply_encoder_instructions_partial` when the
    buffer may end mid-instruction at a chunk boundary."""
    var pos = 0
    var inserts = 0
    while pos < len(buf):
        var step = _apply_one_encoder_instruction(table, buf, pos)
        inserts += step[0]
        pos = step[1]
    return inserts


def apply_encoder_instructions_partial(
    mut table: QpackDynamicTable, buf: Span[UInt8, _]
) raises -> Tuple[Int, Int]:
    """Like :func:`apply_encoder_instructions` but tolerant of a chunk
    boundary mid-instruction: applies every whole instruction and
    returns ``(inserts_applied, bytes_consumed)`` so the caller can keep
    the unconsumed tail and retry once more bytes arrive.

    ponytail: an incomplete *and* a corrupt trailing instruction look the
    same here (both raise mid-parse), so both stop consumption. A truly
    corrupt encoder stream therefore stalls rather than erroring; the
    QUIC idle timeout closes such a connection. The upgrade path is to
    distinguish truncation from corruption per instruction."""
    var consumed = 0
    var inserts = 0
    while consumed < len(buf):
        var instr_start = consumed
        var before_inserts = inserts
        try:
            var step = _apply_one_encoder_instruction(table, buf, instr_start)
            inserts += step[0]
            consumed = step[1]
        except:
            # Roll back any partial table mutation is not needed: a single
            # instruction either fully applies (advancing consumed) or
            # raises before mutating. Stop at the instruction boundary.
            inserts = before_inserts
            consumed = instr_start
            break
    return Tuple[Int, Int](inserts, consumed)


def _apply_one_encoder_instruction(
    mut table: QpackDynamicTable, buf: Span[UInt8, _], pos: Int
) raises -> Tuple[Int, Int]:
    """Apply the single encoder instruction at ``pos``; return
    ``(inserts, new_pos)``."""
    var stbl = _qpack_static_table()
    var b0 = buf[pos]
    if (b0 & UInt8(0x80)) != UInt8(0):
        var is_static = (b0 & UInt8(0x40)) != UInt8(0)
        var ip = decode_integer(buf, pos, 6)
        var name: String
        if is_static:
            if ip.value < 0 or ip.value >= QPACK_STATIC_TABLE_SIZE:
                raise Error("qpack: insert static name index out of range")
            name = stbl[ip.value].name
        else:
            var abs_idx = table.insert_count() - 1 - UInt64(ip.value)
            name = table.get_abs(abs_idx).name
        var lit = _decode_string_literal(buf, ip.offset, 7, UInt8(0x80))
        if not table.insert(QpackHeader(name, lit[0])):
            raise Error("qpack: insert exceeds table capacity")
        return Tuple[Int, Int](1, lit[1])
    elif (b0 & UInt8(0x40)) != UInt8(0):
        var name_lit = _decode_string_literal(buf, pos, 5, UInt8(0x20))
        var value_lit = _decode_string_literal(buf, name_lit[1], 7, UInt8(0x80))
        if not table.insert(QpackHeader(name_lit[0], value_lit[0])):
            raise Error("qpack: insert exceeds table capacity")
        return Tuple[Int, Int](1, value_lit[1])
    elif (b0 & UInt8(0x20)) != UInt8(0):
        var ip = decode_integer(buf, pos, 5)
        table.set_capacity(UInt64(ip.value))
        return Tuple[Int, Int](0, ip.offset)
    else:
        var ip = decode_integer(buf, pos, 5)
        var abs_idx = table.insert_count() - 1 - UInt64(ip.value)
        var dup = table.get_abs(abs_idx)
        if not table.insert(dup^):
            raise Error("qpack: duplicate exceeds table capacity")
        return Tuple[Int, Int](1, ip.offset)


# -- Decoder-stream instructions (RFC 9204 section 4.4) -----------------------

comptime DEC_INSTR_SECTION_ACK: Int = 0
comptime DEC_INSTR_STREAM_CANCEL: Int = 1
comptime DEC_INSTR_INSERT_COUNT_INCREMENT: Int = 2


def encode_section_ack(mut out: List[UInt8], stream_id: Int):
    """Section Acknowledgment: ``1xxxxxxx`` (7-bit stream id)."""
    encode_integer(out, stream_id, 7, UInt8(0x80))


def encode_stream_cancel(mut out: List[UInt8], stream_id: Int):
    """Stream Cancellation: ``01xxxxxx`` (6-bit stream id)."""
    encode_integer(out, stream_id, 6, UInt8(0x40))


def encode_insert_count_increment(mut out: List[UInt8], increment: Int):
    """Insert Count Increment: ``00xxxxxx`` (6-bit increment)."""
    encode_integer(out, increment, 6, UInt8(0x00))


@fieldwise_init
struct DecoderInstruction(Copyable, Movable):
    """A parsed decoder-stream instruction: ``kind`` is one of the
    ``DEC_INSTR_*`` constants, ``value`` is the stream id or increment,
    ``offset`` is the cursor past the instruction."""

    var kind: Int
    var value: UInt64
    var offset: Int


def parse_decoder_instruction(
    buf: Span[UInt8, _], offset: Int
) raises -> DecoderInstruction:
    """Parse one decoder-stream instruction at ``offset``."""
    if offset >= len(buf):
        raise Error("qpack: decoder instruction truncated")
    var b0 = buf[offset]
    if (b0 & UInt8(0x80)) != UInt8(0):
        var ip = decode_integer(buf, offset, 7)
        return DecoderInstruction(
            DEC_INSTR_SECTION_ACK, UInt64(ip.value), ip.offset
        )
    if (b0 & UInt8(0x40)) != UInt8(0):
        var ip = decode_integer(buf, offset, 6)
        return DecoderInstruction(
            DEC_INSTR_STREAM_CANCEL, UInt64(ip.value), ip.offset
        )
    var ip = decode_integer(buf, offset, 6)
    return DecoderInstruction(
        DEC_INSTR_INSERT_COUNT_INCREMENT, UInt64(ip.value), ip.offset
    )


# -- Field-section dynamic codec (RFC 9204 section 4.5) -----------------------


def encode_field_section_dynamic(
    headers: List[QpackHeader],
    table: QpackDynamicTable,
    mut out: List[UInt8],
) raises:
    """Encode a field section that may reference ``table`` entries.

    For each header: a full dynamic match becomes an indexed (relative)
    line; a dynamic name match becomes a literal-with-name-reference;
    otherwise it falls back to the static-table path / literals. The
    Required Insert Count is the largest referenced absolute index + 1
    (0 when no dynamic entry is referenced), and Base is set equal to it
    (delta_base 0), so every reference is pre-base.
    """
    var stbl = _qpack_static_table()
    var max_abs: Int = -1
    # First pass: decide ric (max referenced abs + 1).
    for i in range(len(headers)):
        var idx = table.find(headers[i])
        if idx < 0:
            idx = table.find_name(headers[i].name)
        if idx > max_abs:
            max_abs = idx
    var ric: UInt64 = 0
    if max_abs >= 0:
        ric = UInt64(max_abs) + 1
    var base = ric
    var enc_ric = encode_required_insert_count(ric, table.max_entries())
    encode_integer(out, Int(enc_ric), 8, UInt8(0x00))
    # Sign=0, Delta Base=0 -> Base == Required Insert Count.
    out.append(UInt8(0x00))
    for i in range(len(headers)):
        var h = headers[i].copy()
        var dyn_full = table.find(h)
        if dyn_full >= 0:
            # Indexed Field Line (dynamic, pre-base): 1Txxxxxx, T=0.
            var rel = Int(base) - 1 - dyn_full
            encode_integer(out, rel, 6, UInt8(0x80))
            continue
        var dyn_name = table.find_name(h.name)
        if dyn_name >= 0:
            # Literal With Name Reference (dynamic): 01NTxxxx, T=0.
            var rel = Int(base) - 1 - dyn_name
            encode_integer(out, rel, 4, UInt8(0x40))
            _encode_string_literal(out, h.value, UInt8(0x00), 7, UInt8(0x80))
            continue
        # Static-table fallbacks.
        var s_full = -1
        for j in range(QPACK_STATIC_TABLE_SIZE):
            if stbl[j].name == h.name and stbl[j].value == h.value:
                s_full = j
                break
        if s_full >= 0:
            encode_integer(out, s_full, 6, UInt8(0xC0))
            continue
        var s_name = -1
        for j in range(QPACK_STATIC_TABLE_SIZE):
            if stbl[j].name == h.name:
                s_name = j
                break
        if s_name >= 0:
            encode_integer(out, s_name, 4, UInt8(0x50))
            _encode_string_literal(out, h.value, UInt8(0x00), 7, UInt8(0x80))
            continue
        _encode_string_literal(out, h.name, UInt8(0x20), 3, UInt8(0x08))
        _encode_string_literal(out, h.value, UInt8(0x00), 7, UInt8(0x80))


def decode_field_section_dynamic(
    buf: Span[UInt8, _],
    table: QpackDynamicTable,
) raises -> List[QpackHeader]:
    """Decode a field section against ``table``, resolving dynamic
    indexed / name-reference / post-base lines (RFC 9204 section 4.5).
    Static-only inputs (Required Insert Count 0) decode without touching
    the table."""
    var headers = List[QpackHeader]()
    if len(buf) < 2:
        raise Error("qpack: field section prefix truncated")
    var ric_enc = decode_integer(buf, 0, 8)
    var ric = decode_required_insert_count(
        UInt64(ric_enc.value), table.insert_count(), table.max_entries()
    )
    # Sign + Delta Base (1-bit sign + 7-bit prefix).
    var sign_set = (buf[ric_enc.offset] & UInt8(0x80)) != UInt8(0)
    var delta = decode_integer(buf, ric_enc.offset, 7)
    var base: UInt64
    if sign_set:
        base = ric - UInt64(delta.value) - 1
    else:
        base = ric + UInt64(delta.value)
    # Blocked-stream guard: a reference past what we've received fails.
    if ric > table.insert_count():
        raise Error("qpack: field section blocked on missing inserts")
    var stbl = _qpack_static_table()
    var pos = delta.offset
    while pos < len(buf):
        var b0 = buf[pos]
        if (b0 & UInt8(0x80)) != UInt8(0):
            # Indexed Field Line: 1Txxxxxx
            var t_static = (b0 & UInt8(0x40)) != UInt8(0)
            var ip = decode_integer(buf, pos, 6)
            if t_static:
                if ip.value < 0 or ip.value >= QPACK_STATIC_TABLE_SIZE:
                    raise Error("qpack: static index out of range")
                headers.append(stbl[ip.value].copy())
            else:
                var abs_idx = base - 1 - UInt64(ip.value)
                headers.append(table.get_abs(abs_idx))
            pos = ip.offset
            continue
        if (b0 & UInt8(0x40)) != UInt8(0):
            # Literal Field Line With Name Reference: 01NTxxxx
            var t_static = (b0 & UInt8(0x10)) != UInt8(0)
            var ip = decode_integer(buf, pos, 4)
            var name: String
            if t_static:
                if ip.value < 0 or ip.value >= QPACK_STATIC_TABLE_SIZE:
                    raise Error("qpack: static name index out of range")
                name = stbl[ip.value].name
            else:
                var abs_idx = base - 1 - UInt64(ip.value)
                name = table.get_abs(abs_idx).name
            var lit = _decode_string_literal(buf, ip.offset, 7, UInt8(0x80))
            headers.append(QpackHeader(name, lit[0]))
            pos = lit[1]
            continue
        if (b0 & UInt8(0x20)) != UInt8(0):
            # Literal Field Line With Literal Name: 001Nhxxx
            var name_lit = _decode_string_literal(buf, pos, 3, UInt8(0x08))
            var value_lit = _decode_string_literal(
                buf, name_lit[1], 7, UInt8(0x80)
            )
            headers.append(QpackHeader(name_lit[0], value_lit[0]))
            pos = value_lit[1]
            continue
        if (b0 & UInt8(0x10)) != UInt8(0):
            # Indexed Field Line With Post-Base Index: 0001xxxx
            var ip = decode_integer(buf, pos, 4)
            var abs_idx = base + UInt64(ip.value)
            headers.append(table.get_abs(abs_idx))
            pos = ip.offset
            continue
        # Literal Field Line With Post-Base Name Reference: 0000Nxxx
        var ip = decode_integer(buf, pos, 3)
        var abs_idx = base + UInt64(ip.value)
        var name = table.get_abs(abs_idx).name
        var lit = _decode_string_literal(buf, ip.offset, 7, UInt8(0x80))
        headers.append(QpackHeader(name, lit[0]))
        pos = lit[1]
    return headers^


# -- Owners -------------------------------------------------------------------


struct QpackDecoder(Copyable, Movable):
    """Owns the inbound dynamic table + the Insert Count Increment owed
    back to the peer on the decoder stream."""

    var table: QpackDynamicTable
    var pending_increment: Int

    def __init__(out self, capacity: UInt64 = 0):
        self.table = QpackDynamicTable(capacity)
        self.pending_increment = 0

    def feed_encoder_stream(mut self, buf: Span[UInt8, _]) raises -> Int:
        """Apply encoder-stream bytes; accumulate the Insert Count
        Increment to send. Returns the inserts applied."""
        var n = apply_encoder_instructions(self.table, buf)
        self.pending_increment += n
        return n

    def take_increment(mut self, mut out: List[UInt8]) -> Bool:
        """Emit a pending Insert Count Increment onto the decoder stream
        (if any). Returns whether anything was written."""
        if self.pending_increment <= 0:
            return False
        encode_insert_count_increment(out, self.pending_increment)
        self.pending_increment = 0
        return True

    def decode(self, buf: Span[UInt8, _]) raises -> List[QpackHeader]:
        """Decode a field section against the dynamic table."""
        return decode_field_section_dynamic(buf, self.table)


struct QpackEncoder(Copyable, Movable):
    """Owns the outbound dynamic table; ``insert`` appends an
    encoder-stream instruction and updates the local table mirror."""

    var table: QpackDynamicTable

    def __init__(out self, capacity: UInt64 = 0):
        self.table = QpackDynamicTable(capacity)

    def set_capacity(mut self, cap: UInt64, mut enc_stream: List[UInt8]):
        encode_set_capacity(enc_stream, cap)
        self.table.set_capacity(cap)

    def insert(
        mut self, name: String, value: String, mut enc_stream: List[UInt8]
    ) -> Bool:
        """Insert (name, value), emitting an Insert With Literal Name
        instruction. Returns False if it does not fit the capacity."""
        var h = QpackHeader(name, value)
        if entry_size(h) > self.table.capacity:
            return False
        encode_insert_with_literal_name(enc_stream, name, value)
        return self.table.insert(h^)

    def encode(self, headers: List[QpackHeader], mut out: List[UInt8]) raises:
        """Encode a field section referencing the local table."""
        encode_field_section_dynamic(headers, self.table, out)
