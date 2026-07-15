"""QPACK encoder + decoder (RFC 9204) -- static-only.

QPACK is the HPACK-shaped header compression layer that HTTP/3
uses on top of QUIC. The full RFC 9204 codec ships a dynamic
table that streams insertions on a dedicated unidirectional
QUIC stream (the "encoder stream"), with field sections
referencing entries in the dynamic table by index. The dynamic
table introduces head-of-line blocking risk on the QUIC layer
(field sections may need to wait for inserts they reference)
and a non-trivial encoder-stream protocol on top of the simple
field-section codec.

This module is the **static-only** subset:

* Field section prefix: required-insert-count and base both
  fixed at 0 on encode; decoder rejects field sections whose
  required-insert-count is not 0 (no dynamic-table support yet).
* Field lines: indexed-static, literal-with-static-name, and
  literal-with-literal-name. The dynamic-reference variants
  (``1Tppppppp`` with T=0, plus ``001Nhppp`` post-base) are
  rejected on decode.
* String literals: optional Huffman per RFC 7541 Appendix B
  (shared with HPACK; the encoder picks the shorter form).

The static-only subset is enough for an HTTP/3 server that
talks to a real client: the most common request and response
shapes (``:method GET``, ``:status 200``, common content types)
all hit the static table directly, and literal field lines cover
everything else without head-of-line risk.

Public surface:

* :class:`QpackHeader` -- ``(name, value)`` pair, re-exported
  from ``flare.http2.hpack`` for ergonomic interop.
* :func:`encode_field_section` -- emit the field section prefix
  plus all field lines into a fresh byte list.
* :func:`decode_field_section` -- parse a field section into a
  list of :class:`QpackHeader`. Rejects dynamic-table references.
* :data:`QPACK_STATIC_TABLE_SIZE` -- the 99 of the static table.

Sans-I/O contract: zero I/O imports; registered in
``tools/check_sans_io.sh``.

References:
- RFC 9204 "QPACK: Field Compression for HTTP/3".
- RFC 9114 §4.2 "HTTP Fields" (lowercase mandate).
- RFC 7541 Appendix B (Huffman -- shared with HPACK).
"""

from std.collections import Dict, List
from std.memory import Span

from flare.http.proto.ascii import ascii_unchecked_string
from flare.http2.hpack import (
    HpackHeader as QpackHeader,
    decode_integer,
    encode_integer,
)
from flare.http.hpack_huffman_simd import huffman_decode_simd
from flare.http.hpack_huffman import (
    HuffmanError,
    huffman_decode,
    huffman_encode,
    huffman_encoded_length,
)

from .static_table import (
    QPACK_STATIC_TABLE_SIZE,
    _qpack_static_table,
    static_table_find,
    static_table_find_name,
    static_table_lookup,
)


# ── Encoder ────────────────────────────────────────────────────────────────


def _encode_string_literal(
    mut out: List[UInt8],
    value: String,
    prefix_byte: UInt8,
    prefix_bits: Int,
    huffman_flag: UInt8,
):
    """Emit a QPACK string literal at the current ``out`` cursor.

    The high bits of ``prefix_byte`` are preserved; the Huffman
    flag bit (one above ``prefix_bits``) is set when Huffman
    actually shortens the encoding. Falls back to the raw bytes
    otherwise so we never spend cycles encoding strings that get
    longer (a real concern for already-compressed payloads).
    """
    var raw = value.as_bytes()
    var raw_list = List[UInt8](capacity=len(raw))
    for b in raw:
        raw_list.append(b)
    var encoded = List[UInt8](capacity=len(raw))
    huffman_encode(raw_list, encoded)
    var huff_len = len(encoded)
    var raw_len = len(raw_list)
    if huff_len < raw_len:
        # Use Huffman path.
        encode_integer(out, huff_len, prefix_bits, prefix_byte | huffman_flag)
        for i in range(huff_len):
            out.append(encoded[i])
    else:
        encode_integer(out, raw_len, prefix_bits, prefix_byte)
        for i in range(raw_len):
            out.append(raw_list[i])


def encode_field_section(
    headers: List[QpackHeader],
    mut out: List[UInt8],
) raises:
    """Append the QPACK-encoded field section bytes (RFC 9204 §4.5) to ``out``.

    The caller owns the buffer and may pass the same
    ``List[UInt8]`` through repeated encode calls, clearing
    between calls so the underlying allocation amortises across
    the stream. The encoder appends only; it never reads from or
    truncates the existing contents.

    The static-only codec emits:

    * Field section prefix: required_insert_count=0,
      sign=0 + delta_base=0 (two single-byte 0x00s).
    * Per header, the lowest-cost wire shape:
      - full match in the static table -> indexed field line
        (``11pppppp`` for indices < 63, with continuation bytes
        for higher indices; the static-table flag T is always 1).
      - name-only match -> literal-with-name-reference
        (``0101pppp`` with T=1 for static, then string literal).
      - no match -> literal-with-literal-name
        (``0010nnnn`` with H+name length, then name, then value).

    Header names must be lowercase per RFC 9114 §4.2; the
    encoder emits whatever case the caller provides and trusts
    the call site. The decoder mirrors this -- it surfaces the
    bytes verbatim.
    """
    # Field section prefix: required_insert_count = 0 + Base = 0.
    # 8-bit prefix integer for required_insert_count == 0; the
    # short form is a single 0x00 byte.
    out.append(UInt8(0x00))
    # Sign + Delta Base; sign=0 + 7-bit prefix integer 0 -> 0x00.
    out.append(UInt8(0x00))
    # Build the static table once for the whole field section
    # instead of rebuilding all 99 entries inside static_table_find
    # / static_table_find_name on every header.
    var stbl = _qpack_static_table()
    # Index the static table by header name once (name -> ascending
    # list of static indices) so per-header matching is O(1) hash +
    # a short same-name scan instead of two O(99) linear passes per
    # header (Part II item 6). Indices are appended in ascending j
    # order, preserving the "lowest index wins" semantics the linear
    # scan had for both exact (name+value) and name-only matches.
    var name_to_indices = Dict[String, List[Int]]()
    for j in range(QPACK_STATIC_TABLE_SIZE):
        var nm = stbl[j].name
        if nm in name_to_indices:
            name_to_indices[nm].append(j)
        else:
            var lst = List[Int]()
            lst.append(j)
            name_to_indices[nm] = lst^
    for i in range(len(headers)):
        var h = headers[i].copy()
        var idx = -1
        var name_idx = -1
        if h.name in name_to_indices:
            ref cands = name_to_indices[h.name]
            # Lowest-index entry with this name (name-only fallback).
            name_idx = cands[0]
            # Lowest-index entry with this name AND matching value.
            for k in range(len(cands)):
                if stbl[cands[k]].value == h.value:
                    idx = cands[k]
                    break
        if idx >= 0:
            # 4.5.2 Indexed Field Line: 1Txxxxxx, T=1 for static,
            # 6-bit prefix integer for the index. Prefix byte
            # 0xC0 carries the high "1T" bits.
            encode_integer(out, idx, 6, UInt8(0xC0))
            continue
        if name_idx >= 0:
            # 4.5.4 Literal Field Line With Name Reference:
            # 01NTxxxx, T=1 for static, 4-bit prefix index.
            # Prefix byte 0x50 carries the high "0101" bits with
            # N=0 (allow indexing); 0x70 sets N=1 (never-indexed).
            encode_integer(out, name_idx, 4, UInt8(0x50))
            # 1-byte string-literal prefix: Hxxxxxxx (H=Huffman
            # flag, 7-bit prefix length).
            _encode_string_literal(out, h.value, UInt8(0x00), 7, UInt8(0x80))
            continue
        # 4.5.6 Literal Field Line With Literal Name:
        # 001Nhppp, N=0, h=Huffman flag, 3-bit prefix name length.
        # Prefix byte 0x20 carries the high "001N" bits; the
        # Huffman flag occupies the next bit (0x08 = 1 << 3).
        _encode_string_literal(out, h.name, UInt8(0x20), 3, UInt8(0x08))
        _encode_string_literal(out, h.value, UInt8(0x00), 7, UInt8(0x80))


# ── Decoder ────────────────────────────────────────────────────────────────


def _decode_string_literal(
    buf: Span[UInt8, _],
    offset: Int,
    prefix_bits: Int,
    huffman_mask: UInt8,
) raises -> Tuple[String, Int]:
    """Decode a QPACK string literal.

    Reads the leading byte's Huffman flag (mask
    ``huffman_mask``), then the ``prefix_bits``-bit prefix
    integer length, then the payload bytes. If the Huffman bit
    is set, the payload is decoded via the shared codec.
    """
    if offset >= len(buf):
        raise Error("qpack: literal truncated at flag byte")
    var huffman = (buf[offset] & huffman_mask) != UInt8(0)
    var ip = decode_integer(buf, offset, prefix_bits)
    var n = ip.value
    if ip.offset + n > len(buf):
        raise Error("qpack: literal payload truncated")
    # Slice the payload directly out of the input span instead of
    # rebuilding it byte-by-byte; the per-byte append loop here was a
    # top _realloc cost under request concurrency.
    var payload = buf[ip.offset : ip.offset + n]
    # QPACK string literals carry token-shaped ASCII per RFC 9204 §4
    # (after any Huffman decode); ``ascii_unchecked_string`` builds a
    # ``String`` of the exact length with one ``memcpy`` and no UTF-8
    # validation pass.
    if huffman:
        # Huffman expands ~8:5 worst case; reserve a generous estimate
        # up front so the decode loop fills one allocation instead of
        # growing the backing store byte-by-byte (a top allocator cost
        # under request concurrency).
        var bytes = List[UInt8](capacity=n + (n // 2) + 8)
        # Cached-table decoder (see hpack_huffman_simd): O(1) per
        # short code via the comptime _ROOT_TABLE instead of the
        # scalar codec's per-byte 257-symbol linear scan, which
        # dominated QPACK decode CPU under request concurrency.
        huffman_decode_simd(payload, bytes)
        var s = ascii_unchecked_string(Span[UInt8, _](bytes))
        return Tuple[String, Int](s^, ip.offset + n)
    var s = ascii_unchecked_string(payload)
    return Tuple[String, Int](s^, ip.offset + n)


def decode_field_section(
    buf: Span[UInt8, _],
) raises -> List[QpackHeader]:
    """Parse a QPACK field section.

    Static-only: rejects field sections whose
    required-insert-count is not 0 (the encoder never emits one
    above 0 either; a peer that sends a non-zero count is
    using the dynamic table we don't support yet, and the right
    behaviour is to surface a connection error rather than mis-
    interpret the payload).

    Returns the parsed headers in wire order. Field-line type
    dispatch:

    * ``1Txxxxxx`` -- indexed; rejects T=0 (dynamic; not supported).
    * ``01NTxxxx`` -- literal with name reference; rejects T=0.
    * ``001Nhxxx`` -- literal with literal name.
    * ``0001xxxx`` -- indexed post-base (dynamic only) -> reject.
    * ``0000Nhxx`` -- literal with name reference post-base
      (dynamic only) -> reject.
    """
    var headers = List[QpackHeader]()
    if len(buf) < 2:
        raise Error("qpack: field section prefix truncated")
    # Required Insert Count (8-bit prefix).
    var ric = decode_integer(buf, 0, 8)
    if ric.value != 0:
        raise Error(
            "qpack: required_insert_count "
            + String(ric.value)
            + " > 0; dynamic table not supported"
        )
    # Sign + Delta Base (1-bit + 7-bit prefix). The Base value is
    # only relevant when required_insert_count > 0; we still
    # parse the byte to advance the cursor.
    var base = decode_integer(buf, ric.offset, 7)
    var pos = base.offset
    # Build the static table once for the whole field section; the
    # decoder hits it on every indexed / name-reference line, and
    # rebuilding all 99 (name, value) pairs per line was a top
    # decode-side CPU cost under request concurrency.
    var stbl = _qpack_static_table()
    while pos < len(buf):
        var b0 = buf[pos]
        if (b0 & UInt8(0x80)) != UInt8(0):
            # Indexed Field Line: 1Txxxxxx
            var t_static = (b0 & UInt8(0x40)) != UInt8(0)
            if not t_static:
                raise Error(
                    "qpack: indexed dynamic field line; dynamic"
                    " table not supported"
                )
            var ip = decode_integer(buf, pos, 6)
            if ip.value < 0 or ip.value >= QPACK_STATIC_TABLE_SIZE:
                raise Error(
                    "qpack: static index " + String(ip.value) + " out of range"
                )
            headers.append(stbl[ip.value].copy())
            pos = ip.offset
            continue
        if (b0 & UInt8(0x40)) != UInt8(0):
            # Literal Field Line With Name Reference: 01NTxxxx
            var t_static = (b0 & UInt8(0x10)) != UInt8(0)
            if not t_static:
                raise Error(
                    "qpack: literal-with-name-ref dynamic; dynamic"
                    " table not supported"
                )
            var ip = decode_integer(buf, pos, 4)
            if ip.value < 0 or ip.value >= QPACK_STATIC_TABLE_SIZE:
                raise Error(
                    "qpack: static name index "
                    + String(ip.value)
                    + " out of range"
                )
            var lit = _decode_string_literal(buf, ip.offset, 7, UInt8(0x80))
            headers.append(QpackHeader(stbl[ip.value].name, lit[0]))
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
            # Indexed Field Line With Post-Base Index (dynamic).
            raise Error(
                "qpack: indexed-post-base dynamic field line;"
                " dynamic table not supported"
            )
        # Literal Field Line With Post-Base Name Reference: 0000Nhxx
        raise Error(
            "qpack: literal-post-base dynamic field line;"
            " dynamic table not supported"
        )
    return headers^
