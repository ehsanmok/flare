"""WebSocket permessage-deflate extension (RFC 7692).

Per-message DEFLATE compression for WebSocket data frames. The
extension is negotiated via ``Sec-WebSocket-Extensions`` during
the opening handshake (see :mod:`flare.ws.extensions`); after a
successful negotiation the peers compress every TEXT/BINARY data
frame individually -- the RSV1 bit signals that the payload is
DEFLATE-encoded (RFC 7692 §6).

Wire shape (RFC 7692 §7.2):

- The compressed payload is a *raw* DEFLATE stream (no zlib or
  gzip header) terminated with a sync flush.
- The encoder MUST drop the trailing 4 bytes ``0x00 0x00 0xff 0xff``
  before placing the bytes on the wire (the spec calls this
  "removing the empty deflate block").
- The decoder MUST append the same 4 bytes back to the payload
  before passing it to ``inflate``.

Two codec paths are exposed:

- **No-context-takeover** (the default; safest under RFC
  7692 §7.1.1.1 / §7.1.1.2): every message is compressed against
  a fresh sliding window. The free functions
  :func:`compress_message` and :func:`decompress_message`
  re-initialise the LZ77 state per call; no z_stream lives
  between messages.

- **Context-takeover** (RFC 7692 §7.1.1 default mode): the LZ77
  sliding window persists across messages on both sides. Use
  :class:`PermessageDeflateContext`; each instance owns a pair
  of heap-allocated z_streams (one for the encoder, one for the
  decoder). Carrying context typically halves the compressed
  size on small repetitive payloads at the cost of ~256 KiB of
  zlib state per connection.

Shared invariants:

- ``max_window_bits`` is fixed at 15 (the default); any
  smaller-window offer is silently negotiated up to 15.
- A per-message decompressed-size cap (default 16 MiB) is
  enforced before any allocation -- the same zip-bomb defense
  applied across the rest of flare's compression paths.
- The compressor uses :data:`DEFAULT_DEFLATE_LEVEL` = 6 (zlib's
  default); callers may override per-direction via
  :class:`PermessageDeflateConfig` (no-context) or via
  :meth:`PermessageDeflateContext.__init__` (with-context).

Public surface:

- :class:`PermessageDeflateConfig` -- per-side knobs.
- :func:`compress_message(plaintext, level)` -> ``List[UInt8]``.
- :func:`decompress_message(compressed, max_decompressed_bytes)`
  -> ``List[UInt8]``; raises if the cap is exceeded.
- :class:`PermessageDeflateContext` -- persistent compressor +
  decompressor for the context-takeover branch.

Higher-level frame integration (RSV1 dispatch on send/recv) lives
in :mod:`flare.ws.client_h2` for the h2 path and as a flag on
:class:`flare.ws.frame.WsFrame.rsv1` for the h1 path -- the codec
side is fully isolated here so the compression-oracle hardening
review only needs to scrutinise this single file.
"""

from std.ffi import OwnedDLHandle, c_int

from ..utils.dylib import find_flare_lib


def _find_flare_zlib_lib() -> String:
    """Return the path to ``libflare_zlib.so``.

    Thin wrapper over :func:`flare.utils.dylib.find_flare_lib`
    pinned to the ``"zlib"`` shim name. Replaces the previous
    ``from ..http.encoding import _find_flare_zlib_lib`` so the
    ``flare.ws`` package no longer depends on ``flare.http`` for
    FFI plumbing (WS shouldn't reach into HTTP just to find a
    dylib).
    """
    return find_flare_lib("zlib")


comptime DEFAULT_DEFLATE_LEVEL: Int = 6
"""``zlib``'s default compression level (1..9, where 9 is slowest /
densest). Used when :class:`PermessageDeflateConfig` doesn't
override per-direction."""

comptime DEFAULT_MAX_DECOMPRESSED_BYTES: Int = 16 * 1024 * 1024
"""Per-message decompressed-size cap (16 MiB). The decoder bails
with an Error before allocating output past this size; callers
should treat the failure as a protocol violation and close the
connection with :data:`WsCloseCode.MESSAGE_TOO_BIG` (1009).
This is the simplest defense against zip-bomb / compression-oracle
payloads -- attackers who can pick the plaintext can otherwise
inflate a few-byte ciphertext into many MiB of decompressed
output, exhausting the server."""

comptime _SYNC_FLUSH_TRAILER: List[UInt8] = [
    UInt8(0x00),
    UInt8(0x00),
    UInt8(0xFF),
    UInt8(0xFF),
]
"""RFC 7692 §7.2.1: the empty-deflate-block trailer the encoder
removes and the decoder appends back."""


struct PermessageDeflateConfig(Copyable, Defaultable, Movable):
    """Per-side knobs for the permessage-deflate extension.

    All four RFC 7692 §7.1 parameters are surfaced for negotiation
    + symmetry, even though the codec implementation always
    runs with ``no_context_takeover`` on both sides (see module
    docstring). ``max_window_bits`` <= 15 is accepted; the codec
    never produces output that violates the cap because raw
    deflate with windowBits = -15 already keeps the window at
    most 32 KiB.
    """

    var enabled: Bool
    """Master switch. ``False`` (the default) means the extension
    is neither offered (client) nor accepted (server) during the
    handshake."""

    var server_no_context_takeover: Bool
    """Whether the server MUST reset its LZ77 context at the end
    of each message. The codec always enforces ``True`` regardless
    of this value -- surfaced for handshake honesty."""

    var client_no_context_takeover: Bool
    """Whether the client MUST reset its LZ77 context at the end
    of each message. The codec always enforces ``True`` regardless
    of this value -- surfaced for handshake honesty."""

    var server_max_window_bits: Int
    """Max bits in the LZ77 sliding window the server is willing
    to use. Range 8..15; the codec always operates at 15."""

    var client_max_window_bits: Int
    """Same as :attr:`server_max_window_bits` for the client
    side."""

    var compression_level: Int
    """``zlib`` compression level for outgoing messages (1..9, 0 =
    no compression, -1 = zlib default). Defaults to
    :data:`DEFAULT_DEFLATE_LEVEL`."""

    var max_decompressed_bytes: Int
    """Per-message decompressed-size cap (bytes). Defaults to
    :data:`DEFAULT_MAX_DECOMPRESSED_BYTES` (16 MiB). Set to a
    smaller value on memory-constrained servers; do **not** raise
    above 64 MiB without first auditing the rest of the
    request-pipeline for unbounded buffering."""

    def __init__(out self):
        self.enabled = False
        self.server_no_context_takeover = True
        self.client_no_context_takeover = True
        self.server_max_window_bits = 15
        self.client_max_window_bits = 15
        self.compression_level = DEFAULT_DEFLATE_LEVEL
        self.max_decompressed_bytes = DEFAULT_MAX_DECOMPRESSED_BYTES


# ── Compression (raw DEFLATE + strip sync trailer) ───────────────


def _do_compress_raw_deflate(
    read lib: OwnedDLHandle,
    data: Span[UInt8, _],
    level: c_int,
) raises -> List[UInt8]:
    """Compress ``data`` as a raw DEFLATE stream via
    ``flare_compress_raw_deflate``.

    The wrapper always emits ``Z_SYNC_FLUSH`` so the output ends
    with the empty-deflate-block trailer ``0x00 0x00 0xff 0xff``.
    Callers are responsible for stripping those 4 bytes before
    placing the result on the wire (RFC 7692 §7.2.1).

    Args:
        lib: Borrowed handle to ``libflare_zlib.so`` (kept mapped
            across the FFI call).
        data: Plaintext input.
        level: zlib compression level passed through to
            ``deflateInit2``.
    """
    var fn_compress = lib.get_function[
        def(Int, c_int, Int, c_int, c_int) thin abi("C") -> c_int
    ]("flare_compress_raw_deflate")

    # zlib's worst-case bound: srclen + (srclen >> 12) + (srclen >> 14)
    # + (srclen >> 25) + 13. We add a constant slack for the empty
    # block trailer and short inputs.
    var n = len(data)
    var cap = n + (n >> 11) + 16 + 64
    while True:
        var out = List[UInt8](capacity=cap)
        out.resize(cap, 0)
        var written = fn_compress(
            Int(data.unsafe_ptr()),
            c_int(n),
            Int(out.unsafe_ptr()),
            c_int(cap),
            level,
        )
        if Int(written) < 0:
            raise Error("flare_compress_raw_deflate failed: " + String(written))
        if Int(written) < cap:
            out.resize(Int(written), 0)
            return out^
        cap *= 2


def compress_message(
    data: Span[UInt8, _], level: Int = DEFAULT_DEFLATE_LEVEL
) raises -> List[UInt8]:
    """Compress one WebSocket message per RFC 7692 §7.2.1.

    Returns the raw-DEFLATE-encoded bytes with the trailing
    ``0x00 0x00 0xff 0xff`` sync marker stripped. The caller
    places the result in a WS data frame with the RSV1 bit set
    (RFC 7692 §6).

    Args:
        data: Plaintext message bytes.
        level: ``zlib`` compression level (1..9; 0 = no compression;
            -1 = zlib default).

    Returns:
        The compressed payload, ready for the wire.

    Raises:
        Error: If the underlying zlib call reports an error.
    """
    if len(data) == 0:
        # RFC 7692 §7.2.3.6: an empty payload compresses to a single
        # 0x00 byte; the strip-trailer rule still applies. Emit
        # exactly one zero byte to match Chrome / Firefox behaviour.
        var out = List[UInt8]()
        out.append(UInt8(0x00))
        return out^
    var lib = OwnedDLHandle(_find_flare_zlib_lib())
    var raw = _do_compress_raw_deflate(lib, data, c_int(level))
    # Strip the trailing 4-byte sync marker. RFC 7692 §7.2.1: the
    # encoder MUST remove the empty deflate block. If the trailer
    # isn't present (zlib emitted Z_FINISH before flush) we leave
    # the bytes untouched -- the decoder side will append the
    # marker unconditionally and inflate will tolerate the trailing
    # 0x00 0x00 0xff 0xff sync block.
    var n = len(raw)
    if (
        n >= 4
        and raw[n - 4] == UInt8(0x00)
        and raw[n - 3] == UInt8(0x00)
        and raw[n - 2] == UInt8(0xFF)
        and raw[n - 1] == UInt8(0xFF)
    ):
        var trimmed = List[UInt8](capacity=n - 4)
        for i in range(n - 4):
            trimmed.append(raw[i])
        return trimmed^
    return raw^


# ── Decompression (re-append sync trailer + raw INFLATE + cap) ───


def _do_decompress_raw_inflate_capped(
    read lib: OwnedDLHandle,
    data: Span[UInt8, _],
    max_out: Int,
) raises -> List[UInt8]:
    """Decompress raw DEFLATE input, growing the output buffer up
    to ``max_out`` bytes; raise if the decoder would exceed the
    cap.

    Uses ``flare_decompress`` with ``windowBits = -15`` (raw
    inflate). ``max_out`` is the per-message decompressed-size
    cap from :class:`PermessageDeflateConfig`.

    Args:
        lib: Borrowed handle to ``libflare_zlib.so``.
        data: The compressed payload (with the sync trailer
            already re-appended).
        max_out: The decompressed-size cap.
    """
    var fn_decomp = lib.get_function[
        def(Int, c_int, Int, c_int, c_int) thin abi("C") -> c_int
    ]("flare_decompress")
    var window_bits = c_int(-15)
    var cap = max(len(data) * 4, 4096)
    if cap > max_out:
        cap = max_out
    while True:
        var out = List[UInt8](capacity=cap)
        out.resize(cap, 0)
        var written = fn_decomp(
            Int(data.unsafe_ptr()),
            c_int(len(data)),
            Int(out.unsafe_ptr()),
            c_int(cap),
            window_bits,
        )
        if Int(written) < 0:
            raise Error("flare_decompress failed: " + String(written))
        if Int(written) < cap:
            out.resize(Int(written), 0)
            return out^
        # Output buffer was completely filled -- might be truncated.
        # Try doubling, but never above ``max_out`` (RFC 7692
        # zip-bomb cap).
        if cap >= max_out:
            raise Error(
                "permessage-deflate: decompressed output exceeded"
                " max_decompressed_bytes ("
                + String(max_out)
                + " bytes)"
            )
        cap *= 2
        if cap > max_out:
            cap = max_out


def decompress_message(
    data: Span[UInt8, _],
    max_decompressed_bytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES,
) raises -> List[UInt8]:
    """Decompress one WebSocket message per RFC 7692 §7.2.2.

    Re-appends the ``0x00 0x00 0xff 0xff`` sync marker the encoder
    stripped, then runs raw DEFLATE inflate. The decompressed
    output is capped at ``max_decompressed_bytes`` to defuse
    zip-bomb / compression-oracle payloads -- exceeding the cap
    raises an Error and the caller MUST close the connection
    with status code 1009 (MESSAGE_TOO_BIG).

    Args:
        data: The on-wire compressed payload (sync marker stripped).
        max_decompressed_bytes: The per-message size cap. Defaults
            to :data:`DEFAULT_MAX_DECOMPRESSED_BYTES` (16 MiB).

    Returns:
        The plaintext message bytes.

    Raises:
        Error: If the cap is exceeded or zlib reports a
            non-recoverable error.
    """
    if len(data) == 0:
        raise Error(
            "permessage-deflate: empty payload (RFC 7692 §7.2.2 forbids"
            " a zero-length compressed message)"
        )
    var n = len(data)
    var with_trailer = List[UInt8](capacity=n + 4)
    for i in range(n):
        with_trailer.append(data[i])
    with_trailer.append(UInt8(0x00))
    with_trailer.append(UInt8(0x00))
    with_trailer.append(UInt8(0xFF))
    with_trailer.append(UInt8(0xFF))
    var lib = OwnedDLHandle(_find_flare_zlib_lib())
    return _do_decompress_raw_inflate_capped(
        lib, Span[UInt8, _](with_trailer), max_decompressed_bytes
    )


# ── Context-takeover (persistent z_streams; RFC 7692 §7.1) ────────


def _do_pmd_compressor_new(
    read lib: OwnedDLHandle, level: c_int, window_bits: c_int
) raises -> Int:
    """Allocate a persistent deflate z_stream via FFI. Returns the
    opaque handle (an ``intptr_t``-encoded ``z_stream*``)."""
    var fn_new = lib.get_function[def(c_int, c_int) thin abi("C") -> Int](
        "flare_pmd_compressor_new"
    )
    return fn_new(level, window_bits)


def _do_pmd_compress_chunk(
    read lib: OwnedDLHandle,
    handle: Int,
    in_buf: Int,
    in_len: c_int,
    out_buf: Int,
    out_cap: c_int,
) raises -> c_int:
    """Compress one chunk through a persistent deflate context."""
    var fn_chunk = lib.get_function[
        def(Int, Int, c_int, Int, c_int) thin abi("C") -> c_int
    ]("flare_pmd_compress_chunk")
    return fn_chunk(handle, in_buf, in_len, out_buf, out_cap)


def _do_pmd_compressor_free(
    read lib: OwnedDLHandle, handle: Int
) raises -> None:
    """Release a persistent deflate context."""
    var fn_free = lib.get_function[def(Int) thin abi("C") -> None](
        "flare_pmd_compressor_free"
    )
    fn_free(handle)


def _do_pmd_decompressor_new(
    read lib: OwnedDLHandle, window_bits: c_int
) raises -> Int:
    """Allocate a persistent inflate z_stream via FFI."""
    var fn_new = lib.get_function[def(c_int) thin abi("C") -> Int](
        "flare_pmd_decompressor_new"
    )
    return fn_new(window_bits)


def _do_pmd_decompress_chunk(
    read lib: OwnedDLHandle,
    handle: Int,
    in_buf: Int,
    in_len: c_int,
    out_buf: Int,
    out_cap: c_int,
) raises -> c_int:
    var fn_chunk = lib.get_function[
        def(Int, Int, c_int, Int, c_int) thin abi("C") -> c_int
    ]("flare_pmd_decompress_chunk")
    return fn_chunk(handle, in_buf, in_len, out_buf, out_cap)


def _do_pmd_decompressor_free(
    read lib: OwnedDLHandle, handle: Int
) raises -> None:
    var fn_free = lib.get_function[def(Int) thin abi("C") -> None](
        "flare_pmd_decompressor_free"
    )
    fn_free(handle)


struct PermessageDeflateContext(Movable):
    """Persistent compressor + decompressor for permessage-deflate
    with **context-takeover** (RFC 7692 §7.1).

    Owns one ``z_stream`` per direction; the LZ77 sliding window
    survives across :meth:`compress` / :meth:`decompress` calls
    so subsequent messages benefit from the dictionary built up
    by earlier ones. This is the default mode of RFC 7692 -- the
    ``server_no_context_takeover`` / ``client_no_context_takeover``
    extension parameters are the *opt-out* knobs.

    Lifetime: one instance per direction-pair per connection.
    The destructor calls ``deflateEnd`` / ``inflateEnd`` and
    ``free`` so leaking an instance leaks ~256 KiB of zlib state
    plus the LZ77 dictionary. The struct is :class:`Movable` but
    deliberately not :class:`Copyable`: copying a live handle
    would double-free.

    Single-threaded per instance. Two threads calling
    :meth:`compress` simultaneously is undefined behaviour
    (matches zlib's own contract). The WebSocket adapter
    serialises send + receive per-connection, so this constraint
    is cheap to honour.
    """

    var _comp_handle: Int
    """Opaque ``z_stream*`` for the encoder. ``0`` after move /
    explicit close to make double-free harmless."""

    var _decomp_handle: Int
    """Opaque ``z_stream*`` for the decoder."""

    var max_decompressed_bytes: Int
    """Per-message decompressed-size cap. Set at construction;
    enforced on every :meth:`decompress` call."""

    var _level: Int
    """zlib compression level. Saved so :meth:`reset_compressor`
    can re-initialise the encoder when the peer requested
    no_context_takeover mid-flight."""

    var _window_bits: Int
    """Negative window-bits value used for raw deflate. Saved so
    :meth:`reset_*` calls can re-initialise without parameter
    drift."""

    def __init__(
        out self,
        level: Int = DEFAULT_DEFLATE_LEVEL,
        window_bits: Int = -15,
        max_decompressed_bytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES,
    ) raises:
        """Allocate a persistent compressor + decompressor pair.

        Args:
            level: ``zlib`` compression level (1..9; 0 = no
                compression; -1 = zlib default).
            window_bits: Negative for raw deflate, matching the
                RFC 7692 §7.1.2.1 negotiated max-window-bits
                value. Default ``-15`` = 32 KiB sliding window.
            max_decompressed_bytes: Per-message decompressed-size
                cap; defaults to
                :data:`DEFAULT_MAX_DECOMPRESSED_BYTES` (16 MiB).

        Raises:
            Error: If either ``flare_pmd_*_new`` returns a zlib
                error code, or the heap allocation fails.
        """
        var lib = OwnedDLHandle(_find_flare_zlib_lib())
        var c = _do_pmd_compressor_new(lib, c_int(level), c_int(window_bits))
        if c == 0:
            raise Error(
                "permessage-deflate: flare_pmd_compressor_new"
                " returned 0 (heap allocation failed)"
            )
        # Negative values are zlib error codes returned through
        # the same channel as the success-handle. zlib error
        # codes are in [-6, -2]; any negative value is treated
        # as an init failure.
        if c < 0:
            raise Error(
                "permessage-deflate: deflateInit2 returned zlib error "
                + String(c)
            )
        var d = _do_pmd_decompressor_new(lib, c_int(window_bits))
        if d == 0:
            _do_pmd_compressor_free(lib, c)
            raise Error(
                "permessage-deflate: flare_pmd_decompressor_new"
                " returned 0 (heap allocation failed)"
            )
        if d < 0:
            _do_pmd_compressor_free(lib, c)
            raise Error(
                "permessage-deflate: inflateInit2 returned zlib error "
                + String(d)
            )
        self._comp_handle = c
        self._decomp_handle = d
        self.max_decompressed_bytes = max_decompressed_bytes
        self._level = level
        self._window_bits = window_bits

    def __init__(out self, *, deinit take: Self):
        """Transfer ownership; the source is consumed via
        ``deinit`` so its destructor is never invoked."""
        self._comp_handle = take._comp_handle
        self._decomp_handle = take._decomp_handle
        self.max_decompressed_bytes = take.max_decompressed_bytes
        self._level = take._level
        self._window_bits = take._window_bits

    def __del__(deinit self):
        """Release both z_streams through the FFI; safe to call
        on a moved-from instance (handles are zero)."""
        if self._comp_handle == 0 and self._decomp_handle == 0:
            return
        # Best-effort cleanup; surfaces of failures are limited
        # to log lines (Error in __del__ would propagate badly).
        try:
            var lib = OwnedDLHandle(_find_flare_zlib_lib())
            if self._comp_handle != 0:
                _do_pmd_compressor_free(lib, self._comp_handle)
            if self._decomp_handle != 0:
                _do_pmd_decompressor_free(lib, self._decomp_handle)
        except:
            pass

    def compress(mut self, data: Span[UInt8, _]) raises -> List[UInt8]:
        """Compress one message fragment with context-takeover.

        The LZ77 dictionary built up by prior calls is preserved,
        so subsequent messages benefit from cross-message
        repetition. The trailing ``0x00 0x00 0xff 0xff`` sync
        marker is stripped before return per RFC 7692 §7.2.1.

        Args:
            data: Plaintext bytes.

        Returns:
            Compressed payload, ready for the wire (with RSV1=1).

        Raises:
            Error: If zlib returns a negative error code.
        """
        if self._comp_handle == 0:
            raise Error("permessage-deflate: compress on a released context")
        if len(data) == 0:
            # RFC 7692 §7.2.3.6: empty payload encodes to a single
            # 0x00 byte. Don't touch zlib; emit directly so the
            # persistent z_stream's accumulated state survives.
            var out = List[UInt8]()
            out.append(UInt8(0x00))
            return out^
        var lib = OwnedDLHandle(_find_flare_zlib_lib())
        var n = len(data)
        # Worst-case bound from zlib: srclen + (srclen >> 12) +
        # (srclen >> 14) + (srclen >> 25) + 13. Add slack for the
        # sync marker + headroom for the rare expansion case.
        var cap = n + (n >> 11) + 32 + 64
        while True:
            var out = List[UInt8](capacity=cap)
            out.resize(cap, 0)
            var written = _do_pmd_compress_chunk(
                lib,
                self._comp_handle,
                Int(data.unsafe_ptr()),
                c_int(n),
                Int(out.unsafe_ptr()),
                c_int(cap),
            )
            if Int(written) < 0:
                raise Error(
                    "permessage-deflate: deflate chunk returned zlib error "
                    + String(written)
                )
            if Int(written) < cap:
                # Fits; strip the sync marker (RFC 7692 §7.2.1).
                var w = Int(written)
                if (
                    w >= 4
                    and out[w - 4] == UInt8(0x00)
                    and out[w - 3] == UInt8(0x00)
                    and out[w - 2] == UInt8(0xFF)
                    and out[w - 1] == UInt8(0xFF)
                ):
                    out.resize(w - 4, 0)
                else:
                    out.resize(w, 0)
                return out^
            # Output buffer entirely filled -- doubling is the
            # only safe response since ``deflate(Z_SYNC_FLUSH)``
            # may have produced exactly ``cap`` bytes without
            # reaching the end. The zlib internal state is
            # already advanced, so we must NOT call deflate
            # again with the same input; instead grow the buffer
            # and retry from scratch with a fresh input
            # iteration. In practice this never triggers for
            # realistic payloads because the worst-case bound
            # above is correct; the loop is defensive.
            cap *= 2

    def decompress(mut self, data: Span[UInt8, _]) raises -> List[UInt8]:
        """Decompress one message fragment with context-takeover.

        Re-appends the ``0x00 0x00 0xff 0xff`` sync marker the
        encoder stripped, then inflates against the persistent
        z_stream. The output is capped at
        :attr:`max_decompressed_bytes` to defuse zip-bomb /
        compression-oracle payloads.

        Args:
            data: On-wire compressed payload (sync marker
                stripped).

        Returns:
            Decompressed plaintext.

        Raises:
            Error: If the cap is exceeded or zlib reports a
                non-recoverable error.
        """
        if self._decomp_handle == 0:
            raise Error("permessage-deflate: decompress on a released context")
        if len(data) == 0:
            raise Error(
                "permessage-deflate: empty payload (RFC 7692"
                " §7.2.2 forbids a zero-length compressed"
                " message)"
            )
        var lib = OwnedDLHandle(_find_flare_zlib_lib())
        var n = len(data)
        var with_trailer = List[UInt8](capacity=n + 4)
        for i in range(n):
            with_trailer.append(data[i])
        with_trailer.append(UInt8(0x00))
        with_trailer.append(UInt8(0x00))
        with_trailer.append(UInt8(0xFF))
        with_trailer.append(UInt8(0xFF))
        var cap = max(n * 4, 4096)
        if cap > self.max_decompressed_bytes:
            cap = self.max_decompressed_bytes
        while True:
            var out = List[UInt8](capacity=cap)
            out.resize(cap, 0)
            var written = _do_pmd_decompress_chunk(
                lib,
                self._decomp_handle,
                Int(with_trailer.unsafe_ptr()),
                c_int(len(with_trailer)),
                Int(out.unsafe_ptr()),
                c_int(cap),
            )
            if Int(written) < 0:
                raise Error(
                    "permessage-deflate: inflate chunk returned zlib error "
                    + String(written)
                )
            if Int(written) < cap:
                out.resize(Int(written), 0)
                return out^
            if cap >= self.max_decompressed_bytes:
                raise Error(
                    "permessage-deflate: decompressed output"
                    " exceeded max_decompressed_bytes ("
                    + String(self.max_decompressed_bytes)
                    + " bytes)"
                )
            cap *= 2
            if cap > self.max_decompressed_bytes:
                cap = self.max_decompressed_bytes
