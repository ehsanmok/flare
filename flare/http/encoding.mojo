"""HTTP content-encoding helpers: gzip and deflate via zlib FFI.

Uses the top-level ``ffi`` stdlib module (nightly):
    https://docs.modular.com/mojo/std/ffi/

zlib is declared in pixi.toml so ``$CONDA_PREFIX/lib/libz.so.1`` is always
available at runtime regardless of host OS.

Key zlib symbols used:
    inflateInit2  — initialise decompressor (windowBits controls format)
    inflate       — feed compressed chunks and receive plaintext output
    inflateEnd    — release decompressor state
    deflateInit2  — initialise compressor
    deflate       — compress
    deflateEnd    — release compressor state
"""


struct Encoding:
    """HTTP ``Content-Encoding`` / ``Accept-Encoding`` token constants."""

    comptime IDENTITY: String = "identity"
    """No encoding applied; pass-through."""

    comptime GZIP: String = "gzip"
    """IETF gzip format (zlib + gzip wrapper, windowBits = 15 | 16)."""

    comptime DEFLATE: String = "deflate"
    """Raw deflate or zlib-wrapped deflate (windowBits = 15 or -15)."""

    comptime BR: String = "br"
    """Brotli encoding (future; requires libbrotlidec)."""


fn decompress_gzip(data: Span[UInt8]) raises -> List[UInt8]:
    """Decompress a gzip-encoded buffer using zlib.

    Uses ``inflateInit2`` with ``windowBits = 47`` (gzip auto-detect).

    Args:
        data: The compressed bytes to decompress.

    Returns:
        The decompressed bytes.

    Raises:
        HttpError: If the input is not valid gzip data or decompression fails.
    """
    # TODO:
    # from ffi import external_call
    # z_stream_init → inflateInit2(stream, 47)    # 47 = 15 | 32 gzip/zlib auto
    # while inflate returns Z_OK or Z_BUF_ERROR: collect output chunks
    # inflateEnd
    raise Error("decompress_gzip: not yet implemented")


fn decompress_deflate(data: Span[UInt8]) raises -> List[UInt8]:
    """Decompress a deflate-encoded buffer using zlib.

    Tries zlib-wrapped deflate first (``windowBits = 15``); on failure
    retries with raw deflate (``windowBits = -15``), matching browser
    behaviour for the ambiguous ``deflate`` encoding.

    Args:
        data: The compressed bytes to decompress.

    Returns:
        The decompressed bytes.

    Raises:
        HttpError: If the input is not valid deflate data.
    """
    raise Error("decompress_deflate: not yet implemented")


fn compress_gzip(data: Span[UInt8], level: Int = 6) raises -> List[UInt8]:
    """Compress bytes using gzip via zlib.

    Args:
        data:  The plaintext bytes to compress.
        level: Compression level (1 = fastest, 9 = best; 6 = default).

    Returns:
        The gzip-compressed bytes.

    Raises:
        HttpError: If compression fails.
    """
    raise Error("compress_gzip: not yet implemented")


fn decode_content(data: Span[UInt8], encoding: String) raises -> List[UInt8]:
    """Decode ``data`` according to the ``Content-Encoding`` header value.

    Args:
        data:     The (possibly compressed) response body.
        encoding: The value of the HTTP ``Content-Encoding`` header.

    Returns:
        The decoded (plain) bytes. If ``encoding`` is ``"identity"`` or
        ``""`` the original bytes are returned without copying.

    Raises:
        HttpError: If the encoding is not supported or decompression fails.
    """
    if encoding == Encoding.GZIP:
        return decompress_gzip(data)
    elif encoding == Encoding.DEFLATE:
        return decompress_deflate(data)
    elif encoding == Encoding.IDENTITY or encoding == "":
        # No copy — caller should take ownership if desired
        var out = List[UInt8](capacity=len(data))
        for b in data:
            out.append(b)
        return out^
    else:
        raise Error("decode_content: unsupported encoding '" + encoding + "'")
