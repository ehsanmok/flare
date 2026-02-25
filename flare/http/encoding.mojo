"""HTTP content-encoding helpers: gzip and deflate via zlib FFI.

Calls zlib through ``libflare_zlib.so``, a thin C wrapper built automatically
on ``pixi install`` / environment activation via ``flare/http/ffi/build.sh``.

**Why a C wrapper instead of calling zlib directly?**

The C wrapper exposes a single-call ``(const void*, int, void*, int, int) -> int``
API so Mojo never needs to re-read z_stream fields after a foreign call — Mojo's
JIT can serve stale stack-slot values for memory modified by external calls,
returning incorrect byte counts.

**Why helper functions with borrowed ``lib``?**

Mojo's ASAP (As Soon As Possible) destruction policy destroys an ``OwnedDLHandle``
immediately after its last *Mojo-visible* use, which is the ``get_function`` call
that retrieves the function pointer.  ASAP then calls ``dlclose`` and unmaps the
library *before* the pointer is actually invoked, crashing the JIT on both macOS
ARM64 and Linux.

The fix: each public entry point opens ``lib``, then delegates to a private helper
that accepts ``lib`` as a ``read`` (borrowed) parameter.  A borrow cannot be
ASAP-destroyed — it stays alive for the helper's entire execution, including every
C call inside it.

Public API surface:

- ``decompress_gzip(data)``    → ``List[UInt8]``
- ``decompress_deflate(data)`` → ``List[UInt8]``
- ``compress_gzip(data, level=6)`` → ``List[UInt8]``
- ``decode_content(data, encoding)`` → ``List[UInt8]``
"""

from os import getenv
from ffi import OwnedDLHandle, c_int


fn _find_flare_zlib_lib() -> String:
    """Return the path to ``libflare_zlib.so``.

    Search order:
    1. ``$FLARE_ZLIB_LIB`` — set by the pixi activation script.
    2. ``$CONDA_PREFIX/lib/libflare_zlib.so`` — installed via conda/pixi.
    3. ``build/libflare_zlib.so`` — bare checkout without a conda environment.

    Returns:
        Path string suitable for passing to ``OwnedDLHandle``.
    """
    var explicit = getenv("FLARE_ZLIB_LIB", "")
    if explicit:
        return explicit
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix:
        return prefix + "/lib/libflare_zlib.so"
    return "build/libflare_zlib.so"


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


fn _do_decompress(
    read lib: OwnedDLHandle,
    data: Span[UInt8],
    window_bits: c_int,
) raises -> List[UInt8]:
    """Decompress using ``flare_decompress``, growing the output buffer on overflow.

    ``lib`` is a borrow: it cannot be ASAP-destroyed while this function runs,
    keeping the shared library mapped across every C call below.

    Args:
        lib:         Borrowed handle to ``libflare_zlib.so``.
        data:        Compressed input bytes.
        window_bits: zlib windowBits (47=auto gzip/zlib, 15=zlib, -15=raw).

    Returns:
        Decompressed bytes.

    Raises:
        Error: If zlib reports a non-recoverable error.
    """
    var fn_decomp = lib.get_function[
        fn(Int, c_int, Int, c_int, c_int) -> c_int
    ]("flare_decompress")

    var cap = max(len(data) * 4, 4096)
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
            # Buffer was large enough; trim to actual output.
            out.resize(Int(written), 0)
            return out^

        # Output buffer was completely filled — might be truncated; double and retry.
        cap *= 2


fn _decompress_impl(
    data: Span[UInt8], window_bits: c_int
) raises -> List[UInt8]:
    """Entry point for gzip/zlib decompression.

    Args:
        data:        Compressed input bytes.
        window_bits: zlib windowBits passed through to ``_do_decompress``.

    Returns:
        Decompressed bytes.

    Raises:
        Error: If zlib reports a non-recoverable error.
    """
    if len(data) == 0:
        return List[UInt8]()
    var lib = OwnedDLHandle(_find_flare_zlib_lib())
    return _do_decompress(lib, data, window_bits)


fn _do_decompress_deflate(
    read lib: OwnedDLHandle,
    data: Span[UInt8],
) raises -> List[UInt8]:
    """Decompress using ``flare_decompress_deflate``, growing on overflow.

    ``lib`` is a borrow: it cannot be ASAP-destroyed while this function runs,
    keeping the shared library mapped across every C call below.

    Args:
        lib:  Borrowed handle to ``libflare_zlib.so``.
        data: Compressed input bytes.

    Returns:
        Decompressed bytes.

    Raises:
        Error: If neither zlib-wrapped nor raw deflate succeeds.
    """
    var fn_decomp = lib.get_function[fn(Int, c_int, Int, c_int) -> c_int](
        "flare_decompress_deflate"
    )

    var cap = max(len(data) * 4, 4096)
    while True:
        var out = List[UInt8](capacity=cap)
        out.resize(cap, 0)

        var written = fn_decomp(
            Int(data.unsafe_ptr()),
            c_int(len(data)),
            Int(out.unsafe_ptr()),
            c_int(cap),
        )

        if Int(written) < 0:
            raise Error("flare_decompress_deflate failed: " + String(written))

        if Int(written) < cap:
            out.resize(Int(written), 0)
            return out^

        cap *= 2


fn _decompress_deflate_impl(data: Span[UInt8]) raises -> List[UInt8]:
    """Entry point for deflate decompression (zlib-wrapped with raw fallback).

    Args:
        data: Compressed input bytes.

    Returns:
        Decompressed bytes.

    Raises:
        Error: If neither zlib-wrapped nor raw deflate succeeds.
    """
    if len(data) == 0:
        return List[UInt8]()
    var lib = OwnedDLHandle(_find_flare_zlib_lib())
    return _do_decompress_deflate(lib, data)


fn _do_compress(
    read lib: OwnedDLHandle,
    data: Span[UInt8],
    level: c_int,
) raises -> List[UInt8]:
    """Compress using ``flare_compress_gzip``.

    ``lib`` is a borrow: it cannot be ASAP-destroyed while this function runs,
    keeping the shared library mapped across the C call below.

    Args:
        lib:   Borrowed handle to ``libflare_zlib.so``.
        data:  Plaintext input bytes.
        level: Compression level (1–9).

    Returns:
        Gzip-compressed bytes.

    Raises:
        Error: If compression fails.
    """
    var fn_comp = lib.get_function[fn(Int, c_int, Int, c_int, c_int) -> c_int](
        "flare_compress_gzip"
    )

    # Worst-case gzip overhead: ~18 bytes header/trailer + 0.1% + 12 bytes.
    var cap = len(data) + (len(data) >> 10) + 32
    var out = List[UInt8](capacity=cap)
    out.resize(cap, 0)

    var written = fn_comp(
        Int(data.unsafe_ptr()),
        c_int(len(data)),
        Int(out.unsafe_ptr()),
        c_int(cap),
        level,
    )

    if Int(written) < 0:
        raise Error("flare_compress_gzip failed: " + String(written))

    out.resize(Int(written), 0)
    return out^


fn decompress_gzip(data: Span[UInt8]) raises -> List[UInt8]:
    """Decompress a gzip-encoded buffer using zlib.

    Uses ``flare_decompress`` with ``windowBits = 47`` (auto-detect gzip or
    zlib-wrapped deflate).

    Args:
        data: The compressed bytes to decompress.

    Returns:
        The decompressed bytes.

    Raises:
        Error: If the input is not valid gzip data or decompression fails.
    """
    return _decompress_impl(data, c_int(47))


fn decompress_deflate(data: Span[UInt8]) raises -> List[UInt8]:
    """Decompress a deflate-encoded buffer using zlib.

    Tries zlib-wrapped deflate first; falls back to raw deflate, matching
    browser behaviour for the ambiguous ``deflate`` encoding.

    Args:
        data: The compressed bytes to decompress.

    Returns:
        The decompressed bytes.

    Raises:
        Error: If neither zlib-wrapped nor raw deflate succeeds.
    """
    return _decompress_deflate_impl(data)


fn compress_gzip(data: Span[UInt8], level: Int = 6) raises -> List[UInt8]:
    """Compress bytes using gzip via zlib.

    Args:
        data:  The plaintext bytes to compress.
        level: Compression level (1 = fastest, 9 = best; 6 = default).

    Returns:
        The gzip-compressed bytes (including gzip header and trailer).

    Raises:
        Error: If compression fails or the output buffer was unexpectedly small.
    """
    if len(data) == 0:
        return List[UInt8]()
    var lib = OwnedDLHandle(_find_flare_zlib_lib())
    return _do_compress(lib, data, c_int(level))


fn decode_content(data: Span[UInt8], encoding: String) raises -> List[UInt8]:
    """Decode ``data`` according to the ``Content-Encoding`` header value.

    Args:
        data:     The (possibly compressed) response body.
        encoding: The value of the HTTP ``Content-Encoding`` header.

    Returns:
        Decoded bytes. If ``encoding`` is ``"identity"`` or ``""``
        the original bytes are copied and returned.

    Raises:
        Error: If the encoding is not supported or decompression fails.
    """
    if encoding == Encoding.GZIP:
        return decompress_gzip(data)
    elif encoding == Encoding.DEFLATE:
        return decompress_deflate(data)
    elif encoding == Encoding.IDENTITY or encoding == "":
        var out = List[UInt8](capacity=len(data))
        for b in data:
            out.append(b)
        return out^
    else:
        raise Error("decode_content: unsupported encoding '" + encoding + "'")
