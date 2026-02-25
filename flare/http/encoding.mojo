"""HTTP content-encoding helpers: gzip and deflate via zlib FFI.

Calls zlib through ``libflare_zlib.so``, a thin C wrapper built automatically
on ``pixi install`` / environment activation via ``flare/http/ffi/build.sh``.

**Why a C wrapper instead of calling zlib directly?**

Mojo's LLVM JIT on Linux crashes when ``OwnedDLHandle.get_function()`` is
called into a freshly-``dlopen``'d library.  Pre-mapping the wrapper via
``LD_PRELOAD`` (set by ``build.sh``) avoids the crash.  The C wrapper also
exposes a single-call ``(const void*, int, void*, int, int) -> int`` API so
Mojo never needs to re-read z_stream fields after a foreign call — Mojo's JIT
can serve stale stack-slot values for memory modified by external calls,
returning incorrect byte counts.

Public API surface:

- ``decompress_gzip(data)``    → ``List[UInt8]``
- ``decompress_deflate(data)`` → ``List[UInt8]``
- ``compress_gzip(data, level=6)`` → ``List[UInt8]``
- ``decode_content(data, encoding)`` → ``List[UInt8]``
"""

from os import getenv
from ffi import OwnedDLHandle, c_int
from memory import stack_allocation


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


fn _decompress_impl(
    data: Span[UInt8], window_bits: c_int
) raises -> List[UInt8]:
    """Core decompression: call ``flare_decompress`` with a grow-on-overflow loop.

    Starts with a 4× guess buffer; doubles until the C function confirms
    all input was consumed.

    Args:
        data:        Compressed input bytes.
        window_bits: zlib windowBits (47=auto gzip/zlib, 15=zlib, -15=raw).

    Returns:
        Decompressed bytes.

    Raises:
        Error: If zlib reports a non-recoverable error.
    """
    if len(data) == 0:
        return List[UInt8]()

    var lib = OwnedDLHandle(_find_flare_zlib_lib())
    var fn_decomp = lib.get_function[
        fn (Int, c_int, Int, c_int, c_int) -> c_int
    ]("flare_decompress")

    var cap = max(len(data) * 4, 4096)
    while True:
        var out = List[UInt8](capacity=cap)
        out.resize(cap, 0)

        var written = Int(
            fn_decomp(
                Int(data.unsafe_ptr()),
                c_int(len(data)),
                Int(out.unsafe_ptr()),
                c_int(cap),
                window_bits,
            )
        )

        if written < 0:
            raise Error("flare_decompress failed: " + String(written))

        if written < cap:
            # Buffer was large enough; trim to actual output.
            out.resize(written, 0)
            return out^

        # Output buffer was completely filled — might be truncated; double and retry.
        cap *= 2


fn _decompress_deflate_impl(data: Span[UInt8]) raises -> List[UInt8]:
    """Decompress deflate-encoded data, trying zlib-wrapped then raw fallback.

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
    var fn_decomp = lib.get_function[
        fn (Int, c_int, Int, c_int) -> c_int
    ]("flare_decompress_deflate")

    var cap = max(len(data) * 4, 4096)
    while True:
        var out = List[UInt8](capacity=cap)
        out.resize(cap, 0)

        var written = Int(
            fn_decomp(
                Int(data.unsafe_ptr()),
                c_int(len(data)),
                Int(out.unsafe_ptr()),
                c_int(cap),
            )
        )

        if written < 0:
            raise Error("flare_decompress_deflate failed: " + String(written))

        if written < cap:
            out.resize(written, 0)
            return out^

        cap *= 2


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
    var fn_comp = lib.get_function[
        fn (Int, c_int, Int, c_int, c_int) -> c_int
    ]("flare_compress_gzip")

    # Worst-case gzip overhead: ~18 bytes header/trailer + 0.1% + 12 bytes.
    var cap = len(data) + (len(data) >> 10) + 32
    var out = List[UInt8](capacity=cap)
    out.resize(cap, 0)

    var written = Int(
        fn_comp(
            Int(data.unsafe_ptr()),
            c_int(len(data)),
            Int(out.unsafe_ptr()),
            c_int(cap),
            c_int(level),
        )
    )

    if written < 0:
        raise Error("flare_compress_gzip failed: " + String(written))

    out.resize(written, 0)
    return out^


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
