"""HTTP content-encoding helpers: gzip and deflate via zlib FFI.

Uses ``external_call`` from the stdlib ``ffi`` module (nightly) to invoke
zlib symbols directly — no wrapper shared library needed.

On macOS ``libz.dylib`` is always in the system dyld cache, so ``external_call``
finds its symbols without any extra setup.  On Linux the Mojo JIT does **not**
auto-load ``libz.so``, causing a "Symbols not found" error.  The fix is to
call ``OwnedDLHandle(zlib_path)`` before any ``external_call`` into zlib, which
``dlopen``s the library and registers its symbols with the JIT session.  The
handle is kept alive on the stack for the duration of each function.

z_stream layout (LP64: Linux/macOS 64-bit):

    offset  size  field
        0     8   next_in   (pointer)
        8     4   avail_in  (unsigned int)
       12     4   (padding)
       16     8   total_in  (unsigned long)
       24     8   next_out  (pointer)
       32     4   avail_out (unsigned int)
       36     4   (padding)
       40     8   total_out (unsigned long)
       ...
    = 112 bytes total

All pointer arguments to zlib are passed as ``Int`` (pointer-sized on
64-bit) to avoid Mojo's origin/mutability inference issues with FFI.
"""

from sys import CompilationTarget
from ffi import external_call, OwnedDLHandle
from memory import UnsafePointer, stack_allocation


fn _zlib_path() -> String:
    """Return the platform-specific path to the zlib shared library.

    On macOS, ``libz.dylib`` is part of the system dyld cache.
    On Linux, ``libz.so.1`` is the stable ABI-versioned name.

    Returns:
        Absolute or linker-searchable path for ``OwnedDLHandle``.
    """

    @parameter
    if CompilationTarget.is_macos():
        return "libz.dylib"
    else:
        return "libz.so.1"


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


# z_stream offsets (LP64)
comptime _Z_STREAM_SIZE: Int = 112
comptime _Z_NEXT_IN_OFF: Int = 0  # pointer (Int)
comptime _Z_AVAIL_IN_OFF: Int = 8  # UInt32
comptime _Z_NEXT_OUT_OFF: Int = 24  # pointer (Int)
comptime _Z_AVAIL_OUT_OFF: Int = 32  # UInt32

comptime _Z_OK: Int32 = 0
comptime _Z_STREAM_END: Int32 = 1
comptime _Z_BUF_ERROR: Int32 = -5
comptime _Z_NO_FLUSH: Int32 = 0
comptime _Z_FINISH: Int32 = 4
comptime _Z_CHUNK: Int = 65536

# ABI version prefix — zlib only checks first char ('1')
comptime _ZLIB_VER: String = "1.2.11"


fn _inflate_impl(data: Span[UInt8], window_bits: Int32) raises -> List[UInt8]:
    """Core inflate loop for any zlib ``windowBits`` setting.

    On Linux the Mojo JIT won't find zlib symbols unless the library has been
    explicitly ``dlopen``'d.  ``_zlib_handle`` ensures that happens before any
    ``external_call`` into zlib.

    Args:
        data:        Compressed input bytes.
        window_bits: zlib windowBits (47=gzip auto, 15=zlib, -15=raw deflate).

    Returns:
        Decompressed bytes.

    Raises:
        Error: If zlib initialisation or decompression fails.
    """
    if len(data) == 0:
        return List[UInt8]()

    # Load libz so its symbols are visible to external_call on Linux.
    var _zlib_handle = OwnedDLHandle(_zlib_path())

    # Allocate and zero-initialise z_stream on the stack
    var strm = stack_allocation[_Z_STREAM_SIZE, UInt8]()
    for i in range(_Z_STREAM_SIZE):
        (strm + i).init_pointee_copy(UInt8(0))

    # next_in = data pointer, avail_in = len(data)
    (strm + _Z_NEXT_IN_OFF).bitcast[Int]().init_pointee_copy(
        Int(data.unsafe_ptr())
    )
    (strm + _Z_AVAIL_IN_OFF).bitcast[UInt32]().init_pointee_copy(
        UInt32(len(data))
    )

    var ver = _ZLIB_VER

    # inflateInit2_(strm, windowBits, version, stream_size)
    var init_rc = external_call["inflateInit2_", Int32, Int, Int32, Int, Int32](
        Int(strm),
        window_bits,
        Int(ver.unsafe_ptr()),
        Int32(_Z_STREAM_SIZE),
    )
    if init_rc != _Z_OK:
        raise Error("inflateInit2_ failed with code " + String(Int(init_rc)))

    var out = List[UInt8](capacity=len(data) * 3)
    var chunk = List[UInt8](capacity=_Z_CHUNK)
    chunk.resize(_Z_CHUNK, 0)
    var done = False

    while not done:
        # Set next_out and avail_out each iteration
        (strm + _Z_NEXT_OUT_OFF).bitcast[Int]().init_pointee_copy(
            Int(chunk.unsafe_ptr())
        )
        (strm + _Z_AVAIL_OUT_OFF).bitcast[UInt32]().init_pointee_copy(
            UInt32(_Z_CHUNK)
        )

        var ret = external_call["inflate", Int32, Int, Int32](
            Int(strm), _Z_NO_FLUSH
        )

        var avail_out_remaining = Int(
            (strm + _Z_AVAIL_OUT_OFF).bitcast[UInt32]()[]
        )
        var have = _Z_CHUNK - avail_out_remaining
        for i in range(have):
            out.append(chunk[i])

        if ret == _Z_STREAM_END:
            done = True
        elif ret == _Z_BUF_ERROR:
            var avail_in_rem = (strm + _Z_AVAIL_IN_OFF).bitcast[UInt32]()[]
            if avail_in_rem == 0:
                done = True
            else:
                _ = external_call["inflateEnd", Int32, Int](Int(strm))
                raise Error("inflate Z_BUF_ERROR with remaining input")
        elif ret != _Z_OK:
            _ = external_call["inflateEnd", Int32, Int](Int(strm))
            raise Error("inflate failed with code " + String(Int(ret)))
        else:
            var avail_in_rem = (strm + _Z_AVAIL_IN_OFF).bitcast[UInt32]()[]
            if avail_in_rem == 0:
                done = True

    _ = external_call["inflateEnd", Int32, Int](Int(strm))
    return out^


fn decompress_gzip(data: Span[UInt8]) raises -> List[UInt8]:
    """Decompress a gzip-encoded buffer using zlib.

    Uses ``inflateInit2_`` with ``windowBits = 47`` (auto-detect gzip or
    zlib-wrapped deflate).

    Args:
        data: The compressed bytes to decompress.

    Returns:
        The decompressed bytes.

    Raises:
        Error: If the input is not valid gzip data or decompression fails.
    """
    return _inflate_impl(data, Int32(47))


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
        Error: If neither zlib-wrapped nor raw deflate succeeds.
    """
    try:
        return _inflate_impl(data, Int32(15))
    except:
        return _inflate_impl(data, Int32(-15))


fn compress_gzip(data: Span[UInt8], level: Int = 6) raises -> List[UInt8]:
    """Compress bytes using gzip via zlib.

    Args:
        data:  The plaintext bytes to compress.
        level: Compression level (1 = fastest, 9 = best; 6 = default).

    Returns:
        The gzip-compressed bytes.

    Raises:
        Error: If compression fails.
    """
    if len(data) == 0:
        return List[UInt8]()

    # Load libz so its symbols are visible to external_call on Linux.
    var _zlib_handle = OwnedDLHandle(_zlib_path())

    var strm = stack_allocation[_Z_STREAM_SIZE, UInt8]()
    for i in range(_Z_STREAM_SIZE):
        (strm + i).init_pointee_copy(UInt8(0))

    (strm + _Z_NEXT_IN_OFF).bitcast[Int]().init_pointee_copy(
        Int(data.unsafe_ptr())
    )
    (strm + _Z_AVAIL_IN_OFF).bitcast[UInt32]().init_pointee_copy(
        UInt32(len(data))
    )

    var ver = _ZLIB_VER

    # deflateInit2_(strm, level, method=8, windowBits=31, memLevel=8,
    #               strategy=0, version, stream_size)
    # windowBits = 15 | 16 = 31 → gzip container
    var init_rc = external_call[
        "deflateInit2_",
        Int32,
        Int,
        Int32,
        Int32,
        Int32,
        Int32,
        Int32,
        Int,
        Int32,
    ](
        Int(strm),
        Int32(level),
        Int32(8),  # Z_DEFLATED
        Int32(31),  # gzip container (15 | 16)
        Int32(8),  # memLevel default
        Int32(0),  # Z_DEFAULT_STRATEGY
        Int(ver.unsafe_ptr()),
        Int32(_Z_STREAM_SIZE),
    )

    if init_rc != _Z_OK:
        raise Error("deflateInit2_ failed with code " + String(Int(init_rc)))

    var out = List[UInt8](capacity=len(data) + (len(data) >> 10) + 32)
    var chunk = List[UInt8](capacity=_Z_CHUNK)
    chunk.resize(_Z_CHUNK, 0)
    var done = False

    while not done:
        (strm + _Z_NEXT_OUT_OFF).bitcast[Int]().init_pointee_copy(
            Int(chunk.unsafe_ptr())
        )
        (strm + _Z_AVAIL_OUT_OFF).bitcast[UInt32]().init_pointee_copy(
            UInt32(_Z_CHUNK)
        )

        var ret = external_call["deflate", Int32, Int, Int32](
            Int(strm), _Z_FINISH
        )

        var avail_out_rem = Int((strm + _Z_AVAIL_OUT_OFF).bitcast[UInt32]()[])
        var have = _Z_CHUNK - avail_out_rem
        for i in range(have):
            out.append(chunk[i])

        if ret == _Z_STREAM_END:
            done = True
        elif ret != _Z_OK and ret != _Z_BUF_ERROR:
            _ = external_call["deflateEnd", Int32, Int](Int(strm))
            raise Error("deflate failed with code " + String(Int(ret)))
        else:
            var avail_in_rem = (strm + _Z_AVAIL_IN_OFF).bitcast[UInt32]()[]
            if avail_in_rem == 0:
                done = True

    _ = external_call["deflateEnd", Int32, Int](Int(strm))
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
