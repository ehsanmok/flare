/**
 * flare HTTP - minimal zlib wrapper for Mojo FFI.
 *
 * Exposes a single-call compression/decompression API so Mojo never needs to
 * read back z_stream fields through raw pointer arithmetic after an external
 * call -- Mojo's LLVM JIT may serve stale register values for stack slots that
 * were modified by a foreign call, leading to incorrect "have = 0" reads.
 *
 * All functions take pointer arguments as void* (mapped to Mojo Int) and
 * integer parameters as int (mapped to Mojo c_int / Int32).
 *
 * Mojo callers must keep the OwnedDLHandle for this library alive across every
 * call by passing it as a 'read' (borrowed) parameter.  Mojo's ASAP destruction
 * policy otherwise calls dlclose() immediately after get_function() returns --
 * before the retrieved function pointer is ever invoked -- unmapping the library
 * and crashing the JIT on both macOS ARM64 and Linux.
 *
 * Build: see build.sh
 */

#include <zlib.h>
#include <stddef.h>
#include <string.h>

/* ── Decompress (inflate) ──────────────────────────────────────────────────── */

/**
 * Decompress ``in_len`` bytes from ``in_buf`` into ``out_buf``.
 *
 * Handles both gzip and zlib-wrapped deflate automatically.  Raw deflate is
 * tried as a fallback when ``window_bits = 47`` initial decompression fails.
 *
 * @param in_buf      Pointer to the compressed input bytes.
 * @param in_len      Number of compressed input bytes.
 * @param out_buf     Pointer to the output buffer (pre-allocated by caller).
 * @param out_cap     Size of the output buffer in bytes.
 * @param window_bits zlib windowBits: 47 = auto gzip/zlib, 15 = zlib,
 *                    -15 = raw deflate.
 * @return Number of bytes written to ``out_buf`` on success; negative zlib
 *         error code on failure.
 */
int flare_decompress(const void *in_buf, int in_len,
                     void *out_buf, int out_cap,
                     int window_bits) {
    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));
    strm.next_in  = (Bytef *)in_buf;
    strm.avail_in = (uInt)in_len;

    int rc = inflateInit2(&strm, window_bits);
    if (rc != Z_OK) return rc;

    strm.next_out  = (Bytef *)out_buf;
    strm.avail_out = (uInt)out_cap;

    rc = inflate(&strm, Z_SYNC_FLUSH);
    int written = out_cap - (int)strm.avail_out;
    inflateEnd(&strm);

    if (rc == Z_STREAM_END || rc == Z_OK || rc == Z_BUF_ERROR) {
        return written;
    }
    return rc;  /* negative error code */
}

/**
 * Decompress a deflate-encoded buffer, trying zlib-wrapped first then raw.
 *
 * Matches browser behaviour for the ambiguous HTTP ``deflate`` encoding.
 *
 * @param in_buf   Pointer to the compressed input bytes.
 * @param in_len   Number of compressed input bytes.
 * @param out_buf  Pointer to the output buffer (pre-allocated by caller).
 * @param out_cap  Size of the output buffer in bytes.
 * @return Number of bytes written to ``out_buf`` on success; negative on failure.
 */
int flare_decompress_deflate(const void *in_buf, int in_len,
                              void *out_buf, int out_cap) {
    /* Try zlib-wrapped first (windowBits = 15) */
    int rc = flare_decompress(in_buf, in_len, out_buf, out_cap, 15);
    if (rc >= 0) return rc;

    /* Fall back to raw deflate (windowBits = -15) */
    return flare_decompress(in_buf, in_len, out_buf, out_cap, -15);
}

/* ── Compress (deflate) ────────────────────────────────────────────────────── */

/**
 * Compress ``in_len`` bytes from ``in_buf`` into a gzip container.
 *
 * @param in_buf   Pointer to the plaintext input bytes.
 * @param in_len   Number of plaintext input bytes.
 * @param out_buf  Pointer to the output buffer (pre-allocated by caller).
 * @param out_cap  Size of the output buffer in bytes.
 * @param level    Compression level (1–9; 0 = no compression; -1 = default).
 * @return Number of bytes written to ``out_buf`` on success; negative on failure.
 */
int flare_compress_gzip(const void *in_buf, int in_len,
                        void *out_buf, int out_cap,
                        int level) {
    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));

    /* windowBits = 15 | 16 = gzip container; method = Z_DEFLATED */
    int rc = deflateInit2(&strm, level, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
    if (rc != Z_OK) return rc;

    strm.next_in   = (Bytef *)in_buf;
    strm.avail_in  = (uInt)in_len;
    strm.next_out  = (Bytef *)out_buf;
    strm.avail_out = (uInt)out_cap;

    rc = deflate(&strm, Z_FINISH);
    int written = out_cap - (int)strm.avail_out;
    deflateEnd(&strm);

    if (rc == Z_STREAM_END) return written;
    if (rc == Z_OK || rc == Z_BUF_ERROR) return written;  /* partial: buf_error */
    return rc;  /* negative error code */
}

/**
 * Return the size of z_stream in bytes (for diagnostics).
 */
int flare_zstream_size(void) {
    return (int)sizeof(z_stream);
}
