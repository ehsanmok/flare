/**
 * flare HTTP — minimal brotli wrapper for Mojo FFI.
 *
 * Exposes a single-call ``(const void*, size_t, void*, size_t,
 * int) -> int`` API mirroring zlib_wrapper.c so Mojo never re-reads
 * encoder/decoder state across foreign calls (the JIT cache hazard
 * documented in flare/http/encoding.mojo applies the same way to
 * BrotliDecoderState/BrotliEncoderState).
 *
 * The conda-forge ``libbrotli{common,dec,enc}`` packages ship the
 * shared libraries but not the public headers. We inline the
 * minimal subset of <brotli/encode.h> / <brotli/decode.h> below —
 * the brotli ABI has been stable since 1.0.0 (2016) so this is
 * forward-compatible across the conda-forge 1.x series we depend
 * on.
 *
 * Build:
 *   gcc -O2 -fPIC -shared -o libflare_brotli.so brotli_wrapper.c \
 *       -L$CONDA_PREFIX/lib -lbrotlidec -lbrotlienc -lbrotlicommon \
 *       -Wl,-rpath,$CONDA_PREFIX/lib
 *
 * Returns:
 *   - On success: number of bytes written to ``dst``.
 *   - On failure: a negative error code:
 *       -1 = generic failure (input/output null, decoder/encoder error).
 *       -2 = output buffer too small (caller must grow + retry).
 */

#include <stddef.h>
#include <stdint.h>

/* ── Inline brotli ABI declarations (minimal subset) ─────────────────────── */

/* From <brotli/types.h> — BROTLI_BOOL is a typedef'd int. */
#define BROTLI_FALSE 0
#define BROTLI_TRUE  1

/* From <brotli/encode.h> — encoder defaults / modes. */
#define BROTLI_DEFAULT_WINDOW 22
#define BROTLI_MODE_GENERIC   0
#define BROTLI_MODE_TEXT      1
#define BROTLI_MODE_FONT      2

/* One-shot encoder. Matches the public BrotliEncoderCompress signature. */
extern int BrotliEncoderCompress(
    int quality,
    int lgwin,
    int mode,
    size_t input_size,
    const uint8_t* input_buffer,
    size_t* encoded_size,
    uint8_t* encoded_buffer);

/* From <brotli/decode.h> — decoder one-shot result codes. */
typedef enum {
    BROTLI_DECODER_RESULT_ERROR             = 0,
    BROTLI_DECODER_RESULT_SUCCESS           = 1,
    BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT  = 2,
    BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT = 3
} BrotliDecoderResult;

extern BrotliDecoderResult BrotliDecoderDecompress(
    size_t encoded_size,
    const uint8_t* encoded_buffer,
    size_t* decoded_size,
    uint8_t* decoded_buffer);

/* ── Public C API (callable from Mojo via OwnedDLHandle) ─────────────────── */

int flare_brotli_compress(const void* src, size_t src_len,
                          void* dst, size_t dst_cap,
                          int quality) {
    if (!src || !dst) return -1;
    if (quality < 0) quality = 5;
    if (quality > 11) quality = 11;
    size_t out_len = dst_cap;
    int rc = BrotliEncoderCompress(
        quality,
        BROTLI_DEFAULT_WINDOW,
        BROTLI_MODE_GENERIC,
        src_len,
        (const uint8_t*)src,
        &out_len,
        (uint8_t*)dst);
    if (rc == BROTLI_FALSE) {
        if (out_len == 0 || out_len == dst_cap) return -2;
        return -1;
    }
    return (int)out_len;
}

int flare_brotli_decompress(const void* src, size_t src_len,
                            void* dst, size_t dst_cap) {
    if (!src || !dst) return -1;
    size_t out_len = dst_cap;
    BrotliDecoderResult rc = BrotliDecoderDecompress(
        src_len,
        (const uint8_t*)src,
        &out_len,
        (uint8_t*)dst);
    if (rc == BROTLI_DECODER_RESULT_SUCCESS) {
        return (int)out_len;
    }
    if (rc == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
        return -2;
    }
    /* The one-shot ``BrotliDecoderDecompress`` returns ERROR (rc=0)
     * — not NEEDS_MORE_OUTPUT — when the caller's output buffer is
     * too small but the encoded stream itself is valid. Treat
     * "ERROR with the full buffer consumed" as a buffer-size hint
     * so the Mojo caller retries with 2x the cap, matching the
     * zlib code path. We only know it's a buffer issue when
     * ``out_len == dst_cap`` (decoder filled everything we gave
     * it). For genuinely corrupt input ``out_len`` is typically
     * smaller than ``dst_cap``. */
    if (out_len == dst_cap) {
        return -2;
    }
    return -1;
}
