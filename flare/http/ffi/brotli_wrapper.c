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

#include "scratch_cache.h"

/* ── Inline brotli ABI declarations (minimal subset) ─────────────────────── */

/* From <brotli/types.h> — BROTLI_BOOL is a typedef'd int. */
#define BROTLI_FALSE 0
#define BROTLI_TRUE  1

/* From <brotli/encode.h> — encoder defaults / modes. */
#define BROTLI_DEFAULT_WINDOW 22
#define BROTLI_MODE_GENERIC   0
#define BROTLI_MODE_TEXT      1
#define BROTLI_MODE_FONT      2

/* Streaming encoder, from <brotli/encode.h>. */
typedef void* (*brotli_alloc_func)(void* opaque, size_t size);
typedef void (*brotli_free_func)(void* opaque, void* address);
typedef struct BrotliEncoderStateStruct BrotliEncoderState;
#define BROTLI_PARAM_MODE      0
#define BROTLI_PARAM_QUALITY   1
#define BROTLI_PARAM_LGWIN     2
#define BROTLI_PARAM_SIZE_HINT 5
#define BROTLI_OPERATION_FINISH 2
extern BrotliEncoderState* BrotliEncoderCreateInstance(
    brotli_alloc_func alloc_func, brotli_free_func free_func, void* opaque);
extern void BrotliEncoderDestroyInstance(BrotliEncoderState* state);
extern int BrotliEncoderSetParameter(
    BrotliEncoderState* state, int param, uint32_t value);
extern int BrotliEncoderCompressStream(
    BrotliEncoderState* state, int op,
    size_t* available_in, const uint8_t** next_in,
    size_t* available_out, uint8_t** next_out, size_t* total_out);
extern int BrotliEncoderIsFinished(BrotliEncoderState* state);

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
    BrotliEncoderState* s =
        BrotliEncoderCreateInstance(scratch_alloc, scratch_free, NULL);
    if (!s) return -1;
    BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, (uint32_t)quality);
    BrotliEncoderSetParameter(s, BROTLI_PARAM_LGWIN, BROTLI_DEFAULT_WINDOW);
    BrotliEncoderSetParameter(s, BROTLI_PARAM_MODE, BROTLI_MODE_GENERIC);
    if (src_len < ((size_t)1 << 30))
        BrotliEncoderSetParameter(s, BROTLI_PARAM_SIZE_HINT, (uint32_t)src_len);
    size_t avail_in = src_len;
    const uint8_t* next_in = (const uint8_t*)src;
    size_t avail_out = dst_cap;
    uint8_t* next_out = (uint8_t*)dst;
    int ok = BrotliEncoderCompressStream(s, BROTLI_OPERATION_FINISH,
                                         &avail_in, &next_in,
                                         &avail_out, &next_out, NULL);
    int done = ok && BrotliEncoderIsFinished(s);
    BrotliEncoderDestroyInstance(s);
    if (!ok) return -1;
    if (!done) return -2;
    return (int)(dst_cap - avail_out);
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
