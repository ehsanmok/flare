/**
 * flare HTTP — per-thread cache for an encoder's large work buffers.
 *
 * Included by the brotli and zlib wrappers, each of which builds its own
 * copy into its shared library.
 */

#ifndef FLARE_SCRATCH_CACHE_H
#define FLARE_SCRATCH_CACHE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* An encoder allocates its work buffers per call: brotli over 600 KiB at
 * quality 1, zlib deflate four 64 KiB blocks. Blocks that size come
 * straight from the OS and go back to it on free, so every response paid
 * for mapping, zero-filling and unmapping them, more than the compression
 * itself under load. Each thread keeps a few freed large blocks for the
 * next call instead.
 *
 * Bounded: only blocks of 64 KiB to 1 MiB are kept, at most 8 and 4 MiB
 * per thread, released when the thread exits. A kept block holds the
 * previous call's scratch, which the encoder overwrites before reading;
 * its output depends on its input alone.
 */

#define CACHE_SLOTS 8
#define CACHE_MIN_BLOCK ((size_t)64 << 10)
#define CACHE_MAX_BLOCK ((size_t)1 << 20)
#define CACHE_MAX_BYTES ((size_t)4 << 20)
#define BLOCK_HEADER 16

typedef struct {
    int n;
    size_t bytes;
    size_t size[CACHE_SLOTS];
    void* block[CACHE_SLOTS];
} scratch_cache;

static pthread_key_t cache_key;
static pthread_once_t cache_once = PTHREAD_ONCE_INIT;
static int cache_key_ok = 0;

static void cache_release(void* p) {
    scratch_cache* c = (scratch_cache*)p;
    for (int i = 0; i < c->n; i++) free(c->block[i]);
    free(c);
}

static void cache_key_init(void) {
    cache_key_ok = pthread_key_create(&cache_key, cache_release) == 0;
}

static scratch_cache* thread_cache(void) {
    pthread_once(&cache_once, cache_key_init);
    if (!cache_key_ok) return NULL;
    scratch_cache* c = (scratch_cache*)pthread_getspecific(cache_key);
    if (!c) {
        c = (scratch_cache*)calloc(1, sizeof(scratch_cache));
        if (c && pthread_setspecific(cache_key, c) != 0) {
            free(c);
            c = NULL;
        }
    }
    return c;
}

static void* scratch_alloc(void* opaque, size_t size) {
    (void)opaque;
    if (size > SIZE_MAX - BLOCK_HEADER) return NULL;
    scratch_cache* c = size >= CACHE_MIN_BLOCK ? thread_cache() : NULL;
    if (c) {
        for (int i = 0; i < c->n; i++) {
            if (c->size[i] == size) {
                uint8_t* b = (uint8_t*)c->block[i];
                c->bytes -= size;
                c->n--;
                c->size[i] = c->size[c->n];
                c->block[i] = c->block[c->n];
                return b + BLOCK_HEADER;
            }
        }
    }
    uint8_t* b = (uint8_t*)malloc(size + BLOCK_HEADER);
    if (!b) return NULL;
    *(size_t*)b = size;
    return b + BLOCK_HEADER;
}

static void scratch_free(void* opaque, void* address) {
    (void)opaque;
    if (!address) return;
    uint8_t* b = (uint8_t*)address - BLOCK_HEADER;
    size_t size = *(size_t*)b;
    if (size >= CACHE_MIN_BLOCK && size <= CACHE_MAX_BLOCK) {
        scratch_cache* c = thread_cache();
        if (c && c->n < CACHE_SLOTS && c->bytes + size <= CACHE_MAX_BYTES) {
            c->size[c->n] = size;
            c->block[c->n] = b;
            c->n++;
            c->bytes += size;
            return;
        }
    }
    free(b);
}

#endif
