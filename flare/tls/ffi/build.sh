#!/bin/bash
# Build the OpenSSL TLS wrapper shared library for flare.
# Uses OpenSSL installed via pixi (conda-forge).
#
# This script is idempotent - skips the rebuild if the library is already
# up-to-date (source files are not newer than the output).
#
# NOTE: When used as a pixi activation script, use 'return' not 'exit'
# so the sourcing shell is not terminated.
#
# Install layout (matches ehsanmok/json's libsimdjson_wrapper.so):
#   1. Build into $BUILD_DIR/libflare_tls.so (source-tree artifact).
#   2. Copy to $CONDA_PREFIX/lib/libflare_tls.so — the CANONICAL location.
# Mojo's _find_flare_lib* helpers resolve the library via CONDA_PREFIX, so
# anything pixi launches finds it automatically without FLARE_LIB-style
# env-var indirection.
#
# Why also LD_PRELOAD on Linux (same .so path as the install)?
#   All of flare's FFI entry points now route through ``_do_*(read lib:
#   OwnedDLHandle, ...)`` borrow helpers (see flare/tls/stream.mojo,
#   flare/tls/_server_ffi.mojo, flare/ws/{client,server}.mojo,
#   flare/crypto/hmac.mojo, flare/net/_libc.mojo, flare/net/socket.mojo,
#   flare/tcp/stream.mojo, flare/http/{encoding,middleware,fs}.mojo).
#   That's the load-bearing fix for Mojo's ASAP destruction policy:
#   the borrow keeps ``lib`` alive across both ``get_function`` and the
#   call, so ``dlclose`` cannot fire between them and the cached
#   function pointer cannot dangle.
#
#   LD_PRELOAD remains as belt-and-suspenders defense: it pins the .so
#   refcount above zero so even a hypothetical regression to the naive
#   pattern (e.g. a contributor adding a new FFI call site that forgets
#   the borrow helper) cannot dlclose the library. Critically we
#   LD_PRELOAD the *same .so file* Mojo dlopens (both resolve to
#   $INSTALLED), so there is exactly one mapping in the process —
#   no "two copies, one unmapped" hazard.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../../../build"
TARGET="$BUILD_DIR/libflare_tls.so"
INSTALLED="$CONDA_PREFIX/lib/libflare_tls.so"
SOURCE="$SCRIPT_DIR/openssl_wrapper.cpp"
HEADER="$SCRIPT_DIR/openssl_wrapper.h"

# Verify CONDA_PREFIX is set (pixi sets this on activation)
if [ -z "$CONDA_PREFIX" ]; then
    echo "Warning: CONDA_PREFIX not set. Skipping flare TLS FFI build."
    return 0 2>/dev/null || true
fi

# ── Idempotency check ────────────────────────────────────────────────────────
_needs_rebuild() {
    [ ! -f "$TARGET" ] && return 0
    [ ! -f "$INSTALLED" ] && return 0
    [ "$SOURCE" -nt "$TARGET" ] && return 0
    [ "$HEADER" -nt "$TARGET" ] && return 0
    # Rebuild if the pixi-managed OpenSSL library itself was updated
    [ "$CONDA_PREFIX/lib/libssl.so" -nt "$TARGET" ] 2>/dev/null && return 0
    [ "$CONDA_PREFIX/lib/libssl.dylib" -nt "$TARGET" ] 2>/dev/null && return 0
    # Rebuild if the CONDA_PREFIX copy is stale relative to the build copy
    # (e.g. pixi recreated the env but kept the source-tree build/).
    [ "$TARGET" -nt "$INSTALLED" ] 2>/dev/null && return 0
    return 1
}

if ! _needs_rebuild; then
    if [[ "$(uname)" != "Darwin" ]]; then
        export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${INSTALLED}"
    fi
    return 0 2>/dev/null || true
fi

# ── Build ────────────────────────────────────────────────────────────────────
echo "========================================"
echo "Building flare TLS FFI wrapper"
echo "========================================"
echo ""
echo "Using OpenSSL from: $CONDA_PREFIX"
echo "  Headers: $CONDA_PREFIX/include/openssl/"
echo "  Library: $CONDA_PREFIX/lib/"
echo ""

# Verify OpenSSL headers are present
if [ ! -f "$CONDA_PREFIX/include/openssl/ssl.h" ]; then
    echo "Error: openssl/ssl.h not found at $CONDA_PREFIX/include/"
    echo "Run 'pixi install' to install dependencies."
    return 1 2>/dev/null || true
fi

mkdir -p "$BUILD_DIR"

# Use clang++ on macOS (matches the system libc++ ABI), g++ on Linux
if [[ "$(uname)" == "Darwin" ]]; then
    CXX="clang++"
else
    CXX="g++"
fi

echo "Building libflare_tls.so..."

if $CXX -O2 -std=c++17 -fPIC -DNDEBUG -shared \
    -o "$TARGET" \
    "$SOURCE" \
    -I"$CONDA_PREFIX/include" \
    -L"$CONDA_PREFIX/lib" \
    -lssl -lcrypto \
    -Wl,-rpath,"$CONDA_PREFIX/lib"; then
    echo ""
    echo "Build complete!"
    echo "Library: $TARGET"
    ls -la "$TARGET"
else
    echo "Build failed!"
    return 1 2>/dev/null || true
fi

# ── Install to $CONDA_PREFIX/lib (canonical location) ────────────────────────
mkdir -p "$CONDA_PREFIX/lib"
cp "$TARGET" "$INSTALLED"
echo "Installed: $INSTALLED"

# ── Keep the library mapped on Linux so ASAP-destroyed OwnedDLHandles ────────
# don't tear it down under the JIT's feet (see the long comment at the top
# of this file). Always LD_PRELOAD the same path Mojo dlopens: $INSTALLED.
if [[ "$(uname)" != "Darwin" ]]; then
    export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${INSTALLED}"
fi
