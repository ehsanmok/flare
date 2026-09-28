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
# Keeping the library mapped:
#   All of flare's FFI entry points route through ``_do_*(read lib:
#   OwnedDLHandle, ...)`` borrow helpers, which keep ``lib`` alive across
#   both the symbol lookup and the call, so ``dlclose`` cannot fire
#   between them. As a second guard, the library is linked with
#   ``-z nodelete`` on Linux: once loaded it is never unmapped, so even
#   a call site that forgot the borrow cannot leave a dangling pointer.
#
#   This used to be done by exporting LD_PRELOAD from the activation
#   script, which injected libflare_tls.so, and with it conda's libssl,
#   into every process pixi started, system tools included.
#
# A failed build removes the installed copy and says so on stderr.
# It used to leave the previous library in place, so everything after
# ran the old code without a sign that the new source had not built.

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
NODELETE=""
if [[ "$(uname)" == "Darwin" ]]; then
    CXX="clang++"
else
    CXX="g++"
    NODELETE="-Wl,-z,nodelete"
fi

echo "Building libflare_tls.so..."

if $CXX -O2 -std=c++17 -fPIC -DNDEBUG -shared \
    -o "$TARGET" \
    "$SOURCE" \
    -I"$CONDA_PREFIX/include" \
    -L"$CONDA_PREFIX/lib" \
    -lssl -lcrypto \
    $NODELETE \
    -Wl,-rpath,"$CONDA_PREFIX/lib"; then
    echo ""
    echo "Build complete!"
    echo "Library: $TARGET"
    ls -la "$TARGET"
else
    echo "ERROR: libflare_tls.so failed to build; removed the stale copy" >&2
    rm -f "$TARGET" "$INSTALLED"
    return 1 2>/dev/null || true
fi

# ── Install to $CONDA_PREFIX/lib (canonical location) ────────────────────────
mkdir -p "$CONDA_PREFIX/lib"
cp "$TARGET" "$INSTALLED"
echo "Installed: $INSTALLED"
