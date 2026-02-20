#!/bin/bash
# Build the OpenSSL TLS wrapper shared library for flare.
# Uses OpenSSL installed via pixi (conda-forge).
#
# This script is idempotent - skips the rebuild if the library is already
# up-to-date (source files are not newer than the output).
#
# NOTE: When used as a pixi activation script, use 'return' not 'exit'
# so the sourcing shell is not terminated.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../../../build"
TARGET="$BUILD_DIR/libflare_tls.so"
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
    [ "$SOURCE" -nt "$TARGET" ] && return 0
    [ "$HEADER" -nt "$TARGET" ] && return 0
    # Rebuild if the pixi-managed OpenSSL library itself was updated
    [ "$CONDA_PREFIX/lib/libssl.so" -nt "$TARGET" ] 2>/dev/null && return 0
    [ "$CONDA_PREFIX/lib/libssl.dylib" -nt "$TARGET" ] 2>/dev/null && return 0
    return 1
}

if ! _needs_rebuild; then
    export FLARE_LIB="$TARGET"
    if [[ "$(uname)" != "Darwin" ]]; then
        export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${TARGET}"
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

# ── Export path so _find_flare_lib() resolves it without pathlib ──────────────
# `build.sh` is *sourced* by pixi's activation script, so `export` persists into
# any `pixi run …` child process. This avoids the need for `pathlib.Path.exists()`
# in Mojo (which caused a runtime crash on Linux x86_64).
export FLARE_LIB="$TARGET"

# ── Preload on Linux so Mojo's JIT can call into the library ──────────────────
# Mojo's LLVM JIT crashes on Linux when calling functions obtained via
# OwnedDLHandle.get_function() into a freshly-dlopen'd shared library.
# Pre-mapping the library at process startup (via LD_PRELOAD) avoids this:
# the code pages are already present before the JIT runs, so indirect calls
# through function pointers work correctly.  macOS does not have this issue.
if [[ "$(uname)" != "Darwin" ]]; then
    export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${TARGET}"
fi
