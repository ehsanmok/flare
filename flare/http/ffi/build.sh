#!/bin/bash
# Build the zlib wrapper shared library for flare HTTP encoding.
# Uses zlib installed via pixi (conda-forge).
#
# This script is idempotent - skips the rebuild if the library is already
# up-to-date (source file is not newer than the output).
#
# NOTE: When used as a pixi activation script, use 'return' not 'exit'
# so the sourcing shell is not terminated.
#
# Install layout (matches flare/tls/ffi/build.sh and ehsanmok/json):
#   1. Build into $BUILD_DIR/libflare_zlib.so (source-tree artifact).
#   2. Copy to $CONDA_PREFIX/lib/libflare_zlib.so — the CANONICAL location.
# Mojo's _find_flare_zlib_lib resolves via CONDA_PREFIX, so anything pixi
# launches finds it automatically without env-var indirection.
#
# LD_PRELOAD on Linux: keeps libflare_zlib.so mapped so ASAP-destroyed
# OwnedDLHandles in flare/http/encoding.mojo don't dlclose it under the
# JIT's feet. See the sibling flare/tls/ffi/build.sh for the full rationale.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../../../build"
TARGET="$BUILD_DIR/libflare_zlib.so"
INSTALLED="$CONDA_PREFIX/lib/libflare_zlib.so"
SOURCE="$SCRIPT_DIR/zlib_wrapper.c"

# Verify CONDA_PREFIX is set (pixi sets this on activation)
if [ -z "$CONDA_PREFIX" ]; then
    echo "Warning: CONDA_PREFIX not set. Skipping flare zlib FFI build."
    return 0 2>/dev/null || true
fi

# ── Idempotency check ────────────────────────────────────────────────────────
_needs_rebuild() {
    [ ! -f "$TARGET" ] && return 0
    [ ! -f "$INSTALLED" ] && return 0
    [ "$SOURCE" -nt "$TARGET" ] && return 0
    [ "$CONDA_PREFIX/lib/libz.so" -nt "$TARGET" ] 2>/dev/null && return 0
    [ "$CONDA_PREFIX/lib/libz.dylib" -nt "$TARGET" ] 2>/dev/null && return 0
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
echo "Building flare zlib FFI wrapper"
echo "========================================"
echo ""
echo "Using zlib from: $CONDA_PREFIX"
echo "  Headers: $CONDA_PREFIX/include/"
echo "  Library: $CONDA_PREFIX/lib/"
echo ""

# Verify zlib header is present
if [ ! -f "$CONDA_PREFIX/include/zlib.h" ]; then
    echo "Error: zlib.h not found at $CONDA_PREFIX/include/"
    echo "Run 'pixi install' to install dependencies."
    return 1 2>/dev/null || true
fi

mkdir -p "$BUILD_DIR"

# Use clang on macOS, gcc on Linux
if [[ "$(uname)" == "Darwin" ]]; then
    CC="clang"
else
    CC="gcc"
fi

echo "Building libflare_zlib.so..."

if $CC -O2 -fPIC -shared \
    -o "$TARGET" \
    "$SOURCE" \
    -I"$CONDA_PREFIX/include" \
    -L"$CONDA_PREFIX/lib" \
    -lz \
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

# ── Keep the library mapped on Linux (same reasoning as flare/tls/ffi/build.sh) ──
if [[ "$(uname)" != "Darwin" ]]; then
    export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${INSTALLED}"
fi
