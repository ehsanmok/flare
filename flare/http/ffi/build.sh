#!/bin/bash
# Build the zlib wrapper shared library for flare HTTP encoding.
# Uses zlib installed via pixi (conda-forge).
#
# This script is idempotent - skips the rebuild if the library is already
# up-to-date (source file is not newer than the output).
#
# NOTE: When used as a pixi activation script, use 'return' not 'exit'
# so the sourcing shell is not terminated.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../../../build"
TARGET="$BUILD_DIR/libflare_zlib.so"
SOURCE="$SCRIPT_DIR/zlib_wrapper.c"

# Verify CONDA_PREFIX is set (pixi sets this on activation)
if [ -z "$CONDA_PREFIX" ]; then
    echo "Warning: CONDA_PREFIX not set. Skipping flare zlib FFI build."
    return 0 2>/dev/null || true
fi

# ── Idempotency check ────────────────────────────────────────────────────────
_needs_rebuild() {
    [ ! -f "$TARGET" ] && return 0
    [ "$SOURCE" -nt "$TARGET" ] && return 0
    [ "$CONDA_PREFIX/lib/libz.so" -nt "$TARGET" ] 2>/dev/null && return 0
    [ "$CONDA_PREFIX/lib/libz.dylib" -nt "$TARGET" ] 2>/dev/null && return 0
    return 1
}

if ! _needs_rebuild; then
    export FLARE_ZLIB_LIB="$TARGET"
    if [[ "$(uname)" != "Darwin" ]]; then
        export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${TARGET}"
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

export FLARE_ZLIB_LIB="$TARGET"

# ── Preload on Linux so Mojo's JIT can call into the library ──────────────────
# Mojo's LLVM JIT crashes on Linux when calling functions obtained via
# OwnedDLHandle.get_function() into a freshly-dlopen'd shared library.
# Pre-mapping the library at process startup (via LD_PRELOAD) avoids this:
# the code pages are already present before the JIT runs, so indirect calls
# through function pointers work correctly.  macOS does not have this issue.
if [[ "$(uname)" != "Darwin" ]]; then
    export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${TARGET}"
fi
