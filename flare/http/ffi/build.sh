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
# The libraries are linked with ``-z nodelete`` on Linux, for the reason
# flare/tls/ffi/build.sh gives; they used to be pushed into LD_PRELOAD.
# A failed build removes the installed copy and says so on stderr.
#
# Each of the three libraries is checked on its own. The zlib check used
# to return from the script when zlib was up to date, so a change to
# brotli_wrapper.c or fs_wrapper.c was never rebuilt.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../../../build"
TARGET="$BUILD_DIR/libflare_zlib.so"
INSTALLED="$CONDA_PREFIX/lib/libflare_zlib.so"
SOURCE="$SCRIPT_DIR/zlib_wrapper.c"
BROTLI_TARGET="$BUILD_DIR/libflare_brotli.so"
BROTLI_INSTALLED="$CONDA_PREFIX/lib/libflare_brotli.so"
BROTLI_SOURCE="$SCRIPT_DIR/brotli_wrapper.c"

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

NODELETE=""
[[ "$(uname)" != "Darwin" ]] && NODELETE="-Wl,-z,nodelete"

# Use clang on macOS, gcc on Linux
if [[ "$(uname)" == "Darwin" ]]; then
    CC="clang"
else
    CC="gcc"
fi

if _needs_rebuild; then
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

echo "Building libflare_zlib.so..."

if $CC -O2 -fPIC -shared \
    -o "$TARGET" \
    "$SOURCE" \
    -I"$CONDA_PREFIX/include" \
    -L"$CONDA_PREFIX/lib" \
    -lz \
    $NODELETE \
    -Wl,-rpath,"$CONDA_PREFIX/lib"; then
    echo ""
    echo "Build complete!"
    echo "Library: $TARGET"
    ls -la "$TARGET"
else
    echo "ERROR: libflare_zlib.so failed to build; removed the stale copy" >&2
    rm -f "$TARGET" "$INSTALLED"
    return 1 2>/dev/null || true
fi

# ── Install to $CONDA_PREFIX/lib (canonical location) ────────────────────────
mkdir -p "$CONDA_PREFIX/lib"
cp "$TARGET" "$INSTALLED"
echo "Installed: $INSTALLED"
fi  # _needs_rebuild (zlib)

# ── flare brotli FFI wrapper ────────────────────────────────────────────────
# Build is conditional on libbrotli being present; flare's [dependencies]
# pull libbrotlicommon/dec/enc from conda-forge so the default env always
# satisfies it. If the encoder/decoder headers are missing we skip the
# build so users on bare-checkout environments can still import flare —
# Encoding.BR will then raise at first use rather than at activation.
_brotli_needs_rebuild() {
    [ ! -f "$BROTLI_TARGET" ] && return 0
    [ ! -f "$BROTLI_INSTALLED" ] && return 0
    [ "$BROTLI_SOURCE" -nt "$BROTLI_TARGET" ] && return 0
    [ "$BROTLI_TARGET" -nt "$BROTLI_INSTALLED" ] 2>/dev/null && return 0
    return 1
}

if [ -f "$CONDA_PREFIX/lib/libbrotlienc.so" ] \
    || [ -f "$CONDA_PREFIX/lib/libbrotlienc.dylib" ]; then
    if _brotli_needs_rebuild; then
        echo "Building libflare_brotli.so..."
        if $CC -O2 -fPIC -shared \
            -o "$BROTLI_TARGET" \
            "$BROTLI_SOURCE" \
            -L"$CONDA_PREFIX/lib" \
            -lbrotlienc -lbrotlidec -lbrotlicommon \
            $NODELETE \
            -Wl,-rpath,"$CONDA_PREFIX/lib"; then
            cp "$BROTLI_TARGET" "$BROTLI_INSTALLED"
            echo "Installed: $BROTLI_INSTALLED"
        else
            echo "ERROR: libflare_brotli.so failed to build; removed the stale copy (continuing without br)" >&2
            rm -f "$BROTLI_TARGET" "$BROTLI_INSTALLED"
        fi
    fi
else
    echo "libbrotli not installed — skipping libflare_brotli.so"
fi

# ── flare fs FFI wrapper ────────────────────────────────────────────────────
# Wraps libc open/close/read so flare's FileServer can avoid colliding
# with Mojo stdlib's internal external_call signatures for those names.
FS_TARGET="$BUILD_DIR/libflare_fs.so"
FS_INSTALLED="$CONDA_PREFIX/lib/libflare_fs.so"
FS_SOURCE="$SCRIPT_DIR/fs_wrapper.c"

_fs_needs_rebuild() {
    [ ! -f "$FS_TARGET" ] && return 0
    [ ! -f "$FS_INSTALLED" ] && return 0
    [ "$FS_SOURCE" -nt "$FS_TARGET" ] && return 0
    [ "$FS_TARGET" -nt "$FS_INSTALLED" ] 2>/dev/null && return 0
    return 1
}

if _fs_needs_rebuild; then
    echo "Building libflare_fs.so..."
    if $CC -O2 -fPIC -shared \
        -o "$FS_TARGET" \
        "$FS_SOURCE" \
        $NODELETE; then
        cp "$FS_TARGET" "$FS_INSTALLED"
        echo "Installed: $FS_INSTALLED"
    else
        echo "ERROR: libflare_fs.so failed to build; removed the stale copy" >&2
        rm -f "$FS_TARGET" "$FS_INSTALLED"
        return 1 2>/dev/null || true
    fi
fi
