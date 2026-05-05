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
# LD_PRELOAD on Linux: belt-and-suspenders defense for the
# OwnedDLHandle / ASAP-destruction class of bug. The Mojo-side fix —
# routing every FFI call through a ``_do_*(read lib: OwnedDLHandle, ...)``
# borrow helper — is now applied at every call site (see
# flare/http/encoding.mojo, flare/http/middleware.mojo, flare/http/fs.mojo,
# flare/tls/stream.mojo, flare/tls/_server_ffi.mojo, flare/ws/{client,server}.mojo,
# flare/crypto/hmac.mojo, flare/net/{socket,_libc}.mojo, flare/tcp/stream.mojo).
# LD_PRELOAD pins the .so refcount above zero so even a hypothetical
# regression to the naive pattern cannot dlclose the library mid-call.
# See the sibling flare/tls/ffi/build.sh for the full rationale.

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

_install_preloads() {
    # Add every flare-built FFI shim into LD_PRELOAD on Linux so that
    # ASAP-destroyed OwnedDLHandles don't dlclose them under the JIT.
    if [[ "$(uname)" == "Darwin" ]]; then
        return 0
    fi
    [ -f "$INSTALLED" ] && export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${INSTALLED}"
    [ -f "$BROTLI_INSTALLED" ] && export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${BROTLI_INSTALLED}"
    [ -f "$CONDA_PREFIX/lib/libflare_fs.so" ] && export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${CONDA_PREFIX}/lib/libflare_fs.so"
}

if ! _needs_rebuild; then
    _install_preloads
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

# ── flare brotli FFI wrapper (v0.6 Track I) ─────────────────────────────────
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
            -Wl,-rpath,"$CONDA_PREFIX/lib"; then
            cp "$BROTLI_TARGET" "$BROTLI_INSTALLED"
            echo "Installed: $BROTLI_INSTALLED"
        else
            echo "Brotli build failed (continuing without br codec)"
        fi
    fi
else
    echo "libbrotli not installed — skipping libflare_brotli.so"
fi

# ── flare fs FFI wrapper (v0.6 Track H) ─────────────────────────────────
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
        "$FS_SOURCE"; then
        cp "$FS_TARGET" "$FS_INSTALLED"
        echo "Installed: $FS_INSTALLED"
    else
        echo "fs wrapper build failed!"
        return 1 2>/dev/null || true
    fi
fi

_install_preloads
