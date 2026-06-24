#!/bin/bash
# Build the rustls QUIC FFI cdylib for flare.
# Uses the Rust toolchain installed via pixi (conda-forge `rust` package
# in feature.dev / feature.bench / feature.fuzz; the host `~/.cargo/bin/cargo`
# in the default env if rust is not declared there).
#
# This script is idempotent -- cargo's own incremental build skips
# unchanged sources, and the install copy uses `cp -u` so the
# CONDA_PREFIX copy is only touched when the source-tree artifact
# is strictly newer.
#
# NOTE: When used as a pixi activation script, use 'return' not 'exit'
# so the sourcing shell is not terminated.
#
# Install layout (matches flare/tls/ffi/build.sh):
#   1. Build into $CARGO_OUTPUT (cargo's native path under target/release).
#   2. Copy to $BUILD_DIR/libflare_rustls_quic.so (source-tree artifact).
#   3. Copy to $CONDA_PREFIX/lib/libflare_rustls_quic.so -- the CANONICAL
#      location flare.utils.dylib.find_flare_lib("rustls_quic") resolves.
#
# Why also LD_PRELOAD on Linux (same .so path as the install)?
#   Mojo's OwnedDLHandle dlopens the rustls .so. flare's FFI surfaces
#   route every call through `read lib: OwnedDLHandle` borrow helpers
#   so dlclose cannot fire between get_function and the call. The
#   LD_PRELOAD here pins the .so refcount above zero as belt-and-suspenders
#   defense: a hypothetical regression to the naive pattern (e.g. a new
#   FFI call site that forgets the borrow helper) still can't unmap the
#   library mid-call. Same .so path that Mojo dlopens (both resolve to
#   $INSTALLED), so there is exactly one mapping in the process -- no
#   "two copies, one unmapped" hazard.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPPER_DIR="$SCRIPT_DIR/rustls_wrapper"
BUILD_DIR="$SCRIPT_DIR/../../../build"
TARGET="$BUILD_DIR/libflare_rustls_quic.so"
INSTALLED="$CONDA_PREFIX/lib/libflare_rustls_quic.so"
# cargo names the cdylib per the host platform: libflare_rustls_quic.so on
# Linux, libflare_rustls_quic.dylib on macOS. The installed/canonical name
# stays .so on both (find_flare_lib resolves .so everywhere, and macOS dyld
# loads a Mach-O dylib regardless of the file extension), so only the cargo
# source path is platform-dependent.
if [[ "$(uname)" == "Darwin" ]]; then
    CARGO_OUTPUT="$WRAPPER_DIR/target/release/libflare_rustls_quic.dylib"
else
    CARGO_OUTPUT="$WRAPPER_DIR/target/release/libflare_rustls_quic.so"
fi
CARGO_TOML="$WRAPPER_DIR/Cargo.toml"
CARGO_LOCK="$WRAPPER_DIR/Cargo.lock"
SOURCE="$WRAPPER_DIR/src/lib.rs"

# Verify CONDA_PREFIX is set (pixi sets this on activation)
if [ -z "$CONDA_PREFIX" ]; then
    echo "Warning: CONDA_PREFIX not set. Skipping flare rustls QUIC FFI build."
    return 0 2>/dev/null || true
fi

# Skip silently if cargo isn't on PATH. The default env (without the
# rust conda package) relies on the contributor's host cargo, which
# may or may not be installed; if it isn't, we leave the .so unbuilt
# and the Mojo-side find_flare_lib("rustls_quic") raises a clear
# "run pixi -e dev install" message rather than failing activation.
if ! command -v cargo >/dev/null 2>&1; then
    return 0 2>/dev/null || true
fi

# ── Idempotency check (cargo handles the inner one) ──────────────────────────
_needs_rebuild() {
    [ ! -f "$CARGO_OUTPUT" ] && return 0
    [ ! -f "$TARGET" ] && return 0
    [ ! -f "$INSTALLED" ] && return 0
    [ "$SOURCE" -nt "$CARGO_OUTPUT" ] && return 0
    [ "$CARGO_TOML" -nt "$CARGO_OUTPUT" ] && return 0
    [ "$CARGO_LOCK" -nt "$CARGO_OUTPUT" ] && return 0
    [ "$CARGO_OUTPUT" -nt "$INSTALLED" ] && return 0
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
echo "Building flare rustls QUIC FFI cdylib"
echo "========================================"
echo ""

# Run cargo from the wrapper dir so target/ lands next to Cargo.toml.
# `--locked` requires Cargo.lock to be exactly what's tracked in-tree,
# pinning the rustls + ring + dependency graph for reproducibility.
if ! ( cd "$WRAPPER_DIR" && cargo build --release --locked ); then
    echo "Build failed!"
    return 1 2>/dev/null || true
fi

# ── Install to both build/ and $CONDA_PREFIX/lib (canonical location) ────────
mkdir -p "$BUILD_DIR"
cp -f "$CARGO_OUTPUT" "$TARGET"
echo "Built: $TARGET"
ls -la "$TARGET"

mkdir -p "$CONDA_PREFIX/lib"
# Atomic install: copy to a temp then rename over $INSTALLED. A plain
# `cp -f` overwrites the file in place, which corrupts the running
# image whenever $INSTALLED is the LD_PRELOADed path (this script
# exports it below) -- the loader's mapped pages get truncated and any
# process holding the mapping (including cp itself) takes a SIGSEGV.
# rename() swaps the directory entry to a fresh inode and leaves the
# old mapped inode intact, so in-flight mappings stay valid.
cp -f "$TARGET" "$INSTALLED.tmp.$$"
mv -f "$INSTALLED.tmp.$$" "$INSTALLED"
echo "Installed: $INSTALLED"

# ── Keep the library mapped on Linux so ASAP-destroyed OwnedDLHandles ────────
# don't tear it down under the JIT's feet (see the long comment at the top
# of this file). Always LD_PRELOAD the same path Mojo dlopens: $INSTALLED.
if [[ "$(uname)" != "Darwin" ]]; then
    export LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${INSTALLED}"
fi
