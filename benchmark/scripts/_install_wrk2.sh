#!/usr/bin/env bash
# benchmark/scripts/_install_wrk2.sh
#
# Build wrk2 from a pinned commit. Used by the bench harness when
# the platform-pinned conda-forge package isn't available
# (linux-64 has no pinned wrk2 build as of this commit; macOS has
# wrk2 in Homebrew but the bench env needs the same pinned
# version across machines for reproducible numbers).
#
# Output: $WRK2_DIR/wrk2 binary. Caller adds it to PATH.
#
# Pinned commit chosen for stability: latest tag at the time of
# the v0.5.0 Step 2 commit. Update this when wrk2 publishes a
# new release.

set -euo pipefail

# Pinned commit — wrk2's last release is from 2019 (44a94c1
# "Add support for higher concurrency"). Pin to that.
WRK2_COMMIT="${WRK2_COMMIT:-44a94c17d8e6a0bac8559b53da76848e430cb7a7}"
WRK2_REPO="${WRK2_REPO:-https://github.com/giltene/wrk2.git}"

# Target dir: prefer the bench env's bin/, fall back to a local
# build dir.
WRK2_DIR="${WRK2_DIR:-$(pwd)/build/wrk2}"

mkdir -p "$WRK2_DIR"
cd "$WRK2_DIR"

if [ -x "./wrk2" ]; then
    echo "[bench] wrk2 already built at $WRK2_DIR/wrk2"
    exit 0
fi

if [ ! -d ".git" ]; then
    echo "[bench] cloning wrk2 ${WRK2_COMMIT}"
    git clone "$WRK2_REPO" .
    git checkout "$WRK2_COMMIT"
fi

# wrk2's vendored LuaJIT emits a ``bytecode.o`` ELF that newer
# binutils (the gcc-15.2 / binutils-2.45 stack the bench env's
# conda packages pull in) treats as corrupt and refuse to link.
# The system gcc on Ubuntu 22.04 (gcc 11.4 + binutils 2.38) builds
# wrk2 cleanly. Prefer the system toolchain when it can find
# openssl + zlib headers; fall back to conda-env paths only if
# the host doesn't ship the dev headers.
USE_SYSTEM_GCC="no"
if [ -x /usr/bin/cc ] \
    && [ -f /usr/include/openssl/ssl.h ] \
    && [ -f /usr/include/zlib.h ]; then
    USE_SYSTEM_GCC="yes"
    echo "[bench] using system gcc + openssl + zlib for wrk2 build"
    # Make sure the Makefile sees the system compiler even when
    # this script is invoked through ``pixi run`` (which puts the
    # conda gcc on PATH first).
    export CC=/usr/bin/cc
fi

if [ "$USE_SYSTEM_GCC" = "no" ]; then
    PREFIX="${CONDA_PREFIX:-}"
    if [ -n "$PREFIX" ] && [ -d "$PREFIX/include" ]; then
        if ! grep -q "# flare-bench-env-injected" Makefile; then
            echo "[bench] patching Makefile for openssl + zlib from CONDA_PREFIX=$PREFIX"
            python3 - "$PREFIX" <<'PY'
import sys, pathlib
prefix = sys.argv[1]
mk = pathlib.Path("Makefile")
text = mk.read_text()
inject = (
    "# flare-bench-env-injected: pick up openssl + zlib from the\n"
    "# bench env's CONDA_PREFIX (added by benchmark/scripts/_install_wrk2.sh).\n"
    f"CFLAGS  += -I{prefix}/include\n"
    f"LDFLAGS += -L{prefix}/lib -Wl,-rpath,{prefix}/lib\n"
    "\n"
)
needle = "SRC  := wrk.c"
assert needle in text, "wrk2 Makefile shape changed; update the patch"
text = text.replace(needle, inject + needle, 1)
mk.write_text(text)
PY
        fi
    fi
fi

echo "[bench] building wrk2 (this should take <1 minute)"
make clean >/dev/null 2>&1 || true
make -j

# wrk2's Makefile produces ./wrk (the binary), not ./wrk2.
# Rename so the harness can detect it.
if [ -x "./wrk" ] && [ ! -x "./wrk2" ]; then
    cp ./wrk ./wrk2
fi

echo "[bench] wrk2 built: $WRK2_DIR/wrk2"
