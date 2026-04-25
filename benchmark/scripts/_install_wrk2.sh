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

# wrk2 builds with plain make. On macOS the system clang +
# libssl from Homebrew or the bench env's openssl provide what
# wrk2 needs.
echo "[bench] building wrk2 (this should take <1 minute)"
make clean >/dev/null 2>&1 || true
make -j

# wrk2's Makefile produces ./wrk (the binary), not ./wrk2.
# Rename so the harness can detect it.
if [ -x "./wrk" ] && [ ! -x "./wrk2" ]; then
    cp ./wrk ./wrk2
fi

echo "[bench] wrk2 built: $WRK2_DIR/wrk2"
