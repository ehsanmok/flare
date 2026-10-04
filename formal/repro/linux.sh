#!/usr/bin/env bash
# Run Linux-only repros in a persistent Linux container (native architecture).
#
#   formal/repro/linux.sh formal/repro/<file>.mojo   # run one repro
#   formal/repro/linux.sh --exec '<shell command>'    # run in the container's repo copy
#   FLARE_LINUX_NOSYNC=1 formal/repro/linux.sh ...    # keep the copy as is (flip checks)
#
# The container keeps its own copy of the repo at /work/flare (with its own
# .pixi), refreshed from the host tree before each run unless
# FLARE_LINUX_NOSYNC=1. Do flip checks in that copy (--exec 'cd ... && edit'),
# never in the host's flare/; the next synced run restores it.
# seccomp is unconfined because Docker's default profile blocks io_uring.
set -euo pipefail
here="$(cd "$(dirname "$0")/../.." && pwd)"
name="${FLARE_LINUX_CONTAINER:-flare-formal-linux}"
image="${FLARE_LINUX_IMAGE:-ubuntu:24.04}"
# Native architecture: io_uring is unavailable under x86_64 emulation.
case "$(uname -m)" in arm64|aarch64) platform=linux/arm64 ;; *) platform=linux/amd64 ;; esac
# The current Docker context (Docker Desktop, ...); OrbStack if that daemon is
# down. FLARE_LINUX_CONTEXT forces one.
ctx=()
if [ -n "${FLARE_LINUX_CONTEXT:-}" ]; then ctx=(--context "$FLARE_LINUX_CONTEXT")
elif ! docker info >/dev/null 2>&1 && docker --context orbstack info >/dev/null 2>&1; then
  ctx=(--context orbstack)
fi
d() { docker ${ctx[@]+"${ctx[@]}"} "$@"; }

if ! d inspect "$name" >/dev/null 2>&1; then
  d run -d --name "$name" --platform "$platform" --security-opt seccomp=unconfined \
    -v "$here":/host:ro "$image" sleep infinity >/dev/null
  d exec "$name" bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl ca-certificates rsync git build-essential >/dev/null
    curl -fsSL https://pixi.sh/install.sh | bash >/dev/null
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
    mkdir -p /work/flare'
elif [ "$(d inspect -f '{{.State.Running}}' "$name")" != true ]; then
  d start "$name" >/dev/null
fi

if [ "${FLARE_LINUX_NOSYNC:-0}" != 1 ]; then
  d exec "$name" rsync -a --delete --exclude=/.pixi --exclude=/formal/.lake \
    --exclude=/.git /host/ /work/flare/
fi
# The rustls QUIC library the QUIC/H3 repros dlopen. Activation skips it when
# cargo is not on PATH, so build it once into the (unsynced) pixi env.
d exec -w /work/flare "$name" bash -lc '
  export PATH=$HOME/.pixi/bin:$HOME/.cargo/bin:$PATH
  [ -f .pixi/envs/default/lib/libflare_rustls_quic.so ] ||
    pixi run -e default bash -c "source flare/tls/ffi/build_rustls.sh" >&2'

if [ "${1:-}" = --exec ]; then
  shift
  exec docker ${ctx[@]+"${ctx[@]}"} exec -i -w /work/flare "$name" bash -lc "export PATH=\$HOME/.pixi/bin:\$PATH; $*"
fi
[ $# -eq 1 ] || { echo "usage: $0 formal/repro/<file>.mojo | --exec '<cmd>'" >&2; exit 2; }
exec docker ${ctx[@]+"${ctx[@]}"} exec -i -w /work/flare "$name" bash -lc \
  "export PATH=\$HOME/.pixi/bin:\$PATH; pixi run mojo -I . '$1'"
