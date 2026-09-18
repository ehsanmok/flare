#!/usr/bin/env bash
# tests/tools/install_h2spec.sh
#
# Fetch h2spec (RFC 9113 / RFC 7541 server conformance suite) at a
# pinned release. Mirrors benchmark/scripts/_install_wrk2.sh: the
# binary lands in build/ so both the local harness and CI find it at a
# fixed path, and the version is pinned so a conformance result means
# the same thing across machines.
#
# Output: $H2SPEC_DIR/h2spec. tests/tools/run_conformance.sh looks there
# first, then falls back to an h2spec already on PATH.
#
# Prebuilt release rather than `go install`: h2spec's module path has
# no /v2 suffix, so `go install ...@v2.x` is rejected outright, and the
# tarball needs no toolchain at all.
#
# Run as: pixi run install-h2spec

set -euo pipefail

# Pinned. Bump deliberately -- a new suite version can add cases and
# turn a green run red for reasons unrelated to any flare change.
H2SPEC_VERSION="${H2SPEC_VERSION:-v2.6.0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
H2SPEC_DIR="${H2SPEC_DIR:-${REPO_ROOT}/build/h2spec}"

mkdir -p "$H2SPEC_DIR"

if [ -x "$H2SPEC_DIR/h2spec" ]; then
    echo "[conformance] h2spec already present at $H2SPEC_DIR/h2spec"
    exit 0
fi

case "$(uname -s)" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *)      echo "[conformance] unsupported OS $(uname -s)" >&2; exit 1 ;;
esac

# Upstream publishes amd64 only. On arm64 macOS this runs under
# Rosetta; fail loudly rather than install a binary that cannot exec.
case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    *)
        echo "[conformance] h2spec publishes amd64 builds only;" >&2
        echo "              $(uname -m) is unsupported. Build from source" >&2
        echo "              and set H2SPEC_BIN to point at it." >&2
        exit 1
        ;;
esac

URL="https://github.com/summerwind/h2spec/releases/download/${H2SPEC_VERSION}/h2spec_${OS}_${ARCH}.tar.gz"

echo "[conformance] fetching h2spec ${H2SPEC_VERSION} (${OS}/${ARCH})"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! curl -fsSL "$URL" -o "$TMP/h2spec.tar.gz"; then
    echo "[conformance] download failed: $URL" >&2
    exit 1
fi

tar -xzf "$TMP/h2spec.tar.gz" -C "$TMP"
if [ ! -f "$TMP/h2spec" ]; then
    echo "[conformance] tarball did not contain an h2spec binary" >&2
    exit 1
fi

install -m 0755 "$TMP/h2spec" "$H2SPEC_DIR/h2spec"
echo "[conformance] h2spec installed: $H2SPEC_DIR/h2spec"
"$H2SPEC_DIR/h2spec" --version 2>&1 | head -1 || true
