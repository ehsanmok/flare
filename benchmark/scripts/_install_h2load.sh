#!/usr/bin/env bash
# benchmark/scripts/_install_h2load.sh
#
# Locate or install ``h2load`` (from nghttp2). v0.6 Track J uses it
# to drive the HTTP/2 throughput / latency benchmarks the way wrk2
# drives the HTTP/1.1 ones.
#
# Strategy (in order):
#   1. Prefer ``h2load`` from PATH (most CI images ship nghttp2).
#   2. Fall back to the system package manager (``apt install
#      nghttp2-client`` on Ubuntu, ``brew install nghttp2`` on
#      macOS) when the user explicitly opts in via FLARE_INSTALL_H2LOAD=1.
#   3. Otherwise emit a friendly diagnostic and exit non-zero so the
#      benchmark task fails fast rather than producing fake numbers.
#
# Output: prints the absolute path of the resolved binary on stdout
# (so callers can ``H2LOAD=$(./_install_h2load.sh)``).

set -euo pipefail

if command -v h2load >/dev/null 2>&1; then
    command -v h2load
    exit 0
fi

if [ "${FLARE_INSTALL_H2LOAD:-0}" = "1" ]; then
    case "$(uname -s)" in
        Linux*)
            if command -v apt-get >/dev/null 2>&1; then
                echo "[bench] installing nghttp2-client via apt-get..." >&2
                sudo apt-get update -qq && \
                    sudo apt-get install -y -qq nghttp2-client >&2
                command -v h2load
                exit 0
            fi
            ;;
        Darwin*)
            if command -v brew >/dev/null 2>&1; then
                echo "[bench] installing nghttp2 via Homebrew..." >&2
                brew install nghttp2 >&2
                command -v h2load
                exit 0
            fi
            ;;
    esac
fi

cat >&2 <<EOF
[bench] h2load not found on PATH.

  v0.6 Track J's HTTP/2 benchmarks need h2load (nghttp2). Install
  it on this host before running the h2 throughput task:

    Ubuntu / Debian:
        sudo apt-get install nghttp2-client

    macOS:
        brew install nghttp2

  Or set FLARE_INSTALL_H2LOAD=1 to let this script install it for you.
EOF
exit 1
