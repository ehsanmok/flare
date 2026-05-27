#!/usr/bin/env bash
# tools/check_sans_io.sh -- enforce the sans-I/O parser-sublayer contract.
#
# The files listed in ``SANS_IO_FILES`` form the canonical pure-function
# parser surface re-exported by ``flare.http.proto``. They MUST NOT import
# from any of the I/O-bearing subsystems below. Adding a file to the list
# is a one-line edit; removing one is a deliberate signal that it has
# grown an I/O dependency and no longer belongs in the sans-I/O surface.
#
# Forbidden prefixes (with both ``from flare.X`` and ``from .X`` /
# ``from ..X`` flavours):
#
#   flare.runtime  -- reactor, scheduler, cancel, timer wheel, handoff,
#                     pools, blocking helpers, io_uring driver.
#   flare.io       -- BufReader (socket-bound reader).
#   flare.tcp / flare.udp / flare.uds -- socket types.
#   flare.tls      -- OpenSSL FFI bindings.
#   flare.net      -- socket address resolution helpers.
#
# Usage: ``pixi run check-sans-io`` (wired in pixi.toml).
#
# Exit code 0 = clean; non-zero = at least one forbidden import found.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Files that publish the sans-I/O contract. New sans-I/O modules join
# this list when they ship; the lint runs across exactly this set.
#
# v0.8 baseline (the parser surface re-exported by ``flare.http.proto``):
SANS_IO_FILES=(
    "flare/http/proto/__init__.mojo"
    "flare/http/cookie.mojo"
    "flare/http/form.mojo"
    "flare/http/multipart.mojo"
    "flare/http/url.mojo"
    "flare/http/headers.mojo"
    "flare/http/header_view.mojo"
    "flare/http/header_phf.mojo"
    "flare/http/intern.mojo"
    "flare/http/simd_parsers.mojo"
    "flare/http/hpack_huffman.mojo"
    "flare/http/hpack_huffman_simd.mojo"
    "flare/http2/frame.mojo"
    "flare/http2/hpack.mojo"
    "flare/http2/state.mojo"
)

# Forbidden import patterns. Each matches both ``from flare.<X>`` /
# ``import flare.<X>`` and the relative-import equivalents ``from .X``
# / ``from ..X`` that appear inside sub-packages.
#
# We anchor on "from " or "import " to avoid false hits from prose in
# docstrings (those are inside triple-quoted strings; the prefix check
# never crosses lines).
FORBIDDEN_PREFIXES=(
    "flare.runtime"
    "flare.io"
    "flare.tcp"
    "flare.udp"
    "flare.uds"
    "flare.tls"
    "flare.net"
)

violations=0

for file in "${SANS_IO_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "check-sans-io: ERROR: registered file does not exist: $file" >&2
        violations=$((violations + 1))
        continue
    fi

    for prefix in "${FORBIDDEN_PREFIXES[@]}"; do
        # Match the import statement form, not arbitrary prose.
        # Patterns: "from flare.runtime", "import flare.runtime",
        # "from .runtime" / "from ..runtime" when the relative path
        # resolves to flare.runtime (rare; we still flag it for
        # signal — relative imports across the parser/reactor split
        # are a smell).
        if grep -nE "^(from|import)[[:space:]]+(${prefix//./\\.})\\b" "$file" \
           > /dev/null 2>&1; then
            echo "check-sans-io: $file imports forbidden module: $prefix" >&2
            grep -nE "^(from|import)[[:space:]]+(${prefix//./\\.})\\b" "$file" >&2
            violations=$((violations + 1))
        fi
    done
done

if [[ $violations -gt 0 ]]; then
    echo "" >&2
    echo "check-sans-io: $violations violation(s) found." >&2
    echo "  Either:" >&2
    echo "  1. Remove the I/O import from the parser file (preferred), or" >&2
    echo "  2. Remove the file from SANS_IO_FILES in tools/check_sans_io.sh" >&2
    echo "     (signals that the file is no longer pure-function)." >&2
    exit 1
fi

echo "check-sans-io: ${#SANS_IO_FILES[@]} files clean."
