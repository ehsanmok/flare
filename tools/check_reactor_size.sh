#!/usr/bin/env bash
# tools/check_reactor_size.sh -- enforce file-size discipline across the
# library, with a tight bar on the reactor sub-packages and a looser
# regression bar on the rest.
#
# Two passes run:
#
#   Pass A (600 lines): ``flare/http/_reactor`` + ``flare/http/_server``.
#     After the v0.8 reactor decomposition every file in these
#     sub-packages should fit in a reviewer's working memory; anything
#     bigger means the next refactor missed a natural seam and the
#     duplication / divergence pressure the decomposition undid is
#     creeping back.
#
#   Pass B (1000 lines): ``flare/quic`` ``flare/runtime`` ``flare/net``
#     ``flare/http2`` ``flare/http``. The v0.8 §1 structural-debt pass
#     brought every oversized module under 1000 lines (or onto the
#     allowlist); this pass guards against regressions.
#
# Usage: ``pixi run check-reactor-size`` (wired in pixi.toml).
#
# Thresholds:
#   FLARE_REACTOR_MAX_LINES (Pass A; default 600).
#   Pass B is fixed at 1000.
#
# ALLOWLIST policy (both passes):
#   Files in an allowlist are tracked + reported but do not fail the
#   lint. Every entry MUST carry a dated ``# TODO(YYYY-MM-DD ...)``
#   comment in the allowlisted source file referencing the planned
#   decomposition; the lint checks for the marker and promotes an
#   undated entry back to a hard violation. An entry leaves the list by
#   being split below the threshold. Allowlisted today: the monolith
#   structs Mojo cannot split across files (``HttpServer``,
#   ``QuicListener``) plus the in-flight ``conn_handle`` split.
#
# Exit code 0 = clean (every file under its threshold or on the matching
# allowlist), non-zero = at least one file is over threshold and not
# allowlisted.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Pass A: tight bar on the reactor / server sub-packages.
pass_a_threshold="${FLARE_REACTOR_MAX_LINES:-600}"
pass_a_dirs=(
    "flare/http/_reactor"
    "flare/http/_server"
)
pass_a_allowlist=(
    "flare/http/_reactor/conn_handle.mojo"
)

# Pass B: regression bar across the broader library.
pass_b_threshold=1000
pass_b_dirs=(
    "flare/quic"
    "flare/runtime"
    "flare/net"
    "flare/http2"
    "flare/http"
)
pass_b_allowlist=(
    "flare/quic/server.mojo"
    "flare/http/server.mojo"
    "flare/http/client.mojo"
    "flare/quic/client.mojo"
    "flare/http2/client.mojo"
)

total_violations=0
total_allowlisted=0
total_clean=0

# run_pass THRESHOLD DIRS_ARRAY_NAME ALLOWLIST_ARRAY_NAME
#
# Uses bash namerefs (declare -n) to receive the dir + allowlist arrays
# by name so the two passes share one implementation.
run_pass() {
    local threshold="$1"
    local -n dirs_ref="$2"
    local -n allow_ref="$3"

    local scan_dir
    for scan_dir in "${dirs_ref[@]}"; do
        if [[ ! -d "$scan_dir" ]]; then
            echo "check-reactor-size: ERROR: $scan_dir not found" >&2
            exit 2
        fi
    done

    local file lines entry is_allowlisted
    while IFS= read -r -d '' file; do
        lines=$(wc -l < "$file")
        if (( lines > threshold )); then
            is_allowlisted=0
            for entry in "${allow_ref[@]}"; do
                if [[ "$file" == "$entry" ]]; then
                    is_allowlisted=1
                    break
                fi
            done
            if (( is_allowlisted == 1 )); then
                if grep -E "^[[:space:]]*#.*TODO\([0-9]{4}-[0-9]{2}-[0-9]{2}" "$file" \
                   > /dev/null 2>&1; then
                    echo "check-reactor-size: ALLOWLISTED: $file ($lines lines, threshold $threshold)" >&2
                    total_allowlisted=$((total_allowlisted + 1))
                else
                    echo "check-reactor-size: VIOLATION: $file is allowlisted but has no dated '# TODO(YYYY-MM-DD ...)' marker" >&2
                    total_violations=$((total_violations + 1))
                fi
            else
                echo "check-reactor-size: VIOLATION: $file ($lines lines > $threshold)" >&2
                total_violations=$((total_violations + 1))
            fi
        else
            total_clean=$((total_clean + 1))
        fi
    done < <(find "${dirs_ref[@]}" -name '*.mojo' -print0)
}

run_pass "$pass_a_threshold" pass_a_dirs pass_a_allowlist
run_pass "$pass_b_threshold" pass_b_dirs pass_b_allowlist

total=$((total_clean + total_allowlisted + total_violations))

if (( total_violations > 0 )); then
    echo "" >&2
    echo "check-reactor-size: $total_violations violation(s) found." >&2
    echo "  Either:" >&2
    echo "  1. Split the offending file under its threshold (the" >&2
    echo "     preferred fix; restores the v0.8 decomposition gain), or" >&2
    echo "  2. Add the file to the matching allowlist in" >&2
    echo "     tools/check_reactor_size.sh with a dated" >&2
    echo "     '# TODO(YYYY-MM-DD ...)' split comment in the source file" >&2
    echo "     (only when a split is blocked, e.g. a Mojo struct that" >&2
    echo "     cannot span files)." >&2
    exit 1
fi

echo "check-reactor-size: $total_clean file(s) under threshold," \
     "$total_allowlisted allowlisted, $total total."
