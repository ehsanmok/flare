#!/usr/bin/env bash
# tools/check_reactor_size.sh -- enforce file-size discipline in the
# reactor sub-package.
#
# After the v0.8 reactor decomposition (commits 1-4 of the v0.8
# blast plan), every file under ``flare/http/_reactor/`` should fit
# in a reviewer's working memory. The bar is **600 lines per file**:
# anything bigger means the next refactor missed a natural seam,
# and the duplication / divergence pressure that the decomposition
# pass undid is creeping back. The lint guards the gain.
#
# Usage: ``pixi run check-reactor-size`` (wired in pixi.toml).
#
# Threshold:
#   FLARE_REACTOR_MAX_LINES (default 600).
#
# Allowlist:
#   Files in ``ALLOWLIST`` are tracked + reported but do not fail the
#   lint. The allowlist is meant to **shrink to empty** as
#   decomposition work lands; a file leaves the allowlist by being
#   split.
#
# ALLOWLIST policy:
#   Every entry MUST come with:
#     1. A dated ``# TODO(YYYY-MM-DD)`` comment in the allowlisted
#        source file referencing the planned decomposition. The lint
#        checks for the marker and refuses to honour an undated
#        entry.
#     2. A deadline (next minor version cycle) by which the entry
#        must clear. The dated TODO doubles as the deadline anchor;
#        when the date passes, the next sweep removes the entry
#        unconditionally and the lint starts failing the file.
#   Entries without a dated TODO are removed at the next sweep.
#
# Exit code 0 = clean (every file under threshold or on the
# allowlist), non-zero = at least one file is over threshold and not
# allowlisted.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

threshold="${FLARE_REACTOR_MAX_LINES:-600}"

# Files that exceed the threshold today but have a documented split
# plan attached. Each entry is a path relative to the repo root.
# The CI lint reports allowlisted offenders so the pressure to split
# stays visible; a file leaves this list by being decomposed below
# the threshold (and the lint then enforces the bar on the result).
ALLOWLIST=(
    "flare/http/_reactor/conn_handle.mojo"
)

# Directories whose every .mojo file must fit the budget. The set
# grows as decomposition lands: ``_reactor`` was the original v0.8
# split; ``_server`` holds the request-parser / response-writer
# helpers peeled out of the oversized ``flare/http/server.mojo``.
scan_dirs=(
    "flare/http/_reactor"
    "flare/http/_server"
)
for scan_dir in "${scan_dirs[@]}"; do
    if [[ ! -d "$scan_dir" ]]; then
        echo "check-reactor-size: ERROR: $scan_dir not found" >&2
        exit 2
    fi
done

violations=0
allowlisted=0
clean=0

while IFS= read -r -d '' file; do
    lines=$(wc -l < "$file")
    if (( lines > threshold )); then
        is_allowlisted=0
        for entry in "${ALLOWLIST[@]}"; do
            if [[ "$file" == "$entry" ]]; then
                is_allowlisted=1
                break
            fi
        done
        if (( is_allowlisted == 1 )); then
            # ALLOWLIST hygiene: every allowlisted file MUST carry a
            # dated ``# TODO(YYYY-MM-DD ...)`` marker pointing at the
            # planned decomposition. Undated TODOs (or no TODO at all)
            # promote the file back to a hard violation so the entry
            # cannot live in the list silently.
            if grep -E "^[[:space:]]*#.*TODO\([0-9]{4}-[0-9]{2}-[0-9]{2}" "$file" \
               > /dev/null 2>&1; then
                echo "check-reactor-size: ALLOWLISTED: $file ($lines lines, threshold $threshold)" >&2
                allowlisted=$((allowlisted + 1))
            else
                echo "check-reactor-size: VIOLATION: $file is allowlisted but has no dated '# TODO(YYYY-MM-DD ...)' marker" >&2
                violations=$((violations + 1))
            fi
        else
            echo "check-reactor-size: VIOLATION: $file ($lines lines > $threshold)" >&2
            violations=$((violations + 1))
        fi
    else
        clean=$((clean + 1))
    fi
done < <(find "${scan_dirs[@]}" -name '*.mojo' -print0)

total=$((clean + allowlisted + violations))

if (( violations > 0 )); then
    echo "" >&2
    echo "check-reactor-size: $violations violation(s) found." >&2
    echo "  Either:" >&2
    echo "  1. Split the offending file into < $threshold-line modules" >&2
    echo "     (the preferred fix; restores the v0.8 decomposition" >&2
    echo "     gain), or" >&2
    echo "  2. Add the file to ALLOWLIST in tools/check_reactor_size.sh" >&2
    echo "     with a TODO(track-N) split comment in the source file" >&2
    echo "     (only when a split is in flight)." >&2
    exit 1
fi

echo "check-reactor-size: $clean file(s) under threshold ($threshold lines)," \
     "$allowlisted allowlisted, $total total."
