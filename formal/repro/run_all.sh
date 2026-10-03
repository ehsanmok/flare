#!/usr/bin/env bash
# Runs every Mojo repro for a Lean-found issue and prints its status.
#
# Contract for formal/repro/<ID>_<slug>.mojo:
#   * header comment line `# PLATFORM: any` | `linux` | `macos`
#   * optional `# SKIP: <reason>` (model-only issue, not reproducible here)
#   * prints a line starting with `BUG REPRODUCED:` and raises (exit != 0)
#     while the bug is present; prints `OK:` and exits 0 once fixed.
#
# Status:  OPEN   exit != 0 and the BUG REPRODUCED marker was printed
#          FIXED  exit == 0
#          ERROR  exit != 0 without the marker (compile error, crash, ...)
#          SKIP   wrong platform or `# SKIP:` header
# Exit code of this script: 0 iff no ERROR. (OPEN is the expected state on
# this branch: the repros document bugs, they do not fix them.)
#
# No `sort` here on purpose: under pixi it once blinded a conformance gate.
set -u
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
case "$(uname -s)" in Linux) plat=linux ;; Darwin) plat=macos ;; *) plat=other ;; esac
open=0; fixed=0; err=0; skip=0
printf '%-10s %-6s %-6s %s\n' ID STATUS PLAT FILE
for f in formal/repro/*.mojo; do
  [ -e "$f" ] || continue
  base="$(basename "$f" .mojo)"; id="${base%%_*}"
  want="$(grep -m1 '^# PLATFORM:' "$f" | awk '{print $3}')"; want="${want:-any}"
  reason="$(grep -m1 '^# SKIP:' "$f" | sed 's/^# SKIP: *//')"
  if [ -n "$reason" ] || { [ "$want" != any ] && [ "$want" != "$plat" ]; }; then
    printf '%-10s %-6s %-6s %s  (%s)\n' "$id" SKIP "$want" "$f" "${reason:-needs $want}"
    skip=$((skip+1)); continue
  fi
  log="$(mojo -I . "$f" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then st=FIXED; fixed=$((fixed+1))
  elif printf '%s' "$log" | grep -q '^BUG REPRODUCED:'; then st=OPEN; open=$((open+1))
  else st=ERROR; err=$((err+1)); printf '%s\n' "$log" | tail -20; fi
  printf '%-10s %-6s %-6s %s\n' "$id" "$st" "$want" "$f"
done
echo "open=$open fixed=$fixed error=$err skip=$skip"
[ $err -eq 0 ]
