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
#
# FORMAL_REPRO_LINUX (macOS hosts): `auto` (default) runs `# PLATFORM: linux`
# repros in a Linux container through repro/linux.sh when docker is usable;
# `all` also runs the `any` repros there (rows tagged `linux*`); `off` skips.
case "$(uname -s)" in Linux) plat=linux ;; Darwin) plat=macos ;; *) plat=other ;; esac
mode="${FORMAL_REPRO_LINUX:-auto}"
use_linux=0
if [ "$plat" = macos ] && [ "$mode" != off ] && command -v docker >/dev/null \
   && docker info >/dev/null 2>&1; then use_linux=1; fi
if [ "$plat" = macos ] && [ "$use_linux" = 0 ] && [ "$mode" != off ] && command -v docker >/dev/null \
   && docker --context orbstack info >/dev/null 2>&1; then use_linux=1; fi
open=0; fixed=0; err=0; skip=0
printf '%-10s %-6s %-6s %s\n' ID STATUS PLAT FILE
synced=0
# FORMAL_REPRO_TIMEOUT: seconds before a hung repro is killed (an ERROR row).
limit="${FORMAL_REPRO_TIMEOUT:-600}"
capped() { perl -e 'alarm shift; exec @ARGV or die "exec: $!"' "$limit" "$@"; }
run_one() {  # $1 file, $2 where (host|linux); sets log, rc
  if [ "$2" = linux ]; then
    log="$(FLARE_LINUX_NOSYNC=$synced capped bash formal/repro/linux.sh "$1" 2>&1)"; rc=$?; synced=1
  else
    log="$(capped mojo -I . "$1" 2>&1)"; rc=$?
  fi
}
classify() {  # $1 id, $2 plat label, $3 file
  if [ $rc -eq 0 ]; then st=FIXED; fixed=$((fixed+1))
  elif printf '%s' "$log" | grep -q '^BUG REPRODUCED:'; then st=OPEN; open=$((open+1))
  else st=ERROR; err=$((err+1)); printf '%s\n' "$log" | tail -20; fi
  printf '%-10s %-6s %-6s %s\n' "$1" "$st" "$2" "$3"
}
for f in formal/repro/*.mojo; do
  [ -e "$f" ] || continue
  base="$(basename "$f" .mojo)"; id="${base%%_*}"
  want="$(grep -m1 '^# PLATFORM:' "$f" | awk '{print $3}')"; want="${want:-any}"
  reason="$(grep -m1 '^# SKIP:' "$f" | sed 's/^# SKIP: *//')"
  if [ -z "$reason" ] && [ "$want" = linux ] && [ "$use_linux" = 1 ]; then
    run_one "$f" linux; classify "$id" linux "$f"; continue
  fi
  if [ -n "$reason" ] || { [ "$want" != any ] && [ "$want" != "$plat" ]; }; then
    printf '%-10s %-6s %-6s %s  (%s)\n' "$id" SKIP "$want" "$f" "${reason:-needs $want}"
    skip=$((skip+1)); continue
  fi
  if [ "$want" = any ] && [ "$use_linux" = 1 ] && [ "$mode" = all ]; then
    run_one "$f" linux; classify "$id" "linux*" "$f"
  fi
  run_one "$f" host
  classify "$id" "$want" "$f"
done
echo "open=$open fixed=$fixed error=$err skip=$skip"
[ $err -eq 0 ]
