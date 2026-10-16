#!/usr/bin/env python3
"""One-screen status of the Lean verification factory.

    status.py [--json]

Sections:
  anchors      fidelity anchors by tier and state (ok / stale / missing)
  spec guard   locked entries and anything changed, removed or not yet locked
  difftest     oracle targets, the last run (formal/.lake/difftest/last.json),
               regression corpus size
  obligations  verified kernels (formal/obligations/*.toml): status, whether
               their specs are locked, whether their anchors are fresh, and
               their last difftest result

Read-only and fast (no Lean build, no Mojo run).
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
FORMAL = HERE.parent
REPO = FORMAL.parent
sys.path[:0] = [str(HERE), str(FORMAL / "difftest")]

import anchors  # noqa: E402
import spec_guard  # noqa: E402
from targets import TARGETS  # noqa: E402

LAST = FORMAL / ".lake" / "difftest" / "last.json"
REGRESS = FORMAL / "difftest" / "regressions"

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None


def load_toml(p):
    """tomllib when available; otherwise enough TOML for obligation records
    (string, bool and string-array values; arrays may span lines)."""
    if tomllib:
        with open(p, "rb") as f:
            return tomllib.load(f)
    out, key, buf = {}, None, None
    for ln in p.read_text().splitlines():
        s = ln.split(" #", 1)[0].strip() if not ln.lstrip().startswith('"') else ln.strip()
        if not s or s.startswith("#"):
            continue
        if buf is not None:
            buf.extend(re.findall(r'"((?:[^"\\]|\\.)*)"', s))
            if s.endswith("]"):
                out[key], buf = buf, None
            continue
        m = re.match(r"^([A-Za-z_]+)\s*=\s*(.*)$", s)
        if not m:
            continue
        key, v = m.group(1), m.group(2)
        if v.startswith("["):
            items = re.findall(r'"((?:[^"\\]|\\.)*)"', v)
            if v.endswith("]"):
                out[key] = items
            else:
                buf = items
        elif v in ("true", "false"):
            out[key] = v == "true"
        else:
            out[key] = v.strip('"')
    return out


def anchor_status():
    tiers = anchors.load_tiers()
    counts = {"pinned": Counter(), "tracked": Counter()}
    stale = []
    for a in anchors.all_anchors():
        state, _ = anchors.evaluate(a, None)
        counts[a.tier][state] += 1
        if state != "ok":
            stale.append({"tier": a.tier, "state": state, "lean": f"formal/{a.lean}", "line": a.line,
                          "ref": a.ref()})
    archived = sum(1 for rel in anchors.lean_files()
                   if anchors.tier_of(rel, tiers) == "archived")
    return {"pinned": dict(counts["pinned"]), "tracked": dict(counts["tracked"]),
            "archived_files": archived, "not_ok": stale}


def spec_status():
    cur, lock = spec_guard.current(), spec_guard.read_lock()
    return {
        "locked": len(lock),
        "changed": sorted(k for k in cur if k in lock and cur[k][1] != lock[k][1]),
        "removed": sorted(k for k in lock if k not in cur),
        "new_spec": sorted(k for k in cur if k not in lock and cur[k][0] == "spec"),
        "new_theorems": sum(1 for k in cur if k not in lock and cur[k][0] == "thm"),
    }, cur, lock


def difftest_status():
    last = json.loads(LAST.read_text()) if LAST.exists() else None
    corpus = {}
    for p in sorted(REGRESS.glob("*.txt")):
        n = sum(1 for ln in p.read_text().splitlines() if ln.split("#", 1)[0].strip())
        corpus[p.stem] = n
    return {"targets": sorted(TARGETS), "last": last, "regressions": corpus}


def obligation_status(spec_cur, spec_lock, last):
    out = []
    ran = (last or {}).get("targets", {})
    all_a = anchors.all_anchors()
    for p in sorted((FORMAL / "obligations").glob("*.toml")):
        o = load_toml(p)
        model = o.get("model", "")
        specs = {}
        for name in o.get("specs", []):
            key = f"{model}::{name}"
            if key not in spec_cur:
                specs[name] = "missing"
            elif key not in spec_lock:
                specs[name] = "unlocked"
            else:
                specs[name] = "locked" if spec_lock[key][1] == spec_cur[key][1] else "changed"
        model_anchors = [a for a in all_a if a.lean == model]
        fresh = sum(1 for a in model_anchors if anchors.evaluate(a, None)[0] == "ok")
        dt = {}
        for t in o.get("difftest", []):
            r = ran.get(t)
            dt[t] = ("not run" if r is None else
                     "ok" if not (r["drift"] or r["spec"] or r["harness"]) else
                     f"drift={r['drift']} spec={r['spec']} harness={r['harness']}")
        out.append({"id": o.get("id", p.stem), "file": p.relative_to(REPO).as_posix(),
                    "status": o.get("status", "?"), "issue": o.get("issue", ""),
                    "theorems": len(o.get("theorems", [])), "specs": specs,
                    "anchors": f"{fresh}/{len(model_anchors)} fresh", "difftest": dt})
    return out


def _counts(c):
    return ", ".join(f"{c.get(k, 0)} {k}" for k in ("ok", "stale", "missing"))


def render(s):
    a, sp, dt = s["anchors"], s["spec_guard"], s["difftest"]
    print("Lean verification factory\n")
    print("anchors")
    print(f"  pinned   {_counts(a['pinned'])}")
    print(f"  tracked  {_counts(a['tracked'])}")
    print(f"  archived {a['archived_files']} files (never checked)")
    pinned_bad = [r for r in a["not_ok"] if r["tier"] == "pinned"]
    for r in pinned_bad[:10]:
        print(f"    {r['state']:7} {r['lean']}:{r['line']}  {r['ref']}")
    if len(pinned_bad) > 10:
        print(f"    ... {len(pinned_bad) - 10} more (anchors.py check --tier pinned)")

    print("\nspec guard")
    pending = len(sp["changed"]) + len(sp["removed"]) + len(sp["new_spec"])
    print(f"  {sp['locked']} locked; {pending} awaiting a human --lock; "
          f"{sp['new_theorems']} new theorem(s) unlocked")
    for label in ("changed", "removed", "new_spec"):
        for k in sp[label]:
            print(f"    {label:8} {k}")

    print("\ndifftest")
    last = dt["last"]
    print(f"  {len(dt['targets'])} targets; regression corpus "
          f"{sum(dt['regressions'].values())} case(s) in {len(dt['regressions'])} file(s)")
    if last:
        bad = {t: r for t, r in last["targets"].items() if r["drift"] or r["spec"] or r["harness"]}
        n = sum(r["cases"] for r in last["targets"].values())
        print(f"  last run {last['time']}: {len(last['targets'])} target(s), {n} cases, "
              f"{'all agree' if not bad else f'{len(bad)} target(s) disagree'}")
        for t, r in bad.items():
            print(f"    {t}: drift={r['drift']} spec={r['spec']} harness={r['harness']}")
    else:
        print("  never run (pixi run -e formal difftest)")

    print("\nobligations")
    if not s["obligations"]:
        print("  none (see the formal-kernel skill)")
    for o in s["obligations"]:
        locks = Counter(o["specs"].values())
        lock_txt = ", ".join(f"{v} {k}" for k, v in sorted(locks.items())) or "no specs"
        dts = "; ".join(f"{t} {r}" for t, r in o["difftest"].items()) or "no difftest"
        print(f"  {o['id']:24} {o['status']:13} specs: {lock_txt}; anchors {o['anchors']}; "
              f"{o['theorems']} theorems; {dts}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    spec, cur, lock = spec_status()
    dt = difftest_status()
    s = {"anchors": anchor_status(), "spec_guard": spec, "difftest": dt,
         "obligations": obligation_status(cur, lock, dt["last"])}
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        render(s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
