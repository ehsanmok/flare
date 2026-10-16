#!/usr/bin/env python3
"""Cursor `stop` hook: when the agent finishes a turn that left pinned Lean
models stale (or touched formal/spec.lock), send it back with a follow-up.

Fails open: any error prints `{}` so a broken toolchain never traps the agent.
"""

import json
import subprocess
import sys


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        event = {}
    if event.get("status", "completed") != "completed":
        return {}

    if sh("git", "cat-file", "-e", "HEAD:formal/tiers.toml").returncode != 0:
        return {}  # factory not committed yet: every anchor would look new vs HEAD
    changed = sh("git", "status", "--porcelain", "--", "flare", "formal").stdout
    if not changed.strip():
        return {}

    problems = []
    if sh("git", "diff", "--quiet", "HEAD", "--", "formal/spec.lock").returncode != 0:
        problems.append(
            "`formal/spec.lock` was modified. Only a human may re-lock specs: revert it with "
            "`git checkout HEAD -- formal/spec.lock` and restore any theorem statement or spec "
            "definition you changed. If you believe a spec must change, ask the user."
        )

    res = sh("python3", "formal/scripts/anchors.py", "check", "--base", "HEAD",
             "--tier", "pinned", "--json")
    rows = json.loads(res.stdout or "[]")
    if rows:
        listed = "\n".join(
            f"- {r['state']} {r['lean']}:{r['line']} mirrors {r['mojo']}#{'+'.join(r['symbols'])}"
            for r in rows[:15]
        )
        more = f"\n- ... and {len(rows) - 15} more" if len(rows) > 15 else ""
        problems.append(
            f"Your change left {len(rows)} pinned Lean model anchor(s) stale:\n{listed}{more}\n"
            "Follow the formal-sync skill (.cursor/skills/formal-sync/SKILL.md): update each "
            "impl model to mirror the new Mojo code, re-prove with `lake build`, run "
            "`python3 formal/difftest/run.py --affected --base HEAD`, then refresh the anchors. "
            "If a proof fails because the new code violates a spec, stop and report it as a bug."
        )

    if not problems:
        return {}
    return {"followup_message": "Formal factory check:\n\n" + "\n\n".join(problems)}


if __name__ == "__main__":
    try:
        out = main()
    except Exception:  # noqa: BLE001 - fail open
        out = {}
    print(json.dumps(out))
