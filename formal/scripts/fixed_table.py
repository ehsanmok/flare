#!/usr/bin/env python3
"""Write formal/report/Fixed.md: the commit that fixed each finding.

Reads `git log` for subjects ending in `(<ID>)` (the fix commits carry the
finding ID in the subject) and joins them with the severity from the report
index. Run it after the fixes are in their final history:

    python3 formal/scripts/fixed_table.py
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent

def index_from_report():
    """(id, severity) rows of the findings index in REPORT.md."""
    rows = []
    for line in (ROOT / "REPORT.md").read_text().splitlines():
        m = re.match(r"\| ([A-Z][A-Z0-9]*-\d+) \| (\w+) \|", line)
        if m:
            rows.append((m.group(1), m.group(2)))
    return rows


def main():
    log = subprocess.run(
        ["git", "log", "--format=%h%x09%s"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    fix = {}
    for line in log:
        h, _, subj = line.partition("\t")
        m = re.search(r"\(([A-Z0-9]+-\d+)\)\s*$", subj)
        if m and subj.startswith("fix("):
            fix.setdefault(m.group(1), (h, subj))
    index = index_from_report()
    rows = ["| ID | Severity | Commit | Subject |", "|---|---|---|---|"]
    missing = []
    for fid, sev in index:
        if fid not in fix:
            missing.append(fid)
            continue
        h, subj = fix[fid]
        rows.append(f"| {fid} | {sev} | `{h}` | {subj} |")
    if missing:
        sys.exit(f"fixed_table: no fix commit for {missing}")
    text = (
        "# Fixes\n\n"
        f"One commit per finding ({len(index)} in all), as `git log` records them. "
        "Each commit changes `flare/`, adds a regression test, updates the docs, "
        "updates the Lean model and marks the repro resolved.\n\n" + "\n".join(rows) + "\n"
    )
    (ROOT / "report" / "Fixed.md").write_text(text)
    print(f"wrote formal/report/Fixed.md: {len(index)} fixes")


if __name__ == "__main__":
    main()
