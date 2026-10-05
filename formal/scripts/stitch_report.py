#!/usr/bin/env python3
"""Build formal/REPORT.md from the per-layer sections in formal/report/.

Each layer file has a `# Title`, a preamble, and `## ` sections drawn from
SECTION_TARGET. The stitched report regroups them by kind (components,
traceability, findings, refuted suspicions, documentation gaps, not covered)
rather than by layer, and prepends a generated findings index and counts.

    python3 formal/scripts/stitch_report.py           # write REPORT.md
    python3 formal/scripts/stitch_report.py --check   # exit 1 if stale
"""

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = ROOT / "report"

LAYERS = [
    "L1_encoding.md",
    "L2_machine.md",
    "L3_h1_ws.md",
    "L3_h2.md",
    "L3_quic_h3.md",
    "L4_app.md",
    "L5_concurrency.md",
    "Machine.md",
]
DOCS = "Docs.md"

SECTION_TARGET = {
    "Components": "components",
    "Findings": "findings",
    "Checked, not a bug": "refuted",
    "Traceability": "trace",
    "Documentation gaps": "gaps",
    "Not covered": "uncovered",
}

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


def die(msg):
    sys.exit(f"stitch_report: {msg}")


def split(path):
    """Return (title, preamble, [(section name, body)])."""
    lines = path.read_text().splitlines()
    if not lines or not lines[0].startswith("# "):
        die(f"{path.name}: first line must be a '# ' title")
    title = lines[0][2:].strip()
    preamble, sections, cur = [], [], None
    fence = False
    for line in lines[1:]:
        if line.startswith("```"):
            fence = not fence
        if not fence and line.startswith("## "):
            cur = (line[3:].strip(), [])
            sections.append(cur)
        elif cur is None:
            preamble.append(line)
        else:
            cur[1].append(line)
    return title, "\n".join(preamble).strip(), [(n, "\n".join(b).strip()) for n, b in sections]


def demote(text, by):
    out, fence = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            fence = not fence
        m = None if fence else re.match(r"^(#{1,6}) ", line)
        if m:
            depth = len(m.group(1)) + by
            if depth > 6:
                die(f"heading too deep after demotion: {line!r}")
            line = "#" * depth + line[len(m.group(1)):]
        out.append(line)
    return "\n".join(out)


FINDING_RE = re.compile(r"^### ([A-Z][A-Z0-9]*-\d+): (.+)$", re.M)
# finding id -> its report section carries a `Status: resolved` line
_REPORT_RESOLVED = {}


def findings_in(body):
    """Yield (id, title, severity) for each `### ID: title` in a Findings body."""
    heads = list(FINDING_RE.finditer(body))
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(body)
        chunk = body[m.end():end]
        sev = re.search(r"Severity\W*\s*([A-Za-z]+)", chunk)
        if not sev or sev.group(1).capitalize() not in SEVERITIES:
            die(f"{m.group(1)}: no recognisable Severity line")
        in_report = re.search(r"^Status: resolved\b", chunk, re.M) is not None
        _REPORT_RESOLVED[m.group(1)] = in_report
        yield m.group(1), m.group(2).strip(), sev.group(1).capitalize()


def bug_file(fid):
    p = ROOT / "Flare" / "Bugs" / (fid.replace("-", "_") + ".lean")
    return p.relative_to(ROOT).as_posix() if p.exists() else None


def repro_file(fid):
    hits = sorted((ROOT / "repro").glob(f"{fid}_*.mojo"))
    return hits[0].relative_to(ROOT).as_posix() if len(hits) == 1 else None


def resolved_state(fid):
    """The three places a resolution is recorded must agree: the repro's
    `# RESOLVED:` header, the Bugs file's `Status: resolved` line, and the
    report section's `Status: resolved` line. Returns True/False or dies."""
    rp = (ROOT / repro_file(fid)).read_text().splitlines()[:8]
    in_repro = any(l.startswith("# RESOLVED:") for l in rp)
    in_lean = re.search(r"^Status: resolved\b", (ROOT / bug_file(fid)).read_text(), re.M) is not None
    in_report = _REPORT_RESOLVED.get(fid, False)
    if not (in_repro == in_lean == in_report):
        die(
            f"{fid}: resolution marker disagrees (repro header: {in_repro}, "
            f"Bugs file: {in_lean}, report section: {in_report})"
        )
    return in_repro


def repro_platform(path):
    head = (ROOT / path).read_text().splitlines()[:5]
    plat = next((l.split(":", 1)[1].strip() for l in head if l.startswith("# PLATFORM:")), "?")
    skip = any(l.startswith("# SKIP:") for l in head)
    return plat + (", skip" if skip else "")


def lean_counts():
    files = [p for p in (ROOT / "Flare").rglob("*.lean")] + [ROOT / "Flare.lean"]
    thm = re.compile(r"^\s*(?:private\s+|protected\s+)?(?:theorem|lemma)\s", re.M)
    n_thm = sum(len(thm.findall(p.read_text())) for p in files)
    n_lines = sum(len(p.read_text().splitlines()) for p in files)
    audit = [ROOT / "Flare" / "Audit.lean"] + sorted((ROOT / "Flare" / "Audit").glob("*.lean"))
    n_audit = sum(p.read_text().count("\n#print axioms ") for p in audit if p.exists())
    return len(files), n_lines, n_thm, n_audit


def main():
    check = "--check" in sys.argv[1:]
    buckets = {k: [] for k in set(SECTION_TARGET.values())}
    layer_titles, index = [], []

    for name in LAYERS:
        title, preamble, sections = split(REPORT_DIR / name)
        layer_titles.append((title, preamble))
        for sec, body in sections:
            if sec not in SECTION_TARGET:
                die(f"{name}: unknown section '## {sec}'")
            buckets[SECTION_TARGET[sec]].append((title, body))
            if sec == "Findings":
                index += [(fid, t, s, title) for fid, t, s in findings_in(body)]

    docs_path = REPORT_DIR / DOCS
    docs_title = docs_pre = None
    docs_tables = []
    if docs_path.exists():
        docs_title, docs_pre, sections = split(docs_path)
        for sec, body in sections:
            if sec == "Findings":
                buckets["findings"].append((docs_title, body))
                index += [(fid, t, s, docs_title) for fid, t, s in findings_in(body)]
            elif sec in SECTION_TARGET:
                buckets[SECTION_TARGET[sec]].append((docs_title, body))
            else:
                docs_tables.append((sec, body))

    seen = Counter(fid for fid, *_ in index)
    dup = [f for f, n in seen.items() if n > 1]
    if dup:
        die(f"duplicate finding ids: {dup}")
    missing = [f for f, *_ in index if not bug_file(f) or not repro_file(f)]
    if missing:
        die(f"findings without a Bugs file or exactly one repro: {missing}")
    bugs = {p.stem.replace("_", "-") for p in (ROOT / "Flare" / "Bugs").glob("*.lean")}
    repros = {p.name.split("_", 1)[0] for p in (ROOT / "repro").glob("*.mojo")}
    is_id = re.compile(r"^[A-Z][A-Z0-9]*-\d+$").match
    orphans = sorted(x for x in (bugs | repros) - set(seen) if is_id(x))
    if orphans:
        die(f"Bugs files or repros with no report finding: {orphans}")

    resolved = {f: resolved_state(f) for f, *_ in index}
    n_resolved = sum(resolved.values())
    by_sev = Counter(s for _, _, s, _ in index)
    n_files, n_lines, n_thm, n_audit = lean_counts()
    sev_line = ", ".join(f"{by_sev[s]} {s.lower()}" for s in SEVERITIES if by_sev[s])
    counts = (
        f"| | |\n|---|---|\n"
        f"| Lean files | {n_files} ({n_lines} lines) |\n"
        f"| Theorems | {n_thm} |\n"
        f"| Headline theorems in the axiom audit | {n_audit} |\n"
        f"| Confirmed findings | {len(index)} ({sev_line}) |\n"
        f"| Mojo repros | {len(index)}, one per finding |\n"
        f"| Resolved (fix landed, repro kept as a regression check) | {n_resolved} of {len(index)} |"
    )

    front = (REPORT_DIR / "_front.md").read_text().strip()
    back = (REPORT_DIR / "_back.md").read_text().strip()
    if "<!-- COUNTS -->" not in front:
        die("_front.md must contain <!-- COUNTS -->")
    out = [front.replace("<!-- COUNTS -->", counts)]

    out.append("## 3. Layer by layer")
    for i, (title, preamble) in enumerate(layer_titles, 1):
        out.append(f"### 3.{i} {title}")
        out.append(demote(preamble, 2))
        for t, body in buckets["components"]:
            if t == title:
                out.append(demote(body, 1))

    out.append("## 4. Traceability")
    for i, (t, body) in enumerate(buckets["trace"], 1):
        out.append(f"### 4.{i} {t}")
        out.append(demote(body, 1))

    out.append("## 5. Findings")
    out.append(
        "Every finding below has a Lean counterexample and a proof that the "
        "minimal fix meets the specification, in `formal/Flare/Bugs/`, and a "
        "Mojo repro in `formal/repro/` that failed while the bug was present "
        "and passes now that the fix has landed. Each finding's `Status: "
        "resolved` note says what changed."
    )
    rows = [
        "| ID | Severity | Status | Finding | Lean | Repro (platform) |",
        "|---|---|---|---|---|---|",
    ]
    for fid, t, s, _ in index:
        rp = repro_file(fid)
        cell = t.replace("|", r"\|")
        status = "resolved" if resolved[fid] else "open"
        rows.append(
            f"| {fid} | {s} | {status} | {cell} | `{bug_file(fid)}` | `{rp}` ({repro_platform(rp)}) |"
        )
    out.append("\n".join(rows))
    for i, (t, body) in enumerate(buckets["findings"], 1):
        out.append(f"### 5.{i} {t}")
        out.append(demote(body, 1))
    out.append("### Refuted suspicions")
    out.append(
        "Suspicions that turned out not to be bugs, each with the theorem or "
        "argument that settles it."
    )
    for t, body in buckets["refuted"]:
        out.append(f"#### {t}")
        out.append(demote(body, 2))

    out.append("## 6. Documentation versus code")
    if docs_title:
        out.append(demote(docs_pre, 1))
        for sec, body in docs_tables:
            out.append(f"### {sec}")
            out.append(demote(body, 1))
    for t, body in buckets["gaps"]:
        out.append(f"### {t}")
        out.append(demote(body, 1))

    out.append("## 7. Not covered and next steps")
    for t, body in buckets["uncovered"]:
        out.append(f"### {t}")
        out.append(demote(body, 1))
    out.append(back)

    text = "\n\n".join(p for p in out if p) + "\n"
    target = ROOT / "REPORT.md"
    if check:
        if not target.exists() or target.read_text() != text:
            die("REPORT.md is stale; run formal/scripts/stitch_report.py")
        return
    target.write_text(text)
    print(f"wrote {target.relative_to(ROOT.parent)}: {len(index)} findings, {n_thm} theorems")


if __name__ == "__main__":
    main()
