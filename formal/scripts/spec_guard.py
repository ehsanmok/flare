#!/usr/bin/env python3
"""Lock what the proofs mean: theorem statements and spec definitions.

An impl model may change freely (it follows the Mojo code); the claims made
about it may not change without a human looking. spec_guard fingerprints

  * the statement of every `theorem`/`lemma` (not its proof),
  * the full text of every spec definition: a name with `spec`/`Spec` as a
    word part (`specStep`, `portSpec`, `SpecRequest`), a `Prop`-valued
    definition, every declaration in a `*Spec.lean` or `*Rfc.lean` file, and
    any declaration whose doc comment contains `[spec]`,

with comments and whitespace removed, into formal/spec.lock.

    spec_guard.py --check [--staged]   # exit 1 if a locked entry changed or vanished,
                                       # or an unlocked spec definition appeared
    spec_guard.py --lock               # rewrite spec.lock (humans only)

New theorems are allowed without re-locking (they only add claims); they are
listed as "unlocked" so the next deliberate --lock picks them up.
"""

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

FORMAL = Path(__file__).resolve().parent.parent
REPO = FORMAL.parent
LOCK = FORMAL / "spec.lock"

DECL = re.compile(
    r"^(?:@\[[^\]]*\]\s*)?(?:(?:private|protected|noncomputable|partial|unsafe|nonrec)\s+)*"
    r"(theorem|lemma|def|abbrev|structure|inductive|class|instance|opaque)\b\s*([^\s:({\[]*)",
    re.M,
)
CONT = re.compile(r"^(\s|\||termination_by|decreasing_by|where|deriving|\)|$)")
SPEC_NAME = re.compile(r"(?:^|[a-z_.])[sS]pec(?![a-z])")


def strip_comments(src):
    out, i, depth, n = [], 0, 0, len(src)
    while i < n:
        if src.startswith("/-", i):
            depth += 1
            i += 2
        elif depth and src.startswith("-/", i):
            depth -= 1
            i += 2
        elif depth:
            out.append("\n" if src[i] == "\n" else " ")
            i += 1
        elif src.startswith("--", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i : j + 1])
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def _statement(text):
    """Text up to the `:=` (or first `|` arm) that starts the proof."""
    depth, i, n = 0, 0, len(text)
    while i < n:
        c = text[i]
        if c in "([{⟨":
            depth += 1
        elif c in ")]}⟩":
            depth -= 1
        elif depth == 0 and text.startswith(":=", i):
            return text[:i]
        elif depth == 0 and c == "|" and i > 0 and text[i - 1] == "\n":
            return text[:i]
        i += 1
    return text


def _norm(s):
    return " ".join(s.split())


def _doc_before(raw_lines, line_no):
    """The doc comment directly above line `line_no` (attributes may sit in between), or ""."""
    j = line_no - 1
    while j >= 0 and raw_lines[j].lstrip().startswith("@["):
        j -= 1
    if j < 0 or not raw_lines[j].rstrip().endswith("-/"):
        return ""
    k = j
    while k >= 0 and "/--" not in raw_lines[k]:
        k -= 1
    return "\n".join(raw_lines[max(k, 0) : j + 1]) if k >= 0 else ""


def entries(rel, src):
    """{key: fingerprint} for one Lean file; `rel` is relative to formal/."""
    code = strip_comments(src)
    lines = code.split("\n")
    raw_lines = src.split("\n")
    spec_file = rel.endswith("Spec.lean") or rel.endswith("Rfc.lean")
    starts = [m for m in DECL.finditer(code)]
    out, seen = {}, {}
    for k, m in enumerate(starts):
        line_no = code.count("\n", 0, m.start())
        j = line_no + 1
        while j < len(lines) and CONT.match(lines[j]) and not DECL.match(lines[j]):
            j += 1
        text = "\n".join(lines[line_no:j])
        kind, name = m.group(1), m.group(2) or f"<{m.group(1)}>"
        tagged = "[spec]" in _doc_before(raw_lines, line_no)
        if kind in ("theorem", "lemma"):
            body, what = _statement(text), "thm"
        elif (spec_file or tagged or SPEC_NAME.search(name)
              or re.search(r"(?::|→)\s*Prop\s*(?::=|$|\n)", _statement(text))):
            body, what = text, "spec"
        else:
            continue
        seen[name] = seen.get(name, 0) + 1
        key = f"{rel}::{name}" + (f"#{seen[name]}" if seen[name] > 1 else "")
        out[key] = (what, hashlib.sha256(_norm(body).encode()).hexdigest()[:12])
    return out


def current(staged=False):
    out = {}
    for p in sorted((FORMAL / "Flare").rglob("*.lean")):
        rel = p.relative_to(FORMAL).as_posix()
        if staged:
            r = subprocess.run(["git", "show", f":formal/{rel}"], cwd=REPO, capture_output=True, text=True)
            if r.returncode != 0:
                continue
            src = r.stdout
        else:
            src = p.read_text()
        out.update(entries(rel, src))
    return out


def read_lock():
    out = {}
    if LOCK.exists():
        for line in LOCK.read_text().splitlines():
            if line.startswith("#") or not line.strip():
                continue
            h, what, key = line.split(None, 2)
            out[key] = (what, h)
    return out


def write_lock(cur):
    lines = ["# spec.lock: fingerprints of theorem statements and spec definitions.",
             "# Regenerate only after reviewing the change: pixi run -e formal formal-spec-lock",
             "# <sha> <thm|spec> <file>::<name>"]
    lines += [f"{h} {what} {key}" for key, (what, h) in sorted(cur.items())]
    LOCK.write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--lock", action="store_true")
    ap.add_argument("--staged", action="store_true")
    args = ap.parse_args()
    cur, lock = current(args.staged), read_lock()
    changed = sorted(k for k in cur if k in lock and cur[k][1] != lock[k][1])
    gone = sorted(k for k in lock if k not in cur)
    new_spec = sorted(k for k in cur if k not in lock and cur[k][0] == "spec")
    new_thm = sorted(k for k in cur if k not in lock and cur[k][0] == "thm")
    if args.lock:
        write_lock(cur)
        for label, ks in (("changed", changed), ("removed", gone), ("new spec", new_spec), ("new theorem", new_thm)):
            for k in ks:
                print(f"{label:12} {k}")
        print(f"spec.lock: {len(cur)} entries ({sum(1 for v in cur.values() if v[0] == 'spec')} spec, "
              f"{sum(1 for v in cur.values() if v[0] == 'thm')} theorem statements)")
        return 0
    for k in changed:
        print(f"CHANGED   {k}")
    for k in gone:
        print(f"REMOVED   {k}")
    for k in new_spec:
        print(f"NEW SPEC  {k}")
    if new_thm:
        print(f"({len(new_thm)} new theorem(s) not yet locked; fine, they only add claims)")
    if changed or gone or new_spec:
        print("\nspec_guard: a theorem statement or spec definition changed. If the change is intended,\n"
              "a human reviews it and runs `pixi run -e formal formal-spec-lock`. Agents must not.",
              file=sys.stderr)
        return 1
    print(f"spec_guard: OK ({len(lock)} locked entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
