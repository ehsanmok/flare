#!/usr/bin/env python3
"""Fidelity anchors: tie each Lean impl model to the Mojo symbols it mirrors.

An anchor sits in a Lean doc comment and names Mojo symbols plus a hash of
their normalized source:

    /-- mirrors flare/http2/hpack.mojo#decode_integer sha=3f9a1c2e0b7d at=8c6e1400 -/

* `#A.f+g` lists the mirrored symbols: functions and methods by qualified
  name, `Struct` for a struct's declarations without its methods, and
  module-level `comptime`/`alias`/`var` by name. The `n`th overload of a
  name is `name@n` (n >= 2).
* `sha` hashes the symbols' source with comments, docstrings, blank lines
  and line wrapping removed, so reformatting or moving code is not drift.
* `at` is the commit on which the anchor was last confirmed; diff the
  symbols from there to see what the model has not caught up with.

Models are tiered in formal/tiers.toml (pinned / tracked / archived).

    anchors.py check [--staged | --base REV] [--tier T] [--fail-on T] [--json]
    anchors.py who-models FILE[:LINE]
    anchors.py refresh [--stale] [--at REV] [LEAN_FILE[:LINE] ...]
    anchors.py make [--rev REV] flare/x.mojo#Sym[+Sym...]
    anchors.py list [--json]
    anchors.py migrate [--dry-run]

`check` with no mode flag reports every stale anchor in the working tree.
`--staged` checks the index and reports only anchors whose symbols the
staged change touches (versus HEAD); `--base REV` does the same for the
working tree versus REV. `--fail-on` exits 1 when a reported anchor in that
tier (pinned, tracked or any) is stale.
"""

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

FORMAL = Path(__file__).resolve().parent.parent
REPO = FORMAL.parent
LEAN_ROOT = FORMAL / "Flare"
SHA_LEN = 12
AUDIT_COMMIT = "59bda50"

ANCHOR_RE = re.compile(
    r"(flare/[\w/.-]+?\.mojo)#([\w.@+]+) sha=([0-9a-f]{%d}) at=([0-9a-f]{7,40})" % SHA_LEN
)
DOC_RE = re.compile(r"/-[-!].*?-/", re.S)


def git(*args, check=True):
    r = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout if r.returncode == 0 else None


def short(rev):
    return git("rev-parse", "--short=8", rev).strip()


# ── Sources at a revision ───────────────────────────────────────────────────
#
# A "source" is where file contents come from: None for the working tree,
# ":" for the index, or a commit-ish.

_file_cache = {}


def read_file(path, src):
    key = (path, src)
    if key not in _file_cache:
        if src is None:
            p = REPO / path
            _file_cache[key] = p.read_text() if p.exists() else None
        else:
            spec = f":{path}" if src == ":" else f"{src}:{path}"
            _file_cache[key] = git("show", spec, check=False)
    return _file_cache[key]


# ── Mojo lexing and symbol index ────────────────────────────────────────────


def lex(text):
    """Return (shape, keep): two copies of `text` with the same newlines.

    `shape` drops comments and string contents (a literal becomes `""`),
    for bracket counting and statement shape. `keep` drops only comments,
    for hashing.
    """
    shape, keep = [], []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "#":
            j = text.find("\n", i)
            j = n if j < 0 else j
            i = j
        elif c in "\"'":
            q = text[i : i + 3] if text[i : i + 3] in ('"""', "'''") else c
            j = i + len(q)
            while j < n and not text.startswith(q, j):
                if text[j] == "\\":
                    j += 1
                elif len(q) == 1 and text[j] == "\n":
                    break
                j += 1
            end = min(n, j + len(q))
            lit = text[i:end]
            shape.append('"' + "\n" * lit.count("\n") + '"')
            keep.append(lit)
            i = end
        else:
            shape.append(c)
            keep.append(c)
            i += 1
    return "".join(shape), "".join(keep)


@dataclass
class LLine:
    start: int  # 1-based physical line numbers, inclusive
    end: int
    indent: int
    shape: str
    keep: str


def logical_lines(text):
    shape, keep = lex(text)
    sl, kl, raw = shape.split("\n"), keep.split("\n"), text.split("\n")
    out, i = [], 0
    while i < len(sl):
        j, depth, in_str = i, 0, False
        while True:
            for ch in sl[j]:
                if ch == '"':
                    in_str = not in_str
                elif in_str:
                    continue
                elif ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
            done = depth <= 0 and not in_str and not sl[j].rstrip().endswith("\\")
            if done or j + 1 >= len(sl):
                break
            j += 1
        s = "\n".join(sl[i : j + 1])
        if s.strip():
            ind = len(raw[i]) - len(raw[i].lstrip(" "))
            out.append(LLine(i + 1, j + 1, ind, s, "\n".join(kl[i : j + 1])))
        i = j + 1
    return out


@dataclass
class Sym:
    name: str
    kind: str  # fn | struct | stmt
    lls: list = field(default_factory=list)  # LLine
    span: list = field(default_factory=list)  # [(start, end)]

    def lines(self):
        return [(a, b) for a, b in self.span]

    def first_line(self):
        return min(a for a, _ in self.span)


def _block_end(L, i):
    j = i + 1
    if L[i].shape.rstrip().endswith(":"):
        while j < len(L) and L[j].indent > L[i].indent:
            j += 1
    return j


def index_symbols(text):
    L = logical_lines(text)
    syms = []

    def walk(lo, hi, prefix, top):
        loose, decs, i = [], [], lo
        while i < hi:
            ll = L[i]
            s = ll.shape.strip()
            e = _block_end(L, i)
            if s.startswith("@"):
                decs.append(i)
                i += 1
                continue
            body = decs + list(range(i, e))
            m = re.match(r"(?:async\s+)?(def|fn)\s+(\w+)", s)
            if m:
                lls = [L[k] for k in body]
                syms.append(Sym(prefix + m.group(2), "fn", lls, [(lls[0].start, L[e - 1].end)]))
            elif re.match(r"(struct|trait)\s+(\w+)", s):
                q = prefix + re.match(r"(struct|trait)\s+(\w+)", s).group(2)
                inner = walk(i + 1, e, q + ".", False)
                lls = [L[k] for k in decs + [i] + inner]
                syms.append(Sym(q, "struct", lls, [(x.start, x.end) for x in lls]))
            elif top and re.match(r"(comptime|alias|var|let)\s+(\w+)", s):
                lls = [L[k] for k in body]
                name = re.match(r"(comptime|alias|var|let)\s+(\w+)", s).group(2)
                syms.append(Sym(name, "stmt", lls, [(lls[0].start, L[e - 1].end)]))
            else:
                loose.extend(body)
            decs = []
            i = e
        return loose

    walk(0, len(L), "", True)
    seen = {}
    for s in sorted(syms, key=Sym.first_line):
        seen[s.name] = seen.get(s.name, 0) + 1
        if seen[s.name] > 1:
            s.name = f"{s.name}@{seen[s.name]}"
    return {s.name: s for s in syms}


_DOC_SHAPE = re.compile(r'\s*[A-Za-z]?"\s*"\s*')
_TOKEN = re.compile(r'[A-Za-z_]?(?:"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|\w+|\S')


def normalize(sym):
    base = sym.lls[0].indent
    out = []
    for ll in sym.lls:
        if _DOC_SHAPE.fullmatch(ll.shape):
            continue
        toks = " ".join(_TOKEN.findall(ll.keep))
        toks = re.sub(r", ([)\]}])", r"\1", toks)
        out.append(f"{ll.indent - base}:{toks}")
    return "\n".join(out)


def hash_syms(syms):
    h = hashlib.sha256()
    for s in syms:
        h.update(s.name.encode() + b"\n" + normalize(s).encode() + b"\0")
    return h.hexdigest()[:SHA_LEN]


_index_cache = {}


def symbols_at(path, src):
    key = (path, src)
    if key not in _index_cache:
        text = read_file(path, src)
        _index_cache[key] = None if text is None else index_symbols(text)
    return _index_cache[key]


def lookup(index, name):
    """Exact qualified name, else a unique `.name` suffix match."""
    if name in index:
        return index[name]
    hits = [s for k, s in index.items() if k.endswith("." + name)]
    return hits[0] if len(hits) == 1 else None


def anchor_hash(path, names, src):
    """Hash of `names` in `path` at `src`, or None if any is missing."""
    idx = symbols_at(path, src)
    if idx is None:
        return None
    syms = [idx.get(n) for n in names]
    if any(s is None for s in syms):
        return None
    return hash_syms(syms)


# ── Tiers ───────────────────────────────────────────────────────────────────


def load_tiers():
    tiers, cur = {"pinned": [], "archived": []}, None
    for line in (FORMAL / "tiers.toml").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            cur = m.group(1)
            tiers.setdefault(cur, [])
            continue
        for pat in re.findall(r'"([^"]+)"', line):
            if cur:
                tiers[cur].append(pat)
    return tiers


def _glob_match(path, pat):
    if "**" in pat:
        return fnmatch.fnmatch(path, pat.replace("**", "*"))
    return fnmatch.fnmatch(path, pat) and path.count("/") == pat.count("/")


def tier_of(rel, tiers):
    for t in ("archived", "pinned"):
        if any(_glob_match(rel, p) for p in tiers.get(t, [])):
            return t
    return "tracked"


# ── Anchors in Lean files ───────────────────────────────────────────────────


@dataclass
class Anchor:
    lean: str  # path relative to formal/
    line: int
    mojo: str
    names: list
    sha: str
    at: str
    tier: str
    span: tuple  # character span of the match in the Lean file

    def ref(self):
        return f"{self.mojo}#{'+'.join(self.names)}"


def lean_files():
    return sorted(p.relative_to(FORMAL).as_posix() for p in LEAN_ROOT.rglob("*.lean"))


def read_lean(rel, src):
    return read_file(f"formal/{rel}", src)


def anchors_in(rel, text, tier):
    out = []
    for m in ANCHOR_RE.finditer(text):
        out.append(Anchor(rel, text.count("\n", 0, m.start()) + 1, m.group(1),
                          m.group(2).split("+"), m.group(3), m.group(4), tier, m.span()))
    return out


def all_anchors(src=None, include_archived=False):
    tiers = load_tiers()
    out = []
    for rel in lean_files():
        t = tier_of(rel, tiers)
        if t == "archived" and not include_archived:
            continue
        text = read_lean(rel, src)
        if text:
            out.extend(anchors_in(rel, text, t))
    return out


# ── check ───────────────────────────────────────────────────────────────────


def evaluate(a, src):
    cur = anchor_hash(a.mojo, a.names, src)
    if cur is None:
        return "missing", None
    return ("ok" if cur == a.sha else "stale"), cur


def cmd_check(args):
    if args.staged:
        lean_src, cur_src, base_src = ":", ":", "HEAD"
    elif args.base:
        lean_src, cur_src, base_src = None, None, args.base
    else:
        lean_src, cur_src, base_src = None, None, None
    rows, untouched = [], 0
    for a in all_anchors(lean_src):
        if args.tier and a.tier != args.tier:
            continue
        state, cur = evaluate(a, cur_src)
        if state == "ok":
            continue
        if base_src is not None:
            touched = anchor_hash(a.mojo, a.names, base_src) != cur
            text = read_lean(a.lean, lean_src)
            new_anchor = text[a.span[0]:a.span[1]] not in (read_lean(a.lean, base_src) or "")
            if not touched and not new_anchor:
                untouched += 1
                continue
        rows.append({"state": state, "tier": a.tier, "lean": f"formal/{a.lean}", "line": a.line,
                     "mojo": a.mojo, "symbols": a.names, "sha": a.sha, "current": cur, "at": a.at})
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            print(f"{r['state'].upper():8} {r['tier']:8} {r['lean']}:{r['line']}  "
                  f"{r['mojo']}#{'+'.join(r['symbols'])}  (at {r['at']})")
        if base_src is not None and untouched:
            print(f"({untouched} other anchors were already stale and are not touched by this change)")
    fail = {"pinned": {"pinned"}, "tracked": {"pinned", "tracked"}, "any": {"pinned", "tracked"}}
    bad = [r for r in rows if r["tier"] in fail.get(args.fail_on or "", set())]
    if bad and not args.json:
        print(f"\n{len(bad)} {args.fail_on} anchor(s) stale. Update the model(s), re-prove, then "
              "`python3 formal/scripts/anchors.py refresh FILE:LINE` (or run /formal-verify).",
              file=sys.stderr)
    return 1 if bad else 0


# ── who-models ──────────────────────────────────────────────────────────────


OBLIGATIONS = FORMAL / "obligations"
OBLIGATION_REF = re.compile(r'"(flare/[^"#\s]+\.mojo)#([^"\s]+)"')


def obligation_refs():
    """(toml path, key, mojo file, symbol names) for every anchor ref in formal/obligations/*.toml."""
    out = []
    for p in sorted(OBLIGATIONS.glob("*.toml")):
        key = None
        for ln in p.read_text().splitlines():
            m = re.match(r"^([a-z_]+)\s*=", ln)
            if m:
                key = m.group(1)
            for r in OBLIGATION_REF.finditer(ln):
                out.append((p.relative_to(REPO).as_posix(), key, r.group(1), r.group(2).split("+")))
    return out


def _covers(mojo, names, line):
    if line is None:
        return True
    idx = symbols_at(mojo, None) or {}
    spans = [sp for n in names if n in idx for sp in idx[n].lines()]
    return any(lo <= line <= hi for lo, hi in spans)


def cmd_who(args):
    path, _, line = args.target.partition(":")
    line = int(line) if line else None
    hits = 0
    for a in all_anchors(include_archived=args.all):
        if a.mojo != path or not _covers(a.mojo, a.names, line):
            continue
        state, _ = evaluate(a, None)
        print(f"{state:8} {a.tier:8} formal/{a.lean}:{a.line}  {a.ref()}")
        hits += 1
    for toml, key, mojo, names in obligation_refs():
        if mojo != path or not _covers(mojo, names, line):
            continue
        print(f"{'kernel':8} {key:8} {toml}  {mojo}#{'+'.join(names)}")
        hits += 1
    return 0 if hits else 1


# ── refresh / make / list ───────────────────────────────────────────────────


def _select(args):
    sel = {}
    for t in args.targets:
        f, _, ln = t.partition(":")
        f = f[len("formal/"):] if f.startswith("formal/") else f
        sel.setdefault(f, set())
        if ln:
            sel[f].add(int(ln))
    return sel


def cmd_refresh(args):
    sel = _select(args)
    if not sel and not args.stale:
        print("refresh: name LEAN_FILE[:LINE] targets or pass --stale", file=sys.stderr)
        return 2
    at = short(args.at)
    tiers = load_tiers()
    changed, failed = 0, 0
    for rel in lean_files():
        if sel and rel not in sel:
            continue
        text = read_lean(rel, None)
        lines_sel = sel.get(rel, set())
        docs = [(text.count("\n", 0, d.start()) + 1, text.count("\n", 0, d.end()) + 1)
                for d in DOC_RE.finditer(text)]
        edits = []
        for a in anchors_in(rel, text, tier_of(rel, tiers)):
            if lines_sel:
                doc = [(lo, hi) for lo, hi in docs if lo <= a.line <= hi]
                lo, hi = doc[0] if doc else (a.line, a.line)
                if not any(lo <= x <= hi for x in lines_sel):
                    continue
            state, cur = evaluate(a, None)
            if args.stale and state == "ok":
                continue
            if cur is None:
                print(f"MISSING  formal/{rel}:{a.line} {a.ref()}: symbol gone; edit the anchor by hand "
                      "(`anchors.py make` prints a fresh one)", file=sys.stderr)
                failed += 1
                continue
            edits.append((a.span, f"{a.ref()} sha={cur} at={at}"))
            print(f"refreshed formal/{rel}:{a.line} {a.ref()} sha={cur} at={at}")
        for (s, e), new in sorted(edits, reverse=True):
            text = text[:s] + new + text[e:]
        if edits:
            (FORMAL / rel).write_text(text)
            changed += len(edits)
    print(f"{changed} anchor(s) refreshed")
    return 1 if failed else 0


def cmd_make(args):
    path, _, names = args.ref.partition("#")
    idx = symbols_at(path, args.rev)
    if idx is None:
        print(f"no such file: {path}", file=sys.stderr)
        return 1
    resolved = []
    for n in names.split("+"):
        s = lookup(idx, n)
        if s is None:
            near = [k for k in idx if n.split(".")[-1] in k][:8]
            print(f"unknown symbol {n} in {path}; candidates: {', '.join(near) or '-'}", file=sys.stderr)
            return 1
        resolved.append(s)
    print(f"{path}#{'+'.join(s.name for s in resolved)} sha={hash_syms(resolved)} "
          f"at={short(args.rev or 'HEAD')}")
    return 0


def cmd_list(args):
    rows = []
    for a in all_anchors(include_archived=args.all):
        state, _ = evaluate(a, None)
        rows.append({"state": state, "tier": a.tier, "lean": f"formal/{a.lean}", "line": a.line,
                     "mojo": a.mojo, "symbols": a.names, "sha": a.sha, "at": a.at})
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            print(f"{r['state']:8} {r['tier']:8} {r['lean']}:{r['line']}  {r['mojo']}#{'+'.join(r['symbols'])}")
    return 0


# ── migrate (one-time: line-range headers -> anchors) ───────────────────────

RANGES = r"\d+(?:-\d+)?(?:,\s?\d+(?:-\d+)?)*"
SYMREF = r"`(\w+(?:\.\w+)?)`"
REF_RE = re.compile(
    r"(?<![\w/])(flare/[\w/]+\.mojo)"
    r"(?::(" + RANGES + r")|\s+" + SYMREF + r")"
    r"((?:(?:\s+\([^()]*\))?\s+and\s+:?" + RANGES + r"|(?:\s*,\s*|\s+and\s+)" + SYMREF + r")*)"
)
COMMIT_RE = re.compile(r"\s?@([0-9a-f]{7,40})\b")


def _parse_ranges(s):
    out = []
    for part in re.split(r",\s?", s):
        a, _, b = part.partition("-")
        out.append((int(a), int(b or a)))
    return out


def _blame(rel):
    out = git("blame", "--porcelain", "--", f"formal/{rel}", check=False) or ""
    m, cur = {}, None
    for line in out.splitlines():
        h = re.match(r"([0-9a-f]{40}) \d+ (\d+)", line)
        if h:
            cur = h.group(1)
            m[int(h.group(2))] = cur
    return m


def _resolve(path, rev, ranges, names):
    idx = symbols_at(path, rev)
    if idx is None:
        return None, f"{path} not present at {rev}"
    picked = []
    for lo, hi in ranges:
        hit = [s for s in idx.values() if any(a <= hi and lo <= b for a, b in s.lines())]
        if not hit:
            return None, f"{path}:{lo}-{hi} at {rev} covers no symbol"
        picked.extend(sorted(hit, key=Sym.first_line))
    for n in names:
        s = lookup(idx, n)
        if s is None:
            return None, f"{path} `{n}` at {rev} is not a unique symbol"
        picked.append(s)
    uniq = []
    for s in picked:
        if s.name not in [u.name for u in uniq]:
            uniq.append(s)
    return uniq, None


def cmd_migrate(args):
    tiers = load_tiers()
    done, problems = 0, []
    for rel in lean_files():
        if tier_of(rel, tiers) == "archived":
            continue
        text = read_lean(rel, None)
        blame = None
        edits = []
        for d in DOC_RE.finditer(text):
            doc = d.group(0)
            if "mirrors" not in doc:
                continue
            refs = list(REF_RE.finditer(doc))
            for k, m in enumerate(refs):
                tail_end = refs[k + 1].start() if k + 1 < len(refs) else len(doc)
                tail = doc[m.end():tail_end]
                cm = COMMIT_RE.search(tail)
                if cm and "std/" in tail[: cm.start()]:
                    cm = None
                line = text.count("\n", 0, d.start() + m.start()) + 1
                if cm:
                    rev = cm.group(1)
                else:
                    blame = blame if blame is not None else _blame(rel)
                    rev = blame.get(line, "HEAD")
                    if rev == "0" * 40:
                        rev = "HEAD"
                ranges, names = [], []
                if m.group(2):
                    ranges += _parse_ranges(m.group(2))
                if m.group(3):
                    names.append(m.group(3))
                more = m.group(4) or ""
                for r in re.finditer(r"and\s+:?(" + RANGES + ")", more):
                    ranges += _parse_ranges(r.group(1))
                names += re.findall(SYMREF, more)
                # A symbol named in the note right after the reference wins
                # over a line range that was off by a few lines.
                note = re.match(r"\s*(?:@[0-9a-f]{7,40}\s*)?\(([^()]*)\)", tail)
                bt = note and re.search(SYMREF, note.group(1))
                if bt and lookup(symbols_at(m.group(1), rev) or {}, bt.group(1)):
                    names.append(bt.group(1))
                syms, err = _resolve(m.group(1), rev, ranges, names)
                if err:
                    problems.append(f"formal/{rel}:{line}: {err}")
                    continue
                notes = re.findall(r"\(([^()]*)\)", more)
                new = f"{m.group(1)}#{'+'.join(s.name for s in syms)} sha={hash_syms(syms)} at={short(rev)}"
                if notes:
                    new += " (" + "; ".join(notes) + ")"
                base = d.start()
                edits.append((base + m.start(), base + m.end(), new))
                if cm:
                    edits.append((base + m.end() + cm.start(), base + m.end() + cm.end(), ""))
        if not edits:
            continue
        edits.sort(reverse=True)
        for s, e, new in edits:
            text = text[:s] + new + text[e:]
        done += sum(1 for _, _, n in edits if n)
        if not args.dry_run:
            (FORMAL / rel).write_text(text)
    print(f"{done} reference(s) migrated to anchors")
    for p in problems:
        print("UNRESOLVED " + p)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    g = c.add_mutually_exclusive_group()
    g.add_argument("--staged", action="store_true")
    g.add_argument("--base")
    c.add_argument("--tier", choices=["pinned", "tracked"])
    c.add_argument("--fail-on", choices=["pinned", "tracked", "any"])
    c.add_argument("--json", action="store_true")
    w = sub.add_parser("who-models")
    w.add_argument("target")
    w.add_argument("--all", action="store_true", help="include archived models")
    r = sub.add_parser("refresh")
    r.add_argument("targets", nargs="*")
    r.add_argument("--stale", action="store_true")
    r.add_argument("--at", default="HEAD")
    mk = sub.add_parser("make")
    mk.add_argument("ref")
    mk.add_argument("--rev", help="hash the symbols at this commit instead of the working tree")
    ls = sub.add_parser("list")
    ls.add_argument("--json", action="store_true")
    ls.add_argument("--all", action="store_true")
    mg = sub.add_parser("migrate")
    mg.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    return {"check": cmd_check, "who-models": cmd_who, "refresh": cmd_refresh, "make": cmd_make,
            "list": cmd_list, "migrate": cmd_migrate}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
