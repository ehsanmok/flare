"""Code-complexity + test-reference metrics for the (Mojo) flare tree.

Mojo has no first-party cyclomatic-complexity or line-coverage tool, so we
lean on two open-source proxies that work on Mojo's overwhelmingly
``def``-based, Python-shaped syntax:

* complexity -- lizard's Python reader, driven through its in-process API so
  ``.mojo`` sources are analyzed as Python without temp-file copies. flare is
  2057 ``def`` vs 0 ``fn`` (the handful of ``fn`` tokens are variable names in
  FFI comments), so the Python reader covers ~100% of real functions.

* coverage  -- a *reference* proxy, not line coverage: a source module counts
  as covered when its dotted import path is named by at least one test, OR a
  ``test_<stem>.mojo`` exists. ponytail: this can't see lines executed only
  transitively (a private ``_server/parse.mojo`` exercised via the
  ``http.server`` re-export reads as uncovered); the per-module list below
  makes those explicit. Upgrade path: real coverage once the Mojo toolchain
  emits instrumentation.

Usage: ``python tools/metrics.py [complexity|coverage|all]``  (default: all)
"""

import os
import re
import sys

import lizard

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT, "flare")
TEST_DIR = os.path.join(ROOT, "tests")
CCN_WARN = 15  # functions at/above this cyclomatic complexity are flagged


def _mojo_files(base):
    for dirpath, _, names in os.walk(base):
        for n in sorted(names):
            if n.endswith(".mojo"):
                yield os.path.join(dirpath, n)


def _analyze(path):
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    # Force lizard's Python reader by handing it a .py filename.
    return lizard.analyze_file.analyze_source_code(path[:-5] + ".py", src)


def complexity():
    total_nloc = 0
    funcs = []  # (ccn, nloc, name, relpath, line)
    file_count = 0
    for path in _mojo_files(SRC_DIR):
        rel = os.path.relpath(path, ROOT)
        res = _analyze(path)
        file_count += 1
        total_nloc += res.nloc
        for f in res.function_list:
            funcs.append(
                (f.cyclomatic_complexity, f.nloc, f.name, rel, f.start_line)
            )

    fn_count = len(funcs) or 1
    avg_ccn = sum(f[0] for f in funcs) / fn_count
    max_ccn = max((f[0] for f in funcs), default=0)
    over = sorted((f for f in funcs if f[0] >= CCN_WARN), reverse=True)

    print("== Complexity (flare/, lizard Python reader) ==")
    print(f"  source files     : {file_count}")
    print(f"  functions        : {len(funcs)}")
    print(f"  source NLOC       : {total_nloc}")
    print(f"  avg cyclomatic    : {avg_ccn:.2f}")
    print(f"  max cyclomatic    : {max_ccn}")
    print(f"  functions CCN>={CCN_WARN}: {len(over)}")
    if over:
        print(f"\n  Top {min(15, len(over))} by cyclomatic complexity:")
        print(f"    {'CCN':>4} {'NLOC':>5}  location")
        for ccn, nloc, name, rel, line in over[:15]:
            print(f"    {ccn:>4} {nloc:>5}  {rel}:{line}  {name}")
    return len(over)


_IMPORT_RE = re.compile(r"(?:from|import)\s+(flare(?:\.[A-Za-z0-9_]+)*)")


def _dotted(path):
    rel = os.path.relpath(path, ROOT)[:-5]  # strip .mojo
    return rel.replace(os.sep, ".")


def coverage():
    # Every dotted path named by any test import.
    imported = set()
    test_files = list(_mojo_files(TEST_DIR))
    for path in test_files:
        with open(path, encoding="utf-8") as fh:
            for m in _IMPORT_RE.finditer(fh.read()):
                imported.add(m.group(1))
    test_stems = {os.path.basename(p)[len("test_"):-len(".mojo")]
                  for p in test_files
                  if os.path.basename(p).startswith("test_")}

    modules = [p for p in _mojo_files(SRC_DIR)
               if os.path.basename(p) != "__init__.mojo"]
    covered, uncovered = [], []
    for path in modules:
        dotted = _dotted(path)
        stem = os.path.basename(path)[:-len(".mojo")]
        hit = dotted in imported or stem in test_stems
        (covered if hit else uncovered).append(_dotted(path))

    total = len(modules) or 1
    print("== Test reference coverage (proxy, not line coverage) ==")
    print(f"  source modules    : {len(modules)}")
    print(f"  test files        : {len(test_files)}")
    print(f"  referenced by tests: {len(covered)} ({100 * len(covered) / total:.0f}%)")
    print(f"  not referenced     : {len(uncovered)}")
    if uncovered:
        print("\n  Not directly referenced by any test "
              "(often re-export shims / internal split modules):")
        for d in sorted(uncovered):
            print(f"    {d}")
    return len(uncovered)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("complexity", "all"):
        complexity()
    if which == "all":
        print()
    if which in ("coverage", "all"):
        coverage()


if __name__ == "__main__":
    main()
