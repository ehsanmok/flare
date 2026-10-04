#!/usr/bin/env python3
"""Search the Lean sources under Flare/ with comments and string literals
blanked out, so doc text may mention "admit" or "axiom".

    code_grep.py REGEX [SKIP_PREFIX ...]

Prints `path:line: code` for each hit; exit 0 iff there was one.
"""

import os
import re
import sys


def code_only(src):
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
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(" " * (j + 1 - i))
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def main():
    pat, skip = re.compile(sys.argv[1]), tuple(sys.argv[2:])
    hit = False
    for root, _, files in os.walk("Flare"):
        for f in sorted(files):
            p = os.path.join(root, f)
            if not f.endswith(".lean") or (skip and p.startswith(skip)):
                continue
            with open(p, encoding="utf-8") as fh:
                code = code_only(fh.read())
            for k, line in enumerate(code.split("\n"), 1):
                if pat.search(line):
                    print(f"{p}:{k}: {line.strip()}")
                    hit = True
    sys.exit(0 if hit else 1)


if __name__ == "__main__":
    main()
