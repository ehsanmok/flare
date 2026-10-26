#!/usr/bin/env python3
"""Trust surface of the headline theorems.

For every theorem in the axiom audit (Flare/Audit.lean, Flare/Audit/*.lean),
list the Flare definitions its statement reaches (`#trust_surface`,
Flare/Core/TrustSurface.lean): what a reader has to read to believe the
claim. The proof is machine-checked; these definitions are not.

    trust_surface.py                 # summary: theorems by surface size
    trust_surface.py NAME [NAME...]  # the full surface of these theorems

The full listing for every audited theorem goes to formal/.lake/trust.txt.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

FORMAL = Path(__file__).resolve().parent.parent
OUT = FORMAL / ".lake" / "trust.txt"
LAKE = ["pixi", "run", "-e", "formal", "lake"]


def audited():
    names = []
    for f in [FORMAL / "Flare" / "Audit.lean", *sorted((FORMAL / "Flare" / "Audit").glob("*.lean"))]:
        names += re.findall(r"^#print axioms (\S+)", f.read_text(), re.M)
    return list(dict.fromkeys(names))


def surfaces(names):
    subprocess.run([*LAKE, "build", "Flare", "Flare.Core.TrustSurface"], cwd=FORMAL, check=True,
                   capture_output=True)
    src = "import Flare\nimport Flare.Core.TrustSurface\n" + "".join(f"#trust_surface {n}\n" for n in names)
    with tempfile.NamedTemporaryFile("w", suffix=".lean", dir=FORMAL / ".lake", delete=False) as f:
        f.write(src)
    try:
        r = subprocess.run([*LAKE, "env", "lean", f.name], cwd=FORMAL, capture_output=True, text=True)
    finally:
        Path(f.name).unlink()
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit("trust_surface: lean failed")
    out = {}
    for block in re.split(r"^(?=trust surface of )", r.stdout, flags=re.M):
        m = re.match(r"trust surface of (\S+) \((\d+)\):\n?(.*)", block, re.S)
        if m:
            out[m[1]] = [line.strip() for line in m[3].splitlines() if line.strip()]
    return out


def main():
    names = sys.argv[1:] or audited()
    res = surfaces(names)
    if sys.argv[1:]:
        for n, defs in res.items():
            print(f"{n} ({len(defs)}):")
            print("".join(f"  {d}\n" for d in defs), end="")
        return 0
    OUT.write_text("".join(f"{n} ({len(d)}):\n" + "".join(f"  {x}\n" for x in d) for n, d in res.items()))
    sizes = sorted(((len(d), n) for n, d in res.items()), reverse=True)
    print(f"trust surface: {len(res)} audited theorems; full listing in formal/.lake/trust.txt")
    print("largest:")
    for k, n in sizes[:10]:
        print(f"  {k:4}  {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
