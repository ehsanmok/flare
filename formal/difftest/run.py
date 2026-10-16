#!/usr/bin/env python3
"""Differential testing: Lean impl models (and specs) against the real Mojo.

For each target the runner generates inputs, runs the Lean oracle
(formal/Oracle, built as `flare-oracle`) and the target's Mojo driver
(formal/difftest/drivers/) on the same batch, and compares answers:

  drift   the Mojo answer differs from the Lean impl: the transliteration
          is out of date, or the code changed behaviour
  spec    the Lean impl differs from the Lean spec: a real bug candidate
  harness a driver or the oracle could not answer (BAD:...)

Each mismatch is delta-minimized and appended to regressions/<target>.txt,
which is replayed on every later run.

    run.py [--targets a,b] [--cases N] [--seed S] [--quick] [--json]
    run.py --affected [--staged | --base REV]   # targets touched by a change
    run.py --soak SECONDS                       # new seeds until time is up
    run.py --list

Exit status is 1 when any mismatch is found.
"""

import argparse
import hashlib
import json
import random
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FORMAL = HERE.parent
REPO = FORMAL.parent
sys.path[:0] = [str(HERE), str(FORMAL / "scripts")]

import anchors  # noqa: E402
from targets import TARGETS  # noqa: E402

ORACLE = FORMAL / ".lake" / "build" / "bin" / "flare-oracle"
WORK = FORMAL / ".lake" / "difftest"
DRIVERS = HERE / "drivers"
REGRESS = HERE / "regressions"


def sh(cmd, cwd=REPO):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"difftest: command failed: {' '.join(map(str, cmd))}")
    return r.stdout


# ── Builds ──────────────────────────────────────────────────────────────────


def build_oracle():
    sh(["pixi", "run", "-e", "formal", "lake", "build", "flare-oracle"], cwd=FORMAL)
    names = sh([str(ORACLE), "--list"]).split()
    if set(names) != set(TARGETS):
        raise SystemExit(f"difftest: Oracle/Registry.lean and targets.py disagree: "
                         f"{sorted(set(names) ^ set(TARGETS))}")


def _sources_digest(driver):
    h = hashlib.sha256()
    for p in [DRIVERS / f"{driver}.mojo", DRIVERS / "_dtio.mojo", *sorted((REPO / "flare").rglob("*.mojo"))]:
        h.update(p.as_posix().encode() + p.read_bytes())
    return h.hexdigest()


def build_driver(driver):
    out = WORK / "bin" / driver
    stamp = out.with_suffix(".stamp")
    digest = _sources_digest(driver)
    if out.exists() and stamp.exists() and stamp.read_text() == digest:
        return out
    out.parent.mkdir(parents=True, exist_ok=True)
    sh(["pixi", "run", "mojo", "build", "-I", ".", str(DRIVERS / f"{driver}.mojo"), "-o", str(out)])
    stamp.write_text(digest)
    return out


# ── Inputs ──────────────────────────────────────────────────────────────────

SPECIAL = [0x00, 0x01, 0x1F, 0x3F, 0x40, 0x7E, 0x7F, 0x80, 0x81, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF,
           0xE0, 0xED, 0xEF, 0xF0, 0xF4, 0xF5, 0xF8, 0xFE, 0xFF]


def _byte(r):
    return r.choice(SPECIAL) if r.random() < 0.3 else r.randrange(256)


def g_bytes(r, m):
    return bytes(_byte(r) for _ in range(r.randint(0, m)))


def g_text(r, m):
    alpha = b"abcdefghijklmnopqrstuvwxyz0123456789-_.:/?=&%; ,\"'"
    out = bytearray()
    for _ in range(r.randint(0, m)):
        x = r.random()
        out.append(r.choice(alpha) if x < 0.6 else r.randrange(0x20, 0x7F) if x < 0.85 else _byte(r))
    return bytes(out)


def _boundaries(bits):
    out = set()
    for k in range(bits + 1):
        for d in (-1, 0, 1):
            v = (1 << k) + d
            if 0 <= v < (1 << bits):
                out.add(v)
    return sorted(out)


def g_hpack_int_decode(r, m):
    nsel = r.randrange(8)
    pref = (1 << (nsel + 1)) - 1
    first = (pref if r.random() < 0.7 else r.randrange(pref + 1)) | (r.randrange(256) & ~pref & 0xFF)
    cont = []
    for i in range(r.randint(0, max(0, m - 2))):
        more = r.random() < 0.8
        cont.append((r.choice([0x00, 0x7F, r.randrange(128)])) | (0x80 if more else 0))
        if not more:
            break
    return bytes([nsel | (r.randrange(32) << 3), first, *cont])


def g_hpack_int_encode(r, m):
    nsel = r.randrange(8)
    n = nsel + 1
    base = (1 << n) - 1
    pool = [base - 1, base, base + 1, base + 127, base + 128, (1 << 31) - 1, 1 << 31, (1 << 31) + 1,
            (1 << 32) - 1] + [x for x in _boundaries(32) if r.random() < 0.2]
    v = r.choice(pool) if r.random() < 0.6 else r.randrange(1 << r.randint(1, 32))
    return bytes([nsel, r.randrange(256)]) + max(0, v).to_bytes(4, "big")


def g_quic_decode(r, m):
    tag = r.randrange(4)
    ln = (1, 2, 4, 8)[tag]
    body = bytes([(tag << 6) | r.randrange(64)]) + bytes(_byte(r) for _ in range(ln - 1))
    x = r.random()
    if x < 0.15:
        body = body[: r.randrange(len(body) + 1)]
    elif x < 0.3:
        body += bytes(_byte(r) for _ in range(r.randint(1, 2)))
    return body[:m]


def g_quic_encode(r, m):
    pool = _boundaries(64) + [63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1, 1 << 62]
    v = r.choice(pool) if r.random() < 0.5 else r.randrange(1 << r.randint(1, 64))
    return v.to_bytes(8, "big")


def _enc_cp(cp):
    if cp < 0x80:
        return bytes([cp])
    if cp < 0x800:
        return bytes([0xC0 | cp >> 6, 0x80 | cp & 0x3F])
    if cp < 0x10000:
        return bytes([0xE0 | cp >> 12, 0x80 | cp >> 6 & 0x3F, 0x80 | cp & 0x3F])
    return bytes([0xF0 | cp >> 18 & 0x07, 0x80 | cp >> 12 & 0x3F, 0x80 | cp >> 6 & 0x3F, 0x80 | cp & 0x3F])


def g_utf8(r, m):
    target, out = r.randint(0, m), bytearray()
    while len(out) < target:
        x = r.random()
        if x < 0.25:
            out += _enc_cp(r.randrange(0x80))
        elif x < 0.45:
            out += _enc_cp(r.choice([0x80, 0x7FF, 0x800, 0xD7FF, 0xD800, 0xDFFF, 0xE000, 0xFFFD, 0xFFFF,
                                     0x10000, 0x10FFFF, 0x110000, 0x13FFFF]))
        elif x < 0.65:
            out += _enc_cp(r.randrange(0x80, 0x140000))
        elif x < 0.75:  # overlong forms
            cp = r.randrange(0x80)
            out += r.choice([bytes([0xC0 | cp >> 6, 0x80 | cp & 0x3F]),
                             bytes([0xE0, 0x80 | cp >> 6, 0x80 | cp & 0x3F])])
        elif x < 0.85:  # truncated multi-byte sequence
            out += _enc_cp(r.randrange(0x80, 0x10FFFF))[:-1]
        else:
            out.append(_byte(r))
    return bytes(out[:m])


CHUNK_CAP = 4096


def _chunk_line(r, body, cuts, at):
    """A chunk-size or trailer line, sometimes padded to the CHUNK_LINE_MAX
    boundary; `cuts` collects truncation points around its CRLF (a line
    split right after CR is where the cap is easy to get off by one)."""
    if r.random() < 0.1:
        pad = CHUNK_CAP + r.choice([-1, 0, 1, 2]) - len(body) - 1
        body += b";" + b"x" * max(0, pad)
        cuts.extend(at + len(body) + d for d in (0, 1))
    return body


def g_chunked(r, m):
    """byte 0: max_body selector, byte 1: start cursor, then a chunked body
    (valid, then often truncated or perturbed)."""
    out, cuts = bytearray(), []
    for _ in range(r.choice([0, 1, 1, 2, 3])):
        size = r.choice([1, 2, 5, 15, 16, 17, 255]) if r.random() < 0.7 else r.randrange(64)
        digits = format(size, "x")
        digits = digits.upper() if r.random() < 0.3 else digits
        digits = "0" * r.choice([0, 0, 0, 1, 3]) + digits
        ext = r.choice([b"", b"", b";a=b", b"; q", b';n="v"'])
        out += _chunk_line(r, digits.encode() + ext, cuts, len(out)) + b"\r\n"
        out += bytes(r.choice(b"abcxyz\r\n") for _ in range(size)) + b"\r\n"
    out += _chunk_line(r, b"0" + r.choice([b"", b";e"]), cuts, len(out)) + b"\r\n"
    for _ in range(r.choice([0, 0, 1, 2])):
        out += _chunk_line(r, r.choice([b"X: y", b"Trailer-A: 1", b"k:"]), cuts, len(out)) + b"\r\n"
    out += b"\r\n"
    if r.random() < 0.15:
        out += b"GET / HTTP/1.1\r\n"
    x = r.random()
    if cuts and x < 0.5:
        del out[r.choice(cuts):]
    elif x < 0.25:
        del out[r.randrange(len(out) + 1):]
    elif x < 0.5:
        i = r.randrange(len(out))
        out[i] = r.choice([10, 13, 59, 48, 102, 71, 32, 9, _byte(r)])
    elif x < 0.6:
        out.insert(r.randrange(len(out) + 1), 10)
    return bytes([r.randrange(256), r.choice([0, 0, 0, r.randrange(8)])]) + bytes(out[: m - 2])


H2_PSEUDO = [b"\x82", b"\x83", b"\x84", b"\x86", b"\x87", b"\x41\x01a", b"\x41\x81\x1f", b"\x01\x00",
             b"\x04\x00", b"\x10\x07:status\x03200"]
H2_VALID = [b"\x5c\x015", b"\x0f\x0d\x0210", b"\x40\x01x\x01y", b"\x40\x02te\x08trailers", b"\x90",
            b"\x7a\x01z", b"\xbe", b"\x20\x3f\xe1\x1f", b"\x40\x01x\x81\x1f", b"\x0f\x0d\x015"]
H2_INVALID = [b"\x40\x01X\x01y", b"\x40\x0aconnection\x02hi", b"\x20", b"\x3f\xe1\x1f", b"\x00\x00\x00",
              b"\xff\xff\xff\xff", b"\x40\x02te\x01x"]
H2_REGULAR = H2_VALID * 3 + H2_INVALID
H2_FIELDS = H2_PSEUDO + H2_REGULAR
H2_SIDS = [1, 1, 1, 3, 3, 5, 0, 2, 7, 255]


def _h2(ty, flags, sid, payload):
    return bytes([ty, flags, sid, len(payload)]) + payload[:255]


def _h2_block(r):
    if r.random() < 0.7:
        fs = [b"\x82", b"\x84", b"\x87", b"\x41\x01a"]
        fs += [r.choice(H2_REGULAR if r.random() < 0.85 else H2_PSEUDO) for _ in range(r.choice([0, 0, 1, 2]))]
        if r.random() < 0.3:
            r.shuffle(fs)
    else:
        fs = [r.choice(H2_FIELDS) for _ in range(r.randint(0, 4))]
    return b"".join(fs)


def _h2_padded(r, flags, body, prio=b""):
    if not flags & 8:
        return prio + body
    tail = bytes(r.choice([0, 1, 3]))
    pad = len(tail)
    if r.random() < 0.2:
        pad = len(prio) + len(body) + len(tail) + r.choice([-1, 0, 1])
    return bytes([max(0, min(pad, 255))]) + prio + body + tail


def _h2_frame(r, live):
    """One frame; `live` is the generator's list of opened stream ids. Most
    frames are well-formed and aimed at a live stream so traces get deep."""
    k = r.random()
    noise = r.random() < 0.12
    if not live and not noise:
        k = 0.0
    sid = r.choice(H2_SIDS) if noise or not live else r.choice(live)
    if k < 0.3:
        if not noise and (not live or r.random() < 0.6):
            sid = (max(live) + 2) if live else 1
            live.append(sid)
        blk = _h2_block(r)
        cut = r.randrange(len(blk) + 1) if blk and r.random() < 0.25 else None
        flags = r.choice([4, 4, 5, 1]) | (8 if r.random() < 0.15 else 0) | (0x20 if r.random() < 0.15 else 0)
        if cut is not None:
            flags &= ~4
        elif not flags & 4 and r.random() < 0.7:
            cut = len(blk)
        prio = (bytes([0, 0, 0, r.choice([0, 0, sid, 3])]) + b"\x10") if flags & 0x20 else b""
        out = _h2(1, flags, sid, _h2_padded(r, flags, blk[:cut] if cut is not None else blk, prio))
        if cut is not None:
            out += _h2(9, r.choice([4, 4, 4, 0]), sid if r.random() < 0.9 else 3, blk[cut:])
        return out
    if k < 0.5:
        flags = r.choice([0, 1, 1]) | (8 if r.random() < 0.2 else 0)
        body = bytes(r.choice([0, 1, 5, 100, 250]))
        return _h2(0, flags, sid, _h2_padded(r, flags, body))
    if k < 0.62:
        if r.random() < 0.15:
            return _h2(4, 1, 0 if not noise else r.choice([0, 1]), bytes(0 if not noise else 6))
        pairs = b""
        for _ in range(r.choice([0, 1, 1, 2])):
            ident = r.choice([1, 2, 3, 4, 4, 5, 6, 8, 0x99])
            val = r.choice([0, 1, 10, 100, 16384, 65535, 70000] if not noise else
                           [2, 16383, (1 << 31) - 1, 1 << 31, 1 << 24])
            if ident in (2, 8) and not noise:
                val &= 1
            pairs += ident.to_bytes(2, "big") + val.to_bytes(4, "big")
        if noise and pairs:
            pairs = pairs[:-1]
        return _h2(4, 0, 0 if not noise else 1, pairs)
    if k < 0.74:
        inc = r.choice([1, 10, 65535, 100000] if not noise else [0, (1 << 31) - 1])
        p = inc.to_bytes(4, "big")
        return _h2(8, 0, r.choice([0, sid]), p if r.random() < 0.95 else p[:3])
    if k < 0.8:
        return _h2(3, 0, sid, r.choice([0, 1, 8]).to_bytes(4, "big")[: 3 if noise and r.random() < 0.5 else 4])
    if k < 0.86:
        dep = r.choice([0, sid, 3])
        return _h2(2, 0, sid, (bytes([0, 0, 0, dep]) + b"\x10")[: 4 if noise and r.random() < 0.5 else 5])
    if k < 0.92:
        return _h2(6, r.choice([0, 0, 1]), 1 if noise else 0, bytes(7 if noise and r.random() < 0.5 else 8))
    if k < 0.94:
        return _h2(7, 0, r.choice([0, 0, 1]), bytes(8))
    return _h2(r.choice([5, 9, 0x0a, 0x20]), r.choice([0, 4]), sid, bytes(r.choice([0, 4])))


def g_h2(r, m):
    """A server's view of a client: SETTINGS first (usually), then a mix of
    request HEADERS (sometimes split over CONTINUATION, padded or with
    priority), DATA, SETTINGS, WINDOW_UPDATE, RST_STREAM, PRIORITY, PING,
    GOAWAY and unexpected frames. Records as in formal/Oracle/H2.lean."""
    out = bytearray(_h2(4, 0, 0, b"") if r.random() < 0.8 else b"")
    live = []
    for _ in range(r.randint(1, 12)):
        out += _h2_frame(r, live)
    if r.random() < 0.05 and out:
        out[r.randrange(len(out))] = _byte(r)
    return bytes(out[:m])


GENERATORS = {"bytes": g_bytes, "text": g_text, "hpack_int_decode": g_hpack_int_decode,
              "hpack_int_encode": g_hpack_int_encode, "quic_decode": g_quic_decode,
              "quic_encode": g_quic_encode, "utf8": g_utf8, "chunked": g_chunked, "h2": g_h2}

_SEED_RE = re.compile(r'_bytes\("((?:[^"\\]|\\.)*)"\)')


def fuzz_seeds(files):
    out = []
    for f in files:
        p = REPO / "fuzz" / f
        if not p.exists():
            continue
        for lit in _SEED_RE.findall(p.read_text()):
            try:
                out.append(lit.encode("latin-1").decode("unicode_escape").encode("latin-1"))
            except (UnicodeError, ValueError):
                continue
    return out


def mutate(r, data, m):
    b = bytearray(data)
    for _ in range(r.randint(1, 3)):
        op = r.randrange(6)
        if op == 0 and b:
            i = r.randrange(len(b))
            b[i] ^= 1 << r.randrange(8)
        elif op == 1 and b:
            b[r.randrange(len(b))] = _byte(r)
        elif op == 2:
            b.insert(r.randint(0, len(b)), _byte(r))
        elif op == 3 and b:
            del b[r.randrange(len(b))]
        elif op == 4 and b:
            del b[r.randint(0, len(b) - 1):]
        elif op == 5 and b:
            i = r.randrange(len(b))
            b[i:i] = b[i: i + r.randint(1, 4)]
    return bytes(b[:m])


def regressions(name):
    p = REGRESS / f"{name}.txt"
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        h = line.split("#", 1)[0].strip()
        if re.fullmatch(r"(?:[0-9a-f]{2})*", h):
            out.append(bytes.fromhex(h))
    return out


def gen_cases(name, n, r):
    t = TARGETS[name]
    m, gen = t["max_len"], GENERATORS[t["gen"]]
    cases = list(regressions(name))
    seeds = fuzz_seeds(t.get("fuzz", []))
    cases += [s[:m] for s in seeds]
    if "derive" in t:
        src = TARGETS[t["derive"]]
        raw = [GENERATORS[src["gen"]](r, src["max_len"]) for _ in range(n)]
        for (impl, _spec) in oracle([(t["derive"], x) for x in raw]):
            if impl.startswith("OK:"):
                enc = bytes.fromhex(impl[3:])
                cases.append(enc if r.random() < 0.5 else mutate(r, enc, m))
    while len(cases) < n:
        x = r.random()
        if seeds and x < 0.15:
            cases.append(mutate(r, r.choice(seeds), m))
        elif cases and x < 0.25:
            cases.append(mutate(r, r.choice(cases), m))
        else:
            cases.append(gen(r, m))
    return cases


# ── Running both sides ──────────────────────────────────────────────────────


def _batch(cases):
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", dir=WORK, delete=False)
    f.write("".join(f"{name}\t{data.hex()}\n" for name, data in cases))
    f.close()
    return Path(f.name)


def oracle(cases):
    if not cases:
        return []
    WORK.mkdir(parents=True, exist_ok=True)
    inp = _batch(cases)
    out = inp.with_suffix(".lean")
    sh([str(ORACLE), str(inp), str(out)])
    rows = [tuple(line.split("\t", 1)) for line in out.read_text().splitlines()]
    inp.unlink()
    out.unlink()
    return rows


def mojo(cases):
    by_driver = {}
    for i, (name, data) in enumerate(cases):
        by_driver.setdefault(TARGETS[name]["driver"], []).append((i, name, data))
    answers = [None] * len(cases)
    for driver, items in by_driver.items():
        exe = build_driver(driver)
        inp = _batch([(n, d) for _, n, d in items])
        out = inp.with_suffix(".mojo")
        sh([str(exe), str(inp), str(out)])
        for (i, _, _), line in zip(items, out.read_text().splitlines()):
            answers[i] = line
        inp.unlink()
        out.unlink()
    return answers


def classify(impl, spec, got):
    if impl.startswith("BAD") or got is None or got.startswith("BAD"):
        return "harness"
    if got != impl:
        return "drift"
    if spec != "-" and spec != impl:
        return "spec"
    return None


def evaluate(cases):
    lean = oracle(cases)
    got = mojo(cases)
    return [(c, impl, spec, g, classify(impl, spec, g)) for c, (impl, spec), g in zip(cases, lean, got)]


MINIMIZE_SECONDS = 30


def minimize(name, data, kind):
    """Delta debugging: cut chunks of halving size, then zero chunks, keeping
    any candidate that still shows the same kind of mismatch. Gives up after
    MINIMIZE_SECONDS with the smallest input found so far."""
    cur, deadline = data, time.monotonic() + MINIMIZE_SECONDS

    def smallest(cands):
        cands = [c for c in dict.fromkeys(cands) if c != cur]
        if not cands:
            return None
        ok = [row[0][1] for row in evaluate([(name, c) for c in cands]) if row[4] == kind]
        return min(ok, key=lambda c: (len(c), c)) if ok else None

    for op in ("cut", "zero"):
        k = max(1, len(cur) // 2)
        while k >= 1 and time.monotonic() < deadline:
            starts = range(0, len(cur), k)
            if op == "cut":
                cands = [cur[:i] + cur[i + k:] for i in starts]
            else:
                cands = [cur[:i] + bytes(len(cur[i:i + k])) + cur[i + k:] for i in starts if any(cur[i:i + k])]
            best = smallest(cands)
            if best is None:
                k //= 2
            else:
                cur = best
                k = min(k, max(1, len(cur) // 2))
    return cur


def record(name, data, impl, spec, got, kind):
    REGRESS.mkdir(exist_ok=True)
    p = REGRESS / f"{name}.txt"
    known = {d.hex() for d in regressions(name)}
    if data.hex() in known:
        return False
    with p.open("a") as f:
        f.write(f"{data.hex()}  # {kind}: mojo={got} lean={impl} spec={spec} ({time.strftime('%Y-%m-%d')})\n")
    return True


# ── Target selection ────────────────────────────────────────────────────────


def affected(staged, base):
    if staged:
        cur, ref = ":", "HEAD"
        files = set(sh(["git", "diff", "--cached", "--name-only"]).split())
    else:
        cur, ref = None, base
        files = set(sh(["git", "diff", "--name-only", base]).split())
    shared = {"formal/difftest/drivers/_dtio.mojo", "formal/difftest/targets.py", "formal/difftest/run.py"}
    harness = bool(files & shared) or any(f.startswith("formal/Oracle/") for f in files)
    out = []
    for name, t in TARGETS.items():
        hit = harness or f"formal/difftest/drivers/{t['driver']}.mojo" in files
        hit = hit or any(f"formal/{m}" in files for m in t["models"])
        for s in t["symbols"]:
            path, _, names = s.partition("#")
            if path in files and (anchors.anchor_hash(path, names.split("+"), ref)
                                  != anchors.anchor_hash(path, names.split("+"), cur)):
                hit = True
        if hit:
            out.append(name)
    return out


# ── Main ────────────────────────────────────────────────────────────────────


def run_round(names, n, seed, quiet=False):
    r = random.Random(seed)
    cases = [(name, d) for name in names for d in gen_cases(name, n, r)]
    rows = evaluate(cases)
    summary = {name: {"cases": 0, "drift": 0, "spec": 0, "harness": 0} for name in names}
    bad = []
    for (name, data), impl, spec, got, kind in rows:
        summary[name]["cases"] += 1
        if kind:
            summary[name][kind] += 1
            bad.append((name, data, impl, spec, got, kind))
    found = []
    seen = set()
    for name, data, impl, spec, got, kind in bad:
        if (name, kind) in seen or kind == "harness":
            if kind == "harness" and (name, kind) not in seen:
                found.append({"target": name, "kind": kind, "input": data.hex(), "mojo": got, "lean": impl})
                seen.add((name, kind))
            continue
        seen.add((name, kind))
        small = minimize(name, data, kind)
        (_, impl2, spec2, got2, _), = evaluate([(name, small)])
        new = record(name, small, impl2, spec2, got2, kind)
        found.append({"target": name, "kind": kind, "input": small.hex(), "mojo": got2, "lean": impl2,
                      "spec": spec2, "new": new})
    if not quiet:
        for name, s in summary.items():
            flag = "ok" if not (s["drift"] or s["spec"] or s["harness"]) else "MISMATCH"
            print(f"{flag:8} {name:20} {s['cases']:6} cases  drift={s['drift']} spec={s['spec']} "
                  f"harness={s['harness']}")
        for f in found:
            print(f"  {f['kind'].upper()} {f['target']} input={f['input'] or '(empty)'}: "
                  f"mojo={f['mojo']} lean={f['lean']}" + (f" spec={f.get('spec')}" if f.get("spec") else ""))
    return summary, found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets")
    ap.add_argument("--cases", type=int, default=3000)
    ap.add_argument("--quick", action="store_true", help="1000 cases per target")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--affected", action="store_true")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--staged", action="store_true")
    g.add_argument("--base", default=None)
    ap.add_argument("--soak", type=int, metavar="SECONDS")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for name, t in TARGETS.items():
            print(f"{name:20} {t['driver']:16} {' '.join(t['symbols'])}")
        return 0
    if args.affected:
        names = affected(args.staged, args.base or "HEAD")
        if not names:
            print("difftest: no target affected")
            return 0
    elif args.targets:
        names = args.targets.split(",")
        unknown = [n for n in names if n not in TARGETS]
        if unknown:
            raise SystemExit(f"difftest: unknown target(s) {unknown}")
    else:
        names = list(TARGETS)

    WORK.mkdir(parents=True, exist_ok=True)
    if not args.no_build:
        build_oracle()
        for d in sorted({TARGETS[n]["driver"] for n in names}):
            build_driver(d)
    n = 1000 if args.quick else args.cases
    seed = args.seed if args.seed is not None else int(time.time())
    print(f"difftest: {len(names)} target(s), {n} cases each, seed {seed}")
    total, found = {}, []
    deadline = time.time() + (args.soak or 0)
    rnd = 0
    while True:
        summary, f = run_round(names, n, seed + rnd, quiet=bool(args.soak) and rnd > 0)
        for k, v in summary.items():
            acc = total.setdefault(k, {"cases": 0, "drift": 0, "spec": 0, "harness": 0})
            for kk in acc:
                acc[kk] += v[kk]
        found += f
        rnd += 1
        if not args.soak or time.time() >= deadline:
            break
    if args.soak:
        print(f"soak: {rnd} round(s), {sum(v['cases'] for v in total.values())} cases, "
              f"{len(found)} mismatch(es)")
    result = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "seed": seed, "rounds": rnd,
              "targets": total, "mismatches": found}
    (WORK / "last.json").write_text(json.dumps(result, indent=2))
    if args.json:
        print(json.dumps(result, indent=2))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
