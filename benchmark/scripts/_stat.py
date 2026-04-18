#!/usr/bin/env python3
"""Aggregate multiple wrk runs into a single stable/unstable datapoint.

Usage:
    _stat.py <out.json> <run1.txt> <run2.txt> ...

Reads each runN.txt (raw wrk stdout) and parses out:
  - Requests/sec
  - Latency 50%, 99%, max
  - Timeouts
  - Socket errors

Writes a JSON blob with runs[], median of middle N-2 runs, mean, stdev,
stdev_pct, and ``stable`` (True iff stdev_pct < 3.0).
"""

import json
import re
import statistics
import sys
from pathlib import Path


LAT_RE = re.compile(
    r"^\s*(?:Latency|50%|99%|Max)\s+([0-9.]+)(us|ms|s)?",
    re.MULTILINE,
)
RPS_RE = re.compile(r"^\s*Requests/sec:\s+([0-9.]+)", re.MULTILINE)
TIMEOUT_RE = re.compile(r"Socket errors:.*timeout\s+([0-9]+)")
ERR_RE = re.compile(
    r"Socket errors:\s+connect\s+([0-9]+),\s+read\s+([0-9]+),"
    r"\s+write\s+([0-9]+)"
)


def _ms(val: float, unit: str | None) -> float:
    """Normalise a latency value to milliseconds."""
    u = (unit or "ms").lower()
    if u == "us":
        return val / 1000.0
    if u == "s":
        return val * 1000.0
    return val


def _parse(text: str) -> dict:
    """Parse one wrk stdout blob into a structured dict."""
    rps = 0.0
    m = RPS_RE.search(text)
    if m:
        rps = float(m.group(1))

    p50 = p99 = latmax = 0.0
    # wrk --latency emits lines like:
    #     50%    1.23ms
    #     99%    3.45ms
    #    Max   12.00ms
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("50%"):
            parts = s.split()
            mval = re.match(r"^([0-9.]+)([a-z]*)", parts[1])
            if mval:
                p50 = _ms(float(mval.group(1)), mval.group(2))
        elif s.startswith("99%"):
            parts = s.split()
            mval = re.match(r"^([0-9.]+)([a-z]*)", parts[1])
            if mval:
                p99 = _ms(float(mval.group(1)), mval.group(2))
        elif s.startswith("Max"):
            parts = s.split()
            mval = re.match(r"^([0-9.]+)([a-z]*)", parts[1])
            if mval:
                latmax = _ms(float(mval.group(1)), mval.group(2))

    timeouts = 0
    tm = TIMEOUT_RE.search(text)
    if tm:
        timeouts = int(tm.group(1))

    socket_errors = 0
    em = ERR_RE.search(text)
    if em:
        socket_errors = int(em.group(1)) + int(em.group(2)) + int(em.group(3))

    return {
        "req_per_sec": rps,
        "p50_ms": p50,
        "p99_ms": p99,
        "max_ms": latmax,
        "timeouts": timeouts,
        "socket_errors": socket_errors,
    }


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: _stat.py <out.json> <run1.txt> [run2.txt ...]", file=sys.stderr)
        return 2

    out = Path(argv[1])
    run_paths = [Path(p) for p in argv[2:]]
    runs: list[dict] = []
    for p in run_paths:
        text = p.read_text(errors="replace")
        r = _parse(text)
        r["run"] = len(runs) + 1
        runs.append(r)

    rps_values = [r["req_per_sec"] for r in runs if r["req_per_sec"] > 0]
    if len(rps_values) < 3:
        summary = {
            "median_req_per_sec": 0.0,
            "mean_req_per_sec": 0.0,
            "stdev": 0.0,
            "stdev_pct": 100.0,
            "median_p50_ms": 0.0,
            "median_p99_ms": 0.0,
            "total_timeouts": sum(r["timeouts"] for r in runs),
            "total_socket_errors": sum(r["socket_errors"] for r in runs),
            "stable": False,
            "note": "too few valid runs for stats",
        }
    else:
        sorted_rps = sorted(rps_values)
        # Drop min + max, median of the middle.
        trimmed = sorted_rps[1:-1] if len(sorted_rps) >= 3 else sorted_rps
        median_rps = statistics.median(trimmed)
        mean_rps = statistics.mean(rps_values)
        stdev = statistics.stdev(rps_values) if len(rps_values) >= 2 else 0.0
        stdev_pct = (stdev / mean_rps * 100.0) if mean_rps > 0 else 100.0

        p50_values = sorted(r["p50_ms"] for r in runs if r["p50_ms"] > 0)
        p99_values = sorted(r["p99_ms"] for r in runs if r["p99_ms"] > 0)
        median_p50 = statistics.median(p50_values) if p50_values else 0.0
        median_p99 = statistics.median(p99_values) if p99_values else 0.0

        summary = {
            "median_req_per_sec": median_rps,
            "mean_req_per_sec": mean_rps,
            "stdev": stdev,
            "stdev_pct": stdev_pct,
            "median_p50_ms": median_p50,
            "median_p99_ms": median_p99,
            "total_timeouts": sum(r["timeouts"] for r in runs),
            "total_socket_errors": sum(r["socket_errors"] for r in runs),
            "stable": stdev_pct < 3.0,
        }

    payload = {"runs": runs, "summary": summary}
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(
        f"  median={summary['median_req_per_sec']:,.0f} req/s "
        f"stdev={summary['stdev_pct']:.2f}% "
        f"p50={summary['median_p50_ms']:.2f}ms "
        f"p99={summary['median_p99_ms']:.2f}ms "
        f"stable={summary['stable']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
