#!/usr/bin/env python3
"""Aggregate multiple wrk2 ``--latency`` runs into a single
stable/unstable datapoint.

Usage:
    _stat.py <out.json> <run1.txt> <run2.txt> ...

Reads each runN.txt (raw wrk2 stdout) and parses out:
  - Requests/sec (server-bottlenecked, since the harness drives
    wrk2 in saturate mode with a very high ``-R``).
  - Latency Distribution percentiles: 50, 75, 90, 99, 99.9,
    99.99, 99.999.
  - Timeouts.
  - Socket errors.

Writes a JSON blob with runs[], median of middle N-2 runs, mean,
stdev, stdev_pct, and ``stable`` (True iff stdev_pct < 3.0).

wrk2 ``--latency`` block looks like::

    Latency Distribution (HdrHistogram - Recorded Latency)
     50.000%    1.23ms
     75.000%    1.45ms
     90.000%    1.78ms
     99.000%    3.10ms
     99.900%    5.21ms
     99.990%    8.93ms
     99.999%   12.40ms
    100.000%   18.20ms

Match against the percentage prefix and capture the value + unit
on the same line.
"""

import json
import re
import statistics
import sys
from pathlib import Path


# wrk2 --latency: ``50.000%    1.23ms`` (note the trailing %.000).
LATENCY_RE = re.compile(
    r"^\s*([0-9]+(?:\.[0-9]+)?)%\s+([0-9]+(?:\.[0-9]+)?)(us|ms|s|m)\s*$",
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
    if u == "m":
        return val * 60_000.0
    return val


# Map nominal percentile -> output key. wrk2 prints them with 3
# decimals (50.000%, 99.900%, etc.); match within a tight epsilon.
_PCT_KEYS: list[tuple[float, str]] = [
    (50.0, "p50_ms"),
    (75.0, "p75_ms"),
    (90.0, "p90_ms"),
    (99.0, "p99_ms"),
    (99.9, "p99_9_ms"),
    (99.99, "p99_99_ms"),
    (99.999, "p99_999_ms"),
]


def _parse(text: str) -> dict:
    """Parse one wrk2 stdout blob into a structured dict."""
    rps = 0.0
    m = RPS_RE.search(text)
    if m:
        rps = float(m.group(1))

    out = {key: 0.0 for _, key in _PCT_KEYS}

    # wrk2 also prints a header section with ``Latency`` /
    # ``Req/Sec`` summary stats (in the ``Thread Stats`` block).
    # The percentile block we want is under
    # ``Latency Distribution (HdrHistogram - Recorded Latency)``;
    # wrk's older ``Latency Distribution`` block has the same
    # shape so the regex catches both.
    in_dist = False
    for line in text.splitlines():
        if "Latency Distribution" in line:
            in_dist = True
            continue
        if not in_dist:
            continue
        s = line.strip()
        if not s or s.startswith("Detailed"):
            in_dist = False
            continue
        m = LATENCY_RE.match("  " + s)  # add leading whitespace for the regex
        if not m:
            # Could be a non-percentile line like
            # ``HdrHistogram of 12345 entries`` or a blank.
            continue
        pct = float(m.group(1))
        val = float(m.group(2))
        unit = m.group(3)
        ms_val = _ms(val, unit)
        for nominal, key in _PCT_KEYS:
            if abs(pct - nominal) < 0.001:
                out[key] = ms_val
                break

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
        "p50_ms": out["p50_ms"],
        "p75_ms": out["p75_ms"],
        "p90_ms": out["p90_ms"],
        "p99_ms": out["p99_ms"],
        "p99_9_ms": out["p99_9_ms"],
        "p99_99_ms": out["p99_99_ms"],
        "p99_999_ms": out["p99_999_ms"],
        "timeouts": timeouts,
        "socket_errors": socket_errors,
    }


def main(argv: list[str]) -> int:
    # Optional --peak-rps <value> overrides the
    # median_req_per_sec calculation. The harness's two-phase
    # design measures peak capacity in a separate find-peak
    # run; the 5 measurement runs are at a fixed sub-peak rate
    # specifically to stress the latency tail. ``Requests/sec``
    # values inside those measurement runs all equal the fixed
    # rate, so a "median req/s" computed over them is
    # uninformative. Pass the peak in so the summary headlines
    # the capacity number.
    peak_rps_override: float | None = None
    args: list[str] = []
    i = 1
    while i < len(argv):
        if argv[i] == "--peak-rps" and i + 1 < len(argv):
            peak_rps_override = float(argv[i + 1])
            i += 2
            continue
        args.append(argv[i])
        i += 1

    if len(args) < 2:
        print(
            "usage: _stat.py [--peak-rps R] <out.json> <run1.txt> [run2.txt ...]",
            file=sys.stderr,
        )
        return 2

    out = Path(args[0])
    run_paths = [Path(p) for p in args[1:]]
    runs: list[dict] = []
    for p in run_paths:
        text = p.read_text(errors="replace")
        r = _parse(text)
        r["run"] = len(runs) + 1
        runs.append(r)

    rps_values = [r["req_per_sec"] for r in runs if r["req_per_sec"] > 0]

    def _median_of(field: str) -> float:
        vals = sorted(r[field] for r in runs if r[field] > 0)
        return statistics.median(vals) if vals else 0.0

    if len(rps_values) < 3:
        summary = {
            "median_req_per_sec": 0.0,
            "mean_req_per_sec": 0.0,
            "stdev": 0.0,
            "stdev_pct": 100.0,
            "median_p50_ms": 0.0,
            "median_p99_ms": 0.0,
            "median_p99_9_ms": 0.0,
            "median_p99_99_ms": 0.0,
            "median_p99_999_ms": 0.0,
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

        # Headline req/s is peak capacity (find-peak phase) when
        # the harness supplied it; otherwise fall back to the
        # median over measurement runs.
        headline_rps = (
            peak_rps_override if peak_rps_override is not None else median_rps
        )
        summary = {
            "median_req_per_sec": headline_rps,
            "peak_req_per_sec": peak_rps_override or 0.0,
            "sustain_req_per_sec": median_rps,
            "mean_req_per_sec": mean_rps,
            "stdev": stdev,
            "stdev_pct": stdev_pct,
            "median_p50_ms": _median_of("p50_ms"),
            "median_p99_ms": _median_of("p99_ms"),
            "median_p99_9_ms": _median_of("p99_9_ms"),
            "median_p99_99_ms": _median_of("p99_99_ms"),
            "median_p99_999_ms": _median_of("p99_999_ms"),
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
        f"p99.9={summary['median_p99_9_ms']:.2f}ms "
        f"p99.99={summary['median_p99_99_ms']:.2f}ms "
        f"stable={summary['stable']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
