#!/usr/bin/env python3
"""Aggregate multiple ``h2load --npn-list=h3`` runs into a single
stable/unstable datapoint for the v0.8 HTTP/3 bench harness.

Usage:
    _stat_h3.py <out.json> <run1.txt> <run2.txt> ...

Where each ``runN.txt`` is the stdout of one h2load invocation +
the optional per-request log file lives next to it as
``runN.txt.log`` (a tab-separated ``starttime\tstatus\tlatency_us``
file written by ``h2load --log-file``).

Why two files: ``h2load`` prints aggregate summary stats
(``req/s``, ``time for request: min max mean sd``) but not
percentiles by default. The harness asks for ``--log-file``
specifically so we can compute the same p99 / p99.9 / p99.99
the h1 / h2 tables in :doc:`docs/benchmark.md` quote, with the
same coordinated-omission-corrected discipline.

Output JSON shape mirrors :mod:`_stat`: ``{runs:[...], summary:{...}}``
with per-percentile median + sample-stdev across the N runs so
downstream consumers can quote "p99 = X +/- Y ms" without
re-deriving variance.
"""

import json
import re
import statistics
import sys
from pathlib import Path


# h2load: ``finished in 12.34s, 1234567.89 req/s, ...``
RPS_RE = re.compile(r"finished in[^,]+,\s+([0-9]+(?:\.[0-9]+)?)\s+req/s", re.MULTILINE)
# h2load: ``requests: 100000 total, 100000 started, 100000 done, X succeeded, Y failed, Z errored, T timeout``
REQ_RE = re.compile(
    r"requests:\s+([0-9]+)\s+total,\s+[0-9]+\s+started,\s+[0-9]+\s+done,"
    r"\s+([0-9]+)\s+succeeded,\s+([0-9]+)\s+failed,\s+([0-9]+)\s+errored,"
    r"\s+([0-9]+)\s+timeout",
    re.MULTILINE,
)
# h2load: ``status codes: 100000 2xx, 0 3xx, 0 4xx, 0 5xx``
STATUS_RE = re.compile(
    r"status codes:\s+([0-9]+)\s+2xx,\s+([0-9]+)\s+3xx,\s+([0-9]+)\s+4xx,\s+([0-9]+)\s+5xx",
    re.MULTILINE,
)


def _percentile(values_sorted: list[float], pct: float) -> float:
    """Linear-interpolated percentile (NIST type 7); same shape
    as :func:`numpy.percentile` and the ``HdrHistogram`` quantile
    output the h1 / h2 harness reports."""
    if not values_sorted:
        return 0.0
    n = len(values_sorted)
    if n == 1:
        return values_sorted[0]
    rank = pct / 100.0 * (n - 1)
    lo = int(rank)
    hi = min(lo + 1, n - 1)
    frac = rank - lo
    return values_sorted[lo] + frac * (values_sorted[hi] - values_sorted[lo])


def _parse_log_file(path: Path) -> list[float]:
    """Parse h2load --log-file content into a sorted list of
    per-request latencies (milliseconds). Returns ``[]`` when the
    log file is missing or empty (e.g. h2load was rejected before
    finishing any requests)."""
    if not path.exists():
        return []
    latencies_ms: list[float] = []
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            us = int(parts[-1])
        except ValueError:
            continue
        if us < 0:
            continue
        latencies_ms.append(us / 1000.0)
    latencies_ms.sort()
    return latencies_ms


def _parse_run(stdout_path: Path) -> dict:
    """Parse one h2load stdout + matching log file into a
    structured record."""
    text = stdout_path.read_text(errors="replace")
    rps = 0.0
    m = RPS_RE.search(text)
    if m:
        rps = float(m.group(1))

    total = succ = fail = err = tout = 0
    rm = REQ_RE.search(text)
    if rm:
        total = int(rm.group(1))
        succ = int(rm.group(2))
        fail = int(rm.group(3))
        err = int(rm.group(4))
        tout = int(rm.group(5))

    status_2xx = status_3xx = status_4xx = status_5xx = 0
    sm = STATUS_RE.search(text)
    if sm:
        status_2xx = int(sm.group(1))
        status_3xx = int(sm.group(2))
        status_4xx = int(sm.group(3))
        status_5xx = int(sm.group(4))

    latencies = _parse_log_file(stdout_path.with_suffix(stdout_path.suffix + ".log"))
    p50 = _percentile(latencies, 50.0) if latencies else 0.0
    p99 = _percentile(latencies, 99.0) if latencies else 0.0
    p99_9 = _percentile(latencies, 99.9) if latencies else 0.0
    p99_99 = _percentile(latencies, 99.99) if latencies else 0.0
    p99_999 = _percentile(latencies, 99.999) if latencies else 0.0

    return {
        "req_per_sec": rps,
        "p50_ms": p50,
        "p99_ms": p99,
        "p99_9_ms": p99_9,
        "p99_99_ms": p99_99,
        "p99_999_ms": p99_999,
        "requests_total": total,
        "requests_succeeded": succ,
        "requests_failed": fail,
        "requests_errored": err,
        "requests_timeout": tout,
        "status_2xx": status_2xx,
        "status_3xx": status_3xx,
        "status_4xx": status_4xx,
        "status_5xx": status_5xx,
        "latency_samples": len(latencies),
    }


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(
            "usage: _stat_h3.py <out.json> <run1.txt> [run2.txt ...]",
            file=sys.stderr,
        )
        return 2

    out = Path(argv[1])
    runs: list[dict] = []
    for p in argv[2:]:
        r = _parse_run(Path(p))
        r["run"] = len(runs) + 1
        runs.append(r)

    rps_values = [r["req_per_sec"] for r in runs if r["req_per_sec"] > 0]

    def _median(field: str) -> float:
        vals = sorted(r[field] for r in runs if r[field] > 0)
        return statistics.median(vals) if vals else 0.0

    def _stdev(field: str) -> float:
        vals = [r[field] for r in runs if r[field] > 0]
        return statistics.stdev(vals) if len(vals) >= 2 else 0.0

    if len(rps_values) < 3:
        summary = {
            "median_req_per_sec": 0.0,
            "mean_req_per_sec": 0.0,
            "stdev_req_per_sec": 0.0,
            "stdev_pct": 100.0,
            "median_p50_ms": 0.0,
            "median_p99_ms": 0.0,
            "median_p99_9_ms": 0.0,
            "median_p99_99_ms": 0.0,
            "median_p99_999_ms": 0.0,
            "stdev_p50_ms": 0.0,
            "stdev_p99_ms": 0.0,
            "stdev_p99_9_ms": 0.0,
            "stdev_p99_99_ms": 0.0,
            "stdev_p99_999_ms": 0.0,
            "total_timeouts": sum(r["requests_timeout"] for r in runs),
            "total_errors": sum(
                r["requests_failed"] + r["requests_errored"] for r in runs
            ),
            "total_non_2xx": sum(
                r["status_3xx"] + r["status_4xx"] + r["status_5xx"] for r in runs
            ),
            "stable": False,
            "note": "too few valid runs for stats",
        }
    else:
        sorted_rps = sorted(rps_values)
        trimmed = sorted_rps[1:-1] if len(sorted_rps) >= 3 else sorted_rps
        median_rps = statistics.median(trimmed)
        mean_rps = statistics.mean(rps_values)
        stdev = statistics.stdev(rps_values) if len(rps_values) >= 2 else 0.0
        stdev_pct = (stdev / mean_rps * 100.0) if mean_rps > 0 else 100.0
        # 8% sigma honesty gate per benchmark/configs/h3_throughput.yaml
        # (QUIC pacing + RTT estimation has wider run-to-run
        # variance than h2-over-TCP).
        summary = {
            "median_req_per_sec": median_rps,
            "mean_req_per_sec": mean_rps,
            "stdev_req_per_sec": stdev,
            "stdev_pct": stdev_pct,
            "median_p50_ms": _median("p50_ms"),
            "median_p99_ms": _median("p99_ms"),
            "median_p99_9_ms": _median("p99_9_ms"),
            "median_p99_99_ms": _median("p99_99_ms"),
            "median_p99_999_ms": _median("p99_999_ms"),
            "stdev_p50_ms": _stdev("p50_ms"),
            "stdev_p99_ms": _stdev("p99_ms"),
            "stdev_p99_9_ms": _stdev("p99_9_ms"),
            "stdev_p99_99_ms": _stdev("p99_99_ms"),
            "stdev_p99_999_ms": _stdev("p99_999_ms"),
            "total_timeouts": sum(r["requests_timeout"] for r in runs),
            "total_errors": sum(
                r["requests_failed"] + r["requests_errored"] for r in runs
            ),
            "total_non_2xx": sum(
                r["status_3xx"] + r["status_4xx"] + r["status_5xx"] for r in runs
            ),
            "stable": stdev_pct < 8.0,
        }

    payload = {"runs": runs, "summary": summary}
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(
        f"  median={summary['median_req_per_sec']:,.0f} req/s "
        f"sigma={summary.get('stdev_req_per_sec', 0.0):,.0f} req/s "
        f"({summary['stdev_pct']:.2f}%) "
        f"p50={summary['median_p50_ms']:.2f}+/-{summary.get('stdev_p50_ms', 0.0):.2f}ms "
        f"p99={summary['median_p99_ms']:.2f}+/-{summary.get('stdev_p99_ms', 0.0):.2f}ms "
        f"p99.9={summary['median_p99_9_ms']:.2f}+/-{summary.get('stdev_p99_9_ms', 0.0):.2f}ms "
        f"p99.99={summary['median_p99_99_ms']:.2f}+/-{summary.get('stdev_p99_99_ms', 0.0):.2f}ms "
        f"stable={summary['stable']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
