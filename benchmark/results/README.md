# Benchmark results

Each run produces a directory under this folder named
`<YYYY-MM-DD>T<HHMM>-<host>-<commit>/` containing:

- `env.json` — hardware, OS/kernel, tuning knobs, exact toolchain versions
- `integrity.md` — byte-level body diff proof across all targets (must
  pass before any measurement rounds are recorded)
- `<target>-<workload>-<config>.json` — structured per-tuple result
  (runs, median, stdev, stable flag)
- `summary.md` — single-table view of all tuples in the run
- `RAW/` — verbatim wrk stdout for every run (`runN.txt`), plus server
  stdout/stderr captures

See `../../.cursor/rules/bench_vs_baseline.md` for the full methodology
(variance gates, CPU pinning, warmup protocol, result schema).

## Run a fresh comparison

```bash
pixi run --environment bench bench-vs-baseline
```

Narrow scope (useful while iterating perf):

```bash
pixi run --environment bench bench-vs-baseline-quick
pixi run --environment bench bench-vs-baseline -- --only=flare,go_nethttp
```

Pre-flight integrity check only (no measurement rounds):

```bash
pixi run --environment bench bench-integrity-only
```
