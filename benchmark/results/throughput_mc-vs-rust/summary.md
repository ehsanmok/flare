# Benchmark summary

- Run: 2026-04-29T0519-ehsan-dev-1412801
- See env.json for hardware / toolchain versions.

| Target | Workload | Config | Req/s (median) | stdev% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| actix_web | plaintext | throughput_mc | 263970 | 0.21 | 1.19 | 2.84 | 21.06 | 26.74 | true |
| axum | plaintext | throughput_mc | 201003 | 0.17 | 1.29 | 2.84 | 3.29 | 6.81 | true |
| flare | plaintext | throughput_mc | 53589 | 0.21 | 0.97 | 2.04 | 2.39 | 2.67 | true |
| flare_mc | plaintext | throughput_mc | 146068 | 0.35 | 1.07 | 2.30 | 2.88 | 3.30 | true |
| hyper | plaintext | throughput_mc | 218702 | 0.27 | 1.24 | 2.80 | 3.25 | 3.64 | true |
