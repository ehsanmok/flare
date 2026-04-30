# Benchmark summary

- Run: 2026-04-30T0228-ehsan-dev-c84a119
- See env.json for hardware / toolchain versions.

| Target | Workload | Config | Req/s (median) | stdev% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| actix_web | plaintext | throughput_mc | 264691 | 0.17 | 1.19 | 2.80 | 11.44 | 21.61 | true |
| axum | plaintext | throughput_mc | 201042 | 0.21 | 1.29 | 2.82 | 3.27 | 3.65 | true |
| flare | plaintext | throughput_mc | 56086 | 0.32 | 1.21 | 2.70 | 3.16 | 3.54 | true |
| flare_mc | plaintext | throughput_mc | 170305 | 0.17 | 1.13 | 2.38 | 2.73 | 3.11 | true |
| go_nethttp | plaintext | throughput_mc | 35940 | 0.21 | 1.12 | 2.92 | 4.29 | 5.47 | true |
| hyper | plaintext | throughput_mc | 221349 | 0.17 | 1.24 | 2.82 | 3.28 | 3.67 | true |
| nginx | plaintext | throughput_mc | 63764 | 0.39 | 1.06 | 2.29 | 2.70 | 3.03 | true |
