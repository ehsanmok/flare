# flare docs

Long-form documentation for [flare](../README.md). The top-level
[`README.md`](../README.md) is a lean entry point. The files in this
directory carry the detail.

| Page | What's in it |
|---|---|
| [`architecture.md`](architecture.md) | Reactor + per-connection state machine + thread-per-core scheduler, with a request-lifecycle sequence diagram including the v0.5 `Cancel` injection point. |
| [`benchmark.md`](benchmark.md) | Methodology, workloads, baselines, the v0.4.1 wrk numbers, and the v0.5 wrk2 / mixed-keepalive transition. |
| [`security.md`](security.md) | Per-layer security posture, the sanitised-error-response policy, fuzz / soak budget. |
| [`cookbook.md`](cookbook.md) | Index of `examples/NN_*.mojo` mapped to use cases. |

flare is **pre-1.0**. The public Mojo API is stable within a minor (a
`v0.5.x` patch never breaks `v0.5.0` source); breaking changes only land
at minor bumps. Internal types (anything in `_*.mojo` or anything
`flare.runtime.*` not re-exported from the package barrel) carry no
stability guarantee.

For the strategy doc that decides *which* version each piece of work
lands in, see `.cursor/rules/development.mdc` and `.cursor/rules/design-0.5.md`
in the repository.
