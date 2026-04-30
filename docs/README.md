# flare docs

Long-form documentation for [flare](../README.md). The top-level
[`README.md`](../README.md) is a lean entry point. The files in this
directory carry the detail.

| Page | What's in it |
|---|---|
| [`architecture.md`](architecture.md) | Reactor + per-connection state machine + thread-per-core scheduler, with a request-lifecycle sequence diagram including the `Cancel` injection point. |
| [`benchmark.md`](benchmark.md) | Methodology, workloads, baselines, single-worker vs multi-worker tables, and the soak harness for long-running operational gates (slow-client / churn / mixed-load). |
| [`security.md`](security.md) | Per-layer security posture, the sanitised-error-response policy, fuzz / soak budget. |
| [`cookbook.md`](cookbook.md) | Index of `examples/NN_*.mojo` mapped to use cases. |

The public Mojo API is stable within a minor: patch releases never
break source for the same minor. Breaking changes only land at minor
bumps. Internal types (anything in `_*.mojo`, or anything in
`flare.runtime.*` not re-exported from the package barrel) carry no
stability guarantee.
