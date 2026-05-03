# flare docs

Long-form documentation for [flare](../README.md). The top-level
[`README.md`](../README.md) is a lean entry point. The files in this
directory carry the detail.

| Page | What's in it |
|---|---|
| [`architecture.md`](architecture.md) | Reactor + per-connection state machine + thread-per-core scheduler, with a request-lifecycle sequence diagram including the `Cancel` injection point, two listener strategies, and the HTTP/2 same-handler-different-wire compatibility contract. |
| [`benchmark.md`](benchmark.md) | Methodology, workloads, baselines, single-worker vs multi-worker tables, the listener-mode A/B (`EPOLLEXCLUSIVE` shared listener vs per-worker `SO_REUSEPORT`), and the soak harness for long-running operational gates (slow-client / churn / mixed-load). |
| [`security.md`](security.md) | Per-layer security posture (including `flare.http2`'s `SETTINGS_ENABLE_PUSH=0`, RFC 9113 §9.1.1 same-origin enforcement, and ALPN refusal-to-downgrade), the sanitised-error-response policy, fuzz / soak budget. |
| [`concurrency.md`](concurrency.md) | The Mojo closure-binding rules flare relies on, the cross-thread primitive surface (`Cancel`, `HandoffQueue`, `block_in_pool`), and the owned-by-one-thread invariant. |
| [`cookbook.md`](cookbook.md) | Index of `examples/NN_*.mojo` mapped to use cases. |

The public Mojo API is stable within a minor: patch releases never
break source for the same minor. Breaking changes only land at minor
bumps. Internal types (anything in `_*.mojo`, or anything in
`flare.runtime.*` not re-exported from the package barrel) carry no
stability guarantee.
