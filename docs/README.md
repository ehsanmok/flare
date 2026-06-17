# flare docs

Long-form documentation for [flare](../README.md). The top-level
[`README.md`](../README.md) is a lean entry point. The files in this
directory carry the detail.

| Page | What's in it |
|---|---|
| [`features.md`](features.md) | Complete feature inventory across HTTP server / client, HTTP/2, WebSocket, TLS, sessions, middleware, extractors, runtime primitives, observability, configuration knobs, and stability guarantees. Each entry links to the source module and example. |
| [`architecture.md`](architecture.md) | Reactor + per-connection state machine + thread-per-core scheduler, with a request-lifecycle sequence diagram including the `Cancel` injection point, two listener strategies, and the HTTP/2 same-handler-different-wire compatibility contract. |
| [`benchmark.md`](benchmark.md) | Methodology, workloads, baselines, single-worker vs multi-worker tables, the listener-mode A/B (`EPOLLEXCLUSIVE` shared listener vs per-worker `SO_REUSEPORT`), and the soak harness for long-running operational gates (slow-client / churn / mixed-load). |
| [`build.md`](build.md) | Build modes (`-D ASSERT=none/safe/all/warn`), the sanitizer harness (`tests-asan` / `tests-tsan` / `tests-asserts-all`), production-build guidance, and contributor pattern for `debug_assert` on new FFI wrappers. |
| [`security.md`](security.md) | Per-layer security posture (including `flare.http2`'s `SETTINGS_ENABLE_PUSH=0`, RFC 9113 §9.1.1 same-origin enforcement, and ALPN refusal-to-downgrade), the sanitised-error-response policy, fuzz / soak budget. |
| [`tls-strategy.md`](tls-strategy.md) | The TLS backend choice (OpenSSL via FFI for TCP, rustls binding for QUIC (planned)), what stays out-of-tree, version + verification cadence. |
| [`threat-model.md`](threat-model.md) | Adversary classes (anonymous attacker, authenticated abuser, malicious peer), per-attack mitigations, non-goals, disclosure process, verification cadence. |
| [`operations.md`](operations.md) | Production runbook -- topology choices, TLS posture, health endpoints, graceful shutdown, observability, resource limits, common failure modes, container deployment, soak harness. |
| [`concurrency.md`](concurrency.md) | The Mojo closure-binding rules flare relies on, the cross-thread primitive surface (`Cancel`, `HandoffQueue`, `block_in_pool`), and the owned-by-one-thread invariant. |
| [`cookbook.md`](cookbook.md) | Index of files under `examples/{basic,intermediate,advanced}/` mapped to use cases. |

The public Mojo API is stable within a minor: patch releases never
break source for the same minor. Breaking changes only land at minor
bumps. Internal types (anything in `_*.mojo`, or anything in
`flare.runtime.*` not re-exported from the package barrel) carry no
stability guarantee.
