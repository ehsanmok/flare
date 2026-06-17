# Operations

Running flare in production. This page is the short, opinionated
counterpart to [`security.md`](security.md) and
[`benchmark.md`](benchmark.md): what to wire up, what to monitor,
and what to do when something looks wrong.

The goal of this page is *not* a tour of every knob. It is the
minimum set of things you must own before flare is in front of
users.

## Sizing + topology

| Mode | When to pick it | Knob |
|---|---|---|
| Single worker | < 5 k req/s, or you genuinely care about ordering across requests. | `HttpServer.serve(handler)` |
| Multi worker, `SO_REUSEPORT` | Default for > 5 k req/s. Each worker has its own listener + reactor; kernel hashes accepts across them. Best p99 / p99.99 in heterogeneous workloads. | `HttpServer.serve(handler, num_workers=N)` |
| Multi worker, shared listener (`EPOLLEXCLUSIVE`) | When you want a single accept queue and willing to tolerate a small p99.99 bump under skewed keep-alive. | `HttpServer.serve_shared_listener(...)` |
| Multi listener | Same handler exposed on multiple addresses (IPv4 + IPv6, public + UDS, etc). | `HttpServer.bind_many([SocketAddr.localhost(80), ...])` |

Sizing rule of thumb: start with `num_workers =
runtime.scheduler.physical_core_count()` and *do not* oversubscribe.
flare is thread-per-core; SMT siblings hurt tail latency more than
they help median.

## TLS

- ALPN advertised on wss:// is `["http/1.1"]` today (the
  `WsClient.connect_prefer_h2` factory is the opt-in route to
  `["h2", "http/1.1"]`; see [`features.md`](features.md)).
- `HttpClient` over `https://` advertises both and dispatches on
  the server's selection (RFC 7301).
- The TLS layer uses the host's OpenSSL. Pin the openssl pixi
  package version with the same caution you'd apply to nginx.
- Certificate reload without dropping connections:
  ``TlsAcceptor.reload(...)`` swaps the certificate atomically.
  Worked example: [`examples/advanced/cert_reload.mojo`](../examples/advanced/cert_reload.mojo).
- Backend rationale + planned rustls-for-QUIC direction:
  [`tls-strategy.md`](tls-strategy.md).

## Health endpoints

flare does not ship a built-in `/healthz`. The intentional
shape:

```mojo
def healthz(req: Request) raises -> Response:
    return Response(200, "ok\n")

var app = App[Unit]()
app.get("/healthz", healthz)
```

Two reasons for the explicit choice:

1. The probe URL is part of *your* contract with your load
   balancer / k8s probe / Datadog agent. flare cannot guess
   whether you want `/healthz`, `/health`, `/_health`, or
   `/__/health`.
2. The probe semantics (is the worker pool ready? is a
   downstream dependency up?) belong to the application, not
   the framework. The 200-OK echo above is the contract; deepen
   it as your service requires.

## Graceful shutdown

`HttpServer.serve()` honours `SIGINT` and `SIGTERM`. On signal:

1. The listener is closed (no new accepts).
2. Active connections drain through `Cancel` cells: each handler
   in flight receives a cooperative cancellation token and is
   given up to `server_config.shutdown_grace_ms` (default 5 s)
   to finish.
3. Connections that exceed the grace window are RST'd; the
   handler's `Cancel.is_cancelled()` will be `True` for the
   final response.

For zero-downtime deploys behind a load balancer:

1. Stop sending traffic at the LB.
2. Send `SIGTERM` to the old flare process.
3. Wait for the process to exit (its grace window must be
   longer than the longest p99.9 handler).
4. Start the new flare process.

If you do not have a load balancer in front, flare-via-pixi
processes are not a hot-restart story. Run two ports and an
`iptables` flip, or run behind nginx.

## Observability

flare ships three layers, all opt-in. Mix them as needed.

| Layer | What it gives you | Source |
|---|---|---|
| `RequestId[Inner]` | A per-request ID injected into every log line and echoed in `X-Request-Id` on the response. | [`flare.http.middleware`](../flare/http/middleware.mojo) |
| `StructuredLogger[Inner]` | One JSON object per response on stdout (method, path, status, duration_us, request_id). Wire to your log shipper directly. | [`flare.http.structured_logger`](../flare/http/structured_logger.mojo) |
| `MetricsCollector[Inner]` | Prometheus-format counters + histograms on `/metrics`. Cardinality is bounded by the router's route count, not by the URL path. | [`flare.http.metrics`](../flare/http/metrics.mojo) |

Recommended minimum: wire `RequestId[StructuredLogger[YourApp]]`
on every server. A request-id-bearing log line is the difference
between "looks like 3 % of requests fail" and "here is the exact
500, with the upstream call that returned the bad response".

## Resource limits

The HTTP server reads four limits from `ServerConfig`. Defaults
are tuned for sidecar / API-gateway shapes; raise only after
auditing the buffering chain.

| Limit | Default | Raise when |
|---|---|---|
| `max_header_list_size` | 8 KiB | You really do have a downstream that sends 32 KiB cookies. |
| `max_body_bytes` | 10 MiB | You're accepting file uploads. Use multipart streaming, not in-memory. |
| `max_uri_bytes` | 8 KiB | Almost never. URLs longer than 8 KiB are usually a bug. |
| `keep_alive_idle_ms` | 60 s | Keep-alive-heavy clients (browsers) -- consider 120 s; CDN -- 300 s; never above 600 s. |

The corresponding HTTP/2 limits live on `Http2ServerConfig`:

| Limit | Default | Notes |
|---|---|---|
| `SETTINGS_MAX_HEADER_LIST_SIZE` | 8 KiB | Advertised in the preface SETTINGS. |
| `SETTINGS_MAX_CONCURRENT_STREAMS` | 100 | Per RFC 9113 §6.5.2. |
| `SETTINGS_ENABLE_PUSH` | 0 (client) | We do not accept server push. |

## Process posture

- Run flare as an **unprivileged user** (uid >= 1000). flare
  does not need root for ports >= 1024; bind to 8443 + map via
  iptables or run behind a reverse proxy.
- Capabilities: nothing beyond `CAP_NET_BIND_SERVICE` if you
  must bind to 80/443 directly. Prefer the proxy route.
- Resource limits: `RLIMIT_NOFILE` should be >= 65 536 for
  serious traffic. The pixi tasks set this automatically; in
  systemd units, set `LimitNOFILE=65536`.
- Memory: a flare worker steady-states around 30-80 MiB
  resident for HTTP/1.1 only; +30-50 MiB if `permessage-deflate`
  contexts are negotiated heavily (each `PermessageDeflateContext`
  carries ~256 KiB of zlib state per connection).

## Failure modes and what to do

| Symptom | Likely cause | First action |
|---|---|---|
| p99 latency creeps up over hours, no traffic-shape change. | Per-connection state leak (typically `PermessageDeflateContext` not closing on hung WS clients). | Look at `/metrics` for `flare_active_connections{transport="ws"}`. If it monotonically grows, set `WsServer.with_idle_timeout(60_000)`. |
| 5xx spike after deploy, no traceback. | Sanitised-error policy is hiding the root cause. | Tail logs for `request_id=<X>` to recover the full error message; the response body is intentionally generic (see `security.md`). |
| Worker `panic` exits but the rest keep running. | `CatchPanic[Inner]` middleware caught a Mojo abort; one worker is restarting. | Check `/metrics` for `flare_worker_restarts_total`. The pool self-heals; investigate the corresponding log line. |
| TLS handshake errors in the log, intermittent. | OpenSSL session ticket key rotation drift (you reloaded the cert but the old keys are still in use somewhere). | `TlsAcceptor.reload` rotates ticket keys atomically; check that you're reloading on every host. |
| Memory grows unboundedly under WS load. | Each `WsConnection` allocates 64 KiB of recv buffer; many idle WS clients * 64 KiB. | Set `WsServer.with_idle_timeout`. Audit `permessage-deflate` if context-takeover is on. |

## Soak harness

flare ships three soak workloads under the `bench` pixi
environment:

| Task | What it stresses | Duration |
|---|---|---|
| `pixi run --environment bench bench-soak-slow-clients` | Lingering reads, partial header dribbles, idle keep-alive. | 60 s default; `SOAK_DURATION_SECS=86400` for 24 h. |
| `pixi run --environment bench bench-soak-churn` | Rapid connection open/close, accept storms. | Same. |
| `pixi run --environment bench bench-soak-mixed` | Mix of the above plus uniform request load. | Same. |
| `pixi run --environment bench bench-soak-smoke` | 5-minute CI gate across all three workloads. | Fixed. |
| `pixi run --environment bench bench-soak-extended` | 300 s per workload; for pre-release validation without the 24 h wait. | Fixed. |

The runners write reports under
`benchmark/results/<version>/soak_*/<host>/<utc-timestamp>.json`
with median + p99 + p99.99 windows in 1-min, 1-hr, and full-
duration buckets. The gate definitions (RSS within 2x of cold-
start, no monotonic-growing connection count) live in
[`benchmark.md`](benchmark.md#soak-gates).

Soak runs every minor release on the EPYC 7R32 reference host;
Apple Silicon (M2 Pro, 12 cores) runs the same harness for
cross-arch corroboration. A second-host bench publication
(adding an Intel Sapphire Rapids SKU) is in flight. The
methodology is identical; the cross-host numbers are in the
same JSON layout so downstream comparison tools work without
code changes.

## Container deployment

flare runs cleanly in a static Docker image. The dependency
shape is:

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 libbrotli1 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY ./target/server /usr/local/bin/server
COPY ./certs /etc/flare/certs
EXPOSE 8443
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/server", "--addr", "0.0.0.0:8443"]
```

Three knobs to remember:

1. `USER 1000:1000` -- never root in the image.
2. `LimitNOFILE=65536` -- set this in your orchestrator (k8s
   `containers.resources` or systemd unit).
3. Mount certs read-only; flare reloads atomically via
   `TlsAcceptor.reload`.

## Further reading

- [`security.md`](security.md) -- per-layer security posture +
  sanitised-error policy.
- [`threat-model.md`](threat-model.md) -- attack surface +
  mitigations.
- [`benchmark.md`](benchmark.md) -- methodology + reference
  numbers.
- [`concurrency.md`](concurrency.md) -- the closure-binding +
  cross-thread primitive rules.
