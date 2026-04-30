# `benchmark/results/v0.6/h2/`

HTTP/2 throughput and latency baselines for v0.6 Track J.

## What's in here

`flare_h2.json` and `hyper_h2.json` (one per peer) are
`h2load`-format records of:

- **Peer**: `flare_h2` (this repo) or `hyper_h2`
  ([hyperium/h2](https://github.com/hyperium/h2) v0.4 + a tiny
  echo handler) for cross-stack comparison.
- **Workload**: `h2_throughput` (see
  `benchmark/configs/h2_throughput.yaml`).
- **Metrics**: req/s, p50/p95/p99 latency, bytes/s, error count.

The harness driver is
`benchmark/scripts/_install_h2load.sh`, which finds or installs the
`h2load` binary (from nghttp2). The full bench wrapper lives outside
this commit's scope (Track J shipped the protocol; running real
numbers against `flare_h2` requires terminating TLS and routing
into the synchronous driver in `flare/http2/server.mojo`).

## Why the runs aren't checked in

`flare_h2` is a *driver*, not a server: the actual frame loop is
synchronous and unit-tested via `tests/test_h2_server.mojo`. To get
publishable numbers we need the reactor wiring (Track K, planned
for v0.7) so the same driver can run async over many connections.

Running against the synchronous driver in isolation would publish
single-thread CPU-bound numbers that don't reflect what users
actually see, and we don't want a misleading data point checked in.
The harness, the config, and the install script *are* checked in
so v0.7 can populate this directory without further infrastructure
changes.

## When the runs land

After Track K's reactor integration, this directory will host:

- `flare_h2_<commit>.json` — flare's h2 throughput at HEAD.
- `hyper_h2_<commit>.json` — Hyper's h2 throughput at the same
  point in time, on the same hardware.
- `summary.md` — a side-by-side table linking back to the design
  doc.

The Track J commit message points back here so the v0.7 milestone
has a concrete checklist.
