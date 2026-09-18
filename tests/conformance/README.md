# `tests/conformance/` — cross-validation corpora for the sans-I/O sublayer

This directory holds wire-format test corpora that the `flare.http.proto.*`
sans-I/O sublayer is cross-validated against. The goal is the same one
the canonical Python `python-hyper` family pursues: an HTTP / HTTP/2 /
HPACK / WebSocket / QUIC parser is only trustworthy when it round-trips
the same bit-exact fixtures every other conforming implementation does.

## Layout

| Subdir | RFC / spec | Status |
|---|---|---|
| `h1/` | RFC 9112 (HTTP/1.1 wire grammar) | in-house fixtures (19), driven through the parser |
| `ws/` | RFC 6455 + permessage-deflate | in-house fixtures (13), driven through `WsFrame.decode_one`; still worth vendoring the full `crossbario/autobahn-testsuite` corpus |
| `h2/` | RFC 9113 (HTTP/2 frame codec) | no corpus — but h2spec now runs against the live server, see below |
| `hpack/` | RFC 7541 (HPACK) | no corpus — h2spec covers part of this against the live server |
| `cache/` | RFC 9111 (HTTP caching) | TODO — vendor from `mnot/cache-tests` |
| `quic/` | RFC 9000 + RFC 9001 (QUIC v1) | TODO — vendor from `aioquic` + `quiche` |
| `qpack/` | RFC 9204 (QPACK) | TODO |
| `h3/` | RFC 9114 (HTTP/3) | no JSON corpus; 7 inline server wire-shape cases in `tests/conformance/test_conformance_h3_server.mojo` |

## Fixture corpora vs live-server suites

These corpora test the sans-I/O parsers directly. They do not replace
running a third-party suite against a live server, which is the only
thing that catches "our parser and our client agree with each other and
both are wrong". `pixi run conformance` covers that half:

| Suite | Provisioned | What it drives |
|---|---|---|
| h2spec (RFC 9113 + 7541) | yes, `pixi run install-h2spec` | the h2c server |
| autobahn (RFC 6455 + 7692) | no — needs `wstest` and a `tests/tools/conformance/autobahn.json` that does not exist yet | the WsServer |
| quic-interop | no — flare has no runner integration yet | the QuicListener |

The in-house fixtures under `h1/` are the bootstrap set: they cover the
grammar corners flare's own parser exercises today (LF-only line endings,
mixed-case methods, OWS around `:`, obs-fold, oversized URI, chunked
transfer with extensions, etc.) so the conformance runner has something
to chew on while the upstream vendoring goes through license review.

## How to add an upstream corpus

Each corpus directory has a `LICENSE` file copied verbatim from the
upstream repository it was lifted from, an `ORIGIN.md` documenting the
source commit hash + license + how to refresh, and a set of `*.json`
fixture files in the format the conformance runner consumes (see
`fixture-format.md`).

Vendoring policy:

1. **License audit first.** The corpus license must be compatible with
   flare's Apache 2.0. Acceptable upstream licenses: Apache 2.0, MIT,
   BSD, ISC, CC0. If unsure, hand-write the fixtures from the RFC text
   instead.
2. **Verbatim copies, no edits.** Fixture data files are mirrored
   bit-exact from upstream. Format conversions (e.g. Python `pytest`
   parametrize → flat JSON) belong in a `tests/tools/conformance_*.py`
   script run at vendoring time, not at test time. No such script
   exists yet; the first corpus to need one writes it.
3. **Snapshot the commit hash.** `ORIGIN.md` records the exact upstream
   commit the fixtures came from. Refresh by re-running the conversion
   script against a newer hash + updating `ORIGIN.md`.
4. **Pin versions in `pixi.toml`.** When vendoring tools (e.g. `protoc`,
   `grpc-go`) are needed at vendor time, they land as `dev` feature
   dependencies with the pinned version.

## Fixture format

Each fixture is a JSON file with a flat top-level structure:

```json
{
  "name": "request_line_with_lf_only",
  "spec": "RFC 9112 §2.2",
  "input_hex": "47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0a 0a",
  "expect": "reject",
  "expect_reason": "bare LF before strict-mode parser",
  "leniency": {"allow_lf_only_line_endings": true},
  "expected_method": "GET",
  "expected_uri": "/",
  "expected_version": "HTTP/1.1"
}
```

- `name` — human-readable test id.
- `spec` — anchor in the relevant RFC.
- `input_hex` — wire bytes as space-separated hex pairs.
- `expect` — `"accept"` or `"reject"`.
- `expect_reason` — free-text rationale; consumed by the runner only on
  failure.
- `leniency` — optional `_ExperimentalH1LeniencyConfig` overrides that flip behaviour
  (e.g. `allow_lf_only_line_endings: true` flips the expectation from
  reject → accept).
- `expected_*` — fields the parser must produce when `expect == "accept"`.

The conformance runner (`tests/conformance/test_conformance_h1.mojo`)
loads every `*.json` file under `tests/conformance/h1/`, runs flare's parser
on the hex bytes, and asserts the expected outcome. The WebSocket
runner (`tests/conformance/test_conformance_ws.mojo`) does the same for
`tests/conformance/ws/` through `WsFrame.decode_one`, asserting opcode, FIN,
post-unmask payload and close code on accept and a raise on reject.
