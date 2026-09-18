# Conformance fixture format

Each fixture is a JSON file. Naming convention:
`<spec>_<scenario>_<expected-outcome>.json`. Examples:
`rfc9112_request_line_with_lf_only_reject.json`,
`rfc9112_chunked_with_empty_extension_accept.json`.

## Schema

```
{
  "name":           String,     // human-readable id
  "spec":           String,     // RFC anchor
  "input_hex":      String,     // space-separated hex pairs
  "expect":         "accept" | "reject",
  "expect_reason":  String,     // why this outcome is correct
  "leniency":       Object,     // optional _ExperimentalH1LeniencyConfig fields
  "expected_method": String,    // present when expect == "accept"
  "expected_uri":    String,
  "expected_version": String
}
```

- `input_hex` is a flat string of 2-character hex pairs separated by
  ASCII space. Whitespace between pairs is collapsed during loading.
  Comments inside the hex string are not supported; the JSON `name`
  field is the place for human notes.
- `leniency` is keyed by `_ExperimentalH1LeniencyConfig` field name. Any omitted
  field uses the strict default (`False`). The conformance runner
  hands the resulting config to the parser before applying the input
  bytes.
- `expected_method` / `expected_uri` / `expected_version` are required
  only when `expect == "accept"` and the fixture is a request-line
  test. Header / body fixtures will grow `expected_headers` /
  `expected_body` fields when those parsers gain conformance
  coverage.

## Adding fixtures

1. Pick the RFC section the scenario tests.
2. Capture the wire bytes (e.g. via tcpdump, or hand-author from the
   ABNF grammar in the RFC).
3. Convert to space-separated hex with `xxd -p -c 1 | tr '\n' ' '`.
4. Drop the JSON in the appropriate `conformance/<area>/` subdir.
5. Re-run the conformance runner (`pixi run test-conformance-h1`).
6. If the fixture is sensitive to a leniency flag, document the flag
   under `leniency`.

The runner loads every `*.json` in `tests/conformance/h1/` automatically;
new fixtures need no test-code change.

## WebSocket schema (`tests/conformance/ws/`)

WebSocket fixtures live in `tests/conformance/ws/` and follow the same
`accept`/`reject` shape with WS-specific expected-* fields. The
runner is `tests/conformance/test_conformance_ws.mojo`; new
fixtures are picked up automatically.

```
{
  "name":           String,     // Autobahn-style id, e.g. "1.1.1_*"
  "spec":           String,     // RFC 6455 section anchor
  "input_hex":      String,     // raw on-the-wire frame bytes
  "expect":         "accept" | "reject",
  "expect_reason":  String,
  "expected_opcode":      Int,  // 0..0xF, accept only
  "expected_fin":         Bool, // accept only
  "expected_masked":      Bool, // accept only, optional
  "expected_payload_hex": String, // accept only, optional
  "expected_payload_len": Int,  // accept only, optional
  "expected_close_code":  Int   // accept + opcode == 0x8 only
}
```

The Autobahn case-number prefix (e.g. `1.1.1`, `5.4.1`, `7.7.1`)
is preserved in the `name` field as an anchor back to the
upstream test suite. The corpus is a hand-rolled subset, not a
full Autobahn run; the categorisation mirrors the upstream
section numbers (1.x framing, 2.x ping/pong, 3.x reserved bits,
5.x fragmentation, 7.x close handshake) so future fixtures slot
into the same naming scheme.
