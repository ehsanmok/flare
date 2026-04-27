# Security

flare's security posture is layered. Each row below lists what
that layer enforces — by default, on every request, with no opt-in
needed.

| Layer | What it does |
|---|---|
| `flare.net` | Rejects null bytes, CRLF, `@` in IP strings before they reach libc. |
| `flare.dns` | Blocks injection in hostnames (null / CRLF / `@`, length limits). |
| `flare.tls` | TLS 1.2+ only, weak ciphers disabled, SNI always sent. Client and server both supported (server-side reactor-state-machine handshake is a follow-up; the blocking `handshake_fd(fd)` ships today). |
| `flare.http` | RFC 7230 token validation on header names and values; CR / LF / `\0` rejected at parse time. |
| `flare.http` | Configurable limits on headers (8 KB), body (10 MB), URI (8 KB). |
| `flare.http` | **Sanitised error responses**: 4xx bodies do not echo extractor `raise Error(...)` messages by default. Logs carry the full message + request id; the client gets a fixed status reason. |
| `flare.ws` | Client frames masked per RFC 6455, `Sec-WebSocket-Accept` verified. |
| `flare.ws` | CSPRNG nonce for handshake key, UTF-8 validation on TEXT frames. |

---

## Sanitised error responses

The criticism that drove this:

> A request to `/users/<script>alert(1)</script>` would echo that
> string in the 400 body with `Content-Type: text/plain`. Plain
> text is safe in a browser, but logs that auto-link or terminals
> that ANSI-interpret can be surprised. More importantly:
> parser-error messages are a DoS / log-poisoning surface and
> should be sanitised or replaced with status-code-only responses.

Default behaviour:

- 400 / 4xx responses use a **fixed status reason** as the body
  (e.g. `"Bad Request"`, `"Not Found"`). The raised error message is
  **not** copied into the response.
- The full message (including any user input the extractor was
  parsing) is **logged** with the request id, so production debugging
  works.
- 500 (handler `raise`) is the same: fixed body, full message
  logged with request id.

Local-development opt-in:

```mojo
var srv = HttpServer.bind(SocketAddr.localhost(8080), ServerConfig(
    expose_error_messages=True,
))
```

Flipping `expose_error_messages` to `True` echoes the raised message
into the response body. Use it locally; do not use it in production.

The fuzz harness `fuzz/fuzz_extractors.mojo` includes a property that
generates URLs with high-bit / control / HTML-ish payloads and
asserts the response body equals the fixed reason — i.e., that no
fuzzer-generated input ever escapes into a 400 body. The property
runs at every release tag.

---

## Fuzz / property-test budget

19 harnesses today, covering:

- HTTP parsing (request, response, headers, URL, cookies, auth)
- WebSocket frames (mask, opcode, close codes)
- Router paths (linear scan)
- Comptime route trie (oracle: 500K-run check that
  `ComptimeRouter` and `Router` agree on every status code for
  every path)
- Reactor / connection state machine (chunk boundaries, churn,
  shutdown)
- Multicore scheduler shutdown
- Typed extractors
- SIMD header scanner
- Property tests on the timer wheel, headers, auth, WebSocket
  round-trip

4M+ runs across all harnesses, zero crashes to date.

---

## Soak

Real soak tests as release gates: slow-client, churn, mixed-load.
These do not produce a number to brag about. They produce the
answer to "can I run this in production?"

Harness, gates, and the three-tier (smoke / extended / 24-hour
release-gate) shape live with the rest of the performance work in
[`benchmark.md`](benchmark.md#soak-long-running-operational-gates).

---

## Reporting

For security issues, please open a private security advisory on
GitHub or email the maintainer directly. Do not file a public issue
for vulnerabilities.

flare is pre-1.0 and has zero known production deployments. Treat
the maturity gap honestly: nginx, Go `net/http`, hyper, and axum
all shipped CVEs in their first two years, and the HTTP/2 HPACK
parser (planned, future release) is the highest-CVE-risk subsystem
on the roadmap. That work is explicitly gated on flare's
operational maturity landing first.
