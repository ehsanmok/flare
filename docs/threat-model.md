# Threat model

What flare protects against, what it does not, and where the
boundaries are. This document is the long-form companion to
[`security.md`](security.md): the table there lists *what each
layer enforces*; this page lists *what attackers can try and how
flare responds*.

Scope: flare is a library + runtime. The threat model below
assumes flare is deployed as a process under an unprivileged
user, behind a network boundary you control (cloud LB, nginx,
ALB, or a public IP with iptables). What sits on the other side
of flare -- your handlers, your database, your storage -- is
yours; flare protects the wire, the parser, and the request-
lifecycle invariants.

## Assets

| Asset | Why it matters |
|---|---|
| Process memory | Contains in-flight request bodies, headers, possibly secrets passed through `App[S]`. |
| TLS private keys | A compromise here ends the trust story. |
| Server identity (cert) | Trust + signing chain. |
| Application state | Whatever `App[S]` carries (typically DB pools, signing keys, session secrets). |
| Logs | May contain PII, request IDs, and (in dev) error messages with user input. |
| Disk (cache, sessions) | `FilesystemCacheStore`, `InMemorySessionStore` overflows, etc. |

## Trust boundaries

| Boundary | Who is on the other side | flare's response |
|---|---|---|
| Process / kernel | Anyone with `ptrace` rights, root, or the same uid. | flare cannot defend against root; depend on Linux user isolation + seccomp at the orchestrator layer. |
| Process / OpenSSL | The host's libssl + libcrypto. | flare pins major versions via pixi; CVE response is a pixi bump. |
| Process / zlib + brotli + FFI shims | The host's libz + libbrotli + the flare-built `libflare_*.so`. | The flare shims are built from `flare/{http,tls}/ffi/*.c` at activation time; they're trivially auditable. |
| flare / network | Anyone on the public internet (worst case). | Everything below. |

## Adversaries

We model three. Mitigations downgrade gracefully: the things
that stop A1 also help against A2 and A3.

### A1. Anonymous internet attacker

A worst-case adversary: anyone who can open a TCP / TLS / UDP
connection to the public address. No knowledge of the app, no
existing credentials.

| Attack | Mitigation in flare |
|---|---|
| Malformed HTTP/1.1 request (header injection, smuggling, CRLF). | `flare.http.proto` is a sans-I/O parser with RFC 7230 / 9112 token validation. CR / LF / NUL rejected at parse time; multiple `Content-Length` rejected (`H1LeniencyConfig.allow_multiple_content_length` defaults to false). TE-chunked-with-CL rejected. Conformance suite under `conformance/h1/` covers the negative cases. |
| Slowloris-style header flood. | `ServerConfig.max_header_list_size` caps the header bytes the server will accept before closing; default 8 KiB. The reactor's per-connection read timeout (configurable) shuts the socket on stalls. |
| Large body upload to exhaust memory. | `ServerConfig.max_body_bytes` (default 10 MiB) is checked at the parser layer before allocating. Multipart streaming is opt-in; the default body-buffering path enforces the cap. |
| HTTP/2 rapid-reset flood (CVE-2023-44487). | `SETTINGS_MAX_CONCURRENT_STREAMS = 100` advertised in the preface bounds the rapid-reset budget per connection. Cancellation cost is constant; no goroutine-per-stream allocation lurks behind the abstraction. |
| HTTP/2 priority frame abuse. | flare's H2 driver ignores PRIORITY (RFC 9113 §5.3.1 deprecation); never builds the priority tree, so priority-tree attacks have no surface. |
| HPACK decoding DoS (HEADERS bomb). | The HPACK decoder enforces `SETTINGS_MAX_HEADER_LIST_SIZE`; once the limit is exceeded the stream is RST'd with `ENHANCE_YOUR_CALM`. The dynamic table size is capped via SETTINGS. |
| HPACK Huffman DoS (compression oracle). | The decoder is constant-time relative to input length; the new table-driven kernel (v0.8) does not branch on payload content. |
| permessage-deflate zip-bomb. | Per-message decompressed-size cap (default 16 MiB) is enforced before allocation. Exceeding the cap raises and the WS connection is closed with 1009 (`MESSAGE_TOO_BIG`). Both the no-context-takeover and context-takeover code paths honour the cap. |
| TLS downgrade. | TLS 1.2+ only, weak ciphers disabled (`flare.tls.config` whitelist). No TLS 1.0 / 1.1 fallback path exists. |
| TLS session-ticket replay. | flare emits new tickets on every handshake; the OpenSSL rotation key is part of the TlsAcceptor and rotates with `reload`. |
| WS unmasked client frame. | `WsConnection.recv` enforces the RFC 6455 §5.1 client-side mask requirement; unmasked frames are rejected with 1002. |
| WS UTF-8 violation in TEXT frame. | Frame-level UTF-8 validator runs on every TEXT payload; invalid sequences trigger 1007 (`INVALID_FRAME_PAYLOAD_DATA`). |
| URL-injected control characters (`\0`, CR, LF, `@` in IP literals). | `flare.net` + `flare.dns` reject these *before* the bytes reach libc. |

### A2. Authenticated abuser

Same wire access as A1, plus a valid app credential (session
cookie, API key, etc).

| Attack | Mitigation |
|---|---|
| Path traversal via static files. | `FileServer` rejects `..`, NUL, absolute paths at the request layer; only resolves relative paths under the declared root. |
| Cookie tampering on signed sessions. | `signed_cookie_*` and `Session[T]` use HMAC-SHA256; invalid HMACs are rejected at the extractor layer, so the handler never sees a forged session. Key rotation is supported via `signed_cookie_decode_keys` (multiple keys, oldest-last). |
| Replay of stolen session cookie. | Session contents include a server-side expiry; out-of-band rotation requires app-level support. flare does not bind sessions to TLS exporter or client IP; that decision is application policy. |
| CSRF. | flare does not ship CSRF middleware in v0.8. SameSite cookie attributes are honoured (`Cookie.same_site`), but the framework cannot defend against application-level CSRF on its own. **You must** require a CSRF token on state-changing requests. |
| XSS via reflected error message. | Sanitised-error policy: 4xx responses use a fixed status reason; the raised message is logged but not echoed. The Compress middleware and StaticResponse path do not auto-link or interpret content. |
| Open redirect via Location header. | `Redirect` honours absolute URLs verbatim. **Validate the redirect target** if you build it from user input. |

### A3. Malicious peer in a proxy/server chain

flare deployed as a sidecar, gateway, or origin behind a CDN. The
attacker controls something in the chain (a compromised upstream,
a malicious origin, a hostile WS client).

| Attack | Mitigation |
|---|---|
| Request smuggling between flare and an upstream. | flare's H1 parser rejects ambiguous framing (TE+CL, multiple CL). When fronting another HTTP server, prefer HTTP/2 to the upstream where possible -- the H1 ambiguity surface is the issue, not flare. |
| H2 frame fuzzing from peer. | `fuzz/fuzz_h2_frame.mojo` exercises the codec for >= 200K runs per cycle. The current corpus has zero open crashes. |
| HPACK fuzzing from peer. | Mirror harness: `fuzz/fuzz_hpack_decoder.mojo`; same coverage discipline. |
| WS frame fuzzing from client. | `fuzz/fuzz_ws_frame.mojo` + the new `fuzz/fuzz_permessage_deflate_context.mojo` (v0.8) cover the wire codec + the LZ77 lifecycle. |
| Hostile origin in proxy mode. | flare is not a forward proxy; we do not parse upstream responses as separate requests. If you write a proxy on top of flare, *you* own the response parsing surface. |
| Untrusted cert (mTLS scenario). | `TlsAcceptor.with_client_cert_verification` enforces a CA bundle; if it isn't set, mTLS is not active and the cert is not consulted. There is no "trust on first use" behaviour. |

## Non-goals

These are real classes of risk; flare does not address them, and
shipping flare does not buy you protection against them.

- **CSRF**: application-layer; flare provides the SameSite knob
  and the signed-cookie primitive but no CSRF middleware.
- **DDoS at the network layer**: requires a CDN / scrubbing
  provider / firewall. flare's per-connection caps mitigate
  *some* L7 abuse (slowloris, header flood) but cannot defend
  against bandwidth saturation or SYN floods.
- **Side channels at the CPU level (Spectre / L1TF)**: out of
  scope for an application library; depend on host kernel
  mitigations.
- **PII / GDPR concerns**: flare logs whatever you tell it to.
  Audit your `StructuredLogger` config and your handler logs;
  the framework cannot know which fields are PII.
- **Secret storage**: flare does not provide secret management.
  Inject secrets via env / mounted files / a sidecar; do not
  hard-code them.

## Disclosure

Security issues: open a private security advisory on the GitHub
repo. Do not file a public issue. The maintainer triages within
72 hours and responds with a fix plan within one week of
acknowledgement.

For non-disclosable bugs (the issue is already public, an open
PR is fixing it), the normal issue tracker is fine.

## Verification cadence

| What | When | Where |
|---|---|---|
| Sanitiser builds (asan + tsan) | Every cycle, before release. | `pixi run tests-asan` / `pixi run tests-tsan` |
| Fuzz corpora (12+ harnesses) | Every cycle, >= 200K runs each. | `pixi run fuzz-all` |
| Conformance fixtures (h1 + ws) | Every cycle. | `pixi run test-conformance-h1` + `pixi run test-conformance-ws` |
| Soak (24 h) | Once per minor release on EPYC 7R32. | `SOAK_DURATION_SECS=86400 pixi run --environment bench bench-soak-mixed` (output under `benchmark/results/`) |
| Cross-arch soak (Apple Silicon) | Once per minor release. | Same task on the M2 host. |
| Threat-model review | Every minor; doc-level only between minors. | This page. |
