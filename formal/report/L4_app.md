# L4: Application layer (HTTP/1.1 connection, routing, middleware, client policy)

Scope. This layer covers the parts of flare that sit above HTTP framing. On
the server side these are:

- the per-connection HTTP/1.1 state machine (`ConnHandle`) and its keep-alive
  and `Connection`-header logic;
- `ServerConfig.check` and the deadlines it feeds;
- the runtime and comptime routers;
- the generic middleware (Logger, RequestId, CatchPanic, Compress), content
  negotiation, CORS, cookies and form decoding;
- the reliability middleware (RateLimit, CircuitBreaker, Retry);
- the single-worker drain;
- the h2c upgrade hand-off to the HTTP/2 driver and the WebSocket upgrade branch.

On the client side these are `Url.parse`, the redirect policy and loop, and
the idle-connection pool, including how `HttpClient` leases pooled fds. All models are against flare at commit 59bda50,
written in core Lean 4.33 (no Mathlib).

The build covers 22 model modules (`Flare.L4_App.*`) and 25 issue files
(`Flare.Bugs.APP_*`). The aggregate `Flare.L4_App` imports all of them and
builds cleanly. The modules contain no `sorry`, `admit` or `axiom`, and
`native_decide` appears only in `Flare/Bugs/`. `Flare/Audit/L4.lean` prints
the axiom footprint of 160 headline theorems. Outside `Flare.Bugs` the
footprint is a subset of `propext`, `Quot.sound` and `Classical.choice`. The
counterexamples that use `native_decide` add one auxiliary axiom each
(`<thm>._native.native_decide.ax_*`).

Theorem count: 446 in the model modules and 112 in the issue files. Unless a
row says otherwise, a theorem is general: it is quantified over all inputs
or over every reachable state.

## Components

### 1. HTTP/1.1 connection state machine (`Flare.L4.ConnSM`)

**Model.** The model is a labelled transition system over socket events:
`arrive bytes`, `readable eof late`, `writable n`, `timeout` and `ioError`.
It mirrors these parts of `flare/http/_reactor/conn_handle.mojo`:

| Mojo function | Lines |
|---|---|
| `on_readable` | 760-916 |
| `_check_request_complete` | 579-695 |
| `_apply_keepalive_policy` | 697-715 |
| `_finalise_response` | 718-756 |
| `_queue_error` | 1576-1580 |
| `on_writable` | 1262-1375 |
| `on_timeout` | 1403-1411 |

Several inputs are parameters instead of being modelled here:

- HTTP framing is an abstract oracle `frame : Bytes -> needMore | complete r n | error s`. `Oracle.WF` requires that a complete request occupies `0 < n <= len` bytes and is determined by those bytes. The framing itself belongs to L3.
- Serialisation, the handler outcome, the per-request close verdict and the WebSocket version check are also parameters.
- A flag `fix` selects the APP-01 fix.

The invariant `Inv` has nine clauses:

- the input tiles into dispatched requests;
- every dispatched request is the oracle's reading of exactly its own bytes;
- the answers are those requests in order;
- the wire is a prefix of the queued responses;
- the reading phase is quiescent;
- two keep-alive bounds.

The submodule `Framing` models the body and `Content-Length` decisions of
`serialize_response_into` (`flare/http/_reactor/write_path.mojo:222-235`) and
the static fast path (`conn_handle.mojo:1174-1211`).

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ConnSM.inv_inductive`, `inv_reachable` | `Inv` holds in every reachable state | proved |
| `Flare.L4.ConnSM.responses_fifo` | the requests answered by queued responses are exactly the dispatched requests, in order; each is the oracle's reading of its own bytes; those bytes tile a prefix of the input | proved |
| `Flare.L4.ConnSM.wire_is_responses` | bytes sent are a prefix of the queued responses' bytes; while reading they are all of them | proved |
| `Flare.L4.ConnSM.writable_resumes` | a writable event sends exactly the next `min n remaining` bytes from `wpos`, and leaves WRITING iff the response is complete | proved |
| `Flare.L4.ConnSM.timeout_closes` | `on_timeout` always yields CLOSING with `should_close` and `done` | proved |
| `Flare.L4.ConnSM.segs_frozen`, `run_segs_frozen` | once `should_close` is set, no later step or run dispatches another request | proved |
| `Flare.L4.ConnSM.ka_bound` | `keepalive_count <= max_keepalive_requests` in every reachable state, when `max_keepalive_requests >= 1` (which `ServerConfig.check` enforces) | proved |
| `Flare.L4.ConnSM.closeHonoured_step`, `fixed_no_request_after_close_header` | with the APP-01 fix: once a `Connection: close` response is queued, no further request is ever dispatched | proved (fixed machine) |
| `Flare.Bugs.APP_01.violates_spec` | without the fix, a reachable state violates `CloseHonoured` | counterexample |
| `Flare.L4.ConnSM.Framing.serialize_spec` | no body for HEAD, 1xx, 204 or 304; no `Content-Length` on 1xx or 204; otherwise the body is sent with its length | proved |
| `Flare.L4.ConnSM.Framing.headFlagFixed_spec`, `staticBytesFixed_spec` | with the APP-05 and APP-04 fixes, every response to HEAD has no body | proved (fixed) |

The original plan asked for six properties:

- One response per request in FIFO order is covered by `responses_fifo` and `wire_is_responses`.
- Timeout reaching CLOSING is covered by `timeout_closes`.
- No read after `should_close` is covered by `run_segs_frozen`.
- The keep-alive bound is covered by `ka_bound`.
- Bodyless HEAD, 1xx, 204 and 304 responses hold only for `serialize_response_into`. On two paths HEAD does get a body: the static path (APP-04) and the error path (APP-05).
- "A close response implies close" is false for the shipped code (APP-01). It is restated for the fixed machine.

`closeHonoured_parse` needed an extra hypothesis, `should_close -> peer_eof`, which `closeHonoured_step` carries as part of its induction.

**Limitations.**

- Liveness under fair event delivery is proved separately in section 17 (`Flare.L4.ConnLive`). Streaming bodies (`body_src`) and TLS cross-interest are modelled in section 18 (`Flare.L4.ConnStream`). The h2c hand-off and the WebSocket branch are modelled in section 16 (`Flare.L4.ConnExt`).
- The time budget appears only as the boolean `late`. The arithmetic is in `ServerConfig.closeTime_le`.
- Documented deviations:
  - The model enters CLOSING after a flush with `should_close`. Mojo leaves `STATE_WRITING`, and the handle is freed at once.
  - The model drops the request bytes after a handler error. Mojo leaves them unread.
  - The model checks the size cap once per drain, not per 8 KiB chunk. Both answer 413 and close.

### 2. Connection header and keep-alive verdicts (`Flare.L4.KeepAlive`)

**Model.** Byte-level transliterations of four functions in
`flare/http/_reactor/keepalive_scan.mojo`:

| Mojo function | Lines |
|---|---|
| `_is_keepalive_fast` | 206-236 |
| `_is_close_fast` | 239-259 |
| `_compute_close_after` | 350-390 |
| `_wants_close` | 393-484 |

Every byte constant is spelled out as a list, so no `String` reaches the
kernel. The spec is RFC 9110 §7.6.1 / RFC 9112 §9.6. The `Connection` value
is a comma list of tokens, trimmed of OWS and compared case-insensitively.
`close` means close. HTTP/1.0 closes unless a token is `keep-alive`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.KeepAlive.computeCloseAfterFixed_eq_spec` | the token-splitting fix equals the spec for every header value and version | proved |
| `Flare.L4.KeepAlive.computeCloseAfter_single` | when the value is a single token, the shipped function already equals the spec | proved |
| `Flare.L4.KeepAlive.wantsCloseFixed_spec` | the line-start, scan-all fix of `_wants_close` returns true iff some header line is `Connection` with a close verdict | proved |
| `Flare.L4.KeepAlive.wantsClose_sound_close` | when the shipped scan matches a real `Connection` line whose value is `close`, it returns true | proved |

**Limitations.** `_wants_close` is modelled on the raw request bytes. The
claim that the fast paths reach it was checked against the Mojo call sites,
not modelled.

### 3. Server configuration and deadlines (`Flare.L4.ServerConfig`)

**Model.** `ServerConfig.check` (`flare/http/_server/config.mojo:276-329`)
becomes a decidable predicate. The model also covers the timer instructions
that `conn_handle.mojo` issues (614-620, 667-691, 1314-1320, 1370-1375) and
the read-buffer size cap (448-453).

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ServerConfig.default_check` | the default config passes `check` | proved |
| `Flare.L4.ServerConfig.timer_instr_nonneg` | under `check`, every timer instruction is `>= 0`, so each phase replaces the previous timer | proved |
| `Flare.L4.ServerConfig.body_timer_le_request` | under `check`, the body timer is at most `request_timeout_ms` when both are enabled | proved |
| `Flare.L4.ServerConfig.closeTime_le` | given a monotone clock (`Flare.Assumptions.MonotoneClock`), one request's read phase ends by `t0 + R + T` | proved |
| `Flare.L4.ServerConfig.head_timer_unordered` | `check` accepts configs whose idle (head) timer exceeds `request_timeout_ms` | proved (observation) |
| `Flare.L4.ServerConfig.overCapFixed_eq_spec` | the subtraction form of the size cap equals the exact-arithmetic spec for all non-negative `Int64` inputs | proved |

### 4. Runtime router (`Flare.L4.Router`) and comptime router (`Flare.L4.ComptimeRouter`)

**Model.** The runtime router models these parts of `flare/http/router.mojo`:

| Mojo function | Lines |
|---|---|
| `_split_path` | 111-133 |
| `_compile_segments` | 136-156 |
| `_match` | 838-873 |
| `Router.serve` precedence | 675-776 |
| `_MountedRouter.serve` | 800-823 |

`Router.serve` tries direct routes in registration order, then mounts, then
405, then the fallback, then 404. Paths are `List Char`; every byte the
router inspects is ASCII. The comptime model covers `routes.mojo:66-284`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Router.serve_eq_spec`, `serveMounts_eq_spec` | on routers built from accepted patterns, `serve` equals the independent dispatch spec | proved |
| `Flare.L4.Router.serve_deterministic` | `serve` is a function of router and request | proved |
| `Flare.L4.Router.serve_valid` | every outcome is one of: a handler call, a 405 with a non-empty duplicate-free `Allow`, the fallback, or a 404, at any mount depth | proved |
| `Flare.L4.Router.allow_exact` | without mounts, `Allow` lists each matching method exactly once and never the request's method | proved |
| `Flare.L4.Router.first_route_wins` | the first matching route handles the request (registration-order shadowing) | proved |
| `Flare.L4.Router.mount_compose` | mounting `leaf` at `p2` inside a mount at `p1` is mounting it at `p1 ++ p2` | proved |
| `Flare.L4.Router.mount_boundary` | `/api` does not claim `/apix` | proved |
| `Flare.L4.Router.splitPath_idem`, `route_ignores_query` | path splitting computes a normal form, and the query never affects routing | proved |
| `Flare.L4.ComptimeRouter.serveCT_eq_serve` | on any table, ComptimeRouter answers like the runtime router with the same routes | proved |
| `Flare.L4.ComptimeRouter.router_equiv_comptime` | on valid patterns, registering the table succeeds and both routers agree on every request | proved |
| `Flare.Bugs.APP_10.matchOne_violates_spec` | ComptimeRouter matches `/files/a` against the invalid pattern `/files/*/meta` | counterexample |

The Router module has 61 theorems, of which the table lists the headline
ones. The rest are lemmas about splitting, compilation and stripping.

### 5. Generic middleware (`Flare.L4.Middleware`)

**Model.** A handler is `Req -> Except String Resp`, where a Mojo `raise` is
`.error`. Header maps mirror `HeaderMap` (`flare/http/headers.mojo:139-213`):
an ordered list with case-insensitive names. `set` replaces the first match or
appends, `append` always appends, and `get` returns the first match.

The model covers these structs in `flare/http/middleware.mojo`:

| Mojo struct | Lines |
|---|---|
| `Logger` | 61-86 |
| `RequestId` | 105-111 |
| `Compress.serve` | 345-382 |
| `CatchPanic` | 397-404 |

Logger's printing is dropped. RequestId's generated id
(`perf_counter_ns`) is a parameter. Compress takes the negotiated pick and
the encoder as parameters; negotiation itself is component 6.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Middleware.logger_transparent` | `Logger h = h`, including the re-raised message | proved |
| `Flare.L4.Middleware.catchPanic_total`, `catchPanic_ok`, `catchPanic_idem`, `catchPanic_logger` | CatchPanic never raises, passes successes through, is idempotent and absorbs Logger | proved |
| `Flare.L4.Middleware.requestId_sets`, `requestId_echo` | every successful response carries the request id; a non-empty inbound `x-request-id` is echoed | proved |
| `Flare.L4.Middleware.requestId_outside_catchPanic` | `RequestId(CatchPanic(h))` puts the id on every response | proved |
| `Flare.L4.Middleware.catchPanic_outside_requestId_error` | `CatchPanic(RequestId(h))` returns the bare 500 (no id) when `h` raises: stacking order matters | proved |
| `Flare.L4.Middleware.compress_skips_encoded` | a response that already has `Content-Encoding` is untouched | proved |
| `Flare.L4.Middleware.compress_content_length`, `compress_vary_when_encoded` | when Compress changes a response, `Content-Length` equals the encoded length and `Vary: Accept-Encoding` is present | proved |
| `Flare.Bugs.APP_26.violates_spec`, `APP_27.violates_spec` | a 206 is re-encoded; the identity variant lacks `Vary` | counterexample |
| `Flare.L4.Middleware.compress_partial` | the shipped Compress passes every 206 / `Content-Range` response through unchanged | proved (fixed) |
| `Flare.L4.Middleware.compressFixed_partial`, `compressFixed_vary`, `compressFixed_agrees` | the fixed Compress meets both specs, and agrees with the shipped one whenever the shipped one encodes a non-partial response | proved |

**Limitations.** The model does not check the header-injection test of
`HeaderMap.set`. A value read from a parsed request cannot contain CR or LF.

### 6. Content-coding negotiation (`Flare.L4.Negotiate`)

**Model.** The model has two layers over `flare/http/middleware.mojo:131-260`.
The byte layer covers `_parse_q`, splitting, stripping, lowercasing and the
`q=` search. The decision layer is the loop body at 236-252 and the final
choice at 253-260. The spec follows RFC 9110 §12.5.3:

- each coding's effective weight is its explicit maximum, else the `*` weight;
- the pick is the highest non-zero weight;
- ties go br, then gzip, then identity;
- when every weight is 0, the result is passthrough.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Negotiate.parseQ_le`, `parseQ_zero_dot`, `parseQ_failOpen` | weights lie in 0..1000; `0.DDD` is read exactly; a weight not starting with `0` reads as 1000 | proved |
| `Flare.L4.Negotiate.classify_upper` | coding names are case-insensitive | proved |
| `Flare.L4.Negotiate.decide_eq_spec_of_noStar`, `negotiate_eq_spec_of_noStar` | without `*`, flare's loop returns exactly the spec pick, at the entry level and at the byte level | proved |
| `Flare.L4.Negotiate.specPick_perm`, `decide_perm_of_noStar` | the spec, and flare without `*`, do not depend on entry order | proved |
| `Flare.L4.Negotiate.decide_br_imp` | br is chosen only when brotli is linkable | proved |
| `Flare.L4.Negotiate.decideFixed_eq_spec` | the fixed loop equals the spec on every entry list | proved |
| `Flare.L4.Negotiate.parseHeaderMojo_eq`, `negotiateMojo_eq` | a byte-level model of Mojo's own comma splitter (`parseHeaderMojo`, which emits no trailing empty segment) parses every header to the same entry list as the model's splitter, so the negotiation results are equal on every input | proved |

**Limitations.** None beyond the L3 framing boundary. The earlier gap (Mojo's
splitter does not emit a trailing empty segment, the model's does) is closed
by `parseHeaderMojo_eq`.

### 7. CORS (`Flare.L4.Cors`)

**Model.** The model covers four Mojo functions:

| Mojo function | Lines in `flare/http/cors.mojo` |
|---|---|
| `_origin_allowed` | 89-98 |
| `_join` | 101-107 |
| `_attach_origin` | 121-150 |
| `Cors.serve` | 152-197 |

Header names are a normalised inductive type. The spec is WHATWG Fetch
§3.2. Allowed origins form a set, and `*` never authorises a credentialed
request. A credentialed response's ACAO is the request origin. When ACAO
depends on `Origin`, every response carries `Vary: Origin`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Cors.originAllowed_sound` | flare never admits an origin the spec rejects (fail-closed) | proved |
| `Flare.L4.Cors.originAllowed_eq_spec_noCreds` | without credentials, flare's check equals the spec | proved |
| `Flare.L4.Cors.acao_not_star_with_creds`, `acao_origin_or_star` | with credentials, ACAO is never `*` and equals the request origin | proved |
| `Flare.L4.Cors.attach_has_vary` | every response the middleware stamps carries `Vary: Origin` | proved |
| `Flare.L4.Cors.preflight_ignores_inner` | an allowed preflight is a 204 that does not call the inner handler | proved |
| `Flare.L4.Cors.originAllowedFixed_iff`, `serveFixed_vary` | the fixed check equals the spec; the fixed `serve` puts `Vary: Origin` on every response | proved |

### 8. Cookies (`Flare.L4.Cookie`)

**Model.** Byte-level models of four parts of `flare/http/cookie.mojo`:

| Mojo function | Lines |
|---|---|
| `Cookie.to_set_cookie_header` and its validation | 89-136, 168-212 |
| `parse_cookie_header` | not mapped to lines |
| `CookieJar.to_request_header` | not mapped to lines |
| `_parse_max_age` | 146-165 |

The spec covers RFC 6265 §4.1.1, §4.2.1 and §5.2.2.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Cookie.toSetCookie_valid`, `toSetCookie_split` | every emitted `Set-Cookie` value parses as a `set-cookie-string` whose attributes are the intended ones | proved |
| `Flare.L4.Cookie.toSetCookie_noCtl`, `toSetCookie_noCRLF` | no emitted byte is a control character; in particular no CR or LF (no header injection) | proved |
| `Flare.L4.Cookie.toSetCookie_none_secure` | `SameSite=None` (any case) always comes with `Secure` | proved |
| `Flare.L4.Cookie.splitSemi_join` | joining with `;` and splitting are inverse on `;`-free pieces | proved |
| `Flare.L4.Cookie.parseMaxAge_sound`, `parseMaxAge_bound` | an accepted Max-Age equals its RFC value; it lies in `(-10^18, 10^18)`, so it never collides with the ignore sentinel | proved |
| `Flare.L4.Cookie.parseMaxAge_complete` | every RFC-valid Max-Age of at most 18 digits is accepted with its exact value | proved (for at most 18 digits) |

### 9. Form codec (`Flare.L4.Form`)

**Model.** Byte-level models of five functions in `flare/http/form.mojo`:

| Mojo function | Lines |
|---|---|
| `_hex_nibble` | 28-47 |
| `urldecode` | 50-95 (byte loop `urldecodeBytes`, then the UTF-8 check) |
| `urlencode` | 90-129 |
| `FormData.to_urlencoded` | 199-213 |
| `parse_form_urlencoded` | 216-264 |

The spec covers WHATWG URL §5.1-5.2. It also requires RFC 3629 well-formed
UTF-8 for anything passed to `String(unsafe_from_utf8=...)`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Form.urldecodeBytes_urlencode` | the byte loop inverts `urlencode` for every byte string | proved |
| `Flare.L4.Form.urldecode_urlencode` | the shipped `urldecode (urlencode s) = s` for every well-formed UTF-8 string | proved |
| `Flare.L4.Form.urlencode_noSep` | encoded bytes contain no `&`, `;` or `=` | proved |
| `Flare.L4.Form.parseFormOld_toUrlencoded` | the pre-fix parser round-trips every list of byte-string pairs (including ill-formed ones) | proved |
| `Flare.L4.Form.parseForm_toUrlencoded` | the shipped `parse_form_urlencoded (to_urlencoded fd) = fd` for every list of well-formed UTF-8 pairs | proved |
| `Flare.L4.Form.urldecode_valid`, `urldecode_urlencode` | the shipped decode only returns well-formed UTF-8 and keeps the round trip on valid input | proved |
| `Flare.Bugs.APP_24.urldecode_violates_spec` | the pre-fix `urldecode("%F0")` returned the lone byte `0xF0` | counterexample |
| `Flare.Bugs.APP_24.parseForm_rejects_F0` | the shipped `parse_form_urlencoded("a=%F0")` is rejected | proved (fixed) |

### 10. URL parser (`Flare.L4.Url`)

**Model.** A byte-level model of `Url.parse` (`flare/http/url.mojo:73-197`),
`_find` / `_rfind` (218-261), `_default_port` (264-269) and `_parse_port`
(272-299). One combinator, `parseWith`, is parameterised by the three
splitting steps, so the shipped parser and the fixed parsers share every
other line. The spec is RFC 3986 §3.2:

- the authority ends at the first `/`, `?` or `#`;
- the host is a piece of the authority and contains no `@`;
- the port is `*DIGIT`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Url.parsePort_iff`, `parsePort_fits` | `_parse_port` accepts exactly 1-5 digits with value 1..65535, and the accumulator cannot overflow | proved |
| `Flare.L4.Url.parse_port` | every successful parse has `1 <= port <= 65535` | proved |
| `Flare.L4.Url.hostPort_ipv6_port`, `hostPort_regname` | IPv6 brackets are stripped; a plain `host:port` is recovered exactly | proved |
| `Flare.L4.Url.parseFixed_spec` | the fixed parser meets both host specs for all inputs | proved |
| `Flare.L4.Url.parseOld_eq_parseFixed_of_clean` | the pre-fix parser (`parseOld`) equals the fully fixed one on inputs with no `?`, no `#` and at most one `@` | proved |
| `Flare.Bugs.APP_23.host_confusion`, `APP_25.host_has_at` | host-confusion witnesses | counterexample |

### 11. Reliability: RateLimit, CircuitBreaker, Retry

**RateLimit** (`Flare.L4.RateLimit`, `reliability.mojo:361-404`). One locked
read-modify-write per request, with wrapping `Int64` arithmetic. The spec is
an exact-arithmetic token bucket. `step` is the shipped code, with `elapsed`
clamped to `maxElapsed` (APP-40); `stepOld` is the pre-fix code.

**CircuitBreaker** (`Flare.L4.CircuitBreaker`, `reliability.mojo:413-485`).
The model is an LTS whose labels are request arrivals and completions, so any
number of requests can be in flight at once. The entry check and the outcome
bookkeeping are separate atomic steps. This is coarser than the Mojo code, so
each counterexample trace of the model is also a trace of the code. Two flags
select the APP-41 and APP-42 fixes.

**Retry** (`Flare.L4.Retry`, `reliability.mojo:164-271`). Covers
`_backoff_sleep_ms` with wrapping multiplication, and the attempt loop over an
arbitrary sequence of outcomes.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.RateLimit.step_eq_spec`, `step_inv` | for any idle time (sane rate and burst, no overflow hypothesis) the shipped `step` computes exactly the spec tokens and decision, and keeps `0 <= tokens <= cap` | proved |
| `Flare.L4.RateLimit.step_last_ok` | the clock carry never runs ahead of `now` or backwards, and leaves under one milli-token period uncredited | proved |
| `Flare.L4.RateLimit.stepOld_eq_spec`, `stepOld_inv`, `stepOld_last_ok` | the same for the pre-fix `stepOld`, but only while `elapsed * rate` fits in `Int64` | proved |
| `Flare.L4.RateLimit.overflow_iff`, `threshold_rate_*` | the exact wrap threshold `elapsed > (2^63-1)/rate`, instantiated for several rates | proved |
| `Flare.L4.CircuitBreaker.counts_inductive`, `step_counts_inv`, `step_counts_inv_shipped` | failure counts are consistent with the state in every reachable state | proved |
| `Flare.L4.CircuitBreaker.step_open_rejects`, `step_success_closes`, `step_failure_reopens` | the sequential transition rules | proved |
| `Flare.L4.Retry.budget_eq_spec`, `budget_le_max`, `budget_mono` | for a sane policy the backoff is `min(initial * m^(N-2), max)`, non-decreasing and capped | proved |
| `Flare.L4.Retry.sleep_bounds` | the jittered sleep lies in `[0, budget]`, assuming `random_ui64` stays in range (hypothesis `DrawOk`) | proved |
| `Flare.L4.Retry.serve_calls_bounded`, `serve_result_is_last`, `serve_retry_only_on_failure`, `serve_failure_exhausts` | between 1 and `max_attempts` calls; returns the last outcome; retries only after failure | proved |
| `Flare.L4.Retry.uncapped_wraps` | with `max_backoff_ms <= 0` (no cap), the budget wraps to 0 at attempt 59 for `100 ms x 2` | proved (observation) |

### 12. Redirects (`Flare.L4.Redirect`)

**Model.** The model has four parts:

- `Url.parse`;
- `_resolve_location` (`redirect_policy.mojo:154-185`);
- `_same_origin` (188-198);
- `RedirectPolicy.decide` (271-354).

It also covers the redirect loop of `HttpClient._send_once`
(`client.mojo:2196-2281`). That loop runs over an arbitrary server and
tracks which credentials each hop carries.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Redirect.decide_follow_lt_max`, `sendLoop_terminates` | at most `max_redirects` redirects are followed | proved |
| `Flare.L4.Redirect.sendLoop_confined` | with `forward_auth_cross_origin = False`, every hop that carries `Authorization`, a caller `Cookie` or `Proxy-Authorization` targets the original origin, for every server | proved |
| `Flare.L4.Redirect.sendLoop_auth_monotone`, `sendLoop_cookie_proxy_monotone` | once dropped, a credential is never re-added, even if a later hop returns to the original origin | proved |
| `Flare.L4.Redirect.decide_method_rfc` | 307/308 keep the method and body; 303 turns all but HEAD into GET | proved |
| `Flare.L4.Redirect.decide_301_delete_is_get` | a DELETE answered by 301 becomes GET (documented deviation) | proved (observation) |

### 13. Client connection pool (`Flare.L4.ClientPool`)

**Model.** Per-origin LIFO deques of idle fds, as in
`flare/http/client_pool.mojo:203-293`:

- `release` closes the fd when pooling is off, the total cap is reached or the
  host's deque is full; otherwise it appends.
- `acquire` pops from the back, closing entries older than `idle_timeout_ms`.

The `Dict` is an association list, and the invariant keeps its keys unique.
A ghost list records every `(key, fd)` the pool accepted. Events are
arbitrary interleavings of `release` and `acquire` with arbitrary clock
values.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ClientPool.inv_inductive`, `inv_reachable` | unique keys, the per-host bound, the total bound, and the origin of every pooled fd hold in every reachable state | proved |
| `Flare.L4.ClientPool.caps` | each origin holds at most `max(max_idle_per_host, 0)` idle fds; with the total cap enabled, the pool holds at most `max_idle_total` | proved |
| `Flare.L4.ClientPool.acquire_same_origin` | `acquire key` returns only fds that were released under `key` (no cross-origin reuse) | proved |

**Limitations.**

- The pool trusts its caller to release each fd once (section 15 shows
  `HttpClient` does). A double release files the fd twice. In Mojo, the second `acquire` of that fd then raises
  `KeyError` on `insertion_ts_ms[fd]`, because the first `acquire` popped the
  timestamp.
- The model reads a missing timestamp as 0 and does not delete timestamps.
  Timestamps only feed the age test.
- Keys are not lowercased, which costs reuse but is not a safety issue (see
  APP-44).

### 14. Single-worker drain (`Flare.L4.Drain`)

**Model.** `HttpServer.drain(timeout_ms)` (`flare/http/server.mojo:1694-1755`)
closes the listener, sets `_stopping`, and returns a `ShutdownReport` of
zeros. A response still being written when the reactor sees the flag
(`lag ≤ pollCap` = 100 ms later) is cut: the bytes delivered are
`min pending (rate * (stopDelay + lag))`, where `stopDelay` is the time from
the `drain` call to the flag (`delivered`, mirrors the loop exit at
`_unified_reactor_impl.mojo:1103-1170` and the close-all at 1000-1046).

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Drain.drain_ignores_timeout` | the result does not depend on `timeout_ms` | proved (APP-46) |
| `Flare.L4.Drain.drain_report_zero`, `drain_stops` | the report is all zeros; the listener is closed and `_stopping` set | proved |
| `Flare.L4.Drain.delivered_le_pollCap` | whatever the timeout, at most `rate * pollCap` more bytes go out | proved (APP-46) |
| `Flare.L4.Drain.fixed_graceful` | waiting out `timeout_ms` before setting the flag delivers every response the peer can absorb within the timeout | proved |
| `Flare.L4.Drain.fixed_zero_is_hard_stop` | under the fix, `drain(0)` is still the hard stop | proved |

The zero counts are documented (see "Documentation gaps"); the ignored
timeout is APP-46. The multi-worker `Scheduler.drain` belongs to L5.

### 15. `HttpClient` pool leases (`Flare.L4.ClientLease`)

**Model.** `_send_h1_pooled` (`flare/http/client.mojo:2509-2593`) is the
only caller of `ClientPool.acquire` and `release`. `sendPooled` covers every
path through it, with an oracle choosing which call raises
(`_arm_read_timeout`, `write_all`, the framed read, `release`, `_may_replay`,
the fresh dial). Across requests, `Client` composes the pool with the set of
fds held by requests; that the kernel never returns an fd number that is
still open is the guard of `dial`. The TLS and QUIC pools hold values that
are moved into `release` and are not `Copyable`, so a second release is a
compile-time error; they are not modelled.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ClientLease.dispose_first`, `dispose_second` | each connection the function acquires or opens is released or closed exactly once, on every path | proved |
| `Flare.L4.ClientLease.release_once` | no path releases the same connection twice | proved |
| `Flare.L4.ClientLease.inv_reachable` | in every reachable state, each fd number occurs at most once across the pool and the held set | proved |
| `Flare.L4.ClientLease.acquire_not_held`, `pool_fd_once` | `acquire` never returns an fd a request still holds; no fd is filed twice | proved |

### 16. Connection extensions: h2c hand-off and WebSocket over TLS (`Flare.L4.ConnExt`)

**Model.** `H2c` keeps the connection kind, whether an upgrade is pending,
the bytes of the 101 still queued and whether write interest is armed. A
writable edge on a `KIND_H1` connection goes to `_drive_h1_writable`
(`_unified_reactor_impl.mojo:812-855`, `243-258`), which ignores the
`h2c_upgrade` cue that `on_writable` keeps reporting once the 101 has
flushed (`conn_handle.mojo:1353-1362`); only `_drive_h1` (174-215)
migrates. After the upgrade request the client waits for the server
preface (RFC 7540 §3.2), so the only events are writable edges, which keep
coming while write interest is armed. `Ws` is the WebSocket branch of
`on_readable` (`conn_handle.mojo:838-885`) and where `_handle_ws_upgrade`
writes (the detached raw fd, 1476-1574).

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ConnExt.H2c.impl_spins` | with the 101 queued behind a full send buffer, after any number of writable edges the connection is still `KIND_H1` and write-armed | proved (APP-47) |
| `Flare.L4.ConnExt.H2c.fixed_spec` | routing the edge to `_drive_h1` while an upgrade is pending migrates on the first writable edge, and the connection stays HTTP/2 | proved |
| `Flare.L4.ConnExt.Ws.old_violates` | before the fix (`wireOld`), a valid handshake on a TLS connection with a WebSocket handler is answered in cleartext | proved (APP-48, resolved) |
| `Flare.L4.ConnExt.Ws.spec`, `cleartext_same` | the shipped branch (`not self.tls`) keeps TLS connections inside TLS and changes nothing on cleartext ones | proved |

### 17. Liveness of the connection machine (`Flare.L4.ConnLive`)

**Model.** `ConnLive` runs `ConnSM.step` over an infinite event sequence
`σ` (`trace fix P s0 σ n` is the state after `n` events) from any state
satisfying `ConnSM.Inv`. It adds two hypotheses.

- `Fair` is about the reactor and the kernel. While the handle is reading
  and the kernel holds data, a FIN is pending, or `read_buf` already holds a
  whole request, a readable event is eventually delivered. The last case is
  the reactor's re-drive of pipelined requests via `has_buffered_request()`
  (`_unified_reactor_impl.mojo:220-235, 832-855`). While the handle is
  writing, a writable event with room for at least one byte is eventually
  delivered, which is the kernel draining towards a reading peer.
- `Oracle.Ext` says that bytes appended behind a complete request do not
  change how it frames. Any HTTP/1.1 framer that decides a message from its
  own bytes has this property.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ConnLive.eventually_served` | if the handle is reading, not done, and `read_buf ++ kernel queue` frames as a complete request `r`, then some later position is either done, or has dispatched exactly `r` next, is back in STATE_READING and has written every queued response byte | proved |
| `Flare.L4.ConnLive.done_reason` | a step that makes the handle done sets `should_close`, and is a timer expiry, an I/O error, a FIN with no whole request buffered, or the flush of a response queued with `should_close` | proved |
| `Flare.L4.ConnLive.trace_done_sc` | on every trace, done implies `should_close` | proved |

Together with `ConnSM.responses_fifo` this gives: under fair delivery,
every whole request the peer sends is answered, in order, unless the
connection closes for one of the reasons in `done_reason`.

**Limitations.** Fairness is a hypothesis, not proved from the reactor
loop. The pipelined re-drive was checked by reading the cited lines.

### 18. Streaming bodies and TLS cross-interest (`Flare.L4.ConnStream`)

**Streaming model (`Stream`).** A handler that returns a streaming response
leaves the chunked head in `write_buf` and the source in `body_src`
(`_finalise_response`, `conn_handle.mojo:731-743`). The source is a list of
poll results (data, end of stream, or a raise), one per `next()` call; an
empty data chunk is an idle poll. `batch` mirrors `_stream_refill`
(1621-1642): at most `STREAM_BATCH_CHUNKS` chunks or `STREAM_BATCH_BYTES`
bytes, an empty chunk ends the batch, end of stream appends the terminator
and drops the source, a raise closes the connection. `wloop` mirrors the
flush and refill passes of `on_writable` (1286-1351), at most
`STREAM_EDGE_PASSES` per writable edge, and `finish` the tail (1364-1375).
Chunk framing and the terminator are parameters (L3). The kernel takes at
most `k` bytes per writable edge.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ConnStream.Stream.inv_onWritable` | the invariant holds across every writable edge: wire plus unsent `write_buf` equals the head followed by the rendering of the polls consumed so far, in source order; consumed and remaining polls tile the original source | proved |
| `Flare.L4.ConnStream.Stream.wire_exact_at_end` | back in STATE_READING, the wire is exactly the head, the framed non-empty chunks in source order, then the terminator | proved |
| `Flare.L4.ConnStream.Stream.wire_prefix` | at every point the wire is a prefix of that byte string | proved |
| `Flare.L4.ConnStream.Stream.interest` | still writing and not done means write interest only; back to reading means read interest; done means `should_close`; never write interest outside STATE_WRITING | proved |

**TLS model (`Tls`).** `SSL_read` may stop on `SSL_IO_WANT_WRITE`
(`conn_handle.mojo:501-507`) and `SSL_write` on `SSL_IO_WANT_READ`
(1231-1235); both set `tls_cross_interest` and arm read and write. The
reactor clears the flag and sends readable edges, and writable edges while
the flag is set, to the read driver (`_unified_reactor_impl.mojo:812-831`);
in STATE_WRITING the read driver's `on_readable` asks for writability and
the inline cycle runs `on_writable` (174-190). The TLS layer is an oracle:
each edge carries what `SSL_read` returns before it stops and why, and how
many bytes `SSL_write` takes before it stops and why.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ConnStream.Tls.blocked_interest` | whenever the pending operation stops on the opposite direction, the flag is set and both interests are armed | proved |
| `Flare.L4.ConnStream.Tls.retry_read`, `retry_write` | with the flag set, an edge of either kind retries the blocked operation | proved |
| `Flare.L4.ConnStream.Tls.read_fifo` | plaintext is appended to `read_buf` in the order `SSL_read` returns it | proved |
| `Flare.L4.ConnStream.Tls.inv_route` | after any routed edge the wire is the response prefix up to `write_pos`; a CLOSING handle is done | proved |
| `Flare.L4.ConnStream.Tls.interest_nonempty` | after any routed edge a live handle has some interest armed, and an unsent response has write interest | proved |

No defect was found. Two efficiency observations are listed under "Checked,
not a bug".

### 19. Interim `100 Continue` (`Flare.L4.Continue`)

**Model.** `_maybe_send_continue` (`conn_handle.mojo:544-576`) writes
`HTTP/1.1 100 Continue\r\n\r\n` once, from STATE_READING, with one
non-blocking write whose result it drops. The final response is then
serialised into a cleared `write_buf` and flushed from offset 0. `Plain`
takes the kernel's count `k` for the one `send` as an oracle. `Tls` models
`SSL_write` under flare's SSL modes (none are set in
`flare/tls/ffi/openssl_wrapper.cpp`). It returns the full length or a WANT
sentinel, never a short count. After a WANT the record stays pending, and a
later `SSL_write` from a different buffer fails with
`SSL_R_BAD_WRITE_RETRY`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Continue.Plain.violates` | for every `0 < k < 25`, the wire after the previous responses is `I.take k ++ R`, neither `R` nor `I ++ R` | proved (APP-49) |
| `Flare.L4.Continue.Plain.fixed_spec` | keeping the unsent tail and prepending it to `write_buf` gives `R` or `I ++ R` for every `k` | proved |
| `Flare.L4.Continue.Tls.violates` | if the interim record does not go out whole, the response's `SSL_write` fails and the connection closes with `R` unsent | proved (APP-49) |
| `Flare.L4.Continue.Tls.fixed_spec` | retrying the interim from a buffer the connection keeps, before the response, meets the spec in both outcomes | proved |

## Findings

Every repro below was run from the repository root with
`pixi run mojo -I . formal/repro/<file>.mojo`. The quoted `BUG REPRODUCED`
line is the output observed in this run, with exit status 1.

For each finding, the minimal fix was applied temporarily to the single flare
file named. The repro then printed the quoted `OK` line and exited 0. The
file was restored with `git checkout -- <file>`, and `git status --short
flare/` was confirmed clean.

Flip results for APP-20, 21, 22, 23 and 25 were recorded by the agents that
filed them.

Socket-based repros were re-checked for nondeterminism. APP-01, 04, 05 and
06 drive a `ConnHandle` over a loopback socket. They now poll
`on_readable` (up to 50 times, 20 ms apart) until a response is queued,
instead of a single 100 ms sleep. If no request arrives they raise a setup
error, never `OK`. APP-01 also requires the 426 to carry `Connection: close`
before it can print `OK`. Each of APP-01, 04, 05, 06, 46, 47 and 48 was run 3
times after these changes, and every run printed its `BUG REPRODUCED` line.
The flips for APP-01, 05, 06, 46 and 48 were re-run against the revised
repros and printed `OK`. APP-04's repro change affects only the wait,
so its flip was not repeated. All other flips were re-run for this report.
Every repro except APP-49 is `# PLATFORM: any`. APP-49 is `# PLATFORM:
linux`: it is run with `formal/repro/linux.sh` in the Linux container, and
its flip was done in the container's copy of the repo, which the next synced
run restores. All findings are status OPEN.

### APP-01: 426 response says `Connection: close` but the connection stays open

**Severity: Low.** The RFC rule is a MUST, but the client has already been
told to close. The only effect is on pipelined requests, which also bypass
`max_keepalive_requests`.

**RFC clause.** RFC 9112 §9.6: a server that sends `close` MUST initiate
closure and MUST NOT process further requests.

**What goes wrong.** `conn_handle.mojo:846-856` answers a WebSocket version
mismatch with a 426 through `_finalise_response(r426^, True)`. That function
only uses `close_after` for the header and never sets `should_close`. After
the flush, `on_writable` returns to READING, and the next request is served.

**Lean.** `Flare.Bugs.APP_01.ws426_close_header_but_kept_open` and
`violates_spec` give a reachable state with a close-header response and
`should_close = false`. The fix is proved sufficient by
`Flare.L4.ConnSM.fixed_no_request_after_close_header`.

**Fix.** Set `self.should_close = True` before the `return`.

**Repro.** `formal/repro/APP-01_ws426_keeps_connection_open.mojo`

- Observed: `BUG REPRODUCED: 426 sent 'Connection: close' but on_writable returned done=False, want_read= True state_reading= True`
- Flip: `OK: the 426 response closes the connection (done=True)`

### APP-02: `_wants_close` matches `connection:` mid-line and stops at the first hit

**Severity: Low.** The server keeps a connection alive against the client's
`close`.

**RFC clause.** RFC 9112 §9.6 and RFC 9110 §7.6.1.

**What goes wrong.** The scan in `keepalive_scan.mojo:432-480` matches the
bytes `connection:` at any offset, so it first hits inside `X-Connection:`,
and it `break`s after the first match. The real `Connection: close` line is
never read. The static and short-request fast paths then reply
`Connection: keep-alive`.

**Lean.** `Flare.Bugs.APP_02.wantsClose_misses_close` and `violates_spec`
use the 63-byte request with `X-Connection` at offset 27. The fix is proved
sufficient by `wantsCloseFixed_meets_spec`, which is general (via
`Flare.L4.KeepAlive.wantsCloseFixed_spec`).

**Fix.** Match only at line starts and OR the verdicts of all matching lines.

**Repro.** `formal/repro/APP-02_wants_close_substring_match.mojo`

- Observed: `BUG REPRODUCED: _wants_close returned False for a request carrying 'Connection: close' after an 'X-Connection' header`
- Flip: `OK: _wants_close honours 'Connection: close' after X-Connection`

### APP-03: `close` inside a `Connection` token list is ignored

**Severity: Low**, for the same reason as APP-02.

**RFC clause.** RFC 9110 §7.6.1 (`Connection = #connection-option`) and RFC
9112 §9.6.

**What goes wrong.** `_compute_close_after` (`keepalive_scan.mojo:357-397`)
compares the whole value with `close` and `keep-alive`. The values
`keep-alive, close` and `TE, close` match neither, and HTTP/1.1 defaults to
keep-alive.

**Lean.** `Flare.Bugs.APP_03.computeCloseAfter_misses_close` and
`violates_spec`. The fix is proved sufficient by
`computeCloseAfterFixed_meets_spec`, which is general.

**Fix.** Split on `,`, trim OWS, lowercase, and test each token.

**Repro.** `formal/repro/APP-03_connection_close_token_list.mojo`

- Observed: `BUG REPRODUCED: _compute_close_after kept the connection alive for Connection: 'keep-alive, close' -> False and 'TE, close' -> False`
- Flip: `OK: a close token inside a Connection list closes the connection`

### APP-04: the static fast path sends the body in reply to HEAD

**Severity: Medium.** The connection stays alive, so a keep-alive client
reads the body as the start of the next response. This is response
desynchronisation.

**RFC clause.** RFC 9110 §9.3.2: the server MUST NOT send content in a
response to HEAD. RFC 9112 §6.3.

**What goes wrong.** `on_readable_static` (`conn_handle.mojo:1174-1211`)
never inspects the method. It queues the whole pre-encoded GET response
with `Connection: keep-alive`.

**Lean.** `Flare.Bugs.APP_04.static_head_emits_body` (about the pre-fix
`staticBytesOld`). The shipped fix is proved to meet the spec by
`staticFixed_head_no_body` (via `Flare.L4.ConnSM.Framing.staticBytes_spec`).

**Fix.** For a request line starting with `HEAD `, queue only the bytes up to
the first CRLFCRLF.

**Repro.** `formal/repro/APP-04_static_head_sends_body.mojo`

- Observed: `BUG REPRODUCED: HEAD on the static path queued 13 body bytes after the headers; keep-alive= True`
- Flip: `OK: HEAD on the static path queues the head only`

Status: resolved. The static fast path now queues only the head (up to the first CRLFCRLF) of the pre-encoded bytes for a request line starting with `HEAD `. Test: `tests/http/test_server_reactor_state.mojo::test_static_head_queues_head_only`. The model `staticBytes` mirrors the fix; `staticBytesOld` is the pre-fix code.

### APP-05: an error response to HEAD carries a body

**Severity: Low.** The connection closes afterwards, so the bytes cannot
desynchronise a later response.

**RFC clause.** RFC 9110 §9.3.2.

**What goes wrong.** When the handler raises on a HEAD request, `_queue_error`
leads to `_serialize_response` (`conn_handle.mojo:1576-1594`). That calls
`serialize_response_into` without `head_request`, so the body is serialised.

**Lean.** `Flare.Bugs.APP_05.handler_error_head_emits_body` (status 500,
25-byte body). The fix is proved sufficient by `errorFixed_head_no_body`.

**Fix.** Pass `self.head_request`.

**Repro.** `formal/repro/APP-05_error_reply_to_head_has_body.mojo`

- Observed: `BUG REPRODUCED: error response to HEAD carries 25 body bytes: '500 Internal Server Error'`
- Flip: `OK: the error response to HEAD has no body`

### APP-06: the size cap `max_header_size + max_body_size` wraps

**Severity: Low.** It needs an "unlimited" body cap such as `Int.MAX`, which
`ServerConfig.check` accepts. With that config every request is refused.

**Spec.** A request within both limits is not rejected as too large.

**What goes wrong.** `conn_handle.mojo:448-453` (also 492-497 and 536-541)
computes `8192 + Int.MAX`, which wraps negative, so every non-empty buffer
gets 413.

**Lean.** `Flare.Bugs.APP_06.check_accepts`, `overflow_cap_rejects_one_byte`
and `violates_spec`. The fix is proved sufficient by `capFixed_spec` (via
`Flare.L4.ServerConfig.overCapFixed_eq_spec`).

**Fix.** Use `len - max_header_size > max_body_size` at all three sites.

**Repro.** `formal/repro/APP-06_size_cap_int_overflow.mojo`

- Observed: `BUG REPRODUCED: a 27 byte GET was answered 413 with max_body_size=Int.MAX`
- Flip: `OK: the GET is served with max_body_size=Int.MAX`

### APP-10: ComptimeRouter accepts a non-final `*` and ignores the rest of the pattern

**Severity: Low.** It needs an invalid route table, which the runtime router
rejects.

**Spec.** The pattern grammar: `*` must be last (`router.mojo:148-151`).

**What goes wrong.** `_match_one` (`routes.mojo:264-274`) treats a middle `*`
as a tail wildcard. `/files/*/meta` then matches `GET /files/a`.

**Lean.** `Flare.Bugs.APP_10.router_rejects`, `comptime_misroutes` and
`matchOne_violates_spec`. The fix is proved sufficient by `fixed_meets_spec`,
which is general.

**Fix.** Return false when the wildcard is not the last segment.

**Repro.** `formal/repro/APP-10_comptime_router_nonfinal_wildcard.mojo`

- Observed: `BUG REPRODUCED: pattern /files/*/meta matched GET /files/a with status 200 body meta:a`
- Flip: `OK: GET /files/a is 404 for pattern /files/*/meta`

### APP-20: `negotiate_encoding` mishandles `*`

**Severity: Low.** RFC 9110 §12.1 allows a non-preferred response, so no
MUST is broken. The effect is a weaker or missing compression choice.

**RFC clause.** RFC 9110 §12.5.3.

**What goes wrong.** `middleware.mojo:236-240` counts `*` only while
`best_q == 0`, and the `*` entry always selects identity. Three headers show
the problem:

- `gzip;q=0.5, *` gives gzip, where the spec gives br.
- `*, gzip;q=0.5` gives identity, so the result depends on entry order.
- `identity;q=0, *` gives identity, an encoding the client refused.

**Lean.** `Flare.Bugs.APP_20.negotiate_violates_spec`. The fix is proved
sufficient by `fixed_meets_spec`, which is general.

**Fix.** Track the `*` weight and the per-coding maxima, then pick after the
loop.

**Repro.** `formal/repro/APP-20_negotiate_wildcard.mojo`

- Observed: `BUG REPRODUCED: 'gzip;q=0.5, *' -> gzip / '*, gzip;q=0.5' -> identity (brotli on, expected br for both); 'identity;q=0, *' -> identity (expected gzip)`
- Flip: `OK: wildcard weights honoured: br br gzip`

### APP-21: the CORS allowlist is order dependent under credentials

**Severity: Low.** The failure is fail-closed.

**Spec clause.** Fetch §3.2.

**What goes wrong.** `cors.mojo:94-95` returns `not allow_credentials` at the
first `*`. With credentials on, `["*", origin]` therefore rejects a listed
origin.

**Lean.** `Flare.Bugs.APP_21.violates_spec`. The fix is proved sufficient by
`fixed_meets_spec`, which is general.

**Fix.** On `*` with credentials, `continue` instead of returning.

**Repro.** `formal/repro/APP-21_cors_credentials_order.mojo`

- Observed: `BUG REPRODUCED: with credentials, ['*', origin] gives ACAO '' but [origin, '*'] gives 'https://app.example.com'`
- Flip: `OK: listed origin allowed in both orders: https://app.example.com https://app.example.com`

### APP-22: `Vary: Origin` is missing on responses the CORS middleware does not stamp

**Severity: Low.** The risk is cache mixing.

**Spec clause.** Fetch §3.2.5.

**What goes wrong.** `cors.mojo:160-171` returns the inner response unchanged
when `Origin` is absent or rejected, without adding `Vary`.

**Lean.** `Flare.Bugs.APP_22.missing_vary` and `violates_spec`. The fix is
proved sufficient by `fixed_meets_spec`.

**Fix.** Append `Vary: Origin` on every path.

**Repro.** `formal/repro/APP-22_cors_missing_vary.mojo`

- Observed: `BUG REPRODUCED: ACAO varies with Origin ('https://a.example' for https://a.example, absent otherwise) but Vary: Origin is missing on the no-Origin response (False) / rejected-origin response (False)`
- Flip: `OK: Vary: Origin present on all responses`

### APP-23: `Url.parse` does not end the authority at `?` (host confusion)

**Severity: Medium.** The input is a valid RFC 3986 URI on which an allowlist
check of `Url.parse(u).host` disagrees with browsers and curl.

**RFC clause.** RFC 3986 §3.2.

**What goes wrong.** `url.mojo:101-123` cuts the authority only at `/` and
takes the fragment at the last `#`.

- `http://evil.com?@good.com/` gives host `good.com`.
- `http://good.com?x=/y` gives host `good.com?x=`.

**Lean.** `Flare.Bugs.APP_23.host_confusion` (about the pre-fix `parseOld`).
The shipped `parse` is proved to meet the spec by `implFixed_meets_spec` and
`Flare.L4.Url.parseWith_fixedSplit_hostInAuthority`.

**Fix.** Find the first `#`, and end the authority at the first `/` or `?`.

**Repro.** `formal/repro/APP-23_url_authority_query_host_confusion.mojo`

- Observed: `BUG REPRODUCED: Url.parse('http://evil.com?@good.com/').host = 'good.com' (query ''), Url.parse('http://good.com?x=/y').host = 'good.com?x='; RFC 3986 hosts are 'evil.com' and 'good.com'`
- Flip: `OK: authority ends at '?': hosts evil.com and good.com query @good.com/`

Status: resolved. Url.parse takes the fragment at the first `#` and ends the authority at the first `/` or `?` (an authority ending at `?` gets path `/`). Tests: `tests/http/test_http.mojo::test_url_authority_ends_at_query`, `::test_url_fragment_starts_at_first_hash`. The model `parse` mirrors the fix; `parseOld` is the pre-fix pipeline.

### APP-24: `urldecode` returns a `String` holding ill-formed UTF-8

**Severity: Medium.** The input is attacker-controlled: it is reachable from
any form body through `parse_form_urlencoded` and the `Form` extractor. It
breaks the `String(unsafe_from_utf8=...)` safety precondition.

The repro observes only the ill-formed string. The out-of-bounds read during
code-point iteration is what the stdlib contract allows, not something
observed here.

**Spec.** RFC 3629, and WHATWG URL §5.1 ("UTF-8 decode without BOM").

**What goes wrong.** `form.mojo:87` wraps the decoded bytes with
`unsafe_from_utf8`. As a result, `%F0` yields the single byte `0xF0`.

**Lean.** `Flare.Bugs.APP_24.urldecode_violates_spec` and `parseForm_F0`.
The shipped fix (about the pre-fix `urldecodeOld`) is proved to meet the
spec by `urldecodeFixed_meets_spec` and `urldecodeFixed_roundtrip`;
`parseForm_rejects_F0` shows the form path rejects `a=%F0`.

**Fix.** Use `String(from_utf8=...)` (which raises) or the lossy decode.

**Repro.** `formal/repro/APP-24_urldecode_invalid_utf8.mojo`

- Observed: `BUG REPRODUCED: urldecode('%F0') / parse_form_urlencoded('a=%F0') produced a String that is not valid UTF-8 (direct: True , form: True )`
- Flip: `OK: urldecode never yields ill-formed UTF-8 for '%F0'`

Status: resolved. urldecode now builds its result with `String(from_utf8=...)` and raises when the decoded bytes are not valid UTF-8; `parse_form_urlencoded` and the `Form` extractor reject such bodies (400). Tests: `tests/http/test_form.mojo::test_urldecode_rejects_ill_formed_utf8`, `::test_urldecode_accepts_well_formed_utf8`, `::test_parse_ill_formed_utf8_raises`. Decision: raise (the Lean fix) rather than substitute U+FFFD, so callers never silently accept altered data.

### APP-25: userinfo is split at the first `@`

**Severity: Low.** The input is not valid RFC 3986, but the resulting host
differs from the one WHATWG and curl pick.

**RFC clause.** RFC 3986 §3.2.2: no host form contains `@`.

**What goes wrong.** `url.mojo:143-148` splits at the first `@`, so
`http://a@evil.com@good.com/` gives host `evil.com@good.com`.

**Lean.** `Flare.Bugs.APP_25.host_has_at`. The fix is proved sufficient by
`implFixed_meets_spec` and `Flare.L4.Url.parseWith_fixedStrip_noAt`.

**Fix.** Use `_rfind(authority, "@")`.

**Repro.** `formal/repro/APP-25_url_userinfo_first_at.mojo`

- Observed: `BUG REPRODUCED: Url.parse('http://a@evil.com@good.com/').host = 'evil.com@good.com' contains '@' (WHATWG/curl host: 'good.com')`
- Flip: `OK: host has no '@': good.com`

### APP-26: Compress re-encodes a 206 Partial Content body and keeps its `Content-Range`

**Severity: Medium.** It affects data integrity for range clients when
Compress wraps a handler that serves ranges. `FileServer` does exactly that
(`fs.mojo:381-430`) and advertises `Accept-Ranges: bytes`. Resumed or
parallel downloads that also send `Accept-Encoding: gzip` receive a body
that does not match its `Content-Range`.

**RFC clause.** RFC 9110 §14.4 and §8.4: the offsets in `Content-Range`
refer to the selected representation, content coding included.

**What goes wrong.** `middleware.mojo:345-376` checks the pick, the size and
an existing `Content-Encoding`, but not the status or `Content-Range`. The
2048 identity bytes are gzipped to 35 bytes. `Content-Length` is rewritten,
while `Content-Range: bytes 0-2047/10000` stays.

**Lean.** `Flare.Bugs.APP_26.partial_reencoded` and `violates_spec` (about
the pre-fix `compressOld`), against the spec `PartialSpec` ("a partial
response passes through unchanged"). `partial_body_replaced` states the
general case. The shipped `compress` is proved to meet it by
`fixed_meets_spec` (via
`Flare.L4.Middleware.compress_partial`), which is general.

**Fix.** Return the inner response unchanged when the status is 206 or it
carries `Content-Range`.

**Repro.** `formal/repro/APP-26_compress_encodes_partial_content.mojo`. It
uses a stub inner handler that returns what FileServer returns for
`Range: bytes=0-2047`.

- Observed: `BUG REPRODUCED: 206 with Content-Range 'bytes 0-2047/10000' was re-encoded as gzip; body is 35 bytes, Content-Length 35`
- Flip (the two lines after the `content-encoding` check in `flare/http/middleware.mojo`): `OK: partial response passed through unencoded (status 206, 2048 bytes)`

Status: resolved. Compress.serve returns a 206, or any response carrying `Content-Range`, unchanged (no re-encoding, Content-Range and Content-Length intact). Tests: `tests/http/test_middleware.mojo::test_compress_partial_content_passthrough`, `::test_compress_content_range_header_passthrough`. The model `compress` mirrors the fix; `compressOld` is the pre-fix code.

### APP-27: Compress omits `Vary: Accept-Encoding` on the identity responses it negotiated

**Severity: Low.** This is a SHOULD. A shared cache can store the identity
variant as the only one, and the cost is lost compression.

**RFC clause.** RFC 9110 §12.5.5.

**What goes wrong.** For a body at or above `min_size_bytes` that is not
already encoded, the representation depends on `Accept-Encoding`. Only the
encoding branch appends `Vary`. The identity response for the same URL
(sent when there is no `Accept-Encoding`, when identity is preferred, or
when every coding is refused) has no `Vary`.

**Lean.** `Flare.Bugs.APP_27.identity_without_vary` and `violates_spec`,
against the spec `VarySpec`. The fix is proved sufficient by
`fixed_meets_spec` (via `Flare.L4.Middleware.compressFixed_vary`), which is
general.

**Fix.** Append `Vary: Accept-Encoding` on every response past the size and
already-encoded checks.

**Repro.** `formal/repro/APP-27_compress_missing_vary_on_identity.mojo`

- Observed: `BUG REPRODUCED: gzip response has Vary: Accept-Encoding (gzip) but the identity response for the same URL has none`
- Flip (`Vary` appended before the `quality == 0` check, later append removed): `OK: Vary: Accept-Encoding on both variants`

### APP-40: the RateLimit refill product wraps after a long idle period

**Severity: Medium.** The middleware causes its own multi-hour outage. A
negative token count is stored, and `last` does not advance, so the state
keeps getting worse. At `1e6/s` the wrap needs only 2.56 h of idle time.

**Spec.** The token bucket in the docstring.

**What goes wrong.** `reliability.mojo:369-374` computes
`(elapsed * rate) // 1_000_000`, and the product wraps `Int64`.

**Lean.** `Flare.Bugs.APP_40.full_bucket_rejected_after_idle` and
`product_overflows`. The fix is proved sufficient by
`implFixed_refines_spec`, and `Flare.L4.RateLimit.overflow_iff` gives the
exact threshold.

**Fix.** Clamp `elapsed` to the time needed to fill the bucket (shipped).

**Repro.** `formal/repro/APP-40_ratelimit_refill_overflow.mojo`

- Observed: `BUG REPRODUCED: full bucket after 9300 s idle at rate 1e6/s returned 429 ; stored milli-tokens now -9145744073710`
- Flip: `OK: request admitted after 9300 s idle; milli-tokens 999999000`

Status: resolved. `serve` clamps `elapsed` to `max_elapsed = burst * 1e9 // rate + 1` before forming the refill product. Test: `tests/http/test_reliability.mojo::test_ratelimit_full_bucket_admits_after_a_long_idle_period`; the repro now prints `OK:`. The shipped model is `Flare.L4.RateLimit.step`; `Flare.Bugs.APP_40.implFixed_refines_spec` is `step_eq_spec` for it.

### APP-41: CircuitBreaker measures the cooldown from the start of the failing request

**Severity: Medium.** A failure slower than `cooldown_ms` opens the breaker
already expired. Slow upstreams are the main case breakers exist for.

**Spec.** The docstring at `reliability.mojo:404-411`.

**What goes wrong.** `now` is read on entry (449) and stored as the
opened-at time (435-440, 463, 468).

**Lean.** `Flare.Bugs.APP_41.slow_failure_skips_cooldown`. The fix is proved
sufficient by `fixed_cooldown_respected`.

**Fix.** Call `_record_failure(Int64(perf_counter_ns()))` at both sites (shipped).

**Repro.** `formal/repro/APP-41_circuitbreaker_cooldown_from_request_start.mojo`

- Observed: `BUG REPRODUCED: call right after the trip returned 500 and the inner handler ran 2 times (expected 503, 1 call); first status 500`
- Flip: `OK: breaker fast-failed with 503 during cooldown; inner calls 1`

Status: resolved. Both `_record_failure` call sites in `serve` now pass `perf_counter_ns()` read when the failure is recorded, so the cooldown counts from the failure. Test: `tests/http/test_reliability.mojo::test_circuitbreaker_cooldown_counts_from_the_failure_not_the_request`; the repro now prints `OK:`. The shipped model is `Flare.L4.CircuitBreaker.stepShipped` (`fix41` on, `fix42` off until APP-42); `Flare.Bugs.APP_41.shipped_meets_spec` is stated about it.

### APP-42: CircuitBreaker admits every request while HALF_OPEN

**Severity: Low.** Concurrent requests reach a recovering upstream during the
single-probe window.

**Spec.** The docstring at `reliability.mojo:31-34` and 409-411: "one
probe".

**What goes wrong.** `serve` tests only `state == OPEN` (450-460).

**Lean.** `Flare.Bugs.APP_42.halfopen_admits_two`. The fix is proved
sufficient by `fixed_halfopen_one_probe` and `fixed_both`.

**Fix.** Fast-fail on HALF_OPEN, and claim the transition with a
compare-and-swap.

**Repro.** `formal/repro/APP-42_circuitbreaker_halfopen_unbounded_probes.mojo`

- Observed: `BUG REPRODUCED: while worker 1's probe was in flight (HALF_OPEN), worker 2 got 200 and its upstream ran 1 time(s); expected 503 and 0. trip status 500 probe status 200`
- Flip: `OK: second request fast-failed with 503 while the probe was in flight`

### APP-43: a network-path `Location` (`//host/path`) is resolved as a path

**Severity: Low.** The client fetches the wrong resource, and
`same_origin_only` does not reject the hop. Credentials stay on the original
host, so nothing leaks.

**RFC clause.** RFC 9110 §10.2.2, and RFC 3986 §4.2 and §5.2.2.

**What goes wrong.** `redirect_policy.mojo:171-172` returns
`origin + location` for any reference that starts with `/`.

**Lean.** `Flare.Bugs.APP_43.network_path_resolved_as_path` and
`violates_spec`. The fix is proved sufficient by `resolveFixed_network_path`
and `resolveFixed_other`.

**Fix.** For a reference starting with `//`, return `scheme + ":" + location`.

**Repro.** `formal/repro/APP-43_redirect_network_path_location.mojo`

- Observed: `BUG REPRODUCED: '//cdn.example.net/img' against https://api.example.com/a resolved to https://api.example.com:443//cdn.example.net/img ; decide next_url https://api.example.com:443//cdn.example.net/img forward_authorization True`
- Flip: `OK: network-path Location resolved to https://cdn.example.net/img`

### APP-44: `_same_origin` compares hosts case-sensitively

**Severity: Low.** The failure is fail-safe: the redirect is refused
spuriously and credentials are dropped.

**RFC clause.** RFC 6454 §4 and RFC 3986 §3.2.2.

**What goes wrong.** `redirect_policy.mojo:188-198` compares with
`a.host != b.host`, and `Url.parse` keeps the host's case.

**Lean.** `Flare.Bugs.APP_44.host_case_not_same_origin`. The fix is proved
sufficient by `sameOriginFixed_case`.

**Fix.** Compare lowercased hosts.

**Repro.** `formal/repro/APP-44_same_origin_host_case.mojo`

- Observed: `BUG REPRODUCED: _same_origin(API.example.com, api.example.com) = False ; same_origin_only decide action = 2 (0=FOLLOW, 2=REJECT)`
- Flip: `OK: host comparison is case-insensitive`

### APP-45: relative references are not resolved per RFC 3986 §5.2

**Severity: Low.** The client fetches the wrong resource.

**RFC clause.** RFC 3986 §5.2.2 and §5.4.1.

**What goes wrong.** Two cases are wrong:

- `?page=2` against `http://h/list/items` gives `http://h:80/list/?page=2`.
- Dot segments are kept, so `../g` against `/b/c/d` gives `/b/c/../g`.

**Lean.** `Flare.Bugs.APP_45.query_only_reference_wrong` and
`dot_segments_kept`. The fix is proved sufficient by
`resolveFixed_query_only`, which covers the query-only case.

**Fix.** For `?` references, return `origin + base.path + location`. The
full fix also applies `remove_dot_segments`.

**Repro.** `formal/repro/APP-45_redirect_relative_reference_resolution.mojo`

- Observed: `BUG REPRODUCED: '?page=2' against http://h/list/items -> http://h:80/list/?page=2`
- Flip: `OK: query-only reference resolved per RFC 3986: http://h:80/list/items?page=2`

### APP-46: single-worker `drain(timeout_ms)` is a hard stop

**Severity.** Medium. Graceful shutdown of a single-worker server cuts every
in-flight response, which is what `drain` exists to avoid.

**Spec.** flare's own contract: `close()` (`server.mojo:1680-1689`) is the
"hard stop" where "in-flight handlers may be cut mid-write -- there is no
wait. Use drain(timeout_ms) for a graceful tear-down"; `drain` (1695-1701)
"waits up to timeout_ms milliseconds for in-flight reactor events to
flush"; its Notes (1729-1731): "The drain timeout bounds the wait for
handlers to return".

**What goes wrong.** `drain` (1733-1755) closes the listener, sets
`_stopping` and returns; `timeout_ms` is never read. The inline comment
(1746-1752) calls the timeout "advisory on this path". The reactor on the
serving thread sees the flag within one poll (at most 100 ms) and closes
every live connection (`_unified_reactor_impl.mojo:1000-1046`).

**Lean.** `Flare.Bugs.APP_46.cut_example` (1000 bytes pending, 1 byte/ms,
`timeout_ms = 5000`: 100 bytes delivered), `violates_spec`. Fix: after
closing the listener, wait out `timeout_ms` before setting `_stopping`;
`fixed_meets_spec`, `fixed_on_example`.

**Repro.** `formal/repro/APP-46_drain_is_hard_stop.mojo`: `serve()` on a
second thread, a 32 MiB response read at 64 KiB every 5 ms, `drain(5000)`
200 ms in. Observed:
`BUG REPRODUCED: drain(timeout_ms=5000) returned after 0 ms (report drained=0 in_flight=0) and the in-flight 32 MiB response was cut: the client (reading 64 KiB every 5 ms) got 4627156 bytes`.

**Flip.** A 1 ms sleep loop until `timeout_ms` has elapsed, between the
listener close and `_stopping = True`:
`OK: in-flight response fully delivered during drain (33554538 bytes, drain took 5000 ms)`, exit 0.
The inline comment reports that `libc_nanosleep_ms` once showed a large
wall-clock multiplier in this call context; with the 1 ms sleeps of the
flip the measured drain was 5000 ms, as requested.

**Determinism.** If `drain` closed the listener before the reactor accepted
the connection, the client would get no bytes and the repro would report a
false bug. The repro now waits until the client has received response
bytes before calling `drain`, and prints `inconclusive:` if none arrive
within 5 s. Under the bug, the reader cannot absorb 32 MiB within the
window, so a false `OK` is not possible. After this change: 3 of 3 runs
printed `BUG REPRODUCED` (3669108, 3930368 and 4758020 bytes received).
The flip was re-run with 10 ms `usleep` steps and printed `OK: in-flight
response fully delivered during drain (33554538 bytes, drain took 6798 ms)`,
exit 0.

Status: resolved. `HttpServer.drain` closes the listener, waits `timeout_ms` (negative clamps to 0; 1 ms sleeps bounded by `monotonic_now_ms`), then sets `_stopping`; `drain(0)` is still `close()`. Tests: `tests/http/test_server_drain.mojo::test_drain_lets_an_in_flight_response_finish`, `::test_drain_waits_out_the_timeout_before_stopping`; the repro now prints `OK:` (3 of 3 runs). The shipped delay is `Flare.L4.Drain.stopDelayFixed`; `Flare.Bugs.APP_46.fixed_meets_spec` is stated about it. Decision: the single-worker path always waits the full `timeout_ms`, since it publishes no live-connection count (idle keep-alive connections would count as live anyway); documented in the docstring and `docs/operations.md`.

### APP-47: an h2c upgrade whose 101 flushes on a writable edge never migrates

**Severity.** Medium. The connection busy-spins on writability, the server
never sends its HTTP/2 preface, and the upgrade request is never answered.
It needs the 101 to be held back by a full send buffer, for example behind
a large earlier response on the same connection that the client has not
read yet. `conn_handle.mojo:877-880` names this exact failure ("a loop that
cannot migrate the connection would leave it write-armed forever
re-announcing the upgrade (a busy spin)") as the reason h2c is refused over
TLS; the writable-edge path has the same problem in cleartext.

**Spec.** RFC 7540 §3.2: after the 101 the server's first bytes are its
connection preface, and the upgrade request is answered as stream 1.

**What goes wrong.** See section 16: a writable edge goes to
`_drive_h1_writable`, which applies the step without migrating; the step
has no interest bits, so `_apply_step` leaves write interest armed and
every poll returns another writable edge.

**Lean.** `Flare.Bugs.APP_47.violates_spec`. Fix: also route a writable
edge to `_drive_h1` while `_h2c_upgrade_pending` is set;
`fixed_meets_spec`.

**Repro.** `formal/repro/APP-47_h2c_upgrade_lost_on_writable_edge.mojo`
drives `_unified_handle_conn_event` with real reactor events. The first
version was nondeterministic on macOS: socket-buffer autotuning sometimes
let the 101 flush inline, so the writable-edge path was never reached and
the run printed a false `OK`; one run also hung. It now pins both
socket buffers, refills the send buffer until a pass after a pause sends
nothing, and counts an attempt only if the 101 is still queued after the
first event (up to five attempts, else inconclusive). Observed 8 of 8 runs
on macOS and on Linux:
`BUG REPRODUCED: 101 flushed on a writable edge but the connection was never migrated: still KIND_H1 after 5 polls, 5 writable edges delivered, client received 71 bytes after the backlog (101 is 71 bytes; no SETTINGS frame)`.

**Flip.** `if is_readable or (tls_cross and is_writable) or h1_ptr[]._h2c_upgrade_pending:`
at `_unified_reactor_impl.mojo:812`: 5 of 5 runs
`OK: connection migrated (kind 2), client received 92 bytes after the backlog (101 + SETTINGS)`, exit 0.

### APP-48: a WebSocket upgrade on a TLS connection is served in cleartext

**Severity.** High. With `bind_tls` and `ServerConfig.ws` set, a `wss://`
handshake is answered in cleartext on the TLS socket, and every WebSocket
frame the handler sends after that goes out unencrypted. The client's TLS
stack fails on the first non-record byte, so data leaks to the network
rather than being exchanged.

**Spec.** flare's documented contract (`server.mojo:813-814`,
`conn_handle.mojo:1506-1508`): "Cleartext only: a wss:// connection is
terminated by the TLS connection handler, which has no upgrade seam."

**What goes wrong.** `on_readable` (`conn_handle.mojo:857`) takes the
WebSocket branch whenever `config.ws.handler` is set; `_handle_ws_upgrade`
(1476-1574) detaches the raw fd and writes with a plain `TcpStream`. The
h2c branch just below checks `not self.tls` (881). TLS connections reach
this code through `_migrate_tls` (`_unified_reactor_impl.mojo:545-552`).

**Lean.** `Flare.Bugs.APP_48.violates_spec`. Fix: `if config.ws.handler and
not self.tls:`; `fixed_meets_spec` (TLS connections stay inside TLS,
cleartext behaviour unchanged).

**Repro.** `formal/repro/APP-48_ws_upgrade_over_tls_sends_cleartext.mojo`
peeks at the raw TCP bytes the server sends back inside a TLS session.
Observed: after the TLS session-ticket records, the cleartext
`HTTP/1.1 101 Switching Protocols ...` and an unencrypted text frame
carrying `secret-token`.

**Determinism.** The first version peeked once after 300 ms. If only the
session-ticket records had arrived by then, it would have printed a false
`OK`. The repro now peeks for up to 2 s and searches the raw bytes for a
cleartext `HTTP/1.1 101` or `secret-token` at any offset. It prints `OK`
only if there is no cleartext and the answer decrypts through TLS to an
HTTP response; otherwise it prints `inconclusive:`. 3 of 3 runs printed:
`BUG REPRODUCED: raw TCP bytes on the TLS connection contain cleartext at offset 510 of 653: HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n...`
(the tail is the binary WebSocket frame).

**Flip.** `OK: no cleartext on the wire (684 raw bytes, first byte 23); the answer decrypts to 'HTTP/1.1 200 OK'`, exit 0.

Status: resolved. `on_readable` computes `config.ws.handler and not self.tls` once and uses it for both the version-mismatch 426 and the upgrade, so a handshake on TLS is served as plain HTTP/1.1 inside TLS. Test: `tests/http/test_server_ws_upgrade.mojo::test_ws_handshake_on_tls_is_never_upgraded_in_cleartext`; the repro now prints `OK:`.

### APP-49: an interim `100 Continue` the socket does not take whole is never completed

**Severity.** Medium. On cleartext the client receives a truncated interim
line glued to the final response, for example
`HTTP/1.1 100 Continue\r\n\rHTTP/1.1 200 OK`. No client can parse that
stream. On TLS the final response is lost and the connection is torn down.
Both need the socket send buffer to be nearly full when the head of an
`Expect: 100-continue` request is read. That happens with a pipelining or
slow-reading client after a large response, because the connection returns
to STATE_READING as soon as the previous response has been handed to the
kernel. The cleartext case needs a short `send`, which Linux allows. It does
not happen on BSD or macOS, where a non-blocking TCP `send` below the
low-water mark is all or nothing. The TLS case needs only that the 47-byte
record cannot be written whole.

**Spec.** RFC 9112 §2.1 and §4, RFC 9110 §15.2: a server sends complete
messages, and an interim response is a whole status line and header
section; a request read whole is answered.

**What goes wrong.** `_maybe_send_continue` (`conn_handle.mojo:544-576`)
drops the result of `_send` (cleartext) or `tls.send` (TLS) and sets
`continue_sent` either way. The docstring calls the write best effort and
relies on the client's fallback, which covers an interim that was not sent
at all, not one that was partly sent. Cleartext: the kernel's partial count
is lost, and the response's bytes follow the partial interim. TLS: flare
sets no SSL mode, so `SSL_write` returns WANT_WRITE rather than a short
count. OpenSSL keeps the record pending. `_flush_write_buf_tls` then calls
`SSL_write` from `write_buf`, a different buffer, which OpenSSL rejects with
`SSL_R_BAD_WRITE_RETRY`. flare classifies that as fatal and sets
`should_close`.

**Lean.** `Flare.Bugs.APP_49.violates_spec` covers every short send,
including the observed 24-of-25 case (`observed_wire`).
`tls_response_lost` covers the TLS case. Fix: cleartext, keep the unsent
tail and put it in front of the response in `write_buf`
(`_transition_to_writing`); TLS, keep the interim in a buffer the connection
owns and retry `SSL_write` from it at the start of `_flush_write_buf_tls`.
`fixed_meets_spec` covers both.

**Repro.** `formal/repro/APP-49_continue_partial_send_corrupts_stream.mojo`,
`# PLATFORM: linux`, run with `formal/repro/linux.sh` (Linux 6.12,
aarch64). A client sets SO_RCVBUF 4096 before connecting, then pipelines a
GET and the head of a POST with `Expect: 100-continue`, reading nothing.
The accepted socket has SO_SNDBUF 2048. The repro drives `ConnHandle` and
varies the size of the first response. A variant counts only if, after the
client has read the whole first response, the interim is short (cleartext)
or absent (TLS); otherwise the repro prints `inconclusive:`. A Python sweep
in the same container found the cleartext window first: the kernel takes
`6144 - L` bytes after an `L`-byte write for `6119 < L < 6144`, on every
repeat, but only when the client's small window is set before connect and
the interim follows the flush immediately. 3 of 3 runs printed:
`BUG REPRODUCED: cleartext: send took 24 of 25 bytes of the 100 Continue after a 6120 byte response; the client then read HTTP/1.1 100 Continue\r\n\rHTTP/1.1 200 OK\r\nCon`
and
`BUG REPRODUCED: TLS: the interim record did not go out after a 2922 byte response (client read it all, then nothing for 300 ms); the final response step closed=True and the client then read 0 bytes:`.
On macOS neither precondition was met in 300 cleartext and 1600 TLS sizes,
and the repro printed `inconclusive:` for both.

**Flip.** Both fixes in `flare/http/_reactor/conn_handle.mojo`, in the
container's copy (restored by the next sync):
`OK: cleartext: send took 24 of 25 bytes of the 100 Continue after a 6120 byte response; the client then read HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nCo`
and
`OK: TLS: the interim record did not go out after a 2922 byte response (client read it all, then nothing for 300 ms); the final response step closed=False and the client then read 126 bytes: HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nCo`,
exit 0.

## Documentation gaps

- **Percent-decoding claim.** `docs/features.md:279` lists "`Url`,
  `UrlParseError`: URL parser, percent decoding" for `flare.http.url`.
  `url.mojo` performs no percent-decoding: host, path, query and fragment
  are returned raw. Percent-decoding lives in `flare.http.form` (`urldecode`).
- **Single-worker drain** (the timeout itself is APP-46). The docs describe a timed, measured drain:
  - `docs/features.md:110` lists "`HttpServer.drain(timeout_ms) -> ShutdownReport` per worker";
  - `docs/architecture.md:291` shows drain flipping `SHUTDOWN` on live connections;
  - the method's own summary (`server.mojo:1697-1701`) says it "waits up to `timeout_ms` milliseconds for in-flight reactor events to flush";
  - its Notes paragraph (1729-1731) says "The drain timeout bounds the wait for handlers to return".

  The body (1733-1755) closes the listener, sets `_stopping` and returns
  at once. The inline comment (1743-1752) says the wait is "capped at 1ms",
  but no sleep call follows. The report has all counts zero
  (`Flare.L4.Drain.drain_ignores_timeout`, `drain_report_zero`). The
  docstring's "Returns" paragraph and the inline comment do say this, so the
  code is consistent with part of its own documentation. The summary line
  and `features.md` are not. Only the multi-worker `Scheduler.drain` (L5)
  measures anything.
- **Redirect method rewriting.** The `RedirectDecision` docstring
  (`redirect_policy.mojo:134-137`) documents POST, PUT and PATCH becoming
  GET on 301/302/303. The code does this for DELETE as well
  (`decide_301_delete_is_get`). RFC 9110 §15.4.2 permits it only for POST.
  This is documented behaviour, recorded here as a deviation.

## Checked, not a bug

- **ConnSM.** Pipelined requests are answered in order, exactly once, and the
  wire is always a prefix of the queued responses (`responses_fifo`,
  `wire_is_responses`). Timeouts always close (`timeout_closes`). No request
  is dispatched after `should_close` (`run_segs_frozen`). The keep-alive
  count respects `max_keepalive_requests` (`ka_bound`). The general
  serialiser omits the body for HEAD, 1xx, 204 and 304 (`serialize_spec`);
  APP-04 and APP-05 are the two paths that bypass it.
- **ServerConfig.** `check` lets the idle (head) timer exceed
  `request_timeout_ms` (`head_timer_unordered`). The request budget is still
  enforced on every readable event, and `closeTime_le` bounds the read phase
  by `R + T`. This is an observation, not a defect.
- **Router.** Registration-order shadowing is documented design
  (`first_route_wins`). Mounts match whole segments (`mount_boundary`).
  `Allow` is exact and duplicate-free (`allow_exact`). The query never
  affects routing. ComptimeRouter equals Router on every valid table.
- **Middleware composition.** Logger is transparent. CatchPanic is total and
  idempotent. The order of RequestId and CatchPanic matters
  (`requestId_outside_catchPanic` versus
  `catchPanic_outside_requestId_error`); this is a usage note, not a defect.
- **Content negotiation.** Passthrough instead of 406 is permitted by RFC 9110
  §12.5.3, §12.1 and §15.5.7. Other behaviours:
  - A malformed q value is fail-open, as documented.
  - More than three decimals are truncated; such input is malformed.
  - Duplicate entries resolve to the maximum.
  - Names are case-insensitive.
  - `x-gzip` is not recognised: a minor SHOULD deviation (§8.4.1.3), not filed.
- **CORS.** ACAO `*` with credentials is impossible. An unlisted origin is
  never admitted. Preflight method and header lists are not validated; this
  is documented, and the browser enforces them.
- **Cookies.** `Set-Cookie` output never contains CR, LF or other controls.
  `SameSite=None` always carries `Secure`. Max-Age parsing cannot wrap.
- **Form.** The round trips `urldecode(urlencode s) = s` and
  `parse(to_urlencoded fd) = fd` hold for all well-formed UTF-8 strings (for
  all byte strings before the APP-24 fix, which was the only defect).
- **Url.** These behaviours were checked and are not filed:
  - `HTTP://` in upper case is rejected (fail-closed).
  - An empty port raises.
  - Ports longer than five digits are rejected, as an overflow guard.
  - Port 0 is rejected.
  - Trailing junk after `]` is accepted, with no host confusion.
  - Port overflow is impossible (`parsePort_fits`).
- **Redirect.** Termination is proved. Credential confinement and
  monotonicity hold for every server. Dropping credentials permanently is
  stricter than curl, which is fail-safe.
- **Retry.** With `max_backoff_ms <= 0` (no cap) the budget wraps at attempt
  59 (`uncapped_wraps`). This needs an explicitly uncapped policy and more
  than 58 attempts, so it is not filed.
- **ClientPool.** The per-host and total caps hold in every reachable state,
  and no fd is handed to a different origin (`caps`, `acquire_same_origin`).
  The pool key is not lowercased, so host spellings get separate buckets; this
  is a missed reuse, noted under APP-44. A double `release` by the caller
  would hand an fd out twice. The documented contract (`release`
  docstring) puts this on the caller, and `HttpClient`, its only caller,
  disposes of each fd exactly once (section 15).
- **Idle streaming source.** When a streaming source polls idle, `on_writable`
  returns with write interest armed and an empty buffer. On the
  level-triggered reactor the socket is writable at once, so the source is
  polled again on every reactor turn: a busy poll while the source is idle.
  Bytes and order are correct (`Stream.inv_onWritable`), and the connection
  never loses interest (`Stream.interest`). This is a CPU cost, not a
  correctness defect.
- **TLS write blocked on read.** While `SSL_write` waits for peer data
  (`SSL_IO_WANT_READ`) both interests are armed, so writable edges keep
  arriving and each retries `SSL_write` until the peer's record arrives. This
  spins in the same way; liveness and the wire invariant hold
  (`Tls.retry_write`, `Tls.inv_route`).
- **h2c leftover bytes.** At migration, bytes still in `read_buf` after the
  upgrade request are not handed to the HTTP/2 driver. RFC 7540 §3.2 has the
  client send its preface only after the 101, so a conforming client cannot
  have sent them.
- **Liveness.** Under fair event delivery every whole request is eventually
  dispatched and its response fully written, or the connection closes with
  `should_close` for a listed reason (`eventually_served`, `done_reason`).

## Traceability

| Lean definition | Mojo file:line (@59bda50) | Theorems | Status |
|---|---|---|---|
| `Flare.L4.ConnSM.init`, `queueError`, `finalise`, `applyKA` | http/_reactor/conn_handle.mojo:354-398, 1576-1580, 718-756, 697-715 | `inv_init`, `inv_queueError`, `ka_bound` | proved |
| `Flare.L4.ConnSM.dispatch`, `parse`, `onReadable` | conn_handle.mojo:846-856, 907-916, 579-695, 760-916 | `inv_dispatch`, `inv_parse`, `inv_onReadable`, `responses_fifo` | proved; APP-01 |
| `Flare.L4.ConnSM.onWritable`, `onTimeout`, `step`, `lts` | conn_handle.mojo:1262-1375, 1403-1411 | `writable_resumes`, `timeout_closes`, `segs_frozen`, `inv_inductive` | proved |
| `Flare.L4.ConnSM.Framing.serialize` | http/_reactor/write_path.mojo:151-155, 222-235 | `serialize_spec` | proved |
| `Flare.L4.ConnSM.Framing.headFlag`, `staticBytes` | conn_handle.mojo:747-754, 1576-1594, 1174-1220 | `headFlagFixed_spec`, `staticBytes_spec` | APP-04, APP-05 |
| `Flare.L4.KeepAlive.isKeepaliveFast`, `isCloseFast`, `computeCloseAfter` | http/_reactor/keepalive_scan.mojo:206-236, 239-259, 350-390 | `computeCloseAfter_single`, `computeCloseAfterFixed_eq_spec` | APP-03 |
| `Flare.L4.KeepAlive.wantsClose` and helpers | keepalive_scan.mojo:393-484 | `wantsClose_sound_close`, `wantsCloseFixed_spec` | APP-02 |
| `Flare.L4.ServerConfig.check`, timers, `overCapImpl` | http/_server/config.mojo:132-144, 206-221, 276-329; conn_handle.mojo:448-453, 598-691, 1314-1375 | `default_check`, `timer_instr_nonneg`, `closeTime_le`, `overCapFixed_eq_spec` | proved; APP-06 |
| `Flare.L4.Router.splitPath`, `compile`, `matchSegs`, `serve`, `serveMounts` | http/router.mojo:111-156, 175-214, 339-394, 488-498, 675-929 | `serve_eq_spec`, `serve_valid`, `allow_exact`, `mount_compose` | proved |
| `Flare.L4.ComptimeRouter.matchOne`, `scanCT`, `serveCT` | http/routes.mojo:66-78, 91-174, 199-284 | `serveCT_eq_serve`, `router_equiv_comptime` | proved; APP-10 |
| `Flare.L4.Middleware.setH`, `appendH`, `getH`, `hasH` | http/headers.mojo:139-213 | `getH_setH_self`, `hasH_setH_self` | proved |
| `Flare.L4.Middleware.logger`, `requestId`, `catchPanic` | http/middleware.mojo:61-86, 105-111, 397-404 | `logger_transparent`, `catchPanic_idem`, `requestId_outside_catchPanic` | proved |
| `Flare.L4.Middleware.compress`, `encodeAs` | http/middleware.mojo:345-382 | `compress_content_length`, `compress_partial`, `compressFixed_vary` | APP-26, APP-27 |
| `Flare.L4.Negotiate.parseQ`, `parseEntry`, `parseHeader`, `step`, `negotiate` | http/middleware.mojo:131-260 | `decide_eq_spec_of_noStar`, `decideFixed_eq_spec` | APP-20 |
| `Flare.L4.Cors.originAllowed`, `attachOrigin`, `serve` | http/cors.mojo:89-197 | `originAllowed_sound`, `acao_not_star_with_creds`, `serveFixed_vary` | APP-21, APP-22 |
| `Flare.L4.Cookie.toSetCookie`, `parseMaxAge` | http/cookie.mojo:89-212 | `toSetCookie_noCRLF`, `toSetCookie_none_secure`, `parseMaxAge_sound` | proved |
| `Flare.L4.Form.urldecode`, `urlencode`, `parseForm`, `toUrlencoded` | http/form.mojo:28-129, 199-270 | `urldecode_urlencode`, `parseForm_toUrlencoded` | proved; APP-24 |
| `Flare.L4.Url.parse`, `parseWith`, `parsePort` | http/url.mojo:73-299 | `parsePort_iff`, `parse_port`, `parseFixed_spec` | APP-23, APP-25 |
| `Flare.L4.RateLimit.step` (pre-fix: `stepOld`), `spec` | http/reliability.mojo:361-404 | `step_eq_spec`, `step_inv`, `overflow_iff` | resolved (APP-40) |
| `Flare.L4.CircuitBreaker.stepG`, `step` | http/reliability.mojo:413-485 | `step_counts_inv`, `step_open_rejects` | APP-41, APP-42 |
| `Flare.L4.Retry.budget`, `sleep`, `serve` | http/reliability.mojo:164-271 | `budget_eq_spec`, `sleep_bounds`, `serve_calls_bounded` | proved |
| `Flare.L4.Redirect.resolveLocation`, `sameOrigin`, `decideR`, `sendLoop` | http/redirect_policy.mojo:154-354; http/client.mojo:2196-2281 | `sendLoop_terminates`, `sendLoop_confined`, `decide_method_rfc` | APP-43, APP-44, APP-45 |
| `Flare.L4.ClientPool.release`, `acquire`, `popLoop`, `total` | http/client_pool.mojo:86-102, 203-293 | `inv_inductive`, `caps`, `acquire_same_origin` | proved |
| `Flare.L4.Drain.drain` | http/server.mojo:1694-1755 | `drain_ignores_timeout`, `drain_report_zero` | proved (APP-46; docs gap for the report) |
| `Flare.L4.Drain.delivered`, `stopDelay` | http/server.mojo:1733-1755, http/_unified_reactor_impl.mojo:1000-1046, 1103-1170 | `delivered_le_pollCap`, `APP_46.violates_spec`, `fixed_graceful` | counterexample (APP-46) |
| `Flare.L4.ClientLease.sendPooled`, `Client` | http/client.mojo:2509-2593 | `dispose_first`, `release_once`, `inv_reachable`, `acquire_not_held` | proved |
| `Flare.L4.ConnExt.H2c.route`, `driveH1`, `driveH1Writable` | http/_unified_reactor_impl.mojo:174-258, 812-855; http/_reactor/conn_handle.mojo:1353-1362 | `impl_spins`, `APP_47.violates_spec`, `fixed_spec` | counterexample (APP-47) |
| `Flare.L4.ConnLive.trace`, `Fair`, `Oracle.Ext` | http/_reactor/conn_handle.mojo (via `ConnSM.step`); http/_unified_reactor_impl.mojo:220-235, 832-855 | `eventually_served`, `done_reason`, `trace_done_sc` | proved |
| `Flare.L4.ConnStream.Stream.batch`, `wloop`, `finish`, `onWritable` | http/_reactor/conn_handle.mojo:1621-1642, 1286-1351, 1364-1375, 1262-1375 | `inv_onWritable`, `wire_exact_at_end`, `interest` | proved |
| `Flare.L4.ConnStream.Tls.drain`, `flush`, `readDriver`, `writeDriver`, `route` | conn_handle.mojo:479-520, 1213-1240, 1314-1375; http/_unified_reactor_impl.mojo:174-190, 243-258, 812-831 | `blocked_interest`, `retry_read`, `retry_write`, `inv_route`, `interest_nonempty` | proved |
| `Flare.L4.Negotiate.parseHeaderMojo` | http/middleware.mojo:131-235 | `parseHeaderMojo_eq`, `negotiateMojo_eq` | proved |
| `Flare.L4.Continue.Plain.sendContinue`, `finalise`, `flush`; `Tls.sendContinue`, `flush` | http/_reactor/conn_handle.mojo:544-576, 718-756, 1423-1435, 1286-1312, 1213-1240 | `Plain.violates`, `Tls.violates`, `APP_49.violates_spec`, `fixed_meets_spec` | counterexample (APP-49) |
| `Flare.L4.ConnExt.Ws.upgradeTaken`, `wire` (pre-fix: `upgradeTakenOld`, `wireOld`) | http/_reactor/conn_handle.mojo:838-885, 1476-1574 | `APP_48.violates_spec`, `spec` | resolved (APP-48) |
