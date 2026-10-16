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
the idle-connection pool, including how `HttpClient` leases pooled fds.

A last module, `Flare.L4.Policies`, proves five documented promises about
error logging, entry points, sessions and TLS resumption (section 20).

The models describe the shipped code and are written in core Lean 4.33 (no
Mathlib). Each implementation definition carries a symbol-based anchor to
the Mojo function it mirrors, checked by `formal/scripts/anchors.py`.

The build covers 23 model modules (`Flare.L4_App.*`). The aggregate
`Flare.L4_App` imports all of them and builds cleanly. The modules contain
no `sorry`, `admit`, `axiom` or `native_decide`. `Flare/Audit/L4.lean`
prints the axiom footprint of 120 headline theorems; the footprint is a
subset of `propext`, `Quot.sound` and `Classical.choice`.

Theorem count: 444 in the model modules. Unless a row says otherwise, a
theorem is general: it is quantified over all inputs or over every
reachable state.

## Components

### 1. HTTP/1.1 connection state machine (`Flare.L4.ConnSM`)

**Model.** The model is a labelled transition system over socket events:
`arrive bytes`, `fin`, `readable late`, `writable n`, `timeout` and `ioError`.
It mirrors these methods of `ConnHandle` in
`flare/http/_reactor/conn_handle.mojo`: `on_readable`,
`_check_request_complete`, `_apply_keepalive_policy`, `_finalise_response`,
`_queue_error`, `on_writable` and `on_timeout`.

Several inputs are parameters instead of being modelled here:

- HTTP framing is an abstract oracle `frame : Bytes -> needMore | complete r n | error s`. `Oracle.WF` requires that a complete request occupies `0 < n <= len` bytes and is determined by those bytes. The framing itself belongs to L3.
- Serialisation, the handler outcome, the per-request close verdict and the WebSocket version check are also parameters.

The machine is the shipped code, including the APP-01 fix.

The invariant `Inv` has nine clauses:

- the input tiles into dispatched requests;
- every dispatched request is the oracle's reading of exactly its own bytes;
- the answers are those requests in order;
- the wire is a prefix of the queued responses;
- the reading phase is quiescent;
- two keep-alive bounds.

The submodule `Framing` models the body and `Content-Length` decisions of
`serialize_response_into` (`flare/http/_reactor/write_path.mojo`), the HEAD
flag passed on the handler and error paths, and the static fast path
(`on_readable_static`).

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ConnSM.inv_inductive`, `inv_reachable` | `Inv` holds in every reachable state | proved |
| `Flare.L4.ConnSM.responses_fifo` | the requests answered by queued responses are exactly the dispatched requests, in order; each is the oracle's reading of its own bytes; those bytes tile a prefix of the input | proved |
| `Flare.L4.ConnSM.wire_is_responses` | bytes sent are a prefix of the queued responses' bytes; while reading they are all of them | proved |
| `Flare.L4.ConnSM.writable_resumes` | a writable event sends exactly the next `min n remaining` bytes from `wpos`, and leaves WRITING iff the response is complete | proved |
| `Flare.L4.ConnSM.timeout_closes` | `on_timeout` always yields CLOSING with `should_close` and `done` | proved |
| `Flare.L4.ConnSM.segs_frozen`, `run_segs_frozen` | once `should_close` is set, no later step or run dispatches another request | proved |
| `Flare.L4.ConnSM.ka_bound` | `keepalive_count <= max_keepalive_requests` in every reachable state, when `max_keepalive_requests >= 1` (which `ServerConfig.check` enforces) | proved |
| `Flare.L4.ConnSM.closeHonoured_step`, `no_request_after_close_header` | once a `Connection: close` response is queued, no further request is ever dispatched (APP-01) | proved |
| `Flare.L4.ConnSM.Framing.serialize_spec` | no body for HEAD, 1xx, 204 or 304; no `Content-Length` on 1xx or 204; otherwise the body is sent with its length | proved |
| `Flare.L4.ConnSM.Framing.headFlag_spec`, `staticBytes_spec` | on the handler path, the error path (APP-05) and the static fast path (APP-04), every response to HEAD has no body | proved |

The original plan asked for six properties:

- One response per request in FIFO order is covered by `responses_fifo` and `wire_is_responses`.
- Timeout reaching CLOSING is covered by `timeout_closes`.
- No read after `should_close` is covered by `run_segs_frozen`.
- The keep-alive bound is covered by `ka_bound`.
- Bodyless HEAD, 1xx, 204 and 304 responses are covered by `serialize_spec`; for HEAD on the static and error paths (APP-04, APP-05) by `staticBytes_spec` and `headFlag_spec`.
- "A close response implies close" (APP-01) is covered by `no_request_after_close_header`.

`closeHonoured_parse` needed an extra hypothesis, `should_close -> peer_eof`, which `closeHonoured_step` carries as part of its induction.

**Limitations.**

- Liveness under fair event delivery is proved separately in section 17 (`Flare.L4.ConnLive`). Streaming bodies (`body_src`) and TLS cross-interest are modelled in section 18 (`Flare.L4.ConnStream`). The h2c hand-off and the WebSocket branch are modelled in section 16 (`Flare.L4.ConnExt`).
- The time budget appears only as the boolean `late`. The arithmetic is in `ServerConfig.closeTime_le`.
- Documented deviations:
  - The model enters CLOSING after a flush with `should_close`. Mojo leaves `STATE_WRITING`, and the handle is freed at once.
  - The model drops the request bytes after a handler error. Mojo leaves them unread.
  - The model checks the size cap once per drain, not per 8 KiB chunk. Both answer 413 and close.

### 2. Connection header and keep-alive verdicts (`Flare.L4.KeepAlive`)

**Model.** Byte-level transliterations of the `Connection`-header functions
in `flare/http/_reactor/keepalive_scan.mojo`: the fast checks
`_connection_is_keepalive` and `_connection_is_close`, the option-list
reader `_conn_token_mask`, `_compute_close_after` and `_wants_close`.

Every byte constant is spelled out as a list, so no `String` reaches the
kernel. The spec is RFC 9110 §7.6.1 / RFC 9112 §9.6. The `Connection` value
is a comma list of tokens, trimmed of OWS and compared case-insensitively.
`close` means close. HTTP/1.0 closes unless a token is `keep-alive`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.KeepAlive.computeCloseAfter_eq_spec` | the token-splitting `_compute_close_after` (APP-03) equals the spec for every header value and version | proved |
| `Flare.L4.KeepAlive.wantsClose_spec` | the line-start, scan-all `_wants_close` (APP-02) returns true whenever some header line is `Connection` with a close verdict | proved |
| `Flare.L4.KeepAlive.wantsClose_sound_close` | on an HTTP/1.1 request line the scan reports close only for a `Connection` line at a line start with a close verdict | proved |

**Limitations.** `_wants_close` is modelled on the raw request bytes. The
claim that the fast paths reach it was checked against the Mojo call sites,
not modelled.

### 3. Server configuration and deadlines (`Flare.L4.ServerConfig`)

**Model.** `ServerConfig.check` (`flare/http/_server/config.mojo`)
becomes a decidable predicate. The model also covers the timer instructions
that `conn_handle.mojo` issues (`_check_request_complete`, `on_writable`)
and the read-buffer size cap (`_drain_recv`, `_drain_recv_tls`,
`_append_pre_recv_bytes`).

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ServerConfig.default_check` | the default config passes `check` | proved |
| `Flare.L4.ServerConfig.timer_instr_nonneg` | under `check`, every timer instruction is `>= 0`, so each phase replaces the previous timer | proved |
| `Flare.L4.ServerConfig.body_timer_le_request` | under `check`, the body timer is at most `request_timeout_ms` when both are enabled | proved |
| `Flare.L4.ServerConfig.closeTime_le` | given a monotone clock (`Flare.Assumptions.MonotoneClock`), one request's read phase ends by `t0 + R + T` | proved |
| `Flare.L4.ServerConfig.head_timer_unordered` | `check` accepts configs whose idle (head) timer exceeds `request_timeout_ms` | proved (observation) |
| `Flare.L4.ServerConfig.overCapImpl_eq_spec` | the subtraction form of the size cap (APP-06) equals the exact-arithmetic spec whenever the length and header cap are non-negative, for every `Int64` body cap | proved |

### 4. Runtime router (`Flare.L4.Router`) and comptime router (`Flare.L4.ComptimeRouter`)

**Model.** The runtime router models these parts of `flare/http/router.mojo`:
`_split_path`, `_compile_segments`, `_match`, the precedence of
`Router.serve`, and `_MountedRouter.serve`.

`Router.serve` tries direct routes in registration order, then mounts, then
405, then the fallback, then 404. Paths are `List Char`; every byte the
router inspects is ASCII. The comptime model covers `ComptimeRoute`,
`_match_one` and `ComptimeRouter.serve` in `flare/http/routes.mojo`.

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
| `Flare.L4.ComptimeRouter.serveCT_eq_serve` | on any table of valid patterns, ComptimeRouter answers like the runtime router with the same routes | proved |
| `Flare.L4.ComptimeRouter.matchOne_eq_spec`, `matchOne_nonfinal_wild` | `_match_one` (APP-10) meets the matching spec on every pattern, and a non-final `*` matches nothing | proved |
| `Flare.L4.ComptimeRouter.router_equiv_comptime` | on valid patterns, registering the table succeeds and both routers agree on every request | proved |

The Router module has 61 theorems, of which the table lists the headline
ones. The rest are lemmas about splitting, compilation and stripping.

### 5. Generic middleware (`Flare.L4.Middleware`)

**Model.** A handler is `Req -> Except String Resp`, where a Mojo `raise` is
`.error`. Header maps mirror `HeaderMap` (`flare/http/headers.mojo`):
an ordered list with case-insensitive names. `set` replaces the first match or
appends, `append` always appends, and `get` returns the first match.

The model covers the `serve` methods of `Logger`, `RequestId`, `Compress`
and `CatchPanic` in `flare/http/middleware.mojo`.

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
| `Flare.L4.Middleware.compress_content_length`, `compress_vary_when_encoded` | when Compress changes the body, `Content-Length` equals the encoded length; whenever it changes a response, `Vary: Accept-Encoding` is present | proved |
| `Flare.L4.Middleware.compress_partial` | Compress passes every 206 / `Content-Range` response through unchanged (APP-26, spec `PartialSpec`) | proved |
| `Flare.L4.Middleware.compress_vary`, `compress_agrees` | Compress meets the APP-27 spec (`VarySpec`); it agrees with `compressNoVary` (the same code without the identity-branch `Vary`) whenever that one changes a response, so the APP-27 fix only adds `Vary` | proved |

**Limitations.** The model does not check the header-injection test of
`HeaderMap.set`. A value read from a parsed request cannot contain CR or LF.

### 6. Content-coding negotiation (`Flare.L4.Negotiate`)

**Model.** The model has two layers over `_parse_q` and `negotiate_encoding`
in `flare/http/middleware.mojo`. The byte layer covers `_parse_q`,
splitting, stripping, lowercasing and the `q=` search. The decision layer,
`decide'`, is the loop that collects the per-coding maxima and the `*`
weight (`stepFixed`), followed by the final choice. The spec follows RFC
9110 §12.5.3:

- each coding's effective weight is its explicit maximum, else the `*` weight;
- the pick is the highest non-zero weight;
- ties go br, then gzip, then identity;
- when every weight is 0, the result is passthrough.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Negotiate.parseQ_le`, `parseQ_zero_dot`, `parseQ_failOpen` | weights lie in 0..1000; `0.DDD` is read exactly; a weight not starting with `0` reads as 1000 | proved |
| `Flare.L4.Negotiate.classify_upper` | coding names are case-insensitive | proved |
| `Flare.L4.Negotiate.specPick_perm`, `decide'_perm` | the spec and the decision (with or without `*`) do not depend on entry order | proved |
| `Flare.L4.Negotiate.decide'_eq_spec`, `negotiate_eq_spec`, `decide'_refused_identity` | the decision (APP-20) equals the spec on every entry list and header, so br is picked only when brotli is linkable; an explicitly refused identity is never served unless nothing is acceptable | proved |
| `Flare.L4.Negotiate.parseHeaderMojo_eq` | a byte-level model of Mojo's own comma splitter (`parseHeaderMojo`, which emits no trailing empty segment) parses every header to the same entry list as the model's splitter, so the negotiation results are equal on every input | proved |

**Limitations.** None beyond the L3 framing boundary. Mojo's splitter does
not emit a trailing empty segment and the model's does; `parseHeaderMojo_eq`
shows the difference never changes the entry list.

### 7. CORS (`Flare.L4.Cors`)

**Model.** The model covers five functions in `flare/http/cors.mojo`:
`_origin_allowed`, `_join`, `Cors._attach_origin`, `_ensure_vary_origin`
and `Cors.serve`.

Header names are a normalised inductive type. The spec is WHATWG Fetch
§3.2. Allowed origins form a set, and `*` never authorises a credentialed
request. A credentialed response's ACAO is the request origin. When ACAO
depends on `Origin`, every response carries `Vary: Origin`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Cors.originAllowed_sound` | flare never admits an origin the spec rejects (fail-closed) | proved |
| `Flare.L4.Cors.originAllowed_iff`, `originAllowed_eq_spec_noCreds`, `originAllowed_perm` | the check (APP-21) equals the spec for every configuration, credentials or not, and does not depend on list order | proved |
| `Flare.L4.Cors.acao_not_star_with_creds`, `acao_origin_or_star` | with credentials, ACAO is never `*` and equals the request origin | proved |
| `Flare.L4.Cors.attach_has_vary` | every response the middleware stamps carries `Vary: Origin` | proved |
| `Flare.L4.Cors.preflight_ignores_inner` | an allowed preflight is a 204 that does not call the inner handler | proved |
| `Flare.L4.Cors.serve_vary` | `serve` (APP-22) puts `Vary: Origin` on every response | proved |

### 8. Cookies (`Flare.L4.Cookie`)

**Model.** Byte-level models of four parts of `flare/http/cookie.mojo`:
`Cookie.to_set_cookie_header` and its validation helpers (`_is_token_byte`,
`_all_token`, `_is_cookie_value`, `_is_av_value`), `parse_cookie_header`,
`CookieJar.to_request_header` and `_parse_max_age`. Only
`to_set_cookie_header`, its helpers and `_parse_max_age` carry anchors.

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
`_hex_nibble`, `urldecode` (the byte loop `urldecodeBytes`, then the UTF-8
check added for APP-24), `urlencode`, `FormData.to_urlencoded` and
`parse_form_urlencoded`.

The spec covers WHATWG URL §5.1-5.2. It also requires RFC 3629 well-formed
UTF-8 for anything passed to a Mojo `String`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Form.urldecodeBytes_urlencode` | the byte loop inverts `urlencode` for every byte string | proved |
| `Flare.L4.Form.urlencode_noSep` | encoded bytes contain no `&`, `;` or `=` | proved |
| `Flare.L4.Form.parseFormWith_toUrlencoded` | for any decoder that inverts `urlencode` on the components that occur, the parser round-trips `to_urlencoded` | proved |
| `Flare.L4.Form.parseForm_toUrlencoded` | `parse_form_urlencoded (to_urlencoded fd) = fd` for every list of well-formed UTF-8 pairs | proved |
| `Flare.L4.Form.urldecode_valid`, `urldecode_urlencode` | `urldecode` only returns well-formed UTF-8 (APP-24), and `urldecode (urlencode s) = s` for every well-formed UTF-8 string | proved |
| `Flare.L4.Form.urldecode_sub` | the UTF-8 check only rejects; it never changes a successful decode of the byte loop | proved |

### 10. URL parser (`Flare.L4.Url`)

**Model.** A byte-level model of `Url.parse` (`flare/http/url.mojo`),
`_find` / `_rfind`, `_default_port` and `_parse_port`. One combinator,
`parseWith`, is parameterised by the three splitting steps; `parse`
instantiates it with the first-`#` fragment split, the `/`-or-`?`
authority split (APP-23) and the last-`@` userinfo strip (APP-25). The
spec is RFC 3986 §3.2:

- the authority ends at the first `/`, `?` or `#`;
- the host is a piece of the authority and contains no `@`;
- the port is `*DIGIT`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Url.parsePort_iff`, `parsePort_fits` | `_parse_port` accepts exactly 1-5 digits with value 1..65535, and the accumulator cannot overflow | proved |
| `Flare.L4.Url.parse_port` | every successful parse has `1 <= port <= 65535` | proved |
| `Flare.L4.Url.hostPort_ipv6_port`, `hostPort_regname` | IPv6 brackets are stripped; a plain `host:port` is recovered exactly | proved |
| `Flare.L4.Url.parseWith_fixedSplit_hostInAuthority`, `parseWith_fixedStrip_noAt` | with the first-`#` fragment split and the `/`-or-`?` authority split, the host lies inside the RFC authority for any userinfo strip that returns a piece of its input; with the last-`@` strip, the host contains no `@` whatever the other steps are | proved |
| `Flare.L4.Url.parse_spec` | `parse` meets both host specs for all inputs | proved |

### 11. Reliability: RateLimit, CircuitBreaker, Retry

**RateLimit** (`Flare.L4.RateLimit`, `RateLimit.serve` in
`reliability.mojo`). One locked read-modify-write per request, with
wrapping `Int64` arithmetic. The spec is an exact-arithmetic token bucket.
`step` is the shipped code, with `elapsed` clamped to `maxElapsed`
(APP-40). `stepUnclamped` is the same step without the clamp; it agrees
with `step` whenever `elapsed` is within the clamp, which is how the proof
of `step_eq_spec` uses it.

**CircuitBreaker** (`Flare.L4.CircuitBreaker`, `CircuitBreaker.serve` and
`_record_failure` in `reliability.mojo`). The model is an LTS whose labels
are request arrivals and completions, so any number of requests can be in
flight at once. The entry check and the outcome bookkeeping are separate
atomic steps. This is coarser than the Mojo code, so every trace of the
model is also a trace of the code, given that the OPEN -> HALF_OPEN claim
is a compare-and-swap. `step` is the shipped code: opened-at is stamped with
the completion time (APP-41), and arrivals fast-fail while half-open
(APP-42).

**Retry** (`Flare.L4.Retry`, `_backoff_sleep_ms` and `Retry.serve` in
`reliability.mojo`). Covers `_backoff_sleep_ms` with wrapping
multiplication, and the attempt loop over an arbitrary sequence of
outcomes.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.RateLimit.step_eq_spec`, `step_inv` | for any idle time (sane rate and burst, no overflow hypothesis) `step` computes exactly the spec tokens and decision, and keeps `0 <= tokens <= cap` | proved |
| `Flare.L4.RateLimit.step_last_ok` | the clock carry never runs ahead of `now` or backwards, and leaves under one milli-token period uncredited | proved |
| `Flare.L4.RateLimit.stepUnclamped_eq_spec`, `stepUnclamped_inv`, `stepUnclamped_last_ok` | the same for `stepUnclamped`, under the extra hypothesis that `elapsed * rate` fits in `Int64` | proved |
| `Flare.L4.RateLimit.overflow_iff`, `threshold_rate_1e6`, `threshold_rate_1e5`, `threshold_rate_1e3` | the exact wrap threshold `elapsed > (2^63-1)/rate` of the unclamped product, instantiated for several rates | proved |
| `Flare.L4.CircuitBreaker.counts_inductive`, `step_counts_inv` | failure counts are consistent with the state in every reachable state | proved |
| `Flare.L4.CircuitBreaker.step_open_rejects`, `step_success_closes`, `step_failure_reopens` | the sequential transition rules | proved |
| `Flare.L4.CircuitBreaker.cooldown_respected` | every OPEN -> HALF_OPEN transition is an arrival at least `cooldown` after the breaker (re)opened (APP-41) | proved |
| `Flare.L4.CircuitBreaker.single_probe` | while half-open, at most one request has been admitted since the breaker entered half-open (APP-42) | proved |
| `Flare.L4.Retry.budget_eq_spec`, `budget_le_max`, `budget_mono` | for a sane policy the backoff is `min(initial * m^(N-2), max)`, non-decreasing and capped | proved |
| `Flare.L4.Retry.sleep_bounds` | the jittered sleep lies in `[0, budget]`, assuming `random_ui64` stays in range (hypothesis `DrawOk`) | proved |
| `Flare.L4.Retry.serve_calls_bounded`, `serve_result_is_last`, `serve_retry_only_on_failure`, `serve_failure_exhausts` | between 1 and `max_attempts` calls; returns the last outcome; retries only after failure | proved |
| `Flare.L4.Retry.uncapped_wraps` | with `max_backoff_ms <= 0` (no cap), the budget wraps to 0 at attempt 59 for `100 ms x 2` | proved (observation) |

### 12. Redirects (`Flare.L4.Redirect`)

**Model.** The model has four parts:

- `Url.parse`;
- `_resolve_location` with `_remove_dot_segments` (`redirect_policy.mojo`;
  APP-43, APP-45);
- `_same_origin`, which compares lowercased hosts (APP-44);
- `RedirectPolicy.decide`.

It also covers the redirect loop of `HttpClient._send_once`
(`client.mojo`). That loop runs over an arbitrary server and tracks which
credentials each hop carries.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Redirect.decide_follow_lt_max`, `sendLoop_terminates` | at most `max_redirects` redirects are followed | proved |
| `Flare.L4.Redirect.rdsAux_no_dots` | the stack walk of `_remove_dot_segments` (RFC 3986 §5.2.4) never leaves a `.` or `..` segment in its output, from any stack that holds none | proved |
| `Flare.L4.Redirect.sendLoop_confined` | with `forward_auth_cross_origin = False`, every hop that carries `Authorization`, a caller `Cookie` or `Proxy-Authorization` targets the original origin, for every server | proved |
| `Flare.L4.Redirect.sendLoop_auth_monotone`, `sendLoop_cookie_proxy_monotone` | once dropped, a credential is never re-added, even if a later hop returns to the original origin | proved |
| `Flare.L4.Redirect.decide_method_rfc` | 307/308 keep the method and body; 303 turns all but HEAD into GET | proved |
| `Flare.L4.Redirect.decide_301_delete_is_get` | a DELETE answered by 301 becomes GET (documented deviation) | proved (observation) |

### 13. Client connection pool (`Flare.L4.ClientPool`)

**Model.** Per-origin LIFO deques of idle fds, as in `ClientPool.release`
and `ClientPool.acquire` (`flare/http/client_pool.mojo`):

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

**Model.** `HttpServer.drain(timeout_ms)` (`flare/http/server.mojo`)
closes the listener, waits out `timeout_ms` (negative clamps to 0), then
sets `_stopping` (APP-46). The reactor sees the flag at most
`pollCap` = 100 ms later (`_poll_timeout_ms`) and closes every live
connection. A response still being written then is cut: the bytes
delivered are `min pending (rate * (stopDelay + lag))`, where `stopDelay`
is the time from the `drain` call to the flag and `lag ≤ pollCap`
(`delivered`, which mirrors the loop exit of `_run_unified_loop_for_fd` and
the close-all in `_drain_remaining_conns_unified`). The `ShutdownReport`
counts are not modelled.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Drain.graceful` | `stopDelay` meets `GracefulSpec`: a response the peer can absorb within `timeout_ms` is delivered in full, whatever the poll lag | proved |
| `Flare.L4.Drain.stopDelay_nonpos` | `drain(t)` with `t <= 0` sets the flag at once, so `drain(0)` is the hard stop of `close()` | proved |

The multi-worker `Scheduler.drain` belongs to L5.

### 15. `HttpClient` pool leases (`Flare.L4.ClientLease`)

**Model.** `HttpClient._send_h1_pooled` (`flare/http/client.mojo`) is the
only caller of `ClientPool.acquire` and `release`. `sendPooled` covers every
path through it, with an oracle choosing which call raises
(`_arm_read_timeout`, `write_all`, the framed read, `release`, `_may_replay`,
the fresh dial). Across requests, `client` composes the pool with the set of
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
the bytes of the 101 still queued and whether write interest is armed.
Only `_drive_h1` (`flare/http/_unified_reactor_impl.mojo`) acts on the
`h2c_upgrade` cue that `on_writable` reports once the 101 has flushed, by
migrating the connection; `_drive_h1_writable` applies the step without
migrating. `route` mirrors the routing in `_unified_handle_conn_event`: a
writable edge on a `KIND_H1` connection goes to `_drive_h1` while an
upgrade is pending (APP-47), otherwise to `_drive_h1_writable`. After the
upgrade request the client waits for the server preface (RFC 7540 §3.2),
so the only events are writable edges, which keep coming while write
interest is armed. `Ws` is the WebSocket branch of `on_readable`, guarded
by `not self.tls` (APP-48), and where `_handle_ws_upgrade` writes (the
detached raw fd).

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ConnExt.H2c.run_spec` | with the 101 queued behind a full send buffer, the first writable edge migrates the connection, and it stays HTTP/2 after any number of further edges | proved |
| `Flare.L4.ConnExt.Ws.spec` | a TLS connection never writes in cleartext, whether or not a WebSocket handler is configured and the request is a handshake | proved |

### 17. Liveness of the connection machine (`Flare.L4.ConnLive`)

**Model.** `ConnLive` runs `ConnSM.step` over an infinite event sequence
`σ` (`trace P s0 σ n` is the state after `n` events) from any state
satisfying `ConnSM.Inv`. It adds two hypotheses.

- `Fair` is about the reactor and the kernel. While the handle is reading
  and the kernel holds data, a FIN is pending, or `read_buf` already holds a
  whole request, a readable event is eventually delivered. The last case is
  the reactor's re-drive of pipelined requests via `has_buffered_request()`
  (in `_drive_h1` and `_unified_handle_conn_event`). While the handle is
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
loop. The pipelined re-drive was checked by reading the reactor code.

### 18. Streaming bodies and TLS cross-interest (`Flare.L4.ConnStream`)

**Streaming model (`Stream`).** A handler that returns a streaming response
leaves the chunked head in `write_buf` and the source in `body_src`
(`_finalise_response` in `conn_handle.mojo`). The source is a list of
poll results (data, end of stream, or a raise), one per `next()` call; an
empty data chunk is an idle poll. `batch` mirrors `_stream_refill`: at
most `STREAM_BATCH_CHUNKS` chunks or `STREAM_BATCH_BYTES` bytes, an empty
chunk ends the batch, end of stream appends the terminator and drops the
source, a raise closes the connection. `wloop` mirrors the flush and
refill passes of `on_writable`, at most `STREAM_EDGE_PASSES` per writable
edge, and `finish` the tail of `on_writable`.
Chunk framing and the terminator are parameters (L3). The kernel takes at
most `k` bytes per writable edge.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.ConnStream.Stream.inv_onWritable` | the invariant holds across every writable edge: wire plus unsent `write_buf` equals the head followed by the rendering of the polls consumed so far, in source order; consumed and remaining polls tile the original source | proved |
| `Flare.L4.ConnStream.Stream.wire_exact_at_end` | back in STATE_READING, the wire is exactly the head, the framed non-empty chunks in source order, then the terminator | proved |
| `Flare.L4.ConnStream.Stream.wire_prefix` | at every point the wire is a prefix of that byte string | proved |
| `Flare.L4.ConnStream.Stream.interest` | still writing and not done means write interest only; back to reading means read interest; done means `should_close`; never write interest outside STATE_WRITING | proved |

**TLS model (`Tls`).** `SSL_read` may stop on `SSL_IO_WANT_WRITE`
(`_drain_recv_tls`) and `SSL_write` on `SSL_IO_WANT_READ`
(`_flush_write_buf_tls`); both set `tls_cross_interest` and arm read and
write. The reactor (`_unified_handle_conn_event`) clears the flag and sends
readable edges, and writable edges while the flag is set, to the read
driver; in STATE_WRITING the read driver's `on_readable` asks for
writability and the inline cycle of `_drive_h1` runs `on_writable`. The TLS
layer is an oracle:
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

**Model.** `_maybe_send_continue` (`conn_handle.mojo`) writes
`HTTP/1.1 100 Continue\r\n\r\n` once, from STATE_READING, with one
non-blocking write. Whatever of it the write does not take is kept in
`continue_pending` and sent before the final response (APP-49). The spec
(RFC 9112 §2.1 and §4, RFC 9110 §15.2): after the earlier responses the
wire is the final response `R`, or the whole interim `I` and then `R`, and
the connection is not torn down.

`Plain` takes the kernel's count `k` for the one `send` as an oracle; the
unsent tail of a short send goes in front of the response in
`_transition_to_writing`. `Tls` models `SSL_write` under flare's SSL modes
(none are set in `flare/tls/ffi/openssl_wrapper.cpp`). It returns the full
length or a WANT sentinel, never a short count. After a WANT the record
stays pending, and a later `SSL_write` from a different buffer fails with
`SSL_R_BAD_WRITE_RETRY`. flare sends the interim from the connection-owned
buffer and retries it from there at the start of `_flush_write_buf_tls`.

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Continue.Plain.run_spec` | keeping the unsent tail and putting it in front of the response gives `R` or `I ++ R` for every `k` | proved |
| `Flare.L4.Continue.Tls.run_spec` | retrying the interim from the connection's own buffer, before the response, meets the spec whether or not the interim record went out whole | proved |

### 20. Documented policies (`Flare.L4.Policies`)

**Model.** Five small models, one per documented promise (DOC-04 to
DOC-08, see the documentation chapter). Each abstracts one code path to the
values the promise talks about and proves the promise for the shipped
code.

- `ErrorLog`: the handler-error path (`log_handler_error` in
  `flare/errors.mojo`) and the extractor-error path (`Extracted.serve` and
  `_bad_request_from_error` in `flare/http/extract.mojo`).
- `EntryPoints`: the single-listener entry points of `HttpServer`: their
  inline TLS check and `_reject_extra_listeners` (`flare/http/server.mojo`).
- `Session`: `CookieSessionStore.encode_at` / `load_at` and
  `BackedSessionStore` with `DEFAULT_SESSION_TTL_S` (`flare/http/session.mojo`).
- `TlsReload`: `TlsAcceptor.reload` (`flare/tls/acceptor.mojo`), as a fresh
  context with a new ticket key and an empty session cache.
- `Tickets`: `TlsServerConfig.enable_session_tickets` and
  `TlsAcceptor.__init__` (`flare/tls/acceptor.mojo`).

| Lean name | Statement | Status |
|---|---|---|
| `Flare.L4.Policies.ErrorLog.policy` | a handler error answers 500 `Internal Server Error` and an extractor error 400 `Bad Request`; both log a line carrying the full message and the request id | proved |
| `Flare.L4.Policies.EntryPoints.entry_spec` | an entry point raises when a TLS context or extra listeners are bound, and never runs a loop that silently ignores a bound listener | proved |
| `Flare.L4.Policies.Session.expires` | a session issued at time `i` is refused from `i + DEFAULT_SESSION_TTL_S` on, for the signed-cookie store and for the backed store with its default TTL | proved |
| `Flare.L4.Policies.TlsReload.rotates`, `reload_new_ticket` | after `reload`, no ticket or cached session issued before it resumes; tickets issued after it do | proved |
| `Flare.L4.Policies.Tickets.opt_in` | session tickets are off by default, and off disables both issuing and resuming | proved |

## Findings

Every repro below was run from the repository root with
`pixi run mojo -I . formal/repro/<file>.mojo`; the repro files and the
`Flare.Bugs.APP_*` counterexamples are kept at the git tag
`formal-audit-0.12`. The quoted `BUG REPRODUCED` line is the output
observed in that run, with exit status 1.

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
run restores.

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

**Lean.** The counterexamples `Flare.Bugs.APP_01.ws426_close_header_but_kept_open`
and `violates_spec` (at tag `formal-audit-0.12`) give a reachable state of
the pre-fix machine with a close-header response and `should_close = false`.
The shipped machine satisfies the spec:
`Flare.L4.ConnSM.no_request_after_close_header`.

**Fix.** Set `self.should_close = True` before the `return`.

**Repro.** `formal/repro/APP-01_ws426_keeps_connection_open.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: 426 sent 'Connection: close' but on_writable returned done=False, want_read= True state_reading= True`
- Flip: `OK: the 426 response closes the connection (done=True)`

Status: resolved. The 426 branch of on_readable sets `should_close = True` before `_finalise_response`, so the flush ends the connection and a pipelined request behind the 426 is never served. Test: `tests/http/test_server_reactor_state.mojo::test_ws_426_closes_connection` (deterministic: Reactor readiness wait, no sleeps). The model `Flare.L4.ConnSM.lts` is the shipped machine.

### APP-02: `_wants_close` matches `connection:` mid-line and stops at the first hit

**Severity: Low.** The server keeps a connection alive against the client's
`close`.

**RFC clause.** RFC 9112 §9.6 and RFC 9110 §7.6.1.

**What goes wrong.** The scan in `keepalive_scan.mojo:432-480` matches the
bytes `connection:` at any offset, so it first hits inside `X-Connection:`,
and it `break`s after the first match. The real `Connection: close` line is
never read. The static and short-request fast paths then reply
`Connection: keep-alive`.

**Lean.** The counterexamples `Flare.Bugs.APP_02.wantsClose_misses_close`
and `violates_spec` (at tag `formal-audit-0.12`) use the 63-byte request
with `X-Connection` at offset 27 against the pre-fix scan. The shipped
`wantsClose` meets the spec for every request:
`Flare.L4.KeepAlive.wantsClose_spec`.

**Fix.** Match only at line starts and OR the verdicts of all matching lines.

**Repro.** `formal/repro/APP-02_wants_close_substring_match.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: _wants_close returned False for a request carrying 'Connection: close' after an 'X-Connection' header`
- Flip: `OK: _wants_close honours 'Connection: close' after X-Connection`

Status: resolved. `_wants_close` tests `connection:` only at a line start (so `X-Connection:` no longer matches) and ORs the verdicts of every `Connection` line instead of breaking at the first match. Tests: `tests/http/test_connection_keepalive_fastpath.mojo::test_wants_close_after_x_connection_header`, `::test_wants_close_ignores_connection_inside_other_header_names`, `::test_wants_close_ors_every_connection_line`. The model `wantsClose` mirrors the fix.

### APP-03: `close` inside a `Connection` token list is ignored

**Severity: Low**, for the same reason as APP-02.

**RFC clause.** RFC 9110 §7.6.1 (`Connection = #connection-option`) and RFC
9112 §9.6.

**What goes wrong.** `_compute_close_after` (`keepalive_scan.mojo:357-397`)
compares the whole value with `close` and `keep-alive`. The values
`keep-alive, close` and `TE, close` match neither, and HTTP/1.1 defaults to
keep-alive.

**Lean.** The counterexamples `Flare.Bugs.APP_03.computeCloseAfterOld_misses_close`
and `violates_spec` (at tag `formal-audit-0.12`) are about the pre-fix
function. The shipped function meets the spec for every value and version:
`Flare.L4.KeepAlive.computeCloseAfter_eq_spec`.

**Fix.** Split on `,`, trim OWS, lowercase, and test each token.

**Repro.** `formal/repro/APP-03_connection_close_token_list.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: _compute_close_after kept the connection alive for Connection: 'keep-alive, close' -> False and 'TE, close' -> False`
- Flip: `OK: a close token inside a Connection list closes the connection`

Status: resolved. `_compute_close_after` (slow path) and `_wants_close` now read the `Connection` value as a comma-separated option list (`_conn_token_mask`: split on `,`, trim OWS, case-fold), so `keep-alive, close` and `TE, close` close the connection; HTTP/1.0 stays open only with a `keep-alive` option. Tests: `tests/http/test_connection_keepalive_fastpath.mojo::test_compute_close_after_close_inside_option_list`, `::test_compute_close_after_option_list_without_close`, `::test_wants_close_option_list`. The model `computeCloseAfter`/`verdict` mirror the fix.

### APP-04: the static fast path sends the body in reply to HEAD

**Severity: Medium.** The connection stays alive, so a keep-alive client
reads the body as the start of the next response. This is response
desynchronisation.

**RFC clause.** RFC 9110 §9.3.2: the server MUST NOT send content in a
response to HEAD. RFC 9112 §6.3.

**What goes wrong.** `on_readable_static` (`conn_handle.mojo:1174-1211`)
never inspects the method. It queues the whole pre-encoded GET response
with `Connection: keep-alive`.

**Lean.** The counterexample `Flare.Bugs.APP_04.static_head_emits_body`
(at tag `formal-audit-0.12`) is about the pre-fix static path. The shipped
path meets the spec: `Flare.L4.ConnSM.Framing.staticBytes_spec`.

**Fix.** For a request line starting with `HEAD `, queue only the bytes up to
the first CRLFCRLF.

**Repro.** `formal/repro/APP-04_static_head_sends_body.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: HEAD on the static path queued 13 body bytes after the headers; keep-alive= True`
- Flip: `OK: HEAD on the static path queues the head only`

Status: resolved. The static fast path now queues only the head (up to the first CRLFCRLF) of the pre-encoded bytes for a request line starting with `HEAD `. Test: `tests/http/test_server_reactor_state.mojo::test_static_head_queues_head_only`. The model `staticBytes` mirrors the fix.

### APP-05: an error response to HEAD carries a body

**Severity: Low.** The connection closes afterwards, so the bytes cannot
desynchronise a later response.

**RFC clause.** RFC 9110 §9.3.2.

**What goes wrong.** When the handler raises on a HEAD request, `_queue_error`
leads to `_serialize_response` (`conn_handle.mojo:1576-1594`). That calls
`serialize_response_into` without `head_request`, so the body is serialised.

**Lean.** The counterexample `Flare.Bugs.APP_05.handler_error_head_emits_body`
(status 500, 25-byte body; at tag `formal-audit-0.12`) is about the pre-fix
flag. The shipped `headFlag` meets the spec on both paths:
`Flare.L4.ConnSM.Framing.headFlag_spec`.

**Fix.** Pass `self.head_request`.

**Repro.** `formal/repro/APP-05_error_reply_to_head_has_body.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: error response to HEAD carries 25 body bytes: '500 Internal Server Error'`
- Flip: `OK: the error response to HEAD has no body`

Status: resolved. `_serialize_response` (used by `_queue_error`) now passes `self.head_request`, and errors raised before the request is parsed (408, 413, 431, 400 ...) take the flag from the buffered `HEAD ` prefix via `_note_head_from_buf`, so an error response to HEAD has no body (the stale flag of an earlier HEAD no longer leaks into a later request). Tests: `tests/http/test_server_reactor_state.mojo::test_handler_error_for_head_has_no_body`, `::test_parse_errors_for_head_have_no_body`, `::test_error_after_head_on_keepalive_conn_keeps_body`. The model `headFlag` is the shipped flag.

### APP-06: the size cap `max_header_size + max_body_size` wraps

**Severity: Low.** It needs an "unlimited" body cap such as `Int.MAX`, which
`ServerConfig.check` accepts. With that config every request is refused.

**Spec.** A request within both limits is not rejected as too large.

**What goes wrong.** `conn_handle.mojo:448-453` (also 492-497 and 536-541)
computes `8192 + Int.MAX`, which wraps negative, so every non-empty buffer
gets 413.

**Lean.** The counterexamples `Flare.Bugs.APP_06.check_accepts`,
`overflow_cap_rejects_one_byte` and `violates_spec` (at tag
`formal-audit-0.12`) are about the pre-fix sum. The shipped `overCapImpl`
meets the spec: `Flare.L4.ServerConfig.overCapImpl_eq_spec`.

**Fix.** Use `len - max_header_size > max_body_size` at all three sites.

**Repro.** `formal/repro/APP-06_size_cap_int_overflow.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: a 27 byte GET was answered 413 with max_body_size=Int.MAX`
- Flip: `OK: the GET is served with max_body_size=Int.MAX`

Status: resolved. The three read-buffer cap checks in `conn_handle.mojo` (and the legacy `_parse_http_request`) now test `len - max_header_size > max_body_size`, so the sum is never formed and `max_body_size = Int.MAX` serves requests. Tests: `tests/http/test_server_reactor_state.mojo::test_unlimited_body_cap_serves_request`, `::test_unlimited_body_cap_bufring_path`, `::test_body_cap_still_rejects_oversized_input`. The model `overCapImpl` is the shipped test.

### APP-10: ComptimeRouter accepts a non-final `*` and ignores the rest of the pattern

**Severity: Low.** It needs an invalid route table, which the runtime router
rejects.

**Spec.** The pattern grammar: `*` must be last (`router.mojo:148-151`).

**What goes wrong.** `_match_one` (`routes.mojo:264-274`) treats a middle `*`
as a tail wildcard. `/files/*/meta` then matches `GET /files/a`.

**Lean.** The counterexamples `Flare.Bugs.APP_10.router_rejects`,
`comptime_misroutes` and `matchOne_violates_spec` (at tag
`formal-audit-0.12`) are about the pre-fix matcher. The shipped `matchOne`
meets the spec on every pattern: `Flare.L4.ComptimeRouter.matchOne_eq_spec`
and `matchOne_nonfinal_wild`.

**Fix.** Return false when the wildcard is not the last segment.

**Repro.** `formal/repro/APP-10_comptime_router_nonfinal_wildcard.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: pattern /files/*/meta matched GET /files/a with status 200 body meta:a`
- Flip: `OK: GET /files/a is 404 for pattern /files/*/meta`

Status: resolved. `_match_one` returns `False` for a `*` that is not the last pattern segment (`if j != len(pat_segs) - 1`), so a pattern like `/files/*/meta` matches nothing instead of capturing the tail. Tests: `tests/http/test_routes_comptime.mojo::test_non_final_wildcard_matches_nothing`, `::test_final_wildcard_still_captures_rest`. The model `matchOne`/`scanCT`/`serveCT` are the shipped ones.

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

**Lean.** The counterexample `Flare.Bugs.APP_20.negotiate_violates_spec`
(at tag `formal-audit-0.12`) is about the pre-fix loop. The shipped
decision meets the spec on every header: `Flare.L4.Negotiate.decide'_eq_spec`
and `negotiate_eq_spec`.

**Fix.** Track the `*` weight and the per-coding maxima, then pick after the
loop.

**Repro.** `formal/repro/APP-20_negotiate_wildcard.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: 'gzip;q=0.5, *' -> gzip / '*, gzip;q=0.5' -> identity (brotli on, expected br for both); 'identity;q=0, *' -> identity (expected gzip)`
- Flip: `OK: wildcard weights honoured: br br gzip`

Status: resolved. `negotiate_encoding` records the largest weight per coding (br, gzip, identity) and for `*`, gives every coding without its own entry the `*` weight, then picks the highest non-zero weight (ties br > gzip > identity). Tests: `tests/http/test_middleware.mojo::test_negotiate_wildcard_weight_applies_to_unlisted_codings`, `::test_negotiate_wildcard_is_order_independent`, `::test_negotiate_identity_refused_with_wildcard`, `::test_negotiate_wildcard_alone_selects_best_available_coding` (replaces `test_negotiate_wildcard_falls_back_to_identity`, which pinned the pre-fix bare-`*` -> identity answer). The model `decide'`/`negotiate` are the shipped ones.

### APP-21: the CORS allowlist is order dependent under credentials

**Severity: Low.** The failure is fail-closed.

**Spec clause.** Fetch §3.2.

**What goes wrong.** `cors.mojo:94-95` returns `not allow_credentials` at the
first `*`. With credentials on, `["*", origin]` therefore rejects a listed
origin.

**Lean.** The counterexample `Flare.Bugs.APP_21.violates_spec` (at tag
`formal-audit-0.12`) is about the pre-fix check. The shipped `originAllowed`
meets the spec for every configuration: `Flare.L4.Cors.originAllowed_iff`
and `originAllowed_perm`.

**Fix.** On `*` with credentials, `continue` instead of returning.

**Repro.** `formal/repro/APP-21_cors_credentials_order.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: with credentials, ['*', origin] gives ACAO '' but [origin, '*'] gives 'https://app.example.com'`
- Flip: `OK: listed origin allowed in both orders: https://app.example.com https://app.example.com`

Status: resolved. `_origin_allowed` now `continue`s past a `*` entry when credentials are on (and still returns True for `*` without credentials), so the allowlist is order independent. Tests: `tests/http/test_cors.mojo::test_credentials_allowlist_is_order_independent`, `::test_wildcard_without_credentials_still_first_match`. The model `originAllowed` is the shipped check.

### APP-22: `Vary: Origin` is missing on responses the CORS middleware does not stamp

**Severity: Low.** The risk is cache mixing.

**Spec clause.** Fetch §3.2.5.

**What goes wrong.** `cors.mojo:160-171` returns the inner response unchanged
when `Origin` is absent or rejected, without adding `Vary`.

**Lean.** The counterexamples `Flare.Bugs.APP_22.missing_vary` and
`violates_spec` (at tag `formal-audit-0.12`) are about the pre-fix `serve`.
The shipped `serve` puts `Vary: Origin` on every response:
`Flare.L4.Cors.serve_vary`.

**Fix.** Append `Vary: Origin` on every path.

**Repro.** `formal/repro/APP-22_cors_missing_vary.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: ACAO varies with Origin ('https://a.example' for https://a.example, absent otherwise) but Vary: Origin is missing on the no-Origin response (False) / rejected-origin response (False)`
- Flip: `OK: Vary: Origin present on all responses`

Status: resolved. The pass-through paths of `Cors.serve` (no `Origin`, rejected origin, rejected preflight 403) now go through `_ensure_vary_origin`, which appends `Vary: Origin` unless the response already has it, so every response carries it. Tests: `tests/http/test_cors.mojo::test_vary_origin_on_response_without_origin`, `::test_vary_origin_on_rejected_origin_and_preflight`, `::test_vary_origin_single_on_allowed_and_not_duplicated`. The model `serve` is the shipped one.

### APP-23: `Url.parse` does not end the authority at `?` (host confusion)

**Severity: Medium.** The input is a valid RFC 3986 URI on which an allowlist
check of `Url.parse(u).host` disagrees with browsers and curl.

**RFC clause.** RFC 3986 §3.2.

**What goes wrong.** `url.mojo:101-123` cuts the authority only at `/` and
takes the fragment at the last `#`.

- `http://evil.com?@good.com/` gives host `good.com`.
- `http://good.com?x=/y` gives host `good.com?x=`.

**Lean.** The counterexample `Flare.Bugs.APP_23.host_confusion` (at tag
`formal-audit-0.12`) is about the pre-fix parser. The shipped `parse` meets
the spec: `Flare.L4.Url.parseWith_fixedSplit_hostInAuthority` and
`parse_spec`.

**Fix.** Find the first `#`, and end the authority at the first `/` or `?`.

**Repro.** `formal/repro/APP-23_url_authority_query_host_confusion.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: Url.parse('http://evil.com?@good.com/').host = 'good.com' (query ''), Url.parse('http://good.com?x=/y').host = 'good.com?x='; RFC 3986 hosts are 'evil.com' and 'good.com'`
- Flip: `OK: authority ends at '?': hosts evil.com and good.com query @good.com/`

Status: resolved. Url.parse takes the fragment at the first `#` and ends the authority at the first `/` or `?` (an authority ending at `?` gets path `/`). Tests: `tests/http/test_http.mojo::test_url_authority_ends_at_query`, `::test_url_fragment_starts_at_first_hash`. The model `parse` mirrors the fix.

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

**Lean.** The counterexamples `Flare.Bugs.APP_24.urldecode_violates_spec`
and `parseForm_F0` (at tag `formal-audit-0.12`) are about the pre-fix
decoder. The shipped `urldecode` only returns well-formed UTF-8 and keeps
the round trip on valid input: `Flare.L4.Form.urldecode_valid` and
`urldecode_urlencode`.

**Fix.** Use `String(from_utf8=...)` (which raises) or the lossy decode.

**Repro.** `formal/repro/APP-24_urldecode_invalid_utf8.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: urldecode('%F0') / parse_form_urlencoded('a=%F0') produced a String that is not valid UTF-8 (direct: True , form: True )`
- Flip: `OK: urldecode never yields ill-formed UTF-8 for '%F0'`

Status: resolved. urldecode now builds its result with `String(from_utf8=...)` and raises when the decoded bytes are not valid UTF-8; `parse_form_urlencoded` and the `Form` extractor reject such bodies (400). Tests: `tests/http/test_form.mojo::test_urldecode_rejects_ill_formed_utf8`, `::test_urldecode_accepts_well_formed_utf8`, `::test_parse_ill_formed_utf8_raises`. Decision: raise (the Lean fix) rather than substitute U+FFFD, so callers never silently accept altered data.

### APP-25: userinfo is split at the first `@`

**Severity: Low.** The input is not valid RFC 3986, but the resulting host
differs from the one WHATWG and curl pick.

**RFC clause.** RFC 3986 §3.2.2: no host form contains `@`.

**What goes wrong.** `url.mojo:143-148` (before the fix) split at the first `@`, so
`http://a@evil.com@good.com/` gives host `evil.com@good.com`.

**Lean.** The counterexample `Flare.Bugs.APP_25.host_has_at` (at tag
`formal-audit-0.12`) is about the pre-fix userinfo strip. The shipped strip
meets the spec: `Flare.L4.Url.parseWith_fixedStrip_noAt` and `parse_spec`.

**Fix.** Use `_rfind(authority, "@")`.

**Repro.** `formal/repro/APP-25_url_userinfo_first_at.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: Url.parse('http://a@evil.com@good.com/').host = 'evil.com@good.com' contains '@' (WHATWG/curl host: 'good.com')`
- Flip: `OK: host has no '@': good.com`

Status: resolved. Url.parse strips userinfo through the last `@` (`_rfind(authority, "@")`), so `http://a@evil.com@good.com/` has host `good.com` and no host contains `@`. Tests: `tests/http/test_http.mojo::test_url_userinfo_split_at_last_at`. Decision: split at the last `@` (WHATWG/curl behaviour) rather than raise.

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

**Lean.** The counterexamples `Flare.Bugs.APP_26.partial_reencoded` and
`violates_spec`, and the general `partial_body_replaced` (at tag
`formal-audit-0.12`), are about the pre-fix Compress, against the spec
`PartialSpec` ("a partial response passes through unchanged"). The shipped
`compress` meets it for every configuration:
`Flare.L4.Middleware.compress_partial`.

**Fix.** Return the inner response unchanged when the status is 206 or it
carries `Content-Range`.

**Repro.** `formal/repro/APP-26_compress_encodes_partial_content.mojo` (at tag `formal-audit-0.12`). It
uses a stub inner handler that returns what FileServer returns for
`Range: bytes=0-2047`.

- Observed: `BUG REPRODUCED: 206 with Content-Range 'bytes 0-2047/10000' was re-encoded as gzip; body is 35 bytes, Content-Length 35`
- Flip (the two lines after the `content-encoding` check in `flare/http/middleware.mojo`): `OK: partial response passed through unencoded (status 206, 2048 bytes)`

Status: resolved. Compress.serve returns a 206, or any response carrying `Content-Range`, unchanged (no re-encoding, Content-Range and Content-Length intact). Tests: `tests/http/test_middleware.mojo::test_compress_partial_content_passthrough`, `::test_compress_content_range_header_passthrough`. The model `compress` mirrors the fix.

### APP-27: Compress omits `Vary: Accept-Encoding` on the identity responses it negotiated

**Severity: Low.** This is a SHOULD. A shared cache can store the identity
variant as the only one, and the cost is lost compression.

**RFC clause.** RFC 9110 §12.5.5.

**What goes wrong.** For a body at or above `min_size_bytes` that is not
already encoded, the representation depends on `Accept-Encoding`. Only the
encoding branch appends `Vary`. The identity response for the same URL
(sent when there is no `Accept-Encoding`, when identity is preferred, or
when every coding is refused) has no `Vary`.

**Lean.** The counterexamples `Flare.Bugs.APP_27.identity_without_vary`
and `violates_spec` (at tag `formal-audit-0.12`) are about
`compressNoVary`, the Compress of the APP-26 fix without the identity-branch
`Vary`, against the spec `VarySpec`. The shipped `compress` meets it:
`Flare.L4.Middleware.compress_vary`.

**Fix.** Append `Vary: Accept-Encoding` on every response past the size and
already-encoded checks.

**Repro.** `formal/repro/APP-27_compress_missing_vary_on_identity.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: gzip response has Vary: Accept-Encoding (gzip) but the identity response for the same URL has none`
- Flip (`Vary` appended before the `quality == 0` check, later append removed): `OK: Vary: Accept-Encoding on both variants`

Status: resolved. Compress.serve appends `Vary: Accept-Encoding` to every response past the size, already-encoded and partial checks, including the identity variants (no header, identity preferred, every coding refused); passed-through responses get none. Tests: `tests/http/test_middleware.mojo::test_compress_identity_variant_has_vary`, `::test_compress_vary_on_every_negotiated_outcome`, `::test_compress_no_vary_when_passed_through`. The model `compress` is the shipped code; `compressNoVary` is the same code without the APP-27 `Vary`, kept for `compress_agrees`.

### APP-40: the RateLimit refill product wraps after a long idle period

**Severity: Medium.** The middleware causes its own multi-hour outage. A
negative token count is stored, and `last` does not advance, so the state
keeps getting worse. At `1e6/s` the wrap needs only 2.56 h of idle time.

**Spec.** The token bucket in the docstring.

**What goes wrong.** `reliability.mojo:369-374` computes
`(elapsed * rate) // 1_000_000`, and the product wraps `Int64`.

**Lean.** The counterexamples `Flare.Bugs.APP_40.full_bucket_rejected_after_idle`
and `product_overflows` (at tag `formal-audit-0.12`) are about the
unclamped step. The shipped `step` computes the spec for every idle time:
`Flare.L4.RateLimit.step_eq_spec`; `overflow_iff` gives the exact threshold
of the unclamped product.

**Fix.** Clamp `elapsed` to the time needed to fill the bucket (shipped).

**Repro.** `formal/repro/APP-40_ratelimit_refill_overflow.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: full bucket after 9300 s idle at rate 1e6/s returned 429 ; stored milli-tokens now -9145744073710`
- Flip: `OK: request admitted after 9300 s idle; milli-tokens 999999000`

Status: resolved. `serve` clamps `elapsed` to `max_elapsed = burst * 1e9 // rate + 1` before forming the refill product. Test: `tests/http/test_reliability.mojo::test_ratelimit_full_bucket_admits_after_a_long_idle_period`; the repro now prints `OK:`. The shipped model is `Flare.L4.RateLimit.step`, and `step_eq_spec` is stated about it.

### APP-41: CircuitBreaker measures the cooldown from the start of the failing request

**Severity: Medium.** A failure slower than `cooldown_ms` opens the breaker
already expired. Slow upstreams are the main case breakers exist for.

**Spec.** The docstring at `reliability.mojo:404-411`.

**What goes wrong.** `now` is read on entry (449) and stored as the
opened-at time (435-440, 463, 468).

**Lean.** The counterexample `Flare.Bugs.APP_41.slow_failure_skips_cooldown`
(at tag `formal-audit-0.12`) is about the pre-fix breaker. The shipped
breaker respects the cooldown: `Flare.L4.CircuitBreaker.cooldown_respected`.

**Fix.** Call `_record_failure(Int64(perf_counter_ns()))` at both sites (shipped).

**Repro.** `formal/repro/APP-41_circuitbreaker_cooldown_from_request_start.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: call right after the trip returned 500 and the inner handler ran 2 times (expected 503, 1 call); first status 500`
- Flip: `OK: breaker fast-failed with 503 during cooldown; inner calls 1`

Status: resolved. Both `_record_failure` call sites in `serve` now pass `perf_counter_ns()` read when the failure is recorded, so the cooldown counts from the failure. Test: `tests/http/test_reliability.mojo::test_circuitbreaker_cooldown_counts_from_the_failure_not_the_request`; the repro now prints `OK:`. The shipped model is `Flare.L4.CircuitBreaker.step`, and `cooldown_respected` is stated about it.

### APP-42: CircuitBreaker admits every request while HALF_OPEN

**Severity: Low.** Concurrent requests reach a recovering upstream during the
single-probe window.

**Spec.** The docstring at `reliability.mojo:31-34` and 409-411: "one
probe".

**What goes wrong.** `serve` tests only `state == OPEN` (450-460).

**Lean.** The counterexample `Flare.Bugs.APP_42.halfopen_admits_two` (at
tag `formal-audit-0.12`) is about the pre-fix breaker. The shipped breaker
admits a single probe: `Flare.L4.CircuitBreaker.single_probe`.

**Fix.** Fast-fail on HALF_OPEN, and claim the transition with a
compare-and-swap.

**Repro.** `formal/repro/APP-42_circuitbreaker_halfopen_unbounded_probes.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: while worker 1's probe was in flight (HALF_OPEN), worker 2 got 200 and its upstream ran 1 time(s); expected 503 and 0. trip status 500 probe status 200`
- Flip: `OK: second request fast-failed with 503 while the probe was in flight`

Status: resolved. `serve` fast-fails with 503 while the state is HALF_OPEN, and claims OPEN -> HALF_OPEN with a new `_cell_cas`, so a worker that loses the race also fast-fails and exactly one probe runs. Test: `tests/http/test_reliability.mojo::test_circuitbreaker_half_open_admits_only_the_probe` (a second breaker copy sharing the cell serves a request from inside the probe; it gets 503 and the upstream is not reached; the probe's success closes the breaker). The repro now prints `OK:` (3 of 3 runs). The shipped model is `Flare.L4.CircuitBreaker.step`, and `single_probe` is stated about it. Decision: a probe that never records an outcome would leave the breaker half-open; `serve` is synchronous and records success or failure on every return or raise, so this cannot happen short of the process dying.

### APP-43: a network-path `Location` (`//host/path`) is resolved as a path

**Severity: Low.** The client fetches the wrong resource, and
`same_origin_only` does not reject the hop. Credentials stay on the original
host, so nothing leaks.

**RFC clause.** RFC 9110 §10.2.2, and RFC 3986 §4.2 and §5.2.2.

**What goes wrong.** `redirect_policy.mojo:171-172` returns
`origin + location` for any reference that starts with `/`.

**Lean.** The counterexamples `Flare.Bugs.APP_43.network_path_resolved_as_path`
and `violates_spec`, and the fix theorem `resolveLocation_network_path`, are
at tag `formal-audit-0.12`.

**Fix.** For a reference starting with `//`, return `scheme + ":" + location`.

**Repro.** `formal/repro/APP-43_redirect_network_path_location.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: '//cdn.example.net/img' against https://api.example.com/a resolved to https://api.example.com:443//cdn.example.net/img ; decide next_url https://api.example.com:443//cdn.example.net/img forward_authorization True`
- Flip: `OK: network-path Location resolved to https://cdn.example.net/img`

Status: resolved. `_resolve_location` returns `base.scheme + ":" + location` for a reference starting with `//`. Tests: `tests/http/test_redirect_policy.mojo::test_network_path_location_replaces_the_authority` and `::test_network_path_location_is_cross_origin_for_same_origin_only` (the second covers `same_origin_only` rejecting the hop and a `//` reference naming the same host staying same-origin). The repro now prints `OK:` (3 of 3 runs). The shipped model is `Flare.L4.Redirect.resolveLocation`.

### APP-44: `_same_origin` compares hosts case-sensitively

**Severity: Low.** The failure is fail-safe: the redirect is refused
spuriously and credentials are dropped.

**RFC clause.** RFC 6454 §4 and RFC 3986 §3.2.2.

**What goes wrong.** `redirect_policy.mojo:188-198` compares with
`a.host != b.host`, and `Url.parse` keeps the host's case.

**Lean.** The counterexample `Flare.Bugs.APP_44.host_case_not_same_origin`
and the fix theorem `sameOrigin_case` are at tag `formal-audit-0.12`. The
credential-confinement theorems of section 12 (`sendLoop_confined`) are
stated over the lowercased origin `originOf`.

**Fix.** Compare lowercased hosts.

**Repro.** `formal/repro/APP-44_same_origin_host_case.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: _same_origin(API.example.com, api.example.com) = False ; same_origin_only decide action = 2 (0=FOLLOW, 2=REJECT)`
- Flip: `OK: host comparison is case-insensitive`

Status: resolved. `_same_origin` compares `a.host.lower()` with `b.host.lower()`. Test: `tests/http/test_redirect_policy.mojo::test_same_origin_ignores_host_case` (`same_origin_only` follows `http://API.example.com/old` to `http://api.example.com/new` and keeps Authorization; a different host is still rejected). The repro now prints `OK:` (3 of 3 runs). The shipped model is `Flare.L4.Redirect.sameOrigin`, and `originOf` (the tuple the credential-confinement theorems use) lowercases the host. The client pool still keys on the unnormalised host (not part of this finding).

### APP-45: relative references are not resolved per RFC 3986 §5.2

**Severity: Low.** The client fetches the wrong resource.

**RFC clause.** RFC 3986 §5.2.2 and §5.4.1.

**What goes wrong.** Two cases are wrong:

- `?page=2` against `http://h/list/items` gives `http://h:80/list/?page=2`.
- Dot segments are kept, so `../g` against `/b/c/d` gives `/b/c/../g`.

**Lean.** The counterexamples `Flare.Bugs.APP_45.query_only_reference_wrong`
and `dot_segments_kept`, and the fix theorems `resolveLocation_query_only`
(the query-only case) and `rfc_5_4_1_examples`, are at tag
`formal-audit-0.12`. `Flare.L4.Redirect.rdsAux_no_dots` shows the shipped
dot-segment walk never leaves a `.` or `..` segment.

**Fix.** For `?` references, return `origin + base.path + location`. The
full fix also applies `remove_dot_segments`.

**Repro.** `formal/repro/APP-45_redirect_relative_reference_resolution.mojo` (at tag `formal-audit-0.12`)

- Observed: `BUG REPRODUCED: '?page=2' against http://h/list/items -> http://h:80/list/?page=2`
- Flip: `OK: query-only reference resolved per RFC 3986: http://h:80/list/items?page=2`

Status: resolved. `_resolve_location` now follows RFC 3986 §5.2.2: a `?` reference keeps the whole base path (the base query is replaced), a `#` reference keeps the base path and query, a relative path merges with the directory of the base *path* (a `/` inside the base query used to count as a separator), and the resolved path of a relative or origin-relative reference goes through the new `_remove_dot_segments` (§5.2.4); the query and fragment are not touched. Tests: `tests/http/test_redirect_policy.mojo::test_query_only_reference_keeps_the_base_path`, `::test_dot_segments_are_removed_from_a_relative_reference`, `::test_dot_segments_are_removed_from_an_origin_relative_reference`, `::test_merge_uses_the_base_path_not_its_query` and `::test_rfc3986_section_5_4_1_normal_examples` (29 of the RFC's normal examples). The repro (which checks the query-only case) now prints `OK:` (3 of 3 runs). The shipped model is `Flare.L4.Redirect.resolveLocation` with `removeDotSegments`; `Flare.L4.Redirect.rdsAux_no_dots` shows the dot-segment walk never leaves a `.` or `..` segment. Decision: absolute `http(s)://` Locations are still returned as given (not normalised), as are network-path references; only references flare resolves itself are normalised.

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

**Lean.** The counterexamples `Flare.Bugs.APP_46.cut_example` (1000 bytes
pending, 1 byte/ms, `timeout_ms = 5000`: 100 bytes delivered) and
`violates_spec` are at tag `formal-audit-0.12`. Fix: after closing the
listener, wait out `timeout_ms` before setting `_stopping`; the shipped
delay meets the spec: `Flare.L4.Drain.graceful`.

**Repro.** `formal/repro/APP-46_drain_is_hard_stop.mojo` (at tag `formal-audit-0.12`): `serve()` on a
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

Status: resolved. `HttpServer.drain` closes the listener, waits `timeout_ms` (negative clamps to 0; 1 ms sleeps bounded by `monotonic_now_ms`), then sets `_stopping`; `drain(0)` is still `close()`. Tests: `tests/http/test_server_drain.mojo::test_drain_lets_an_in_flight_response_finish`, `::test_drain_waits_out_the_timeout_before_stopping`; the repro now prints `OK:` (3 of 3 runs). The shipped delay is `Flare.L4.Drain.stopDelay`, and `graceful` is stated about it. Decision: the single-worker path always waits the full `timeout_ms`, since it publishes no live-connection count (idle keep-alive connections would count as live anyway); documented in the docstring and `docs/operations.md`.

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

**What goes wrong.** Every writable edge on a `KIND_H1` connection goes to
`_drive_h1_writable` (see section 16), which applies the step without
migrating; the step has no interest bits, so `_apply_step` leaves write
interest armed and every poll returns another writable edge.

**Lean.** The counterexample `Flare.Bugs.APP_47.violates_spec` (at tag
`formal-audit-0.12`) is about the pre-fix routing. Fix: also route a
writable edge to `_drive_h1` while `_h2c_upgrade_pending` is set; the
shipped routing meets the spec: `Flare.L4.ConnExt.H2c.run_spec`.

**Repro.** `formal/repro/APP-47_h2c_upgrade_lost_on_writable_edge.mojo` (at tag `formal-audit-0.12`)
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

Status: resolved. A writable edge on a `KIND_H1` connection now goes to `_drive_h1` while `_h2c_upgrade_pending` is set (with the handle in `STATE_WRITING`, `on_readable` is a no-op that hands over to `on_writable`), so the flush migrates the connection. Test: `tests/http/test_h2c_upgrade.mojo::test_h2c_upgrade_101_flushed_on_a_writable_edge_migrates` (drives `on_readable` directly so the 101 is queued and unwritten, then delivers one writable edge; no dependence on kernel buffer sizes). The repro now prints `OK:` (3 of 3 runs). The shipped routing is `Flare.L4.ConnExt.H2c.route`, and `run_spec` is stated about it.

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

**Lean.** The counterexample `Flare.Bugs.APP_48.violates_spec` (at tag
`formal-audit-0.12`) is about the pre-fix branch. Fix: `if config.ws.handler
and not self.tls:`; the shipped branch keeps every TLS connection inside
TLS: `Flare.L4.ConnExt.Ws.spec`.

**Repro.** `formal/repro/APP-48_ws_upgrade_over_tls_sends_cleartext.mojo` (at tag `formal-audit-0.12`)
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

**Lean.** The counterexamples `Flare.Bugs.APP_49.violates_spec` (every
short send, including the observed 24-of-25 case `observed_wire`) and
`tls_response_lost` (the TLS case) are at tag `formal-audit-0.12`. Fix:
cleartext, keep the unsent tail and put it in front of the response in
`write_buf` (`_transition_to_writing`); TLS, keep the interim in a buffer
the connection owns and retry `SSL_write` from it at the start of
`_flush_write_buf_tls`. The shipped code meets the spec in both cases:
`Flare.L4.Continue.Plain.run_spec` and `Tls.run_spec`.

**Repro.** `formal/repro/APP-49_continue_partial_send_corrupts_stream.mojo` (at tag `formal-audit-0.12`),
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

Status: resolved. `ConnHandle.continue_pending` keeps what the socket did not take of the interim. Cleartext: the unsent tail of a short `send` is put in front of the response in `_transition_to_writing`. TLS: the interim is sent from that connection-owned buffer and, after WANT_WRITE, retried from it at the start of `_flush_write_buf_tls` before any response byte. A send that takes none of the interim is still dropped (the client's fallback covers it). Tests: `tests/http/test_continue_interim.mojo::test_cleartext_unsent_interim_tail_precedes_the_response`, `::test_interim_taken_whole_leaves_nothing_pending`, `::test_keep_unsent_interim_ignores_none_and_all`, `::test_tls_pending_interim_is_retried_before_the_response` (the first and last put the connection in the state a short send / WANT_WRITE leaves, since the trigger is Linux-only); the repro now prints `OK:` for both variants on Linux. The shipped models are `Flare.L4.Continue.Plain.run` and `Tls.run`, and `Plain.run_spec` and `Tls.run_spec` are stated about them.

## Documentation gaps

- **Percent-decoding claim.** `docs/features.md` lists "`Url`,
  `UrlParseError`: URL parser, percent decoding" for `flare.http.url`.
  `url.mojo` performs no percent-decoding: host, path, query and fragment
  are returned raw. Percent-decoding lives in `flare.http.form` (`urldecode`).
- **Single-worker drain report.** `HttpServer.drain` returns a
  `ShutdownReport` whose counts are all zero; only the multi-worker
  `Scheduler.drain` (L5) measures anything. The docstring's "Returns"
  paragraph says so, and `docs/features.md` describes the wait added for
  APP-46. The report is not modelled.
- **Redirect method rewriting.** The `RedirectDecision` docstring
  (`redirect_policy.mojo`) documents POST, PUT and PATCH becoming
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
  the static and error paths, which bypassed it before APP-04 and APP-05,
  are covered by `staticBytes_spec` and `headFlag_spec`.
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
  `parse(to_urlencoded fd) = fd` hold for all well-formed UTF-8 strings
  (`urldecode_urlencode`, `parseForm_toUrlencoded`); APP-24 was the only
  defect.
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

Mojo paths are relative to `flare/`. Each Lean definition's anchor names the
Mojo symbols it mirrors; `formal/scripts/anchors.py` checks them.

| Lean definition | Mojo symbols | Theorems | Status |
|---|---|---|---|
| `Flare.L4.ConnSM.init`, `queueError`, `finalise`, `applyKA` | `http/_reactor/conn_handle.mojo`: `ConnHandle.__init__`, `_queue_error`, `_transition_to_writing`, `_finalise_response`, `_apply_keepalive_policy` | `inv_init`, `inv_queueError`, `ka_bound` | proved |
| `Flare.L4.ConnSM.dispatch`, `parse`, `onReadable` | `conn_handle.mojo`: `ConnHandle.on_readable`, `_check_request_complete`, `_drain_recv` | `inv_dispatch`, `inv_parse`, `inv_onReadable`, `responses_fifo`, `no_request_after_close_header` | proved; APP-01 |
| `Flare.L4.ConnSM.onWritable`, `onTimeout`, `stepCH`, `lts` | `conn_handle.mojo`: `ConnHandle.on_writable`, `on_timeout` | `writable_resumes`, `timeout_closes`, `segs_frozen`, `inv_inductive` | proved |
| `Flare.L4.ConnSM.Framing.serialize` | `http/_reactor/write_path.mojo`: `serialize_response_into`, `_wire_status` | `serialize_spec` | proved |
| `Flare.L4.ConnSM.Framing.headFlag`, `staticBytes` | `conn_handle.mojo`: `ConnHandle._check_request_complete`, `_handle_ws_upgrade`, `on_readable_view`, `on_readable_static` | `headFlag_spec`, `staticBytes_spec` | proved; APP-04, APP-05 |
| `Flare.L4.KeepAlive.isKeepaliveFast`, `isCloseFast`, `computeCloseAfter` | `http/_reactor/keepalive_scan.mojo`: `_connection_is_keepalive`, `_connection_is_close`, `_conn_token_mask`, `_compute_close_after` | `computeCloseAfter_eq_spec` | proved; APP-03 |
| `Flare.L4.KeepAlive.wantsClose` and helpers | `keepalive_scan.mojo`: `_wants_close` | `wantsClose_sound_close`, `wantsClose_spec` | proved; APP-02 |
| `Flare.L4.ServerConfig.check`, timers, `overCapImpl` | `http/_server/config.mojo`: `ServerConfig`, `ServerConfig.check`; `conn_handle.mojo`: `ConnHandle._check_request_complete`, `on_writable`, `_drain_recv`, `_drain_recv_tls`, `_append_pre_recv_bytes` | `default_check`, `timer_instr_nonneg`, `closeTime_le`, `overCapImpl_eq_spec` | proved; APP-06 |
| `Flare.L4.Router.splitPath`, `compile`, `matchSegs`, `serve`, `serveMounts` | `http/router.mojo`: `_split_path`, `_compile_segments`, `_match`, `Router.serve`, `_MountedRouter.serve`, `_prefix_match` | `serve_eq_spec`, `serve_valid`, `allow_exact`, `mount_compose` | proved |
| `Flare.L4.ComptimeRouter.matchOne`, `scanCT`, `serveCT` | `http/routes.mojo`: `_match_one`, `ComptimeRouter.serve` | `serveCT_eq_serve`, `router_equiv_comptime`, `matchOne_eq_spec` | proved; APP-10 |
| `Flare.L4.Middleware.setH`, `appendH`, `getH`, `hasH` | `http/headers.mojo`: `HeaderMap.set`, `append`, `get`, `contains` | `getH_setH_self`, `hasH_setH_self` | proved |
| `Flare.L4.Middleware.logger`, `requestId`, `catchPanic` | `http/middleware.mojo`: `Logger.serve`, `RequestId.serve`, `CatchPanic.serve` | `logger_transparent`, `catchPanic_idem`, `requestId_outside_catchPanic` | proved |
| `Flare.L4.Middleware.compress`, `encodeAs` | `middleware.mojo`: `Compress.serve` | `compress_content_length`, `compress_partial`, `compress_vary` | proved; APP-26, APP-27 |
| `Flare.L4.Negotiate.parseQ`, `parseEntry`, `parseHeader`, `decide'`, `negotiate` | `middleware.mojo`: `_parse_q`, `negotiate_encoding` | `parseQ_le`, `decide'_eq_spec`, `negotiate_eq_spec` | proved; APP-20 |
| `Flare.L4.Negotiate.parseHeaderMojo` | `middleware.mojo`: `negotiate_encoding` | `parseHeaderMojo_eq` | proved |
| `Flare.L4.Cors.originAllowed`, `attachOrigin`, `ensureVary`, `serve` | `http/cors.mojo`: `_origin_allowed`, `Cors._attach_origin`, `_ensure_vary_origin`, `Cors.serve` | `originAllowed_sound`, `acao_not_star_with_creds`, `serve_vary` | proved; APP-21, APP-22 |
| `Flare.L4.Cookie.toSetCookie`, `parseMaxAge` | `http/cookie.mojo`: `Cookie.to_set_cookie_header`, `_parse_max_age` | `toSetCookie_noCRLF`, `toSetCookie_none_secure`, `parseMaxAge_sound` | proved |
| `Flare.L4.Form.urldecode`, `urlencode`, `parseForm`, `toUrlencoded` | `http/form.mojo`: `urldecode`, `urlencode`, `parse_form_urlencoded`, `FormData.to_urlencoded` | `urldecode_valid`, `urldecode_urlencode`, `parseForm_toUrlencoded` | proved; APP-24 |
| `Flare.L4.Url.parse`, `parseWith`, `parsePort` | `http/url.mojo`: `Url.parse`, `_find`, `_rfind`, `_default_port`, `_parse_port` | `parsePort_iff`, `parse_port`, `parse_spec` | proved; APP-23, APP-25 |
| `Flare.L4.RateLimit.step`, `stepUnclamped`, `spec` | `http/reliability.mojo`: `RateLimit.serve` | `step_eq_spec`, `step_inv`, `overflow_iff` | proved; APP-40 |
| `Flare.L4.CircuitBreaker.arrive`, `finish`, `step` | `reliability.mojo`: `CircuitBreaker.serve`, `_record_failure` | `step_counts_inv`, `step_open_rejects`, `cooldown_respected`, `single_probe` | proved; APP-41, APP-42 |
| `Flare.L4.Retry.budget`, `sleep`, `serve` | `reliability.mojo`: `_backoff_sleep_ms`, `Retry.serve` | `budget_eq_spec`, `sleep_bounds`, `serve_calls_bounded` | proved |
| `Flare.L4.Redirect.resolveLocation`, `removeDotSegments`, `sameOrigin`, `decideR`, `sendLoop` | `http/redirect_policy.mojo`: `_resolve_location`, `_remove_dot_segments`, `_same_origin`, `RedirectPolicy.decide`; `http/client.mojo`: `HttpClient._send_once` | `sendLoop_terminates`, `rdsAux_no_dots`, `sendLoop_confined`, `decide_method_rfc` | proved; APP-43, APP-44, APP-45 |
| `Flare.L4.ClientPool.release`, `acquire`, `popLoop`, `total` | `http/client_pool.mojo`: `ClientPool.release`, `acquire`, `_total_idle` | `inv_inductive`, `caps`, `acquire_same_origin` | proved |
| `Flare.L4.Drain.pollCap`, `delivered`, `stopDelay` | `http/_reactor/lifecycle.mojo`: `_poll_timeout_ms`; `http/_unified_reactor_impl.mojo`: `_run_unified_loop_for_fd`, `_drain_remaining_conns_unified`; `http/server.mojo`: `HttpServer.drain` | `graceful`, `stopDelay_nonpos` | proved; APP-46 |
| `Flare.L4.ClientLease.sendPooled`, `client` | `http/client.mojo`: `HttpClient._send_h1_pooled` | `dispose_first`, `release_once`, `inv_reachable`, `acquire_not_held` | proved |
| `Flare.L4.ConnExt.H2c.route`, `driveH1`, `driveH1Writable` | `http/_unified_reactor_impl.mojo`: `_unified_handle_conn_event`, `_drive_h1`, `_drive_h1_writable`; `conn_handle.mojo`: `ConnHandle.on_writable` | `run_spec` | proved; APP-47 |
| `Flare.L4.ConnExt.Ws.upgradeTaken`, `wire` | `conn_handle.mojo`: `ConnHandle.on_readable`, `_start_h2c_upgrade`, `_handle_ws_upgrade` | `spec` | proved; APP-48 |
| `Flare.L4.ConnLive.trace`, `Fair`, `Oracle.Ext` | `conn_handle.mojo` (via `ConnSM.step`); reactor re-drive in `_unified_reactor_impl.mojo` (not anchored) | `eventually_served`, `done_reason`, `trace_done_sc` | proved |
| `Flare.L4.ConnStream.Stream.batch`, `wloop`, `finish`, `onWritable` | `conn_handle.mojo`: `ConnHandle._stream_refill`, `on_writable` | `inv_onWritable`, `wire_exact_at_end`, `interest` | proved |
| `Flare.L4.ConnStream.Tls.drain`, `flush`, `readDriver`, `writeDriver`, `route` | `conn_handle.mojo`: `ConnHandle._drain_recv_tls`, `_flush_write_buf_tls`, `on_writable`; `_unified_reactor_impl.mojo`: `_drive_h1`, `_drive_h1_writable`, `_unified_handle_conn_event` | `blocked_interest`, `retry_read`, `retry_write`, `inv_route`, `interest_nonempty` | proved |
| `Flare.L4.Continue.Plain.sendContinue`, `finalise`, `flush`; `Tls.sendContinue`, `flush` | `conn_handle.mojo`: `ConnHandle._maybe_send_continue`, `_keep_unsent_interim`, `_check_request_complete`, `_transition_to_writing`, `on_writable`, `_flush_write_buf_tls` | `Plain.run_spec`, `Tls.run_spec` | proved; APP-49 |
| `Flare.L4.Policies.ErrorLog.handlerError`, `extractorError` | `errors.mojo`: `log_handler_error`; `http/extract.mojo`: `Extracted.serve`, `_bad_request_from_error` | `ErrorLog.policy` | proved; DOC-04 |
| `Flare.L4.Policies.EntryPoints.entry` | `http/server.mojo`: `HttpServer._reject_extra_listeners` | `EntryPoints.entry_spec` | proved; DOC-05 |
| `Flare.L4.Policies.Session.csEncode`, `csLoad`, `backedDefaultTtl` | `http/session.mojo`: `CookieSessionStore.encode_at`, `load_at`, `BackedSessionStore.__init__`, `DEFAULT_SESSION_TTL_S` | `Session.expires` | proved; DOC-06 |
| `Flare.L4.Policies.TlsReload.reload` | `tls/acceptor.mojo`: `TlsAcceptor.reload` | `TlsReload.rotates` | proved; DOC-07 |
| `Flare.L4.Policies.Tickets.defaultTickets`, `build` | `tls/acceptor.mojo`: `TlsServerConfig.__init__`, `TlsAcceptor.__init__` | `Tickets.opt_in` | proved; DOC-08 |
