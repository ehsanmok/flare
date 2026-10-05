/-!
# DOC-04: sanitised error responses are not logged with the request id

Status: resolved. `log_handler_error` / `log_error_response`
(`flare/errors.mojo`) now log `[flare:<kind>] rid=<id> <message>` to stderr at
every handler-error site (`flare/http/_reactor/conn_handle.mojo`, the h2
handle, the h3 stream) and in `Extracted.serve` (`flare/http/extract.mojo`);
regression tests `tests/http/test_error_logging.mojo`. `handlerError` and
`extractorError` below are the shipped model; the `Old` variants are the
pre-fix behaviour the counterexample is about.

* flare file (pre-fix): `flare/http/_reactor/conn_handle.mojo:910-915` @59bda50 (the
  handler-error branch of `on_readable` maps the error with
  `map_handler_error`, `flare/errors.mojo:276-301`, queues the response and
  logs nothing; the same shape at conn_handle.mojo:1007, 1083, 1162,
  `flare/http/_h2_conn_handle.mojo:545, 980` and the HTTP/3 path,
  `flare/http/server.mojo:86-100`). `flare/http/extract.mojo:879-880` with
  914-919: `Extracted.serve` passes only the error to
  `_bad_request_from_error`, which prints `[flare:bad-request] <msg>` to stdout
  with no request id.
* Doc clause: `docs/security.md:14` "Logs carry the full message + request
  id"; `docs/security.md:39-43` (4xx: "logged with the request id"; "500
  (handler raise) is the same: fixed body, full message logged with request
  id"); `docs/features.md:672-674`; `flare/http/_server/config.mojo:90-95`.
* What goes wrong: a handler `raise` yields a fixed-body 500 and no log line
  at all; an extractor failure yields a fixed-body 400 and a log line without
  the request id (the `X-Request-Id` the `RequestId` middleware echoes).
* Fix (`handlerError`, `extractorError`): read `x-request-id`
  before the request is consumed and log `rid` with the message.

The model keeps what the policy talks about: the status, the body sent with
`expose_error_messages = False`, and the log lines appended. Typed
`HttpStatusError`s, which `map_handler_error` echoes on purpose, are outside
it: the model's raise is a plain `Error`.
-/
namespace Flare.Bugs.DOC_04

/-- One log line: the request id it names (if any) and the message. -/
structure Line where
  rid : Option String
  msg : String
  deriving DecidableEq, Repr

/-- What an error path produces for one request. -/
structure Out where
  status : Nat
  body : String
  log : List Line
  deriving DecidableEq, Repr

/-- Pre-fix: the message reaches only `map_handler_error`, which drops it when
not exposed; nothing is logged.
mirrors flare/http/_reactor/conn_handle.mojo:908-915 @59bda50 -/
def handlerErrorOld (_rid _msg : String) : Out :=
  { status := 500, body := "Internal Server Error", log := [] }

/-- Pre-fix.
mirrors flare/http/extract.mojo:868-880,914-932 @59bda50 -/
def extractorErrorOld (_rid msg : String) : Out :=
  { status := 400, body := "Bad Request", log := [⟨none, msg⟩] }

/-- The documented policy for one error path: fixed status and body, and a
log line carrying both the full message and the request id. -/
def Policy (status : Nat) (body : String) (path : String → String → Out) : Prop :=
  ∀ rid msg, (path rid msg).status = status ∧ (path rid msg).body = body ∧
    Line.mk (some rid) msg ∈ (path rid msg).log

/-- The shipped handler-error path: `log_handler_error(request_id, msg)` before
`map_handler_error`.
mirrors flare/http/_reactor/conn_handle.mojo:906-915 (fixed, DOC-04) -/
def handlerError (rid msg : String) : Out :=
  { status := 500, body := "Internal Server Error", log := [⟨some rid, msg⟩] }

/-- The shipped extractor-error path: `Extracted.serve` passes the request's
`x-request-id` to `_bad_request_from_error`, which logs it with the message.
mirrors flare/http/extract.mojo:868-885,915-935 (fixed, DOC-04) -/
def extractorError (rid msg : String) : Out :=
  { status := 400, body := "Bad Request", log := [⟨some rid, msg⟩] }

/-- The repro's two requests: the handler message is not logged at all, and
the extractor message is logged without its request id. -/
theorem bug :
    (handlerErrorOld "doc04-rid-500" "doc04-handler-secret").log = [] ∧
    (extractorErrorOld "doc04-rid-400" "doc04-extract-secret").log =
      [⟨none, "doc04-extract-secret"⟩] := by
  simp [handlerErrorOld, extractorErrorOld]

theorem counterexample :
    ¬ Policy 500 "Internal Server Error" handlerErrorOld ∧
    ¬ Policy 400 "Bad Request" extractorErrorOld := by
  refine ⟨fun h => ?_, fun h => ?_⟩
  · have := (h "doc04-rid-500" "doc04-handler-secret").2.2
    simp [handlerErrorOld] at this
  · have := (h "doc04-rid-400" "doc04-extract-secret").2.2
    simp [extractorErrorOld] at this

theorem fixed :
    Policy 500 "Internal Server Error" handlerError ∧
    Policy 400 "Bad Request" extractorError := by
  refine ⟨fun rid msg => ?_, fun rid msg => ?_⟩ <;>
    simp [handlerError, extractorError]

end Flare.Bugs.DOC_04
