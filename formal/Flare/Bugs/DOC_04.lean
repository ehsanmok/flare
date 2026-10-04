/-!
# DOC-04: sanitised error responses are not logged with the request id

* flare file: `flare/http/_reactor/conn_handle.mojo:910-915` @59bda50 (the
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
* Fix (`handlerErrorFixed`, `extractorErrorFixed`): read `x-request-id`
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

/-- The message reaches only `map_handler_error`, which drops it when not
exposed; nothing is logged.
mirrors flare/http/_reactor/conn_handle.mojo:908-915 @59bda50 -/
def handlerError (_rid _msg : String) : Out :=
  { status := 500, body := "Internal Server Error", log := [] }

/-- mirrors flare/http/extract.mojo:868-880,914-932 @59bda50 -/
def extractorError (_rid msg : String) : Out :=
  { status := 400, body := "Bad Request", log := [⟨none, msg⟩] }

/-- The documented policy for one error path: fixed status and body, and a
log line carrying both the full message and the request id. -/
def Policy (status : Nat) (body : String) (path : String → String → Out) : Prop :=
  ∀ rid msg, (path rid msg).status = status ∧ (path rid msg).body = body ∧
    Line.mk (some rid) msg ∈ (path rid msg).log

def handlerErrorFixed (rid msg : String) : Out :=
  { status := 500, body := "Internal Server Error", log := [⟨some rid, msg⟩] }

def extractorErrorFixed (rid msg : String) : Out :=
  { status := 400, body := "Bad Request", log := [⟨some rid, msg⟩] }

/-- The repro's two requests: the handler message is not logged at all, and
the extractor message is logged without its request id. -/
theorem bug :
    (handlerError "doc04-rid-500" "doc04-handler-secret").log = [] ∧
    (extractorError "doc04-rid-400" "doc04-extract-secret").log =
      [⟨none, "doc04-extract-secret"⟩] := by
  simp [handlerError, extractorError]

theorem counterexample :
    ¬ Policy 500 "Internal Server Error" handlerError ∧
    ¬ Policy 400 "Bad Request" extractorError := by
  refine ⟨fun h => ?_, fun h => ?_⟩
  · have := (h "doc04-rid-500" "doc04-handler-secret").2.2
    simp [handlerError] at this
  · have := (h "doc04-rid-400" "doc04-extract-secret").2.2
    simp [extractorError] at this

theorem fixed :
    Policy 500 "Internal Server Error" handlerErrorFixed ∧
    Policy 400 "Bad Request" extractorErrorFixed := by
  refine ⟨fun rid msg => ?_, fun rid msg => ?_⟩ <;>
    simp [handlerErrorFixed, extractorErrorFixed]

end Flare.Bugs.DOC_04
