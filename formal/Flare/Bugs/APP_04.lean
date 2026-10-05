import Flare.L4_App.ConnSM

/-!
# APP-04: the static fast path sends the body in reply to HEAD

flare/http/_reactor/conn_handle.mojo:1174-1211 @59bda50 (`on_readable_static`, pre-fix)
with flare/http/_reactor/write_path.mojo:107-148 (`serialize_static_into`).
The static path never looks at the request method: it copies the whole
pre-encoded response (head and body) into `write_buf`, with
`Connection: keep-alive` unless the request asked to close. A keep-alive
client reads the body bytes as the start of the next response (response
desynchronisation).

Spec (RFC 9110 §9.3.2: the server MUST NOT send content in a response to
HEAD; RFC 9112 §6.3: a response to HEAD ends at the header terminator):
`Flare.L4.ConnSM.Framing.StaticHeadSpec`, the bytes queued for HEAD are
exactly the head.

Status: resolved. `on_readable_static` now queues only the head of the
pre-encoded bytes for HEAD; the model `staticBytes` is the shipped code and
`staticBytesOld` the pre-fix one. Regression test:
`tests/http/test_server_reactor_state.mojo::test_static_head_queues_head_only`.
-/
namespace Flare.Bugs.APP_04

open Flare.L4.ConnSM.Framing

/-- Counterexample (pre-fix code): a static response with a non-empty body
queues `head ++ body` for HEAD. -/
theorem static_head_emits_body :
    staticBytesOld [1] [2] true = [1, 2] ∧ ¬ StaticHeadSpec staticBytesOld := by
  refine ⟨rfl, fun h => ?_⟩
  have := h [1] [2]
  simp [staticBytesOld] at this

/-- The shipped code (for HEAD queue only the bytes up to the first
CRLFCRLF) meets the spec, and leaves GET unchanged. -/
theorem staticFixed_head_no_body :
    StaticHeadSpec staticBytes ∧ ∀ head body, staticBytes head body false = head ++ body :=
  ⟨staticBytes_spec, staticBytes_get⟩

end Flare.Bugs.APP_04
