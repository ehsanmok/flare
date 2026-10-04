import Flare.L4_App.ConnSM

/-!
# APP-04: the static fast path sends the body in reply to HEAD

flare/http/_reactor/conn_handle.mojo:1174-1211 @59bda50 (`on_readable_static`)
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
-/
namespace Flare.Bugs.APP_04

open Flare.L4.ConnSM.Framing

/-- Counterexample: a static response with a non-empty body queues
`head ++ body` for HEAD. -/
theorem static_head_emits_body :
    staticBytes [1] [2] true = [1, 2] ∧ ¬ StaticHeadSpec staticBytes := by
  refine ⟨rfl, fun h => ?_⟩
  have := h [1] [2]
  simp [staticBytes] at this

/-- Fix (for HEAD queue only the bytes up to the first CRLFCRLF) meets the
spec, and leaves GET unchanged. -/
theorem staticFixed_head_no_body :
    StaticHeadSpec staticBytesFixed ∧ ∀ head body, staticBytesFixed head body false = head ++ body :=
  ⟨staticBytesFixed_spec, staticBytesFixed_get⟩

end Flare.Bugs.APP_04
