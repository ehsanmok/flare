import Flare.L3_Protocol.H1.ClientResponse

/-!
# H1-09: an HTTP/1.0 response without keep-alive goes back to the pool

* flare file: `flare/http/_client/parse.mojo:836-884` (`can_reuse` looks at
  `Connection: close` and the framing, never at the response version)
  @59bda50.
* Spec clause: RFC 9112 §9.3: an HTTP/1.0 response persists only with
  `Connection: keep-alive`.
* What goes wrong: `HTTP/1.0 200 OK` with `Content-Length: 2` and no
  Connection field is marked reusable; the server closes, and the next
  pooled request goes to a dead (or reused) socket.
* Fix (`canReuseFixed`): reuse only HTTP/1.1 responses. `canReuseFixed_ok`.
-/
namespace Flare.Bugs.H1_09
open Flare Flare.L3.H1.ClientResponse

theorem shipped_reuses : canReuse HTTP10 true [] (.length 2) = true := by native_decide

theorem counterexample : ¬ PersistOK canReuse := by
  intro h
  have := (h _ _ _ _ shipped_reuses).2
  revert this
  native_decide

theorem fixed_ok : PersistOK canReuseFixed := canReuseFixed_ok

theorem fixed_closes : canReuseFixed HTTP10 true [] (.length 2) = false := by native_decide

end Flare.Bugs.H1_09
