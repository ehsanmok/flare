import Flare.L4_App.KeepAlive

/-!
# APP-02: `_wants_close` matches `connection:` anywhere and stops at the first hit

flare/http/_reactor/keepalive_scan.mojo:393-484 @59bda50 (pre-fix; the
`while i < n - nn` scan, lines 436-479). The scan tests for the bytes
`connection:` at every offset of the header block, not only at the start
of a header line, and `break`s after the first match. A header such as
`X-Connection: x` therefore hides a later `Connection: close` line. The
static fast path (`on_readable_static`, conn_handle.mojo:1200) and the
`skip_header_decode_for_short_requests` path (conn_handle.mojo:805) then
keep the connection alive against the client's `close`.

Spec (RFC 9112 §9.6, RFC 9110 §7.6.1): if any header line is
`Connection: close`, the server closes after the response
(`Flare.L4.KeepAlive.WantsCloseSpec`).

Status: resolved. `_wants_close` now matches `connection:` only at a line
start and ORs the verdicts of every such line (it no longer `break`s at the
first match). The model `wantsClose` is the shipped scan, `wantsCloseOld` the
pre-fix one. Regression tests:
`tests/http/test_connection_keepalive_fastpath.mojo::test_wants_close_after_x_connection_header`,
`::test_wants_close_ignores_connection_inside_other_header_names` and
`::test_wants_close_ors_every_connection_line`.
-/
namespace Flare.Bugs.APP_02

open Flare.L4.KeepAlive

def req : Bytes :=
  Bytes.ofString "GET / HTTP/1.1\r\nHost: a\r\nX-Connection: x\r\nConnection: close\r\n\r\n"

/-- Offset of the `Connection: close` line. -/
def lineAt : Nat := 42

/-- Counterexample (pre-fix): the request carries `Connection: close` at a
line start (offset 42) with value `close`, but `_wants_close` returned `false`:
its first match is inside `X-Connection:` at offset 27. -/
theorem wantsClose_misses_close :
    firstConn req req.length = some 27 ∧
    lineStart req req.length lineAt = true ∧ isConn req lineAt = true ∧
    (verdict req req.length lineAt).1 = true ∧
    wantsCloseOld req req.length = false := by
  native_decide

/-- `¬ spec (impl x)` for the pre-fix scan. -/
theorem violates_spec : ¬ WantsCloseSpec req req.length (wantsCloseOld req req.length) := by
  intro h
  have hc := wantsClose_misses_close
  have hfe : firstEol req req.length + 1 ≤ lineAt := by native_decide
  have hlt : lineAt + 11 < req.length := by native_decide
  have := h lineAt hfe hlt hc.2.1 hc.2.2.1 hc.2.2.2.1
  rw [hc.2.2.2.2] at this; cases this

/-- The shipped scan (match only at line starts, OR the per-line verdicts)
meets the spec on every input. -/
theorem wantsCloseFixed_meets_spec (d : Bytes) (n : Nat) :
    WantsCloseSpec d n (wantsClose d n) :=
  wantsClose_spec d n

theorem fixed_on_example : wantsClose req req.length = true := by
  native_decide

end Flare.Bugs.APP_02
