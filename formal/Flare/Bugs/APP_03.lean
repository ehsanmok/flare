import Flare.L4_App.KeepAlive

/-!
# APP-03: a `close` option inside a `Connection` token list is ignored

flare/http/_reactor/keepalive_scan.mojo:350-390 @59bda50
(`_compute_close_after`, pre-fix). The `Connection` value is compared as a whole
against `close` and `keep-alive`. A list value such as `keep-alive, close`
or `TE, close` matches neither; HTTP/1.1 defaults to keep-alive, so the
connection stays open and later requests are served. `_wants_close`
(keepalive_scan.mojo:455-478) has the same whole-value compare.

Spec (RFC 9110 §7.6.1 `Connection = #connection-option`; RFC 9112 §9.6):
the connection closes iff some option is `close`, or the request is
HTTP/1.0 without a `keep-alive` option (`Flare.L4.KeepAlive.closeSpec`).

Status: resolved. `_compute_close_after` falls back to an option-list scan
(`_conn_token_mask`: split on `,`, trim OWS, case-fold) and `_wants_close`
applies the same scan to each `Connection` line's value. The model
`computeCloseAfter` / `verdict` are the shipped ones, `computeCloseAfterOld` /
`verdictOld` the pre-fix ones. Regression tests:
`tests/http/test_connection_keepalive_fastpath.mojo::test_compute_close_after_close_inside_option_list`,
`::test_compute_close_after_option_list_without_close` and
`::test_wants_close_option_list`.
-/
namespace Flare.Bugs.APP_03

open Flare.L4.KeepAlive

def v1 : Bytes := Bytes.ofString "keep-alive, close"
def v2 : Bytes := Bytes.ofString "TE, close"

/-- Counterexample (pre-fix): both values carry a `close` option; the spec closes,
`_compute_close_after` keeps the HTTP/1.1 connection alive. -/
theorem computeCloseAfterOld_misses_close :
    computeCloseAfterOld v1 false = false ∧ closeSpec v1 false = true ∧
    computeCloseAfterOld v2 false = false ∧ closeSpec v2 false = true := by
  native_decide

/-- `¬ spec (impl x)` for the pre-fix function. -/
theorem violates_spec : computeCloseAfterOld v1 false ≠ closeSpec v1 false := by
  rw [computeCloseAfterOld_misses_close.1, computeCloseAfterOld_misses_close.2.1]; decide

/-- The shipped function (token scan on the slow path, fast paths unchanged)
equals the spec on every value and version. -/
theorem computeCloseAfterFixed_meets_spec (v : Bytes) (http10 : Bool) :
    computeCloseAfter v http10 = closeSpec v http10 :=
  computeCloseAfter_eq_spec v http10

end Flare.Bugs.APP_03
