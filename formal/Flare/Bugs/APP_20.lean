import Flare.L4_App.Negotiate

/-!
# APP-20: `negotiate_encoding` mishandles the `*` wildcard

flare/http/middleware.mojo:236-240 @59bda50. A `*` entry only counts when
no earlier entry has set `best_q > 0`, and it always selects `identity`.
RFC 9110 §12.5.3 says `*` "matches any available content coding not
explicitly listed in the field", and "the acceptable content coding with
the highest non-zero qvalue is preferred". Consequences:

* `gzip;q=0.5, *` (brotli available) picks gzip at 0.5 although `*` gives
  br weight 1;
* `*, gzip;q=0.5` picks identity: the result depends on entry order;
* `identity;q=0, *` serves identity, which the client explicitly refused
  (rule 2), although gzip is acceptable through `*`.

Status: resolved. `negotiate_encoding` records the largest weight per coding
(br, gzip, identity) and for `*`, then gives every coding without an entry of
its own the `*` weight and picks the highest non-zero weight (ties
br > gzip > identity). The model `decide'` / `negotiate` are the shipped
ones, `decideOld` / `negotiateOld` the pre-fix loop. Regression tests:
`tests/http/test_middleware.mojo::test_negotiate_wildcard_weight_applies_to_unlisted_codings`,
`::test_negotiate_wildcard_is_order_independent`,
`::test_negotiate_identity_refused_with_wildcard` and
`::test_negotiate_wildcard_alone_selects_best_available_coding` (the last one
replaces `test_negotiate_wildcard_falls_back_to_identity`, which pinned the
pre-fix `*` -> identity answer).
-/
namespace Flare.Bugs.APP_20

open Flare Flare.L4.Negotiate

def hA : Bytes := Bytes.ofString "gzip;q=0.5, *"
def hB : Bytes := Bytes.ofString "*, gzip;q=0.5"
def hC : Bytes := Bytes.ofString "identity;q=0, *"

/-- Non-maximal pick (pre-fix): flare returns gzip/500, the spec br/1000. -/
theorem negotiate_wildcard_not_max :
    negotiateOld true hA = (.gzip, 500) ∧ specPick true (parseHeader hA) = (.br, 1000) := by
  native_decide

/-- Order dependence: the two headers carry the same entries in a different
order, yet flare picks different codings. -/
theorem negotiate_order_dependent :
    (parseHeader hA).Perm (parseHeader hB) ∧
    negotiateOld true hA = (.gzip, 500) ∧ negotiateOld true hB = (.identity, 1000) := by
  refine ⟨?_, by native_decide, by native_decide⟩
  have e1 : parseHeader hA = [(.gzip, 500), (.star, 1000)] := by native_decide
  have e2 : parseHeader hB = [(.star, 1000), (.gzip, 500)] := by native_decide
  rw [e1, e2]; exact List.Perm.swap _ _ _

/-- The shipped decision gives the same pick for the two orders. -/
theorem fixed_order_independent : decide' true (parseHeader hA) = decide' true (parseHeader hB) := by
  have e1 : parseHeader hA = [(.gzip, 500), (.star, 1000)] := by native_decide
  have e2 : parseHeader hB = [(.star, 1000), (.gzip, 500)] := by native_decide
  rw [e1, e2]; exact decide'_perm true (List.Perm.swap _ _ _)

/-- Explicitly refused identity is served while gzip is acceptable. -/
theorem negotiate_serves_refused_identity :
    negotiateOld false hC = (.identity, 1000) ∧
    specPick false (parseHeader hC) = (.gzip, 1000) := by
  native_decide

/-- Headline counterexample: `¬ spec (impl x)` for the pre-fix loop. -/
theorem negotiate_violates_spec :
    negotiateOld true hA ≠ specPick true (parseHeader hA) ∧
    negotiateOld false hC ≠ specPick false (parseHeader hC) := by
  native_decide

/-- The shipped decision (per-coding maxima and the `*` weight, pick at the
end) meets the spec on every entry list, hence on all three headers. -/
theorem fixed_meets_spec (brOk : Bool) (h : Bytes) :
    decide' brOk (parseHeader h) = specPick brOk (parseHeader h) :=
  decide'_eq_spec brOk _

theorem fixed_on_examples :
    decide' true (parseHeader hA) = (.br, 1000) ∧
    decide' true (parseHeader hB) = (.br, 1000) ∧
    decide' false (parseHeader hC) = (.gzip, 1000) := by
  native_decide

end Flare.Bugs.APP_20
