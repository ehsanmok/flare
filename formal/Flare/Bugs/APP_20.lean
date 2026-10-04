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
-/
namespace Flare.Bugs.APP_20

open Flare Flare.L4.Negotiate

def hA : Bytes := Bytes.ofString "gzip;q=0.5, *"
def hB : Bytes := Bytes.ofString "*, gzip;q=0.5"
def hC : Bytes := Bytes.ofString "identity;q=0, *"

/-- Non-maximal pick: flare returns gzip/500, the spec br/1000. -/
theorem negotiate_wildcard_not_max :
    negotiate true hA = (.gzip, 500) ∧ specPick true (parseHeader hA) = (.br, 1000) := by
  native_decide

/-- Order dependence: the two headers carry the same entries in a different
order, yet flare picks different codings. -/
theorem negotiate_order_dependent :
    (parseHeader hA).Perm (parseHeader hB) ∧
    negotiate true hA = (.gzip, 500) ∧ negotiate true hB = (.identity, 1000) := by
  refine ⟨?_, by native_decide, by native_decide⟩
  have e1 : parseHeader hA = [(.gzip, 500), (.star, 1000)] := by native_decide
  have e2 : parseHeader hB = [(.star, 1000), (.gzip, 500)] := by native_decide
  rw [e1, e2]; exact List.Perm.swap _ _ _

/-- Explicitly refused identity is served while gzip is acceptable. -/
theorem negotiate_serves_refused_identity :
    negotiate false hC = (.identity, 1000) ∧
    specPick false (parseHeader hC) = (.gzip, 1000) := by
  native_decide

/-- Headline counterexample: `¬ spec (impl x)`. -/
theorem negotiate_violates_spec :
    negotiate true hA ≠ specPick true (parseHeader hA) ∧
    negotiate false hC ≠ specPick false (parseHeader hC) := by
  native_decide

/-- The fixed loop (track per-coding maxima and the `*` weight, pick at the
end) meets the spec on every entry list, hence on all three headers. -/
theorem fixed_meets_spec (brOk : Bool) (h : Bytes) :
    decideFixed brOk (parseHeader h) = specPick brOk (parseHeader h) :=
  decideFixed_eq_spec brOk _

theorem fixed_on_examples :
    decideFixed true (parseHeader hA) = (.br, 1000) ∧
    decideFixed true (parseHeader hB) = (.br, 1000) ∧
    decideFixed false (parseHeader hC) = (.gzip, 1000) := by
  native_decide

end Flare.Bugs.APP_20
