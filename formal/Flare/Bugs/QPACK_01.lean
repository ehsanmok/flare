import Flare.L3_Protocol.Qpack.FieldSection

/-!
# QPACK-01: field-section references escape Required Insert Count

flare/qpack/dynamic.mojo:489-555 @59bda50 (before the fix) computed `base = ric - delta - 1`
in UInt64 without checking `delta < ric` (RFC 9204 §4.5.1.2), computes
post-base `base + ip` with wraparound, and never checks `abs < ric`
(RFC 9204 §4.5.1, §4.5.3, §4.5.5). With RIC = 0, Sign = 1, Delta = 0 the base
is `2^64 - 1` and post-base index 1 resolves to absolute index 0: a field
section that declares "no dynamic references" reads the dynamic table.

Status: resolved. `implOldResolve` is the pre-fix resolver (the counterexample
is about it); the shipped `implResolve` (flare/qpack/dynamic.mojo
`_pre_base_abs`, `_post_base_abs` and the Sign/Delta Base guard) rejects both
witnesses and equals the RFC spec. Regression tests:
tests/qpack/test_qpack_dynamic.mojo (`test_ric_zero_section_cannot_read_the_dynamic_table`
and three more).
-/
namespace Flare.Bugs.QPACK_01
open Flare.L3.Qpack.FieldSection

/-- Table holding one entry (absolute index 0). -/
def g1 : Geo := ⟨0, 1⟩

theorem base_wraps : implBase 0 0 true = 0xFFFFFFFFFFFFFFFF := by decide

/-- RIC = 0, Sign = 1, Delta Base = 0, post-base index 1 → entry 0. -/
theorem counterexample : implOldResolve 0 0 true g1 (.post 1) = some 0 := by decide

theorem violates_safety : ¬ RefSafe 0 (implOldResolve 0 0 true g1 (.post 1)) := by
  intro h; exact absurd (h 0 counterexample) (by decide)

theorem spec_rejects : specResolve 0 0 true 0 1 true 1 = none := by decide

/-- Second witness without wraparound: RIC = 1, Base = 1, post-base index 0
names absolute index 1 ≥ RIC, which flare accepts once two entries exist. -/
theorem counterexample_noWrap : implOldResolve 1 0 false ⟨0, 2⟩ (.post 0) = some 1 := by decide

theorem spec_rejects_noWrap : specResolve 1 0 false 0 2 true 0 = none := by decide

/-- The shipped resolver (`implResolve`) rejects both and meets the spec. -/
theorem fixed_rejects : implResolve 0 0 true g1 (.post 1) = none ∧
    implResolve 1 0 false ⟨0, 2⟩ (.post 0) = none := by decide

theorem fixed_meets_spec (ric delta : UInt64) (sign : Bool) (g : Geo) (r : Ref)
    (hb : Bounded ric delta g r) :
    (implResolve ric delta sign g r).map UInt64.toNat
      = specResolve ric.toNat delta.toNat sign g.dropped.toNat g.ic.toNat r.isPost r.ip.toNat :=
  implResolve_eq_spec ric delta sign g r hb

theorem fixed_safe (ric delta : UInt64) (sign : Bool) (g : Geo) (r : Ref) :
    RefSafe ric (implResolve ric delta sign g r) :=
  implResolve_safe ric delta sign g r

end Flare.Bugs.QPACK_01
