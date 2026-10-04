import Flare.Bugs.H2_Fixtures

/-!
# H2-10: field names with non-ASCII bytes or an inner colon are accepted

`validate_request_fields` (flare/http2/state.mojo:1727-1733 @59bda50)
rejects in a field name only uppercase ASCII, bytes `≤ 0x20` and `0x7f`.
Bytes `≥ 0x80` and a `:` after the first byte pass, so the names
`x\xc3\xa9` and `a:b` are accepted.

RFC 9113 §8.2.1: "A field name MUST NOT contain characters in the ranges
0x00-0x20, 0x41-0x5a, or 0x7f-0xff (all ranges inclusive). [...] With the
exception of pseudo-header fields [...], which have a name that starts
with a single colon, field names MUST NOT include a colon (ASCII COLON,
0x3a)." A request with such a field is malformed (§8.1.1).
-/
namespace Flare.Bugs.H2_10
open Flare Flare.L3.H2.Validate Flare.Bugs.H2_Fixtures

def nUtf8 : Bytes := [0x78, 0xC3, 0xA9]
def nColon : Bytes := [0x61, 0x3A, 0x62]

def req (n : Bytes) : List Header := getReq ++ [⟨n, Bytes.ofString "1"⟩]

theorem bug : implNameOK nUtf8 = true ∧ implNameOK nColon = true ∧
    validate (req nUtf8) false false = true ∧ validate (req nColon) false false = true := by
  native_decide

theorem counterexample : ¬ SpecName nUtf8 ∧ ¬ SpecName nColon := by
  refine ⟨fun h => ?_, fun h => ?_⟩
  · have := (h.2.1 0xC3 (by simp [nUtf8])).2.2; exact absurd this (by decide)
  · exact h.2.2 0x3A (by simp [nColon]) rfl

/-- The accepted requests are malformed: §8.2.1 fails for the added field. -/
theorem counterexample_request : ¬ SpecRequest false (req nUtf8) ∧ ¬ SpecRequest false (req nColon) := by
  refine ⟨fun h => ?_, fun h => ?_⟩
  · have := ((h.1 ⟨nUtf8, Bytes.ofString "1"⟩ (by simp [req])).2.1 0xC3 (by simp [nUtf8])).2.2
    exact absurd this (by decide)
  · exact (h.1 ⟨nColon, Bytes.ofString "1"⟩ (by simp [req])).2.2.1 0x3A (by simp [nColon]) rfl

theorem fixed_trace : fixedNameOK nUtf8 = false ∧ fixedNameOK nColon = false := by native_decide

/-- **Fixed** (also reject bytes `≥ 0x7f`, and `:` after the first byte):
the per-name check is exactly §8.2.1. -/
theorem fixed (n : Bytes) : fixedNameOK n = true ↔ SpecName n := fixedNameOK_iff n

end Flare.Bugs.H2_10
