import Flare.L3_Protocol.H1.HeaderText
import Flare.L1_Encoding.Utf8

/-!
# Field-value validation and the `String` invariant

`_parse_http_request_bytes` checks every byte of a header value
(`flare/http/_server/parse.mojo:277-285`) and then keeps the value as a Mojo
`String` built by `_ascii_unchecked_string`, whose contract
(`flare/http/proto/ascii.mojo:63-70`) is "every byte `< 0x80`".

* `strict_value_ascii`, `strict_value_utf8`: in strict mode every accepted
  value is ASCII, so the contract holds and the `String` is valid UTF-8.
* With `accept_obs_text_in_field_value` it is not (`H1-05`). `valueAccepted`
  (the shipped check since the H1-05 fix) adds a UTF-8 check:
  `fixed_value_utf8`. `valueAcceptedOld` is the byte check alone, as it was
  before the fix.
-/
namespace Flare.L3.H1.FieldValue
open Flare Flare.L3.H1.Text

/-- One value byte: NUL/LF/CR never; `≥ 0x80` only under obs-text; else
field-vchar.
mirrors flare/http/_server/parse.mojo:277-285 @59bda50 -/
def byteOk (obsText : Bool) (c : UInt8) : Bool :=
  !(c == 0 || c == 10 || c == 13) && (if 128 ≤ c then obsText else isFieldVchar c)

/-- mirrors flare/http/_server/parse.mojo:277-285 @59bda50 -/
def valueOk (obsText : Bool) (v : Bytes) : Bool := v.all (byteOk obsText)

/-- The value acceptance before the `H1-05` fix: the byte check alone. Kept
for the counterexample. -/
abbrev valueAcceptedOld := valueOk

/-- The shipped value acceptance: the byte check, and a value with an obs-text
byte must be valid UTF-8 (an ASCII value always is).
mirrors flare/http/_server/parse.mojo:281-296 (fixed, H1-05) -/
def valueAccepted (obsText : Bool) (v : Bytes) : Bool := valueOk obsText v && Flare.L1.Utf8.isValidUtf8 v

/-- Every accepted value is valid UTF-8. -/
def Utf8Safe (chk : Bytes → Bool) : Prop := ∀ v, chk v = true → Flare.L1.Utf8.WF v

theorem byteOk_strict {c : UInt8} (h : byteOk false c = true) : c.toNat < 128 := by
  unfold byteOk at h
  by_cases hc : 128 ≤ c
  · simp [hc] at h
  · have : ¬ (128 : UInt8).toNat ≤ c.toNat := fun x => hc (UInt8.le_iff_toNat_le.mpr x)
    simp at this; omega

theorem strict_value_ascii {v : Bytes} (h : valueOk false v = true) : ∀ c ∈ v, c.toNat < 128 := by
  intro c hc
  exact byteOk_strict (List.all_eq_true.mp h c hc)

theorem wf_of_ascii : ∀ {v : Bytes}, (∀ c ∈ v, c.toNat < 128) → Flare.L1.Utf8.WF v
  | [], _ => Flare.L1.Utf8.WF.nil
  | a :: r, h => by
    have ha := h a (by simp)
    have : Flare.L1.Utf8.seqOK [a] := by simp only [Flare.L1.Utf8.seqOK]; omega
    exact Flare.L1.Utf8.WF.app (s := [a]) this (wf_of_ascii (fun c hc => h c (by simp [hc])))

/-- **Strict mode keeps the `String` invariant.** -/
theorem strict_value_utf8 : Utf8Safe (valueOk false) :=
  fun _ h => wf_of_ascii (strict_value_ascii h)

theorem fixed_value_utf8 (obsText : Bool) : Utf8Safe (valueAccepted obsText) := by
  intro v h
  simp only [valueAccepted, Bool.and_eq_true] at h
  exact (Flare.L1.Utf8.isValidUtf8_iff v).mp h.2

end Flare.L3.H1.FieldValue
