import Flare.L3_Protocol.H1.HeaderText
import Flare.L1_Encoding.Utf8

/-!
# Field-value validation and the `String` invariant

`_parse_http_request_bytes` checks every byte of a header value, and of
every obs-fold continuation, with `_check_field_value` and then keeps the value as a Mojo
`String` built by `_ascii_unchecked_string`, whose contract
(`flare/http/proto/ascii.mojo:63-70`) is "every byte `< 0x80`".

* `strict_value_ascii`, `strict_value_utf8`: in strict mode every accepted
  value is ASCII, so the contract holds and the `String` is valid UTF-8.
* With `accept_obs_text_in_field_value` the byte check alone is not enough;
  `valueAccepted` adds a UTF-8 check: `fixed_value_utf8`.
* `valueOk_complete`, `valueAccepted_complete`: the converse. Every value of
  RFC 9110 §5.5 field-vchars, SP and HTAB passes the byte check (ASCII only
  in strict mode), and with obs-text also the UTF-8 check when it is valid
  UTF-8.
-/
namespace Flare.L3.H1.FieldValue
open Flare Flare.L3.H1.Text

/-- One value byte: NUL/LF/CR never; `≥ 0x80` only under obs-text; else
field-vchar.
mirrors flare/http/_server/parse.mojo#_check_field_value sha=41e444ac2cbf at=ea1b9282 -/
def byteOk (obsText : Bool) (c : UInt8) : Bool :=
  !(c == 0 || c == 10 || c == 13) && (if 128 ≤ c then obsText else isFieldVchar c)

/-- mirrors flare/http/_server/parse.mojo#_check_field_value sha=41e444ac2cbf at=ea1b9282 -/
def valueOk (obsText : Bool) (v : Bytes) : Bool := v.all (byteOk obsText)

/-- The shipped value acceptance: the byte check, and a value with an obs-text
byte must be valid UTF-8 (an ASCII value always is).
mirrors flare/http/_server/parse.mojo#_check_field_value+_parse_http_request_bytes sha=e947e2428622 at=e767e34c (fixed, H1-05) -/
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

/-! ## Completeness -/

set_option maxRecDepth 8000 in
theorem byteOk_of_vchar (o : Bool) (c : UInt8) (h : isFieldVchar c = true)
    (ho : o = true ∨ c.toNat < 128) : byteOk o c = true := by
  have key : ∀ n, n < 256 → ∀ o : Bool, isFieldVchar (UInt8.ofNat n) = true →
      (o = true ∨ n < 128) → byteOk o (UInt8.ofNat n) = true := by decide
  have := key c.toNat c.toNat_lt o (by simpa using h) ho
  simpa using this

/-- **Every field-vchar value passes the byte check** (only ASCII ones in
strict mode). -/
theorem valueOk_complete (o : Bool) (v : Bytes)
    (h : ∀ c ∈ v, isFieldVchar c = true ∧ (o = true ∨ c.toNat < 128)) : valueOk o v = true :=
  List.all_eq_true.mpr fun c hc => byteOk_of_vchar o c (h c hc).1 (h c hc).2

/-- **The shipped check accepts every field-vchar value that is valid
UTF-8**, with obs-text enabled. -/
theorem valueAccepted_complete (v : Bytes) (h : ∀ c ∈ v, isFieldVchar c = true)
    (hw : Flare.L1.Utf8.WF v) : valueAccepted true v = true := by
  simp only [valueAccepted, Bool.and_eq_true]
  exact ⟨valueOk_complete true v (fun c hc => ⟨h c hc, .inl rfl⟩),
    (Flare.L1.Utf8.isValidUtf8_iff v).mpr hw⟩

end Flare.L3.H1.FieldValue
