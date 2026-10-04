import Flare.L4_App.Form

/-!
# APP-24: `urldecode` builds a `String` from ill-formed UTF-8

flare/http/form.mojo:87 @59bda50 returns
`String(unsafe_from_utf8=Span[UInt8, _](out))` where `out` holds whatever
bytes the `%XX` escapes named. Mojo's `String` requires valid UTF-8 for that
constructor (its Safety clause); `%F0` yields the single byte `0xF0`, a
4-byte lead with no continuation bytes. Codepoint iteration over such a
String (`Codepoint.unsafe_decode_utf8_codepoint`) reads past the end of the
buffer. WHATWG URL §5.1 step 3.4 instead runs "UTF-8 decode without BOM",
which replaces ill-formed sequences with U+FFFD.

Spec (RFC 3629, `Flare.L4.Form.Utf8Valid`): every successful decode is
well-formed UTF-8.
-/
namespace Flare.Bugs.APP_24

open Flare.L4.Form

/-- The safety property flare's `String(unsafe_from_utf8=...)` needs. -/
def DecodeSpec (dec : Flare.Bytes → Option Flare.Bytes) : Prop :=
  ∀ s out, dec s = some out → Utf8Valid out = true

/-- `%F0` (bytes `25 46 30`) decodes to the lone lead byte `0xF0`. -/
theorem urldecode_nil : urldecode [] = some [] := by rw [urldecode.eq_def]

theorem urldecode_F0 : urldecode [37, 70, 48] = some [0xF0] := by
  rw [urldecode_pct, urldecode_nil]; decide

theorem F0_invalid : Utf8Valid [0xF0] = false := by decide

/-- Counterexample: flare's `urldecode` violates the spec. -/
theorem urldecode_violates_spec : ¬ DecodeSpec urldecode := by
  intro h
  have := h _ _ urldecode_F0
  rw [F0_invalid] at this
  exact Bool.false_ne_true this

/-- Reachable from a form body: `a=%F0` parses to the value `[0xF0]`. -/
theorem parseForm_F0 : parseForm [97, 61, 37, 70, 48] = some [([97], [0xF0])] := by
  have h := parseForm_single [97, 61, 37, 70, 48] (by decide) (by decide)
  rw [h]
  have hp : parsePair [97, 61, 37, 70, 48] = some ([97], [0xF0]) := by
    have e : breakEq [97, 61, 37, 70, 48] = ([97], some [37, 70, 48]) := by decide
    simp only [parsePair, e, Option.getD_some, urldecode_F0]
    rw [urldecode_other 97 [] (by decide) (by decide), urldecode_nil]; rfl
  rw [hp]; rfl

/-- The fix (validate after decoding, `String(from_utf8=...)`) meets the spec. -/
theorem urldecodeFixed_meets_spec : DecodeSpec urldecodeFixed :=
  fun s out h => urldecodeFixed_valid s out h

/-- …and still round-trips every well-formed UTF-8 string. -/
theorem urldecodeFixed_roundtrip (s : Flare.Bytes) (h : Utf8Valid s = true) :
    urldecodeFixed (urlencode s) = some s := urldecodeFixed_urlencode s h

end Flare.Bugs.APP_24
