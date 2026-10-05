import Flare.L4_App.Form

/-!
# APP-24: `urldecode` builds a `String` from ill-formed UTF-8

flare/http/form.mojo:87 @59bda50 (pre-fix) returned
`String(unsafe_from_utf8=Span[UInt8, _](out))` where `out` holds whatever
bytes the `%XX` escapes named. Mojo's `String` requires valid UTF-8 for that
constructor (its Safety clause); `%F0` yields the single byte `0xF0`, a
4-byte lead with no continuation bytes. Codepoint iteration over such a
String (`Codepoint.unsafe_decode_utf8_codepoint`) reads past the end of the
buffer. WHATWG URL §5.1 step 3.4 instead runs "UTF-8 decode without BOM",
which replaces ill-formed sequences with U+FFFD.

Spec (RFC 3629, `Flare.L4.Form.Utf8Valid`): every successful decode is
well-formed UTF-8.

Status: resolved. `urldecode` now builds the result with
`String(from_utf8=...)` and raises on ill-formed UTF-8 (so
`parse_form_urlencoded` and the `Form` extractor reject such bodies). The
model `urldecode` is the shipped code, `urldecodeOld` the pre-fix one.
Regression tests: `tests/http/test_form.mojo::test_urldecode_rejects_ill_formed_utf8`
and `::test_parse_ill_formed_utf8_raises`.
-/
namespace Flare.Bugs.APP_24

open Flare.L4.Form

/-- The safety property flare's `String(unsafe_from_utf8=...)` needs. -/
def DecodeSpec (dec : Flare.Bytes → Option Flare.Bytes) : Prop :=
  ∀ s out, dec s = some out → Utf8Valid out = true

/-- `%F0` (bytes `25 46 30`) decoded to the lone lead byte `0xF0` before the
fix. -/
theorem bytes_nil : urldecodeBytes [] = some [] := by rw [urldecodeBytes.eq_def]

theorem urldecode_nil : urldecodeOld [] = some [] := bytes_nil

theorem urldecode_F0 : urldecodeOld [37, 70, 48] = some [0xF0] := by
  show urldecodeBytes [37, 70, 48] = _
  rw [urldecodeBytes_pct, bytes_nil]; decide

theorem F0_invalid : Utf8Valid [0xF0] = false := by decide

/-- Counterexample: the pre-fix `urldecode` violates the spec. -/
theorem urldecode_violates_spec : ¬ DecodeSpec urldecodeOld := by
  intro h
  have := h _ _ urldecode_F0
  rw [F0_invalid] at this
  exact Bool.false_ne_true this

/-- Reachable from a form body: `a=%F0` parsed to the value `[0xF0]` before
the fix. -/
theorem parseForm_F0 : parseFormOld [97, 61, 37, 70, 48] = some [([97], [0xF0])] := by
  have h := parseFormWith_single urldecodeOld [97, 61, 37, 70, 48] (by decide) (by decide)
  unfold parseFormOld
  rw [h]
  have hp : parsePairWith urldecodeOld [97, 61, 37, 70, 48] = some ([97], [0xF0]) := by
    have e : breakEq [97, 61, 37, 70, 48] = ([97], some [37, 70, 48]) := by decide
    simp only [parsePairWith, e, Option.getD_some, urldecode_F0]
    have h97 : urldecodeOld [97] = some [97] := by
      show urldecodeBytes [97] = _
      rw [urldecodeBytes_other 97 [] (by decide) (by decide), bytes_nil]; rfl
    rw [h97]; rfl
  rw [hp]; rfl

/-- The shipped `urldecode` (validate after decoding,
`String(from_utf8=...)`) meets the spec. -/
theorem urldecodeFixed_meets_spec : DecodeSpec urldecode :=
  fun s out h => urldecode_valid s out h

/-- …it rejects `%F0`, so `a=%F0` is no longer accepted from a form body… -/
theorem urldecode_rejects_F0 : urldecode [37, 70, 48] = none := by
  unfold urldecode
  rw [show urldecodeBytes [37, 70, 48] = some [0xF0] from urldecode_F0]
  simp [F0_invalid]

theorem parseForm_rejects_F0 : parseForm [97, 61, 37, 70, 48] = none := by
  have h := parseFormWith_single urldecode [97, 61, 37, 70, 48] (by decide) (by decide)
  unfold parseForm
  rw [h]
  have e : breakEq [97, 61, 37, 70, 48] = ([97], some [37, 70, 48]) := by decide
  simp [parsePairWith, e, urldecode_rejects_F0]

/-- …and still round-trips every well-formed UTF-8 string. -/
theorem urldecodeFixed_roundtrip (s : Flare.Bytes) (h : Utf8Valid s = true) :
    urldecode (urlencode s) = some s := urldecode_urlencode s h

end Flare.Bugs.APP_24
