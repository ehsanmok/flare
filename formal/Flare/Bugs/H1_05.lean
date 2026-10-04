import Flare.L3_Protocol.H1.FieldValue

/-!
# H1-05: obs-text header values become non-UTF-8 `String`s

* flare file: `flare/http/_server/parse.mojo:268-285` (value accepted byte by
  byte) and `flare/http/_server/parse_util.mojo:65-89` (`_ascii_strip_slice`
  → `_ascii_unchecked_string`) @59bda50.
* Spec clause: the `_ascii_unchecked_string` contract
  (`flare/http/proto/ascii.mojo:63-70`: every byte `< 0x80`) and the Mojo
  `String` invariant (valid UTF-8). RFC 9110 §5.5 allows obs-text, but only
  as opaque octets.
* What goes wrong: with `accept_obs_text_in_field_value`, the value `[0xFF]`
  passes the byte check and is stored as a `String` holding `0xFF`.
* Fix (`valueOkFixed`): reject values that are not valid UTF-8
  (`fixed_value_utf8`). Strict mode is already safe (`strict_value_utf8`).
-/
namespace Flare.Bugs.H1_05
open Flare Flare.L3.H1.FieldValue

theorem lenient_accepts : valueOk true [0xFF] = true := by native_decide

theorem not_utf8 : Flare.L1.Utf8.isValidUtf8 [0xFF] = false := by native_decide

theorem counterexample : ¬ Utf8Safe (valueOk true) := by
  intro h
  have := (Flare.L1.Utf8.isValidUtf8_iff _).mpr (h _ lenient_accepts)
  rw [not_utf8] at this
  cases this

theorem fixed_utf8 : Utf8Safe (valueOkFixed true) := fixed_value_utf8 true

theorem fixed_rejects : valueOkFixed true [0xFF] = false := by native_decide

end Flare.Bugs.H1_05
