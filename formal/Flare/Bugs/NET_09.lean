import Flare.L2_Machine.Hostname

/-!
# NET-09: the "hostname too long" error cuts a UTF-8 character in half

flare/dns/resolver.mojo:82-87 @59bda50.

Spec: a Mojo `String` holds well-formed UTF-8; the error text built from a
well-formed host must be well-formed (`Flare.L1.Utf8.WF`).

What goes wrong: the message quotes `String(unsafe_from_utf8=host_bytes[:20])`.
Byte 20 can fall inside a multi-byte character; the unchecked constructor
then builds a `String` holding a truncated sequence (here `C3` followed by
the `E2 80 A6` of "…").

Repro: formal/repro/NET-09_hostname_error_splits_utf8.mojo.
-/
namespace Flare.Bugs.NET_09
open Flare.L2.Hostname
open Flare.L1.Utf8 (WF isValidUtf8 isValidUtf8_iff)

/-- 19 × `a`, `é` (C3 A9), 240 × `a`: 261 bytes, valid UTF-8 -/
def host : Flare.Bytes := List.replicate 19 0x61 ++ [0xC3, 0xA9] ++ List.replicate 240 0x61

/-- **Counterexample**: the host is well-formed and too long, and the message
tail flare builds is not well-formed. -/
theorem message_not_utf8 :
    isValidUtf8 host = true ∧ validate host = .tooLong ∧ isValidUtf8 (tooLongTail host) = false := by
  native_decide

theorem message_not_wf : WF host ∧ ¬ WF (tooLongTail host) := by
  have h := message_not_utf8
  refine ⟨(isValidUtf8_iff _).1 h.1, fun hw => ?_⟩
  have := (isValidUtf8_iff _).2 hw
  rw [h.2.2] at this; cases this

/-- **Fix meets spec**: cutting at a character boundary keeps the message
well-formed for every well-formed host, and quotes at most 20 bytes. -/
theorem fixed_wf (h : Flare.Bytes) (hw : WF h) :
    WF (tooLongTailFixed h) ∧ (truncChars 20 h).length ≤ 20 :=
  tooLongTailFixed_wf h hw

end Flare.Bugs.NET_09
