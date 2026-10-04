import Flare.L3_Protocol.H3.Control

/-!
# H3-06: bytes after the GOAWAY stream id are accepted

flare/http3/server.mojo:1197-1211 @59bda50 (`_dispatch_control_frame`,
GOAWAY branch): the payload is checked for emptiness, one varint is decoded
with `decode_varint(payload)` and its value is recorded; `goaway_id.consumed`
is never compared with `len(payload)`.

Spec clause: RFC 9114 §7.2.6 defines the GOAWAY payload as a single
variable-length integer, and §7.1: "if a frame payload contains additional
bytes after the identified fields ... an endpoint MUST treat this as a
connection error of type H3_FRAME_ERROR."

Counterexample: control stream `00 | 04 03 06 60 00` (stream type, SETTINGS)
followed by `07 02 00 ff` (GOAWAY, length 2, id 0, one extra byte 0xff) is
accepted and records GOAWAY id 0.
-/
namespace Flare.Bugs.H3_06
open Flare.L3.H3 Flare.L3.H3.Control

def ctrlPrefix : Bytes := [0x00, 0x04, 0x03, 0x06, 0x60, 0x00]

theorem dec_small (id : Nat) (hid : id < 64) (tl : Bytes) :
    decVarint (UInt8.ofNat id :: tl) = some (id, 1) := by
  have h1 : (UInt8.ofNat id).toNat = id := by simp; omega
  simp only [decVarint, h1, Nat.div_eq_of_lt hid, varLen, ↓reduceIte, List.length_cons]
  rw [if_neg (by omega)]
  simp [vval, h1, Nat.mod_eq_of_lt hid, Bytes.beNat]

/-- **Counterexample** (step level): after SETTINGS, any one-byte varint
followed by any non-empty tail is accepted. -/
theorem impl_accepts_trailing (s : CtlState) (hs : s.settingsReceived = true)
    (hm : s.goawayMax = none) (id : Nat) (hid : id < 64) (tl : Bytes) (htl : tl ≠ []) :
    dispatchControl Fixes.none s 0x07 (UInt8.ofNat id :: tl) =
      .ok { s with goawayMax := some id } := by
  have hv := dec_small id hid tl
  simp [dispatchControl, hs, goaway, hv, Fixes.none, goawayId, hm]

/-- The spec rejects the same payload with H3_FRAME_ERROR. -/
theorem spec_rejects_trailing (s : CtlState) (hs : s.settingsReceived = true)
    (id : Nat) (hid : id < 64) (tl : Bytes) (htl : tl ≠ []) :
    specControl s 0x07 (UInt8.ofNat id :: tl) = .error .frameError := by
  have hv := dec_small id hid tl
  simp [specControl, ctlClass, hs, specGoaway, hv]
  exact fun h => absurd h htl

/-- Trace level, mirroring the repro. -/
theorem trace_impl :
    errOf (feedUnis Fixes.none {} [(2, ctrlPrefix), (2, [0x07, 0x02, 0x00, 0xff])]) = none := by
  native_decide

theorem trace_fixed :
    errOf (feedUnis Fixes.all {} [(2, ctrlPrefix), (2, [0x07, 0x02, 0x00, 0xff])]) =
      some .frameError := by
  native_decide

/-- **The fix meets the spec** on every state and payload. -/
theorem goawayFixed_spec (s : CtlState) (p : Bytes) :
    goaway Fixes.all s p = specGoaway s p :=
  goawayFixed_eq_spec s p

theorem dispatchFixed_spec (s : CtlState) (t : Nat) (p : Bytes) :
    dispatchControl Fixes.all s t p = specControl s t p :=
  dispatchControlFixed_eq_spec s t p

end Flare.Bugs.H3_06
