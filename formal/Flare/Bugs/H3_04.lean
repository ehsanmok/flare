import Flare.L3_Protocol.H3.Control

/-!
# H3-04: HTTP/2-reserved SETTINGS identifiers are accepted

flare/http3/server.mojo:1213-1228 @59bda50 (`_apply_peer_settings`) applied
the four known HTTP/3 identifiers and ignored every other one; it never
raised.

Spec clause: RFC 9114 §7.2.4.1 / §11.2.2: the identifiers 0x02, 0x03, 0x04,
0x05 (HTTP/2 ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE,
MAX_FRAME_SIZE) are reserved; "their receipt MUST be treated as a
connection error of type H3_SETTINGS_ERROR".

Counterexample: the control stream `00 | 04 02 id 01` (SETTINGS {id: 1})
with `id` in {2, 3, 4, 5} was accepted and marked the peer SETTINGS received
(`implOld_*` / `trace_implOld`, which use `Fixes.none`).

Status: resolved. `_apply_peer_settings` raises H3_SETTINGS_ERROR for
identifiers 0x02..0x05 before applying any value. `Fixes.shipped` models
flare with this fix (`impl_rejects_reserved_setting`, `trace_shipped`);
`applyFixed_spec` shows the fix equals RFC 9114 §7.2.4.1. Regression tests:
tests/h3/test_h3_uni_streams.mojo
`test_http2_reserved_setting_identifiers_are_refused` and
`test_unknown_and_known_setting_identifiers_are_still_accepted`.
-/
namespace Flare.Bugs.H3_04
open Flare.L3.H3 Flare.L3.H3.Control

def reserved : List Nat := [0x02, 0x03, 0x04, 0x05]

/-- **Counterexample** (step level). -/
theorem implOld_accepts_reserved_setting :
    ∀ id ∈ reserved, (dispatchControl Fixes.none {} 0x04 [UInt8.ofNat id, 0x01]).toOption =
      some { settingsReceived := true } := by native_decide

theorem spec_rejects :
    ∀ id ∈ reserved, errOf (specControl {} 0x04 [UInt8.ofNat id, 0x01]) = some .settingsError := by
  native_decide

/-- Trace level, mirroring the repro. -/
theorem trace_implOld :
    ∀ id ∈ reserved,
      ((feedUnis Fixes.none {} [(2, [0x00, 0x04, 0x02, UInt8.ofNat id, 0x01])]).toOption.map
        (·.ctl.settingsReceived)) = some true := by native_decide

/-- Shipped: the reserved identifier raises H3_SETTINGS_ERROR, step level and
trace level. -/
theorem impl_rejects_reserved_setting :
    ∀ id ∈ reserved, errOf (dispatchControl Fixes.shipped {} 0x04 [UInt8.ofNat id, 0x01])
      = some .settingsError := by native_decide

theorem trace_shipped :
    ∀ id ∈ reserved,
      errOf (feedUnis Fixes.shipped {} [(2, [0x00, 0x04, 0x02, UInt8.ofNat id, 0x01])])
        = some .settingsError := by native_decide

/-- **The fix meets the spec** (settings list and whole control frame). -/
theorem applyFixed_spec (ps : PeerSettings) (ss : List (Nat × Nat)) :
    applySettings Fixes.all ps ss = specApplySettings ps ss :=
  applySettingsFixed_eq_spec ps ss

theorem dispatchFixed_spec (s : CtlState) (t : Nat) (p : Bytes) :
    dispatchControl Fixes.all s t p = specControl s t p :=
  dispatchControlFixed_eq_spec s t p

end Flare.Bugs.H3_04
