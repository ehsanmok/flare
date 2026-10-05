import Flare.L3_Protocol.H3.Control

/-!
# H3-03: frames forbidden on the control stream are silently ignored

flare/http3/server.mojo:1170-1211 @59bda50 (`_dispatch_control_frame`):
after the SETTINGS-first check only SETTINGS and GOAWAY were acted on; every
other type returned without error, including DATA, HEADERS, PUSH_PROMISE and
the HTTP/2-reserved types.

Spec clause: RFC 9114 §7.2.1 (DATA), §7.2.2 (HEADERS), §7.2.5
(PUSH_PROMISE): receipt on a control stream MUST be treated as a connection
error of type H3_FRAME_UNEXPECTED; §7.2.8 / §11.2.1: the same for
0x02/0x06/0x08/0x09.

Counterexample: control stream `00 | 04 03 06 60 00` (stream type, SETTINGS
{MAX_FIELD_SECTION_SIZE: 8192}) followed by the empty frame `t 00` for any
`t` in {0x00, 0x01, 0x05, 0x02, 0x06, 0x08, 0x09} was accepted
(`implOld_*` / `trace_implOld`, which use `Fixes.none`).

Status: resolved. `_dispatch_control_frame` raises H3_FRAME_UNEXPECTED for
those types after the SETTINGS-first check; CANCEL_PUSH, MAX_PUSH_ID and
unknown types stay accepted. `Fixes.shipped` models flare with this fix
(`impl_rejects_forbidden`, `trace_shipped`); `dispatchFixed_spec` shows
the fix equals the RFC dispatch. Regression tests:
tests/h3/test_h3_uni_streams.mojo
`test_forbidden_frame_types_on_the_control_stream_are_refused` and
`test_allowed_control_frames_are_still_accepted`.
-/
namespace Flare.Bugs.H3_03
open Flare.L3.H3 Flare.L3.H3.Control

def forbidden : List Nat := [0x00, 0x01, 0x05, 0x02, 0x06, 0x08, 0x09]

/-- Stream type 0x00, then SETTINGS with MAX_FIELD_SECTION_SIZE = 8192. -/
def ctrlPrefix : Bytes := [0x00, 0x04, 0x03, 0x06, 0x60, 0x00]

/-- **Counterexample** (step level): once SETTINGS has arrived, flare
accepts every forbidden type and leaves the state unchanged. -/
theorem implOld_accepts_data_on_control (s : CtlState) (hs : s.settingsReceived = true) (t : Nat)
    (ht : t ∈ forbidden) (p : Bytes) : dispatchControl Fixes.none s t p = .ok s := by
  simp only [forbidden, List.mem_cons, List.not_mem_nil, or_false] at ht
  rcases ht with rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [dispatchControl, hs, Fixes.none]

theorem spec_rejects (s : CtlState) (hs : s.settingsReceived = true) (t : Nat)
    (ht : t ∈ forbidden) (p : Bytes) : specControl s t p = .error .frameUnexpected := by
  simp only [forbidden, List.mem_cons, List.not_mem_nil, or_false] at ht
  rcases ht with rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp [specControl, ctlClass, hs]

/-- Trace level, mirroring the repro: both `feed_uni_stream_chunk` calls
succeed for every forbidden type. -/
theorem trace_implOld :
    ∀ t ∈ forbidden, errOf (feedUnis Fixes.none {} [(2, ctrlPrefix), (2, [UInt8.ofNat t, 0])])
      = none := by native_decide

/-- Shipped: the second chunk raises H3_FRAME_UNEXPECTED. -/
theorem trace_shipped :
    ∀ t ∈ forbidden, errOf (feedUnis Fixes.shipped {} [(2, ctrlPrefix), (2, [UInt8.ofNat t, 0])])
      = some .frameUnexpected := by native_decide

/-- Shipped (step level): once SETTINGS has arrived, every forbidden type is
H3_FRAME_UNEXPECTED. -/
theorem impl_rejects_forbidden (s : CtlState) (hs : s.settingsReceived = true) (t : Nat)
    (ht : t ∈ forbidden) (p : Bytes) :
    dispatchControl Fixes.shipped s t p = .error .frameUnexpected := by
  simp only [forbidden, List.mem_cons, List.not_mem_nil, or_false] at ht
  rcases ht with rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [dispatchControl, hs, Fixes.shipped, isForbiddenOnControl, isH2Reserved]

/-- **The fix meets the spec** on every state, type and payload. -/
theorem dispatchFixed_spec (s : CtlState) (t : Nat) (p : Bytes) :
    dispatchControl Fixes.all s t p = specControl s t p :=
  dispatchControlFixed_eq_spec s t p

end Flare.Bugs.H3_03
