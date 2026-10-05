import Flare.L3_Protocol.Quic.TransportParams

/-!
# QUIC-13: preferred_address is not validated

Status: resolved. `decode_transport_parameters` now has a 0x0d branch that checks
the layout and raises on a violation (flare/quic/transport_params.mojo); the value is
still not stored. The counterexample below is about the decoder before the fix
(`Fixes.none`); `Fixes.shipped` has both checks.

Pre-fix behaviour: flare/quic/transport_params.mojo:447-524 @59bda50: `decode_transport_parameters`
has no 0x0d branch, so a preferred_address of any length and layout is
skipped as if unknown. The module docstring (:42-45) says so: "not currently
handled and is skipped on decode like any other unknown id"; RFC 9000 still
requires the value to be checked.

Spec clause: RFC 9000 §18.2 gives preferred_address a fixed layout (IPv4
address and port, IPv6 address and port, a connection-ID length byte, the
CID, a 16-byte stateless reset token) and requires the CID to be 1..20
bytes; §7.4: "An endpoint MUST treat receipt of a transport parameter with
an invalid value as a connection error of type TRANSPORT_PARAMETER_ERROR."

Counterexamples: a zero-length preferred_address (`0d 00`), and a
41-byte one whose CID length byte is 0.

Repro: formal/repro/QUIC-13_preferred_address_not_validated.mojo.
-/
namespace Flare.Bugs.QUIC_13
open Flare Flare.L3.Quic.TransportParams

def emptyPA : Bytes := [0x0d, 0x00]

/-- 24 address bytes, CID length 0, 16 token bytes -/
def zeroCidPA : Bytes := [0x0d, 41] ++ List.replicate 41 0

/-- **Counterexample**: flare accepts both blobs, the spec rejects both. -/
theorem impl_accepts :
    (decode Fixes.none emptyPA).toOption = some {} ∧ specDecode emptyPA = none ∧
      (decode Fixes.none zeroCidPA).toOption = some {} ∧ specDecode zeroCidPA = none := by
  native_decide

/-- **The shipped decoder rejects both blobs.** -/
theorem shipped_rejects :
    (decode Fixes.shipped emptyPA).toOption = none ∧
      (decode Fixes.shipped zeroCidPA).toOption = none := by
  native_decide

/-- **Fix meets spec**: with the layout check (and the QUIC-10 check) the
decoder succeeds exactly when the spec does, with the same result. -/
theorem decodeFixed_spec (b : Bytes) : (decode Fixes.all b).toOption = specDecode b :=
  decodeFixed_eq_spec b

end Flare.Bugs.QUIC_13
