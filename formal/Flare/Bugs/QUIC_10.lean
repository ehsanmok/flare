import Flare.L3_Protocol.Quic.TransportParams

/-!
# QUIC-10: initial_max_streams_* above 2^60 accepted in transport parameters

Status: resolved. `decode_transport_parameters` raises when initial_max_streams_bidi
or _uni exceeds 2^60 (flare/quic/transport_params.mojo, `_MAX_STREAMS_LIMIT`).
The counterexample below is about the decoder before the fix (`Fixes.none`);
`Fixes.shipped` has the check.

Pre-fix behaviour: flare/quic/transport_params.mojo:482-489 @59bda50: the 0x08 and 0x09
branches of `decode_transport_parameters` store the varint with no bound.

Spec clause: RFC 9000 §18.2, initial_max_streams_bidi / _uni: "If this
parameter is absent or zero ... a value greater than 2^60 ... MUST be
treated as a connection error of type TRANSPORT_PARAMETER_ERROR" (and §4.6
for the same bound on MAX_STREAMS, which is QUIC-02).

Counterexample: `08 08 d0 00 00 00 00 00 00 01` (initial_max_streams_bidi =
2^60 + 1) decodes.

Repro: formal/repro/QUIC-10_tp_max_streams_over_2p60_accepted.mojo.
-/
namespace Flare.Bugs.QUIC_10
open Flare Flare.L3.Quic.TransportParams

def blob : Bytes := [0x08, 0x08, 0xD0, 0, 0, 0, 0, 0, 0, 0x01]

/-- **Counterexample**: flare decodes the blob (to a record holding the
2^60 + 1 limit) while the spec rejects it. -/
theorem impl_accepts :
    (decode Fixes.none blob).toOption = some { streamsBidi := some (2 ^ 60 + 1) } ∧
      specDecode blob = none := by
  native_decide

/-- **The shipped decoder rejects the blob.** -/
theorem shipped_rejects : (decode Fixes.shipped blob).toOption = none := by
  native_decide

/-- **Fix meets spec**: with the bound check (and the QUIC-13 check) the
decoder succeeds exactly when the spec does, with the same result. -/
theorem decodeFixed_spec (b : Bytes) : (decode Fixes.all b).toOption = specDecode b :=
  decodeFixed_eq_spec b

end Flare.Bugs.QUIC_10
