import Flare.L3_Protocol.Quic.Streams

/-!
# QUIC-16: the server does not enforce its unidirectional stream limit

Status: resolved. `_route_http3_stream_chunks` (flare/quic/server.mojo) now closes
with STREAM_LIMIT_ERROR when a client unidirectional stream is above
`Connection.adv_max_streams_uni`. The counterexample below is about the server
before the fix (`ServerFixes ⟨false, false⟩`); `ServerFixes.shipped` has the check.

Pre-fix behaviour: flare/quic/server.mojo:1407-1430 @59bda50 (`_route_http3_stream_chunks`)
checks the stream count against `fc_adv_max_bidi` only for bidirectional
streams; a client unidirectional stream of any number is accepted, although
the server advertised `initial_max_streams_uni` (3 by default,
flare/quic/_server_types.mojo:162, sent at :701) and never raises it.

Spec clause: RFC 9000 §4.6: "An endpoint that receives a frame with a stream
ID exceeding the limit it has sent MUST treat this as a connection error of
type STREAM_LIMIT_ERROR."

Counterexample: STREAM on stream 14, the fourth client unidirectional
stream, with a limit of 3.

Repro: formal/repro/QUIC-16_server_uni_stream_limit_not_enforced.mojo.
-/
namespace Flare.Bugs.QUIC_16
open Flare.L3.Quic.Streams

def ctx : Ctx := ⟨fun _ => false, 100, 3⟩

/-- **Counterexample** -/
theorem impl_accepts :
    server ⟨false, false⟩ ctx .stream 14 = none ∧ spec .server ctx .stream 14 = some .limit := by
  native_decide

/-- **The shipped server rejects stream 14.** -/
theorem shipped_rejects : server ServerFixes.shipped ctx .stream 14 = some .limit := by
  native_decide

/-- **Fix meets spec**: with the unidirectional limit added, the server's
STREAM verdict is the spec's for every stream id. -/
theorem fixed_spec (c : Ctx) (hc : ServerOpensNone c) (sid : Nat) :
    server ⟨false, true⟩ c .stream sid = spec .server c .stream sid := by
  rw [← serverFixed_eq_spec c hc .stream sid]; rfl

end Flare.Bugs.QUIC_16
