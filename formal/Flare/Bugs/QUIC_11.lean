import Flare.L3_Protocol.Quic.PeerParams

/-!
# QUIC-11: the server never validates the client's transport parameters

flare/quic/server.mojo:1199-1368 @59bda50 (`_dispatch_crypto_frames`): the
handshake reaches 1-RTT keys and the connection becomes usable without the
client's `quic_transport_parameters` ever being read.

Spec clause: RFC 9000 §18.2, a server "MUST treat receipt of" a server-only
parameter (original_destination_connection_id, stateless_reset_token,
preferred_address, retry_source_connection_id) "as a connection error of
type TRANSPORT_PARAMETER_ERROR"; §7.3, an absent
initial_source_connection_id, or one that differs from the Source CID of
the client's Initial, is a connection error; §7.4 / §18, duplicates and
invalid values are TRANSPORT_PARAMETER_ERROR.

Counterexamples: an empty blob (no initial_source_connection_id), and a
blob carrying the server-only original_destination_connection_id.

Repro: formal/repro/QUIC-11_server_ignores_client_transport_params.mojo.
-/
namespace Flare.Bugs.QUIC_11
open Flare Flare.L3.Quic.PeerParams

def cscid : Bytes := [1, 2, 3, 4, 5, 6, 7, 8]

/-- no parameters at all -/
def noIscid : Bytes := []

/-- original_destination_connection_id (server-only) plus a correct ISCID -/
def withOdcid : Bytes := [0x00, 0x08] ++ cscid ++ [0x0f, 0x08] ++ cscid

/-- **Counterexample**: flare accepts both, the spec rejects both. -/
theorem impl_accepts :
    serverImpl noIscid cscid = true ∧ serverSpec noIscid cscid = false ∧
      serverImpl withOdcid cscid = true ∧ serverSpec withOdcid cscid = false := by
  native_decide

/-- **Fix meets spec**: decoding and checking the client's blob after the
handshake accepts exactly what RFC 9000 allows. -/
theorem serverCheck_spec (b c : Bytes) : serverCheck b c = serverSpec b c :=
  Flare.L3.Quic.PeerParams.serverCheck_spec b c

end Flare.Bugs.QUIC_11
