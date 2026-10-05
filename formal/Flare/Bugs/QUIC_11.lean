import Flare.L3_Protocol.Quic.PeerParams

/-!
# QUIC-11: the server never validates the client's transport parameters

Status: resolved. After the 1-RTT keys are installed the server decodes the
client's `quic_transport_parameters` and closes the connection with
TRANSPORT_PARAMETER_ERROR for a server-only parameter, an absent or wrong
initial_source_connection_id, or a blob that does not decode
(flare/quic/transport_params.mojo `check_client_transport_params`, called from
flare/quic/server.mojo `_client_params_ok`). The counterexample below is about the
pre-fix server, `serverOld`, which read nothing; `serverCheck` is the shipped check.

Pre-fix behaviour (flare/quic/server.mojo:1199-1368 @59bda50,
`_dispatch_crypto_frames`): the handshake reached 1-RTT keys and the connection
became usable without the client's `quic_transport_parameters` ever being read.

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
open Flare Flare.L3.Quic.PeerParams Flare.L3.Quic.TransportParams

def cscid : Bytes := [1, 2, 3, 4, 5, 6, 7, 8]

/-- no parameters at all -/
def noIscid : Bytes := []

/-- original_destination_connection_id (server-only) plus a correct ISCID -/
def withOdcid : Bytes := [0x00, 0x08] ++ cscid ++ [0x0f, 0x08] ++ cscid

/-- The pre-fix server: the client's parameters are never read, so every blob
is accepted. -/
def serverOld (_b _cscid : Bytes) : Bool := true

/-- **Counterexample (pre-fix)**: the old server accepted both, the spec rejects both. -/
theorem impl_accepts :
    serverOld noIscid cscid = true ∧ serverSpec noIscid cscid = false ∧
      serverOld withOdcid cscid = true ∧ serverSpec withOdcid cscid = false := by
  native_decide

/-- **The shipped check rejects both** counterexamples. -/
theorem fixed_rejects :
    serverCheck noIscid cscid = false ∧ serverCheck withOdcid cscid = false := by
  native_decide

/-- **Fix meets spec**: wherever the shipped decoder agrees with the spec decoder
(every blob except the QUIC-10 / QUIC-13 cases), the shipped check accepts exactly what
RFC 9000 allows; with the decoder fixes of those findings it is every blob. -/
theorem fixed_meets_spec (b c : Bytes) (h : (decode Fixes.shipped b).toOption = specDecode b) :
    serverCheck b c = serverSpec b c :=
  serverCheckWith_agree Fixes.shipped b c h

/-- Whatever the decoder, an accepted blob has the ISCID and no server-only id. -/
theorem fixed_sound (b c : Bytes) (h : serverCheck b c = true) :
    (∃ tp, decode Fixes.shipped b = .ok tp ∧ tp.iscid = c) ∧
      serverOnly.all (fun i => !present i b) = true ∧ present 0x0f b = true :=
  serverCheck_sound Fixes.shipped b c h

theorem serverCheck_spec (b c : Bytes) : serverCheckWith Fixes.all b c = serverSpec b c :=
  Flare.L3.Quic.PeerParams.serverCheck_spec b c

end Flare.Bugs.QUIC_11
