import Flare.L3_Protocol.Quic.TransportParams

/-!
# What each endpoint checks in the peer's transport parameters

Two consumers of `decode_transport_parameters` (`TransportParams.decode`):

* the client's `_check_peer_cids` (flare/quic/client.mojo, which calls
  `check_server_transport_params`; fixed, QUIC-12; it used to compare the decoded
  record only), run once the handshake has produced the server's parameter blob;
* the server, which (fixed, QUIC-11) reads and checks the client's blob once the
  1-RTT keys are installed (`_client_params_ok`, flare/quic/server.mojo; it used
  to be never read: `_dispatch_crypto_frames` drove the handshake to 1-RTT keys
  and no server path called `_do_peer_transport_params`).

flare's decoder stores each CID as `Bytes`, empty meaning absent, so a
check written over the decoded record cannot tell "absent" from "present
with length 0". The specs below are stated over the raw TLV list instead
(`present`), as RFC 9000 states them.

Spec, client side (RFC 9000 §7.3, §18.2): the blob decodes (`specDecode`);
original_destination_connection_id and initial_source_connection_id are
present and equal to the Destination CID of the client's first Initial and
to the server's Source CID; retry_source_connection_id is present exactly
when a Retry was followed, with the Retry's Source CID; a server that chose
a zero-length CID sends no preferred_address.

Spec, server side (RFC 9000 §7.3, §18.2): the blob decodes; none of the
server-only parameters (0x00, 0x02, 0x0d, 0x10) is present;
initial_source_connection_id is present and equal to the Source CID of the
client's Initial.

`clientCheck` is the client's check as shipped (QUIC-12 fixed: it scans the raw blob
for the presence of the ids, on top of the comparisons), run with the decoder
`Fixes.shipped` of `TransportParams`; `clientCheckOld` is the check before the fix.
`serverCheckWith` is the server's check, shipped with QUIC-11. `clientCheckFixed_spec`
and `serverCheck_spec` prove they are exactly the specs on every input with the fully
fixed decoder; for the shipped decoder, `clientCheckWith_agree` and
`serverCheckWith_agree` prove it wherever the decoder agrees with the spec decoder.
-/
namespace Flare.L3.Quic.PeerParams
open Flare Flare.L3.H3 Flare.L3.Quic.TransportParams

/-- id `i` occurs in the blob's TLV list -/
def present (i : Nat) (b : Bytes) : Bool :=
  match tlvs b with
  | some ps => (ids ps).contains i
  | none => false

/-- RFC 9000 §7.3 / §18.2, client receiving the server's parameters.
`dcid`: Destination CID of the first Initial; `scid`: the server's Source
CID; `retried`: a Retry was followed, `rscid` its Source CID. -/
def clientSpec (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes) : Bool :=
  match specDecode b with
  | none => false
  | some tp =>
    present 0x00 b && tp.odcid == dcid && present 0x0f b && tp.iscid == scid &&
      (present 0x10 b == retried) && (!retried || tp.rscid == rscid) &&
      (!present 0x0d b || !scid.isEmpty)

/-- `_check_peer_cids` before the fix (QUIC-12): decode (raising on a decode
error), then compare the stored CIDs. `self.retry_scid` is empty unless a Retry
was followed; the ISCID comparison is skipped while `server_scid` is empty.
mirrors flare/quic/client.mojo:641-669 @59bda50 -/
def clientCheckOld (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes) : Bool :=
  let retryScid := if retried then rscid else []
  match decode Fixes.none b with
  | .error _ => false
  | .ok tp => tp.odcid == dcid && (scid.isEmpty || tp.iscid == scid) && tp.rscid == retryScid

/-- The shipped check (QUIC-12): presence scans of 0x00 / 0x0f / 0x10 / 0x0d next
to the comparisons, with decoder fixes `fx`.
mirrors flare/quic/transport_params.mojo `check_server_transport_params` -/
def clientCheckWith (fx : Fixes) (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes) : Bool :=
  match decode fx b with
  | .error _ => false
  | .ok tp =>
    present 0x00 b && tp.odcid == dcid && present 0x0f b && tp.iscid == scid &&
      (present 0x10 b == retried) && (!retried || tp.rscid == rscid) &&
      (!present 0x0d b || !scid.isEmpty)

/-- The shipped client check (decoder fixes `Fixes.shipped`). -/
def clientCheck (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes) : Bool :=
  clientCheckWith Fixes.shipped b dcid scid retried rscid

/-- The client check with every decoder fix. -/
def clientCheckFixed (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes) : Bool :=
  clientCheckWith Fixes.all b dcid scid retried rscid

/-- server-only parameters (RFC 9000 §18.2) -/
def serverOnly : List Nat := [0x00, 0x02, 0x0d, 0x10]

/-- RFC 9000 §7.3 / §18.2, server receiving the client's parameters;
`cscid` is the Source CID of the client's Initial. -/
def serverSpec (b cscid : Bytes) : Bool :=
  match specDecode b with
  | none => false
  | some tp => serverOnly.all (fun i => !present i b) && present 0x0f b && tp.iscid == cscid

/-- The server's check of the client's blob, with decoder fixes `fx`: decode
(raising on an error), none of the server-only ids present, and
initial_source_connection_id present and equal to the Source CID of the
client's Initial. Run once the 1-RTT keys are installed (fixed, QUIC-11).
mirrors flare/quic/transport_params.mojo:531-608, flare/quic/server.mojo:1354,
1377-1396 (fixed, QUIC-11) -/
def serverCheckWith (fx : Fixes) (b cscid : Bytes) : Bool :=
  match decode fx b with
  | .error _ => false
  | .ok tp => serverOnly.all (fun i => !present i b) && present 0x0f b && tp.iscid == cscid

/-- The shipped check (decoder fixes `Fixes.shipped`). -/
def serverCheck (b cscid : Bytes) : Bool := serverCheckWith Fixes.shipped b cscid

theorem decodeFixed_some {b : Bytes} {tp : TP} (h : decode Fixes.all b = .ok tp) :
    specDecode b = some tp := by
  rw [← decodeFixed_eq_spec, h]; rfl

theorem decodeFixed_none {b : Bytes} {e : TPErr} (h : decode Fixes.all b = .error e) :
    specDecode b = none := by
  rw [← decodeFixed_eq_spec, h]; rfl

/-- **The client fix is the spec**, on every input. -/
theorem clientCheckFixed_spec (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes) :
    clientCheckFixed b dcid scid retried rscid = clientSpec b dcid scid retried rscid := by
  unfold clientCheckFixed clientCheckWith clientSpec
  cases h : decode Fixes.all b with
  | error e => rw [decodeFixed_none h]
  | ok tp => rw [decodeFixed_some h]

/-- **The shipped client check is the spec wherever the decoder is**: for any decoder
setting that agrees with the spec decoder on `b`, `clientCheckWith` equals `clientSpec`. -/
theorem clientCheckWith_agree (fx : Fixes) (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes)
    (h : (decode fx b).toOption = specDecode b) :
    clientCheckWith fx b dcid scid retried rscid = clientSpec b dcid scid retried rscid := by
  unfold clientCheckWith clientSpec
  cases hd : decode fx b with
  | error e => rw [hd] at h; simp only [Except.toOption] at h; rw [← h]
  | ok tp => rw [hd] at h; simp only [Except.toOption] at h; rw [← h]

/-- **The server check is the spec wherever the decoder is**: for any decoder
setting that agrees with the spec decoder on `b`, `serverCheckWith` equals
`serverSpec`. -/
theorem serverCheckWith_agree (fx : Fixes) (b cscid : Bytes)
    (h : (decode fx b).toOption = specDecode b) : serverCheckWith fx b cscid = serverSpec b cscid := by
  unfold serverCheckWith serverSpec
  cases hd : decode fx b with
  | error e => rw [hd] at h; simp only [Except.toOption] at h; rw [← h]
  | ok tp => rw [hd] at h; simp only [Except.toOption] at h; rw [← h]

/-- **The server check is the spec**, on every input, with the decoder fixes
of QUIC-10 and QUIC-13. -/
theorem serverCheck_spec (b cscid : Bytes) : serverCheckWith Fixes.all b cscid = serverSpec b cscid :=
  serverCheckWith_agree Fixes.all b cscid (decodeFixed_eq_spec b)

/-- **What the shipped check guarantees**, for any decoder setting: a blob it
accepts decodes, carries none of the server-only parameters, and names the
client's Source CID as initial_source_connection_id. -/
theorem serverCheck_sound (fx : Fixes) (b cscid : Bytes) (h : serverCheckWith fx b cscid = true) :
    (∃ tp, decode fx b = .ok tp ∧ tp.iscid = cscid) ∧
      serverOnly.all (fun i => !present i b) = true ∧ present 0x0f b = true := by
  unfold serverCheckWith at h
  cases hd : decode fx b with
  | error e => rw [hd] at h; cases h
  | ok tp =>
    rw [hd] at h
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    exact ⟨⟨tp, rfl, h.2⟩, h.1.1, h.1.2⟩

end Flare.L3.Quic.PeerParams
