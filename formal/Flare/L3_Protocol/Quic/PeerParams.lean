import Flare.L3_Protocol.Quic.TransportParams

/-!
# What each endpoint checks in the peer's transport parameters

Two consumers of `decode_transport_parameters` (`TransportParams.decode`):

* the client's `_check_peer_cids` (flare/quic/client.mojo:641-669 @59bda50),
  run once the handshake has produced the server's parameter blob;
* the server, which never reads the client's blob: `_dispatch_crypto_frames`
  (flare/quic/server.mojo:1199-1368) drives the handshake to 1-RTT keys and
  no server path calls `_do_peer_transport_params`.

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

`clientCheckFixed` and `serverCheck` are the minimal fixes (scan the raw
blob for the presence of the ids, on top of the existing comparisons), run
with the fixed decoder of `TransportParams` (QUIC-10 and QUIC-13 fixed).
`clientCheckFixed_spec` and `serverCheck_spec` prove they are exactly the
specs on every input.
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

/-- `_check_peer_cids`: decode (raising on a decode error), then compare
the stored CIDs. `self.retry_scid` is empty unless a Retry was followed;
the ISCID comparison is skipped while `server_scid` is empty.
mirrors flare/quic/client.mojo:641-669 @59bda50 -/
def clientCheck (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes) : Bool :=
  let retryScid := if retried then rscid else []
  match decode Fixes.none b with
  | .error _ => false
  | .ok tp => tp.odcid == dcid && (scid.isEmpty || tp.iscid == scid) && tp.rscid == retryScid

/-- The fix: presence scans of 0x00 / 0x0f / 0x10 / 0x0d next to the
existing comparisons, with the fixed decoder. -/
def clientCheckFixed (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes) : Bool :=
  match decode Fixes.all b with
  | .error _ => false
  | .ok tp =>
    present 0x00 b && tp.odcid == dcid && present 0x0f b && tp.iscid == scid &&
      (present 0x10 b == retried) && (!retried || tp.rscid == rscid) &&
      (!present 0x0d b || !scid.isEmpty)

/-- server-only parameters (RFC 9000 §18.2) -/
def serverOnly : List Nat := [0x00, 0x02, 0x0d, 0x10]

/-- RFC 9000 §7.3 / §18.2, server receiving the client's parameters;
`cscid` is the Source CID of the client's Initial. -/
def serverSpec (b cscid : Bytes) : Bool :=
  match specDecode b with
  | none => false
  | some tp => serverOnly.all (fun i => !present i b) && present 0x0f b && tp.iscid == cscid

/-- flare's server: the client's parameters are never read, so every blob
is accepted. mirrors flare/quic/server.mojo:1199-1368 @59bda50 -/
def serverImpl (_b _cscid : Bytes) : Bool := true

/-- The fix: decode once the 1-RTT keys are installed and check. -/
def serverCheck (b cscid : Bytes) : Bool :=
  match decode Fixes.all b with
  | .error _ => false
  | .ok tp => serverOnly.all (fun i => !present i b) && present 0x0f b && tp.iscid == cscid

theorem decodeFixed_some {b : Bytes} {tp : TP} (h : decode Fixes.all b = .ok tp) :
    specDecode b = some tp := by
  rw [← decodeFixed_eq_spec, h]; rfl

theorem decodeFixed_none {b : Bytes} {e : TPErr} (h : decode Fixes.all b = .error e) :
    specDecode b = none := by
  rw [← decodeFixed_eq_spec, h]; rfl

/-- **The client fix is the spec**, on every input. -/
theorem clientCheckFixed_spec (b dcid scid : Bytes) (retried : Bool) (rscid : Bytes) :
    clientCheckFixed b dcid scid retried rscid = clientSpec b dcid scid retried rscid := by
  unfold clientCheckFixed clientSpec
  cases h : decode Fixes.all b with
  | error e => rw [decodeFixed_none h]
  | ok tp => rw [decodeFixed_some h]

/-- **The server fix is the spec**, on every input. -/
theorem serverCheck_spec (b cscid : Bytes) : serverCheck b cscid = serverSpec b cscid := by
  unfold serverCheck serverSpec
  cases h : decode Fixes.all b with
  | error e => rw [decodeFixed_none h]
  | ok tp => rw [decodeFixed_some h]

end Flare.L3.Quic.PeerParams
