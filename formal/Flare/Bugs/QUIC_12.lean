import Flare.L3_Protocol.Quic.PeerParams

/-!
# QUIC-12: the client's CID authentication confuses absent with empty

flare/quic/client.mojo:641-669 @59bda50 (`_check_peer_cids`) compares the
CIDs of the decoded record, where an absent parameter and a zero-length one
are both the empty list, and `decode_transport_parameters` skips 0x0d.

Spec clauses: RFC 9000 §7.3, "An endpoint MUST treat the absence of the
initial_source_connection_id transport parameter from either endpoint ...
as a connection error of type TRANSPORT_PARAMETER_ERROR", and "An endpoint
MUST treat ... presence of the retry_source_connection_id transport
parameter when no Retry packet was received ... as a connection error";
§18.2, "A server that chooses a zero-length connection ID MUST NOT provide
a preferred address. ... a client MUST treat a violation as a connection
error of type TRANSPORT_PARAMETER_ERROR."

Counterexamples (the repro's cases A, B, C):
* A: zero-length server SCID, no initial_source_connection_id;
* B: no Retry, retry_source_connection_id present with length 0;
* C: zero-length server SCID, preferred_address present.

Repro: formal/repro/QUIC-12_client_cid_auth_absent_vs_empty.mojo.
-/
namespace Flare.Bugs.QUIC_12
open Flare Flare.L3.Quic.PeerParams

def dcid : Bytes := [1, 2, 3, 4, 5, 6, 7, 8]
def scid : Bytes := [9, 9, 9, 9]
def odcidTlv : Bytes := [0x00, 0x08] ++ dcid

def blobA : Bytes := odcidTlv
def blobB : Bytes := odcidTlv ++ [0x0f, 0x04] ++ scid ++ [0x10, 0x00]
/-- a well-formed 42-byte preferred_address with a 1-byte CID -/
def blobC : Bytes :=
  odcidTlv ++ [0x0f, 0x00] ++ [0x0d, 42] ++ List.replicate 24 0 ++ [1, 7] ++ List.replicate 16 0

theorem impl_accepts_absent_iscid :
    clientCheck blobA dcid [] false [] = true ∧ clientSpec blobA dcid [] false [] = false := by
  native_decide

theorem impl_accepts_empty_rscid :
    clientCheck blobB dcid scid false [] = true ∧ clientSpec blobB dcid scid false [] = false := by
  native_decide

theorem impl_accepts_pa_with_empty_cid :
    clientCheck blobC dcid [] false [] = true ∧ clientSpec blobC dcid [] false [] = false := by
  native_decide

/-- control: a correct blob passes both -/
theorem control_ok :
    clientCheck (odcidTlv ++ [0x0f, 0x04] ++ scid) dcid scid false [] = true ∧
      clientSpec (odcidTlv ++ [0x0f, 0x04] ++ scid) dcid scid false [] = true := by
  native_decide

/-- **Fix meets spec**: presence scans next to the existing comparisons
accept exactly what RFC 9000 allows, on every input. -/
theorem checkFixed_spec (b d s : Bytes) (retried : Bool) (r : Bytes) :
    clientCheckFixed b d s retried r = clientSpec b d s retried r :=
  clientCheckFixed_spec b d s retried r

end Flare.Bugs.QUIC_12
