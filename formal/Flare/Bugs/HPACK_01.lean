import Flare.Bugs.HPACK_Fixtures
import Flare.L3_Protocol.H2.ConnHpack
import Flare.L3_Protocol.H2.HpackCodec

/-!
# HPACK-01: lossy UTF-8 conversion desynchronises the dynamic table

`_octets_to_string` (flare/http2/hpack.mojo:49-63 @59bda50) stores a
field whose octets contain a byte `≥ 0x80` through `utf8_lossy_string`,
which replaces every ill-formed byte with U+FFFD (3 octets). The stored
entry is larger than the one the peer's encoder indexed, so flare evicts
entries the peer still has (hpack.mojo:290-316) and a later index the
peer legitimately sends is out of range: a legal header block draws
COMPRESSION_ERROR.

RFC 7541 §2.3.2 / §4.1: the dynamic table, and the size of each entry
(name length + value length + 32, on the *octets*), must evolve
identically at encoder and decoder; §2.3.3: index 63 is the second
dynamic entry.

Witness (the repro's): the peer inserts `x-1: a×500` (535 octets), then
`x-2` with 1300 bytes `0xFF` (1335 octets); its table holds 1870 of 4096
octets. flare stores the second value as 3900 octets, so the 3935-octet
entry forces out `x-1`, and index 63 no longer resolves.
`HpackSync.prefix_inv` proves the opposite failure (a *wrong* header) is
impossible.
-/
namespace Flare.Bugs.HPACK_01
open Flare Flare.L3.H2.Hpack Flare.Bugs.HPACK_Fixtures

def e1 : Entry := ⟨Bytes.ofString "x-1", List.replicate 500 0x61⟩
def e2 : Entry := ⟨Bytes.ofString "x-2", List.replicate 1300 0xFF⟩

def evs : List Ev := [.ins e1, .ins e2]

def runJ (c : Bytes → Bytes) : Option Joint := evs.foldlM (jstep c) jinit

theorem bug : (runJ octetsToString).map (fun j => (tsize j.peer, j.peer[1]?, lookup j.dec 63,
      j.dec.dyn.length, (j.dec.dyn.headD ⟨[], []⟩).value.length)) =
    some (1870, some e1, .errRange, 1, 3900) := by native_decide

/-- The peer's table names `e1` at index 63; flare's lookup fails. -/
theorem counterexample : ∃ j, (jointLTS octetsToString).Reachable j ∧
    j.peer[63 - 62]? = some e1 ∧ lookup j.dec 63 = .errRange := by
  have hs : (runJ octetsToString).isSome = true := by native_decide
  obtain ⟨j, hj⟩ := Option.isSome_iff_exists.mp hs
  have hb := bug
  rw [hj] at hb
  simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hb
  exact ⟨j, ⟨jinit, evs, rfl, HPACK_Fixtures.run_of_foldlM _ evs jinit j hj⟩, hb.2.1, hb.2.2.1⟩

theorem fixed_trace : (runJ id).map (fun j => (j.dec.dyn == j.peer, lookup j.dec 63)) =
    some (true, .dyn e1) := by native_decide

/-- **Fixed** (store the octets unchanged): flare's table equals the
peer's after every event sequence, so every index resolves to the peer's
entry. -/
theorem fixed (evs : List Ev) (j' : Joint) (hr : (jointLTS id).Run jinit evs j') :
    j'.dec.dyn = j'.peer ∧ j'.dec.maxSize = j'.peerMax ∧ Inv j'.dec :=
  sync_exact id jinit evs j' (fun _ _ => rfl) ⟨rfl, rfl, inv_init⟩ hr

/-! ## On flare's real codecs, Huffman-coded literals

The same witness, encoded by an RFC 7541 encoder with every string
Huffman-coded (§5.2), decoded by flare's real integer and Huffman
decoders (`Hpack.real`, L1 `HpackInt` / `Huffman.decodeSimdImpl`). -/

def rssR : List (List Rep) :=
  [[.inc 0 e1.name e1.value true true], [.inc 0 e2.name e2.value true true], [.idx 63]]

def blksR : List Bytes := rssR.map (encBlock real Flare.L1.Huffman.encode)

def t2R : Table :=
  match Flare.L3.H2.Conn.decFold real 0 Table.init (blksR.take 2) with
  | (some t, _) => t
  | _ => Table.init

/-- The peer means `e1` by index 63 in its third block. -/
theorem peer_real : (Flare.L3.H2.Conn.pblocks Peer.init rssR).map (·.2) = some [[e1], [e2], [e1]] := by
  native_decide

/-- flare decodes the first two blocks (the second lossily, 3900 octets),
then rejects the legal third block: COMPRESSION_ERROR on the connection. -/
theorem bug_real : (Flare.L3.H2.Conn.decFold real 0 Table.init blksR).1 = none ∧
    (Flare.L3.H2.Conn.decFold real 0 Table.init blksR).2.map (·.map (·.value.length)) = [[500], [3900]] ∧
    result (decode real true t2R (blksR.getD 2 []) 0) = .inl .range := by native_decide

end Flare.Bugs.HPACK_01
