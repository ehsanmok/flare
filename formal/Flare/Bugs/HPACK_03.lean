import Flare.Bugs.HPACK_Fixtures
import Flare.L3_Protocol.H2.ConnHpack
import Flare.L3_Protocol.H2.HpackCodec

/-!
# HPACK-03: the decoder shrinks its table before the peer can know

`Http2Connection.with_config` (flare/http2/server.mojo:200-203 @59bda50)
used to set the decoder's `max_size` and `settings_max_size` to
`header_table_size` at construction, before our SETTINGS has even been
sent. With `header_table_size = 0`, every insert the peer's encoder makes
under the default 4096 octets is discarded (hpack.mojo:299-316), and the
peer's next reference to it is out of range: COMPRESSION_ERROR.

RFC 9113 §6.5.3 and RFC 7541 §4.2: a new SETTINGS_HEADER_TABLE_SIZE takes
effect for the encoder only once it has received our SETTINGS, and the
encoder signals the change with a dynamic table size update; until then
the decoder must keep decoding against the 4096-octet table.

Status: resolved. `with_config` (server and client) now sets only
`settings_max_size` (the ceiling for the peer's size update) and leaves
`max_size` at 4096; the SETTINGS frame advertises `settings_max_size`.
`fixedInit` is the shipped start state (`shipped_init`); `implInit` is
the pre-fix one that `bug` / `counterexample` / `bug_real` still use.

Witness: before our SETTINGS is acknowledged, the peer sends one block:
literal with incremental indexing `x-a: b`, then indexed field 62.
-/
namespace Flare.Bugs.HPACK_03
open Flare Flare.L3.H2.Hpack Flare.Bugs.HPACK_Fixtures

def xa : Entry := ⟨Bytes.ofString "x-a", Bytes.ofString "b"⟩

def blk : Bytes := 0x40 :: str xa.name ++ str xa.value ++ [0xBE]

/-- Pre-fix: flare's decoder after `with_config(header_table_size = 0)`
(server.mojo:200-203 @59bda50). -/
def implInit : Table := { Table.init with maxSize := 0, settingsMax := 0 }

/-- The fix (shipped): keep the 4096 default until the peer's first size
update. mirrors flare/http2/server.mojo `with_config` and client.mojo
`with_config`, which now set only `settings_max_size`. -/
def fixedInit : Table := { Table.init with settingsMax := 0 }

/-- The peer's encoder table (RFC 7541) after the insert. -/
theorem peer_table : specInsert [] 4096 xa = [xa] := by native_decide

theorem bug : result (decode toy false implInit blk 0) = .inl .range := by native_decide

theorem counterexample : ∀ t hs, decode toy false implInit blk 0 ≠ .ok (t, hs) := by
  intro t hs h
  have := bug; rw [h] at this; cases this

theorem fixed_trace : result (decode toy false fixedInit blk 0) = .inr [xa, xa] := by native_decide

/-- The shipped start state: current size 4096, ceiling = advertised 0. -/
theorem shipped_init : fixedInit.maxSize = 4096 ∧ fixedInit.settingsMax = 0 := ⟨rfl, rfl⟩

/-- The peer's size update is honoured up to the advertised size and not
beyond it (RFC 7541 §6.3). -/
theorem shipped_size_update :
    (match sizeUpdate fixedInit 0 0 with | .ok t => t.maxSize = 0 | _ => False) ∧
    sizeUpdate fixedInit 1 0 = .exceedsCap := by
  refine ⟨?_, rfl⟩
  have h : sizeUpdate fixedInit 0 0 = .ok (evictToFit { fixedInit with maxSize := 0 } 0) := by
    simp [sizeUpdate, fixedInit, Table.init]
  rw [h]
  exact (evict_maxSize { fixedInit with maxSize := 0 } 0 rfl).1

def jfix : Joint := { peer := [], peerMax := 4096, dec := fixedInit }

/-- **Fixed**: started from the fixed table, flare's decoder table stays
a (converted) prefix of the peer encoder's 4096-octet table, with the
same maximum, under every sequence of inserts and size updates; with
ASCII entries the two are equal (`HpackSync.sync_exact`). -/
theorem fixed (c : Bytes → Bytes) (hc : Expanding c) :
    ∀ j, (LTS.ofFn (· = jfix) (jstep c)).Reachable j → JInv c j := by
  have hI : (LTS.ofFn (· = jfix) (jstep c)).Inductive (JInv c) :=
    ⟨fun s h => by subst h; exact ⟨⟨rfl, Nat.zero_le _⟩, rfl, ⟨0, rfl⟩⟩,
     fun s l s' hp hs => jinv_step c hc s s' l hp hs⟩
  exact hI.reachable

/-! ## On flare's real codecs, Huffman-coded literals -/

def blkR : Bytes := encBlock real Flare.L1.Huffman.encode [.inc 0 xa.name xa.value true true, .idx 62]

theorem bug_real : result (decode real true implInit blkR 0) = .inl .range := by native_decide

theorem fixed_trace_real : result (decode real true fixedInit blkR 0) = .inr [xa, xa] := by native_decide

end Flare.Bugs.HPACK_03
