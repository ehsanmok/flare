import Flare.L3_Protocol.Qpack.FieldSection

/-!
# QPACK-02: one-byte out-of-bounds read of the Sign/Delta-Base byte

flare/qpack/dynamic.mojo:482-489 @59bda50 only checks `len(buf) >= 2`, then
reads `buf[ric_enc.offset]`. A two-byte field section whose Required Insert
Count uses a multi-byte prefix integer (`0xFF 0x01` = 256) ends exactly at
offset 2, so the read is one past the end. The RIC decode must succeed
first, which needs MaxEntries ≥ 128, i.e. a decoder table capacity ≥ 4096;
with MaxEntries = 256 (capacity 8192) and an empty table, RIC 256 decodes to
255 and the read happens. Unreachable with the default H3 config
(`qpack_max_table_capacity = 0`).
-/
namespace Flare.Bugs.QPACK_02
open Flare.L3.Qpack.FieldSection

def buf : Flare.Bytes := [0xFF, 0x01]

theorem ric_prefix : decodeInt buf 0 8 = some (256, 2) := by decide

theorem ric_decodes : Flare.L3.Qpack.Ric.implDecode 256 0 256 = some 255 := by decide

theorem counterexample : implSignReadIndex buf 0 256 = some 2 := by decide

theorem out_of_bounds : ∃ i, implSignReadIndex buf 0 256 = some i ∧ i ≥ buf.length :=
  ⟨2, counterexample, by decide⟩

theorem fixed_inBounds (b : Flare.Bytes) (t m : UInt64) (i : Nat)
    (h : implFixedSignReadIndex b t m = some i) : i < b.length :=
  implFixedSignReadIndex_inBounds b t m i h

end Flare.Bugs.QPACK_02
