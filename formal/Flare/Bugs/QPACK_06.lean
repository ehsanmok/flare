import Flare.L3_Protocol.Qpack.Encoder

/-!
# QPACK-06: the dynamic-table encoder tracks no acknowledgments

flare/qpack/dynamic.mojo:405-470 @59bda50 (`encode_field_section_dynamic`,
called by `QpackEncoder.encode`, 617-619) references every entry `find` /
`find_name` (160-175) return, and `QpackEncoder.insert` (606-615) inserts
through `QpackDynamicTable.insert` (138-148), which evicts the oldest
entries to make room. `QpackEncoder` has no Known Received Count, no
reference tracking and no way to consume Section Acknowledgment or Insert
Count Increment instructions, and it is not told the peer's
SETTINGS_QPACK_BLOCKED_STREAMS. It is public API (flare/qpack/__init__.mojo
exports it); neither flare endpoint uses it.

Spec clause: RFC 9204 §2.1.2: "An encoder MUST limit the number of streams
that could become blocked to the value of SETTINGS_QPACK_BLOCKED_STREAMS at
all times" (0 by default); §2.1.1: "A dynamic table entry cannot be evicted
immediately after insertion, even if it has never been referenced ... If the
dynamic table does not contain enough room for a new entry without evicting
other entries, and the entries that would be evicted are not evictable, the
encoder MUST NOT insert that entry."

Model: entries are `(name, value)` pairs of `Nat`, size 34 each, table
capacity 40 (room for one entry). Nothing is ever acknowledged, so the Known
Received Count is 0: a conforming encoder may reference no entry while the
peer allows 0 blocked streams, and may evict no entry.

Status: resolved. `QpackEncoder.encode` now encodes against no dynamic
entries (RIC 0) and `QpackEncoder.insert` refuses an entry that would evict,
until acknowledgments are tracked. `implOldRic` and `Table.insert` are the
pre-fix behaviour (the counterexamples `implOld_*` are about them); `implRic`
and `implInsert` are the shipped ones (`implRic_zero`, `implInsert_noEvict`,
`fixed_spec`). Regression tests: tests/qpack/test_qpack_dynamic.mojo
`test_encoder_references_no_unacknowledged_entry`,
`test_encoder_refuses_an_insert_that_would_evict`.
-/
namespace Flare.Bugs.QPACK_06
open Flare.L3.Qpack.Table Flare.L3.Qpack.Encoder

abbrev E := Nat × Nat
def esz : E → Nat := fun _ => 34

def find (t : Table E) (h : E) : Option Nat := findBy (· == h) t
def findName (t : Table E) (h : E) : Option Nat := findBy (·.1 == h.1) t

/-- PRE-FIX: `QpackEncoder.encode` encodes against its own table.
mirrors flare/qpack/dynamic.mojo:418-430 @59bda50 (pre-fix) -/
def implOldRic (t : Table E) (hs : List E) : Nat := ric (find t) (findName t) hs

def t0 : Table E := Table.init 40
def t1 : Table E := (insert esz t0 (1, 2)).getD t0
def t2 : Table E := (insert esz t1 (3, 4)).getD t1

/-- **Counterexample (blocking)**: right after inserting `(1, 2)`, the encoder
references it: RIC 1 > Known Received Count 0, so the stream can block a
decoder that allows 0 blocked streams. -/
theorem implOld_references_unacked : implOldRic t1 [(1, 2)] = 1 := by native_decide

/-- **Counterexample (eviction)**: the next insert evicts the unacknowledged
(and referenced) entry 0; a decoder that applies both inserts before the
section can no longer resolve it. -/
theorem implOld_evicts_unacked : t2.dropped = 1 ∧ t2.getAbs 0 = none ∧ t1.getAbs 0 = some (1, 2) := by
  native_decide

/-- **Shipped**: `QpackEncoder.encode` encodes against an empty
`QpackDynamicTable(0)`, i.e. references nothing, until acknowledgments are
tracked.
mirrors flare/qpack/dynamic.mojo:713-720 (fixed, QPACK-06) -/
def implRic (hs : List E) : Nat := ric (find (Table.init 0)) (findName (Table.init 0)) hs

/-- **Shipped**: `QpackEncoder.insert` refuses an entry that does not fit in the
free space (`size + entry_size > capacity`) instead of evicting.
mirrors flare/qpack/dynamic.mojo:700-711 (fixed, QPACK-06) -/
def implInsert (t : Table E) (h : E) : Option (Table E) :=
  if t.size + esz h > t.capacity then none else Flare.L3.Qpack.Table.insert esz t h

theorem ric_none (hs : List E) : ric (fun _ : E => (none : Option Nat)) (fun _ => none) hs = 0 := by
  unfold ric
  suffices ∀ m, hs.foldl (fun m (h : E) => match ((none : Option Nat) <|> none) with
    | some i => max m (i + 1)
    | none => m) m = m from this 0
  intro m
  induction hs generalizing m with
  | nil => rfl
  | cons h hs ih => exact ih m

theorem implRic_zero (hs : List E) : implRic hs = 0 := ric_none hs

theorem evictTo_noop (target : Nat) (t : Table E) (h : t.size ≤ target) :
    evictTo esz target t = t := by
  obtain ⟨es, c, m, s, d⟩ := t
  cases es with
  | nil => rw [evictTo]
  | cons e es =>
    rw [evictTo]
    simp only at h
    rw [if_neg (by omega)]

/-- The fixed insert never evicts: the absolute indices already handed out
stay valid. -/
theorem implInsert_noEvict (t t' : Table E) (h : E) (ht : implInsert t h = some t') :
    t'.dropped = t.dropped ∧ t'.entries = t.entries ++ [h] := by
  unfold implInsert at ht
  split at ht
  · cases ht
  · next hle =>
    unfold Flare.L3.Qpack.Table.insert at ht
    rw [if_neg (by omega)] at ht
    rw [evictTo_noop _ t (by omega)] at ht
    cases ht
    exact ⟨rfl, rfl⟩

/-- **Fix meets the spec**: with Known Received Count 0 the fixed encoder's
RIC never exceeds it (no stream can block), and no insert evicts. -/
theorem fixed_spec (hs : List E) (t t' : Table E) (h : E) (ht : implInsert t h = some t') :
    implRic hs ≤ 0 ∧ t'.dropped = t.dropped :=
  ⟨Nat.le_of_eq (implRic_zero hs), (implInsert_noEvict t t' h ht).1⟩

end Flare.Bugs.QPACK_06
