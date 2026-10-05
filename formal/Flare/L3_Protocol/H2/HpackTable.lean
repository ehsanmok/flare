import Flare.Core

/-!
# HPACK dynamic table (RFC 7541 §2.3, §4)

`Table` transliterates the dynamic-table half of `HpackDecoder`
(`flare/http2/hpack.mojo:252-328`): `_entry_size`, `_evict_to_fit`,
`_insert`, `_lookup`, and the size-update branch of `decode` (413-423).

Entries hold the octets flare *stores*, which are the wire octets after
`_octets_to_string` (48-76), which keeps them unchanged (`octetsToString`;
the pre-fix lossy conversion is `octetsToStringOld`, with a local
transliteration of `utf8_lossy_string`
(`flare/http/proto/utf8.mojo:31-139`)).

`dynamic_size` is a Mojo `Int`; it is modelled as `Nat`, and
`Inv.size_eq` proves it always equals the sum of entry sizes, so the
subtraction in `_evict_to_fit` never truncates (and the Mojo value never
goes negative or wraps).

Spec side (RFC 7541 §4.4), written independently: eviction keeps the
*longest prefix* (newest entries) whose size plus the incoming entry fits;
`evict_spec` proves the implementation computes exactly that.
-/
namespace Flare.L3.H2.Hpack

/-- A dynamic-table entry: name and value octets as stored. -/
structure Entry where
  name : Bytes
  value : Bytes
  deriving Repr, DecidableEq

/-- RFC 7541 §4.1 entry size.
mirrors flare/http2/hpack.mojo:287-288 @59bda50 -/
def entrySize (e : Entry) : Nat := e.name.length + e.value.length + 32

/-- Sum of entry sizes (RFC 7541 §4.1 table size). -/
def tsize : List Entry → Nat
  | [] => 0
  | e :: es => entrySize e + tsize es

theorem tsize_append (a b : List Entry) : tsize (a ++ b) = tsize a + tsize b := by
  induction a with
  | nil => simp [tsize]
  | cons x xs ih => simp [tsize, ih]; omega

theorem tsize_take_le (l : List Entry) (n : Nat) : tsize (l.take n) ≤ tsize l := by
  have := tsize_append (l.take n) (l.drop n)
  rw [List.take_append_drop] at this; omega

structure Table where
  dyn : List Entry          -- newest first (index 62 = head)
  size : Nat                -- `dynamic_size`
  maxSize : Nat             -- `max_size`
  settingsMax : Nat         -- `settings_max_size`
  deriving Repr, DecidableEq

/-- `HpackDecoder.__init__` (`hpack.mojo:280-285`). -/
def Table.init : Table := { dyn := [], size := 0, maxSize := 4096, settingsMax := 4096 }

/-- The table invariant: the size counter is exact and within bound. -/
structure Inv (t : Table) : Prop where
  size_eq : t.size = tsize t.dyn
  size_le : t.size ≤ t.maxSize

/-! ## Implementation -/

/-- One iteration bound: the `while` loop of `_evict_to_fit` removes one
entry per iteration, so `dyn.length` iterations always suffice.
mirrors flare/http2/hpack.mojo:290-297 @59bda50 -/
def evictLoop (room : Nat) : Nat → Table → Table
  | 0, t => t
  | n + 1, t =>
    if t.size + room > t.maxSize ∧ t.dyn ≠ [] then
      evictLoop room n { t with dyn := t.dyn.dropLast,
                                size := t.size - entrySize (t.dyn.getLastD ⟨[], []⟩) }
    else t

def evictToFit (t : Table) (room : Nat) : Table := evictLoop room t.dyn.length t

/-- mirrors flare/http2/hpack.mojo:299-316 @59bda50 -/
def insert (t : Table) (e : Entry) : Table :=
  let sz := entrySize e
  if sz > t.maxSize then { t with dyn := [], size := 0 }
  else
    let t' := evictToFit t sz
    { t' with dyn := e :: t'.dyn, size := t'.size + sz }

/-- Outcome of the size-update instruction. -/
inductive SizeUpd where
  | ok (t : Table)
  | exceedsCap
  | afterField
  deriving Repr, DecidableEq

/-- Dynamic table size update (§6.3), `fieldsSoFar` = `len(headers)`.
mirrors flare/http2/hpack.mojo:412-423 @59bda50 -/
def sizeUpdate (t : Table) (n : Nat) (fieldsSoFar : Nat) : SizeUpd :=
  if n > t.settingsMax then .exceedsCap
  else if fieldsSoFar > 0 then .afterField
  else .ok (evictToFit { t with maxSize := n } 0)

/-! ## Spec (RFC 7541 §4.3/§4.4) -/

/-- Longest-prefix length that fits: the largest `k ≤ n` with
`tsize (take k l) + room ≤ max`, or `0`. -/
def fitLen (l : List Entry) (room max : Nat) : Nat → Nat
  | 0 => 0
  | k + 1 => if tsize (l.take (k + 1)) + room ≤ max then k + 1 else fitLen l room max k

/-- RFC 7541 §4.4: entries are evicted from the end until the new entry
fits (if nothing fits, the table ends empty). -/
def specEvict (l : List Entry) (room max : Nat) : List Entry :=
  l.take (fitLen l room max l.length)

/-- RFC 7541 §4.4 insertion. -/
def specInsert (l : List Entry) (max : Nat) (e : Entry) : List Entry :=
  if entrySize e > max then [] else e :: specEvict l (entrySize e) max

theorem fitLen_le (l : List Entry) (room max n : Nat) : fitLen l room max n ≤ n := by
  induction n with
  | zero => simp [fitLen]
  | succ k ih => simp only [fitLen]; split <;> omega

theorem fitLen_fits (l : List Entry) (room max n : Nat) (h0 : room ≤ max) :
    tsize (l.take (fitLen l room max n)) + room ≤ max := by
  induction n with
  | zero => simp [fitLen, tsize]; exact h0
  | succ k ih => simp only [fitLen]; split <;> assumption

/-- `fitLen` is maximal: any prefix length `j ≤ n` that fits is at most it. -/
theorem fitLen_max (l : List Entry) (room max n j : Nat) (hj : j ≤ n)
    (hfit : tsize (l.take j) + room ≤ max) : j ≤ fitLen l room max n := by
  induction n with
  | zero => omega
  | succ k ih =>
    simp only [fitLen]
    split
    · omega
    · rename_i hn
      rcases Nat.lt_or_ge j (k + 1) with h | h
      · exact ih (by omega)
      · have : j = k + 1 := by omega
        subst this; exact absurd hfit hn

/-- Characterisation of the spec: the result is a prefix that fits and is
the longest such prefix. -/
theorem specEvict_longest (l : List Entry) (room max : Nat) (h0 : room ≤ max) :
    (∃ k, specEvict l room max = l.take k) ∧
    tsize (specEvict l room max) + room ≤ max ∧
    ∀ j, tsize (l.take j) + room ≤ max → (l.take j).length ≤ (specEvict l room max).length := by
  refine ⟨⟨_, rfl⟩, fitLen_fits _ _ _ _ h0, ?_⟩
  intro j hj
  simp only [specEvict, List.length_take]
  have := fitLen_le l room max l.length
  rcases Nat.lt_or_ge j l.length with h | h
  · have := fitLen_max l room max l.length j (by omega) hj; omega
  · rw [List.take_of_length_le h] at hj
    have := fitLen_max l room max l.length l.length (Nat.le_refl _)
      (by rw [List.take_of_length_le (Nat.le_refl _)]; exact hj)
    omega

/-! ## Implementation = spec -/

theorem take_dropLast (l : List Entry) (k : Nat) (h : k < l.length) :
    (l.take (k + 1)).dropLast = l.take k := by
  rw [List.take_add_one, List.getElem?_eq_getElem h]
  simp only [Option.toList, List.dropLast_concat]

theorem tsize_take_succ (l : List Entry) (k : Nat) (h : k < l.length) :
    tsize (l.take (k + 1)) = tsize (l.take k) + entrySize ((l.take (k + 1)).getLastD ⟨[], []⟩) := by
  have e1 : (l.take (k + 1)).getLastD ⟨[], []⟩ = l[k] := by
    rw [List.take_add_one, List.getElem?_eq_getElem h]
    simp only [Option.toList, List.getLastD_eq_getLast?, List.getLast?_concat, Option.getD_some]
  rw [e1, List.take_add_one, List.getElem?_eq_getElem h, tsize_append]
  simp [tsize]

/-- The loop, started on a prefix `take k l` with an exact counter, ends on
the spec's prefix. -/
theorem evictLoop_take (room : Nat) (l : List Entry) (mx sm : Nat) :
    ∀ k, k ≤ l.length →
    evictLoop room k { dyn := l.take k, size := tsize (l.take k), maxSize := mx, settingsMax := sm }
      = { dyn := l.take (fitLen l room mx k), size := tsize (l.take (fitLen l room mx k)),
          maxSize := mx, settingsMax := sm } := by
  intro k
  induction k with
  | zero => intro _; simp [evictLoop, fitLen]
  | succ k ih =>
    intro hk
    simp only [evictLoop, fitLen]
    by_cases hf : tsize (l.take (k + 1)) + room ≤ mx
    · rw [if_neg (by omega), if_pos hf]
    · have hne : l.take (k + 1) ≠ [] := List.ne_nil_of_length_pos (by simp; omega)
      rw [if_pos ⟨by omega, hne⟩, if_neg hf]
      rw [take_dropLast l k (by omega)]
      have hs := tsize_take_succ l k (by omega)
      have : tsize (List.take (k + 1) l) - entrySize ((List.take (k + 1) l).getLastD ⟨[], []⟩)
          = tsize (l.take k) := by omega
      rw [this]
      exact ih (by omega)

/-- `_evict_to_fit` computes the RFC 7541 §4.4 eviction, and keeps the
counter exact. -/
theorem evict_spec (t : Table) (room : Nat) (h : t.size = tsize t.dyn) :
    evictToFit t room = { t with dyn := specEvict t.dyn room t.maxSize,
                                 size := tsize (specEvict t.dyn room t.maxSize) } := by
  obtain ⟨dyn, size, mx, sm⟩ := t
  simp only at h; subst h
  have := evictLoop_take room dyn mx sm dyn.length (Nat.le_refl _)
  simp only [List.take_length] at this
  simp [evictToFit, this, specEvict]

/-- `_insert` computes RFC 7541 §4.4 insertion. -/
theorem insert_spec (t : Table) (e : Entry) (h : t.size = tsize t.dyn) :
    (insert t e).dyn = specInsert t.dyn t.maxSize e ∧
    (insert t e).size = tsize (insert t e).dyn ∧ (insert t e).maxSize = t.maxSize ∧
    (insert t e).settingsMax = t.settingsMax := by
  unfold insert specInsert
  by_cases hs : entrySize e > t.maxSize
  · simp [hs, tsize]
  · simp only [hs, if_false]
    rw [evict_spec t _ h]
    simp [tsize]; omega

/-! ## The invariant: size = Σ entry sizes ≤ max_size -/

theorem inv_init : Inv Table.init := ⟨rfl, by decide⟩

theorem inv_evict (t : Table) (room : Nat) (h : t.size = tsize t.dyn) (hr : room ≤ t.maxSize) :
    Inv (evictToFit t room) ∧ (evictToFit t room).size + room ≤ t.maxSize := by
  rw [evict_spec t room h]
  have := fitLen_fits t.dyn room t.maxSize t.dyn.length hr
  exact ⟨⟨rfl, by simp [specEvict] at *; omega⟩, by simpa [specEvict] using this⟩

theorem inv_insert (t : Table) (e : Entry) (h : Inv t) : Inv (insert t e) := by
  unfold insert
  by_cases hs : entrySize e > t.maxSize
  · simp only [hs, if_true]; exact ⟨by simp [tsize], by simp⟩
  · simp only [hs, if_false]
    have ⟨⟨h1, _⟩, h3⟩ := inv_evict t (entrySize e) h.size_eq (by omega)
    refine ⟨by simp [tsize, h1]; omega, ?_⟩
    have : (evictToFit t (entrySize e)).maxSize = t.maxSize := by
      rw [evict_spec t _ h.size_eq]
    simp [this]; omega

theorem evict_maxSize (t : Table) (room : Nat) (h : t.size = tsize t.dyn) :
    (evictToFit t room).maxSize = t.maxSize ∧ (evictToFit t room).settingsMax = t.settingsMax := by
  rw [evict_spec t room h]; exact ⟨rfl, rfl⟩

theorem inv_sizeUpdate (t t' : Table) (n k : Nat) (h : Inv t)
    (hu : sizeUpdate t n k = .ok t') : Inv t' ∧ t'.maxSize = n ∧ n ≤ t.settingsMax ∧ k = 0 := by
  unfold sizeUpdate at hu
  split at hu
  · cases hu
  split at hu
  · cases hu
  cases hu
  have h' : ({ t with maxSize := n } : Table).size = tsize ({ t with maxSize := n } : Table).dyn :=
    h.size_eq
  have ⟨hi, _⟩ := inv_evict { t with maxSize := n } 0 h' (Nat.zero_le _)
  have hm := (evict_maxSize { t with maxSize := n } 0 h').1
  exact ⟨hi, hm, by omega, by omega⟩

/-- RFC 7541 §4.2/§6.3: a size update is accepted only at the start of a
block and only up to the advertised SETTINGS value. -/
theorem sizeUpdate_guard (t : Table) (n k : Nat) (t' : Table) (hu : sizeUpdate t n k = .ok t') :
    k = 0 ∧ n ≤ t.settingsMax := by
  unfold sizeUpdate at hu; split at hu; · cases hu
  split at hu; · cases hu
  omega

/-! ## Index address space (RFC 7541 §2.3.3) -/

def STATIC_TABLE_LEN : Nat := 61

/-- Lookup result. -/
inductive Look where
  | static (i : Nat)       -- static-table entry `i` (1..61)
  | dyn (e : Entry)
  | errZero
  | errRange
  deriving Repr, DecidableEq

/-- mirrors flare/http2/hpack.mojo:318-328 @59bda50 -/
def lookup (t : Table) (idx : Nat) : Look :=
  if idx = 0 then .errZero
  else if idx ≤ STATIC_TABLE_LEN then .static idx
  else match t.dyn[idx - STATIC_TABLE_LEN - 1]? with
    | some e => .dyn e
    | none => .errRange

/-- Spec: the combined index space is `1..61` static followed by the
dynamic table newest-first, and anything else is a decoding error. -/
def specLookup (dyn : List Entry) (idx : Nat) : Look :=
  if idx = 0 then .errZero
  else if idx ≤ 61 then .static idx
  else if h : idx - 62 < dyn.length then .dyn dyn[idx - 62] else .errRange

theorem lookup_spec (t : Table) (idx : Nat) : lookup t idx = specLookup t.dyn idx := by
  unfold lookup specLookup STATIC_TABLE_LEN
  split; · rfl
  split; · rfl
  have : idx - 61 - 1 = idx - 62 := by omega
  rw [this]
  split
  · rename_i e h
    have hl : idx - 62 < t.dyn.length := by
      rcases List.getElem?_eq_some_iff.mp h with ⟨hl, _⟩; exact hl
    rw [dif_pos hl]
    rcases List.getElem?_eq_some_iff.mp h with ⟨_, he⟩; rw [he]
  · rename_i h
    have hl : ¬ idx - 62 < t.dyn.length := by
      intro hl; rw [List.getElem?_eq_getElem hl] at h; cases h
    rw [dif_neg hl]

end Flare.L3.H2.Hpack
