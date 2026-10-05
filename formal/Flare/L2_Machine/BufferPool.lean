import Flare.Core

/-!
# BufferPool: bucketed size-class buffer recycling

`flare/runtime/buffer_pool.mojo` (`BufferPool`, `BufferHandle`). A handle is abstracted to its
`bytes.capacity()` and its `class_index` tag; the byte contents are
irrelevant (acquire clears them). Each bucket is a LIFO stack; the head of
the Lean list is the Mojo list's last element (`pop()` / `append`).

`BufferHandle.bytes` and the `BufferHandle(capacity, class_index)`
constructor are public, so the handle passed to `release` is arbitrary:
the caller may have replaced or shrunk `bytes` or forged the tag.
-/
namespace Flare.L2.BufferPool

structure Handle where
  cap : Nat
  cls : Int
  deriving DecidableEq, Repr

structure Pool where
  buckets : Nat → List Handle
  classCap : Nat

/-- mirrors flare/runtime/buffer_pool.mojo `_class_index_for` (fixed, RT-05) (`none` is `_OVERSIZE_CLASS`) -/
def classIndex (n : Nat) : Option Nat :=
  if n ≤ 1024 then some 0
  else if n ≤ 4 * 1024 then some 1
  else if n ≤ 16 * 1024 then some 2
  else if n ≤ 64 * 1024 then some 3
  else none

/-- mirrors flare/runtime/buffer_pool.mojo `_capacity_for_class` (fixed, RT-05) -/
def capacityFor (i : Nat) : Nat :=
  if i = 0 then 1024
  else if i = 1 then 4 * 1024
  else if i = 2 then 16 * 1024
  else if i = 3 then 64 * 1024
  else 0

/-- mirrors flare/runtime/buffer_pool.mojo `__init__`, `with_class_capacity` (fixed, RT-05) -/
def Pool.new (classCap : Nat) : Pool := ⟨fun _ => [], if classCap < 1 then 1 else classCap⟩

def upd (f : Nat → List Handle) (i : Nat) (v : List Handle) : Nat → List Handle :=
  fun j => if j = i then v else f j

/-- mirrors flare/runtime/buffer_pool.mojo `acquire` (fixed, RT-05) -/
def acquire (p : Pool) (n : Nat) : Pool × Handle :=
  match classIndex n with
  | none => (p, ⟨n, -1⟩)
  | some i =>
    match p.buckets i with
    | [] => (p, ⟨capacityFor i, i⟩)
    | h :: rest => ({ p with buckets := upd p.buckets i rest }, h)

/-- `release`, parameterised by the extra acceptance test `ok i h`
(pre-fix flare: none; shipped: `capacity >= _capacity_for_class(i)`). -/
def releaseWith (ok : Nat → Handle → Bool) (p : Pool) (h : Handle) : Pool :=
  if h.cls < 0 ∨ h.cls ≥ 4 then p
  else
    let i := h.cls.toNat
    if (p.buckets i).length ≥ p.classCap then p
    else if ok i h then { p with buckets := upd p.buckets i (h :: p.buckets i) }
    else p

/-- Pre-fix `release` (flare/runtime/buffer_pool.mojo:337-364 @59bda50): recycles by the class
tag alone. Kept for the RT-05 counterexample. -/
def releaseOld := releaseWith (fun _ _ => true)

/-- mirrors flare/runtime/buffer_pool.mojo `release` (fixed, RT-05): a handle
whose capacity is below its class's is dropped. -/
def release := releaseWith (fun i h => decide (capacityFor i ≤ h.cap))

/-! ## Size classes -/

theorem classIndex_fits (n i : Nat) (h : classIndex n = some i) : n ≤ capacityFor i := by
  unfold classIndex at h
  split at h
  · cases h; simp [capacityFor]; omega
  split at h
  · cases h; simp [capacityFor]; omega
  split at h
  · cases h; simp [capacityFor]; omega
  split at h
  · cases h; simp [capacityFor]; omega
  cases h

theorem classIndex_lt (n i : Nat) (h : classIndex n = some i) : i < 4 := by
  unfold classIndex at h
  split at h
  · cases h; decide
  split at h
  · cases h; decide
  split at h
  · cases h; decide
  split at h
  · cases h; decide
  cases h

/-- the class is the smallest one that fits -/
theorem classIndex_least (n i : Nat) (h : classIndex n = some i) (j : Nat) (hj : j < i) :
    capacityFor j < n := by
  unfold classIndex at h
  split at h
  · cases h; omega
  split at h
  · cases h; have : j = 0 := by omega
    subst this; simp [capacityFor]; omega
  split at h
  · cases h
    rcases (by omega : j = 0 ∨ j = 1) with rfl | rfl <;> simp [capacityFor] <;> omega
  split at h
  · cases h
    rcases (by omega : j = 0 ∨ j = 1 ∨ j = 2) with rfl | rfl | rfl <;> simp [capacityFor] <;> omega
  cases h

/-! ## Bucket bound (holds for the pre-fix and the shipped release) -/

def Bounded (p : Pool) : Prop := ∀ i, (p.buckets i).length ≤ p.classCap

theorem bounded_new (c : Nat) : Bounded (Pool.new c) := by
  intro i; simp [Pool.new]

theorem bounded_acquire (p : Pool) (n : Nat) (hb : Bounded p) : Bounded (acquire p n).1 := by
  unfold acquire
  split
  · exact hb
  · rename_i i _
    split
    · exact hb
    · rename_i h rest hbi
      intro j; simp only [upd]
      split
      · subst j; have := hb i; rw [hbi] at this; simp at this; show rest.length ≤ p.classCap; omega
      · exact hb j

theorem bounded_release (ok : Nat → Handle → Bool) (p : Pool) (h : Handle) (hb : Bounded p) :
    Bounded (releaseWith ok p h) := by
  unfold releaseWith
  split
  · exact hb
  · dsimp only
    split
    · exact hb
    · rename_i hlen
      split
      · intro j; simp only [upd]
        split
        · subst j; simp; omega
        · exact hb j
      · exact hb

/-! ## Capacity contract -/

/-- every recycled handle in bucket `i` has at least class `i`'s capacity -/
def Good (p : Pool) : Prop := ∀ i h, h ∈ p.buckets i → capacityFor i ≤ h.cap

theorem good_new (c : Nat) : Good (Pool.new c) := by
  intro i h hm; simp [Pool.new] at hm

/-- **Capacity contract**: with `Good` buckets, `acquire n` returns a
handle of capacity `≥ n` and keeps the buckets `Good`. -/
theorem acquire_spec (p : Pool) (n : Nat) (hg : Good p) :
    n ≤ (acquire p n).2.cap ∧ Good (acquire p n).1 := by
  unfold acquire
  split
  · exact ⟨Nat.le_refl _, hg⟩
  · rename_i i hi
    have hfit := classIndex_fits n i hi
    split
    · exact ⟨hfit, hg⟩
    · rename_i h rest hbi
      refine ⟨Nat.le_trans hfit (hg i h (by rw [hbi]; exact List.mem_cons_self)), ?_⟩
      intro j h' hm
      simp only [upd] at hm
      split at hm
      · subst j; exact hg i h' (by rw [hbi]; exact List.mem_cons_of_mem _ hm)
      · exact hg j h' hm

theorem release_good (p : Pool) (h : Handle) (hg : Good p) : Good (release p h) := by
  unfold release releaseWith
  split
  · exact hg
  · dsimp only
    split
    · exact hg
    · split
      · rename_i hok
        intro j h' hm
        simp only [upd] at hm
        split at hm
        · subst j
          rcases List.mem_cons.1 hm with rfl | hm
          · simpa using hok
          · exact hg _ h' hm
        · exact hg j h' hm
      · exact hg

/-- Client operations: acquire, or release an arbitrary (possibly mutated
or forged) handle. -/
inductive Op
  | acq (n : Nat)
  | rel (h : Handle)

def run : Pool → List Op → Pool
  | p, [] => p
  | p, .acq n :: ops => run (acquire p n).1 ops
  | p, .rel h :: ops => run (release p h) ops

theorem good_run (p : Pool) (ops : List Op) (hg : Good p) : Good (run p ops) := by
  induction ops generalizing p with
  | nil => exact hg
  | cons op ops ih =>
    cases op with
    | acq n => exact ih _ (acquire_spec p n hg).2
    | rel h => exact ih _ (release_good p h hg)

/-- **Shipped code meets spec**: after any history of acquires and arbitrary
releases against the pool, `acquire n` returns capacity `≥ n`. -/
theorem release_preserves_capacity (c : Nat) (ops : List Op) (n : Nat) :
    n ≤ (acquire (run (Pool.new c) ops) n).2.cap :=
  (acquire_spec _ n (good_run _ ops (good_new c))).1

end Flare.L2.BufferPool
