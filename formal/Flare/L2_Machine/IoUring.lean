import Flare.Core

/-!
# io_uring SQ / CQ rings and the provided-buffer ring

`runtime/io_uring_driver.mojo` drives the kernel-shared rings with
free-running `UInt32` counters that wrap at 2^32:

* SQ: kernel-owned `head`, kernel-visible `tail` (`ktail`), user-cached
  `_sq_local_tail` (`ltail`); `entries = mask + 1` is a power of two ≤ 2^15.
* CQ: kernel-owned `tail`, user-owned `head`.

All arithmetic below is `UInt32` (wrapping), exactly as in Mojo. The
parametric lemmas are proved for *all* counter values (by translating to
`Nat` arithmetic modulo 2^32), so they hold across the 2^32 wrap.
-/
namespace Flare.L2.IoUring

/-- `mask` describes a power-of-two ring of at most 2^15 entries
(`IORING_MAX_ENTRIES`; the kernel rounds the ring size up to a power of
two and reports `mask = entries - 1`). -/
def PowMask (m : UInt32) : Prop := ∃ k, k ≤ 15 ∧ m.toNat = 2 ^ k - 1

theorem powMask_bitwise : ∀ k, k ≤ 15 → (UInt32.ofNat (2 ^ k - 1)) &&& (UInt32.ofNat (2 ^ k - 1) + 1) = 0 := by
  decide

theorem PowMask.lt {m : UInt32} (h : PowMask m) : m.toNat < 32768 := by
  obtain ⟨k, hk, hm⟩ := h
  have := Nat.pow_le_pow_right (show 0 < 2 by decide) hk
  have := Nat.two_pow_pos k
  simp only [Nat.reducePow] at *; omega

theorem PowMask.succ {m : UInt32} (h : PowMask m) : (m + 1).toNat = m.toNat + 1 := by
  have := h.lt
  rw [UInt32.toNat_add, UInt32.toNat_one]; omega

theorem and_mask (x m : UInt32) (k : Nat) (hm : m.toNat = 2 ^ k - 1) :
    (x &&& m).toNat = x.toNat % 2 ^ k := by
  rw [UInt32.toNat_and, hm, Nat.and_two_pow_sub_one_eq_mod]

/-- `i ↦ (a + i) mod 2^32 mod 2^k` is injective on `[0, 2^k)`. -/
theorem add_mod_inj (a i j k : Nat) (hk : k ≤ 32) (hi : i < 2 ^ k) (hj : j < 2 ^ k)
    (h : (a + i) % 2 ^ 32 % 2 ^ k = (a + j) % 2 ^ 32 % 2 ^ k) : i = j := by
  have hd : 2 ^ k ∣ 2 ^ 32 := Nat.pow_dvd_pow 2 hk
  rw [Nat.mod_mod_of_dvd _ hd, Nat.mod_mod_of_dvd _ hd] at h
  have hM := Nat.two_pow_pos k
  generalize 2 ^ k = M at *
  rw [Nat.add_mod a i, Nat.add_mod a j, Nat.mod_eq_of_lt hi, Nat.mod_eq_of_lt hj] at h
  have hr := Nat.mod_lt a hM
  generalize a % M = r at *
  rcases Nat.lt_or_ge (r + i) M with h1 | h1 <;> rcases Nat.lt_or_ge (r + j) M with h2 | h2
  · rw [Nat.mod_eq_of_lt h1, Nat.mod_eq_of_lt h2] at h; omega
  · rw [Nat.mod_eq_of_lt h1, Nat.mod_eq_sub_mod h2, Nat.mod_eq_of_lt (by omega)] at h; omega
  · rw [Nat.mod_eq_sub_mod h1, Nat.mod_eq_of_lt (by omega), Nat.mod_eq_of_lt h2] at h; omega
  · rw [Nat.mod_eq_sub_mod h1, Nat.mod_eq_of_lt (by omega), Nat.mod_eq_sub_mod h2,
      Nat.mod_eq_of_lt (by omega)] at h; omega

/-! ## Distance -/

/-- mirrors flare/runtime/io_uring_driver.mojo:297-307 @59bda50 -/
def ringDistance (tail head : UInt32) : UInt32 := tail - head

/-- The fixed `_ring_distance` is the true occupancy whenever the true
(unbounded) counters differ by less than 2^32, wrapped or not. -/
theorem ringDistance_true (H T : Nat) (hle : H ≤ T) (hlt : T - H < 2 ^ 32) :
    (ringDistance (UInt32.ofNat T) (UInt32.ofNat H)).toNat = T - H := by
  unfold ringDistance
  rw [UInt32.toNat_sub]
  have a1 : (UInt32.ofNat T).toNat = T % 2 ^ 32 := by simp
  have a2 : (UInt32.ofNat H).toNat = H % 2 ^ 32 := by simp
  rw [a1, a2]
  have h1 : T % 2 ^ 32 < 2 ^ 32 := Nat.mod_lt _ (by decide)
  have h2 : H % 2 ^ 32 < 2 ^ 32 := Nat.mod_lt _ (by decide)
  have e1 := Nat.div_add_mod T (2 ^ 32)
  have e2 := Nat.div_add_mod H (2 ^ 32)
  -- T = qT*2^32 + rT, H = qH*2^32 + rH, and T - H < 2^32
  omega

/-- The old code widened both counters to `Int` before subtracting; once
the tail had wrapped and the head had not, the distance was hugely
negative (the SQ read as never full). Concrete witness. -/
def oldDistance (tail head : UInt32) : Int := (tail.toNat : Int) - head.toNat

theorem oldDistance_wrong :
    oldDistance (UInt32.ofNat (2 ^ 32)) (UInt32.ofNat (2 ^ 32 - 1)) = -(2 ^ 32 - 1) ∧
    (ringDistance (UInt32.ofNat (2 ^ 32)) (UInt32.ofNat (2 ^ 32 - 1))).toNat = 1 := by
  decide

/-! ## SQ ring -/

structure SQ where
  head : UInt32    -- kernel-owned
  ktail : UInt32   -- kernel-visible tail
  ltail : UInt32   -- user cached tail
  mask : UInt32
  deriving DecidableEq, Repr

/-- Occupancy invariant: `ktail - head ≤ ltail - head ≤ entries`. -/
def SQ.Inv (s : SQ) : Prop :=
  PowMask s.mask ∧ s.ktail - s.head ≤ s.ltail - s.head ∧ s.ltail - s.head ≤ s.mask + 1

/-- mirrors flare/runtime/io_uring_driver.mojo:566-589 @59bda50
Returns the slot index, `none` = NULL (SQ full). -/
def nextSqe (s : SQ) : Option UInt32 :=
  if ringDistance s.ltail s.head ≥ s.mask + 1 then none else some (s.ltail &&& s.mask)

/-- mirrors flare/runtime/io_uring_driver.mojo:591-608 @59bda50
No fullness check of its own: callers must have got a slot from `nextSqe`. -/
def commitSqe (s : SQ) : SQ := { s with ltail := s.ltail + 1 }

/-- mirrors flare/runtime/io_uring_driver.mojo:610-641 @59bda50
Returns the new ring and `to_submit`. -/
def submit (s : SQ) : SQ × UInt32 :=
  ({ s with ktail := s.ltail }, ringDistance s.ltail s.ktail)

/-- Kernel consumes `k ≤ ktail - head` submitted SQEs. -/
def kconsume (s : SQ) (k : UInt32) : SQ := { s with head := s.head + k }

theorem slot_lt_entries (s : SQ) (h : PowMask s.mask) (i : UInt32)
    (hs : nextSqe s = some i) : i < s.mask + 1 := by
  unfold nextSqe at hs; split at hs
  · cases hs
  · cases hs; obtain ⟨k, hk, hm⟩ := h
    rw [UInt32.lt_iff_toNat_lt, and_mask _ _ k hm, PowMask.succ ⟨k, hk, hm⟩, hm]
    have := Nat.mod_lt s.ltail.toNat (Nat.two_pow_pos k)
    have := Nat.two_pow_pos k
    omega

theorem commit_inv (s : SQ) (hi : s.Inv) (hs : (nextSqe s).isSome) : (commitSqe s).Inv := by
  unfold nextSqe ringDistance at hs; split at hs
  · simp at hs
  · rename_i hlt
    obtain ⟨hp, h1, h2⟩ := hi
    have hm := hp.lt
    refine ⟨hp, ?_, ?_⟩ <;> simp only [commitSqe] <;>
    generalize s.ltail = t at * <;> generalize s.head = h at * <;>
    generalize s.ktail = k at * <;> generalize s.mask = m at * <;>
    have := UInt32.toNat_lt t <;> have := UInt32.toNat_lt h <;> have := UInt32.toNat_lt k <;>
    simp only [UInt32.le_iff_toNat_le, UInt32.toNat_sub, UInt32.toNat_add,
      UInt32.toNat_one, ge_iff_le, Nat.not_le] at * <;> omega

theorem submit_inv (s : SQ) (hi : s.Inv) : (submit s).1.Inv := by
  obtain ⟨hp, h1, h2⟩ := hi
  exact ⟨hp, by simp [submit], by simpa [submit] using h2⟩

/-- `to_submit` is exactly the number of committed-but-unsubmitted SQEs, and
after submit nothing is pending. -/
theorem submit_count (s : SQ) :
    (submit s).2 = s.ltail - s.ktail ∧ ringDistance (submit s).1.ltail (submit s).1.ktail = 0 := by
  simp [submit, ringDistance]

theorem kconsume_inv (s : SQ) (hi : s.Inv) (k : UInt32) (hk : k ≤ s.ktail - s.head) :
    (kconsume s k).Inv := by
  obtain ⟨hp, h1, h2⟩ := hi
  have hm := hp.lt
  refine ⟨hp, ?_, ?_⟩ <;> simp only [kconsume] <;>
  generalize s.ltail = t at * <;> generalize s.head = h at * <;>
  generalize s.ktail = kt at * <;> generalize s.mask = m at * <;>
  have := UInt32.toNat_lt t <;> have := UInt32.toNat_lt h <;> have := UInt32.toNat_lt kt <;>
  have := UInt32.toNat_lt k <;>
  simp only [UInt32.le_iff_toNat_le, UInt32.toNat_sub, UInt32.toNat_add, UInt32.toNat_one] at * <;>
  omega

/-- Live SQEs occupy pairwise-distinct slots: for `i, j <` occupancy ≤ entries,
`(head+i) & mask = (head+j) & mask → i = j`. For all 2^32 head values. -/
theorem live_slots_distinct (h i j m : UInt32) (hp : PowMask m)
    (hi : i < m + 1) (hj : j < m + 1) (he : (h + i) &&& m = (h + j) &&& m) : i = j := by
  obtain ⟨k, hk, hm⟩ := hp
  have hs := PowMask.succ ⟨k, hk, hm⟩
  rw [UInt32.lt_iff_toNat_lt, hs, hm] at hi hj
  have hpos := Nat.two_pow_pos k
  rw [← UInt32.toNat_inj, and_mask _ _ k hm, and_mask _ _ k hm, UInt32.toNat_add,
    UInt32.toNat_add] at he
  rw [← UInt32.toNat_inj]
  exact add_mod_inj h.toNat i.toNat j.toNat k (by omega) (by omega) (by omega) he

/-- The slot `nextSqe` hands out never aliases a live (head..ltail) SQE. -/
theorem nextSqe_fresh (s : SQ) (hi : s.Inv) (idx : UInt32) (hs : nextSqe s = some idx)
    (i : UInt32) (hil : i < s.ltail - s.head) : (s.head + i) &&& s.mask ≠ idx := by
  unfold nextSqe ringDistance at hs; split at hs
  · cases hs
  · cases hs; rename_i hlt; obtain ⟨hp, _, _⟩ := hi
    have hm := hp.lt
    have hs := hp.succ
    generalize s.ltail = t at *; generalize s.head = h at *; generalize s.mask = m at *
    have ht : t = h + (t - h) := by
      have := UInt32.toNat_lt t; have := UInt32.toNat_lt h
      rw [← UInt32.toNat_inj, UInt32.toNat_add, UInt32.toNat_sub]; omega
    intro he
    rw [ht] at he
    have hd : t - h < m + 1 := by
      simp only [ge_iff_le, UInt32.not_le] at hlt; exact hlt
    have := live_slots_distinct h i (t - h) m hp
      (UInt32.lt_of_lt_of_le hil (UInt32.le_of_lt hd)) hd he
    rw [this] at hil; exact UInt32.lt_irrefl _ hil

/-! ## CQ ring -/

structure CQ where
  khead_user : UInt32   -- user-owned head
  ktail : UInt32        -- kernel-owned tail
  mask : UInt32
  deriving DecidableEq, Repr

/-- Kernel side assumption: it never posts more than `cq_entries` unreaped
CQEs (it overflows into its own backlog instead). -/
def KernelCQBound (c : CQ) : Prop := c.ktail - c.khead_user ≤ c.mask + 1

/-- mirrors flare/runtime/io_uring_driver.mojo:645-651 @59bda50 -/
def cqeCount (c : CQ) : UInt32 := ringDistance c.ktail c.khead_user

/-- mirrors flare/runtime/io_uring_driver.mojo:653-671 @59bda50
Returns the slot read and the new ring. -/
def reapCqe (c : CQ) : Option (UInt32 × CQ) :=
  if c.khead_user = c.ktail then none
  else some (c.khead_user &&& c.mask, { c with khead_user := c.khead_user + 1 })

/-- Kernel posts one CQE (only when there is room, by assumption). -/
def kpost (c : CQ) : CQ := { c with ktail := c.ktail + 1 }

theorem reap_index_lt (c : CQ) (hp : PowMask c.mask) i c' (h : reapCqe c = some (i, c')) :
    i < c.mask + 1 := by
  unfold reapCqe at h; split at h
  · cases h
  · cases h; obtain ⟨k, hk, hm⟩ := hp
    rw [UInt32.lt_iff_toNat_lt, and_mask _ _ k hm, PowMask.succ ⟨k, hk, hm⟩, hm]
    have := Nat.mod_lt c.khead_user.toNat (Nat.two_pow_pos k)
    have := Nat.two_pow_pos k
    omega

theorem reap_count (c : CQ) i c' (h : reapCqe c = some (i, c')) :
    cqeCount c' + 1 = cqeCount c ∧ cqeCount c ≠ 0 := by
  unfold reapCqe at h; split at h
  · cases h
  · cases h; rename_i hne; simp only [cqeCount, ringDistance]
    generalize c.khead_user = x at *; generalize c.ktail = t at *
    have := UInt32.toNat_lt t; have := UInt32.toNat_lt x
    rw [← UInt32.toNat_inj] at hne
    constructor
    · rw [← UInt32.toNat_inj]
      simp only [UInt32.toNat_sub, UInt32.toNat_add, UInt32.toNat_one]; omega
    · rw [ne_eq, ← UInt32.toNat_inj]
      simp only [UInt32.toNat_sub, UInt32.toNat_zero]; omega

theorem reap_none_iff (c : CQ) : reapCqe c = none ↔ cqeCount c = 0 := by
  unfold reapCqe cqeCount ringDistance
  split
  · rename_i h; simp [h]
  · rename_i h; simp only [reduceCtorEq, false_iff]
    intro h2; apply h; generalize c.khead_user = x at *; generalize c.ktail = t at *
    have := UInt32.toNat_lt t; have := UInt32.toNat_lt x
    rw [← UInt32.toNat_inj] at h2 ⊢
    simp only [UInt32.toNat_sub, UInt32.toNat_zero] at h2; omega

theorem reap_keeps_bound (c : CQ) (hb : KernelCQBound c) i c' (h : reapCqe c = some (i, c')) :
    KernelCQBound c' := by
  unfold reapCqe at h; split at h
  · cases h
  · cases h; unfold KernelCQBound at *; rename_i hne
    generalize c.khead_user = x at *; generalize c.ktail = t at *; generalize c.mask = m at *
    simp only
    have := UInt32.toNat_lt t; have := UInt32.toNat_lt x; have := UInt32.toNat_lt m
    rw [← UInt32.toNat_inj] at hne
    simp only [UInt32.le_iff_toNat_le, UInt32.toNat_sub, UInt32.toNat_add, UInt32.toNat_one] at *
    omega

/-! ## SPSC interleaving: user and kernel steps on the SQ -/

inductive Lbl | commit | submit | consume (k : UInt32)

/-- The SQ as an LTS: user steps (commit after a successful nextSqe, submit)
and kernel steps (consume ≤ submitted) interleave arbitrarily. -/
def sqLTS : LTS SQ Lbl where
  init s := PowMask s.mask ∧ s.head = s.ktail ∧ s.ktail = s.ltail
  step s l s' := match l with
    | .commit => (nextSqe s).isSome ∧ s' = commitSqe s
    | .submit => s' = (submit s).1
    | .consume k => k ≤ s.ktail - s.head ∧ s' = kconsume s k

theorem sq_inductive : sqLTS.Inductive SQ.Inv where
  init s := by
    rintro ⟨hp, h1, h2⟩
    refine ⟨hp, ?_, ?_⟩ <;> rw [h1, h2] <;> simp
  step s l s' hi hs := by
    cases l with
    | commit => obtain ⟨h1, rfl⟩ := hs; exact commit_inv s hi h1
    | submit => subst hs; exact submit_inv s hi
    | consume k => obtain ⟨h1, rfl⟩ := hs; exact kconsume_inv s hi k h1

/-- Every reachable SQ state satisfies the occupancy invariant. -/
theorem sq_reachable_inv (s : SQ) (h : sqLTS.Reachable s) : s.Inv :=
  sq_inductive.reachable s h

/-! ## Provided-buffer ring (runtime/_pbuf_ring.mojo) -/

/-- mirrors flare/runtime/_pbuf_ring.mojo:61-97 @59bda50 (slot index;
Mojo `&` with `entries - 1` on a non-negative `Int` is `% entries`). -/
def pbufIdx (curTail : UInt16) (off entries : Nat) : Nat := (curTail.toNat + off) % entries

/-- The u16 tail wraps at 2^16; since the ring size divides 2^16, the slot
computed from the wrapped tail is the slot of the true (unbounded) tail. -/
theorem pbufIdx_wrap (T off k : Nat) (hk : k ≤ 16) :
    pbufIdx (UInt16.ofNat T) off (2 ^ k) = (T + off) % 2 ^ k := by
  unfold pbufIdx
  have a1 : (UInt16.ofNat T).toNat = T % 2 ^ 16 := by simp
  rw [a1]
  have hd : 2 ^ k ∣ 2 ^ 16 := Nat.pow_dvd_pow 2 hk
  rw [Nat.add_mod, Nat.mod_mod_of_dvd _ hd, ← Nat.add_mod]

/-- Byte offsets (relative to the ring base) written by one `_pbuf_ring_add`:
addr (0..7), len (8..11), bid (12..13) of the chosen 16-byte slot. -/
def pbufWrites (idx : Nat) : List Nat := (List.range 14).map (idx * 16 + ·)

/-- `_pbuf_ring_add` never touches bytes 14..15 of slot 0, where the
kernel-shared tail lives. -/
theorem pbuf_add_preserves_tail (idx : Nat) : 14 ∉ pbufWrites idx ∧ 15 ∉ pbufWrites idx := by
  unfold pbufWrites; constructor <;> simp only [List.mem_map, List.mem_range, not_exists, not_and]
  <;> intro j hj <;> omega

end Flare.L2.IoUring
