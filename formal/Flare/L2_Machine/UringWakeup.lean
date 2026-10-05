import Flare.Core

/-!
# UringReactor cross-thread wakeup machine

`runtime/uring_reactor.mojo (`poll`, `_try_arm_wakeup`, `_arm_wakeup_recv`, `wakeup`)`. A cross-thread `wakeup()` writes the
eventfd; it only becomes a CQE (and so releases a blocked `poll`) if an
`IORING_OP_READ` on the eventfd is in flight in the kernel.

State:
* `cross`   — `_cross_thread_wakeup` (constructed with `enable_wakeup`);
* `armed`   — `_wake_armed`, the user-side flag;
* `pending` / `cap` — committed-but-unsubmitted SQEs and the SQ size;
* `armQ`    — the wakeup read SQE sits in the SQ, not yet submitted;
* `kArmed`  — the wakeup read is in flight in the kernel;
* `ev`      — eventfd counter;
* `cq`      — ready CQEs, `true` = wakeup CQE, `false` = any other op.

Kernel assumption (`KernelConsumesAll`, built into `ksubmit`): an
`io_uring_enter` consumes every submitted SQE, freeing the SQ.
-/
namespace Flare.L2.UringWakeup

structure W where
  cross : Bool
  armed : Bool
  pending : Nat
  cap : Nat
  armQ : Bool
  kArmed : Bool
  ev : Nat
  cq : List Bool
  deriving DecidableEq, Repr

/-- mirrors flare/runtime/uring_reactor.mojo `_try_arm_wakeup`, `_arm_wakeup_recv` (fixed, RT-03)
Lazy arm: `_arm_wakeup_recv` raises when `next_sqe` is NULL (SQ full); the
exception is swallowed and `_wake_armed` stays false. -/
def lazyArm (s : W) : W :=
  if s.cross && !s.armed then
    if s.pending < s.cap then { s with pending := s.pending + 1, armQ := true, armed := true }
    else s
  else s

/-- Kernel side of `io_uring_enter`: consume all SQEs; a queued wakeup read
becomes in flight; an in-flight read with a non-zero eventfd completes. -/
def ksubmit (s : W) : W :=
  if (s.kArmed || s.armQ) && decide (s.ev > 0) then
    { s with pending := 0, armQ := false, kArmed := false, ev := 0, cq := s.cq ++ [true] }
  else { s with pending := 0, armQ := false, kArmed := s.kArmed || s.armQ }

/-- mirrors flare/runtime/uring_reactor.mojo `_drain_into_tracking` (fixed, RT-03)
Drain up to `max` CQEs; returns new state, surfaced count `n`, raw count. -/
def drain (s : W) (max : Nat) : W × Nat × Nat :=
  let taken := s.cq.take max
  ({ s with cq := s.cq.drop max, armed := if true ∈ taken then false else s.armed },
   taken.count false, taken.length)

/-- `wakeup()` from another thread. -/
def wakeup (s : W) : W :=
  if s.cross then
    if s.kArmed then { s with kArmed := false, ev := 0, cq := s.cq ++ [true] }
    else { s with ev := s.ev + 1 }
  else s

structure Res where
  st : W
  n : Nat
  blocked : Bool
  /-- a read is armed on the eventfd when phase 3 starts blocking -/
  armedAtBlock : Bool
  deriving Repr

/-- mirrors flare/runtime/uring_reactor.mojo `poll` (fixed, RT-03)
`fix = true` is the shipped `poll`: `_try_arm_wakeup()` runs again after
phase 1; `fix = false` is the pre-fix `poll`, kept for the RT-03 counterexample. -/
def pollWith (fix : Bool) (s : W) (minC maxC : Nat) : Res :=
  let s0 := lazyArm s
  let s1 := ksubmit s0                                  -- phase 1
  let (s2, n, raw) := drain s1 maxC                     -- phase 2
  let s2' := if fix then lazyArm s2 else s2
  if n < minC ∧ n < maxC ∧ raw = 0 then                 -- phase 3
    ⟨ksubmit s2', n, true, s2'.kArmed || s2'.armQ⟩
  else ⟨s2', n, false, false⟩

/-- The shipped `poll` (re-arms after phase 1). -/
def poll (s : W) (minC maxC : Nat) : Res := pollWith true s minC maxC

/-- The pre-fix `poll` (no re-arm after phase 1), only for `Flare.Bugs.RT_03`. -/
def pollOld (s : W) (minC maxC : Nat) : Res := pollWith false s minC maxC

/-- Liveness requirement: a blocking poll always has the wakeup read armed. -/
def NeverBlocksUnarmed (r : Res) (s : W) : Prop := s.cross → r.blocked → r.armedAtBlock

/-- State invariant: `_wake_armed` means the read is queued, in flight, or its
CQE is waiting in the CQ. -/
def Inv (s : W) : Prop := s.armed → s.armQ ∨ s.kArmed ∨ true ∈ s.cq

theorem lazyArm_inv (s : W) (h : Inv s) : Inv (lazyArm s) := by
  unfold lazyArm Inv at *; split
  · split
    · intro _; simp
    · exact h
  · exact h

theorem lazyArm_cross_unarmed (s : W) (hc : s.cross) (ha : s.armed = false) (hp : s.pending < s.cap) :
    (lazyArm s).armQ = true := by
  simp [lazyArm, hc, ha, hp]

theorem ksubmit_inv (s : W) (h : Inv s) : Inv (ksubmit s) := by
  unfold ksubmit Inv at *; intro ha
  by_cases hc : ((s.kArmed || s.armQ) && decide (s.ev > 0)) = true
  · simp [hc]
  · simp only [hc] at ha ⊢
    rcases h ha with h1 | h1 | h1
    · right; left; simp [h1]
    · right; left; simp [h1]
    · right; right; exact h1

theorem ksubmit_armed (s : W) : (ksubmit s).armed = s.armed := by
  unfold ksubmit; split <;> rfl

theorem ksubmit_pending (s : W) : (ksubmit s).pending = 0 := by
  unfold ksubmit; split <;> rfl

theorem ksubmit_armQ (s : W) : (ksubmit s).armQ = false := by
  unfold ksubmit; split <;> rfl

theorem drain_inv (s : W) m (h : Inv s) : Inv (drain s m).1 := by
  unfold drain Inv at *; simp only
  intro ha; split at ha
  · cases ha
  · rename_i hn
    rcases h ha with h1 | h1 | h1
    · exact Or.inl h1
    · exact Or.inr (Or.inl h1)
    · right; right
      rw [← List.take_append_drop m s.cq] at h1
      rcases List.mem_append.mp h1 with h2 | h2
      · exact absurd h2 hn
      · exact h2

theorem wakeup_inv (s : W) (h : Inv s) : Inv (wakeup s) := by
  unfold wakeup Inv at *; split
  · split
    · intro _; simp
    · exact h
  · exact h

/-- Poll (either version) preserves the invariant. -/
theorem pollWith_inv (fix : Bool) (s : W) mn mx (h : Inv s) : Inv (pollWith fix s mn mx).st := by
  have h2 := drain_inv _ mx (ksubmit_inv _ (lazyArm_inv s h))
  have h2' : Inv (if fix then lazyArm (drain (ksubmit (lazyArm s)) mx).1
      else (drain (ksubmit (lazyArm s)) mx).1) := by
    split
    · exact lazyArm_inv _ h2
    · exact h2
  unfold pollWith; simp only
  split
  · exact ksubmit_inv _ h2'
  · exact h2'

theorem poll_inv (s : W) mn mx (h : Inv s) : Inv (poll s mn mx).st :=
  pollWith_inv true s mn mx h

/-- The shipped poll never blocks with the wakeup read unarmed, from any
state satisfying the invariant, for any `min_complete` / `max_completions`. -/
theorem poll_never_blocks_unarmed (s : W) (mn mx : Nat) (h : Inv s) (hcap : 0 < s.cap) :
    NeverBlocksUnarmed (poll s mn mx) s := by
  intro hc hb
  unfold poll at hb ⊢
  have hI1 : Inv (ksubmit (lazyArm s)) := ksubmit_inv _ (lazyArm_inv s h)
  unfold pollWith at hb ⊢; simp only at hb ⊢
  split at hb
  · rename_i hcond
    rw [if_pos hcond]
    obtain ⟨_, hnm, hraw⟩ := hcond
    -- set names
    generalize hs1 : ksubmit (lazyArm s) = s1 at *
    have hcross : s1.cross = s.cross := by
      rw [← hs1]; unfold ksubmit lazyArm; split <;> split <;> (try split) <;> rfl
    have hpend : s1.pending = 0 := by rw [← hs1]; exact ksubmit_pending _
    have hcap1 : s1.cap = s.cap := by
      rw [← hs1]; unfold ksubmit lazyArm; split <;> split <;> (try split) <;> rfl
    -- raw = 0 and n < max force the CQ to have been empty
    have hcq : s1.cq = [] := by
      unfold drain at hraw hnm; simp only at hraw hnm
      cases hq : s1.cq with
      | nil => rfl
      | cons x xs =>
        rw [hq] at hraw; cases mx with
        | zero => simp at hnm
        | succ k => simp at hraw
    cases ha : (drain s1 mx).1.armed
    · -- not armed: the fixed path re-arms (SQ is empty now)
      have hc2 : (drain s1 mx).1.cross = true := by simp [drain, hcross, hc]
      have hp2 : (drain s1 mx).1.pending < (drain s1 mx).1.cap := by
        simp [drain, hpend, hcap1, hcap]
      simp [lazyArm_cross_unarmed _ hc2 ha hp2]
    · -- armed: by the invariant the read is in flight
      have ha1 : s1.armed = true := by
        unfold drain at ha; simp only at ha; split at ha
        · cases ha
        · exact ha
      have hq : s1.armQ = false := by rw [← hs1]; exact ksubmit_armQ _
      rcases hI1 ha1 with h1 | h1 | h1
      · simp [hq] at h1
      · have : lazyArm (drain s1 mx).1 = (drain s1 mx).1 := by
          unfold lazyArm; simp [ha]
        rw [this]; simp [drain, h1]
      · simp [hcq] at h1
  · cases hb

/-! ## `min_complete` contract -/

def busy : W := ⟨true, true, 0, 8, false, true, 0, [false]⟩

/-- Docstring: "positive = block until at least this many CQEs are ready".
With one non-wakeup CQE ready, `poll(min_complete = 2)` returns 1 without
blocking (raw_consumed ≠ 0 skips phase 3). All in-tree callers pass
`min_complete = 1` (`http/_server_reactor_uring.mojo:206,852`), for which
this weakening is invisible. -/
theorem minComplete_weakened :
    (poll busy 2 64).n = 1 ∧ (poll busy 2 64).blocked = false := by decide

end Flare.L2.UringWakeup
