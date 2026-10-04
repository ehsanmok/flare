import Flare.L5_Concurrency.Thread

/-!
# Scheduler lifecycle bookkeeping: start rollback, stuck-worker indices,
# failing `pthread_join` / `pthread_detach`

Three sequential parts of `flare/runtime/scheduler.mojo` that the
interleaving model (`Flare.L5.Scheduler`) abstracts away.

1. **`start`'s rollback** (:578-633). Allocation order (:361-575): stop flag,
   shared listener (shared mode only), worker array, one stats cell per
   worker, one `SO_REUSEPORT` listener per worker plus the extras (prebind
   mode), then per worker a context and a `pthread_create`. When spawn `k`
   fails, the rollback joins the `k` spawned workers and frees the worker
   array, the `k` claimed contexts, the unclaimed one, the stats cells, the
   shared listener and the stop flag. The heap is a counter per resource;
   freeing a resource with count 0 sets `dbl` (double free), freeing anything
   a worker can reach while a worker thread is alive sets `uaf`.
2. **Drain's stuck-worker branch** (:846-897): the sweep appends `i` to
   `stuck` in increasing order; the branch pops `ctx_addrs[idx]` and
   `stats_addrs[idx]` for `idx` in `reversed(stuck)` (guarded by
   `idx < len`), and `_free_resources` frees what remains.
3. **POSIX return codes** of `pthread_join` / `pthread_detach`, replacing the
   success assumption of `Flare.L5.Scheduler`, and what the teardown does
   when they fail (`except: pass`, :596-600, :677-682, :846-855).
-/
namespace Flare.L5.Lifecycle

/-! ## 1. `start` rollback -/

/-- Heap resources of one `Scheduler.start`. -/
inductive Res where
  | stop | shared | warr
  | stats (i : Nat) | pwl (i : Nat) | ctx (i : Nat)
  deriving DecidableEq, Repr

structure H where
  cnt : Res → Nat
  thr : Nat
  dbl : Bool
  uaf : Bool

def H.empty : H := ⟨fun _ => 0, 0, false, false⟩

def alloc (r : Res) (h : H) : H :=
  { h with cnt := fun x => if x = r then h.cnt x + 1 else h.cnt x }

/-- Every resource but the worker array is reachable from a worker. -/
def free (r : Res) (h : H) : H :=
  if h.cnt r = 0 then { h with dbl := true }
  else { h with cnt := fun x => if x = r then h.cnt x - 1 else h.cnt x,
                uaf := h.uaf || (decide (h.thr > 0) && r != .warr) }

def join (h : H) : H := if h.thr = 0 then { h with dbl := true } else { h with thr := h.thr - 1 }

def allocR (f : Nat → Res) : Nat → H → H
  | 0, h => h
  | k + 1, h => alloc (f k) (allocR f k h)

def freeR (f : Nat → Res) : Nat → H → H
  | 0, h => h
  | k + 1, h => free (f k) (freeR f k h)

def joinR : Nat → H → H
  | 0, h => h
  | k + 1, h => join (joinR k h)

/-- Spawns `0..k-1` succeeded: context `i` allocated, thread `i` running.
mirrors flare/runtime/scheduler.mojo:545-590 @59bda50 -/
def spawnR : Nat → H → H
  | 0, h => h
  | k + 1, h => { (alloc (.ctx k) (spawnR k h)) with thr := (spawnR k h).thr + 1 }

/-- Allocation before the first spawn; `pre` is `prebind_per_worker`, `L`
the number of per-worker listeners (`n * (1 + len(extra_addrs))`).
mirrors flare/runtime/scheduler.mojo:361-543 @59bda50 -/
def startAlloc (pre : Bool) (n L : Nat) : H :=
  let h := alloc .stop H.empty
  let h := if pre then h else alloc .shared h
  let h := alloc .warr h
  let h := allocR .stats n h
  if pre then allocR .pwl L h else h

/-- `start` with spawn `k` failing, then the rollback; `fix` adds the
CONC-06 fix (free `_per_worker_listener_addrs`).
mirrors flare/runtime/scheduler.mojo:572-633 @59bda50 -/
def startFail (fix pre : Bool) (n L k : Nat) : H :=
  let h := spawnR k (startAlloc pre n L)
  let h := alloc (.ctx k) h
  let h := joinR k h
  let h := free .warr h
  let h := freeR .ctx k h
  let h := free (.ctx k) h
  let h := freeR .stats n h
  let h := if pre then h else free .shared h
  let h := if fix && pre then freeR .pwl L h else h
  free .stop h

/-- `_abandon_start` after a failed per-worker bind, before any spawn:
`b` listeners stored so far. `_free_resources` then the worker array.
mirrors flare/runtime/scheduler.mojo:511-543,643-653,703-744 @59bda50 -/
def abandon (n b : Nat) : H :=
  let h := alloc .stop H.empty
  let h := alloc .warr h
  let h := allocR .stats n h
  let h := allocR .pwl b h
  let h := freeR .pwl b h
  let h := freeR .stats n h
  let h := free .stop h
  free .warr h

/-- How many `i < k` have `f i = r`. -/
def hits (f : Nat → Res) : Nat → Res → Nat
  | 0, _ => 0
  | k + 1, r => hits f k r + if f k = r then 1 else 0

theorem hits_ne {f : Nat → Res} {r : Res} (h : ∀ i, f i ≠ r) : ∀ k, hits f k r = 0
  | 0 => rfl
  | k + 1 => by simp [hits, hits_ne h k, h k]

theorem hits_inj {f : Nat → Res} (hf : ∀ i j, f i = f j → i = j) (i : Nat) :
    ∀ k, hits f k (f i) = if i < k then 1 else 0
  | 0 => by simp [hits]
  | k + 1 => by
    rw [hits, hits_inj hf i k]
    by_cases hki : k = i
    · subst hki; simp
    · have : f k ≠ f i := fun e => hki (hf _ _ e)
      simp only [this, if_false, Nat.add_zero]
      by_cases hik : i < k
      · simp [hik, show i < k + 1 by omega]
      · simp [hik, show ¬ i < k + 1 by omega]

theorem hits_le_succ (f : Nat → Res) (k : Nat) (r : Res) : hits f k r ≤ hits f (k + 1) r := by
  simp only [hits]; omega

theorem allocR_eq (f : Nat → Res) : ∀ k h, allocR f k h = { h with cnt := fun r => h.cnt r + hits f k r }
  | 0, h => by cases h; simp [allocR, hits]
  | k + 1, h => by
    rw [allocR, allocR_eq f k h]
    obtain ⟨cnt, thr, dbl, uaf⟩ := h
    simp only [alloc, hits, H.mk.injEq, and_true]
    funext x
    by_cases hx : x = f k
    · subst hx; simp; omega
    · have : f k ≠ x := fun e => hx e.symm
      simp [hx, this]

theorem freeR_eq (f : Nat → Res) : ∀ k h, h.thr = 0 → (∀ r, hits f k r ≤ h.cnt r) →
    freeR f k h = { h with cnt := fun r => h.cnt r - hits f k r }
  | 0, h, _, _ => by cases h; simp [freeR, hits]
  | k + 1, h, ht, hle => by
    rw [freeR, freeR_eq f k h ht (fun r => Nat.le_trans (hits_le_succ f k r) (hle r))]
    have hpos : h.cnt (f k) - hits f k (f k) ≠ 0 := by
      have := hle (f k); simp only [hits, if_true] at this; omega
    obtain ⟨cnt, thr, dbl, uaf⟩ := h
    simp only at ht hpos
    subst ht
    simp only [free, hpos, if_false, H.mk.injEq, gt_iff_lt, Nat.lt_irrefl,
      decide_false, Bool.false_and, Bool.or_false, and_true]
    funext x; simp only [hits]
    by_cases hx : x = f k
    · subst hx; simp; omega
    · have : f k ≠ x := fun e => hx e.symm
      simp [hx, this]

theorem spawnR_eq : ∀ k h, spawnR k h = { h with cnt := fun r => h.cnt r + hits .ctx k r, thr := h.thr + k }
  | 0, h => by cases h; simp [spawnR, hits]
  | k + 1, h => by
    rw [spawnR, spawnR_eq k h]
    obtain ⟨cnt, thr, dbl, uaf⟩ := h
    simp only [alloc, hits, H.mk.injEq, and_true]
    refine ⟨?_, by omega⟩
    funext x
    by_cases hx : x = .ctx k
    · subst hx; simp; omega
    · have : Res.ctx k ≠ x := fun e => hx e.symm
      simp [hx, this]

theorem joinR_eq : ∀ k h, k ≤ h.thr → joinR k h = { h with thr := h.thr - k }
  | 0, h, _ => by cases h; simp [joinR]
  | k + 1, h, hk => by
    rw [joinR, joinR_eq k h (by omega)]
    obtain ⟨cnt, thr, dbl, uaf⟩ := h
    have hk' : k + 1 ≤ thr := hk
    have hne : ¬ (thr - k = 0) := by omega
    simp only [join, hne, if_false]
    congr 1

theorem ctx_inj : ∀ i j, Res.ctx i = Res.ctx j → i = j := fun _ _ h => by cases h; rfl
theorem stats_inj : ∀ i j, Res.stats i = Res.stats j → i = j := fun _ _ h => by cases h; rfl
theorem pwl_inj : ∀ i j, Res.pwl i = Res.pwl j → i = j := fun _ _ h => by cases h; rfl

/-- `hits` of each family, by cases on the resource. -/
theorem hits_ctx (k : Nat) : ∀ r, hits .ctx k r = match r with | .ctx i => if i < k then 1 else 0 | _ => 0
  | .ctx i => hits_inj ctx_inj i k
  | .stop => hits_ne (fun _ h => by cases h) k
  | .shared => hits_ne (fun _ h => by cases h) k
  | .warr => hits_ne (fun _ h => by cases h) k
  | .stats _ => hits_ne (fun _ h => by cases h) k
  | .pwl _ => hits_ne (fun _ h => by cases h) k

theorem hits_stats (k : Nat) : ∀ r, hits .stats k r = match r with | .stats i => if i < k then 1 else 0 | _ => 0
  | .stats i => hits_inj stats_inj i k
  | .stop => hits_ne (fun _ h => by cases h) k
  | .shared => hits_ne (fun _ h => by cases h) k
  | .warr => hits_ne (fun _ h => by cases h) k
  | .ctx _ => hits_ne (fun _ h => by cases h) k
  | .pwl _ => hits_ne (fun _ h => by cases h) k

theorem hits_pwl (k : Nat) : ∀ r, hits .pwl k r = match r with | .pwl i => if i < k then 1 else 0 | _ => 0
  | .pwl i => hits_inj pwl_inj i k
  | .stop => hits_ne (fun _ h => by cases h) k
  | .shared => hits_ne (fun _ h => by cases h) k
  | .warr => hits_ne (fun _ h => by cases h) k
  | .ctx _ => hits_ne (fun _ h => by cases h) k
  | .stats _ => hits_ne (fun _ h => by cases h) k

theorem hits_pos {f : Nat → Res} {r : Res} : ∀ k, hits f k r ≠ 0 → ∃ i, i < k ∧ f i = r
  | 0, h => absurd rfl h
  | k + 1, h => by
    by_cases hk : f k = r
    · exact ⟨k, by omega, hk⟩
    · simp only [hits, hk, if_false, Nat.add_zero] at h
      obtain ⟨i, hi, e⟩ := hits_pos k h
      exact ⟨i, by omega, e⟩

/-- `freeR` over one injective family whose first `k` members are allocated. -/
theorem freeR_fam (f : Nat → Res) (hf : ∀ i j, f i = f j → i = j) (k : Nat) (h : H)
    (ht : h.thr = 0) (hc : ∀ i, i < k → 1 ≤ h.cnt (f i)) :
    freeR f k h = { h with cnt := fun r => h.cnt r - hits f k r } := by
  apply freeR_eq f k h ht
  intro r
  by_cases h0 : hits f k r = 0
  · omega
  · obtain ⟨i, hi, rfl⟩ := hits_pos k h0
    rw [hits_inj hf i k, if_pos hi]; exact hc i hi

theorem freeR_ctx (k : Nat) (h : H) (ht : h.thr = 0) (hc : ∀ i, i < k → 1 ≤ h.cnt (.ctx i)) :
    freeR .ctx k h = { h with cnt := fun r => h.cnt r - hits .ctx k r } :=
  freeR_fam _ ctx_inj k h ht hc
theorem freeR_stats (k : Nat) (h : H) (ht : h.thr = 0) (hc : ∀ i, i < k → 1 ≤ h.cnt (.stats i)) :
    freeR .stats k h = { h with cnt := fun r => h.cnt r - hits .stats k r } :=
  freeR_fam _ stats_inj k h ht hc
theorem freeR_pwl (k : Nat) (h : H) (ht : h.thr = 0) (hc : ∀ i, i < k → 1 ≤ h.cnt (.pwl i)) :
    freeR .pwl k h = { h with cnt := fun r => h.cnt r - hits .pwl k r } :=
  freeR_fam _ pwl_inj k h ht hc

theorem joinR_all (k : Nat) (h : H) (hk : h.thr = k) : joinR k h = { h with thr := 0 } := by
  rw [joinR_eq k h (by omega)]; congr 1; omega

/-- What a rollback leaves allocated. -/
def leftover (fix pre : Bool) (L : Nat) : Res → Nat
  | .pwl i => if !fix && pre && decide (i < L) then 1 else 0
  | _ => 0

/-- The rollback, in closed form, for every `n`, every listener count `L`
and every failing spawn index `k`: no double free, nothing freed under a
live worker, every spawned worker joined, and allocated afterwards exactly
`leftover`. -/
theorem free_pos (r : Res) (h : H) (hc : h.cnt r ≠ 0) (ht : h.thr = 0) :
    free r h = { h with cnt := fun x => if x = r then h.cnt x - 1 else h.cnt x } := by
  obtain ⟨cnt, thr, dbl, uaf⟩ := h
  dsimp only at hc ht; subst ht
  simp [free, hc]

/-- Counts after each phase of `startFail` (all with no live thread, no
double free, no use-after-free). -/
def cA (pre : Bool) (n L : Nat) : Res → Nat
  | .stop => 1
  | .shared => if pre then 0 else 1
  | .warr => 1
  | .stats i => if i < n then 1 else 0
  | .pwl i => if pre && decide (i < L) then 1 else 0
  | .ctx _ => 0

def cB (pre : Bool) (n L k : Nat) : Res → Nat
  | .ctx i => if i < k + 1 then 1 else 0
  | r => cA pre n L r

def cC (pre : Bool) (n L : Nat) : Res → Nat
  | .warr => 0
  | .ctx _ => 0
  | r => cA pre n L r

def cD (pre : Bool) (L : Nat) : Res → Nat
  | .stop => 1
  | .pwl i => if pre && decide (i < L) then 1 else 0
  | _ => 0

theorem phaseA (pre : Bool) (n L : Nat) : startAlloc pre n L = ⟨cA pre n L, 0, false, false⟩ := by
  cases pre <;>
  · simp only [startAlloc, allocR_eq, alloc, H.empty, if_true, if_false, Bool.false_eq_true,
      H.mk.injEq, and_true]
    funext r; cases r <;> simp [cA, hits_stats, hits_pwl]

theorem phaseB (pre : Bool) (n L k : Nat) :
    joinR k (alloc (.ctx k) (spawnR k ⟨cA pre n L, 0, false, false⟩)) = ⟨cB pre n L k, 0, false, false⟩ := by
  rw [joinR_all k _ (by simp [spawnR_eq, alloc])]
  simp only [spawnR_eq, alloc, H.mk.injEq, and_true]
  funext r; cases r <;> simp [cB, cA, hits_ctx]
  rename_i i; (repeat' split) <;> omega

theorem phaseC (pre : Bool) (n L k : Nat) :
    free (.ctx k) (freeR .ctx k (free .warr ⟨cB pre n L k, 0, false, false⟩)) =
      ⟨cC pre n L, 0, false, false⟩ := by
  rw [free_pos .warr _ (by simp [cB, cA]) rfl]
  rw [freeR_ctx k _ rfl (by intro i hi; simp [cB, show i < k + 1 by omega])]
  rw [free_pos (.ctx k) _ (by simp [cB, hits_ctx]) rfl]
  simp only [H.mk.injEq, and_true]
  funext r; cases r <;> simp [cC, cB, cA, hits_ctx]
  rename_i i; (repeat' split) <;> omega

theorem phaseD (pre : Bool) (n L : Nat) :
    (if pre then freeR .stats n ⟨cC pre n L, 0, false, false⟩
      else free .shared (freeR .stats n ⟨cC pre n L, 0, false, false⟩)) = ⟨cD pre L, 0, false, false⟩ := by
  rw [freeR_stats n _ rfl (by intro i hi; simp [cC, cA, hi])]
  cases pre
  · simp only [Bool.false_eq_true, if_false]
    rw [free_pos .shared _ (by simp [cC, cA, hits_stats]) rfl]
    simp only [H.mk.injEq, and_true]
    funext r; cases r <;> simp [cD, cC, cA, hits_stats]
  · simp only [if_true, H.mk.injEq, and_true]
    funext r; cases r <;> simp [cD, cC, cA, hits_stats]

theorem phaseE (fix pre : Bool) (L : Nat) :
    free .stop (if (fix && pre) = true then freeR .pwl L ⟨cD pre L, 0, false, false⟩
      else ⟨cD pre L, 0, false, false⟩) = ⟨leftover fix pre L, 0, false, false⟩ := by
  cases fix <;> cases pre
  all_goals simp only [Bool.and_true, Bool.and_false,
    Bool.false_eq_true, if_true, if_false]
  all_goals try rw [freeR_pwl L _ rfl (by intro i hi; simp [cD, hi])]
  all_goals rw [free_pos .stop _ (by simp [cD, hits_pwl]) rfl]
  all_goals simp only [H.mk.injEq, and_true]
  all_goals funext r; cases r <;> simp [cD, leftover, hits_pwl]

/-- The rollback, in closed form, for every `n`, every listener count `L`
and every failing spawn index `k`: no double free, nothing freed under a
live worker, every spawned worker joined, and allocated afterwards exactly
`leftover`. -/
theorem startFail_eq (fix pre : Bool) (n L k : Nat) :
    startFail fix pre n L k = ⟨leftover fix pre L, 0, false, false⟩ := by
  simp only [startFail]
  rw [phaseA, phaseB, phaseC]
  have hD := phaseD pre n L
  cases pre <;> simp only [Bool.false_eq_true, if_true, if_false] at hD ⊢ <;> rw [hD] <;>
    exact phaseE fix _ L

/-- Headline (bug side): flare's rollback in the per-worker listener mode
leaves every per-worker listener allocated (and nothing else). -/
theorem impl_rollback_leaks (n L k : Nat) (i : Nat) (hi : i < L) :
    (startFail false true n L k).cnt (.pwl i) = 1 := by
  rw [startFail_eq]; simp [leftover, hi]

/-- Headline (fix side): with the per-worker listeners freed too, a failed
`start` leaves nothing allocated, frees nothing twice, frees nothing under
a running worker and joins every spawned worker; in shared-listener mode
flare's own rollback already does. -/
theorem fixed_rollback_clean (pre : Bool) (n L k : Nat) :
    startFail true pre n L k = H.empty := by
  rw [startFail_eq]; simp only [H.empty, H.mk.injEq, and_true]
  funext r; cases r <;> simp [leftover]

theorem impl_rollback_clean_shared (n L k : Nat) : startFail false false n L k = H.empty := by
  rw [startFail_eq]; simp only [H.empty, H.mk.injEq, and_true]
  funext r; cases r <;> simp [leftover]

/-- `_abandon_start` (a failed per-worker bind before any spawn) is clean. -/
theorem abandon_clean (n b : Nat) : abandon n b = H.empty := by
  simp only [abandon, allocR_eq, alloc, H.empty]
  rw [freeR_pwl b _ rfl (by intro i hi; simp [hits_pwl, hi])]
  rw [freeR_stats n _ rfl (by intro i hi; simp [hits_pwl, hits_stats, hi])]
  rw [free_pos .stop _ (by simp [hits_pwl, hits_stats]) rfl]
  rw [free_pos .warr _ (by simp [hits_pwl, hits_stats]) rfl]
  simp only [H.mk.injEq, and_true]
  funext r; cases r <;> simp [hits_pwl, hits_stats] <;> split <;> omega

/-! ## 2. Drain's stuck-worker index bookkeeping -/

/-- Mojo `List.pop(idx)`.
mirrors flare/runtime/scheduler.mojo:893-896 @59bda50 -/
def eraseAt {α : Type} : List α → Nat → List α
  | [], _ => []
  | _ :: l, 0 => l
  | a :: l, i + 1 => a :: eraseAt l i

/-- The entries of `l` whose index satisfies `p`, in order. -/
def keepIdx {α : Type} (p : Nat → Bool) : List α → List α
  | [] => []
  | a :: l => if p 0 then a :: keepIdx (fun j => p (j + 1)) l else keepIdx (fun j => p (j + 1)) l

/-- The sweep appends `i` to `stuck` when worker `i` was detached.
mirrors flare/runtime/scheduler.mojo:845-855 @59bda50 -/
def sweepStuck (det : Nat → Bool) : Nat → List Nat
  | 0 => []
  | k + 1 => sweepStuck det k ++ (if det k then [k] else [])

/-- `for k in range(len(stuck) - 1, -1, -1): idx = stuck[k];
if idx < len(l): l.pop(idx)`.
mirrors flare/runtime/scheduler.mojo:890-896 @59bda50 -/
def popStuck {α : Type} (l : List α) (stuck : List Nat) : List α :=
  stuck.reverse.foldl (fun acc i => if i < acc.length then eraseAt acc i else acc) l

theorem mem_sweepStuck (det : Nat → Bool) (x : Nat) : ∀ k, x ∈ sweepStuck det k ↔ x < k ∧ det x = true
  | 0 => by simp [sweepStuck]
  | k + 1 => by
    rw [sweepStuck, List.mem_append, mem_sweepStuck det x k]
    by_cases hx : x = k
    · subst hx; by_cases hd : det x = true <;> simp [hd]
    · have : x < k + 1 ↔ x < k := by omega
      by_cases hd : det k = true <;> simp [hd, hx, this]

theorem sweepStuck_sorted (det : Nat → Bool) : ∀ k, (sweepStuck det k).Pairwise (· < ·)
  | 0 => List.Pairwise.nil
  | k + 1 => by
    rw [sweepStuck, List.pairwise_append]
    refine ⟨sweepStuck_sorted det k, ?_, ?_⟩
    · split <;> simp
    · intro a ha b hb
      have := ((mem_sweepStuck det a k).mp ha).1
      split at hb <;> simp_all

theorem keepIdx_congr {α : Type} : ∀ (l : List α) (p q : Nat → Bool),
    (∀ j, j < l.length → p j = q j) → keepIdx p l = keepIdx q l
  | [], _, _, _ => rfl
  | a :: l, p, q, h => by
    simp only [keepIdx, h 0 (by simp)]
    rw [keepIdx_congr l (fun j => p (j + 1)) (fun j => q (j + 1))
      (fun j hj => h (j + 1) (by simp; omega))]

theorem keepIdx_true {α : Type} : ∀ (l : List α), keepIdx (fun _ => true) l = l
  | [] => rfl
  | a :: l => by simp [keepIdx, keepIdx_true l]

/-- Popping index `i` = keeping by the predicate shifted past `i`. -/
theorem keepIdx_eraseAt {α : Type} : ∀ (l : List α) (i : Nat) (p : Nat → Bool),
    keepIdx p (eraseAt l i) =
      keepIdx (fun j => if j < i then p j else if j = i then false else p (j - 1)) l
  | [], _, _ => rfl
  | a :: l, 0, p => by simp [eraseAt, keepIdx]
  | a :: l, i + 1, p => by
    simp only [eraseAt, keepIdx, Nat.zero_lt_succ, if_true]
    rw [keepIdx_eraseAt l i (fun j => p (j + 1))]
    have : (fun j => if j < i then p (j + 1) else if j = i then false else p (j - 1 + 1)) =
        (fun j => if j + 1 < i + 1 then p (j + 1) else if j + 1 = i + 1 then false else p (j + 1 - 1)) := by
      funext j
      by_cases h1 : j < i
      · simp [h1]
      · by_cases h2 : j = i
        · simp [h2]
        · simp only [h1, h2, if_false, show ¬ j + 1 < i + 1 by omega, show ¬ j + 1 = i + 1 by omega,
            Nat.add_sub_cancel]
          congr 1; omega
    rw [this]

theorem contains_ge {d : List Nat} {i j : Nat} (hd : ∀ x ∈ d, x < i) (hj : i ≤ j) :
    d.contains j = false := by
  cases h : d.contains j
  · rfl
  · have := hd j (by simpa using h); omega

/-- Descending pops over a strictly decreasing index list keep exactly the
entries whose index is not in the list. -/
theorem foldl_pop {α : Type} : ∀ (d : List Nat) (l : List α), d.Pairwise (· > ·) →
    d.foldl (fun acc i => if i < acc.length then eraseAt acc i else acc) l =
      keepIdx (fun j => !d.contains j) l
  | [], l, _ => by simp [keepIdx_true]
  | i :: d, l, hp => by
    rw [List.pairwise_cons] at hp
    obtain ⟨hlt, hp⟩ := hp
    have hd : ∀ x ∈ d, x < i := fun x hx => hlt x hx
    rw [List.foldl_cons, foldl_pop d _ hp]
    split
    · rw [keepIdx_eraseAt]
      congr 1; funext j
      by_cases h1 : j < i
      · simp [h1, show j ≠ i by omega]
      · by_cases h2 : j = i
        · subst h2; simp
        · simp only [h1, h2, if_false, List.contains_cons]
          rw [contains_ge hd (show i ≤ j - 1 by omega), contains_ge hd (show i ≤ j by omega)]
          simp [show (j == i) = false from by simpa using h2]
    · rename_i hge
      apply keepIdx_congr
      intro j hj
      simp only [List.contains_cons]
      have : (j == i) = false := by simp; omega
      simp [this]

/-- Headline: drain's stuck-worker branch, for any `n`, any set of detached
workers and any list (`_ctx_addrs`, `_stats_addrs`, both indexed by worker
number), leaves exactly the entries of the workers that were *not*
detached — those `_free_resources` then frees — and removes exactly the
detached workers' entries (leaked for the live threads). The same predicate
applies to both lists, so they stay index-aligned. -/
theorem popStuck_keeps_joined {α : Type} (det : Nat → Bool) (n : Nat) (l : List α)
    (hl : l.length = n) : popStuck l (sweepStuck det n) = keepIdx (fun j => !det j) l := by
  rw [popStuck, foldl_pop _ _ (List.pairwise_reverse.mpr (sweepStuck_sorted det n))]
  apply keepIdx_congr
  intro j hj
  rw [List.contains_reverse]
  have hm := mem_sweepStuck det j n
  have hjn : j < n := hl ▸ hj
  by_cases hd : det j = true
  · simp only [hd]; simpa using hm.mpr ⟨hjn, hd⟩
  · simp only [Bool.not_eq_true] at hd
    simp only [hd]; simpa using fun h => absurd (hm.mp h).2 (by simp [hd])

theorem mem_keepIdx {α : Type} : ∀ (l : List α) (p : Nat → Bool) (x : α),
    x ∈ keepIdx p l ↔ ∃ j, l[j]? = some x ∧ p j = true
  | [], _, _ => by simp [keepIdx]
  | a :: l, p, x => by
    have ih := mem_keepIdx l (fun j => p (j + 1)) x
    constructor
    · intro h
      simp only [keepIdx] at h
      split at h
      · rcases List.mem_cons.mp h with rfl | h
        · exact ⟨0, rfl, by assumption⟩
        · obtain ⟨j, hj, hp⟩ := ih.mp h; exact ⟨j + 1, hj, hp⟩
      · obtain ⟨j, hj, hp⟩ := ih.mp h; exact ⟨j + 1, hj, hp⟩
    · rintro ⟨j, hj, hp⟩
      simp only [keepIdx]
      cases j with
      | zero =>
        simp only [List.getElem?_cons_zero, Option.some.injEq] at hj; subst hj
        simp [hp]
      | succ j =>
        have : x ∈ keepIdx (fun j => p (j + 1)) l := ih.mpr ⟨j, hj, hp⟩
        split <;> simp_all

/-- Entry-level form: an entry is freed by `_free_resources` iff it is the
entry of a worker that was not detached. -/
theorem freed_iff_not_detached {α : Type} (det : Nat → Bool) (n : Nat) (l : List α)
    (hl : l.length = n) (x : α) :
    x ∈ popStuck l (sweepStuck det n) ↔ ∃ j, l[j]? = some x ∧ det j = false := by
  rw [popStuck_keeps_joined det n l hl, mem_keepIdx]
  simp

/-! ## 3. Failing `pthread_join` / `pthread_detach` -/

/-- POSIX error returns (IEEE 1003.1, `pthread_join` / `pthread_detach`). -/
inductive Rc where
  | ok | edeadlk | einval | esrch
  deriving DecidableEq, Repr

open Flare.L5.Thread in
/-- `pthread_join(t)` called by thread `caller`: `ESRCH` for a thread that
no longer exists (reaped), `EINVAL` for a non-joinable (detached) one,
`EDEADLK` when the thread joins itself. ("Another thread is already
joining" is `EINVAL` too; excluded by the single owner,
`Thread.at_most_one_effect`.) -/
def pjoin (selfJoin : Bool) : OsT → Rc
  | .reaped => .esrch
  | .detached => .einval
  | .joinable => if selfJoin then .edeadlk else .ok

open Flare.L5.Thread in
/-- `pthread_detach(t)`: `ESRCH` / `EINVAL` as above; detaching oneself is
allowed. -/
def pdetach : OsT → Rc
  | .reaped => .esrch
  | .detached => .einval
  | .joinable => .ok

open Flare.L5.Thread in
/-- With flare's handle discipline (move-only, zeroed on success, never
dropped live; `Flare.L5.Thread.inv_inductive`), a call on a live OS handle
always finds the thread joinable: `pthread_detach` cannot fail and
`pthread_join` fails only when a thread joins itself. -/
theorem live_handle_calls (lin : Bool) (s : St) (h : (handle (Cfg.real lin)).Reachable s)
    (hd : Handle) (hh : s.holds hd) (ht : hd.tid ≠ 0) (selfJoin : Bool) :
    pdetach s.os = .ok ∧ (pjoin selfJoin s.os = .ok ↔ selfJoin = false) := by
  have hos := (((inv_inductive lin).reachable s h).2.2.2.2.1 hd hh ht).2.2
  rw [hos]; cases selfJoin <;> simp [pdetach, pjoin]

/-- One worker at the teardown sweep: whether its `WORKER_STAT_DONE` was
seen (or `timeout_ms <= 0` / `shutdown`, where every worker is joined), and
the return code of the `join` (if done) or `detach` (if not). -/
structure WOut where
  done : Bool
  rc : Rc
  deriving DecidableEq, Repr

/-- The thread may still run after the sweep: it was detached, or its call
failed (with `EDEADLK` the caller *is* that worker). -/
def liveAfter (w : WOut) : Bool := !w.done || w.rc != .ok

/-- flare appends to `stuck` only when `detach` returned; a raising
`join`/`detach` falls into `except: pass` and the worker's resources are
freed with the rest (`_join_workers` has no stuck list at all).
mirrors flare/runtime/scheduler.mojo:670-689,846-855 @59bda50 -/
def keptImpl (w : WOut) : Bool := !w.done && w.rc == .ok

/-- Hardened variant: treat a failed call like a detached worker. -/
def keptFixed (w : WOut) : Bool := liveAfter w

def freedUnderLive (kept : WOut → Bool) (ws : List WOut) : Bool :=
  ws.any fun w => liveAfter w && !kept w

/-- What flare does when a call fails: the teardown frees resources of a
thread that may still run exactly when some call failed. -/
theorem impl_freed_under_live_iff (ws : List WOut) :
    freedUnderLive keptImpl ws = true ↔ ∃ w ∈ ws, w.rc ≠ .ok := by
  simp only [freedUnderLive, List.any_eq_true, liveAfter, keptImpl]
  constructor
  · rintro ⟨w, hw, h⟩
    refine ⟨w, hw, fun hr => ?_⟩
    simp [hr] at h
  · rintro ⟨w, hw, hr⟩
    refine ⟨w, hw, ?_⟩
    cases hd : w.done <;> simp [hr]

/-- When the teardown runs on a thread that is not one of the workers (as
every in-repo caller does: `HttpServer.serve*` calls `shutdown` on the
thread that called `start`, `flare/http/server.mojo:1173-1181,1312-1336,
1614-1628`), every return code is `ok` by `live_handle_calls`, and nothing
is freed under a live thread. -/
theorem impl_safe_of_external_caller (ws : List WOut) (h : ∀ w ∈ ws, w.rc = .ok) :
    freedUnderLive keptImpl ws = false := by
  cases hf : freedUnderLive keptImpl ws
  · rfl
  · obtain ⟨w, hw, hr⟩ := (impl_freed_under_live_iff ws).mp hf
    exact absurd (h w hw) hr

/-- The only reachable failure: `shutdown()` (or `drain(timeout_ms <= 0)`)
called from worker `i` itself joins itself, gets `EDEADLK`, and flare frees
that worker's context, stats cell and the stop flag under it. -/
theorem self_shutdown_frees_caller :
    freedUnderLive keptImpl [⟨true, pjoin true .joinable⟩] = true := by decide

/-- …whereas `drain(timeout_ms > 0)` from a worker detaches itself
(`pthread_detach(pthread_self())` succeeds) and keeps its resources. -/
theorem self_drain_keeps_caller :
    freedUnderLive keptImpl [⟨false, pdetach .joinable⟩] = false := by decide

/-- Hardened teardown: never frees under a possibly live thread. -/
theorem fixed_never_frees_live (ws : List WOut) : freedUnderLive keptFixed ws = false := by
  simp [freedUnderLive, keptFixed]

end Flare.L5.Lifecycle
