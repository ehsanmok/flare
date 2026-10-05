import Flare.Core

/-!
# Blocking pool: the MAX_POOL_SIZE thread cap

`flare/runtime/blocking.mojo` (`MAX_POOL_SIZE`, `_pool_sem_open`, `_pool_try_acquire`, `_pool_release`). The cap is a POSIX named semaphore
created at `MAX_POOL_SIZE`. Each `_pool_try_acquire` / `_pool_release`
reopens it by name; whether that `sem_open` succeeds is an environment
input (`openOk`) to every step (on macOS arm64 it used to be `false` on every step because of the variadic-ABI bug, RT-06; `_pool_sem_open` now passes `mode`/`value` where the callee reads them, so `openOk` holds unless the system is out of fds or /dev/shm). `count` is the semaphore value, `held` the
number of slots handed out (acquires that returned `True` and are not yet
released). `sem_post` has no upper bound (POSIX), so a release always
increments when its `sem_open` succeeds.

Releases are always paired with an earlier successful acquire (flare's
callers do this), modelled by ignoring a release when `held = 0`.
-/
namespace Flare.L2.Blocking

/-- mirrors flare/runtime/blocking.mojo `MAX_POOL_SIZE` (fixed, RT-06) -/
def MAX_POOL_SIZE : Nat := 32

structure Sem where
  count : Nat
  held : Nat
  deriving DecidableEq, Repr

def Sem.init : Sem := ⟨MAX_POOL_SIZE, 0⟩

/-- Fail-open: a failed `sem_open` returns `True` without decrementing.
mirrors flare/runtime/blocking.mojo `_pool_try_acquire`, `_pool_sem_open` (fixed, RT-06) -/
def tryAcquire (openOk : Bool) (s : Sem) : Sem × Bool :=
  if !openOk then ({ s with held := s.held + 1 }, true)
  else if s.count > 0 then (⟨s.count - 1, s.held + 1⟩, true)
  else (s, false)

/-- Fail-closed fix: a failed `sem_open` refuses the slot. -/
def tryAcquireFixed (openOk : Bool) (s : Sem) : Sem × Bool :=
  if !openOk then (s, false)
  else if s.count > 0 then (⟨s.count - 1, s.held + 1⟩, true)
  else (s, false)

/-- mirrors flare/runtime/blocking.mojo `_pool_release`, `_pool_sem_open` (fixed, RT-06) -/
def release (openOk : Bool) (s : Sem) : Sem :=
  if s.held = 0 then s
  else ⟨if openOk then s.count + 1 else s.count, s.held - 1⟩

inductive Op
  | acq (openOk : Bool)
  | rel (openOk : Bool)

def Op.ok : Op → Bool
  | .acq b => b
  | .rel b => b

def runWith (acq : Bool → Sem → Sem × Bool) : Sem → List Op → Sem
  | s, [] => s
  | s, .acq b :: ops => runWith acq (acq b s).1 ops
  | s, .rel b :: ops => runWith acq (release b s) ops

def run := runWith tryAcquire
def runFixed := runWith tryAcquireFixed

/-- **Cap holds while `sem_open` works**: if every `sem_open` succeeds,
`count + held = MAX_POOL_SIZE` throughout, so at most 32 slots are held. -/
theorem paired_cap_invariant (ops : List Op) (hok : ∀ op ∈ ops, op.ok = true) (s : Sem)
    (hs : s.count + s.held = MAX_POOL_SIZE) :
    (run s ops).count + (run s ops).held = MAX_POOL_SIZE ∧ (run s ops).held ≤ MAX_POOL_SIZE := by
  induction ops generalizing s with
  | nil => exact ⟨hs, show s.held ≤ _ by omega⟩
  | cons op ops ih =>
    have hrest : ∀ op ∈ ops, op.ok = true := fun o h => hok o (List.mem_cons_of_mem _ h)
    cases op with
    | acq b =>
      have hb : b = true := hok (.acq b) List.mem_cons_self
      subst hb
      apply ih hrest
      unfold tryAcquire
      simp only [Bool.not_true, Bool.false_eq_true, if_false]
      split <;> simp <;> omega
    | rel b =>
      have hb : b = true := hok (.rel b) List.mem_cons_self
      subst hb
      apply ih hrest
      unfold release
      split
      · exact hs
      · simp; omega

/-- **Fix meets spec**: with the fail-closed acquire, `count + held ≤ 32`
whatever pattern of `sem_open` failures occurs, so at most 32 slots are
ever held. (A failed release `sem_open` can only tighten the cap.) -/
theorem fixed_cap_invariant (ops : List Op) (s : Sem) (hs : s.count + s.held ≤ MAX_POOL_SIZE) :
    (runFixed s ops).count + (runFixed s ops).held ≤ MAX_POOL_SIZE ∧
      (runFixed s ops).held ≤ MAX_POOL_SIZE := by
  induction ops generalizing s with
  | nil => exact ⟨hs, show s.held ≤ _ by omega⟩
  | cons op ops ih =>
    cases op with
    | acq b =>
      apply ih
      unfold tryAcquireFixed
      cases b <;> simp only [Bool.not_true, Bool.not_false, Bool.false_eq_true, if_false, if_true]
      · exact hs
      · split <;> simp <;> omega
    | rel b =>
      apply ih
      unfold release
      split
      · exact hs
      · cases b <;> simp <;> omega

theorem fixed_cap_from_init (ops : List Op) : (runFixed Sem.init ops).held ≤ MAX_POOL_SIZE :=
  (fixed_cap_invariant ops Sem.init (by decide)).2

end Flare.L2.Blocking
