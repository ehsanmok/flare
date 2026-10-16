import Flare.Core

/-!
# Blocking pool: the MAX_POOL_SIZE thread cap

`flare/runtime/blocking.mojo` (`MAX_POOL_SIZE`, `_pool_sem_open`, `_pool_try_acquire`, `_pool_release`). The cap is a POSIX named semaphore
created at `MAX_POOL_SIZE`. Each `_pool_try_acquire` / `_pool_release`
reopens it by name; whether that `sem_open` succeeds is an environment
input (`openOk`) to every step (it holds unless the system is out of fds or /dev/shm). `count` is the semaphore value, `held` the
number of slots handed out (acquires that returned `True` and are not yet
released). `sem_post` has no upper bound (POSIX), so a release always
increments when its `sem_open` succeeds. The acquire is fail-closed.

Releases are always paired with an earlier successful acquire (flare's
callers do this), modelled by ignoring a release when `held = 0`.
-/
namespace Flare.L2.Blocking

/-- mirrors flare/runtime/blocking.mojo#MAX_POOL_SIZE sha=ef50dbf2cbfc at=966d2fbf (fixed, RT-06) -/
def MAX_POOL_SIZE : Nat := 32

structure Sem where
  count : Nat
  held : Nat
  deriving DecidableEq, Repr

def Sem.init : Sem := ⟨MAX_POOL_SIZE, 0⟩

/-- Shipped fail-closed acquire: a failed `sem_open` refuses the slot.
mirrors flare/runtime/blocking.mojo#_pool_try_acquire+_pool_sem_open sha=3d2c48d587d9 at=a246fb26 (fixed, RT-06, RT-07, RT-08) -/
def tryAcquire (openOk : Bool) (s : Sem) : Sem × Bool :=
  if !openOk then (s, false)
  else if s.count > 0 then (⟨s.count - 1, s.held + 1⟩, true)
  else (s, false)

/-- mirrors flare/runtime/blocking.mojo#_pool_release+_pool_sem_open sha=ae06cf9eb19b at=a246fb26 (fixed, RT-06, RT-07, RT-08) -/
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

/-- the shipped (fail-closed) system -/
def run := runWith tryAcquire

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

/-- **Shipped code meets spec**: with the fail-closed acquire, `count + held ≤ 32`
whatever pattern of `sem_open` failures occurs, so at most 32 slots are
ever held. (A failed release `sem_open` can only tighten the cap.) -/
theorem cap_invariant (ops : List Op) (s : Sem) (hs : s.count + s.held ≤ MAX_POOL_SIZE) :
    (run s ops).count + (run s ops).held ≤ MAX_POOL_SIZE ∧
      (run s ops).held ≤ MAX_POOL_SIZE := by
  induction ops generalizing s with
  | nil => exact ⟨hs, show s.held ≤ _ by omega⟩
  | cons op ops ih =>
    cases op with
    | acq b =>
      apply ih
      unfold tryAcquire
      cases b <;> simp only [Bool.not_true, Bool.not_false, Bool.false_eq_true, if_false, if_true]
      · exact hs
      · split <;> simp <;> omega
    | rel b =>
      apply ih
      unfold release
      split
      · exact hs
      · cases b <;> simp <;> omega

theorem cap_from_init (ops : List Op) : (run Sem.init ops).held ≤ MAX_POOL_SIZE :=
  (cap_invariant ops Sem.init (by decide)).2

/-! ## The `SEM_FAILED` check (RT-08)

`sem_open` returns `SEM_FAILED` on failure: glibc `((sem_t *) 0)`, Darwin
`((sem_t *)-1)`. `_sem_open_failed` treats both as a failure on every
platform; using a sentinel as a handle faults. -/

namespace SemOpen

inductive Platform
  | linux
  | macos
  deriving DecidableEq, Repr

def semFailed : Platform → Int
  | .linux => 0
  | .macos => -1

/-- A real semaphore mapping is never at address 0 or at the all-ones
address. -/
def Valid (h : Int) : Prop := h ≠ 0 ∧ h ≠ -1

def semOpen (p : Platform) (ok : Bool) (handle : Int) : Int :=
  if ok then handle else semFailed p

inductive Outcome
  | crash
  | acquired (b : Bool)
  | released
  deriving DecidableEq, Repr

/-- `sem_trywait` / `sem_post` on a pointer that is not a handle faults. -/
def semOp (sem : Int) (result : Outcome) : Outcome :=
  if sem = 0 ∨ sem = -1 then .crash else result

/-- A failed open refuses the slot (fail-closed, RT-07).
mirrors flare/runtime/blocking.mojo#_pool_try_acquire+_sem_open_failed sha=59686e26f106 at=ea1b9282 (fixed, RT-08) -/
def tryAcquire (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool) : Outcome :=
  let sem := semOpen p ok handle
  if sem = 0 ∨ sem = -1 then .acquired false else semOp sem (.acquired waitOk)

/-- mirrors flare/runtime/blocking.mojo#_pool_release+_sem_open_failed sha=26866880eab0 at=ea1b9282 (fixed, RT-08) -/
def release (p : Platform) (ok : Bool) (handle : Int) : Outcome :=
  let sem := semOpen p ok handle
  if sem = 0 ∨ sem = -1 then .released else semOp sem .released

/-- On either platform, whether `sem_open` fails or returns a real handle,
neither operation crashes. -/
theorem never_crashes (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool)
    (hv : Valid handle) :
    tryAcquire p ok handle waitOk ≠ .crash ∧ release p ok handle ≠ .crash := by
  obtain ⟨h0, h1⟩ := hv
  cases p <;> cases ok <;> simp [tryAcquire, release, semOpen, semFailed, semOp, h0, h1]

/-- A failed `sem_open` on either platform refuses the slot and releases
nothing. -/
theorem failure_fails_closed (p : Platform) (handle : Int) (waitOk : Bool) :
    tryAcquire p false handle waitOk = .acquired false ∧ release p false handle = .released := by
  cases p <;> simp [tryAcquire, release, semOpen, semFailed]

end SemOpen

end Flare.L2.Blocking
