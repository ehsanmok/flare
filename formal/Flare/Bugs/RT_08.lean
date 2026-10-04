import Flare.Core

/-!
# RT-08: a failed `sem_open` crashes the process on Linux

flare/runtime/blocking.mojo:185-206 @59bda50.

Spec (docstring of `_pool_try_acquire`, comment at :130-132): if the
semaphore cannot be opened, the cap is skipped and the work still runs
("best-effort, never a hard dependency").

What goes wrong: both `_pool_try_acquire` and `_pool_release` detect a
failed `sem_open` with `Int(sem) == -1`. That is Darwin's `SEM_FAILED`
(`(sem_t *)-1`); glibc's is `(sem_t *)0`. On Linux a failed `sem_open`
(EMFILE once the fd table is full, the overload the cap exists for) slips
past the check and NULL goes to `sem_trywait` / `sem_post`, which
dereference it: SIGSEGV, and the whole server process dies. It also means
the fail-open branch RT-07 describes is unreachable on Linux.

The platform's `SEM_FAILED` is a fact about the C headers, taken as an
input here; the repro observes the crash.

Repro: formal/repro/RT-08_sem_open_failure_null_deref_linux.mojo
(PLATFORM linux).
-/
namespace Flare.Bugs.RT_08

inductive Platform
  | linux
  | macos
  deriving DecidableEq, Repr

/-- `SEM_FAILED`: glibc `((sem_t *) 0)`, Darwin `((sem_t *)-1)`. -/
def semFailed : Platform → Int
  | .linux => 0
  | .macos => -1

/-- A real semaphore mapping is never at address 0 or at the all-ones
address, so neither sentinel is a usable handle. -/
def Valid (h : Int) : Prop := h ≠ 0 ∧ h ≠ -1

/-- What `sem_open` returns: the mapped handle, or `SEM_FAILED`. -/
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

/-- mirrors flare/runtime/blocking.mojo:185-193 @59bda50 -/
def tryAcquireImpl (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool) : Outcome :=
  let sem := semOpen p ok handle
  if sem = -1 then .acquired true else semOp sem (.acquired waitOk)

/-- mirrors flare/runtime/blocking.mojo:199-206 @59bda50 -/
def releaseImpl (p : Platform) (ok : Bool) (handle : Int) : Outcome :=
  let sem := semOpen p ok handle
  if sem = -1 then .released else semOp sem .released

/-- Fix: compare against the platform's `SEM_FAILED`. (Fail-open is kept
so this is independent of RT-07; RT-07's fail-closed fix uses the same
test.) -/
def tryAcquireFixed (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool) : Outcome :=
  let sem := semOpen p ok handle
  if sem = semFailed p then .acquired true else semOp sem (.acquired waitOk)

def releaseFixed (p : Platform) (ok : Bool) (handle : Int) : Outcome :=
  let sem := semOpen p ok handle
  if sem = semFailed p then .released else semOp sem .released

/-- **Counterexample**: on Linux, any failed `sem_open` makes both the
acquire and the release crash, whatever the handle would have been. -/
theorem linux_failure_crashes (handle : Int) (waitOk : Bool) :
    tryAcquireImpl .linux false handle waitOk = .crash ∧
      releaseImpl .linux false handle = .crash := by
  simp [tryAcquireImpl, releaseImpl, semOpen, semFailed, semOp]

/-- The check is right on macOS: there a failed `sem_open` takes the
fail-open branch. -/
theorem macos_failure_fails_open (handle : Int) (waitOk : Bool) :
    tryAcquireImpl .macos false handle waitOk = .acquired true ∧
      releaseImpl .macos false handle = .released := by
  simp [tryAcquireImpl, releaseImpl, semOpen, semFailed]

/-- **Fix meets spec**: on either platform, with `sem_open` failing or
returning a real handle, neither operation crashes. -/
theorem fixed_never_crashes (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool)
    (hv : Valid handle) :
    tryAcquireFixed p ok handle waitOk ≠ .crash ∧ releaseFixed p ok handle ≠ .crash := by
  obtain ⟨h0, h1⟩ := hv
  cases p <;> cases ok <;> simp [tryAcquireFixed, releaseFixed, semOpen, semFailed, semOp, h0, h1]

/-- The fix changes nothing where the original was right: on success, and
on any macOS call. -/
theorem fixed_agrees (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool)
    (hv : Valid handle) (h : ok = true ∨ p = .macos) :
    tryAcquireFixed p ok handle waitOk = tryAcquireImpl p ok handle waitOk ∧
      releaseFixed p ok handle = releaseImpl p ok handle := by
  obtain ⟨h0, h1⟩ := hv
  rcases h with h | h <;> subst h
  · cases p <;> simp [tryAcquireFixed, tryAcquireImpl, releaseFixed, releaseImpl, semOpen,
      semFailed, semOp, h0, h1]
  · cases ok <;> simp [tryAcquireFixed, tryAcquireImpl, releaseFixed, releaseImpl, semOpen,
      semFailed, semOp, h0, h1]

end Flare.Bugs.RT_08
