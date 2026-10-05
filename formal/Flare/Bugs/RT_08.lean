import Flare.Core

/-!
# RT-08: a failed `sem_open` crashes the process on Linux

flare/runtime/blocking.mojo `_pool_try_acquire` / `_pool_release` (pre-fix lines 185-206).

Status: resolved. Both functions now test the result with `_sem_open_failed`,
which rejects both 0 and -1, so a failed `sem_open` takes the fail-open branch
on Linux too (tests: tests/runtime/test_block_in_pool.mojo::
test_acquire_survives_sem_open_failure and ::test_release_survives_sem_open_failure).
The counterexample below is about the pre-fix definitions `tryAcquireOld` /
`releaseOld`.

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
(PLATFORM linux; now prints OK in the Linux container).
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

/-- Pre-fix `_pool_try_acquire`: only Darwin's `SEM_FAILED` (-1) is a failure.
(pre-fix lines 185-193) -/
def tryAcquireOld (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool) : Outcome :=
  let sem := semOpen p ok handle
  if sem = -1 then .acquired true else semOp sem (.acquired waitOk)

/-- Pre-fix `_pool_release` (pre-fix lines 199-206). -/
def releaseOld (p : Platform) (ok : Bool) (handle : Int) : Outcome :=
  let sem := semOpen p ok handle
  if sem = -1 then .released else semOp sem .released

/-- mirrors flare/runtime/blocking.mojo `_pool_try_acquire`, `_sem_open_failed` (fixed, RT-08)
Both 0 and -1 count as a failed open, whatever the platform. (Fail-open is kept,
independent of RT-07.) -/
def tryAcquire (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool) : Outcome :=
  let sem := semOpen p ok handle
  if sem = 0 ∨ sem = -1 then .acquired true else semOp sem (.acquired waitOk)

/-- mirrors flare/runtime/blocking.mojo `_pool_release`, `_sem_open_failed` (fixed, RT-08) -/
def release (p : Platform) (ok : Bool) (handle : Int) : Outcome :=
  let sem := semOpen p ok handle
  if sem = 0 ∨ sem = -1 then .released else semOp sem .released

/-- **Counterexample** (pre-fix `tryAcquireOld` / `releaseOld`): on Linux, any
failed `sem_open` makes both the acquire and the release crash, whatever the handle would have been. -/
theorem linux_failure_crashes (handle : Int) (waitOk : Bool) :
    tryAcquireOld .linux false handle waitOk = .crash ∧
      releaseOld .linux false handle = .crash := by
  simp [tryAcquireOld, releaseOld, semOpen, semFailed, semOp]

/-- The check is right on macOS: there a failed `sem_open` takes the
fail-open branch. -/
theorem macos_failure_fails_open (handle : Int) (waitOk : Bool) :
    tryAcquireOld .macos false handle waitOk = .acquired true ∧
      releaseOld .macos false handle = .released := by
  simp [tryAcquireOld, releaseOld, semOpen, semFailed]

/-- **Shipped code meets spec**: on either platform, with `sem_open` failing or
returning a real handle, neither operation crashes. -/
theorem never_crashes (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool)
    (hv : Valid handle) :
    tryAcquire p ok handle waitOk ≠ .crash ∧ release p ok handle ≠ .crash := by
  obtain ⟨h0, h1⟩ := hv
  cases p <;> cases ok <;> simp [tryAcquire, release, semOpen, semFailed, semOp, h0, h1]

/-- The fix changes nothing where the original was right: on success, and
on any macOS call. -/
theorem agrees_with_old (p : Platform) (ok : Bool) (handle : Int) (waitOk : Bool)
    (hv : Valid handle) (h : ok = true ∨ p = .macos) :
    tryAcquire p ok handle waitOk = tryAcquireOld p ok handle waitOk ∧
      release p ok handle = releaseOld p ok handle := by
  obtain ⟨h0, h1⟩ := hv
  rcases h with h | h <;> subst h
  · cases p <;> simp [tryAcquire, tryAcquireOld, release, releaseOld, semOpen,
      semFailed, semOp, h0, h1]
  · cases ok <;> simp [tryAcquire, tryAcquireOld, release, releaseOld, semOpen,
      semFailed, semOp, h0, h1]

end Flare.Bugs.RT_08
