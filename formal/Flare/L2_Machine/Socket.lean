import Flare.Core

/-!
# RawSocket fd ownership

`RawSocket` (flare/net/socket.mojo:111-220) owns one fd: `close()` is
idempotent (closes when `fd >= 0`, then sets `INVALID_FD`), `__deinit__`
closes when `fd >= 0`, and a move transfers the fd while the source is
declared dead (Mojo runs no destructor on a moved-from value). The struct
is `Movable` but not `Copyable`, so no operation duplicates an fd.

Two layers:
* object level: one `RawSocket`'s `fd` field and the number of `close(2)`
  calls each method issues;
* fd level: for one fd *incarnation* (one `socket()`/`accept()` result;
  the kernel may later reuse the number, which is a new incarnation) the
  number of live objects holding it and the number of times it was closed.
-/
namespace Flare.L2.Socket

def INVALID_FD : Int := -1

/-! ## Object level -/

/-- A live object's `fd` field after `close()`, and the closes issued.
mirrors flare/net/socket.mojo:210-218 @59bda50 -/
def close (fd : Int) : Int × Nat := if 0 ≤ fd then (INVALID_FD, 1) else (fd, 0)

/-- Closes issued by `__deinit__` (the object is gone afterwards).
mirrors flare/net/socket.mojo:200-208 @59bda50 -/
def deinit (fd : Int) : Nat := if 0 ≤ fd then 1 else 0

/-- `close()` is idempotent: a second call issues no `close(2)`. -/
theorem close_idempotent (fd : Int) :
    (close (close fd).1).2 = 0 ∧ (close (close fd).1).1 = (close fd).1 := by
  unfold close INVALID_FD; split <;> simp <;> omega

/-- Any sequence of `close()` calls followed by the destructor issues
exactly one `close(2)` for an open fd and none for `INVALID_FD`. -/
def closeN : Nat → Int → Int × Nat
  | 0, fd => (fd, 0)
  | n + 1, fd => let r := close fd; let r' := closeN n r.1; (r'.1, r.2 + r'.2)

theorem closes_then_deinit_exactly_once (n : Nat) (fd : Int) :
    (closeN n fd).2 + deinit (closeN n fd).1 = if 0 ≤ fd then 1 else 0 := by
  induction n generalizing fd with
  | zero => by_cases h : 0 ≤ fd <;> simp [closeN, deinit, h]
  | succ n ih =>
    simp only [closeN]
    rw [Nat.add_assoc, ih]
    unfold close INVALID_FD; split <;> simp <;> omega

/-! ## fd level -/

/-- Per-incarnation ghost state: live holders, kernel closes, acquired? -/
structure FdSt where
  holders : Nat
  closes : Nat
  got : Bool
  deriving DecidableEq, Repr

/-- What an object-level operation does to one fd incarnation `f`:
* `wrap`: `socket()`/`accept()` produced `f` and a RawSocket now owns it;
* `closeHolder`/`deinitHolder`: `close()`/`__deinit__` on the object holding `f`;
* `moveHolder`: `x^` moves the holder (source dead, destination holds `f`);
* `other`: any operation on an object not holding `f` (incl. `close()` on
  an object at `INVALID_FD`) — no effect on `f`. -/
inductive FdOp where
  | wrap | closeHolder | deinitHolder | moveHolder | other
  deriving DecidableEq, Repr

/-- mirrors flare/net/socket.mojo:143-220 @59bda50 -/
def fdStep (s : FdSt) : FdOp → Option FdSt
  | .wrap => if s.got then none else some { s with holders := s.holders + 1, got := true }
  | .closeHolder => if s.holders = 0 then none
      else some { s with holders := s.holders - 1, closes := s.closes + (close 0).2 }
  | .deinitHolder => if s.holders = 0 then none
      else some { s with holders := s.holders - 1, closes := s.closes + deinit 0 }
  | .moveHolder => if s.holders = 0 then none else some s
  | .other => some s

def FdM : LTS FdSt FdOp := LTS.ofFn (fun s => s = ⟨0, 0, false⟩) fdStep

/-- Conservation: holders + closes = 1 once acquired, 0 before. -/
def FdInv (s : FdSt) : Prop := s.holders + s.closes = if s.got then 1 else 0

theorem fdInv_inductive : FdM.Inductive FdInv := by
  constructor
  · intro s h; simp only [FdM, LTS.ofFn] at h; subst h; simp [FdInv]
  · intro s l s' hI h
    simp only [FdM, LTS.ofFn] at h
    unfold FdInv at *
    cases l <;> simp only [fdStep] at h
    · split at h
      · cases h
      · cases h; rename_i hg; simp [hg] at hI ⊢; omega
    all_goals first
      | (split at h; · cases h
         · cases h; simp only [close, deinit]; simp; omega)
      | (split at h; · cases h
         · cases h; exact hI)
      | (cases h; exact hI)

/-- Headline: along any trace from a fresh state, each fd incarnation is
closed at most once, and exactly once when no object holds it any more
(every owner was closed or destroyed). -/
theorem fd_closed_once (s : FdSt) (hr : FdM.Reachable s) :
    s.closes ≤ 1 ∧ (s.got = true → s.holders = 0 → s.closes = 1) := by
  have h := fdInv_inductive.reachable s hr
  unfold FdInv at h
  constructor
  · split at h <;> omega
  · intro hg hh; simp [hg] at h; omega

/-- Without the non-`Copyable` restriction a copy would make two holders
and the two destructors would close the fd twice (why `RawSocket` is not
`Copyable`). -/
theorem copy_would_double_close :
    let s : FdSt := ⟨2, 0, true⟩
    (fdStep s .deinitHolder >>= fun s => fdStep s .deinitHolder) = some ⟨0, 2, true⟩ := by
  decide

/-! ## Scheduler shared-listener patch -/

/-- Scheduler state for the shared listener: the raw copy of the fd kept
by the scheduler (`_shared_listener_fd`), the fd field of the typed
`TcpListener`, and the kernel close count of the listener incarnation. -/
structure Sched where
  rawFd : Int
  typedFd : Int
  closes : Nat
  deriving DecidableEq, Repr

/-- `_signal_and_close_listener`: close the raw fd and set it to -1.
mirrors flare/runtime/scheduler.mojo:655-668 @59bda50 -/
def signalAndClose (s : Sched) : Sched :=
  if 0 ≤ s.rawFd then { s with rawFd := -1, closes := s.closes + 1 } else s

/-- `_free_resources` for the shared listener: with `patch` (the code at
@59bda50) it sets the typed fd to -1 when the raw fd was already closed,
then runs the listener's destructor.
mirrors flare/runtime/scheduler.mojo:713-725 @59bda50 -/
def freeResources (patch : Bool) (s : Sched) : Sched :=
  let s1 := if patch ∧ s.rawFd < 0 then { s with typedFd := -1 } else s
  { s1 with closes := s1.closes + deinit s1.typedFd }

def signalN : Nat → Sched → Sched
  | 0, s => s
  | n + 1, s => signalN n (signalAndClose s)

theorem signalN_fd (n : Nat) (f : Nat) :
    signalN (n + 1) ⟨f, f, 0⟩ = ⟨-1, f, 1⟩ := by
  induction n with
  | zero => simp [signalN, signalAndClose]
  | succ n ih =>
    simp only [signalN] at *
    have : signalAndClose (⟨-1, f, 1⟩ : Sched) = ⟨-1, f, 1⟩ := by simp [signalAndClose]
    rw [show signalAndClose (signalAndClose ⟨f, f, 0⟩) = signalAndClose ⟨f, f, 0⟩ by
      simp [signalAndClose]] ; exact ih

/-- With the patch, any number of stop signals followed by the teardown
closes the listener exactly once. -/
theorem sched_patch_closes_once (n : Nat) (f : Nat) :
    (freeResources true (signalN n ⟨f, f, 0⟩)).closes = 1 := by
  cases n with
  | zero =>
    have : ¬ ((f : Int) < 0) := by omega
    simp [signalN, freeResources, deinit, this]
  | succ n => rw [signalN_fd]; simp [freeResources, deinit]

/-- Regression guard: without the patch, stop-then-teardown closes the
listener's fd number twice (the second close hits whatever reused it). -/
theorem sched_unpatched_double_close (f : Nat) :
    (freeResources false (signalN 1 ⟨f, f, 0⟩)).closes = 2 := by
  rw [signalN_fd]; simp [freeResources, deinit]

/-! ## `_set_timeval_opt` -/

/-- `sec = ms // 1000`, `usec = (ms % 1000) * 1000` with Mojo's floor
division. For the positive divisor 1000, floor division coincides with
Lean's Euclidean `Int` `/` and `%`.
mirrors flare/net/socket.mojo:481-509 @59bda50 -/
def timeval (ms : Int) : Int × Int := (ms / 1000, (ms % 1000) * 1000)

theorem fdiv_eq_ediv (ms : Int) : Int.fdiv ms 1000 = ms / 1000 ∧ Int.fmod ms 1000 = ms % 1000 :=
  ⟨by rw [Int.fdiv_eq_ediv]; simp, Int.fmod_eq_emod_of_nonneg _ (by decide)⟩

/-- For any `ms` the pair is a valid normalized timeval value of `ms`
milliseconds: `0 ≤ usec < 10^6` and `sec*1000 + usec/1000 = ms`. -/
theorem timeval_exact (ms : Int) :
    0 ≤ (timeval ms).2 ∧ (timeval ms).2 < 1000000 ∧
    (timeval ms).1 * 1000 + (timeval ms).2 / 1000 = ms := by
  simp only [timeval]; omega

/-- No Int64 overflow: both fields fit when `ms` does. -/
theorem timeval_fits (ms : Int) (h : fitsI64 ms) :
    fitsI64 (timeval ms).1 ∧ fitsI64 (timeval ms).2 := by
  unfold fitsI64 I64_MIN I64_MAX at *; simp only [timeval]; omega

/-- Note: a negative timeout gives a negative `tv_sec` (Linux then treats
the option as "no timeout"; macOS rejects it with EDOM). -/
theorem timeval_negative (ms : Int) (h : ms < 0) : (timeval ms).1 < 0 := by
  simp only [timeval]; omega

theorem timeval_minus_one : timeval (-1) = (-1, 999000) := by decide

/-! ## accept: wrap before decode -/

/-- What happened to the accepted fd. -/
inductive AcceptOut where
  | noFd     -- accept(2) failed, nothing to own
  | owned    -- returned inside a TcpStream
  | closed   -- an error was raised after wrapping; the RawSocket destructor closed it
  | leaked   -- an error was raised before wrapping
  deriving DecidableEq, Repr

/-- Pre-fix `TcpListener.accept` / `accept_fd`: `accept(2)`, then
`_sockaddr_to_socket_addr` (may raise), then wrap in `RawSocket`, then
`set_tcp_nodelay` (may raise).
(flare/tcp/listener.mojo:165-201,248-282 @59bda50) -/
def acceptImplOld (fd : Int) (decodeOk nodelayOk : Bool) : AcceptOut :=
  if fd < 0 then .noFd
  else if ¬ decodeOk then .leaked
  else if ¬ nodelayOk then .closed
  else .owned

/-- Shipped `TcpListener.accept` / `accept_fd` through `_adopt_accepted`:
`accept(2)`, then wrap in `RawSocket`, then the peer decode (may raise; the
socket's destructor closes the fd), then `set_tcp_nodelay` (may raise).
mirrors flare/tcp/listener.mojo:62-77, 238, 313 (fixed, NET-05) -/
def acceptImpl (fd : Int) (decodeOk nodelayOk : Bool) : AcceptOut :=
  if fd < 0 then .noFd
  else if ¬ decodeOk then .closed
  else if ¬ nodelayOk then .closed
  else .owned

/-- Spec: the accepted fd is never leaked. -/
def AcceptSpec (o : AcceptOut) : Prop := o ≠ .leaked

/-- **The fd is never leaked** whatever the decode or `nodelay` do. -/
theorem accept_never_leaks (fd : Int) (d n : Bool) : AcceptSpec (acceptImpl fd d n) := by
  unfold AcceptSpec acceptImpl
  repeat' split
  all_goals simp

/-- The fd is never leaked once it is wrapped (`nodelay` failures are safe). -/
theorem accept_nodelay_safe (fd : Int) (b : Bool) : acceptImpl fd true b ≠ .leaked :=
  accept_never_leaks fd true b

/-- The reorder changes nothing on the success path. -/
theorem acceptImpl_agrees (fd : Int) (n : Bool) : acceptImpl fd true n = acceptImplOld fd true n := by
  simp [acceptImpl, acceptImplOld]

end Flare.L2.Socket
