import Flare.Core.LTS

/-!
# ThreadHandle: join / detach ownership

`flare/runtime/_thread.mojo` wraps one pthread (or one AsyncRT task, see
`Flare.L5.AsyncRT`) in a move-only `ThreadHandle`. `join` / `detach` call
`pthread_join` / `pthread_detach` (or `asyncrt_join` / `asyncrt_detach`)
and zero `_thread_id` on success; a zeroed handle makes both a no-op.
There is no `__del__`: dropping a live handle runs nothing.

## Model

One underlying thread, and handle *variables* (`a`, `b`) that may hold a
`Handle` or be uninitialised (`none`: moved-from or dropped). The handle is
only touched by its owning thread through `mut self`, so the handle-level
model is a sequential LTS whose non-determinism is the environment: the
return code of `pthread_join` / `pthread_detach` is a label parameter
(`ok`). Moves (`x^`) transfer the value and leave the source `none`; Mojo's
move checker rejects any later use of the source, which the model reflects
by disabling every operation on a `none` slot. `Cfg.allowAlias` adds a
bitwise copy (`memcpy`-style aliasing that bypasses the move checker) to
show what the zeroing does *not* protect against.

The concurrent part (the task racing the handle on the AsyncRT cell) lives
in `Flare.L5.AsyncRT`; this model supplies its `guard` premise: each
cell sees at most one `asyncrt_join`/`asyncrt_detach`.

Memory model: not relevant at this level (single owner thread, no shared
handle state); `pthread_join` is assumed to provide the usual
happens-before from the joined thread.
-/
namespace Flare.L5.Thread

/-- `_KIND_OS = 0`, `_KIND_ASYNCRT = 1` (`_thread.mojo:70-74`). -/
inductive Kind | os | asyncrt
  deriving DecidableEq, Repr

/-- POSIX state of the pthread: joinable until one successful
`pthread_join` (reaped) or `pthread_detach` (detached). -/
inductive OsT | joinable | detached | reaped
  deriving DecidableEq, Repr

/-- mirrors flare/runtime/_thread.mojo:118-128 @59bda50 -/
structure Handle where
  tid : Nat
  kind : Kind
  deriving DecidableEq, Repr

inductive Slot | a | b
  deriving DecidableEq, Repr

structure St where
  a : Option Handle
  b : Option Handle
  os : OsT
  /-- successful `pthread_join` + `pthread_detach` calls -/
  pthreadOps : Nat
  /-- `asyncrt_join` + `asyncrt_detach` calls -/
  cellOps : Nat
  /-- `pthread_join`/`pthread_detach` calls on a non-joinable thread (POSIX UB) -/
  ub : Nat
  /-- `pthread_setaffinity_np` on `pthread_t` 0 or a reaped thread (Linux) -/
  pinBad : Nat
  deriving DecidableEq, Repr

structure Cfg where
  allowAlias : Bool
  linux : Bool

def Cfg.real (linux : Bool) : Cfg := ⟨false, linux⟩

inductive Ev
  | join (x : Slot) (ok : Bool)
  | detach (x : Slot) (ok : Bool)
  | waitStarted (x : Slot)
  | pin (x : Slot)
  | move (x y : Slot)
  | drop (x : Slot)
  | alias (x y : Slot)
  deriving DecidableEq, Repr

def St.get (s : St) : Slot → Option Handle
  | .a => s.a
  | .b => s.b

def St.set (s : St) : Slot → Option Handle → St
  | .a, h => { s with a := h }
  | .b, h => { s with b := h }

/-- After `spawn` / `spawn_os` returned (`_thread.mojo:131-209`): the
handle is in `a`, the thread is joinable. -/
def init (k : Kind) : St :=
  { a := some ⟨1, k⟩, b := none, os := .joinable, pthreadOps := 0, cellOps := 0,
    ub := 0, pinBad := 0 }

def ubIf (o : OsT) : Nat := if o = .joinable then 0 else 1

/-- `ThreadHandle.join` on slot `x`.
mirrors flare/runtime/_thread.mojo:211-244 @59bda50 -/
def join (s : St) (x : Slot) (ok : Bool) : Option St :=
  match s.get x with
  | none => none
  | some h =>
    if h.tid = 0 then some s
    else match h.kind with
      | .asyncrt => some ({ s.set x (some { h with tid := 0 }) with cellOps := s.cellOps + 1 })
      | .os =>
        if ok then
          some ({ s.set x (some { h with tid := 0 }) with
            os := .reaped, pthreadOps := s.pthreadOps + 1, ub := s.ub + ubIf s.os })
        else some { s with ub := s.ub + ubIf s.os }

/-- `ThreadHandle.detach` on slot `x`.
mirrors flare/runtime/_thread.mojo:246-274 @59bda50 -/
def detach (s : St) (x : Slot) (ok : Bool) : Option St :=
  match s.get x with
  | none => none
  | some h =>
    if h.tid = 0 then some s
    else match h.kind with
      | .asyncrt => some ({ s.set x (some { h with tid := 0 }) with cellOps := s.cellOps + 1 })
      | .os =>
        if ok then
          some ({ s.set x (some { h with tid := 0 }) with
            os := .detached, pthreadOps := s.pthreadOps + 1, ub := s.ub + ubIf s.os })
        else some { s with ub := s.ub + ubIf s.os }

/-- `ThreadHandle.pin_to_cpu`: no-op for AsyncRT and on macOS; on Linux it
passes `_thread_id` to `pthread_setaffinity_np` with no zero check.
mirrors flare/runtime/_thread.mojo:289-346 @59bda50 -/
def pin (c : Cfg) (s : St) (x : Slot) : Option St :=
  match s.get x with
  | none => none
  | some h =>
    if h.kind = .os ∧ c.linux = true then
      some { s with pinBad := s.pinBad + (if h.tid = 0 ∨ s.os = .reaped then 1 else 0) }
    else some s

/-- Executable step. `waitStarted` has no effect at this level (its cell
access is modelled in `Flare.L5.AsyncRT`, guarded by `tid ≠ 0`,
`_thread.mojo:286`).
mirrors flare/runtime/_thread.mojo:211-346 @59bda50 -/
def stepFn (c : Cfg) (s : St) : Ev → Option St
  | .join x ok => join s x ok
  | .detach x ok => detach s x ok
  | .waitStarted x => (s.get x).map fun _ => s
  | .pin x => pin c s x
  | .move x y =>
    match s.get x, s.get y with
    | some h, none => if x = y then none else some ((s.set x none).set y (some h))
    | _, _ => none
  | .drop x => (s.get x).map fun _ => s.set x none
  | .alias x y =>
    match s.get x, s.get y with
    | some h, none => if x = y ∨ c.allowAlias = false then none else some (s.set y (some h))
    | _, _ => none

def handle (c : Cfg) : LTS St Ev := LTS.ofFn (fun s => ∃ k, s = init k) (stepFn c)

/-! ## Invariant -/

/-- Some slot holds `h`. -/
def St.holds (s : St) (h : Handle) : Prop := s.a = some h ∨ s.b = some h

def Inv (s : St) : Prop :=
  -- single owner: a move leaves the source empty
  ¬ (s.a.isSome ∧ s.b.isSome) ∧
  s.ub = 0 ∧
  s.pthreadOps + s.cellOps ≤ 1 ∧
  (s.os = .joinable ↔ s.pthreadOps = 0) ∧
  -- a live handle means nothing has been consumed yet
  (∀ h, s.holds h → h.tid ≠ 0 → s.pthreadOps = 0 ∧ s.cellOps = 0 ∧ s.os = .joinable) ∧
  -- AsyncRT handles never touch the pthread, OS handles never touch a cell
  (∀ h, s.holds h → (h.kind = .asyncrt → s.pthreadOps = 0) ∧ (h.kind = .os → s.cellOps = 0))

theorem inv_init (k : Kind) : Inv (init k) := by
  cases k <;> simp [Inv, init, St.holds]

theorem inv_step (lin : Bool) (s s' : St) (e : Ev) (hi : Inv s)
    (hs : stepFn (Cfg.real lin) s e = some s') : Inv s' := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := hi
  cases e with
  | join x ok =>
    cases x <;> cases ha : s.a <;> cases hb : s.b <;>
      simp_all [stepFn, join, St.get, St.set, St.holds] <;>
      (repeat' split at hs) <;> simp_all [Inv, St.holds, ubIf] <;> grind
  | detach x ok =>
    cases x <;> cases ha : s.a <;> cases hb : s.b <;>
      simp_all [stepFn, detach, St.get, St.set, St.holds] <;>
      (repeat' split at hs) <;> simp_all [Inv, St.holds, ubIf] <;> grind
  | waitStarted x =>
    simp only [stepFn, Option.map_eq_some_iff] at hs
    obtain ⟨_, _, rfl⟩ := hs
    exact ⟨h1, h2, h3, h4, h5, h6⟩
  | pin x =>
    cases x <;> simp_all [stepFn, pin, St.get] <;> (repeat' split at hs) <;>
      simp_all [Inv, St.holds] <;> grind
  | move x y =>
    cases x <;> cases y <;> cases ha : s.a <;> cases hb : s.b <;>
      simp_all [stepFn, St.get, St.set, Inv, St.holds] <;> grind
  | drop x =>
    cases x <;> cases ha : s.a <;> cases hb : s.b <;>
      simp_all [stepFn, St.get, St.set, Inv, St.holds] <;> grind
  | alias x y =>
    cases x <;> cases y <;> cases ha : s.a <;> cases hb : s.b <;>
      simp_all [stepFn, St.get, Cfg.real]

/-- General inductive invariant of the handle protocol (move checker in
force, either platform). -/
theorem inv_inductive (lin : Bool) : (handle (Cfg.real lin)).Inductive Inv where
  init := by rintro s ⟨k, rfl⟩; exact inv_init k
  step := fun s e s' hi hs => inv_step lin s s' e hi hs

/-! ## Headline properties -/

/-- At most one of `join` / `detach` takes effect: across both engines,
successful `pthread_join` + `pthread_detach` + `asyncrt_join` +
`asyncrt_detach` calls total at most one. -/
theorem at_most_one_effect (lin : Bool) (s : St) (h : (handle (Cfg.real lin)).Reachable s) :
    s.pthreadOps + s.cellOps ≤ 1 :=
  ((inv_inductive lin).reachable s h).2.2.1

/-- `pthread_join` / `pthread_detach` are never called on a thread that was
already joined or detached (no POSIX UB), even with failing return codes
and retries. -/
theorem no_posix_ub (lin : Bool) (s : St) (h : (handle (Cfg.real lin)).Reachable s) :
    s.ub = 0 :=
  ((inv_inductive lin).reachable s h).2.1

/-- Idempotence: on a zeroed handle `join` and `detach` change nothing
(join twice, detach after join, join after detach, detach twice). -/
theorem zeroed_noop (c : Cfg) (s : St) (x : Slot) (h : Handle) (hx : s.get x = some h)
    (hz : h.tid = 0) (ok : Bool) :
    stepFn c s (.join x ok) = some s ∧ stepFn c s (.detach x ok) = some s := by
  simp [stepFn, join, detach, hx, hz]

/-- A failed `pthread_join` / `pthread_detach` leaves the handle untouched
(the caller may retry or propagate). -/
theorem failed_call_keeps_handle (c : Cfg) (s s' : St) (x : Slot) (h : Handle)
    (hx : s.get x = some h) (hk : h.kind = .os) (hl : h.tid ≠ 0)
    (hs : stepFn c s (.join x false) = some s' ∨ stepFn c s (.detach x false) = some s') :
    s'.get x = some h ∧ s'.os = s.os ∧ s'.pthreadOps = s.pthreadOps := by
  rcases hs with hs | hs <;> simp [stepFn, join, detach, hx, hk, hl] at hs <;> subst hs <;>
    cases x <;> simp_all [St.get]

/-- Use of a moved-from (or dropped) handle: every operation on an empty
slot is disabled. In Mojo this is a compile-time error (move checker). -/
theorem moved_from_inert (c : Cfg) (s : St) (x : Slot) (hx : s.get x = none) (ok : Bool) :
    stepFn c s (.join x ok) = none ∧ stepFn c s (.detach x ok) = none ∧
    stepFn c s (.waitStarted x) = none ∧ stepFn c s (.pin x) = none ∧
    stepFn c s (.drop x) = none := by
  simp [stepFn, join, detach, pin, hx]

/-- No destructor: dropping the only live handle of a joinable pthread
leaves it joinable forever; no further step exists. This is the documented
contract (`_thread.mojo:20-22`: join before dropping, or detach). -/
theorem drop_live_leaks (lin : Bool) :
    ∃ s', (handle (Cfg.real lin)).Run (init .os) [.drop .a] s' ∧ s'.os = .joinable ∧
      ∀ e, stepFn (Cfg.real lin) s' e = none := by
  refine ⟨_, .cons (s' := (init .os).set .a none) rfl (.nil _), rfl, ?_⟩
  intro e
  rcases e with ⟨x, ok⟩ | ⟨x, ok⟩ | x | x | ⟨x, y⟩ | x | ⟨x, y⟩ <;> (try cases x) <;>
    (try cases y) <;> rfl

/-! ## Limits of the defence in depth -/

/-- Zeroing protects only the handle it is called on. A bitwise alias
(bypassing the move checker) joins the same pthread twice. Not reachable in
flare: `ThreadHandle` is `Movable`, not `Copyable`, and the one place that
builds a second handle to a running thread (`_worker.mojo:131`, wrapping
`pthread_self` for `pin_to_cpu`) never joins or detaches it. -/
theorem alias_double_join (lin : Bool) :
    ∃ s', (handle ⟨true, lin⟩).Run (init .os) [.alias .a .b, .join .a true, .join .b true] s' ∧
      s'.ub = 1 := by
  exact ⟨_, .cons rfl (.cons rfl (.cons rfl (.nil _))), rfl⟩

/-- `pin_to_cpu` has no zero check: on Linux, pinning a handle after `join`
passes `pthread_t` 0 to `pthread_setaffinity_np`. API hazard only: flare's
sole caller pins a fresh handle (`_worker.mojo:131-134`). -/
theorem pin_after_join_hazard :
    ∃ s', (handle (Cfg.real true)).Run (init .os) [.join .a true, .pin .a] s' ∧ s'.pinBad = 1 :=
  ⟨_, .cons rfl (.cons rfl (.nil _)), rfl⟩

/-- On macOS `pin_to_cpu` is a no-op, so the hazard is Linux-only. -/
theorem pin_noop_macos (s : St) (x : Slot) (h : Handle) (hx : s.get x = some h) :
    stepFn (Cfg.real false) s (.pin x) = some s := by
  simp [stepFn, pin, hx, Cfg.real]

end Flare.L5.Thread
