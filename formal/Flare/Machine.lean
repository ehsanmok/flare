import Flare.Core
/-!
# The top-level network abstract machine (one reactor worker)

This is the machine that composes the layers: the event loop of
`_reactor_loop_impl` (flare/http/_server_reactor_epoll.mojo:150-266) together
with the bookkeeping in flare/http/_reactor/lifecycle.mojo (`_apply_step`,
`_cleanup_conn`, `_arm_accept_timer`, `_accept_loop`).

A configuration holds

* `conns`  : the worker's `conns: Dict[Int, Int]` (fd → `ConnHandle`), here
  fd → the connection's state plus a ghost *incarnation* number `gen` that
  tells apart two connections that reuse the same fd number;
* `timers` : the worker's `timers: Dict[Int, UInt64]` (fd → timer id);
* `wheel`  : the active timers of the `TimerWheel`, at the level of its spec
  (`Flare.L2.TimerWheel`: `advance now` fires exactly the active timers with
  `fire_at ≤ now`, and a cancelled timer never fires). Each timer carries the
  fd it was scheduled with (flare passes `UInt64(fd)` as the payload) and, as
  ghost state, the incarnation that armed it;
* `batch`  : the reactor tokens returned by the last `reactor.poll`, not yet
  processed. The listener is registered with token `0`
  (`_server_reactor_epoll.mojo:155-158`) and every client with token = its fd
  (`lifecycle.mojo:236`).

Per-connection behaviour is a parameter (`ConnModel`): its step function sees
only the connection's own state and what the kernel shows it on this event,
and returns a `StepResult` (conn_handle.mojo). `Flare.L4.ConnSM` is one
instance; nothing here depends on which.

Results:

* `inv_reachable`, `no_stale_timer`: with `_cleanup_conn` cancelling the
  timer (flare's code), an idle timer only ever closes the incarnation that
  armed it, even when the kernel reuses the fd number.
  `stale_timer_without_cancel` shows the cancel is necessary: without it a
  timer armed by a closed connection closes the next connection on that fd.
* `no_early_close`, `no_late_close`: idle closes happen at the first poll at
  or after the deadline, never before.
* `conn_invariant_lifts`: any invariant of the per-connection model holds for
  every live connection of every reachable machine state, so layer-4 theorems
  about the connection state machine hold inside the server.
* `dispatch_isolated`: an event for one fd changes no other connection and no
  other `timers` entry.
* `stale_event_redelivered`: an event harvested by `poll` for one
  incarnation can be dispatched to a later incarnation on the same fd (fd
  reuse inside one batch). By `conn_invariant_lifts` this is harmless as long
  as the connection model tolerates spurious readiness, which level-triggered
  epoll requires anyway.
* `routing_ok`: with fd 0 in use (stdin open), no client has token 0, so the
  accept drainer only ever sees listener events.
  `fd0_reachable` / `fd0_never_served`: when fd 0 is free, `accept` can
  return fd 0, whose token collides with the listener's; that connection's
  state never changes again, because every event for it goes to the accept
  drainer. Only its idle timer (if any) ever closes it. This is MACH-01
  (`Flare.Bugs.MACH_01`); `HttpServer.serve` runs the same loop in
  `_unified_reactor_impl.mojo:1080-1160`.
-/
namespace Flare.Machine

abbrev Fd := Nat

/-- mirrors flare/http/_reactor/conn_handle.mojo `StepResult` @59bda50
(`want_read`, `want_write`, `done`, `idle_timeout_ms`; `h2c_upgrade` is not
modelled). `idleMs = 0` cancels the idle timer, `> 0` re-arms it, `< 0`
leaves it alone (lifecycle.mojo:105-114). -/
structure StepResult where
  wantRead : Bool
  wantWrite : Bool
  done : Bool
  idleMs : Int
  deriving DecidableEq, Repr

/-- Per-connection behaviour. `I` is what the kernel shows the connection on
one event (bytes, send capacity, EOF, ...); `onEvent` covers the whole
`on_readable` / `on_writable` fast path of one event, including the
exception-to-`done` mapping (`_server_reactor_epoll.mojo:199-252`). -/
structure ConnModel where
  S : Type
  I : Type
  init : S
  onEvent : S → I → S × StepResult
  /-- `config.idle_timeout_ms`, armed at accept (`_arm_accept_timer`). -/
  idleMs : Nat

/-- Environment and code variants. -/
structure Params where
  /-- the listener's own fd -/
  lfd : Fd
  /-- fd 0 is in use (stdin open), so `accept` never returns it -/
  stdinOpen : Bool
  /-- `_cleanup_conn` cancels the connection's timer (flare: `true`) -/
  cancelOnCleanup : Bool

structure Timer where
  id : Nat
  tok : Fd
  due : Nat
  /-- ghost: incarnation that armed the timer -/
  gen : Nat
  deriving DecidableEq, Repr

structure Live (S : Type) where
  st : S
  gen : Nat
  interest : Nat

/-- Ghost log entry: an idle timer closed connection `fd` (incarnation
`victim`); the timer had been armed by incarnation `armer`, was due at `due`
and fired in the poll at `time`. -/
structure Kill where
  fd : Fd
  victim : Nat
  armer : Nat
  due : Nat
  time : Nat
  deriving DecidableEq, Repr

structure Cfg (S : Type) where
  now : Nat
  conns : Fd → Option (Live S)
  timers : Fd → Option Nat
  wheel : List Timer
  nextTid : Nat
  nextGen : Nat
  batch : List Fd
  kills : List Kill

def upd {α : Type} (f : Fd → α) (k : Fd) (v : α) : Fd → α :=
  fun x => if x = k then v else f x

@[simp] theorem upd_same {α : Type} (f : Fd → α) (k : Fd) (v : α) : upd f k v k = v := by
  simp [upd]

theorem upd_other {α : Type} (f : Fd → α) {k x : Fd} (v : α) (h : x ≠ k) : upd f k v x = f x := by
  simp [upd, h]

inductive Label (I : Type) where
  /-- `reactor.poll` returns `toks`; then `wheel.advance(now)` and the fired loop -/
  | poll (now : Nat) (toks : List Fd)
  /-- one `listener.accept()` returning `fd`; `regOk`: `reactor.register` succeeded -/
  | accept (fd : Fd) (regOk : Bool)
  /-- the accept drain loop hits EAGAIN: the listener event is done -/
  | acceptDone
  /-- the head event has a client token; the kernel shows the connection `i` -/
  | dispatch (i : I)

section Defs
variable {S : Type}

def initCfg : Cfg S :=
  { now := 0, conns := fun _ => none, timers := fun _ => none, wheel := [],
    nextTid := 1, nextGen := 0, batch := [], kills := [] }

def setConn (c : Cfg S) (f : Fd) (v : Option (Live S)) : Cfg S :=
  { c with conns := upd c.conns f v }

/-- The cancel half of `_apply_step` / `_cleanup_conn`:
`_ = wheel.cancel(timers[fd]); _ = timers.pop(fd)`. -/
def cancelFd (c : Cfg S) (f : Fd) : Cfg S :=
  match c.timers f with
  | some tid => { c with wheel := c.wheel.filter (fun t => t.id ≠ tid), timers := upd c.timers f none }
  | none => c

/-- `timers[fd] = wheel.schedule(ms, UInt64(fd))`. -/
def schedule (c : Cfg S) (f : Fd) (ms gen : Nat) : Cfg S :=
  { c with wheel := c.wheel ++ [⟨c.nextTid, f, c.now + ms, gen⟩],
           timers := upd c.timers f (some c.nextTid), nextTid := c.nextTid + 1 }

/-- mirrors flare/http/_reactor/lifecycle.mojo:117-147 @59bda50
(`cancel = false` is the variant without the cancel at 129-137: the entry
is popped from `timers` but the timer stays in the wheel). -/
def cleanup (cancel : Bool) (c : Cfg S) (f : Fd) : Cfg S :=
  setConn (if cancel then cancelFd c f else { c with timers := upd c.timers f none }) f none

def interestOf (r : StepResult) (old : Nat) : Nat :=
  if r.wantRead || r.wantWrite then
    (if r.wantRead then 1 else 0) + (if r.wantWrite then 2 else 0)
  else old

def liveAfter (l : Live S) (st : S) (r : StepResult) : Live S :=
  { l with st := st, interest := interestOf r l.interest }

/-- mirrors flare/http/_reactor/lifecycle.mojo:80-114 @59bda50 -/
def applyStep (c : Cfg S) (f : Fd) (l : Live S) (st : S) (r : StepResult) : Cfg S :=
  if r.idleMs = 0 then cancelFd (setConn c f (some (liveAfter l st r))) f
  else if 0 < r.idleMs then
    schedule (cancelFd (setConn c f (some (liveAfter l st r))) f) f r.idleMs.toNat l.gen
  else setConn c f (some (liveAfter l st r))

def logKill (c : Cfg S) (k : Kill) : Cfg S := { c with kills := c.kills ++ [k] }

/-- The fired loop (`_server_reactor_epoll.mojo:175-178`):
`if fd_tok in conns: _cleanup_conn(fd_tok, ...)`. -/
def fireAll (cancel : Bool) (tm : Nat) : Cfg S → List Timer → Cfg S
  | c, [] => c
  | c, t :: ts =>
    match c.conns t.tok with
    | some l => fireAll cancel tm (cleanup cancel (logKill c ⟨t.tok, l.gen, t.gen, t.due, tm⟩) t.tok) ts
    | none => fireAll cancel tm c ts

/-- `reactor.poll` returned `toks`, then `wheel.advance(now, fired)` and the
fired loop (`_server_reactor_epoll.mojo:163-178`). -/
def pollStep (cancel : Bool) (c : Cfg S) (now : Nat) (toks : List Fd) : Cfg S :=
  fireAll cancel now { c with now := now, batch := toks, wheel := c.wheel.filter (fun t => now < t.due) }
    (c.wheel.filter (fun t => t.due ≤ now))

end Defs

/-- One iteration of `_accept_loop` that got a socket and registered it
(lifecycle.mojo:214-244). -/
def acceptStep (M : ConnModel) (c : Cfg M.S) (fd : Fd) : Cfg M.S :=
  if 0 < M.idleMs then
    schedule { setConn c fd (some ⟨M.init, c.nextGen, 1⟩) with nextGen := c.nextGen + 1 } fd M.idleMs c.nextGen
  else { setConn c fd (some ⟨M.init, c.nextGen, 1⟩) with nextGen := c.nextGen + 1 }

/-- `register` succeeded (`true`) or failed and the socket was dropped (`false`). -/
def acceptOr (M : ConnModel) (c : Cfg M.S) (fd : Fd) : Bool → Cfg M.S
  | true => acceptStep M c fd
  | false => c

/-- The per-event body of the loop (`_server_reactor_epoll.mojo:195-254`). -/
def dispatchAt (M : ConnModel) (P : Params) (c : Cfg M.S) (f : Fd) (i : M.I) : Cfg M.S :=
  match c.conns f with
  | none => c
  | some l =>
    if (M.onEvent l.st i).2.done then cleanup P.cancelOnCleanup c f
    else applyStep c f l (M.onEvent l.st i).1 (M.onEvent l.st i).2

/-- One machine step. -/
def step (M : ConnModel) (P : Params) (c : Cfg M.S) : Label M.I → Option (Cfg M.S)
  | .poll now toks =>
    if c.batch = [] ∧ c.now ≤ now ∧ toks.all (fun k => k = 0 || (c.conns k).isSome) = true then
      some (pollStep P.cancelOnCleanup c now toks)
    else none
  | .accept fd regOk =>
    if c.batch.head? = some 0 ∧ (c.conns fd).isNone = true ∧ fd ≠ P.lfd ∧ (P.stdinOpen = true → fd ≠ 0) then
      some (acceptOr M c fd regOk)
    else none
  | .acceptDone =>
    if c.batch.head? = some 0 then some { c with batch := c.batch.tail } else none
  | .dispatch i =>
    match c.batch with
    | f :: rest => if f = 0 then none else some (dispatchAt M P { c with batch := rest } f i)
    | [] => none

def lts (M : ConnModel) (P : Params) : LTS (Cfg M.S) (Label M.I) :=
  LTS.ofFn (fun c => c = initCfg) (step M P)

/-! ## Frame lemmas: what each helper touches -/

section Frame
variable {S : Type}

@[simp] theorem cancelFd_conns (c : Cfg S) (f : Fd) : (cancelFd c f).conns = c.conns := by
  unfold cancelFd; split <;> rfl

@[simp] theorem cancelFd_kills (c : Cfg S) (f : Fd) : (cancelFd c f).kills = c.kills := by
  unfold cancelFd; split <;> rfl

theorem cancelFd_timers_other (c : Cfg S) {f x : Fd} (hx : x ≠ f) :
    (cancelFd c f).timers x = c.timers x := by
  unfold cancelFd; split
  · exact upd_other _ _ hx
  · rfl

theorem cancelFd_wheel_sub (c : Cfg S) (f : Fd) : ∀ t ∈ (cancelFd c f).wheel, t ∈ c.wheel := by
  unfold cancelFd; split
  · intro t ht; exact (List.mem_filter.1 ht).1
  · intro t ht; exact ht

theorem cleanup_conns_self (b : Bool) (c : Cfg S) (f : Fd) : (cleanup b c f).conns f = none := by
  simp [cleanup, setConn]

theorem cleanup_conns_other {b : Bool} {c : Cfg S} {f x : Fd} (hx : x ≠ f) :
    (cleanup b c f).conns x = c.conns x := by
  cases b <;> simp [cleanup, setConn, upd, hx]

theorem cleanup_timers_other {b : Bool} {c : Cfg S} {f x : Fd} (hx : x ≠ f) :
    (cleanup b c f).timers x = c.timers x := by
  cases b
  · simp [cleanup, setConn, upd, hx]
  · simp only [cleanup, setConn, if_true]; exact cancelFd_timers_other c hx

theorem cleanup_wheel_sub {b : Bool} {c : Cfg S} {f : Fd} : ∀ t ∈ (cleanup b c f).wheel, t ∈ c.wheel := by
  intro t ht
  cases b
  · exact ht
  · exact cancelFd_wheel_sub c f t ht

theorem applyStep_conns_self (c : Cfg S) (f : Fd) (l : Live S) (st : S) (r : StepResult) :
    (applyStep c f l st r).conns f = some (liveAfter l st r) := by
  unfold applyStep
  split
  · simp [setConn]
  · split <;> simp [schedule, setConn]

theorem applyStep_conns_other (c : Cfg S) {f x : Fd} (l : Live S) (st : S) (r : StepResult) (hx : x ≠ f) :
    (applyStep c f l st r).conns x = c.conns x := by
  unfold applyStep
  split
  · simp [setConn, upd, hx]
  · split <;> simp [schedule, setConn, upd, hx]

theorem applyStep_timers_other (c : Cfg S) {f x : Fd} (l : Live S) (st : S) (r : StepResult) (hx : x ≠ f) :
    (applyStep c f l st r).timers x = c.timers x := by
  unfold applyStep
  split
  · rw [cancelFd_timers_other _ hx]; rfl
  · split
    · simp only [schedule]; rw [upd_other _ _ hx, cancelFd_timers_other _ hx]; rfl
    · rfl

theorem fireAll_wheel_sub (b : Bool) (tm : Nat) :
    ∀ (ts : List Timer) (c : Cfg S), ∀ t ∈ (fireAll b tm c ts).wheel, t ∈ c.wheel
  | [], c => fun t ht => ht
  | x :: ts, c => by
    intro t ht
    cases e : c.conns x.tok with
    | none => simp only [fireAll, e] at ht; exact fireAll_wheel_sub b tm ts c t ht
    | some l =>
      simp only [fireAll, e] at ht
      have h1 := fireAll_wheel_sub b tm ts _ t ht
      have h2 := cleanup_wheel_sub t h1
      exact h2

theorem fireAll_conns_sub (b : Bool) (tm : Nat) :
    ∀ (ts : List Timer) (c : Cfg S) (x : Fd) (l : Live S),
      (fireAll b tm c ts).conns x = some l → c.conns x = some l
  | [], _, _, _, h => h
  | t :: ts, c, x, l, h => by
    cases e : c.conns t.tok with
    | none => simp only [fireAll, e] at h; exact fireAll_conns_sub b tm ts c x l h
    | some l0 =>
      simp only [fireAll, e] at h
      have h1 := fireAll_conns_sub b tm ts _ x l h
      by_cases hx : x = t.tok
      · subst hx; rw [cleanup_conns_self] at h1; cases h1
      · rw [cleanup_conns_other hx] at h1; exact h1

theorem dispatchAt_conns_other (M : ConnModel) (P : Params) (c : Cfg M.S) {f x : Fd} (i : M.I)
    (hx : x ≠ f) : (dispatchAt M P c f i).conns x = c.conns x := by
  cases e : c.conns f with
  | none => simp only [dispatchAt, e]
  | some l =>
    simp only [dispatchAt, e]
    split
    · exact cleanup_conns_other hx
    · exact applyStep_conns_other _ _ _ _ hx

theorem dispatchAt_timers_other (M : ConnModel) (P : Params) (c : Cfg M.S) {f x : Fd} (i : M.I)
    (hx : x ≠ f) : (dispatchAt M P c f i).timers x = c.timers x := by
  cases e : c.conns f with
  | none => simp only [dispatchAt, e]
  | some l =>
    simp only [dispatchAt, e]
    split
    · exact cleanup_timers_other hx
    · exact applyStep_timers_other _ _ _ _ hx

theorem acceptStep_conns_other (M : ConnModel) (c : Cfg M.S) {fd x : Fd} (hx : x ≠ fd) :
    (acceptStep M c fd).conns x = c.conns x := by
  unfold acceptStep; split <;> simp [schedule, setConn, upd, hx]

end Frame

/-! ## Bookkeeping invariant -/

section Inv
variable {S : Type}

/-- Every active timer belongs to the live incarnation that armed it and is
the one recorded in `timers`; timer ids are fresh and distinct; every idle
close so far hit the incarnation that armed the timer, at or after the
deadline. -/
structure Inv (c : Cfg S) : Prop where
  own : ∀ t ∈ c.wheel, ∃ l, c.conns t.tok = some l ∧ l.gen = t.gen ∧ c.timers t.tok = some t.id
  fresh : ∀ t ∈ c.wheel, t.id < c.nextTid
  nodup : c.wheel.Pairwise (fun a b => a.id ≠ b.id)
  kills : ∀ k ∈ c.kills, k.victim = k.armer ∧ k.due ≤ k.time

theorem inv_init : Inv (initCfg : Cfg S) where
  own := by simp [initCfg]
  fresh := by simp [initCfg]
  nodup := by simp [initCfg]
  kills := by simp [initCfg]

/-- Two active timers on the same fd are the same timer. -/
theorem Inv.tok_unique {c : Cfg S} (h : Inv c) {a b : Timer} (ha : a ∈ c.wheel) (hb : b ∈ c.wheel)
    (hab : a.tok = b.tok) : a.id = b.id := by
  obtain ⟨_, _, _, ta⟩ := h.own a ha
  obtain ⟨_, _, _, tb⟩ := h.own b hb
  rw [hab, tb] at ta
  exact (Option.some.inj ta).symm

/-- After `cancelFd`, no active timer is on `f`. -/
theorem cancelFd_clear {c : Cfg S} (h : Inv c) (f : Fd) : ∀ t ∈ (cancelFd c f).wheel, t.tok ≠ f := by
  intro t ht htf
  cases e : c.timers f with
  | none =>
    simp only [cancelFd, e] at ht
    obtain ⟨_, _, _, d⟩ := h.own t ht
    rw [htf, e] at d; cases d
  | some tid =>
    simp only [cancelFd, e] at ht
    obtain ⟨hm, hne⟩ := List.mem_filter.1 ht
    obtain ⟨_, _, _, d⟩ := h.own t hm
    rw [htf, e] at d
    simp at hne
    exact hne (Option.some.inj d).symm

theorem cancelFd_inv {c : Cfg S} (h : Inv c) (f : Fd) : Inv (cancelFd c f) := by
  cases e : c.timers f with
  | none => simp only [cancelFd, e]; exact h
  | some tid =>
    simp only [cancelFd, e]
    refine ⟨?_, ?_, ?_, h.kills⟩
    · intro t ht
      obtain ⟨hm, hne⟩ := List.mem_filter.1 ht
      obtain ⟨l, a, b, d⟩ := h.own t hm
      have htf : t.tok ≠ f := by
        intro htf; rw [htf, e] at d; simp at hne; exact hne (Option.some.inj d).symm
      exact ⟨l, a, b, by simpa [upd, htf] using d⟩
    · intro t ht; exact h.fresh t (List.mem_filter.1 ht).1
    · exact h.nodup.sublist List.filter_sublist

theorem cleanup_inv {c : Cfg S} (h : Inv c) (f : Fd) : Inv (cleanup true c f) := by
  have h1 := cancelFd_inv h f
  have hcl := cancelFd_clear h f
  refine ⟨?_, h1.fresh, h1.nodup, h1.kills⟩
  intro t ht
  obtain ⟨l, a, b, d⟩ := h1.own t ht
  refine ⟨l, ?_, b, d⟩
  show upd (cancelFd c f).conns f none t.tok = some l
  rw [upd_other _ _ (hcl t ht)]; exact a

/-- Scheduling a timer for a live connection with no active timer keeps the invariant. -/
theorem schedule_inv {c : Cfg S} (h : Inv c) (f : Fd) (ms : Nat) (l : Live S)
    (hl : c.conns f = some l) (hclear : ∀ t ∈ c.wheel, t.tok ≠ f) :
    Inv (schedule c f ms l.gen) := by
  refine ⟨?_, ?_, ?_, h.kills⟩
  · intro t ht
    simp only [schedule, List.mem_append, List.mem_singleton] at ht
    rcases ht with ht | rfl
    · obtain ⟨l', a, b, d⟩ := h.own t ht
      exact ⟨l', a, b, by simpa [schedule, upd, hclear t ht] using d⟩
    · exact ⟨l, hl, rfl, by simp [schedule]⟩
  · intro t ht
    simp only [schedule, List.mem_append, List.mem_singleton] at ht
    rcases ht with ht | rfl
    · have := h.fresh t ht; simp only [schedule]; omega
    · simp [schedule]
  · simp only [schedule]
    rw [List.pairwise_append]
    refine ⟨h.nodup, by simp, ?_⟩
    intro a ha b hb
    simp only [List.mem_singleton] at hb
    subst hb
    have := h.fresh a ha
    simp only [ne_eq]; omega

theorem setConn_inv {c : Cfg S} (h : Inv c) (f : Fd) (l l' : Live S) (hl : c.conns f = some l)
    (hg : l'.gen = l.gen) : Inv (setConn c f (some l')) := by
  refine ⟨?_, h.fresh, h.nodup, h.kills⟩
  intro t ht
  obtain ⟨l0, a, b, d⟩ := h.own t ht
  by_cases e : t.tok = f
  · rw [e, hl] at a
    have := Option.some.inj a; subst this
    exact ⟨l', by simp [setConn, e], by rw [hg]; exact b, d⟩
  · exact ⟨l0, by simpa [setConn, upd, e] using a, b, d⟩

theorem applyStep_inv {c : Cfg S} (h : Inv c) (f : Fd) (l : Live S) (st : S) (r : StepResult)
    (hl : c.conns f = some l) : Inv (applyStep c f l st r) := by
  have h1 := setConn_inv h f l (liveAfter l st r) hl rfl
  have hl1 : (setConn c f (some (liveAfter l st r))).conns f = some (liveAfter l st r) := by
    simp [setConn]
  unfold applyStep
  split
  · exact cancelFd_inv h1 f
  · split
    · exact schedule_inv (cancelFd_inv h1 f) f r.idleMs.toNat (liveAfter l st r)
        (by rw [cancelFd_conns]; exact hl1) (cancelFd_clear h1 f)
    · exact h1

/-- The fired loop keeps the invariant and logs only correct kills, provided
the fired timers are due, pairwise on distinct fds, and each is owned by the
live incarnation that armed it. -/
theorem fireAll_inv (tm : Nat) :
    ∀ (ts : List Timer) (c : Cfg S), Inv c →
      (∀ t ∈ ts, t.due ≤ tm) →
      (∀ t ∈ ts, ∃ l, c.conns t.tok = some l ∧ l.gen = t.gen) →
      ts.Pairwise (fun a b => a.tok ≠ b.tok) →
      Inv (fireAll true tm c ts)
  | [], c, h, _, _, _ => h
  | t :: ts, c, h, hdue, hown, hpw => by
    obtain ⟨l, hl, hg⟩ := hown t (List.mem_cons_self ..)
    simp only [fireAll, hl]
    have hpw' := List.pairwise_cons.1 hpw
    have h1 : Inv (logKill c ⟨t.tok, l.gen, t.gen, t.due, tm⟩) := by
      refine ⟨h.own, h.fresh, h.nodup, ?_⟩
      intro k hk
      simp only [logKill, List.mem_append, List.mem_singleton] at hk
      rcases hk with hk | rfl
      · exact h.kills k hk
      · exact ⟨hg, hdue t (List.mem_cons_self ..)⟩
    refine fireAll_inv tm ts _ (cleanup_inv h1 t.tok)
      (fun x hx => hdue x (List.mem_cons_of_mem _ hx)) ?_ hpw'.2
    intro x hx
    obtain ⟨l', a, b⟩ := hown x (List.mem_cons_of_mem _ hx)
    exact ⟨l', by rw [cleanup_conns_other (fun e => hpw'.1 x hx e.symm)]; exact a, b⟩

theorem pollStep_inv {c : Cfg S} (h : Inv c) (now : Nat) (toks : List Fd) :
    Inv (pollStep true c now toks) := by
  unfold pollStep
  have hsub : ∀ t ∈ c.wheel.filter (fun t => t.due ≤ now), t ∈ c.wheel :=
    fun t ht => (List.mem_filter.1 ht).1
  apply fireAll_inv
  · refine ⟨?_, ?_, ?_, h.kills⟩
    · intro t ht; exact h.own t (List.mem_filter.1 ht).1
    · intro t ht; exact h.fresh t (List.mem_filter.1 ht).1
    · exact h.nodup.sublist List.filter_sublist
  · intro t ht; simpa using (List.mem_filter.1 ht).2
  · intro t ht
    obtain ⟨l, a, b, _⟩ := h.own t (hsub t ht)
    exact ⟨l, a, b⟩
  · have hn := h.nodup.sublist (List.filter_sublist (p := fun t => decide (t.due ≤ now)))
    exact List.Pairwise.imp_of_mem (fun ha hb hab e => hab (h.tok_unique (hsub _ ha) (hsub _ hb) e)) hn

theorem acceptStep_inv (M : ConnModel) {c : Cfg M.S} (h : Inv c) (fd : Fd) (hnone : c.conns fd = none) :
    Inv (acceptStep M c fd) := by
  have hclear : ∀ t ∈ c.wheel, t.tok ≠ fd := by
    intro t ht e
    obtain ⟨_, a, _, _⟩ := h.own t ht
    rw [e, hnone] at a; cases a
  have h1 : Inv { setConn c fd (some ⟨M.init, c.nextGen, 1⟩) with nextGen := c.nextGen + 1 } := by
    refine ⟨?_, h.fresh, h.nodup, h.kills⟩
    intro t ht
    obtain ⟨l, a, b, d⟩ := h.own t ht
    exact ⟨l, by simpa [setConn, upd, hclear t ht] using a, b, d⟩
  unfold acceptStep
  split
  · exact schedule_inv h1 fd M.idleMs ⟨M.init, c.nextGen, 1⟩ (by simp [setConn]) hclear
  · exact h1

theorem dispatchAt_inv (M : ConnModel) (P : Params) (hP : P.cancelOnCleanup = true)
    {c : Cfg M.S} (h : Inv c) (f : Fd) (i : M.I) : Inv (dispatchAt M P c f i) := by
  cases e : c.conns f with
  | none => simp only [dispatchAt, e]; exact h
  | some l =>
    simp only [dispatchAt, e]
    split
    · rw [hP]; exact cleanup_inv h f
    · exact applyStep_inv h f l _ _ e

theorem inv_step (M : ConnModel) (P : Params) (hP : P.cancelOnCleanup = true)
    (c c' : Cfg M.S) (lab : Label M.I) (h : Inv c) (hs : step M P c lab = some c') : Inv c' := by
  cases lab with
  | poll now toks =>
    simp only [step] at hs
    split at hs
    · cases hs; rw [hP]; exact pollStep_inv h now toks
    · cases hs
  | accept fd regOk =>
    simp only [step] at hs
    split at hs
    · rename_i hc
      cases hs
      cases regOk
      · exact h
      · simp only [acceptOr]; exact acceptStep_inv M h fd (Option.isNone_iff_eq_none.1 hc.2.1)
    · cases hs
  | acceptDone =>
    simp only [step] at hs
    split at hs
    · cases hs; exact ⟨h.own, h.fresh, h.nodup, h.kills⟩
    · cases hs
  | dispatch i =>
    simp only [step] at hs
    cases hb : c.batch with
    | nil => simp [hb] at hs
    | cons f rest =>
      simp only [hb] at hs
      split at hs
      · cases hs
      · cases hs
        exact dispatchAt_inv M P hP (c := { c with batch := rest }) ⟨h.own, h.fresh, h.nodup, h.kills⟩ f i

/-- **Bookkeeping invariant.** With flare's `_cleanup_conn` (timer cancelled),
`Inv` is an inductive invariant of the worker. -/
theorem inv_reachable (M : ConnModel) (P : Params) (hP : P.cancelOnCleanup = true) :
    (lts M P).Inductive Inv :=
  { init := fun s hs => by subst hs; exact inv_init
    step := fun s l s' h hs => inv_step M P hP s s' l h hs }

/-- **No stale timer.** In every reachable state of flare's worker, every
connection an idle timer has closed was the incarnation that armed the timer,
never a later connection that reused the fd number. -/
theorem no_stale_timer (M : ConnModel) (P : Params) (hP : P.cancelOnCleanup = true)
    (c : Cfg M.S) (hr : (lts M P).Reachable c) : ∀ k ∈ c.kills, k.victim = k.armer :=
  fun k hk => (((inv_reachable M P hP).reachable c hr).kills k hk).1

/-- **No early close.** Idle closes happen only once the deadline has passed. -/
theorem no_early_close (M : ConnModel) (P : Params) (hP : P.cancelOnCleanup = true)
    (c : Cfg M.S) (hr : (lts M P).Reachable c) : ∀ k ∈ c.kills, k.due ≤ k.time :=
  fun k hk => (((inv_reachable M P hP).reachable c hr).kills k hk).2

end Inv

/-! ## Timing, isolation, and lifting connection invariants -/

/-- **No late close.** Right after a poll at time `now`, no active timer is
due at or before `now`: every due timer fired in that poll. -/
theorem no_late_close (M : ConnModel) (P : Params) (c c' : Cfg M.S) (now : Nat) (toks : List Fd)
    (hs : step M P c (.poll now toks) = some c') : ∀ t ∈ c'.wheel, now < t.due := by
  simp only [step] at hs
  split at hs
  · cases hs
    intro t ht
    have := fireAll_wheel_sub _ _ _ _ t ht
    simpa using (List.mem_filter.1 this).2
  · cases hs

/-- **Isolation.** Dispatching an event for fd `f` leaves every other
connection and its `timers` entry unchanged. -/
theorem dispatch_isolated (M : ConnModel) (P : Params) (c c' : Cfg M.S) (i : M.I)
    (hs : step M P c (.dispatch i) = some c') (f : Fd) (hf : c.batch.head? = some f)
    (g : Fd) (hg : g ≠ f) : c'.conns g = c.conns g ∧ c'.timers g = c.timers g := by
  simp only [step] at hs
  cases hb : c.batch with
  | nil => simp [hb] at hs
  | cons f' rest =>
    rw [hb] at hf; simp at hf; subst hf
    simp only [hb] at hs
    split at hs
    · cases hs
    · cases hs
      exact ⟨dispatchAt_conns_other M P _ i hg, dispatchAt_timers_other M P _ i hg⟩

/-- States the connection model can reach from `init`. -/
inductive ConnReach (M : ConnModel) : M.S → Prop
  | init : ConnReach M M.init
  | step {s : M.S} (i : M.I) : ConnReach M s → ConnReach M (M.onEvent s i).1

/-- Every live connection's state is reachable in the connection model. -/
def LiveReach (M : ConnModel) (c : Cfg M.S) : Prop := ∀ f l, c.conns f = some l → ConnReach M l.st

section Lift
variable {M : ConnModel}

theorem liveReach_cleanup {c : Cfg M.S} (h : LiveReach M c) (b : Bool) (f : Fd) :
    LiveReach M (cleanup b c f) := by
  intro x l hx
  by_cases e : x = f
  · subst e; rw [cleanup_conns_self] at hx; cases hx
  · rw [cleanup_conns_other e] at hx; exact h x l hx

theorem liveReach_applyStep {c : Cfg M.S} (h : LiveReach M c) {f : Fd} {l : Live M.S} {st : M.S}
    (r : StepResult) (hst : ConnReach M st) : LiveReach M (applyStep c f l st r) := by
  intro x l' hx
  by_cases e : x = f
  · subst e; rw [applyStep_conns_self] at hx
    have := Option.some.inj hx; subst this; exact hst
  · rw [applyStep_conns_other _ _ _ _ e] at hx; exact h x l' hx

theorem liveReach_fireAll (b : Bool) (tm : Nat) :
    ∀ (ts : List Timer) (c : Cfg M.S), LiveReach M c → LiveReach M (fireAll b tm c ts) :=
  fun ts c h x l hx => h x l (fireAll_conns_sub b tm ts c x l hx)

theorem liveReach_step (P : Params) (c c' : Cfg M.S) (lab : Label M.I)
    (h : LiveReach M c) (hs : step M P c lab = some c') : LiveReach M c' := by
  cases lab with
  | poll now toks =>
    simp only [step] at hs; split at hs
    · cases hs; exact liveReach_fireAll _ _ _ _ (fun x l hx => h x l hx)
    · cases hs
  | accept fd regOk =>
    simp only [step] at hs; split at hs
    · cases hs
      cases regOk
      · exact h
      · intro x l hx
        simp only [acceptOr] at hx
        by_cases e : x = fd
        · subst e
          unfold acceptStep at hx
          split at hx <;> simp [schedule, setConn] at hx <;> (subst hx; exact .init)
        · rw [acceptStep_conns_other M c e] at hx; exact h x l hx
    · cases hs
  | acceptDone =>
    simp only [step] at hs; split at hs
    · cases hs; exact fun x l hx => h x l hx
    · cases hs
  | dispatch i =>
    simp only [step] at hs
    cases hb : c.batch with
    | nil => simp [hb] at hs
    | cons f rest =>
      simp only [hb] at hs
      split at hs
      · cases hs
      · cases hs
        have h1 : LiveReach M { c with batch := rest } := fun x l hx => h x l hx
        cases e : c.conns f with
        | none => simp only [dispatchAt, e]; exact h1
        | some l =>
          simp only [dispatchAt, e]
          split
          · exact liveReach_cleanup h1 _ _
          · exact liveReach_applyStep h1 _ (.step i (h f l e))

end Lift

/-- **Connection invariants lift to the server.** If `Q` is an invariant of
the connection model, every live connection of every reachable machine state
satisfies it. -/
theorem conn_invariant_lifts (M : ConnModel) (P : Params) (Q : M.S → Prop)
    (h0 : Q M.init) (hstep : ∀ s i, Q s → Q (M.onEvent s i).1)
    (c : Cfg M.S) (hr : (lts M P).Reachable c) : ∀ f l, c.conns f = some l → Q l.st := by
  have hind : (lts M P).Inductive (LiveReach M) :=
    { init := fun s hs => by subst hs; intro f l h; simp [initCfg] at h
      step := fun s l s' h hs => liveReach_step P s s' l h hs }
  have key : ∀ s, ConnReach M s → Q s := by
    intro s hs
    induction hs with
    | init => exact h0
    | step i _ ih => exact hstep _ i ih
  exact fun f l hf => key _ (hind.reachable c hr f l hf)

/-! ## Token 0: the listener and a client on fd 0 -/

/-- **Routing.** When fd 0 is in use (stdin open), no live connection has
fd 0, so every token-0 event the loop hands to the accept drainer is the
listener's. -/
theorem routing_ok (M : ConnModel) (P : Params) (hP : P.stdinOpen = true)
    (c : Cfg M.S) (hr : (lts M P).Reachable c) : c.conns 0 = none := by
  have hind : (lts M P).Inductive (fun c : Cfg M.S => c.conns 0 = none) := by
    refine ⟨fun s hs => by subst hs; rfl, ?_⟩
    intro s lab s' h hs
    show s'.conns 0 = none
    change step M P s lab = some s' at hs
    cases lab with
    | poll now toks =>
      simp only [step] at hs; split at hs
      · cases hs
        cases e : (pollStep P.cancelOnCleanup s now toks).conns 0 with
        | none => rfl
        | some l =>
          have := fireAll_conns_sub _ _ _ _ 0 l e
          change s.conns 0 = some l at this
          rw [h] at this; cases this
      · cases hs
    | accept fd regOk =>
      simp only [step] at hs; split at hs
      · rename_i hc
        have hfd : (0 : Nat) ≠ fd := fun e => hc.2.2.2 hP e.symm
        cases hs
        cases regOk
        · exact h
        · simp only [acceptOr]; rw [acceptStep_conns_other M s hfd]; exact h
      · cases hs
    | acceptDone =>
      simp only [step] at hs; split at hs
      · cases hs; exact h
      · cases hs
    | dispatch i =>
      simp only [step] at hs
      cases hb : s.batch with
      | nil => simp [hb] at hs
      | cons f rest =>
        simp only [hb] at hs
        split at hs
        · cases hs
        · rename_i hf0
          cases hs
          rw [dispatchAt_conns_other M P _ i (Ne.symm hf0)]; exact h
  exact hind.reachable c hr

/-- **A connection on fd 0 is never served.** No machine step changes the
connection on fd 0: it can only disappear (idle timeout). Its events carry
the listener's token and go to the accept drainer. -/
theorem fd0_never_served (M : ConnModel) (P : Params) (c c' : Cfg M.S) (lab : Label M.I)
    (hs : step M P c lab = some c') (l l' : Live M.S)
    (h0 : c.conns 0 = some l) (h0' : c'.conns 0 = some l') : l' = l := by
  cases lab with
  | poll now toks =>
    simp only [step] at hs; split at hs
    · cases hs
      have := fireAll_conns_sub _ _ _ _ 0 l' h0'
      change c.conns 0 = some l' at this
      rw [h0] at this; exact (Option.some.inj this).symm
    · cases hs
  | accept fd regOk =>
    simp only [step] at hs; split at hs
    · rename_i hc
      have hfd : (0 : Nat) ≠ fd := by
        intro e; subst e
        have := hc.2.1; rw [h0] at this; simp at this
      cases hs
      cases regOk
      · simp only [acceptOr] at h0'; rw [h0] at h0'; exact (Option.some.inj h0').symm
      · simp only [acceptOr] at h0'
        rw [acceptStep_conns_other M c hfd, h0] at h0'; exact (Option.some.inj h0').symm
    · cases hs
  | acceptDone =>
    simp only [step] at hs; split at hs
    · cases hs; change c.conns 0 = some l' at h0'
      rw [h0] at h0'; exact (Option.some.inj h0').symm
    · cases hs
  | dispatch i =>
    simp only [step] at hs
    cases hb : c.batch with
    | nil => simp [hb] at hs
    | cons f rest =>
      simp only [hb] at hs
      split at hs
      · cases hs
      · rename_i hf0
        cases hs
        rw [dispatchAt_conns_other M P _ i (Ne.symm hf0)] at h0'
        change c.conns 0 = some l' at h0'
        rw [h0] at h0'; exact (Option.some.inj h0').symm

/-! ## Concrete traces -/

/-- A toy connection: counts the events it has seen and keeps reading; the
event payload says whether this event ends the connection (peer FIN or an
error). Idle timeout 10 ms. -/
abbrev counter : ConnModel where
  S := Nat
  I := Bool
  init := 0
  onEvent := fun s fin => (s + 1, ⟨true, false, fin, -1⟩)
  idleMs := 10

def flareP : Params := ⟨3, true, true⟩
def noCancelP : Params := ⟨3, true, false⟩
def stdinClosedP : Params := ⟨3, false, true⟩

def runSteps (M : ConnModel) (P : Params) : Cfg M.S → List (Label M.I) → Option (Cfg M.S)
  | c, [] => some c
  | c, l :: ls => (step M P c l).bind (runSteps M P · ls)

theorem runSteps_run (M : ConnModel) (P : Params) :
    ∀ (ls : List (Label M.I)) (c c' : Cfg M.S), runSteps M P c ls = some c' → (lts M P).Run c ls c'
  | [], c, c', h => by
    simp only [runSteps, Option.some.injEq] at h; subst h; exact .nil _
  | l :: ls, c, c', h => by
    simp only [runSteps] at h
    cases e : step M P c l with
    | none => rw [e] at h; cases h
    | some c1 => rw [e] at h; exact .cons e (runSteps_run M P ls c1 c' h)

/-- Accept fd 5 at t=0 (timer due at 10), the peer closes at t=1, a new
connection reuses fd 5 at t=5 (its timer is due at 15), then poll at t=10. -/
def reuseTrace : List (Label Bool) :=
  [.poll 0 [0], .accept 5 true, .acceptDone,
   .poll 1 [5], .dispatch true,
   .poll 5 [0], .accept 5 true, .acceptDone,
   .poll 10 []]

/-- With flare's cancel-on-cleanup, the poll at t=10 closes nothing. -/
theorem reuse_with_cancel :
    (runSteps counter flareP initCfg reuseTrace).map (·.kills) = some [] := by decide

/-- Without the cancel, the first connection's timer fires at t=10 and
closes the second connection (incarnation 1), 5 ms into its 10 ms idle
budget. -/
theorem stale_timer_trace :
    (runSteps counter noCancelP initCfg reuseTrace).map (·.kills) = some [⟨5, 1, 0, 10, 10⟩] := by
  decide

/-- **The cancel is necessary**: the variant without it reaches a state
where an idle timer closed a connection it was not armed for. -/
theorem stale_timer_without_cancel :
    ∃ c, (lts counter noCancelP).Reachable c ∧ ∃ k ∈ c.kills, k.victim ≠ k.armer := by
  cases h : runSteps counter noCancelP initCfg reuseTrace with
  | none => have := stale_timer_trace; rw [h] at this; cases this
  | some c =>
    have hk := stale_timer_trace
    rw [h] at hk
    simp only [Option.map_some, Option.some.injEq] at hk
    exact ⟨c, ⟨initCfg, reuseTrace, rfl, runSteps_run _ _ _ _ _ h⟩, ⟨5, 1, 0, 10, 10⟩,
      by rw [hk]; simp, by decide⟩

/-- The poll at t=10 harvests `[0, 5]` while incarnation 0 lives on fd 5; the
fired loop closes it (its idle timer is due), the accept drainer gets fd 5
again for incarnation 1, and the event harvested for incarnation 0 is then
dispatched to incarnation 1. -/
def batchTrace : List (Label Bool) :=
  [.poll 0 [0], .accept 5 true, .acceptDone,
   .poll 10 [0, 5], .accept 5 true, .acceptDone, .dispatch false]

theorem stale_event_redelivered :
    (runSteps counter flareP initCfg batchTrace).map
      (fun c => (c.kills, (c.conns 5).map (fun l => (l.gen, l.st)))) =
      some ([⟨5, 0, 0, 10, 10⟩], some (1, 1)) := by
  decide

/-- With stdin closed, a client accepted on fd 0 is live and its next event
(token 0) is a listener event. -/
def fd0Trace : List (Label Bool) := [.poll 0 [0], .accept 0 true, .acceptDone, .poll 1 [0]]

theorem fd0_trace :
    (runSteps counter stdinClosedP initCfg fd0Trace).map
      (fun c => ((c.conns 0).map (·.st), c.batch)) = some (some 0, [0]) := by
  decide

theorem fd0_event_not_dispatched (fin : Bool) :
    (runSteps counter stdinClosedP initCfg fd0Trace).bind
      (fun c => step counter stdinClosedP c (.dispatch fin)) = none := by
  cases fin <;> decide

/-- **fd 0 is reachable** when stdin is closed. -/
theorem fd0_reachable :
    ∃ c, (lts counter stdinClosedP).Reachable c ∧ (c.conns 0).isSome := by
  cases h : runSteps counter stdinClosedP initCfg fd0Trace with
  | none => have := fd0_trace; rw [h] at this; cases this
  | some c =>
    have hk := fd0_trace
    rw [h] at hk
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hk
    refine ⟨c, ⟨initCfg, fd0Trace, rfl, runSteps_run _ _ _ _ _ h⟩, ?_⟩
    cases e : c.conns 0 with
    | none => rw [e] at hk; cases hk.1
    | some _ => rfl

end Flare.Machine
