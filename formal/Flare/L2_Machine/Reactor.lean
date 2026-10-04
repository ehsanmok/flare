import Flare.Core

/-!
# Reactor (epoll / kqueue) bookkeeping machine

`runtime/reactor.mojo` keeps `_registered : Dict[c_int, UInt64]` (fd ↦ token)
next to the kernel's interest list. We model:

* the bookkeeping map `reg : Int → Option UInt64`;
* the kernel interest list `kern : Int → Option (UInt64 × Nat)` (token, interest);
* the four public operations, where every kernel call is an explicit
  nondeterministic outcome (`ok : Bool`) supplied by the environment.

The spec is a plain finite map with `insert` / `erase`.
-/
namespace Flare.L2.Reactor

/-! ## Constants (flare/net/_libc_event.mojo:39-45, runtime/event.mojo:21-35) -/

def EPOLLIN : UInt32 := 0x001
def EPOLLOUT : UInt32 := 0x004
def EPOLLERR : UInt32 := 0x008
def EPOLLHUP : UInt32 := 0x010
def EPOLLRDHUP : UInt32 := 0x2000
def EPOLLEXCLUSIVE : UInt32 := 0x10000000

def INTEREST_READ : Nat := 1
def INTEREST_WRITE : Nat := 2
def EVENT_READABLE : Nat := 1
def EVENT_WRITABLE : Nat := 2
def EVENT_ERROR : Nat := 4
def EVENT_HUP : Nat := 8
def WAKEUP_TOKEN : UInt64 := 0xFFFFFFFFFFFFFFFF

/-! ## Bit translation -/

/-- mirrors flare/runtime/reactor.mojo:112-120 @59bda50 -/
def interestToEpoll (interest : Nat) : UInt32 :=
  (if interest &&& INTEREST_READ ≠ 0 then EPOLLIN ||| EPOLLRDHUP else 0) |||
  (if interest &&& INTEREST_WRITE ≠ 0 then EPOLLOUT else 0)

/-- mirrors flare/runtime/reactor.mojo:123-135 @59bda50 -/
def epollToEventFlags (bits : UInt32) : Nat :=
  (if bits &&& EPOLLIN ≠ 0 then EVENT_READABLE else 0) |||
  (if bits &&& EPOLLOUT ≠ 0 then EVENT_WRITABLE else 0) |||
  (if bits &&& EPOLLERR ≠ 0 then EVENT_ERROR else 0) |||
  (if bits &&& (EPOLLHUP ||| EPOLLRDHUP) ≠ 0 then EVENT_HUP else 0)

/-- READ interest always asks for `EPOLLRDHUP`, so a peer half-close is
reported (as HUP) on every read-registered fd. -/
theorem read_interest_has_rdhup (i : Nat) (h : i &&& INTEREST_READ ≠ 0) :
    interestToEpoll i &&& EPOLLRDHUP = EPOLLRDHUP := by
  unfold interestToEpoll; simp only [h, ne_eq, not_false_eq_true, if_true]
  split <;> decide

/-- Only the two interest bits matter, and the translation is injective on
them: the four possible interests give four distinct epoll masks. -/
theorem interestToEpoll_values :
    interestToEpoll 1 = 0x2001 ∧ interestToEpoll 2 = 0x4 ∧
    interestToEpoll 3 = 0x2005 ∧ interestToEpoll 0 = 0 := by decide

/-- `EPOLLEXCLUSIVE` never collides with a bit the translation produces. -/
theorem exclusive_disjoint (i : Nat) : interestToEpoll i &&& EPOLLEXCLUSIVE = 0 := by
  unfold interestToEpoll
  split <;> split <;> decide

/-- Readable is reported exactly when `EPOLLIN` is set. -/
theorem readable_iff_in (b : UInt32) :
    epollToEventFlags b &&& EVENT_READABLE ≠ 0 ↔ b &&& EPOLLIN ≠ 0 := by
  unfold epollToEventFlags
  by_cases h1 : b &&& EPOLLIN ≠ 0 <;> by_cases h2 : b &&& EPOLLOUT ≠ 0 <;>
  by_cases h3 : b &&& EPOLLERR ≠ 0 <;> by_cases h4 : b &&& (EPOLLHUP ||| EPOLLRDHUP) ≠ 0 <;>
  simp_all [EVENT_READABLE, EVENT_WRITABLE, EVENT_ERROR, EVENT_HUP]

/-- Writable is reported exactly when `EPOLLOUT` is set. -/
theorem writable_iff_out (b : UInt32) :
    epollToEventFlags b &&& EVENT_WRITABLE ≠ 0 ↔ b &&& EPOLLOUT ≠ 0 := by
  unfold epollToEventFlags
  by_cases h1 : b &&& EPOLLIN ≠ 0 <;> by_cases h2 : b &&& EPOLLOUT ≠ 0 <;>
  by_cases h3 : b &&& EPOLLERR ≠ 0 <;> by_cases h4 : b &&& (EPOLLHUP ||| EPOLLRDHUP) ≠ 0 <;>
  simp_all [EVENT_READABLE, EVENT_WRITABLE, EVENT_ERROR, EVENT_HUP]

/-- A half-close (`EPOLLIN|EPOLLRDHUP`, what Linux posts on FIN) maps to
READABLE|HUP. -/
theorem half_close_maps : epollToEventFlags (EPOLLIN ||| EPOLLRDHUP) =
    EVENT_READABLE ||| EVENT_HUP := by decide

/-- Round trip: the readable/writable bits of what comes back for a fully
ready fd are exactly the interest that was registered. -/
theorem roundtrip_rw (i : Nat) (hi : i < 4) :
    epollToEventFlags (interestToEpoll i) &&& 3 = i &&& 3 := by
  have : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 := by omega
  rcases this with rfl | rfl | rfl | rfl <;> decide

/-! ## Bookkeeping machine -/

structure St where
  reg : Int → Option UInt64
  kern : Int → Option (UInt64 × Nat)

/-- Errors the Mojo code raises (`NetworkError`). -/
inductive Err | reserved | zeroInterest | dup | notReg | sys
  deriving DecidableEq, Repr

def upd {α} (f : Int → Option α) (k : Int) (v : Option α) : Int → Option α :=
  fun x => if x = k then v else f x

/-- mirrors flare/runtime/reactor.mojo:290-315,646-665 @59bda50
`ok` is the result of `epoll_ctl(ADD)` / the kqueue install. -/
def register (s : St) (fd : Int) (tok : UInt64) (interest : Nat) (ok : Bool) :
    Except Err St :=
  if tok = WAKEUP_TOKEN then .error .reserved
  else if interest = 0 then .error .zeroInterest
  else if (s.reg fd).isSome then .error .dup
  else if ok then .ok { reg := upd s.reg fd (some tok), kern := upd s.kern fd (some (tok, interest)) }
  else .error .sys

/-- mirrors flare/runtime/reactor.mojo:317-383 @59bda50
`okExcl`: ADD with EPOLLEXCLUSIVE; `okPlain`: the fallback plain ADD. -/
def registerExclusive (s : St) (fd : Int) (tok : UInt64) (interest : Nat)
    (okExcl okPlain : Bool) : Except Err St :=
  if tok = WAKEUP_TOKEN then .error .reserved
  else if interest = 0 then .error .zeroInterest
  else if (s.reg fd).isSome then .error .dup
  else if okExcl || okPlain then
    .ok { reg := upd s.reg fd (some tok), kern := upd s.kern fd (some (tok, interest)) }
  else .error .sys

/-- mirrors flare/runtime/reactor.mojo:385-413 @59bda50 -/
def modify (s : St) (fd : Int) (interest : Nat) (ok : Bool) : Except Err St :=
  if interest = 0 then .error .zeroInterest
  else match s.reg fd with
    | none => .error .notReg
    | some tok =>
      if ok then .ok { s with kern := upd s.kern fd (some (tok, interest)) }
      else .error .sys

/-- mirrors flare/runtime/reactor.mojo:415-479 @59bda50
The kernel DEL result is ignored: bookkeeping is always erased. -/
def unregister (s : St) (fd : Int) (_delOk : Bool) : Except Err St :=
  match s.reg fd with
  | none => .error .notReg
  | some _ => .ok { reg := upd s.reg fd none, kern := upd s.kern fd none }

/-- The counterfactual the comment at :428-441 rejects: raise when DEL fails. -/
def unregisterRaising (s : St) (fd : Int) (delOk : Bool) : Except Err St :=
  match s.reg fd with
  | none => .error .notReg
  | some _ => if delOk then .ok { reg := upd s.reg fd none, kern := upd s.kern fd none }
              else .error .sys

/-- Closing an fd makes the kernel drop it from every interest list. -/
def kernelClose (s : St) (fd : Int) : St := { s with kern := upd s.kern fd none }

/-! ## Spec: finite map -/

abbrev Spec := Int → Option UInt64

theorem register_refines (s s' : St) fd tok i ok (h : register s fd tok i ok = .ok s') :
    s'.reg = upd s.reg fd (some tok) ∧ s.reg fd = none ∧ tok ≠ WAKEUP_TOKEN ∧ i ≠ 0 := by
  unfold register at h
  split at h; · cases h
  split at h; · cases h
  split at h; · cases h
  split at h
  · cases h; refine ⟨rfl, ?_, by assumption, by assumption⟩
    rename_i h3 _; simpa using h3
  · cases h

theorem registerExclusive_same_bookkeeping (s : St) fd tok i ok :
    registerExclusive s fd tok i ok false = register s fd tok i ok ∧
    registerExclusive s fd tok i false ok = register s fd tok i ok := by
  unfold registerExclusive register; cases ok <;> simp

theorem unregister_refines (s s' : St) fd d (h : unregister s fd d = .ok s') :
    s'.reg = upd s.reg fd none ∧ (s.reg fd).isSome := by
  unfold unregister at h; split at h
  · cases h
  · cases h; rename_i heq; simp [heq]

/-- Unregister always removes, whatever the kernel said. -/
theorem unregister_always_removes (s : St) fd (d : Bool) (h : (s.reg fd).isSome) :
    ∃ s', unregister s fd d = .ok s' ∧ s'.reg fd = none ∧ s'.kern fd = none := by
  unfold unregister
  cases hr : s.reg fd with
  | none => simp [hr] at h
  | some t => exact ⟨_, rfl, by simp [upd], by simp [upd]⟩

theorem modify_keeps_token (s s' : St) fd i ok (h : modify s fd i ok = .ok s') :
    s'.reg = s.reg ∧ ∃ t, s.reg fd = some t ∧ s'.kern fd = some (t, i) := by
  unfold modify at h; split at h; · cases h
  split at h
  · cases h
  · rename_i t ht; split at h
    · cases h; exact ⟨rfl, t, ht, by simp [upd]⟩
    · cases h

/-- Invariant: bookkeeping and kernel agree on tokens for every registered fd
whose kernel registration is still alive. (`kern ⊆ reg` with same token.) -/
def Agree (s : St) : Prop := ∀ fd t i, s.kern fd = some (t, i) → s.reg fd = some t

theorem agree_register (s s' : St) fd tok i ok (ha : Agree s)
    (h : register s fd tok i ok = .ok s') : Agree s' := by
  unfold register at h
  split at h; · cases h
  split at h; · cases h
  split at h; · cases h
  split at h
  · cases h; intro x t j hx; simp only [upd] at hx ⊢
    by_cases hxf : x = fd
    · simp [hxf] at hx ⊢; exact hx.1
    · simp [hxf] at hx ⊢; exact ha _ _ _ hx
  · cases h

theorem agree_unregister (s s' : St) fd d (ha : Agree s)
    (h : unregister s fd d = .ok s') : Agree s' := by
  unfold unregister at h; split at h; · cases h
  cases h; intro x t j hx; simp only [upd] at hx ⊢; split at hx
  · cases hx
  · rename_i hne; simp [hne]; exact ha _ _ _ hx

theorem agree_close (s : St) fd (ha : Agree s) : Agree (kernelClose s fd) := by
  intro x t j hx; simp only [kernelClose, upd] at hx; split at hx
  · cases hx
  · exact ha _ _ _ hx

/-- fd-reuse safety. The owner closed `fd` (kernel auto-removes it), then
unregisters (DEL fails with EBADF: `delOk = false`). The kernel hands the
same number out again; `register fd t'` passes the duplicate check and binds
`t'`, so later events for that fd carry `t'`. -/
theorem fd_reuse_safe (s : St) fd (t' : UInt64) i (hreg : (s.reg fd).isSome)
    (ht : t' ≠ WAKEUP_TOKEN) (hi : i ≠ 0) :
    ∃ s1 s2, unregister (kernelClose s fd) fd false = .ok s1 ∧
      register s1 fd t' i true = .ok s2 ∧ s2.reg fd = some t' ∧
      s2.kern fd = some (t', i) := by
  have hreg' : ((kernelClose s fd).reg fd).isSome := hreg
  obtain ⟨s1, h1, h1r, _⟩ := unregister_always_removes _ fd false hreg'
  refine ⟨s1, { reg := upd s1.reg fd (some t'), kern := upd s1.kern fd (some (t', i)) },
    h1, ?_, by simp [upd], by simp [upd]⟩
  simp [register, ht, hi, h1r]

/-- The counterfactual: had unregister raised on the failed DEL, the stale
entry rejects the reused fd with `dup` (the connection would be dropped). -/
theorem raising_unregister_rejects_reuse (s : St) fd t' i
    (hreg : (s.reg fd).isSome) (ht : t' ≠ WAKEUP_TOKEN) (hi : i ≠ 0) :
    unregisterRaising (kernelClose s fd) fd false = .error .sys ∧
    register (kernelClose s fd) fd t' i true = .error .dup := by
  obtain ⟨t, htk⟩ := Option.isSome_iff_exists.mp hreg
  constructor
  · simp [unregisterRaising, kernelClose, htk]
  · simp [register, ht, hi, kernelClose, htk]

/-! ## epoll vs kqueue dispatch -/

/-- Readiness of one fd as seen by the kernel. -/
structure Ready where
  rd : Bool      -- readable (data or FIN)
  wr : Bool
  eof : Bool     -- peer half-close / hang-up
  err : Bool     -- pending socket error
  deriving DecidableEq

def bit (b : Bool) (v : Nat) : Nat := if b then v else 0

/-- epoll (level-triggered): one event per fd; kernel reports the interest
bits that are ready plus ERR/HUP unconditionally; RDHUP only with READ
interest. -/
def epollBits (i : Nat) (r : Ready) : UInt32 :=
  (if i &&& 1 ≠ 0 ∧ r.rd then EPOLLIN else 0) |||
  (if i &&& 2 ≠ 0 ∧ r.wr then EPOLLOUT else 0) |||
  (if r.err then EPOLLERR else 0) |||
  (if i &&& 1 ≠ 0 ∧ r.eof then EPOLLRDHUP else 0)

/-- kqueue: one event per *ready filter*; flags from EV_EOF / EV_ERROR.
mirrors flare/runtime/reactor.mojo:586-604 @59bda50 (filter → EVENT_*). -/
def kqueueEvents (i : Nat) (r : Ready) : List Nat :=
  (if i &&& 1 ≠ 0 ∧ (r.rd ∨ r.eof) then
    [EVENT_READABLE ||| bit r.eof EVENT_HUP] else []) ++
  (if i &&& 2 ≠ 0 ∧ r.wr then
    [EVENT_WRITABLE ||| bit r.eof EVENT_HUP] else [])

def orAll : List Nat → Nat := List.foldr (· ||| ·) 0

/-- Dispatch-level equivalence on READABLE/WRITABLE, when the kernel marks a
half-closed socket readable (Linux posts EPOLLIN with RDHUP on FIN; kqueue
fires EVFILT_READ with EV_EOF): OR-ing the flags of all events for a token
gives the same R/W set on both backends. -/
theorem dispatch_rw_equiv (i : Nat) (hi : i < 4) (r : Ready) (hfin : r.eof → r.rd) :
    epollToEventFlags (epollBits i r) &&& 3 = orAll (kqueueEvents i r) &&& 3 := by
  have : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 := by omega
  rcases r with ⟨rd, wr, eof, err⟩
  rcases this with rfl | rfl | rfl | rfl <;>
  cases rd <;> cases wr <;> cases eof <;> cases err <;> simp at hfin <;> decide

/-- The documented difference: a pending socket error with no ready filter
is ERROR on epoll and invisible on kqueue (kqueue reports it as EV_EOF with
`fflags = errno` on the next ready filter, which flare maps to HUP). -/
theorem error_differs :
    epollToEventFlags (epollBits 1 ⟨false, false, false, true⟩) = EVENT_ERROR ∧
    kqueueEvents 1 ⟨false, false, false, true⟩ = [] := by decide

/-- And: a socket readable and writable at once is one epoll event but two
kqueue events (so kqueue fills `max_events` twice as fast). -/
theorem kqueue_counts_filters :
    kqueueEvents 3 ⟨true, true, false, false⟩ = [EVENT_READABLE, EVENT_WRITABLE] := by decide

end Flare.L2.Reactor
