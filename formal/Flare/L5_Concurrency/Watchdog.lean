import Flare.Core.LTS
import Flare.Core.Word

/-!
# DeadlineWatchdog: interleaving model of the slot protocol

`flare/runtime/watchdog.mojo` keeps, per slot, a deadline word
(`0` disarmed, `d > 0` armed, `-1` = `_FIRING` while the poller writes the
cell) and a cancel-cell address word. One worker thread arms/disarms the
slot around each request; one poller thread claims expired deadlines with a
CAS, writes `TIMEOUT` into the cell, and releases the claim.

## Semantics

Interleaving small-step semantics over the shared words `slot`, `addr`,
the cells and the clock. Every atomic operation of the Mojo code (load,
store, CAS) is one step of one thread; the scheduler label picks the thread
(`Lbl.p` poller, `Lbl.w b` worker, `Lbl.rearm` worker re-arming without a
disarm, `Lbl.tick` the clock). Ghost fields (`cur`, `doneReq`, `reqDl`,
`slotReq`, `claimReq`, `claimDl`, `fired`) record which request owns which
deadline; they never influence the real fields.

Request `k` (k ≥ 1) uses cancel cell `k`; address `0` means "no cell".

## Memory model

Sequential consistency abstraction. Every access to the slot word is atomic
(acquire loads, release stores, CAS without an explicit ordering), so the
word has a single modification order and each CAS reads its latest value.
A stale acquire load in the real execution either feeds a CAS that then
fails and retries, or is a load the SC model can also produce at an earlier
interleaving point. The one cross-location dependency, the poller reading
`addr` after its CAS claim, is ordered by the worker's release store of
`addr` sequenced before its CAS, which the poller's CAS reads from. That
argument is written down here, not proved in Lean.

## The arm

The deadline is clamped to `[1, Int64.MAX]` (CONC-01) and `arm` first CASes
an armed slot's old deadline to 0 (CONC-02), so callers may re-arm without a
disarm (`Lbl.rearm`) and any budget is allowed.
-/
namespace Flare.L5.Watchdog

/-- mirrors flare/runtime/watchdog.mojo#_FIRING sha=c29671513856 at=59bda50f -/
def FIRING : Int := -1

/-- Poller program counter, one slot of the scan loop.
mirrors flare/runtime/watchdog.mojo#_watchdog_main sha=8e88562c31b8 at=59bda50f -/
inductive PPc where
  | scan            -- :155 read the clock for this scan
  | load            -- :157 acquire-load the deadline
  | cas (d : Int)   -- :161-164 `d > 0 and now >= d and CAS(d -> FIRING)`
  | claimed         -- :166 acquire-load the cell address
  | write (a : Nat) -- :167-175 release-store TIMEOUT into cell `a` (if a ≠ 0)
  | release         -- :177 release-store 0
  deriving DecidableEq, Repr

/-- Worker program counter.
mirrors flare/runtime/watchdog.mojo#watchdog_arm sha=4b5a96cd4ffd at=acaf0eec (arm, fixed, CONC-01 and CONC-02),
:152-170 (disarm) -/
inductive WPc where
  | idle                     -- between requests
  | armSettle                -- :139 `_settle` of the disarm loop
  | armCas0 (v : Int)        -- :140-142 CAS(v -> 0)
  | armStore                 -- :106 store the cell address
  | armClock                 -- :107 deadline = now + budget
  | armSettle2 (dl : Int)    -- :109 `_settle`
  | armCas (dl v : Int)      -- :110 CAS(v -> dl)
  | handling                 -- the request runs
  | dSettle                  -- :128 `_settle`, `v == 0` returns True
  | dCas (v : Int)           -- :131 CAS(v -> 0) returns False
  deriving DecidableEq, Repr

structure St where
  slot : Int
  addr : Nat
  now : Int
  p : PPc
  pnow : Int
  w : WPc
  cur : Nat
  doneReq : Nat
  reqDl : Int
  slotReq : Nat
  claimReq : Nat
  claimDl : Int
  fired : Bool
  ret : Bool
  cancelled : Nat → Bool

/-- `_deadline_after`: saturate `now + budget` at `Int64.MAX`, then raise it
to at least 1.
mirrors flare/runtime/watchdog.mojo#_deadline_after sha=75247df20f70 at=0b291ce6 (fixed, CONC-01) -/
def deadlineOf (now b : Int) : Int := max (min (now + b) I64_MAX) 1

inductive Lbl where
  | p
  | w (b : Int)
  | rearm
  | tick
  deriving DecidableEq, Repr

def upd (f : Nat → Bool) (i : Nat) (v : Bool) : Nat → Bool :=
  fun j => if j = i then v else f j

/-- One poller step. mirrors flare/runtime/watchdog.mojo#_watchdog_main sha=8e88562c31b8 at=59bda50f -/
def pStep (s : St) : St :=
  match s.p with
  | .scan => { s with pnow := s.now, p := .load }
  | .load => { s with p := .cas s.slot }
  | .cas d =>
    if 0 < d ∧ d ≤ s.pnow ∧ s.slot = d then
      { s with slot := FIRING, claimReq := s.slotReq, claimDl := d, p := .claimed }
    else { s with p := .scan }
  | .claimed => { s with p := .write s.addr }
  | .write a =>
    if a ≠ 0 then
      { s with cancelled := upd s.cancelled a true,
               fired := s.fired || decide (a = s.cur), p := .release }
    else { s with p := .release }
  | .release => { s with slot := 0, p := .scan }

/-- One worker step (`b` is the budget, used at `armClock`).
mirrors flare/runtime/watchdog.mojo#watchdog_arm sha=4b5a96cd4ffd at=acaf0eec (arm, fixed, CONC-01 and CONC-02),
:152-170 (disarm) -/
def wStep (b : Int) (s : St) : Option St :=
  match s.w with
  | .idle => some { s with w := .armSettle }
  | .armSettle =>
    if s.slot = FIRING then some s
    else if s.slot ≠ 0 then some { s with w := .armCas0 s.slot }
    else some { s with w := .armStore }
  | .armCas0 v =>
    if s.slot = v then some { s with slot := 0, w := .armStore }
    else some { s with w := .armSettle }
  | .armStore =>
    some { s with addr := s.cur + 1, doneReq := s.cur, cur := s.cur + 1,
                  fired := false, w := .armClock }
  | .armClock => some { s with w := .armSettle2 (deadlineOf s.now b) }
  | .armSettle2 dl =>
    if s.slot = FIRING then some s else some { s with w := .armCas dl s.slot }
  | .armCas dl v =>
    if s.slot = v then
      some { s with slot := dl, reqDl := dl, slotReq := s.cur, w := .handling }
    else some { s with w := .armSettle2 dl }
  | .handling => some { s with w := .dSettle }
  | .dSettle =>
    if s.slot = FIRING then some s
    else if s.slot = 0 then some { s with ret := true, doneReq := s.cur, w := .idle }
    else some { s with w := .dCas s.slot }
  | .dCas v =>
    if s.slot = v then some { s with slot := 0, ret := false, doneReq := s.cur, w := .idle }
    else some { s with w := .dSettle }

def step (s : St) : Lbl → Option St
  | .p => some (pStep s)
  | .w b => wStep b s
  | .rearm =>
    if s.w = .handling then some { s with w := .armSettle } else none
  | .tick => some { s with now := s.now + 1 }

/-- Initial states: everything zero, clock at least 1 ms (CLOCK_MONOTONIC
reads milliseconds since boot). -/
def Init (s : St) : Prop :=
  s.slot = 0 ∧ s.addr = 0 ∧ 1 ≤ s.now ∧ s.p = .scan ∧ s.w = .idle ∧
  s.cur = 0 ∧ s.doneReq = 0 ∧ s.fired = false

def lts : LTS St Lbl := LTS.ofFn Init step

def claimedP : PPc → Bool
  | .claimed | .write _ | .release => true
  | _ => false

/-! ## Specification -/

/-- A cell write by the poller targets the current request, whose lifetime
has not ended (its disarm has not returned and no later arm began), and the
deadline it claimed is the one that request armed, positive and expired. -/
def Safe (s : St) : Prop :=
  ∀ a, s.p = .write a → a ≠ 0 →
    a = s.cur ∧ s.claimReq = s.cur ∧ s.doneReq < s.cur ∧
    0 < s.claimDl ∧ s.claimDl ≤ s.pnow ∧ s.claimDl = s.reqDl

/-- `disarm` returned `True` exactly when the request's cell was cancelled. -/
def DisarmCorrect (s : St) : Prop :=
  s.w = .idle → 0 < s.cur → s.ret = s.fired

/-- A FIRING slot is always owned by a poller inside its claim window, so
`_settle` waits at most three poller steps. -/
def FiringOwned (s : St) : Prop := s.slot = FIRING → claimedP s.p = true

/-! ## Inductive invariant

Indexed by the two program counters, so that after a case split on both
every clause is a concrete conjunction of linear facts. -/

/-- The claim window facts. -/
def K (s : St) : Prop :=
  s.claimReq = s.cur ∧ s.claimDl = s.reqDl ∧ 0 < s.claimDl ∧ s.claimDl ≤ s.pnow ∧
  s.doneReq < s.cur

/-- Facts independent of the program counters. The armed-slot clause is a
disjunction so that it is not used as a rewrite rule. -/
def Core (s : St) : Prop :=
  s.addr = s.cur ∧ s.doneReq ≤ s.cur ∧ 1 ≤ s.now ∧
  (s.slot = 0 ∨ s.slot = -1 ∨
    (s.slot = s.reqDl ∧ s.slotReq = s.cur ∧ 0 < s.reqDl ∧ s.doneReq < s.cur ∧ s.fired = false))

def PInv : PPc → St → Prop
  | .scan, s | .load, s | .cas _, s => s.slot ≠ -1
  | .claimed, s => s.slot = -1 ∧ K s ∧ s.fired = false
  | .write a, s => s.slot = -1 ∧ K s ∧ a = s.cur ∧ s.fired = false
  | .release, s => s.slot = -1 ∧ K s ∧ s.fired = true

def WInv : WPc → St → Prop
  | .idle, s => s.doneReq = s.cur ∧ s.slot = 0 ∧ (0 < s.cur → s.ret = s.fired)
  | .armSettle, s => s.doneReq = s.cur → s.slot = 0
  | .armCas0 v, s => v ≠ 0 ∧ v ≠ -1 ∧ s.doneReq < s.cur
  | .armStore, s => s.slot = 0
  | .armClock, s => s.slot = 0 ∧ s.doneReq < s.cur ∧ s.fired = false
  | .armSettle2 dl, s => s.slot = 0 ∧ s.doneReq < s.cur ∧ s.fired = false ∧ 0 < dl
  | .armCas dl v, s => s.slot = 0 ∧ s.doneReq < s.cur ∧ s.fired = false ∧ 0 < dl ∧ v = 0
  | .handling, s | .dSettle, s => s.doneReq < s.cur ∧ (s.slot = 0 → s.fired = true)
  | .dCas v, s => v ≠ 0 ∧ v ≠ -1 ∧ s.doneReq < s.cur ∧ (s.slot = 0 → s.fired = true)

def Inv (s : St) : Prop := Core s ∧ PInv s.p s ∧ WInv s.w s

theorem deadlineOf_pos (n b : Int) : 0 < deadlineOf n b := by
  unfold deadlineOf; omega

theorem FIRING_neg : FIRING = -1 := rfl

macro "wd_close" : tactic =>
  `(tactic| (simp_all [Core, PInv, WInv, K, FIRING] <;> try omega))

theorem inv_step_p : ∀ s, Inv s → Inv (pStep s) := by
  rintro s ⟨⟨h1, h2, h3, h4 | h4 | ⟨h4, h5, h6, h7, h8⟩⟩, hpI, hwI⟩
  all_goals
    cases hp : s.p <;> cases hw : s.w <;> simp only [hp, hw, PInv, WInv] at hpI hwI <;>
      simp only [pStep, hp] <;> (try split) <;> simp only [Inv, PInv, WInv, hw] <;> wd_close

theorem inv_step_w : ∀ s b s', Inv s → wStep b s = some s' → Inv s' := by
  rintro s b s' ⟨⟨h1, h2, h3, h4 | h4 | ⟨h4, h5, h6, h7, h8⟩⟩, hpI, hwI⟩ h
  all_goals
    unfold wStep at h
    cases hw : s.w <;> simp only [hw, WInv] at h hwI
    case armClock =>
      simp only [Option.some.injEq] at h; subst h
      have := deadlineOf_pos s.now b
      cases hp : s.p <;> simp only [hp, PInv] at hpI <;> simp only [Inv, PInv, WInv] <;>
        wd_close
    all_goals
      (repeat' split at h) <;> simp only [Option.some.injEq] at h <;> subst h <;>
      cases hp : s.p <;> simp only [hp, PInv] at hpI <;> simp only [Inv, PInv, WInv] <;>
      wd_close

theorem inv_step : ∀ s l s', Inv s → step s l = some s' → Inv s' := by
  intro s l s' I h
  cases l with
  | p => simp only [step, Option.some.injEq] at h; subst h; exact inv_step_p s I
  | w b => exact inv_step_w s b s' I h
  | rearm =>
    simp only [step] at h
    split at h
    · rename_i hr
      simp only [Option.some.injEq] at h; subst h
      obtain ⟨hc, hpI, hwI⟩ := I
      simp only [hr, WInv] at hwI
      refine ⟨hc, ?_, by simp only [WInv]; intro; omega⟩
      cases hp : s.p <;> simp only [hp, PInv, K] at hpI ⊢ <;> exact hpI
    · simp at h
  | tick =>
    simp only [step, Option.some.injEq] at h; subst h
    obtain ⟨⟨h1, h2, h3, h4⟩, hpI, hwI⟩ := I
    refine ⟨⟨h1, h2, by simp only; omega, h4⟩, ?_, ?_⟩
    · cases hp : s.p <;> simp only [hp, PInv, K] at hpI ⊢ <;> exact hpI
    · cases hw : s.w <;> simp only [hw, WInv] at hwI ⊢ <;> exact hwI

theorem inv_init : ∀ s, Init s → Inv s := by
  intro s ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩
  refine ⟨?_, ?_, ?_⟩
  · simp [Core, h1, h2, h3, h6, h7]
  · simp [h4, PInv, h1]
  · simp [h5, WInv, h1, h6, h7]

theorem inv_inductive : lts.Inductive Inv :=
  ⟨inv_init, fun s l s' hi hs => inv_step s l s' hi hs⟩

theorem inv_safe (s : St) (I : Inv s) :
    Safe s ∧ DisarmCorrect s ∧ FiringOwned s := by
  obtain ⟨hc, hpI, hwI⟩ := I
  refine ⟨?_, ?_, ?_⟩
  · intro a hp ha
    simp only [hp, PInv, K] at hpI
    obtain ⟨_, ⟨b1, b2, b3, b4, b5⟩, c1, _⟩ := hpI
    exact ⟨c1, b1, b5, b3, b4, b2⟩
  · intro hw hcur
    simp only [hw, WInv] at hwI
    exact hwI.2.2 hcur
  · intro hs
    cases hp : s.p <;> simp only [hp, PInv, FIRING] at hpI hs ⊢ <;> simp_all [claimedP]

/-- Headline: for every budget, and even when callers re-arm a still-armed
slot, the watchdog fires only into the current request's cell, only for that
request's own expired deadline, never after its disarm returned; disarm's
result is exact; FIRING is always transient. -/
theorem shipped_safe :
    ∀ s, lts.Reachable s → Safe s ∧ DisarmCorrect s ∧ FiringOwned s :=
  fun s hr => inv_safe s (inv_inductive.reachable s hr)

/-- The canonical initial state, clock at 1 ms. -/
def s0 : St :=
  { slot := 0, addr := 0, now := 1, p := .scan, pnow := 0, w := .idle, cur := 0,
    doneReq := 0, reqDl := 0, slotReq := 0, claimReq := 0, claimDl := 0,
    fired := false, ret := false, cancelled := fun _ => false }

theorem s0_init : Init s0 := by simp [Init, s0]

end Flare.L5.Watchdog
