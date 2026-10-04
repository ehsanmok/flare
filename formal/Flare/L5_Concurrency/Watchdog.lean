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

## Configurations

`Cfg` covers the Mojo code (`disarmFirst := false`, `clamp := false`) and
the fix (`disarmFirst`: arm first CASes the old deadline to 0; `clamp`:
deadline clamped to ≥ 1), plus whether callers may re-arm without disarm.
-/
namespace Flare.L5.Watchdog

/-- mirrors flare/runtime/watchdog.mojo:46 @59bda50 -/
def FIRING : Int := -1

/-- Poller program counter, one slot of the scan loop.
mirrors flare/runtime/watchdog.mojo:154-177 @59bda50 -/
inductive PPc where
  | scan            -- :155 read the clock for this scan
  | load            -- :157 acquire-load the deadline
  | cas (d : Int)   -- :161-164 `d > 0 and now >= d and CAS(d -> FIRING)`
  | claimed         -- :166 acquire-load the cell address
  | write (a : Nat) -- :167-175 release-store TIMEOUT into cell `a` (if a ≠ 0)
  | release         -- :177 release-store 0
  deriving DecidableEq, Repr

/-- Worker program counter.
mirrors flare/runtime/watchdog.mojo:98-132 @59bda50 -/
inductive WPc where
  | idle                     -- between requests
  | armSettle                -- :105 `_settle` (fix: disarm loop)
  | armCas0 (v : Int)        -- fix only: CAS(v -> 0)
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

structure Cfg where
  disarmFirst : Bool
  clamp : Bool
  allowRearm : Bool
  adm : Int → Int → Bool

/-- Mojo `Int64(monotonic_now_ms() + budget_ms)`: 64-bit wrap. -/
def wrap (x : Int) : Int := (mojoInt x).toInt

/-- mirrors flare/runtime/watchdog.mojo:107 @59bda50 (clamp = the fix) -/
def deadlineOf (c : Cfg) (now b : Int) : Int :=
  if c.clamp then max (wrap (now + b)) 1 else wrap (now + b)

inductive Lbl where
  | p
  | w (b : Int)
  | rearm
  | tick
  deriving DecidableEq, Repr

def upd (f : Nat → Bool) (i : Nat) (v : Bool) : Nat → Bool :=
  fun j => if j = i then v else f j

/-- One poller step. mirrors flare/runtime/watchdog.mojo:154-177 @59bda50 -/
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
mirrors flare/runtime/watchdog.mojo:98-132 @59bda50 -/
def wStep (c : Cfg) (b : Int) (s : St) : Option St :=
  match s.w with
  | .idle => some { s with w := .armSettle }
  | .armSettle =>
    if s.slot = FIRING then some s
    else if c.disarmFirst ∧ s.slot ≠ 0 then some { s with w := .armCas0 s.slot }
    else some { s with w := .armStore }
  | .armCas0 v =>
    if s.slot = v then some { s with slot := 0, w := .armStore }
    else some { s with w := .armSettle }
  | .armStore =>
    some { s with addr := s.cur + 1, doneReq := s.cur, cur := s.cur + 1,
                  fired := false, w := .armClock }
  | .armClock =>
    if c.adm s.now b then some { s with w := .armSettle2 (deadlineOf c s.now b) }
    else none
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

def step (c : Cfg) (s : St) : Lbl → Option St
  | .p => some (pStep s)
  | .w b => wStep c b s
  | .rearm =>
    if c.allowRearm ∧ s.w = .handling then some { s with w := .armSettle } else none
  | .tick => some { s with now := s.now + 1 }

/-- Initial states: everything zero, clock at least 1 ms (CLOCK_MONOTONIC
reads milliseconds since boot). -/
def Init (s : St) : Prop :=
  s.slot = 0 ∧ s.addr = 0 ∧ 1 ≤ s.now ∧ s.p = .scan ∧ s.w = .idle ∧
  s.cur = 0 ∧ s.doneReq = 0 ∧ s.fired = false

def lts (c : Cfg) : LTS St Lbl := LTS.ofFn Init (step c)

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

def WInv (c : Cfg) : WPc → St → Prop
  | .idle, s => s.doneReq = s.cur ∧ s.slot = 0 ∧ (0 < s.cur → s.ret = s.fired)
  | .armSettle, s => (s.doneReq = s.cur → s.slot = 0) ∧ (s.doneReq < s.cur → c.disarmFirst = true)
  | .armCas0 v, s => v ≠ 0 ∧ v ≠ -1 ∧ s.doneReq < s.cur ∧ c.disarmFirst = true
  | .armStore, s => s.slot = 0
  | .armClock, s => s.slot = 0 ∧ s.doneReq < s.cur ∧ s.fired = false
  | .armSettle2 dl, s => s.slot = 0 ∧ s.doneReq < s.cur ∧ s.fired = false ∧ 0 < dl
  | .armCas dl v, s => s.slot = 0 ∧ s.doneReq < s.cur ∧ s.fired = false ∧ 0 < dl ∧ v = 0
  | .handling, s | .dSettle, s => s.doneReq < s.cur ∧ (s.slot = 0 → s.fired = true)
  | .dCas v, s => v ≠ 0 ∧ v ≠ -1 ∧ s.doneReq < s.cur ∧ (s.slot = 0 → s.fired = true)

def Inv (c : Cfg) (s : St) : Prop := Core s ∧ PInv s.p s ∧ WInv c s.w s

/-- Deadline positivity: what a configuration must guarantee about the
deadlines it stores. -/
def DeadlinePos (c : Cfg) : Prop := ∀ n b, 1 ≤ n → c.adm n b = true → 0 < deadlineOf c n b

theorem FIRING_neg : FIRING = -1 := rfl

macro "wd_close" : tactic =>
  `(tactic| (simp_all [Core, PInv, WInv, K, FIRING] <;> try omega))

theorem inv_step_p (c : Cfg) : ∀ s, Inv c s → Inv c (pStep s) := by
  rintro s ⟨⟨h1, h2, h3, h4 | h4 | ⟨h4, h5, h6, h7, h8⟩⟩, hpI, hwI⟩
  all_goals
    cases hp : s.p <;> cases hw : s.w <;> simp only [hp, hw, PInv, WInv] at hpI hwI <;>
      simp only [pStep, hp] <;> (try split) <;> simp only [Inv, PInv, WInv, hw] <;> wd_close

theorem inv_step_w (c : Cfg) (hdl : DeadlinePos c) :
    ∀ s b s', Inv c s → wStep c b s = some s' → Inv c s' := by
  rintro s b s' ⟨⟨h1, h2, h3, h4 | h4 | ⟨h4, h5, h6, h7, h8⟩⟩, hpI, hwI⟩ h
  all_goals
    unfold wStep at h
    cases hw : s.w <;> simp only [hw, WInv] at h hwI
    case armClock =>
      by_cases ha : c.adm s.now b = true
      · simp only [ha, if_true, Option.some.injEq] at h; subst h
        have := hdl s.now b h3 ha
        cases hp : s.p <;> simp only [hp, PInv] at hpI <;> simp only [Inv, PInv, WInv] <;>
          wd_close
      · simp [ha] at h
    all_goals
      (repeat' split at h) <;> simp only [Option.some.injEq] at h <;> subst h <;>
      cases hp : s.p <;> simp only [hp, PInv] at hpI <;> simp only [Inv, PInv, WInv] <;>
      wd_close

theorem inv_step (c : Cfg) (hra : c.allowRearm = true → c.disarmFirst = true)
    (hdl : DeadlinePos c) :
    ∀ s l s', Inv c s → step c s l = some s' → Inv c s' := by
  intro s l s' I h
  cases l with
  | p => simp only [step, Option.some.injEq] at h; subst h; exact inv_step_p c s I
  | w b => exact inv_step_w c hdl s b s' I h
  | rearm =>
    simp only [step] at h
    split at h
    · rename_i hr
      simp only [Option.some.injEq] at h; subst h
      obtain ⟨hc, hpI, hwI⟩ := I
      have hdf := hra hr.1
      simp only [hr.2, WInv] at hwI
      refine ⟨hc, ?_, by simp only [WInv]; constructor <;> intro <;> first | omega | exact hdf⟩
      cases hp : s.p <;> simp only [hp, PInv, K] at hpI ⊢ <;> exact hpI
    · simp at h
  | tick =>
    simp only [step, Option.some.injEq] at h; subst h
    obtain ⟨⟨h1, h2, h3, h4⟩, hpI, hwI⟩ := I
    refine ⟨⟨h1, h2, by simp only; omega, h4⟩, ?_, ?_⟩
    · cases hp : s.p <;> simp only [hp, PInv, K] at hpI ⊢ <;> exact hpI
    · cases hw : s.w <;> simp only [hw, WInv] at hwI ⊢ <;> exact hwI

theorem inv_init (c : Cfg) : ∀ s, Init s → Inv c s := by
  intro s ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩
  refine ⟨?_, ?_, ?_⟩
  · simp [Core, h1, h2, h3, h6, h7]
  · simp [h4, PInv, h1]
  · simp [h5, WInv, h1, h6, h7]

theorem inv_inductive (c : Cfg) (hra : c.allowRearm = true → c.disarmFirst = true)
    (hdl : DeadlinePos c) : (lts c).Inductive (Inv c) :=
  ⟨inv_init c, fun s l s' hi hs => inv_step c hra hdl s l s' hi hs⟩

theorem inv_safe (c : Cfg) (s : St) (I : Inv c s) :
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

/-- The general theorem: any configuration whose callers re-arm only with
the disarm-first arm, and whose stored deadlines are positive, is safe in
every reachable state. -/
theorem safe_of_cfg (c : Cfg) (hra : c.allowRearm = true → c.disarmFirst = true)
    (hdl : DeadlinePos c) :
    ∀ s, (lts c).Reachable s → Safe s ∧ DisarmCorrect s ∧ FiringOwned s :=
  fun s hr => inv_safe c s ((inv_inductive c hra hdl).reachable s hr)

/-! ## The Mojo code and the fix -/

/-- Budgets for which `now + budget` is a positive `Int64`. -/
def goodAdm (n b : Int) : Bool := decide (1 ≤ n + b ∧ n + b ≤ I64_MAX)

/-- The code at 59bda50 under the discipline "arm only after disarm" with
budgets that give a positive, non-wrapping deadline. -/
def cfgImpl : Cfg := { disarmFirst := false, clamp := false, allowRearm := false, adm := goodAdm }

/-- The fix: clamp the deadline to ≥ 1 and disarm first inside arm. Any
budget; callers may re-arm without disarm. -/
def cfgFixed : Cfg :=
  { disarmFirst := true, clamp := true, allowRearm := true, adm := fun _ _ => true }

theorem deadlinePos_impl : DeadlinePos cfgImpl := by
  intro n b _ ha
  simp only [cfgImpl, goodAdm, decide_eq_true_eq] at ha
  simp only [deadlineOf, cfgImpl, Bool.false_eq_true, if_false, wrap]
  rw [mojoInt_toInt_of_fits]
  · omega
  · unfold fitsI64 I64_MIN; unfold I64_MAX at ha ⊢; omega

theorem deadlinePos_fixed : DeadlinePos cfgFixed := by
  intro n b _ _
  simp only [deadlineOf, cfgFixed, if_true]
  omega

/-- Headline (impl): under "arm only after disarm" and positive budgets the
watchdog fires only into the current request's cell, only for that
request's own expired deadline, never after its disarm returned; disarm's
result is exact; FIRING is always transient. Proved (general invariant,
unbounded). -/
theorem impl_safe :
    ∀ s, (lts cfgImpl).Reachable s → Safe s ∧ DisarmCorrect s ∧ FiringOwned s :=
  safe_of_cfg cfgImpl (by simp [cfgImpl]) deadlinePos_impl

/-- Headline (fix): the clamped, disarm-first arm is safe for every budget
and even when callers re-arm a still-armed slot. Proved (general). -/
theorem fixed_safe :
    ∀ s, (lts cfgFixed).Reachable s → Safe s ∧ DisarmCorrect s ∧ FiringOwned s :=
  safe_of_cfg cfgFixed (by simp [cfgFixed]) deadlinePos_fixed

/-! ## Executable traces (used by the counterexamples in `Flare.Bugs`) -/

def exec (c : Cfg) : St → List Lbl → Option St
  | s, [] => some s
  | s, l :: ls => (step c s l).bind fun s' => exec c s' ls

theorem run_of_exec (c : Cfg) :
    ∀ s ls s', exec c s ls = some s' → (lts c).Run s ls s' := by
  intro s ls
  induction ls generalizing s with
  | nil => intro s' h; simp [exec] at h; subst h; exact .nil _
  | cons l ls ih =>
    intro s' h
    simp only [exec] at h
    cases hs : step c s l with
    | none => simp [hs] at h
    | some t => simp only [hs, Option.bind_some] at h; exact .cons hs (ih t s' h)

/-- The canonical initial state, clock at 1 ms. -/
def s0 : St :=
  { slot := 0, addr := 0, now := 1, p := .scan, pnow := 0, w := .idle, cur := 0,
    doneReq := 0, reqDl := 0, slotReq := 0, claimReq := 0, claimDl := 0,
    fired := false, ret := false, cancelled := fun _ => false }

theorem s0_init : Init s0 := by simp [Init, s0]

end Flare.L5.Watchdog
