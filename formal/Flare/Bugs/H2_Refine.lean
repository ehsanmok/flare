import Flare.Bugs.H2_02
import Flare.Bugs.H2_03
import Flare.Bugs.H2_12
import Flare.Bugs.H2_13
import Flare.Bugs.H2_14
import Flare.Bugs.H2_16
import Flare.Bugs.H2_17
import Flare.Bugs.H2_18
import Flare.Bugs.H2_19
import Flare.Bugs.H2_20
import Flare.L3_Protocol.H2.RefineShipped

/-!
# §5.1 refinement: every guard is a real departure

`Flare.L3.H2.Refine.shipped_classified` shows the shipped code can fail
the §5.1 refinement only where a guard fires. Here, for each guard, a
trace from a freshly configured connection reaches a state where the
guard fires and the shipped step is not a spec step:

* frames: the shipped transition, read through the refinement's own
  labelling (`flab`), with the shipped verdict, is rejected by
  `StreamSpec.specStep` (`specOK = false`, `specOK_false`); the fixed
  model's step on the same state is accepted;
* `g06` (server), `g18`: the shipped step raises, so there is no reply at
  all;
* `g19`: the shipped reply sends WINDOW_UPDATE on a stream it has just
  closed, which `sendPost` forbids;
* `g12`, `g13`: the shipped local action moves a stream from half-closed
  (remote) / closed to half-closed (local), which no run of the spec can
  do (`absorb`).
-/
namespace Flare.Bugs.H2_Refine
open Flare Flare.L3.H2.Conn Flare.L3.H2.Refine Flare.L3.H2.StreamSpec Flare.Bugs.H2_Fixtures

/-! ## Checks -/

/-- Whether the spec accepts the step's transition on the frame's
labelled stream, with the step's verdict. -/
def specOK (c : Conn) (f : Fr) : Res → Bool
  | .error _ => false
  | .ok r =>
    match verdict r.2 (flab c f).1 with
    | .conn e => recvOK (pid c (flab c f).1) (room c) (abs c (flab c f).1) (flab c f).2 (.conn e) .closed
    | v => recvOK (pid c (flab c f).1) (room c) (abs c (flab c f).1) (flab c f).2 v (abs r.1 (flab c f).1)

/-- The spec state a step leads to under the refinement. -/
def post (c : Conn) (f : Fr) (r : Conn × List Out) : Option (Nat → SS) :=
  match verdict r.2 (flab c f).1 with
  | .conn _ => none
  | _ => some (abs r.1)

theorem specOK_false (c : Conn) (f : Fr) (r : Conn × List Out) (h : specOK c f (.ok r) = false) :
    ¬ (Flare.L3.H2.StreamSpec.lts c.isClient).step (some (abs c))
      (.recv (flab c f).1 (flab c f).2 (verdict r.2 (flab c f).1) (room c)) (post c f r) := by
  rintro ⟨M, hM, hs⟩
  cases hM
  simp only [specOK, pid] at h; simp only [post] at hs
  generalize verdict r.2 (flab c f).1 = v at h hs
  cases v <;> dsimp only at h <;> simp only [specStep] at hs <;> rw [hs.1] at h <;> cases h

def raises : Res → Bool
  | .error _ => true
  | .ok _ => false

/-- The connection reached by the shipped code after `pre`. -/
def at_ (init : Conn) (pre : List Ev) : Conn := ((run Fix.none dec init pre).map (·.1)).getD {}

theorem at_reached (init : Conn) (pre : List Ev) (h : (run Fix.none dec init pre).isSome = true) :
    ∃ tr, run Fix.none dec init pre = some (at_ init pre, tr) := by
  cases hr : run Fix.none dec init pre with
  | none => rw [hr] at h; cases h
  | some p => exact ⟨p.2, by simp [at_, hr]⟩

/-- A frame witness: the guard fires, the shipped step is rejected by the
spec, the fixed step is accepted. -/
def frameW (g : Conn → Fr → Bool) (init : Conn) (pre : List Ev) (f : Fr) : Bool :=
  (run Fix.none dec init pre).isSome && g (at_ init pre) f &&
  !specOK (at_ init pre) f (step Fix.none dec (at_ init pre) (.frame f)) &&
  specOK (at_ init pre) f (step F dec (at_ init pre) (.frame f))

/-! ## Frame guards -/

theorem w02 : frameW g02 { maxConcurrent := 1 } (H2_02.tr.take 4) (hdrs 3 true 1) = true := by native_decide
theorem w03 : frameW g03 { isClient := true } H2_03.pre (rstF 1) = true := by native_decide
theorem w04 : frameW g04 { isClient := true } [.frame settings0] (hdrs 2 true 4) = true := by native_decide
theorem w08 : frameW g08 {} [] (hdrs 1 true 1) = true := by native_decide
theorem w11 : frameW g11 { maxConcurrent := 0 } [.frame settings0] (hdrs 1 true 1) = true := by native_decide
theorem w14 : frameW g14 { isClient := true } (H2_14.tr.take 3) (hdrs 1 true 7) = true := by native_decide
theorem w15 : frameW g15 {} [.frame settings0, .frame (hdrs 3 true 1)] (wuF 2 1) = true := by native_decide
theorem w16 : frameW g16 {} [.frame settings0] H2_16.prio = true := by native_decide
theorem w17 : frameW g17 { isClient := true } [.frame settings0, .openLocal 1 true] H2_17.push = true := by
  native_decide
theorem w20 : frameW g20 { isClient := true } (H2_20.tr.take 3) (dataF 1 1 false) = true := by native_decide

/-- H2-06 (server) and H2-18: the guard fires and the shipped step raises. -/
theorem w06 : (run Fix.none dec {} [.frame settings0]).isSome &&
    g06 (at_ {} [.frame settings0]) (hdrs 0 true 1) &&
    raises (step Fix.none dec (at_ {} [.frame settings0]) (.frame (hdrs 0 true 1))) = true := by native_decide

theorem w18 : (run Fix.none dec { isClient := true } [.frame settings0, .openLocal 1 true]).isSome &&
    g18 (at_ { isClient := true } [.frame settings0, .openLocal 1 true]) H2_18.big &&
    raises (step Fix.none dec (at_ { isClient := true } [.frame settings0, .openLocal 1 true])
      (.frame H2_18.big)) = true := by native_decide

/-- H2-19: the guard fires and the shipped reply carries WINDOW_UPDATE(1, 3)
on stream 1, which the step leaves closed; §5.1 forbids sending it there. -/
theorem w19 : (run Fix.none dec { isClient := true } (H2_19.tr.take 3)).isSome &&
    g19 (at_ { isClient := true } (H2_19.tr.take 3)) (dataF 1 3 true) &&
    (match step Fix.none dec (at_ { isClient := true } (H2_19.tr.take 3)) (.frame (dataF 1 3 true)) with
     | .ok r => r.2.contains (.wu 1 3) && abs r.1 1 == .closed
     | .error _ => false) = true := by native_decide

theorem w19_spec : sendPost .closed .wu = none := rfl

/-! ## Local guards -/

theorem run_none {client : Bool} {ls : List Lab} {s : Option (Nat → SS)} :
    (Flare.L3.H2.StreamSpec.lts client).Run none ls s → s = none := by
  intro h
  cases h with
  | nil => rfl
  | cons hs _ => obtain ⟨M, hM, _⟩ := hs; cases hM

def HC (s : SS) : Prop := s = .hcr ∨ s = .closed

theorem okPost_hc (p r : Bool) (s : SS) (k : RK) (s' : SS) (hs : HC s) (h : okPost p r s k s' = true) : HC s' := by
  rcases hs with hs | hs <;> subst hs <;> cases k <;> cases s' <;> simp_all [okPost, HC]

theorem strmOK_hc (s : SS) (k : RK) (s' : SS) (h : (strmOK s k && s' == .closed) = true) : HC s' := by
  simp at h; exact Or.inr h.2

theorem sendPost_hc (s : SS) (k : SK) (s' : SS) (hs : HC s) (h : sendPost s k = some s') : HC s' := by
  rcases hs with hs | hs <;> subst hs <;> cases k <;> simp_all [sendPost, esTo, HC] <;>
    (try split at h) <;> simp_all

/-- Half-closed (remote) and closed are absorbing in the §5.1 spec. -/
theorem absorb {client : Bool} {M M' : Nat → SS} (k : Nat) :
    ∀ {s s' : Option (Nat → SS)} {ls : List Lab}, (Flare.L3.H2.StreamSpec.lts client).Run s ls s' →
      s = some M → s' = some M' → HC (M k) → HC (M' k) := by
  intro s s' ls h
  revert M M'
  induction h with
  | nil => intro M M' h1 h2 hk; rw [h1] at h2; cases h2; exact hk
  | cons hs hr ih =>
    rename_i s0 s1 s2 l ls'
    intro M M' h1 h2 hk
    subst h1
    obtain ⟨M0, hM0, hst⟩ := hs
    cases hM0
    cases s1 with
    | none => rw [run_none hr] at h2; cases h2
    | some M1 =>
      refine ih (M := M1) (M' := M') rfl h2 ?_
      have hoth : ∀ j, Others M M1 j → j ≠ k → HC (M1 k) := by
        intro j ho hj
        rcases ho k (Ne.symm hj) with e | ⟨e, -, -⟩
        · rw [e]; exact hk
        · rw [e] at hk; rcases hk with h | h <;> cases h
      cases l with
      | recv j rk v room =>
        cases v with
        | conn e => simp only [specStep] at hst; cases hst.2
        | ok =>
          simp only [specStep] at hst
          by_cases hj : j = k
          · subst hj; exact okPost_hc _ _ _ _ _ hk hst.1
          · exact hoth j hst.2 hj
        | strm e =>
          simp only [specStep] at hst
          by_cases hj : j = k
          · subst hj; exact strmOK_hc _ _ _ hst.1
          · exact hoth j hst.2 hj
      | send j sk =>
        simp only [specStep] at hst
        by_cases hj : j = k
        · subst hj; exact sendPost_hc _ _ _ hk hst.1
        · exact hoth j hst.2 hj
      | conn => simp only [specStep] at hst; subst hst; exact hk

/-- A local witness: the guard fires and the shipped action moves stream
`k` from `a` to half-closed (local). -/
def localW (init : Conn) (pre : List Ev) (e : Ev) (k : Nat) (a : SS) : Bool :=
  (run Fix.none dec init pre).isSome && guard (at_ init pre) e &&
  abs (at_ init pre) k == a &&
  (match step Fix.none dec (at_ init pre) e with
   | .ok r => abs r.1 k == .hcl
   | .error _ => false)

theorem w12 : localW { isClient := true } (H2_12.tr.take 3) (.endLocal 1 false) 1 .hcr = true := by native_decide
theorem w13 : localW { isClient := true } (H2_13.tr.take 3) (.endLocal 1 true) 1 .closed = true := by native_decide

/-- The shipped action has a result that no spec run reaches. -/
def Departs (init : Conn) (pre : List Ev) (e : Ev) : Prop :=
  ∃ r, step Fix.none dec (at_ init pre) e = .ok r ∧
    ∀ ls, ¬ (Flare.L3.H2.StreamSpec.lts (at_ init pre).isClient).Run (some (abs (at_ init pre))) ls (some (abs r.1))

theorem localW_departs (init : Conn) (pre : List Ev) (e : Ev) (k : Nat) (a : SS) (ha : HC a)
    (h : localW init pre e k a = true) : Departs init pre e := by
  unfold localW at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨-, -⟩, hk⟩, hs⟩ := h
  revert hs
  cases hst : step Fix.none dec (at_ init pre) e with
  | error _ => intro hs; cases hs
  | ok r =>
    intro hs
    simp only [beq_iff_eq] at hs
    refine ⟨r, hst, fun ls hrun => ?_⟩
    have := absorb (M := abs (at_ init pre)) (M' := abs r.1) k hrun rfl rfl (by rw [hk]; exact ha)
    rw [hs] at this; rcases this with h | h <;> cases h

/-- H2-12 and H2-13: no run of the spec matches the shipped local action. -/
theorem w12_departs : Departs { isClient := true } (H2_12.tr.take 3) (.endLocal 1 false) :=
  localW_departs _ _ _ _ _ (Or.inl rfl) w12
theorem w13_departs : Departs { isClient := true } (H2_13.tr.take 3) (.endLocal 1 true) :=
  localW_departs _ _ _ _ _ (Or.inr rfl) w13

end Flare.Bugs.H2_Refine
