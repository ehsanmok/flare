import Flare.L3_Protocol.H2.RefineLocal

/-!
# §5.1 refinement: whole runs of the fixed model

`fixed_step` combines `fixed_frame` (inbound frames) and `fixed_local`
(admissible local actions): each step of the fixed model `F` is matched by
a run of the §5.1 spec LTS (`StreamSpec.lts`) from the abstraction of the
old connection, ending in the abstraction of the new one, or in the spec's
dead state `none` when the reply carries a GOAWAY.

`fixed_run` chains this over a trace up to the first GOAWAY (`runG`);
`fixed_refines` starts from a fresh connection, whose abstraction is the
spec's initial state (every stream idle). Frames after our GOAWAY are out
of scope: §6.8 lets the endpoint ignore them, and the spec has no state
for them.
-/
namespace Flare.L3.H2.Refine
open Flare.L3.H2.Conn Flare.L3.H2.StreamSpec

theorem run_append {S L : Type} {M : LTS S L} {a b d : S} {l1 l2 : List L}
    (h1 : M.Run a l1 b) (h2 : M.Run b l2 d) : M.Run a (l1 ++ l2) d := by
  induction h1 with
  | nil => exact h2
  | cons hs _ ih => exact .cons hs (ih h2)

theorem gaCode_none_of {o : List Out} (h : hasGoaway o = false) : gaCode o = none := by
  induction o with
  | nil => rfl
  | cons x t ih =>
    cases x <;> simp_all [hasGoaway, isGoaway, gaCode]

theorem gaCode_some_of {o : List Out} (h : hasGoaway o = true) : ∃ e, gaCode o = some e := by
  induction o with
  | nil => simp [hasGoaway] at h
  | cons x t ih =>
    simp only [hasGoaway, List.any_cons, Bool.or_eq_true] at h
    cases x with
    | goaway l e => exact ⟨e, rfl⟩
    | _ => rcases h with h | h
           · cases h
           · exact ih h

theorem local_noGoaway (dec : Dec) (c : Conn) (e : Ev) (r : Conn × List Out)
    (he : ∀ f, e ≠ .frame f) (h : step F dec c e = .ok r) : hasGoaway r.2 = false := by
  cases e with
  | frame f => exact absurd rfl (he f)
  | release n =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold release; simp only; split <;> rfl
  | respond k n =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold respond; repeat' split
    all_goals rfl
  | send k n =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold send; simp only; repeat' split
    all_goals rfl
  | openLocal k es => simp only [step, Except.ok.injEq] at h; subst h; rfl
  | pop k => simp only [step, Except.ok.injEq] at h; subst h; rfl
  | endLocal k em => simp only [step, Except.ok.injEq] at h; subst h; rfl
  | stream k => simp only [step, Except.ok.injEq] at h; subst h; rfl
  | drain k =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold drain; repeat' split
    all_goals rfl

/-- One step of the fixed model refines the §5.1 spec. -/
theorem fixed_step (dec : Dec) (c : Conn) (e : Ev) (hI : Inv c) (hok : LocalOK c e) :
    ∃ r, step F dec c e = .ok r ∧
      (hasGoaway r.2 = true → ∃ ls, (StreamSpec.lts c.isClient).Run (some (abs c)) ls none) ∧
      (hasGoaway r.2 = false → Inv r.1 ∧ r.1.isClient = c.isClient ∧ ∃ ls, SRun c.isClient (abs c) ls (abs r.1)) := by
  cases e with
  | frame f =>
    obtain ⟨r, hr, hs, -⟩ := fixed_frame dec c f hI hI.ga
    refine ⟨r, hr, ?_, ?_⟩
    · intro hga
      obtain ⟨e, he⟩ := gaCode_some_of hga
      unfold SGood at hs
      have hv : verdict r.2 (flab c f).1 = .conn e := by unfold verdict; rw [he]
      rw [hv] at hs
      exact ⟨[.recv (flab c f).1 (flab c f).2 (.conn e) (room c)],
        .cons (s' := none) ⟨abs c, rfl, hs, rfl⟩ (.nil _)⟩
    · intro hga
      have hn := gaCode_none_of hga
      have hcl : r.1.isClient = c.isClient := by
        rcases seq_step F dec c f r hI.ga (Or.inl rfl) hr with h | h
        · rw [hga] at h; cases h
        · exact h.2.2
      unfold SGood at hs
      cases hv : verdict r.2 (flab c f).1 with
      | conn e => unfold verdict at hv; rw [hn] at hv; simp only [] at hv; split at hv <;> cases hv
      | ok =>
        rw [hv] at hs
        obtain ⟨h1, h2, -, h4⟩ := hs
        exact ⟨h4, hcl, [.recv (flab c f).1 (flab c f).2 .ok (room c)],
          .cons (s' := some (abs r.1)) ⟨abs c, rfl, h1, h2⟩ (.nil _)⟩
      | strm e =>
        rw [hv] at hs
        obtain ⟨h1, h2, -, h4⟩ := hs
        exact ⟨h4, hcl, [.recv (flab c f).1 (flab c f).2 (.strm e) (room c)],
          .cons (s' := some (abs r.1)) ⟨abs c, rfl, h1, h2⟩ (.nil _)⟩
  | _ =>
    obtain ⟨c', o, hr, hI', ls, hrun⟩ := fixed_local dec c _ hI hok (fun _ h => by cases h)
    refine ⟨(c', o), hr, ?_, ?_⟩
    · intro hga
      rw [local_noGoaway dec c _ _ (fun _ h => by cases h) hr] at hga; cases hga
    · intro _
      exact ⟨hI', (hb_local F dec c _ _ (fun _ h => by cases h) hr).2.2.2.2, ls, hrun⟩

/-- The fixed model on a trace, stopping at the first reply that carries a
GOAWAY (`true` in the second component); `none` if a step raises. -/
def runG (dec : Dec) : Conn → List Ev → Option (Conn × Bool)
  | c, [] => some (c, false)
  | c, e :: es =>
    match step F dec c e with
    | .error _ => none
    | .ok (c', o) => if hasGoaway o then some (c', true) else runG dec c' es

/-- Every local action in the trace meets its contract when it is taken. -/
def Adm (dec : Dec) : Conn → List Ev → Prop
  | _, [] => True
  | c, e :: es => LocalOK c e ∧ ∀ r, step F dec c e = .ok r → hasGoaway r.2 = false → Adm dec r.1 es

/-- **Run refinement.** From any connection satisfying `Inv`, an admissible
trace never raises in the fixed model and is matched by a run of the §5.1
spec: to the abstraction of the final connection (which again satisfies
`Inv`), or to the spec's dead state if the run stopped at a GOAWAY. -/
theorem fixed_run (dec : Dec) :
    ∀ (es : List Ev) (c : Conn), Inv c → Adm dec c es →
      ∃ c' b, runG dec c es = some (c', b) ∧
        ∃ ls, (StreamSpec.lts c.isClient).Run (some (abs c)) ls (if b then none else some (abs c')) ∧
          (b = false → Inv c') := by
  intro es
  induction es with
  | nil => intro c hI _; exact ⟨c, false, rfl, [], .nil _, fun _ => hI⟩
  | cons e es ih =>
    intro c hI hadm
    obtain ⟨hok, hrest⟩ := hadm
    obtain ⟨r, hr, hdead, hlive⟩ := fixed_step dec c e hI hok
    obtain ⟨c1, o⟩ := r
    simp only [runG, hr]
    cases hga : hasGoaway o with
    | true =>
      obtain ⟨ls, hrun⟩ := hdead hga
      exact ⟨c1, true, by simp, ls, hrun, fun h => by cases h⟩
    | false =>
      obtain ⟨hI1, hcl, ls1, hrun1⟩ := hlive hga
      obtain ⟨c', b, hrg, ls2, hrun2, hinv⟩ := ih c1 hI1 (hrest _ hr hga)
      refine ⟨c', b, by simpa using hrg, ls1 ++ ls2, ?_, hinv⟩
      rw [hcl] at hrun2
      exact run_append hrun1 hrun2

/-- The part of `Conn.Fresh` the refinement reads (empty table, no ids
used, no block, nothing reset, no GOAWAY sent). -/
structure Fresh0 (c : Conn) : Prop where
  streams : c.streams = []
  lastPeer : c.lastPeer = 0
  maxLocalSid : c.maxLocalSid = 0
  continuing : c.continuing = 0
  blockRefuse : c.blockRefuse = 0
  resetByUs : c.resetByUs = []
  goawaySent : c.goawaySent = false

theorem fresh0_of {c : Conn} (h : Conn.Fresh c) : Fresh0 c := by
  obtain ⟨h1, -, -, -, h5, h6, -, -, h9, h10, h11, h12⟩ := h
  exact ⟨h1, h9, h12, h6, h11, h10, h5⟩

theorem fresh_get {c : Conn} (h : Fresh0 c) (k : Nat) : get c k = none := by
  unfold Flare.L3.H2.Conn.get; rw [h.streams]; rfl

theorem inv_fresh {c : Conn} (h : Fresh0 c) : Inv c := by
  refine ⟨by unfold NoDupK; rw [h.streams]; exact List.nodup_nil, fun k s hs => ?_, fun k s hs => ?_,
    fun _ k s hs => ?_, fun a => absurd h.continuing a, fun a => absurd h.continuing a,
    fun _ => h.blockRefuse, fun k hk => ?_, h.goawaySent⟩ <;>
    first | (rw [fresh_get h] at hs; cases hs) | (rw [h.resetByUs] at hk; cases hk)

theorem abs_fresh {c : Conn} (h : Fresh0 c) : abs c = fun _ => .idle := by
  funext k
  rw [abs_none (fresh_get h k)]
  unfold idleAbs; rw [h.lastPeer, h.maxLocalSid]
  cases c.isClient <;> by_cases hk : k = 0 <;> simp [hk] <;> omega

/-- **§5.1 refinement of the fixed model.** From a fresh connection, every
admissible trace is matched by a run of the §5.1 spec LTS starting in its
initial state. -/
theorem fixed_refines (dec : Dec) (c : Conn) (es : List Ev) (hf : Conn.Fresh c) (hadm : Adm dec c es) :
    ∃ c' b, runG dec c es = some (c', b) ∧
      ∃ s₀ ls, (StreamSpec.lts c.isClient).init s₀ ∧
        (StreamSpec.lts c.isClient).Run s₀ ls (if b then none else some (abs c')) := by
  obtain ⟨c', b, hr, ls, hrun, -⟩ := fixed_run dec es c (inv_fresh (fresh0_of hf)) hadm
  rw [abs_fresh (fresh0_of hf)] at hrun
  exact ⟨c', b, hr, _, ls, rfl, hrun⟩

end Flare.L3.H2.Refine
