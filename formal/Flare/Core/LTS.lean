/-!
# Labelled transition systems and operational-semantics vocabulary

Every stateful component of flare is modelled as a small-step LTS.
`Impl` models transliterate Mojo code; `Spec` models transcribe the RFC.
Refinement (`Simulates`) connects them; `Invariant` captures safety.
-/
namespace Flare

/-- A labelled transition system over states `S` and labels `L`. -/
structure LTS (S : Type) (L : Type) where
  init : S → Prop
  step : S → L → S → Prop

namespace LTS
variable {S L : Type} (M : LTS S L)

/-- Multi-step execution along a trace of labels. -/
inductive Run : S → List L → S → Prop
  | nil (s : S) : Run s [] s
  | cons {s s' s'' : S} {l : L} {ls : List L} :
      M.step s l s' → Run s' ls s'' → Run s (l :: ls) s''

/-- A state is reachable when some trace from an initial state leads to it. -/
def Reachable (s : S) : Prop := ∃ s₀ ls, M.init s₀ ∧ M.Run s₀ ls s

/-- `P` is an inductive invariant: true initially and preserved by `step`. -/
structure Inductive (P : S → Prop) : Prop where
  init : ∀ s, M.init s → P s
  step : ∀ s l s', P s → M.step s l s' → P s'

theorem Inductive.run {M : LTS S L} {P : S → Prop} (h : M.Inductive P) :
    ∀ {s ls s'}, P s → M.Run s ls s' → P s' := by
  intro s ls s' hp hr
  induction hr with
  | nil => exact hp
  | cons hs _ ih => exact ih (h.step _ _ _ hp hs)

theorem Inductive.reachable {M : LTS S L} {P : S → Prop} (h : M.Inductive P) :
    ∀ s, M.Reachable s → P s := by
  rintro s ⟨s₀, ls, hi, hr⟩
  exact h.run (h.init _ hi) hr

/-- Deterministic executable step function lifted to an LTS. -/
def ofFn (init : S → Prop) (f : S → L → Option S) : LTS S L where
  init := init
  step s l s' := f s l = some s'

end LTS

/-- Forward simulation: every `impl` step is matched by a `spec` step under
the abstraction `abs` (labels map through `lab`). -/
structure Simulates {S₁ S₂ L₁ L₂ : Type}
    (impl : LTS S₁ L₁) (spec : LTS S₂ L₂)
    (abs : S₁ → S₂) (lab : L₁ → L₂) : Prop where
  init : ∀ s, impl.init s → spec.init (abs s)
  step : ∀ s l s', impl.step s l s' → spec.step (abs s) (lab l) (abs s')

theorem Simulates.run {S₁ S₂ L₁ L₂ : Type} {impl : LTS S₁ L₁} {spec : LTS S₂ L₂}
    {abs : S₁ → S₂} {lab : L₁ → L₂} (h : Simulates impl spec abs lab) :
    ∀ {s ls s'}, impl.Run s ls s' → spec.Run (abs s) (ls.map lab) (abs s') := by
  intro s ls s' hr
  induction hr with
  | nil => exact .nil _
  | cons hs _ ih => exact .cons (h.step _ _ _ hs) ih

/-- A streaming consumer is chunking-independent when feeding `a ++ b` equals
feeding `a` then `b`. Used for every incremental parser in flare. -/
def ChunkingIndependent {S E : Type} (feed : S → List UInt8 → Except E S) : Prop :=
  ∀ s a b, feed s (a ++ b) = (feed s a >>= fun s' => feed s' b)

end Flare
