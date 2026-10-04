import Flare.L3_Protocol.H3.RequestReader

/-!
# RFC 9114 §4.1 request-stream grammar vs flare's reader

Spec (independent of flare): an automaton over frame types accepting the
prefixes of `HEADERS DATA* [HEADERS]`, ignoring unknown types and rejecting
control-stream types and the HTTP/2-reserved types.

Results:
* `run_accept_impl` / `run_reject_impl`: flare's `stepFrame` run reports no
  error and tracks the spec state exactly on spec-accepted sequences, and
  reports an error on spec-rejected ones — for sequences without
  HTTP/2-reserved frame types. With them, see `Flare.Bugs.H3_02`.
-/
namespace Flare.L3.H3

variable {Hdrs : Type}

inductive Q | q0 | q1 | q2
  deriving DecidableEq, Repr

/-- RFC 9114 §4.1 (`HEADERS DATA* [HEADERS]`), §7.2.8 (unknown types ignored;
types 0x02/0x06/0x08/0x09 are H3_FRAME_UNEXPECTED), §7.2.3-7.2.7
(CANCEL_PUSH, SETTINGS, GOAWAY, MAX_PUSH_ID on a request stream and
PUSH_PROMISE received by a server are H3_FRAME_UNEXPECTED).
`none` = the frame must be rejected. -/
def specStep (q : Q) (t : Nat) : Option Q :=
  if t = 0x01 then (match q with | .q0 => some .q1 | .q1 => some .q2 | .q2 => none)
  else if t = 0x00 then (match q with | .q1 => some .q1 | _ => none)
  else if t = 0x03 ∨ t = 0x04 ∨ t = 0x05 ∨ t = 0x07 ∨ t = 0x0D then none
  else if t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09 then none
  else some q

def specRun : Q → List Nat → Option Q
  | q, [] => some q
  | q, t :: ts => match specStep q t with
    | none => none
    | some q' => specRun q' ts

def absQ : RState → Option Q
  | .init => some .q0
  | .body => some .q1
  | .trailers => some .q2
  | .done => none

/-- Frame-type classes. -/
inductive K | hdr | dat | ctrl | h2res | unk
  deriving DecidableEq

def kind (t : Nat) : K :=
  if t = 1 then .hdr else if t = 0 then .dat
  else if t = 0x03 ∨ t = 0x04 ∨ t = 0x05 ∨ t = 0x07 ∨ t = 0x0D then .ctrl
  else if t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09 then .h2res else .unk

def specStepK (q : Q) : K → Option Q
  | .hdr => (match q with | .q0 => some .q1 | .q1 => some .q2 | .q2 => none)
  | .dat => (match q with | .q1 => some .q1 | _ => none)
  | .ctrl => none
  | .h2res => none
  | .unk => some q

theorem specStep_kind (q : Q) (t : Nat) : specStep q t = specStepK q (kind t) := by
  unfold specStep kind
  by_cases h1 : t = 1
  · simp [h1, specStepK]
  · by_cases h0 : t = 0
    · simp [h0, specStepK]
    · by_cases hc : t = 0x03 ∨ t = 0x04 ∨ t = 0x05 ∨ t = 0x07 ∨ t = 0x0D
      · simp [h1, h0, hc, specStepK]
      · by_cases hr : t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09
        · simp [h1, h0, hc, hr, specStepK]
        · simp [h1, h0, hc, hr, specStepK]

theorem isControlType_iff (t : Nat) :
    isControlType t = true ↔ (t = 0x03 ∨ t = 0x04 ∨ t = 0x05 ∨ t = 0x07 ∨ t = 0x0D) := by
  unfold isControlType T_SETTINGS T_GOAWAY T_MAX_PUSH_ID T_CANCEL_PUSH T_PUSH_PROMISE
  simp only [Bool.or_eq_true, beq_iff_eq]; omega

theorem isH2Reserved_iff (t : Nat) :
    isH2Reserved t = true ↔ (t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09) := by
  unfold isH2Reserved; simp only [Bool.or_eq_true, beq_iff_eq]; omega

/-- `stepFrame` through the kind classification. -/
def stepFrameK (qd : Bytes → Option Hdrs) (r : Reader) (k : K) (t : Nat) (p : Bytes) :
    Reader × Ev Hdrs :=
  match k with
  | .hdr =>
    if r.st = .trailers then ({r with st := .done}, .error .headersAfterTrailers)
    else if p.length > r.maxField then ({r with st := .done}, .error .fieldTooBig)
    else match qd p with
      | none => ({r with st := .done}, .error .qpack)
      | some h =>
        if r.st = .init then ({r with st := .body}, .headers h)
        else ({r with st := .trailers}, .trailers h)
  | .dat =>
    if r.st ≠ .body then ({r with st := .done}, .error .dataOutside)
    else ({r with bodyBytes := r.bodyBytes + p.length}, .data p)
  | .ctrl => ({r with st := .done}, .error .controlType)
  | .h2res => (r, .unknown t)
  | .unk => (r, .unknown t)

theorem stepFrame_kind (qd : Bytes → Option Hdrs) (r : Reader) (t : Nat) (p : Bytes) :
    stepFrame qd r t p = stepFrameK qd r (kind t) t p := by
  unfold stepFrame kind
  unfold T_HEADERS T_DATA
  by_cases h1 : t = 1
  · subst h1; rfl
  · by_cases h0 : t = 0
    · subst h0; rfl
    · by_cases hc : t = 0x03 ∨ t = 0x04 ∨ t = 0x05 ∨ t = 0x07 ∨ t = 0x0D
      · have := (isControlType_iff t).2 hc
        simp [h1, h0, hc, this, stepFrameK]
      · have : isControlType t = false := by
          cases h : isControlType t
          · rfl
          · exact absurd ((isControlType_iff t).1 h) hc
        by_cases hr : t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09
        · simp [h1, h0, hc, hr, this, stepFrameK]
        · simp [h1, h0, hc, hr, this, stepFrameK]

/-- A frame within the reader's limits whose field section QPACK accepts. -/
def GoodFrame (qd : Bytes → Option Hdrs) (maxField : Nat) (f : Nat × Bytes) : Prop :=
  f.1 = T_HEADERS → f.2.length ≤ maxField ∧ (qd f.2).isSome

theorem stepFrameK_maxField (qd : Bytes → Option Hdrs) (r : Reader) (k : K) (t : Nat)
    (p : Bytes) : (stepFrameK qd r k t p).1.maxField = r.maxField := by
  cases k <;> simp only [stepFrameK] <;> (repeat' split) <;> rfl

theorem stepFrameK_agrees (qd : Bytes → Option Hdrs) (r : Reader) (k : K) (t : Nat)
    (p : Bytes) (q : Q) (hq : absQ r.st = some q)
    (hg : k = .hdr → p.length ≤ r.maxField ∧ (qd p).isSome) (hk : k ≠ .h2res) :
    (stepFrameK qd r k t p).1.maxField = r.maxField ∧
    (∀ q', specStepK q k = some q' →
      (stepFrameK qd r k t p).2.isError = false ∧ absQ (stepFrameK qd r k t p).1.st = some q') ∧
    (specStepK q k = none → (stepFrameK qd r k t p).2.isError = true) := by
  cases k with
  | hdr =>
    obtain ⟨hl, hs⟩ := hg rfl
    have hl' : ¬ p.length > r.maxField := by omega
    rcases hqd : qd p with _ | h
    · rw [hqd] at hs; cases hs
    · cases hst : r.st <;> rw [hst] at hq <;> simp [absQ] at hq <;> subst hq <;>
        simp [stepFrameK, hst, hqd, hl', specStepK, Ev.isError, absQ]
  | dat =>
    cases hst : r.st <;> rw [hst] at hq <;> simp [absQ] at hq <;> subst hq <;>
      simp [stepFrameK, hst, specStepK, Ev.isError, absQ]
  | ctrl => simp [stepFrameK, specStepK, Ev.isError]
  | h2res => exact absurd rfl hk
  | unk => simp [stepFrameK, specStepK, Ev.isError, hq]

theorem kind_ne_h2res {t : Nat} (h : isH2Reserved t = false) : kind t ≠ .h2res := by
  have hr : ¬ (t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09) := by
    intro hh; rw [(isH2Reserved_iff t).2 hh] at h; cases h
  unfold kind
  by_cases h1 : t = 1
  · simp [h1]
  · by_cases h0 : t = 0
    · simp [h0]
    · by_cases hc : t = 0x03 ∨ t = 0x04 ∨ t = 0x05 ∨ t = 0x07 ∨ t = 0x0D
      · simp [h1, h0, hc]
      · simp [h1, h0, hc, hr]

theorem kind_hdr {t : Nat} (h : kind t = .hdr) : t = T_HEADERS := by
  unfold kind at h; unfold T_HEADERS
  by_cases h1 : t = 1
  · exact h1
  · by_cases h0 : t = 0
    · simp [h0] at h
    · by_cases hc : t = 0x03 ∨ t = 0x04 ∨ t = 0x05 ∨ t = 0x07 ∨ t = 0x0D
      · simp [h1, h0, hc] at h
      · by_cases hr : t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09
        · simp [h1, h0, hc, hr] at h
        · simp [h1, h0, hc, hr] at h

/-- One-step agreement of a frame-level step function with the spec. -/
def StepAgrees (step : Reader → Nat → Bytes → Reader × Ev Hdrs) (r : Reader) (t : Nat)
    (p : Bytes) : Prop :=
  (step r t p).1.maxField = r.maxField ∧
  ∀ q, absQ r.st = some q →
    (∀ q', specStep q t = some q' →
      (step r t p).2.isError = false ∧ absQ (step r t p).1.st = some q') ∧
    (specStep q t = none → (step r t p).2.isError = true)

/-- flare's dispatch agrees with the spec on every good frame whose type is
not HTTP/2-reserved. -/
theorem stepFrame_agrees (qd : Bytes → Option Hdrs) (r : Reader) (t : Nat) (p : Bytes)
    (hg : GoodFrame qd r.maxField (t, p)) (hres : isH2Reserved t = false) :
    StepAgrees (stepFrame qd) r t p := by
  have hk := kind_ne_h2res hres
  have hg' : kind t = .hdr → p.length ≤ r.maxField ∧ (qd p).isSome :=
    fun h => hg (kind_hdr h)
  rw [StepAgrees, stepFrame_kind]
  refine ⟨stepFrameK_maxField qd r (kind t) t p, fun q hq => ?_⟩
  rw [specStep_kind]
  exact (stepFrameK_agrees qd r (kind t) t p q hq hg' hk).2

/-- Run a frame-level step function over complete frames. -/
def runFrames (step : Reader → Nat → Bytes → Reader × Ev Hdrs) :
    Reader → List (Nat × Bytes) → Reader × List (Ev Hdrs)
  | r, [] => (r, [])
  | r, (t, p) :: fs =>
    ((runFrames step (step r t p).1 fs).1, (step r t p).2 :: (runFrames step (step r t p).1 fs).2)

/-- Generic acceptance: if every step agrees with the spec, a spec-accepted
sequence produces no error and ends in the matching spec state. -/
theorem runFrames_accept {P : Nat → Prop} (qd : Bytes → Option Hdrs)
    (step : Reader → Nat → Bytes → Reader × Ev Hdrs)
    (hstep : ∀ r t p, GoodFrame qd r.maxField (t, p) → P t → StepAgrees step r t p)
    (fs : List (Nat × Bytes)) (r : Reader) (q q' : Q) (hq : absQ r.st = some q)
    (hgood : ∀ f ∈ fs, GoodFrame qd r.maxField f) (hP : ∀ f ∈ fs, P f.1)
    (hacc : specRun q (fs.map Prod.fst) = some q') :
    (∀ e ∈ (runFrames step r fs).2, e.isError = false) ∧
      absQ (runFrames step r fs).1.st = some q' := by
  induction fs generalizing r q with
  | nil => simp [specRun] at hacc; subst hacc; simp [runFrames, hq]
  | cons f fs ih =>
    obtain ⟨t, p⟩ := f
    have hs := hstep r t p (hgood (t, p) List.mem_cons_self) (hP (t, p) List.mem_cons_self)
    simp only [List.map_cons, specRun] at hacc
    cases hsq : specStep q t with
    | none => rw [hsq] at hacc; cases hacc
    | some qb =>
      rw [hsq] at hacc
      obtain ⟨hne, hq1⟩ := (hs.2 q hq).1 qb hsq
      have ih' := ih (step r t p).1 qb hq1
        (fun f hf => by rw [hs.1]; exact hgood f (by simp [hf]))
        (fun f hf => hP f (by simp [hf])) hacc
      refine ⟨?_, ih'.2⟩
      intro e he
      simp only [runFrames, List.mem_cons] at he
      rcases he with rfl | he
      · exact hne
      · exact ih'.1 e he

/-- Generic rejection: a spec-rejected sequence produces an error event. -/
theorem runFrames_reject {P : Nat → Prop} (qd : Bytes → Option Hdrs)
    (step : Reader → Nat → Bytes → Reader × Ev Hdrs)
    (hstep : ∀ r t p, GoodFrame qd r.maxField (t, p) → P t → StepAgrees step r t p)
    (fs : List (Nat × Bytes)) (r : Reader) (q : Q) (hq : absQ r.st = some q)
    (hgood : ∀ f ∈ fs, GoodFrame qd r.maxField f) (hP : ∀ f ∈ fs, P f.1)
    (hrej : specRun q (fs.map Prod.fst) = none) :
    ∃ e ∈ (runFrames step r fs).2, e.isError = true := by
  induction fs generalizing r q with
  | nil => simp [specRun] at hrej
  | cons f fs ih =>
    obtain ⟨t, p⟩ := f
    have hs := hstep r t p (hgood (t, p) List.mem_cons_self) (hP (t, p) List.mem_cons_self)
    simp only [List.map_cons, specRun] at hrej
    cases hsq : specStep q t with
    | none => exact ⟨_, by simp [runFrames], (hs.2 q hq).2 hsq⟩
    | some qb =>
      rw [hsq] at hrej
      obtain ⟨_, hq1⟩ := (hs.2 q hq).1 qb hsq
      obtain ⟨e, he, hee⟩ := ih (step r t p).1 qb hq1
        (fun f hf => by rw [hs.1]; exact hgood f (by simp [hf]))
        (fun f hf => hP f (by simp [hf])) hrej
      exact ⟨e, by simp [runFrames, he], hee⟩

/-- RFC 9114 §4.1 conformance of flare's request reader (acceptance half),
for sequences without HTTP/2-reserved frame types. -/
theorem run_accept_impl (qd : Bytes → Option Hdrs) (fs : List (Nat × Bytes)) (r : Reader)
    (q q' : Q) (hq : absQ r.st = some q) (hgood : ∀ f ∈ fs, GoodFrame qd r.maxField f)
    (hres : ∀ f ∈ fs, isH2Reserved f.1 = false)
    (hacc : specRun q (fs.map Prod.fst) = some q') :
    (∀ e ∈ (runFrames (stepFrame qd) r fs).2, e.isError = false) ∧
      absQ (runFrames (stepFrame qd) r fs).1.st = some q' :=
  runFrames_accept (P := fun t => isH2Reserved t = false) qd (stepFrame qd)
    (fun r t p hg hp => stepFrame_agrees qd r t p hg hp) fs r q q' hq hgood hres hacc

/-- RFC 9114 §4.1 conformance of flare's request reader (rejection half). -/
theorem run_reject_impl (qd : Bytes → Option Hdrs) (fs : List (Nat × Bytes)) (r : Reader)
    (q : Q) (hq : absQ r.st = some q) (hgood : ∀ f ∈ fs, GoodFrame qd r.maxField f)
    (hres : ∀ f ∈ fs, isH2Reserved f.1 = false)
    (hrej : specRun q (fs.map Prod.fst) = none) :
    ∃ e ∈ (runFrames (stepFrame qd) r fs).2, e.isError = true :=
  runFrames_reject (P := fun t => isH2Reserved t = false) qd (stepFrame qd)
    (fun r t p hg hp => stepFrame_agrees qd r t p hg hp) fs r q hq hgood hres hrej

end Flare.L3.H3
