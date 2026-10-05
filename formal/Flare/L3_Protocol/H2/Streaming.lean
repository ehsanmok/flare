import Flare.L3_Protocol.H2.StreamTable

/-!
# The client's streaming-body mode

`enable_response_streaming` (client.mojo:1189-1197) sets
`defer_body_credit`: from then on the body octets of each DATA frame are
not credited back to the peer when the frame arrives (state.mojo:1450-1455)
but when the application takes them with `drain_body`
(client.mojo:1160-1187), which also hands over the buffered octets.

Results, for every fix set (the shipped code included) and every step:

* `step_rel`: each step keeps every stream's flow fields (`recvW`,
  `pendingCredit`, `buf`), creates it fresh, or (DATA on `k`, `drain k`)
  changes stream `k` only; a stream's buffer is kept, emptied, or extended by
  the frame's own payload, and `drained` output for `k` is exactly the old
  buffer of `k`, which is then empty.
* `ti_step` / `ti_run`: per stream, `recvW + pendingCredit ≤ initW` and
  `pendingCredit ≤ initW` (`pending_le`): we never credit a stream beyond the
  window we advertised, and the credit held back for undrained octets stays
  within one initial window.
* `data_credit`: an accepted DATA frame leaves `recvW + pendingCredit` where
  it was before the frame was debited, holds back exactly the deferred body
  octets (all of them when streaming, none otherwise), and the only stream
  WINDOW_UPDATE it sends carries the rest of the frame; `drain_credit`:
  `drain_body` hands over the buffer, credits back exactly the held credit,
  and sends it as a WINDOW_UPDATE while the stream can still receive DATA.
* `fifo_run`: the octets the application receives from `drain_body` on a
  stream, followed by what is still buffered, are the concatenation of a
  subsequence of the initial buffer and the DATA payloads received on that
  stream, in arrival order: never reordered, duplicated or invented (whole
  payloads are dropped only when the stream is reset or forgotten).

No issue was found in this mode.
-/
namespace Flare.L3.H2.Streaming
open Flare.L3.H2.Conn

/-! ## Flow fields and the per-step stream relation -/

def Flow (s : Stream) : Int × Nat × Bytes := (s.recvW, s.pendingCredit, s.buf)

def FreshS (i : Int) (s : Stream) : Prop := s.recvW = i ∧ s.pendingCredit = 0 ∧ s.buf = []

/-- The per-stream credit bound. -/
def TIs (i : Int) (s : Stream) : Prop := s.recvW + s.pendingCredit ≤ i ∧ (s.pendingCredit : Int) ≤ i

def NoDr (o : List Out) : Prop := ∀ j b, Out.drained j b ∉ o

/-- Where a stream of the new table comes from: fresh, or an entry of the
old table with the same key. -/
def Src (c : Conn) (k : Nat) (s : Stream) : Prop := FreshS c.initW s ∨ (k, s) ∈ c.streams

/-- Every stream of `c'` is fresh or keeps the flow fields of an entry of
`c` with its key. -/
def SR (c c' : Conn) : Prop :=
  c'.initW = c.initW ∧ (NoDupK c.streams → NoDupK c'.streams) ∧
  ∀ k s', (k, s') ∈ c'.streams → FreshS c.initW s' ∨ ∃ s, (k, s) ∈ c.streams ∧ Flow s' = Flow s

def HW (c : Conn) (r : Conn × List Out) : Prop := SR c r.1 ∧ NoDr r.2

theorem sr_refl (c : Conn) : SR c c := ⟨rfl, id, fun _ s' h => Or.inr ⟨s', h, rfl⟩⟩

theorem freshS_flow {i : Int} {s s' : Stream} (h : FreshS i s) (hf : Flow s' = Flow s) : FreshS i s' := by
  simp only [Flow, Prod.mk.injEq] at hf
  obtain ⟨h1, h2, h3⟩ := h
  exact ⟨hf.1.trans h1, hf.2.1.trans h2, hf.2.2.trans h3⟩

theorem sr_trans {a b d : Conn} (h1 : SR a b) (h2 : SR b d) : SR a d := by
  refine ⟨h2.1.trans h1.1, fun h => h2.2.1 (h1.2.1 h), fun k s' hs => ?_⟩
  rcases h2.2.2 k s' hs with hf | ⟨s, hs1, hf⟩
  · left; rw [← h1.1]; exact hf
  · rcases h1.2.2 k s hs1 with hf' | ⟨s0, hs0, hf'⟩
    · left; exact freshS_flow hf' hf
    · right; exact ⟨s0, hs0, hf.trans hf'⟩

theorem sr_streams {c c' : Conn} (h1 : c'.streams = c.streams) (h2 : c'.initW = c.initW) : SR c c' :=
  ⟨h2, fun h => h1 ▸ h, fun _ s' hs => Or.inr ⟨s', h1 ▸ hs, rfl⟩⟩

theorem hw_streams {c : Conn} {r : Conn × List Out} (h1 : r.1.streams = c.streams) (h2 : r.1.initW = c.initW)
    (h3 : NoDr r.2) : HW c r := ⟨sr_streams h1 h2, h3⟩

theorem hw_trans {c c' : Conn} {r : Conn × List Out} (h1 : SR c c') (h2 : HW c' r) : HW c r :=
  ⟨sr_trans h1 h2.1, h2.2⟩

theorem mem_putL {l : List (Nat × Stream)} {k : Nat} {s : Stream} {p : Nat × Stream} (h : p ∈ putL l k s) :
    p = (k, s) ∨ p ∈ l := by
  induction l with
  | nil => simp [putL] at h; exact Or.inl h
  | cons q t ih =>
    unfold putL at h
    split at h
    · rcases List.mem_cons.1 h with h | h
      · exact Or.inl h
      · exact Or.inr (List.mem_cons_of_mem _ h)
    · rcases List.mem_cons.1 h with h | h
      · exact Or.inr (h ▸ List.mem_cons_self ..)
      · rcases ih h with h | h
        · exact Or.inl h
        · exact Or.inr (List.mem_cons_of_mem _ h)

theorem sr_put (c : Conn) (k : Nat) (s s' : Stream) (h : Src c k s) (hf : Flow s' = Flow s) :
    SR c (put c k s') := by
  refine ⟨rfl, fun h => nodupK_putL _ _ _ h, fun j t ht => ?_⟩
  rcases mem_putL ht with he | he
  · simp only [Prod.mk.injEq] at he; obtain ⟨rfl, rfl⟩ := he
    rcases h with h | h
    · exact Or.inl (freshS_flow h hf)
    · exact Or.inr ⟨s, h, hf⟩
  · exact Or.inr ⟨t, he, rfl⟩

theorem mem_of_get {c : Conn} {k : Nat} {s : Stream} (h : get c k = some s) : (k, s) ∈ c.streams := by
  unfold Flare.L3.H2.Conn.get at h
  cases hf : c.streams.find? (·.1 == k) with
  | none => rw [hf] at h; cases h
  | some p =>
    rw [hf] at h; simp only [Option.map_some, Option.some.injEq] at h
    have h1 := List.mem_of_find?_eq_some hf
    have h2 := List.find?_some hf
    simp only [beq_iff_eq] at h2
    subst h
    have : p = (k, p.2) := by rw [← h2]
    rw [← this]; exact h1

theorem src_get {c : Conn} {k : Nat} {s : Stream} (h : get c k = some s) : Src c k s := Or.inr (mem_of_get h)

theorem sr_filter (c : Conn) (P : Nat × Stream → Bool) : SR c { c with streams := c.streams.filter P } :=
  ⟨rfl, fun h => nodupK_filter _ _ h, fun _ s' hs => Or.inr ⟨s', (List.mem_filter.1 hs).1, rfl⟩⟩

theorem sr_rstC (c : Conn) (k : Nat) : SR c (rstC c k) := sr_streams rfl rfl

theorem sr_closeIfKnown (c : Conn) (k : Nat) : SR c (closeIfKnown c k) := by
  unfold closeIfKnown
  split
  · rename_i s hs; exact sr_put c k s _ (src_get hs) rfl
  · exact sr_refl c

theorem sr_ensure (c : Conn) (k : Nat) :
    SR c (ensure c k).1 ∧ Src (ensure c k).1 k (ensure c k).2 := by
  unfold ensure
  split
  · rename_i s hs; exact ⟨sr_refl c, src_get hs⟩
  · simp only []
    split
    · exact ⟨sr_filter c _, Or.inl ⟨rfl, rfl, rfl⟩⟩
    · exact ⟨sr_refl c, Or.inl ⟨rfl, rfl, rfl⟩⟩

theorem noDr_nil : NoDr [] := fun _ _ h => by cases h

theorem noDr_cons {x : Out} {o : List Out} (hx : ∀ j b, x ≠ .drained j b) (h : NoDr o) : NoDr (x :: o) := by
  intro j b hm
  rcases List.mem_cons.1 hm with e | e
  · exact hx j b e.symm
  · exact h j b e

theorem noDr_append {a b : List Out} (ha : NoDr a) (hb : NoDr b) : NoDr (a ++ b) := by
  intro j x hm; rcases List.mem_append.1 hm with h | h
  · exact ha j x h
  · exact hb j x h

theorem noDr_ite {p : Prop} [Decidable p] {a b : List Out} (ha : NoDr a) (hb : NoDr b) :
    NoDr (if p then a else b) := by split <;> assumption

theorem noDr_wu (k n : Nat) : NoDr [.wu k n] := noDr_cons (fun _ _ h => by cases h) noDr_nil
theorem noDr_rst (k e : Nat) : NoDr [.rst k e] := noDr_cons (fun _ _ h => by cases h) noDr_nil
theorem noDr_wu0If (n : Nat) : NoDr (wu0If n) := by unfold wu0If; exact noDr_ite (noDr_wu _ _) noDr_nil

theorem hw_connErr (c : Conn) (e : Nat) : HW c (connErr c e) := by
  unfold connErr; split
  · exact hw_streams rfl rfl noDr_nil
  · exact hw_streams rfl rfl (noDr_cons (fun _ _ h => by cases h) noDr_nil)

theorem hw_connErr_sr {c c' : Conn} (e : Nat) (h : SR c c') : HW c (connErr c' e) := by
  refine ⟨sr_trans h ?_, ?_⟩ <;> unfold connErr <;> split
  · exact sr_streams rfl rfl
  · exact sr_streams rfl rfl
  · exact noDr_nil
  · exact noDr_cons (fun _ _ h => by cases h) noDr_nil

theorem hw_closeRst (c : Conn) (k e : Nat) : HW c (closeIfKnown (rstC c k) k, [.rst k e]) :=
  ⟨sr_trans (sr_rstC c k) (sr_closeIfKnown _ k), noDr_rst k e⟩

theorem hw_rstCloseX (c : Conn) (k e : Nat) (s s' : Stream) (x : List Out) (h : Src c k s)
    (hf : Flow s' = Flow s) (hx : NoDr x) : HW c (rstCloseX c k e s' x) :=
  ⟨sr_put (rstC c k) k s _ h (by rw [← hf]; rfl), noDr_cons (fun _ _ h => by cases h) hx⟩

/-! ## Handlers other than DATA -/

theorem hw_put (c : Conn) (k : Nat) (s s' : Stream) (o : List Out) (h : Src c k s) (hf : Flow s' = Flow s)
    (ho : NoDr o) : HW c (put c k s', o) := ⟨sr_put c k s s' h hf, ho⟩

theorem hw_commitTail (fx : Fix) (c : Conn) (k : Nat) (s0 s : Stream) (isTr es : Bool) (hdrs : List Flare.L3.H2.Validate.Header)
    (hs : Src c k s0) (hf : Flow s = Flow s0) : HW c (commitTail fx c k s isTr es hdrs) := by
  unfold commitTail rstClose
  simp only []
  repeat' split
  all_goals first
    | exact hw_rstCloseX c k _ s0 _ [] hs hf noDr_nil
    | exact hw_put c k s0 _ [] hs hf noDr_nil

theorem hw_commit (fx : Fix) (dec : Dec) (c : Conn) (k : Nat) : HW c (commit fx dec c k) := by
  unfold commit
  simp only []
  have h1 : SR c { c with block := [], blockES := false, decLog := c.decLog ++ [c.block], blockRefuse := 0 } :=
    sr_streams rfl rfl
  have he := sr_ensure { c with block := [], blockES := false, decLog := c.decLog ++ [c.block], blockRefuse := 0 } k
  have h2 := sr_trans h1 he.1
  split
  · exact hw_trans (sr_streams rfl rfl) (hw_connErr _ _)
  · exact hw_trans (sr_streams rfl rfl) (hw_connErr _ _)
  · split
    · exact hw_trans h1 (hw_closeRst _ _ _)
    · unfold rstClose
      repeat' split
      all_goals first
        | exact hw_trans h2 (hw_rstCloseX _ k _ _ _ [] he.2 rfl noDr_nil)
        | exact hw_trans h2 (hw_commitTail _ _ k _ _ _ _ _ he.2 rfl)
        | exact hw_trans h2 (hw_put _ k _ _ [] he.2 rfl noDr_nil)

theorem hw_contBranch (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : HW c (contBranch fx dec c f) := by
  unfold contBranch
  split
  · exact hw_connErr _ _
  · simp only []
    repeat' split
    all_goals first
      | exact hw_trans (sr_streams rfl rfl) (hw_connErr _ _)
      | exact hw_streams rfl rfl noDr_nil
      | exact hw_trans (sr_streams rfl rfl) (hw_commit _ _ _ _)

def HWO (c : Conn) : Option (Conn × List Out) → Prop
  | none => True
  | some r => HW c r

theorem hw_shapeCheck (fx : Fix) (c : Conn) (f : Fr) : HWO c (shapeCheck fx c f) := by
  unfold shapeCheck
  repeat' split
  all_goals first
    | trivial
    | exact hw_connErr _ _
    | exact hw_closeRst _ _ _

def HWS (c : Conn) : (Conn × List Out) ⊕ Conn → Prop
  | .inl r => HW c r
  | .inr c' => SR c c'

theorem hw_idCheck (fx : Fix) (c : Conn) (f : Fr) : HWS c (idCheck fx c f) := by
  unfold idCheck
  repeat' split
  all_goals first
    | exact hw_connErr _ _
    | exact sr_streams rfl rfl

theorem applyDelta_keys (d : Int) (l : List (Nat × Stream)) :
    (applyDelta d l).1.map (·.1) = l.map (·.1) := by
  induction l with
  | nil => rfl
  | cons p t ih =>
    unfold applyDelta
    split
    · simp [ih]
    · split
      · rfl
      · simp [ih]

theorem applyDelta_mem (d : Int) (l : List (Nat × Stream)) (p : Nat × Stream) (h : p ∈ (applyDelta d l).1) :
    ∃ s, (p.1, s) ∈ l ∧ Flow p.2 = Flow s := by
  induction l with
  | nil => simp [applyDelta] at h
  | cons q t ih =>
    unfold applyDelta at h
    split at h
    · rcases List.mem_cons.1 h with e | e
      · subst e; exact ⟨p.2, List.mem_cons_self .., rfl⟩
      · obtain ⟨s, hs, hf⟩ := ih e; exact ⟨s, List.mem_cons_of_mem _ hs, hf⟩
    · split at h
      · exact ⟨p.2, h, rfl⟩
      · rcases List.mem_cons.1 h with e | e
        · subst e; exact ⟨q.2, List.mem_cons_self .., rfl⟩
        · obtain ⟨s, hs, hf⟩ := ih e; exact ⟨s, List.mem_cons_of_mem _ hs, hf⟩

theorem sr_applyDelta (c : Conn) (d : Int) (c' : Conn) (h1 : c'.streams = (applyDelta d c.streams).1)
    (h2 : c'.initW = c.initW) : SR c c' := by
  refine ⟨h2, fun h => ?_, fun k s' hs => ?_⟩
  · unfold NoDupK at h ⊢; rw [h1, applyDelta_keys]; exact h
  · rw [h1] at hs
    obtain ⟨s, h3, h4⟩ := applyDelta_mem d c.streams (k, s') hs
    exact Or.inr ⟨s, h3, h4⟩

def HWT (c : Conn) : Conn ⊕ (Conn × List Out) → Prop
  | .inl c' => SR c c'
  | .inr r => HW c r

theorem hw_applySetting (c : Conn) (id v : Nat) : HWT c (applySetting c id v) := by
  unfold applySetting
  simp only []
  repeat' split
  all_goals first
    | exact hw_connErr _ _
    | exact sr_streams rfl rfl
    | exact sr_applyDelta c _ _ rfl rfl
    | exact hw_connErr_sr _ (sr_applyDelta c _ _ rfl rfl)

theorem hw_applySettings (c : Conn) (l : List (Nat × Nat)) : HWT c (applySettings c l) := by
  induction l generalizing c with
  | nil => exact sr_refl c
  | cons p t ih =>
    obtain ⟨id, v⟩ := p
    have hs := hw_applySetting c id v
    unfold applySettings
    split
    · rename_i c1 hc1; rw [hc1] at hs
      have := ih c1
      revert this; generalize applySettings c1 t = r; intro this
      cases r with
      | inl c2 => exact sr_trans hs this
      | inr r => exact hw_trans hs this
    · rename_i r1 hr1; rw [hr1] at hs; exact hs

theorem hw_settingsH (c : Conn) (f : Fr) : HW c (settingsH c f) := by
  unfold settingsH
  split
  · exact hw_streams rfl rfl noDr_nil
  · have hs := hw_applySettings c f.settings
    split
    · rename_i c' hc; rw [hc] at hs
      exact ⟨hs, noDr_cons (fun _ _ h => by cases h) noDr_nil⟩
    · rename_i r hr; rw [hr] at hs; exact hs

theorem hw_wuH (fx : Fix) (c : Conn) (f : Fr) : HW c (wuH fx c f) := by
  unfold wuH rstClose
  simp only []
  repeat' split
  all_goals first
    | exact hw_connErr _ _
    | exact hw_closeRst _ _ _
    | exact hw_streams rfl rfl noDr_nil
    | (rename_i hg _; exact hw_rstCloseX c _ _ _ _ [] (src_get hg) rfl noDr_nil)
    | (rename_i hg _; exact hw_put c _ _ _ [] (src_get hg) rfl noDr_nil)

def HWN (c : Conn) : (Conn × List Out) ⊕ Nat → Prop
  | .inl r => HW c r
  | .inr _ => True

theorem hw_headersPre (fx : Fix) (c : Conn) (f : Fr) : HWN c (headersPre fx c f) := by
  unfold headersPre
  repeat' split
  all_goals first
    | exact hw_connErr _ _
    | trivial

theorem hw_headersOpen (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (refuse : Nat) :
    HW c (headersOpen fx dec c f refuse) := by
  unfold headersOpen
  simp only []
  have h1 : SR c { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } :=
    sr_streams rfl rfl
  have he := sr_ensure { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid
  have h2 : SR c (if refuse = 0 then
      put (ensure { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid).1
        f.sid (ensure { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid).2
      else { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 }) := by
    split
    · exact sr_trans (sr_trans h1 he.1) (sr_put _ _ _ _ he.2 rfl)
    · exact h1
  split
  · exact ⟨sr_trans h2 (sr_streams rfl rfl), noDr_nil⟩
  · exact hw_trans h2 (hw_commit _ _ _ _)

def HWE (c : Conn) : Res → Prop
  | .ok r => HW c r
  | .error _ => True

theorem hw_headersH (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : HWE c (headersH fx dec c f) := by
  have hp : ∀ r, headersPre fx c f = .inl r → HW c r := by
    intro r hr; have := hw_headersPre fx c f; rw [hr] at this; exact this
  unfold headersH
  repeat' split
  all_goals first
    | exact hw_connErr _ _
    | trivial
    | exact hw_headersOpen _ _ _ _ _
    | (apply hp; assumption)

theorem hw_rstH (c : Conn) (f : Fr) : HW c (rstH c f) := by
  unfold rstH rstFlood
  have h1 := sr_closeIfKnown c f.sid
  split
  · exact ⟨sr_trans h1 (sr_streams rfl rfl), noDr_cons (fun _ _ h => by cases h) noDr_nil⟩
  · exact ⟨sr_trans h1 (sr_streams rfl rfl), noDr_nil⟩

/-! ## The step relation with DATA and drain -/

/-- The payload a step adds to stream `k`'s buffer at most: a DATA frame's
fragment on `k`. -/
def fragOf (e : Ev) (k : Nat) : Option Bytes :=
  match e with
  | .frame f => if f.ty = tDATA ∧ f.sid = k then some f.frag else none
  | _ => none

/-- What one step may do to an existing stream. -/
def SStep (i : Int) (fr : Option Bytes) (s s' : Stream) : Prop :=
  (TIs i s → TIs i s') ∧ (s'.buf = s.buf ∨ s'.buf = [] ∨ ∃ x, fr = some x ∧ s'.buf = s.buf ++ x)

/-- What one step may leave in a stream that had no entry. -/
def NewS (i : Int) (fr : Option Bytes) (s' : Stream) : Prop :=
  (0 ≤ i → TIs i s') ∧ (s'.buf = [] ∨ ∃ x, fr = some x ∧ s'.buf = x)

def GR (c c' : Conn) (fr : Nat → Option Bytes) : Prop :=
  c'.initW = c.initW ∧ (NoDupK c.streams → NoDupK c'.streams) ∧
  ∀ k s', (k, s') ∈ c'.streams → NewS c.initW (fr k) s' ∨ ∃ s, (k, s) ∈ c.streams ∧ SStep c.initW (fr k) s s'

def GW (c : Conn) (r : Conn × List Out) (fr : Nat → Option Bytes) : Prop := GR c r.1 fr ∧ NoDr r.2

theorem tis_flow {i : Int} {s s' : Stream} (hf : Flow s' = Flow s) (h : TIs i s) : TIs i s' := by
  simp only [Flow, Prod.mk.injEq] at hf
  unfold TIs at *; rw [hf.1, hf.2.1]; exact h

theorem newS_fresh {i : Int} {fr : Option Bytes} {s : Stream} (h : FreshS i s) : NewS i fr s := by
  obtain ⟨h1, h2, h3⟩ := h
  exact ⟨fun h0 => by unfold TIs; rw [h1, h2]; omega, Or.inl h3⟩

theorem sstep_flow {i : Int} {fr : Option Bytes} {s s' : Stream} (hf : Flow s' = Flow s) : SStep i fr s s' := by
  refine ⟨tis_flow hf, Or.inl ?_⟩
  simp only [Flow, Prod.mk.injEq] at hf; exact hf.2.2

theorem sstep_congr {i : Int} {fr : Option Bytes} {s s' s'' : Stream} (hf : Flow s'' = Flow s')
    (h : SStep i fr s s') : SStep i fr s s'' := by
  have hb : s''.buf = s'.buf := by simp only [Flow, Prod.mk.injEq] at hf; exact hf.2.2
  exact ⟨fun h1 => tis_flow hf (h.1 h1), hb ▸ h.2⟩

theorem gr_of_sr {c c' : Conn} (fr : Nat → Option Bytes) (h : SR c c') : GR c c' fr := by
  refine ⟨h.1, h.2.1, fun k s' hs => ?_⟩
  rcases h.2.2 k s' hs with h1 | ⟨s, h2, h3⟩
  · exact Or.inl (newS_fresh h1)
  · exact Or.inr ⟨s, h2, sstep_flow h3⟩

theorem gw_of_hw {c : Conn} {r : Conn × List Out} (fr : Nat → Option Bytes) (h : HW c r) : GW c r fr :=
  ⟨gr_of_sr fr h.1, h.2⟩

theorem gr_sr_gr {a b d : Conn} {fr : Nat → Option Bytes} (h1 : SR a b) (h2 : GR b d fr) : GR a d fr := by
  have hI : b.initW = a.initW := h1.1
  refine ⟨h2.1.trans hI, fun h => h2.2.1 (h1.2.1 h), fun k s' hs => ?_⟩
  rcases h2.2.2 k s' hs with h3 | ⟨s, h4, h5⟩
  · left; rw [← hI]; exact h3
  · rw [hI] at h5
    rcases h1.2.2 k s h4 with h6 | ⟨s0, h7, h8⟩
    · left
      obtain ⟨e1, e2, e3⟩ := h6
      refine ⟨fun h0 => h5.1 (by unfold TIs; rw [e1, e2]; omega), ?_⟩
      rcases h5.2 with e | e | ⟨x, hx, e⟩
      · exact Or.inl (e.trans e3)
      · exact Or.inl e
      · exact Or.inr ⟨x, hx, by rw [e, e3]; rfl⟩
    · right
      refine ⟨s0, h7, ?_⟩
      have hb : s.buf = s0.buf := by simp only [Flow, Prod.mk.injEq] at h8; exact h8.2.2
      refine ⟨fun h9 => h5.1 (tis_flow h8 h9), ?_⟩
      rw [← hb]; exact h5.2

theorem gw_sr_gw {a b : Conn} {r : Conn × List Out} {fr : Nat → Option Bytes} (h1 : SR a b) (h2 : GW b r fr) :
    GW a r fr := ⟨gr_sr_gr h1 h2.1, h2.2⟩

theorem gr_streams_right {c c1 c2 : Conn} {fr : Nat → Option Bytes} (h : GR c c1 fr) (h1 : c2.streams = c1.streams)
    (h2 : c2.initW = c1.initW) : GR c c2 fr :=
  ⟨h2.trans h.1, fun n => h1 ▸ h.2.1 n, fun k s' hs => h.2.2 k s' (h1 ▸ hs)⟩

theorem gr_congr {c1 c2 c' : Conn} {fr : Nat → Option Bytes} (h1 : c1.streams = c2.streams) (h2 : c1.initW = c2.initW)
    (h : GR c1 c' fr) : GR c2 c' fr :=
  gr_sr_gr (sr_streams h1 h2) h

theorem gr_put (c : Conn) (k : Nat) (s s' : Stream) (fr : Nat → Option Bytes) (hs : (k, s) ∈ c.streams)
    (hst : SStep c.initW (fr k) s s') : GR c (put c k s') fr := by
  refine ⟨rfl, fun h => nodupK_putL _ _ _ h, fun j t ht => ?_⟩
  rcases mem_putL ht with he | h
  · simp only [Prod.mk.injEq] at he; obtain ⟨rfl, rfl⟩ := he
    exact Or.inr ⟨s, hs, hst⟩
  · exact Or.inr ⟨t, h, sstep_flow rfl⟩

theorem gw_rstCloseX (c : Conn) (k e : Nat) (s s' : Stream) (x : List Out) (fr : Nat → Option Bytes)
    (hs : (k, s) ∈ c.streams) (hst : SStep c.initW (fr k) s s') (hx : NoDr x) :
    GW c (rstCloseX c k e s' x) fr :=
  ⟨gr_put (rstC c k) k s { s' with state := .closed } fr hs (sstep_congr rfl hst),
   noDr_cons (fun _ _ h => by cases h) hx⟩

/-! ### DATA -/

theorem stripLen_le (f : Fr) (p : Bool) (n : Nat) (h : stripLen f p = some n) : n ≤ f.plen := by
  unfold stripLen at h
  simp only [] at h
  split at h
  · cases h
  · rename_i st en hr
    have hen : en ≤ f.plen := by
      split at hr
      · split at hr
        · cases hr
        · split at hr
          · cases hr
          · cases hr; omega
      · cases hr; omega
    split at h
    · split at h
      · cases h
      · cases h; omega
    · cases h; omega

theorem dataCredit_streams (c : Conn) (f : Fr) (cr : Nat) :
    (dataCredit c f cr).1.streams = c.streams ∧ (dataCredit c f cr).1.initW = c.initW ∧ NoDr (dataCredit c f cr).2 := by
  unfold dataCredit
  simp only []
  repeat' split
  all_goals exact ⟨rfl, rfl, fun j b h => by simp at h⟩

theorem gw_dataFinish (fx : Fix) (c : Conn) (f : Fr) (s0 s : Stream) (cr : Nat) (fr : Nat → Option Bytes)
    (hs0 : (f.sid, s0) ∈ c.streams) (hst : SStep c.initW (fr f.sid) s0 s) : GW c (dataFinish fx c f s cr) fr := by
  unfold dataFinish
  split
  · exact gw_rstCloseX c f.sid _ s0 s _ fr hs0 hst (noDr_ite (noDr_wu0If _) noDr_nil)
  · obtain ⟨h1, h2, h3⟩ := dataCredit_streams (put c f.sid (if f.f1 then
      { s with dataComplete := true,
               state := if c.isClient && s.state == .hcl then .closed else .hcr } else s)) f
      (if fx.h2_19 && f.f1 && c.isClient && s.state == .hcl then 0 else cr)
    refine ⟨gr_streams_right (gr_put c f.sid s0 _ fr hs0 (sstep_congr (by split <;> rfl) hst)) h1 h2, h3⟩

theorem deferOf_le (s : Stream) (body : Nat) : deferOf s body ≤ body := by
  unfold deferOf; split <;> omega

theorem gw_dataAccept (fx : Fix) (c : Conn) (f : Fr) (s0 s : Stream) (body : Nat) (fr : Nat → Option Bytes)
    (hs0 : (f.sid, s0) ∈ c.streams) (hfr : fr f.sid = some f.frag) (hr : s.recvW = s0.recvW - f.plen)
    (hp : s.pendingCredit = s0.pendingCredit) (hb : s.buf = s0.buf ++ f.frag) (hnn : 0 ≤ s.recvW)
    (hbody : body ≤ f.plen) : GW c (dataAccept fx c f s body) fr := by
  unfold dataAccept
  split
  · refine gw_rstCloseX c f.sid _ s0 _ _ fr hs0 ⟨fun ht => ?_, Or.inr (Or.inl rfl)⟩ (noDr_wu0If _)
    unfold TIs at *; simp only []; rw [hr, hp]; omega
  · have hd := deferOf_le s body
    generalize hc1 : (if !c.isClient then { c with buffered := c.buffered + body } else c) = c1
    have hs1 : c1.streams = c.streams := by rw [← hc1]; split <;> rfl
    have hi1 : c1.initW = c.initW := by rw [← hc1]; split <;> rfl
    have hg := gw_dataFinish fx c1 f s0
      { s with recvW := s.recvW + ((f.plen : Int) - (deferOf s body : Int)),
               pendingCredit := s.pendingCredit + deferOf s body } (f.plen - deferOf s body) fr
      (hs1 ▸ hs0)
      (by
        rw [hi1]
        refine ⟨fun ht => ?_, Or.inr (Or.inr ⟨f.frag, hfr, hb⟩)⟩
        show s.recvW + ((f.plen : Int) - (deferOf s body : Int)) + ((s.pendingCredit + deferOf s body : Nat) : Int) ≤ c.initW
          ∧ ((s.pendingCredit + deferOf s body : Nat) : Int) ≤ c.initW
        unfold TIs at ht
        rw [hr] at hnn ⊢; rw [hp]
        obtain ⟨t1, t2⟩ := ht
        constructor <;> push_cast <;> omega)
    exact ⟨gr_congr hs1 hi1 hg.1, hg.2⟩

theorem gw_dataBody (fx : Fix) (c : Conn) (f : Fr) (s0 s : Stream) (body : Nat) (fr : Nat → Option Bytes)
    (hs0 : (f.sid, s0) ∈ c.streams) (hfr : fr f.sid = some f.frag) (hr : s.recvW = s0.recvW - f.plen)
    (hp : s.pendingCredit = s0.pendingCredit) (hb : s.buf = s0.buf) (hbody : body ≤ f.plen) :
    GW c (dataBody fx c f s body) fr := by
  have tis_le : ∀ s' : Stream, s'.recvW = s.recvW → s'.pendingCredit = s.pendingCredit →
      TIs c.initW s0 → TIs c.initW s' := by
    intro s' h1 h2 ht; unfold TIs at *; rw [h1, h2, hr, hp]; omega
  unfold dataBody
  split
  · exact gw_rstCloseX c f.sid _ s0 s _ fr hs0 ⟨tis_le s rfl rfl, Or.inl hb⟩ (noDr_ite (noDr_wu0If _) noDr_nil)
  · split
    · exact gw_rstCloseX c f.sid _ s0 _ _ fr hs0 ⟨tis_le _ rfl rfl, Or.inr (Or.inl rfl)⟩ (noDr_wu0If _)
    · split
      · exact gw_rstCloseX c f.sid _ s0 _ _ fr hs0 ⟨tis_le _ rfl rfl, Or.inr (Or.inl rfl)⟩ (noDr_wu0If _)
      · rename_i hneg _ _
        exact gw_dataAccept fx c f s0 _ body fr hs0 hfr hr hp (by simp only []; rw [hb]) (by simp only []; omega) hbody

theorem gw_dataH (fx : Fix) (c : Conn) (f : Fr) (fr : Nat → Option Bytes) (hfr : fr f.sid = some f.frag) :
    GW c (dataH fx c f) fr := by
  unfold dataH
  split
  · exact gw_of_hw fr (hw_streams rfl rfl (noDr_wu0If _))
  · split
    · split <;> exact gw_of_hw fr (hw_connErr _ _)
    · rename_i s hg
      repeat' split
      all_goals first
        | exact gw_of_hw fr (hw_connErr _ _)
        | exact gw_rstCloseX c f.sid _ s _ _ fr (mem_of_get hg) ⟨fun ht => ht, Or.inr (Or.inl rfl)⟩ (noDr_wu0If _)
        | (rename_i body hbody
           exact gw_dataBody fx c f s _ body fr (mem_of_get hg) hfr rfl rfl rfl (stripLen_le f false body hbody))

/-! ### Frames -/

def GWE (c : Conn) (r : Res) (fr : Nat → Option Bytes) : Prop :=
  match r with
  | .ok r => GW c r fr
  | .error _ => True

theorem gwe_hwe {c : Conn} {r : Res} (fr : Nat → Option Bytes) (h : HWE c r) : GWE c r fr := by
  cases r with
  | ok r => exact gw_of_hw fr h
  | error _ => trivial

theorem gw_dispatch (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (fr : Nat → Option Bytes)
    (hfr : f.ty = tDATA → fr f.sid = some f.frag) : GWE c (dispatch fx dec c f) fr := by
  unfold dispatch
  split
  · exact gw_of_hw fr (hw_settingsH c f)
  split
  · split
    · exact gw_of_hw fr (hw_streams rfl rfl noDr_nil)
    · exact gw_of_hw fr (hw_streams rfl rfl (noDr_cons (fun _ _ h => by cases h) noDr_nil))
  split
  · exact gw_of_hw fr (hw_wuH fx c f)
  split
  · exact gwe_hwe fr (hw_headersH fx dec c f)
  split
  · exact gw_of_hw fr (hw_connErr _ _)
  split
  · rename_i h; exact gw_dataH fx c f fr (hfr h)
  split
  · exact gw_of_hw fr (hw_streams rfl rfl noDr_nil)
  split
  · exact gw_of_hw fr (hw_rstH c f)
  · exact gw_of_hw fr (hw_streams rfl rfl noDr_nil)

theorem gw_handle (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (fr : Nat → Option Bytes)
    (hfr : f.ty = tDATA → fr f.sid = some f.frag) : GWE c (handle fx dec c f) fr := by
  unfold handle
  split
  · exact gw_of_hw fr (hw_contBranch fx dec c f)
  have hs := hw_shapeCheck fx c f
  split
  · rename_i r hr; rw [hr] at hs; exact gw_of_hw fr hs
  split
  · exact gw_of_hw fr (hw_connErr _ _)
  have hi := hw_idCheck fx c f
  split
  · rename_i r hr; rw [hr] at hi; exact gw_of_hw fr hi
  · rename_i c1 hr; rw [hr] at hi
    have := gw_dispatch fx dec c1 f fr hfr
    revert this; generalize dispatch fx dec c1 f = r; intro this
    cases r with
    | ok r => exact gw_sr_gw hi this
    | error _ => trivial

theorem gw_handleW (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (fr : Nat → Option Bytes)
    (hfr : f.ty = tDATA → fr f.sid = some f.frag) : GWE c (handleW fx dec c f) fr := by
  have h := gw_handle fx dec c f fr hfr
  unfold handleW
  split
  · exact gw_of_hw fr (hw_connErr _ _)
  · revert h; generalize handle fx dec c f = r; intro h
    cases r with
    | ok r => exact ⟨gr_streams_right h.1 rfl rfl, h.2⟩
    | error _ => trivial

theorem gw_prefaceGate (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (fr : Nat → Option Bytes)
    (hfr : f.ty = tDATA → fr f.sid = some f.frag) : GWE c (prefaceGate fx dec c f) fr := by
  unfold prefaceGate
  split
  · split
    · have h := gw_handleW fx dec { c with peerSettingsSeen := true } f fr hfr
      revert h; generalize handleW fx dec { c with peerSettingsSeen := true } f = r; intro h
      cases r with
      | ok r => exact gw_sr_gw (sr_streams rfl rfl) h
      | error _ => trivial
    · split
      · exact gw_of_hw fr (hw_connErr _ _)
      · exact gw_handleW fx dec c f fr hfr
  · exact gw_handleW fx dec c f fr hfr

theorem gw_frame (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) :
    GWE c (step fx dec c (.frame f)) (fragOf (.frame f)) := by
  have hfr : f.ty = tDATA → fragOf (.frame f) f.sid = some f.frag := by
    intro h; simp [fragOf, h]
  show GWE c (if c.isClient then driveClient fx dec c f else driveFrame fx dec c f) _
  split
  · unfold driveClient
    split
    · split
      · exact gw_of_hw _ (hw_connErr _ _)
      · trivial
    split
    · exact gw_of_hw _ (hw_streams rfl rfl (noDr_ite (noDr_rst _ _) noDr_nil))
    · exact gw_prefaceGate fx dec c f _ hfr
  · unfold driveFrame
    split
    · exact gw_of_hw _ (hw_streams rfl rfl noDr_nil)
    split
    · exact gw_of_hw _ (hw_connErr _ _)
    · exact gw_prefaceGate fx dec c f _ hfr

/-! ### Local events -/

/-- The octets `o` hands to the application for stream `k`. -/
def drainedOf (k : Nat) (o : List Out) : List Bytes :=
  o.filterMap (fun x => match x with | .drained j b => if j = k then some b else none | _ => none)

/-- Stream `k`'s buffered octets (none when it has no entry). -/
def bufOf (c : Conn) (k : Nat) : Bytes :=
  match get c k with
  | some s => s.buf
  | none => []

/-- A step hands stream `k`'s octets over only by emptying its buffer. -/
def DrOK (c c' : Conn) (o : List Out) : Prop :=
  ∀ k, drainedOf k o = [] ∨ (drainedOf k o = [bufOf c k] ∧ bufOf c' k = [])

theorem drainedOf_noDr (k : Nat) (o : List Out) (h : NoDr o) : drainedOf k o = [] := by
  induction o with
  | nil => rfl
  | cons x t ih =>
    have ht : NoDr t := fun j b hm => h j b (List.mem_cons_of_mem _ hm)
    cases x with
    | drained j b => exact absurd (List.mem_cons_self ..) (h j b)
    | _ => simp only [drainedOf, List.filterMap_cons] at ih ⊢; exact ih ht

theorem drainedOf_self (k : Nat) (b : Bytes) (o : List Out) :
    drainedOf k (.drained k b :: o) = b :: drainedOf k o := by
  simp [drainedOf]

theorem drainedOf_other (k j : Nat) (b : Bytes) (o : List Out) (h : k ≠ j) :
    drainedOf j (.drained k b :: o) = drainedOf j o := by
  simp [drainedOf, h]

theorem drOK_noDr {c c' : Conn} {o : List Out} (h : NoDr o) : DrOK c c' o :=
  fun k => Or.inl (drainedOf_noDr k o h)

theorem gw_drain (c : Conn) (k : Nat) (fr : Nat → Option Bytes) :
    GR c (drain c k).1 fr ∧ DrOK c (drain c k).1 (drain c k).2 := by
  unfold drain
  split
  · exact ⟨gr_of_sr fr (sr_refl c), drOK_noDr noDr_nil⟩
  · split
    · exact ⟨gr_of_sr fr (sr_refl c), drOK_noDr noDr_nil⟩
    · rename_i s hg
      refine ⟨gr_put c k s _ fr (mem_of_get hg) ⟨fun ht => ?_, Or.inr (Or.inl rfl)⟩, fun j => ?_⟩
      · unfold TIs at *; simp only []; omega
      · by_cases hj : k = j
        · subst hj
          right
          refine ⟨?_, ?_⟩
          · rw [drainedOf_self, drainedOf_noDr k _ (noDr_ite (noDr_wu _ _) noDr_nil)]
            simp [bufOf, hg]
          · simp [bufOf]
        · left
          rw [drainedOf_other k j _ _ hj]
          exact drainedOf_noDr j _ (noDr_ite (noDr_wu _ _) noDr_nil)

theorem sr_local_put (c : Conn) (k : Nat) (f : Stream → Stream) (hf : ∀ s, Flow (f s) = Flow s) :
    SR c (match get c k with | none => c | some s => put c k (f s)) := by
  split
  · exact sr_refl c
  · rename_i s hg; exact sr_put c k s _ (src_get hg) (hf s)

/-- Every step: the stream relation for the frame's DATA payload, and
`drained` output only by emptying the buffer. -/
theorem step_rel (fx : Fix) (dec : Dec) (c c' : Conn) (e : Ev) (o : List Out)
    (h : step fx dec c e = .ok (c', o)) : GR c c' (fragOf e) ∧ DrOK c c' o := by
  cases e with
  | frame f =>
    have hg := gw_frame fx dec c f
    rw [h] at hg
    exact ⟨hg.1, drOK_noDr hg.2⟩
  | drain k =>
    simp only [step, Except.ok.injEq] at h
    have := gw_drain c k (fragOf (.drain k)); rw [h] at this; exact this
  | release n =>
    simp only [step, Except.ok.injEq] at h
    have : HW c (release fx c n) := by
      unfold release; simp only []; split
      · exact hw_streams rfl rfl (noDr_wu _ _)
      · exact hw_streams rfl rfl noDr_nil
    rw [h] at this; exact ⟨gr_of_sr _ this.1, drOK_noDr this.2⟩
  | respond k n =>
    simp only [step, Except.ok.injEq] at h
    have : HW c (respond c k n) := by
      unfold respond; split
      · exact hw_streams rfl rfl noDr_nil
      · rename_i s hg; split
        · exact hw_streams rfl rfl noDr_nil
        · exact hw_trans (sr_streams rfl rfl) (hw_put _ k s _ _ (src_get hg) rfl (fun j b hm => by simp at hm))
    rw [h] at this; exact ⟨gr_of_sr _ this.1, drOK_noDr this.2⟩
  | send k n =>
    simp only [step, Except.ok.injEq] at h
    have : HW c (send c k n) := by
      unfold send; split
      · exact hw_streams rfl rfl noDr_nil
      · rename_i s hg; simp only []; split
        · exact hw_streams rfl rfl noDr_nil
        · exact hw_trans (sr_streams rfl rfl) (hw_put _ k s _ _ (src_get hg) rfl (fun j b hm => by simp at hm))
    rw [h] at this; exact ⟨gr_of_sr _ this.1, drOK_noDr this.2⟩
  | openLocal k es =>
    simp only [step, Except.ok.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    refine ⟨gr_of_sr _ ?_, drOK_noDr noDr_nil⟩
    unfold openLocal
    exact sr_trans (sr_streams rfl rfl) (sr_put _ k _ _ (Or.inl ⟨rfl, rfl, rfl⟩) rfl)
  | pop k =>
    simp only [step, Except.ok.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨gr_of_sr _ (sr_filter c _), drOK_noDr noDr_nil⟩
  | endLocal k em =>
    simp only [step, Except.ok.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    refine ⟨gr_of_sr _ ?_, drOK_noDr noDr_nil⟩
    unfold endLocal; split
    · exact sr_refl c
    · rename_i s hg; split
      · exact sr_refl c
      · exact sr_put c k s _ (src_get hg) rfl
  | stream k =>
    simp only [step, Except.ok.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨gr_of_sr _ (sr_local_put c k _ (fun _ => rfl)), drOK_noDr noDr_nil⟩

/-! ## Credit bound -/

/-- Every stream satisfies the credit bound. -/
def TI (c : Conn) : Prop := 0 ≤ c.initW ∧ ∀ p ∈ c.streams, TIs c.initW p.2

theorem ti_gr {c c' : Conn} {fr : Nat → Option Bytes} (h : GR c c' fr) (hi : TI c) : TI c' := by
  refine ⟨h.1 ▸ hi.1, fun p hp => ?_⟩
  rw [h.1]
  rcases h.2.2 p.1 p.2 hp with h1 | ⟨s, h2, h3⟩
  · exact h1.1 hi.1
  · exact h3.1 (hi.2 _ h2)

/-- The credit bound is invariant under every step, for every fix set. -/
theorem ti_step (fx : Fix) (dec : Dec) (c c' : Conn) (e : Ev) (o : List Out)
    (h : step fx dec c e = .ok (c', o)) (hi : TI c) : TI c' :=
  ti_gr (step_rel fx dec c c' e o h).1 hi

theorem ti_run (fx : Fix) (dec : Dec) (c c' : Conn) (es : List Ev) (tr : List (Ev × List Out))
    (h : run fx dec c es = some (c', tr)) (hi : TI c) : TI c' := by
  induction es generalizing c tr with
  | nil => simp only [run, Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h; exact hi
  | cons e es ih =>
    unfold run at h
    split at h
    · cases h
    · rename_i c1 o hs
      split at h
      · cases h
      · rename_i c2 tr2 hr
        simp only [Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h
        exact ih c1 tr2 hr (ti_step fx dec c c1 e o hs hi)

/-- A fresh table (no streams) satisfies the credit bound when the
advertised window is non-negative. -/
theorem ti_empty (c : Conn) (h0 : 0 ≤ c.initW) (he : c.streams = []) : TI c :=
  ⟨h0, fun p hp => by rw [he] at hp; cases hp⟩

/-- The octets a streaming response holds undrained never exceed one
initial window when the frames' payloads are their declared lengths: the
held-back credit counts exactly the undrained body octets. -/
theorem pending_le (c : Conn) (hi : TI c) (k : Nat) (s : Stream) (hs : (k, s) ∈ c.streams) :
    (s.pendingCredit : Int) ≤ c.initW ∧ s.recvW + s.pendingCredit ≤ c.initW :=
  ⟨(hi.2 _ hs).2, (hi.2 _ hs).1⟩

/-! ## FIFO delivery -/

/-- The payloads of the DATA frames on stream `k` in a trace. -/
def chunks (k : Nat) (es : List Ev) : List Bytes := es.filterMap (fun e => fragOf e k)

/-- Everything the application received from `drain_body` on stream `k`. -/
def delivered (k : Nat) (tr : List (Ev × List Out)) : Bytes :=
  (tr.flatMap (fun p => drainedOf k p.2)).flatten

theorem buf_key {c c' : Conn} {fr : Nat → Option Bytes} (h : GR c c' fr) (hn : NoDupK c.streams) (k : Nat) :
    bufOf c' k = [] ∨ bufOf c' k = bufOf c k ∨
      ∃ x, fr k = some x ∧ (bufOf c' k = bufOf c k ++ x ∨ bufOf c' k = x) := by
  unfold bufOf
  cases hg : get c' k with
  | none => exact Or.inl rfl
  | some s' =>
    simp only []
    rcases h.2.2 k s' (mem_of_get hg) with ⟨_, h1 | ⟨x, hx, h2⟩⟩ | ⟨s, h3, _, h4⟩
    · exact Or.inl h1
    · exact Or.inr (Or.inr ⟨x, hx, Or.inr h2⟩)
    · have hgs : get c k = some s := by
        have := find_of_mem_nodup c.streams (k, s) hn h3
        simp only [Conn.get, this, Option.map_some]
      rw [hgs]; simp only []
      rcases h4 with h5 | h5 | ⟨x, hx, h6⟩
      · exact Or.inr (Or.inl h5)
      · exact Or.inl h5
      · exact Or.inr (Or.inr ⟨x, hx, Or.inl h6⟩)

theorem fifo_gen (fx : Fix) (dec : Dec) (k : Nat) (es : List Ev) :
    ∀ (c c' : Conn) (tr : List (Ev × List Out)) (R s1 s2 : List Bytes),
    run fx dec c es = some (c', tr) → NoDupK c.streams → (s1 ++ s2).Sublist R → bufOf c k = s2.flatten →
    ∃ t1 t2 : List Bytes, (t1 ++ t2).Sublist (R ++ chunks k es) ∧ s1.flatten ++ delivered k tr = t1.flatten ∧
      bufOf c' k = t2.flatten := by
  induction es with
  | nil =>
    intro c c' tr R s1 s2 h _ hs hb
    simp only [run, Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h
    exact ⟨s1, s2, by simpa [chunks] using hs, by simp [delivered], hb⟩
  | cons e es ih =>
    intro c c' tr R s1 s2 h hn hs hb
    unfold run at h
    split at h
    · cases h
    · rename_i c1 o hstep
      split at h
      · cases h
      · rename_i c2 tr2 hr
        simp only [Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h
        obtain ⟨hgr, hdr⟩ := step_rel fx dec c c1 e o hstep
        have hn1 := hgr.2.1 hn
        have hchunks : chunks k (e :: es) = (fragOf e k).toList ++ chunks k es := by
          simp only [chunks, List.filterMap_cons]; cases fragOf e k <;> rfl
        have hdel : delivered k ((e, o) :: tr2) = (drainedOf k o).flatten ++ delivered k tr2 := by
          simp [delivered, List.flatMap_cons, List.flatten_append]
        rw [hchunks, hdel, ← List.append_assoc]
        have hs1 : s1.Sublist R := (List.sublist_append_left s1 s2).trans hs
        -- the new split of the first step
        have key : ∃ u1 u2 : List Bytes, (u1 ++ u2).Sublist (R ++ (fragOf e k).toList) ∧
            u1.flatten = s1.flatten ++ (drainedOf k o).flatten ∧ bufOf c1 k = u2.flatten := by
          rcases hdr k with hd | ⟨hd, hb1⟩
          · rw [hd]
            rcases buf_key hgr hn k with h1 | h1 | ⟨x, hx, h1 | h1⟩
            · exact ⟨s1, [], by simpa using hs1.trans (List.sublist_append_left _ _), by simp, by simp [h1]⟩
            · exact ⟨s1, s2, hs.trans (List.sublist_append_left _ _), by simp, h1.trans hb⟩
            · refine ⟨s1, s2 ++ [x], ?_, by simp, by rw [h1, hb]; simp⟩
              rw [hx, ← List.append_assoc]; exact List.Sublist.append_right hs _
            · refine ⟨s1, [x], ?_, by simp, by rw [h1]; simp⟩
              rw [hx]; exact List.Sublist.append_right hs1 _
          · refine ⟨s1 ++ s2, [], by simpa using hs.trans (List.sublist_append_left _ _), ?_, by rw [hb1]; rfl⟩
            rw [hd, hb]; simp
        obtain ⟨u1, u2, hu, hu1, hu2⟩ := key
        obtain ⟨t1, t2, ht, ht1, ht2⟩ := ih c1 c2 tr2 _ u1 u2 hr hn1 hu hu2
        exact ⟨t1, t2, ht, by rw [← ht1, hu1, List.append_assoc], ht2⟩

/-- FIFO delivery: what `drain_body` handed over on stream `k`, followed by
what is still buffered, is the concatenation of a subsequence of the
initial buffer and the DATA payloads received on `k`, in arrival order. -/
theorem fifo_run (fx : Fix) (dec : Dec) (k : Nat) (c c' : Conn) (es : List Ev) (tr : List (Ev × List Out))
    (h : run fx dec c es = some (c', tr)) (hn : NoDupK c.streams) :
    ∃ t1 t2 : List Bytes, (t1 ++ t2).Sublist (bufOf c k :: chunks k es) ∧ delivered k tr = t1.flatten ∧
      bufOf c' k = t2.flatten := by
  obtain ⟨t1, t2, ht, h1, h2⟩ := fifo_gen fx dec k es c c' tr [bufOf c k] [] [bufOf c k] h hn
    (by simp) (by simp)
  exact ⟨t1, t2, ht, by simpa using h1, h2⟩

/-! ## Credit returned by DATA and by `drain_body` -/

/-- `drain_body` hands over the buffer, credits the held-back octets to the
stream's receive window, and sends them as a stream WINDOW_UPDATE while the
peer may still send DATA. -/
theorem drain_credit (c : Conn) (k : Nat) (s : Stream) (hk : k ≠ 0) (hg : get c k = some s) :
    get (drain c k).1 k = some { s with buf := [], pendingCredit := 0, recvW := s.recvW + s.pendingCredit } ∧
    (drain c k).2 = .drained k s.buf ::
      (if s.pendingCredit > 0 && !s.dataComplete && s.state != .closed then [.wu k s.pendingCredit] else []) := by
  unfold drain
  simp [hk, hg]

theorem dataCredit_get (c : Conn) (f : Fr) (cr k : Nat) : get (dataCredit c f cr).1 k = get c k := by
  simp only [Conn.get, (dataCredit_streams c f cr).1]

theorem dataCredit_wu (c : Conn) (f : Fr) (cr n : Nat) (hsid : f.sid ≠ 0)
    (h : Out.wu f.sid n ∈ (dataCredit c f cr).2) : n = cr ∧ 0 < cr := by
  unfold dataCredit at h
  simp only [] at h
  repeat' split at h
  all_goals simp_all

theorem dataFinish_ok (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (cr : Nat) (hsid : f.sid ≠ 0)
    (hcl : ¬(f.f1 && (0 : Int) ≤ s.contentLength && (s.received : Int) ≠ s.contentLength) = true) :
    ∃ s4, get (dataFinish fx c f s cr).1 f.sid = some s4 ∧ Flow s4 = Flow s ∧
      ∀ n, Out.wu f.sid n ∈ (dataFinish fx c f s cr).2 → n = cr := by
  unfold dataFinish
  rw [if_neg hcl]
  refine ⟨_, by rw [dataCredit_get, get_put, if_pos rfl], by split <;> rfl, fun n hn => ?_⟩
  have := dataCredit_wu _ f _ n hsid hn
  revert this; split <;> intro this <;> omega

/-- An accepted DATA frame (not reset for an overrun or a content-length
mismatch) leaves `recvW + pendingCredit` of its stream where it was before
the frame was debited, holds back exactly the deferred body octets, and
credits the stream with no other amount than the rest of the frame. -/
theorem data_credit (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (body : Nat) (hsid : f.sid ≠ 0)
    (hacc : ¬(!c.isClient && (0 : Int) ≤ s.contentLength && (s.received : Int) > s.contentLength) = true)
    (hcl : ¬(f.f1 && (0 : Int) ≤ s.contentLength && (s.received : Int) ≠ s.contentLength) = true) :
    ∃ s', get (dataAccept fx c f s body).1 f.sid = some s' ∧
      s'.recvW + s'.pendingCredit = s.recvW + s.pendingCredit + f.plen ∧
      s'.pendingCredit = s.pendingCredit + deferOf s body ∧
      ∀ n, Out.wu f.sid n ∈ (dataAccept fx c f s body).2 → n = f.plen - deferOf s body := by
  unfold dataAccept
  rw [if_neg hacc]
  obtain ⟨s4, hg, hf, hw⟩ := dataFinish_ok fx (if !c.isClient then { c with buffered := c.buffered + body } else c) f
    { s with recvW := s.recvW + ((f.plen : Int) - (deferOf s body : Int)),
             pendingCredit := s.pendingCredit + deferOf s body } (f.plen - deferOf s body) hsid hcl
  simp only [Flow, Prod.mk.injEq] at hf
  refine ⟨s4, hg, ?_, by rw [hf.2.1], hw⟩
  rw [hf.1, hf.2.1]; push_cast; omega

end Flare.L3.H2.Streaming
