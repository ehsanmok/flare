import Flare.L3_Protocol.H2.ConnFlow

/-!
# Header-block sequencing (RFC 9113 §4.3, §6.10)

The HPACK decoder is shared by the whole connection, so it must see every
field block the peer sent, in order, each one reassembled from its
HEADERS / PUSH_PROMISE frame and the CONTINUATION frames that follow it
on the same stream. `rstep` is that reassembly; `Conn.decLog` records the
blocks flare hands to the decoder (`_commit_header_block`).

* `seq_step`: while no GOAWAY is emitted, one inbound frame moves
  (pending block, `decLog`) exactly as `rstep` does — in server role, and
  in client role with the H2-17 fix. Without that fix the client drops
  PUSH_PROMISE blocks (`Flare.Bugs.H2_17`).
* `seq_run`: over a whole run with no GOAWAY, `decLog` is the RFC
  reassembly of the inbound frames.
-/
namespace Flare.L3.H2.Conn
open Flare.L3.H2.Validate (Header)

/-! ## The RFC reassembly -/

/-- The block being received (`(stream, octets so far)`) and the completed
blocks after one inbound frame. -/
def rstep (pd : Option (Nat × Bytes)) (log : List Bytes) (f : Fr) : Option (Nat × Bytes) × List Bytes :=
  match pd with
  | none =>
    if f.ty = tHEADERS ∨ f.ty = tPUSH then
      if f.eh then (none, log ++ [f.frag]) else (some (f.sid, f.frag), log)
    else (none, log)
  | some (k, b) =>
    if f.ty = tCONT ∧ f.sid = k then
      if f.eh then (none, log ++ [b ++ f.frag]) else (some (k, b ++ f.frag), log)
    else (some (k, b), log)

/-- The frames of a trace, in order. -/
def framesOf : List Ev → List Fr
  | [] => []
  | .frame f :: es => f :: framesOf es
  | _ :: es => framesOf es

def rrun : Option (Nat × Bytes) × List Bytes → List Fr → Option (Nat × Bytes) × List Bytes
  | s, [] => s
  | s, f :: fs => rrun (rstep s.1 s.2 f) fs

/-- The block flare is reassembling. -/
def pendOf (c : Conn) : Option (Nat × Bytes) :=
  if c.continuing = 0 then none else some (c.continuing, c.block)

/-! ## Footprint -/

/-- The fields this file tracks are unchanged. -/
def HB (c c' : Conn) : Prop :=
  c'.decLog = c.decLog ∧ c'.continuing = c.continuing ∧ c'.block = c.block ∧
  c'.goawaySent = c.goawaySent ∧ c'.isClient = c.isClient

/-- A GOAWAY was emitted, or the tracked fields are unchanged. -/
def U (c : Conn) (r : Conn × List Out) : Prop := hasGoaway r.2 = true ∨ HB c r.1

theorem hb_refl (c : Conn) : HB c c := ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem hb_trans {a b d : Conn} (h1 : HB a b) (h2 : HB b d) : HB a d :=
  ⟨h2.1.trans h1.1, h2.2.1.trans h1.2.1, h2.2.2.1.trans h1.2.2.1, h2.2.2.2.1.trans h1.2.2.2.1,
   h2.2.2.2.2.trans h1.2.2.2.2⟩

theorem u_of_hb {c c' : Conn} {r : Conn × List Out} (h : HB c c') (hu : U c' r) : U c r := by
  rcases hu with hu | hu
  · exact Or.inl hu
  · exact Or.inr (hb_trans h hu)

theorem u_connErr (c : Conn) (e : Nat) : U c (connErr c e) := by
  unfold connErr; split
  · exact Or.inr (hb_refl _)
  · exact Or.inl rfl

theorem hb_closeIfKnown (c : Conn) (k : Nat) : HB c (closeIfKnown c k) := by
  unfold closeIfKnown; split <;> exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem hb_ensure (c : Conn) (k : Nat) : HB c (ensure c k).1 := by
  unfold ensure; split
  · exact hb_refl _
  · split <;> exact ⟨rfl, rfl, rfl, rfl, rfl⟩

@[simp] theorem ensure_decLog (c : Conn) (k : Nat) : (ensure c k).1.decLog = c.decLog :=
  (hb_ensure c k).1
@[simp] theorem ensure_continuing (c : Conn) (k : Nat) : (ensure c k).1.continuing = c.continuing :=
  (hb_ensure c k).2.1
@[simp] theorem ensure_block (c : Conn) (k : Nat) : (ensure c k).1.block = c.block :=
  (hb_ensure c k).2.2.1
@[simp] theorem ensure_goawaySent (c : Conn) (k : Nat) : (ensure c k).1.goawaySent = c.goawaySent :=
  (hb_ensure c k).2.2.2.1
@[simp] theorem ensure_isClient (c : Conn) (k : Nat) : (ensure c k).1.isClient = c.isClient :=
  (hb_ensure c k).2.2.2.2

theorem u_closeRst (c : Conn) (k e : Nat) : U c (closeIfKnown (rstC c k) k, [.rst k e]) :=
  Or.inr (hb_trans (a := c) (b := rstC c k) ⟨rfl, rfl, rfl, rfl, rfl⟩ (hb_closeIfKnown _ _))

theorem u_rstCloseX (c : Conn) (k e : Nat) (s : Stream) (x : List Out) : U c (rstCloseX c k e s x) :=
  Or.inr ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem hb_commitTail (fx : Fix) (c : Conn) (k : Nat) (s : Stream) (isTr es : Bool)
    (hdrs : List Header) : HB c (commitTail fx c k s isTr es hdrs).1 := by
  unfold commitTail rstClose rstCloseX
  simp only
  repeat' split
  all_goals exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- `commit` logs the block (or emits a GOAWAY). -/
theorem w_commit (fx : Fix) (dec : Dec) (c : Conn) (k : Nat) :
    hasGoaway (commit fx dec c k).2 = true ∨
    ((commit fx dec c k).1.decLog = c.decLog ++ [c.block] ∧
     (commit fx dec c k).1.continuing = c.continuing ∧
     (commit fx dec c k).1.goawaySent = c.goawaySent ∧ (commit fx dec c k).1.isClient = c.isClient) := by
  have key : ∀ r, U { c with block := [], blockES := false, decLog := c.decLog ++ [c.block] } r →
      hasGoaway r.2 = true ∨ (r.1.decLog = c.decLog ++ [c.block] ∧ r.1.continuing = c.continuing ∧
        r.1.goawaySent = c.goawaySent ∧ r.1.isClient = c.isClient) := by
    intro r h
    rcases h with h | ⟨h1, h2, _, h4, h5⟩
    · exact Or.inl h
    · exact Or.inr ⟨h1, h2, h4, h5⟩
  apply key
  unfold commit
  simp only
  split
  · exact u_connErr _ _
  · exact u_connErr _ _
  · split
    · exact u_closeRst _ _ _
    · have he := hb_ensure { c with block := [], blockES := false, decLog := c.decLog ++ [c.block], blockRefuse := 0 } k
      repeat' split
      all_goals first
        | exact Or.inr (hb_trans he (hb_commitTail _ _ _ _ _ _ _))
        | exact Or.inr (hb_trans he ⟨rfl, rfl, rfl, rfl, rfl⟩)
        | (unfold rstClose rstCloseX; exact Or.inr (hb_trans he ⟨rfl, rfl, rfl, rfl, rfl⟩))

/-! ## Handlers that do not touch header blocks -/

def UO (c : Conn) : Option (Conn × List Out) → Prop
  | none => True
  | some r => U c r

def US (c : Conn) : (Conn × List Out) ⊕ Conn → Prop
  | .inl r => U c r
  | .inr c' => HB c c'

def UT (c : Conn) : Conn ⊕ (Conn × List Out) → Prop
  | .inl c' => HB c c'
  | .inr r => U c r

theorem u_shapeCheck (fx : Fix) (c : Conn) (f : Fr) : UO c (shapeCheck fx c f) := by
  unfold shapeCheck
  repeat' split
  all_goals first
    | trivial
    | exact u_connErr _ _
    | exact u_closeRst _ _ _

theorem u_idCheck (fx : Fix) (c : Conn) (f : Fr) : US c (idCheck fx c f) := by
  unfold idCheck
  repeat' split
  all_goals first
    | exact u_connErr _ _
    | exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem u_applySetting (c : Conn) (id v : Nat) : UT c (applySetting c id v) := by
  unfold applySetting
  simp only
  repeat' split
  all_goals first
    | exact u_connErr _ _
    | exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem u_applySettings (c : Conn) (l : List (Nat × Nat)) : UT c (applySettings c l) := by
  induction l generalizing c with
  | nil => exact hb_refl _
  | cons p t ih =>
    obtain ⟨id, v⟩ := p
    have hs := u_applySetting c id v
    unfold applySettings
    split
    · rename_i c1 hc1; rw [hc1] at hs
      have := ih c1
      revert this; generalize applySettings c1 t = r; intro this
      cases r with
      | inl c2 => exact hb_trans hs this
      | inr r => exact u_of_hb hs this
    · rename_i r1 hr1; rw [hr1] at hs; exact hs

theorem u_settingsH (c : Conn) (f : Fr) : U c (settingsH c f) := by
  unfold settingsH
  split
  · exact Or.inr ⟨rfl, rfl, rfl, rfl, rfl⟩
  · have hs := u_applySettings c f.settings
    split
    · rename_i c' hc; rw [hc] at hs; exact Or.inr hs
    · rename_i r hr; rw [hr] at hs; exact hs

theorem u_wuH (fx : Fix) (c : Conn) (f : Fr) : U c (wuH fx c f) := by
  unfold wuH rstClose
  simp only
  repeat' split
  all_goals first
    | exact u_connErr _ _
    | exact u_closeRst _ _ _
    | exact u_rstCloseX _ _ _ _ _
    | exact Or.inr ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem u_rstH (c : Conn) (f : Fr) : U c (rstH c f) := by
  unfold rstH rstFlood
  have := hb_closeIfKnown c f.sid
  split
  · exact Or.inl rfl
  · exact Or.inr ⟨this.1, this.2.1, this.2.2.1, this.2.2.2.1, this.2.2.2.2⟩

theorem u_dataCredit (c : Conn) (f : Fr) (cr : Nat) : U c (dataCredit c f cr) := by
  unfold dataCredit
  simp only
  repeat' split
  all_goals exact Or.inr ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem u_dataFinish (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (cr : Nat) :
    U c (dataFinish fx c f s cr) := by
  unfold dataFinish
  split
  · exact u_rstCloseX _ _ _ _ _
  · exact u_of_hb ⟨rfl, rfl, rfl, rfl, rfl⟩ (u_dataCredit _ f _)

theorem u_dataAccept (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (n : Nat) :
    U c (dataAccept fx c f s n) := by
  unfold dataAccept
  split
  · exact u_rstCloseX _ _ _ _ _
  · refine u_of_hb ?_ (u_dataFinish _ _ _ _ _)
    split <;> exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem u_dataBody (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (n : Nat) :
    U c (dataBody fx c f s n) := by
  unfold dataBody
  repeat' split
  all_goals first
    | exact u_rstCloseX _ _ _ _ _
    | exact u_dataAccept _ _ _ _ _

theorem u_dataH (fx : Fix) (c : Conn) (f : Fr) : U c (dataH fx c f) := by
  unfold dataH
  repeat' split
  all_goals first
    | exact u_connErr _ _
    | exact u_dataBody _ _ _ _ _
    | exact Or.inr ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem u_dispatch (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (r : Conn × List Out)
    (hh : f.ty ≠ tHEADERS) (h : dispatch fx dec c f = .ok r) : U c r := by
  unfold dispatch at h
  repeat' split at h
  all_goals first
    | (rw [Except.ok.injEq] at h; subst h; first
        | exact u_settingsH c f
        | exact u_wuH fx c f
        | exact u_connErr _ _
        | exact u_dataH fx c f
        | exact u_rstH c f
        | exact Or.inr ⟨rfl, rfl, rfl, rfl, rfl⟩)
    | exact absurd ‹_› hh

/-! ## Header blocks -/

/-- The pending-block / log move of one frame, or a GOAWAY. -/
def Seq (c : Conn) (f : Fr) (r : Conn × List Out) : Prop :=
  hasGoaway r.2 = true ∨
  ((pendOf r.1, r.1.decLog) = rstep (pendOf c) c.decLog f ∧
   r.1.goawaySent = c.goawaySent ∧ r.1.isClient = c.isClient)

theorem goaway_connErr (c : Conn) (e : Nat) (hg : c.goawaySent = false) :
    hasGoaway (connErr c e).2 = true := by
  simp [connErr, hg, hasGoaway, isGoaway]

theorem seq_of_hb {c c' : Conn} {f : Fr} {r : Conn × List Out} (h : HB c c') (hs : Seq c' f r) :
    Seq c f r := by
  rcases hs with hs | ⟨h1, h2, h3⟩
  · exact Or.inl hs
  · refine Or.inr ⟨?_, h2.trans h.2.2.2.1, h3.trans h.2.2.2.2⟩
    have : pendOf c' = pendOf c := by simp [pendOf, h.2.1, h.2.2.1]
    rw [h1, this, h.1]

theorem seq_commit_of (fx : Fix) (dec : Dec) (c c1 : Conn) (f : Fr) (k : Nat)
    (hr : rstep (pendOf c) c.decLog f = (none, c1.decLog ++ [c1.block]))
    (h0 : c1.continuing = 0) (hg : c1.goawaySent = c.goawaySent) (hi : c1.isClient = c.isClient) :
    Seq c f (commit fx dec c1 k) := by
  rcases w_commit fx dec c1 k with h | ⟨h1, h2, h3, h4⟩
  · exact Or.inl h
  · refine Or.inr ⟨?_, h3.trans hg, h4.trans hi⟩
    rw [hr]; simp [pendOf, h2, h0, h1]

theorem seq_contBranch (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h0 : c.continuing ≠ 0)
    (hg : c.goawaySent = false) : Seq c f (contBranch fx dec c f) := by
  have hp : pendOf c = some (c.continuing, c.block) := by simp [pendOf, h0]
  unfold contBranch
  split
  · exact Or.inl (goaway_connErr _ _ hg)
  · rename_i hne
    have hcf : f.ty = tCONT ∧ f.sid = c.continuing := by simpa using hne
    simp only
    split
    · exact Or.inl (goaway_connErr _ _ hg)
    split
    · exact Or.inl (goaway_connErr _ _ hg)
    split
    · exact Or.inl (goaway_connErr _ _ hg)
    split
    · rename_i heh
      have hf : f.eh = false := by simpa using heh
      refine Or.inr ⟨?_, rfl, rfl⟩
      rw [hp]; simp [pendOf, h0, rstep, hcf, hf]
    · rename_i heh
      have hf : f.eh = true := by simpa using heh
      apply seq_commit_of
      · rw [hp]; simp [rstep, hcf, hf]
      · rfl
      · rfl
      · rfl

theorem seq_headersOpen (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (refuse : Nat)
    (h0 : c.continuing = 0) (ht : f.ty = tHEADERS) (hs : f.sid ≠ 0) :
    Seq c f (headersOpen fx dec c f refuse) := by
  have hp : pendOf c = none := by simp [pendOf, h0]
  unfold headersOpen
  simp only
  cases hf : f.eh
  · by_cases hr : refuse = 0
    · simp only [hr, if_true, Bool.not_false]
      refine Or.inr ⟨?_, by simp [put], by simp [put]⟩
      rw [hp]; simp [rstep, ht, hf, pendOf, hs, put]
    · simp only [hr, if_false, Bool.not_false]
      refine Or.inr ⟨?_, rfl, rfl⟩
      rw [hp]; simp [rstep, ht, hf, pendOf, hs]
  · by_cases hr : refuse = 0
    · simp only [hr, if_true, Bool.not_true]
      apply seq_commit_of
      · rw [hp]; simp [rstep, ht, hf, put]
      · simp [put, h0]
      · simp [put]
      · simp [put]
    · simp only [hr, if_false, Bool.not_true]
      apply seq_commit_of
      · rw [hp]; simp [rstep, ht, hf]
      · exact h0
      · rfl
      · rfl

theorem headersPre_inl (fx : Fix) (c : Conn) (f : Fr) (r : Conn × List Out)
    (h : headersPre fx c f = .inl r) : ∃ e, r = connErr c e := by
  unfold headersPre at h
  repeat' split at h
  all_goals first
    | (cases h; exact ⟨_, rfl⟩)
    | cases h

theorem idCheck_inl (fx : Fix) (c : Conn) (f : Fr) (r : Conn × List Out)
    (h : idCheck fx c f = .inl r) : r = connErr c ePROTOCOL := by
  unfold idCheck at h
  repeat' split at h
  all_goals first
    | (cases h; rfl)
    | cases h

theorem headersH_cases (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (r : Conn × List Out)
    (h : headersH fx dec c f = .ok r) :
    (∃ e, r = connErr c e) ∨ (f.sid ≠ 0 ∧ ∃ rf, r = headersOpen fx dec c f rf) := by
  unfold headersH at h
  repeat' split at h
  all_goals (try (simp only [Except.ok.injEq] at h; subst h))
  all_goals first
    | cases h
    | exact Or.inl ⟨_, rfl⟩
    | exact Or.inr ⟨‹_›, _, rfl⟩
    | exact Or.inl (headersPre_inl fx c f _ ‹headersPre fx c f = Sum.inl _›)

theorem seq_headersH (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (r : Conn × List Out)
    (h0 : c.continuing = 0) (ht : f.ty = tHEADERS) (hg : c.goawaySent = false)
    (h : headersH fx dec c f = .ok r) : Seq c f r := by
  rcases headersH_cases fx dec c f r h with ⟨e, rfl⟩ | ⟨hs, rf, rfl⟩
  · exact Or.inl (goaway_connErr _ _ hg)
  · exact seq_headersOpen _ _ _ _ _ h0 ht hs

theorem seq_of_u (c : Conn) (f : Fr) (r : Conn × List Out) (h0 : c.continuing = 0)
    (hh : ¬ (f.ty = tHEADERS ∨ f.ty = tPUSH)) (hu : U c r) : Seq c f r := by
  rcases hu with hu | ⟨h1, h2, h3, h4, h5⟩
  · exact Or.inl hu
  · refine Or.inr ⟨?_, h4, h5⟩
    simp [pendOf, h0, h2, h1, rstep, hh]

theorem seq_handle (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (r : Conn × List Out)
    (hg : c.goawaySent = false) (h : handle fx dec c f = .ok r) : Seq c f r := by
  unfold handle at h
  split at h
  · rename_i h0; rw [Except.ok.injEq] at h; subst h; exact seq_contBranch fx dec c f h0 hg
  · rename_i h0
    have h0 : c.continuing = 0 := by omega
    by_cases hp : f.ty = tPUSH
    · have : shapeCheck fx c f = some (connErr c ePROTOCOL) := by
        simp [shapeCheck, hp, tPUSH, tPING, tGOAWAY, tSETTINGS, tPRIORITY, tRST, tWU, tDATA]
      rw [this] at h; simp only [Except.ok.injEq] at h; subst h
      exact Or.inl (goaway_connErr _ _ hg)
    by_cases ht : f.ty = tHEADERS
    · have : shapeCheck fx c f = none := by
        simp [shapeCheck, ht, tHEADERS, tPING, tGOAWAY, tSETTINGS, tPRIORITY, tRST, tWU, tDATA, tPUSH]
      rw [this] at h; simp only at h
      split at h
      · rw [Except.ok.injEq] at h; subst h; exact Or.inl (goaway_connErr _ _ hg)
      · have hi := u_idCheck fx c f
        split at h
        · rename_i r' hid
          rw [Except.ok.injEq] at h; subst h
          rw [idCheck_inl fx c f r' hid]; exact Or.inl (goaway_connErr _ _ hg)
        · rename_i c' hid
          rw [hid] at hi
          have hd : dispatch fx dec c' f = headersH fx dec c' f := by
            simp [dispatch, ht, tHEADERS, tSETTINGS, tPING, tWU]
          rw [hd] at h
          exact seq_of_hb hi (seq_headersH fx dec c' f r (hi.2.1.trans h0) ht (hi.2.2.2.1.trans hg) h)
    · have hh : ¬ (f.ty = tHEADERS ∨ f.ty = tPUSH) := by omega
      apply seq_of_u c f r h0 hh
      have hs := u_shapeCheck fx c f
      split at h
      · rename_i r' hr; rw [hr] at hs; rw [Except.ok.injEq] at h; subst h; exact hs
      · split at h
        · rw [Except.ok.injEq] at h; subst h; exact u_connErr _ _
        · have hi := u_idCheck fx c f
          split at h
          · rename_i r' hid; rw [hid] at hi; rw [Except.ok.injEq] at h; subst h; exact hi
          · rename_i c' hid; rw [hid] at hi
            exact u_of_hb hi (u_dispatch fx dec c' f r ht h)

theorem seq_handleW (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (r : Conn × List Out)
    (hg : c.goawaySent = false) (h : handleW fx dec c f = .ok r) : Seq c f r := by
  unfold handleW at h
  split at h
  · rw [Except.ok.injEq] at h; subst h; exact Or.inl (goaway_connErr _ _ hg)
  · split at h
    · rename_i c' o hh
      rw [Except.ok.injEq] at h; subst h
      rcases seq_handle fx dec c f (c', o) hg hh with h1 | ⟨h1, h2, h3⟩
      · exact Or.inl h1
      · exact Or.inr ⟨h1, h2, h3⟩
    · cases h

theorem seq_prefaceGate (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (r : Conn × List Out)
    (hg : c.goawaySent = false) (h : prefaceGate fx dec c f = .ok r) : Seq c f r := by
  unfold prefaceGate at h
  split at h
  · split at h
    · exact seq_of_hb (c' := { c with peerSettingsSeen := true }) ⟨rfl, rfl, rfl, rfl, rfl⟩
        (seq_handleW fx dec _ f r hg h)
    · split at h
      · rw [Except.ok.injEq] at h; subst h; exact Or.inl (goaway_connErr _ _ hg)
      · exact seq_handleW fx dec c f r hg h
  · exact seq_handleW fx dec c f r hg h

/-- **Sequencing, one frame.** In server role, and in client role with the
H2-17 fix, a frame either draws a GOAWAY or moves flare's pending block
and decoder log exactly as the RFC reassembly does. -/
theorem seq_step (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (r : Conn × List Out)
    (hg : c.goawaySent = false) (hfx : fx.h2_17 = true ∨ c.isClient = false)
    (h : step fx dec c (.frame f) = .ok r) : Seq c f r := by
  simp only [step] at h
  split at h
  · rename_i hc
    unfold driveClient at h
    split at h
    · split at h
      · rw [Except.ok.injEq] at h; subst h; exact Or.inl (goaway_connErr _ _ hg)
      · cases h
    · split at h
      · rename_i hp
        have h17 : fx.h2_17 = false := by
          simp only [Bool.and_eq_true, Bool.not_eq_true'] at hp; exact hp.1
        rcases hfx with hfx | hfx
        · rw [hfx] at h17; cases h17
        · rw [hfx] at hc; cases hc
      · exact seq_prefaceGate fx dec c f r hg h
  · simp only [driveFrame, hg, Bool.false_eq_true, ↓reduceIte] at h
    split at h
    · rw [Except.ok.injEq] at h; subst h; exact Or.inl (goaway_connErr _ _ hg)
    · exact seq_prefaceGate fx dec c f r hg h

/-- Local actions never touch header blocks. -/
theorem hb_local (fx : Fix) (dec : Dec) (c : Conn) (e : Ev) (r : Conn × List Out)
    (he : ∀ f, e ≠ .frame f) (h : step fx dec c e = .ok r) : HB c r.1 := by
  cases e with
  | frame f => exact absurd rfl (he f)
  | release n =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold release; simp only; split <;> exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  | respond k n =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold respond; repeat' split
    all_goals exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  | send k n =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold send; simp only; repeat' split
    all_goals exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  | openLocal k es =>
    simp only [step, Except.ok.injEq] at h; subst h; exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  | pop k =>
    simp only [step, Except.ok.injEq] at h; subst h; exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  | endLocal k em =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold endLocal; repeat' split
    all_goals exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  | stream k =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold enableStream; split <;> exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  | drain k =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold drain; repeat' split
    all_goals exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- **Sequencing, whole run.** While no reply carries a GOAWAY, flare's
decoder log is exactly the RFC reassembly of the inbound frames (server
role, or client role with the H2-17 fix). -/
theorem seq_run (fx : Fix) (dec : Dec) :
    ∀ (es : List Ev) (c c'' : Conn) (tr : List (Ev × List Out)),
      run fx dec c es = some (c'', tr) → c.goawaySent = false →
      (fx.h2_17 = true ∨ c.isClient = false) → tr.all (fun p => !hasGoaway p.2) = true →
      (pendOf c'', c''.decLog) = rrun (pendOf c, c.decLog) (framesOf es) ∧
      c''.goawaySent = false ∧ c''.isClient = c.isClient := by
  intro es
  induction es with
  | nil =>
    intro c c'' tr hr hg _ _
    simp only [run, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨rfl, rfl⟩ := hr
    exact ⟨rfl, hg, rfl⟩
  | cons e es ih =>
    intro c c'' tr hr hg hfx hno
    simp only [run] at hr
    split at hr
    · cases hr
    · rename_i c' o hs
      split at hr
      · cases hr
      · rename_i c3 tr' hr'
        simp only [Option.some.injEq, Prod.mk.injEq] at hr
        obtain ⟨hc3, htr⟩ := hr
        subst hc3 htr
        simp only [List.all_cons, Bool.and_eq_true, Bool.not_eq_true'] at hno
        cases e with
        | frame f =>
          rcases seq_step fx dec c f (c', o) hg hfx hs with h1 | ⟨h1, h2, h3⟩
          · rw [h1] at hno; cases hno.1
          · have := ih c' c3 tr' hr' (h2.trans hg) (by rw [h3]; exact hfx) hno.2
            refine ⟨?_, this.2.1, this.2.2.trans h3⟩
            rw [this.1]; simp only [framesOf, rrun]; rw [← h1]
        | _ =>
          have hb : HB c c' := hb_local fx dec c _ (c', o) (by intro f hf; cases hf) hs
          have hp : pendOf c' = pendOf c := by simp [pendOf, hb.2.1, hb.2.2.1]
          have := ih c' c3 tr' hr' (hb.2.2.2.1.trans hg) (by rw [hb.2.2.2.2]; exact hfx) hno.2
          refine ⟨?_, this.2.1, this.2.2.trans hb.2.2.2.2⟩
          rw [this.1, hp, hb.1]; rfl

end Flare.L3.H2.Conn
