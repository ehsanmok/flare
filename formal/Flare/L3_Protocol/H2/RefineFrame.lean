import Flare.L3_Protocol.H2.RefineHdr

/-!
# §5.1 refinement: one inbound frame

`flab c f` is the spec reading of frame `f` in connection state `c`: the
stream it concerns and its `RK`. Frames on stream 0, frames that break
the preface or interleave a header block, and frame types §5.1 says
nothing about read as `other` (any verdict; the frame-level rules are
checked separately by `FReq`).

`fixed_frame`: for the fixed model `F`, every inbound frame from an
`Inv` state with no GOAWAY sent is handled without raising, meets the
§5.1 obligation `SGood` for `flab c f`, and meets `FReq`: a frame over
the advertised size draws FRAME_SIZE_ERROR; otherwise a frame that breaks
the preface (§3.4), interleaves a header block (§6.10), names stream 0
where a stream is required (§6.1-6.4, 6.10) or a stream where stream 0
is required (§6.5, 6.7, 6.8) draws PROTOCOL_ERROR.
-/
namespace Flare.L3.H2.Refine
open Flare.L3.H2.Conn Flare.L3.H2.StreamSpec

attribute [local simp] ePROTOCOL eSTREAM_CLOSED eFLOW eCALM eCOMPRESSION eFRAME_SIZE eREFUSED eNO

/-! ## Same stream states -/

def stl (l : List (Nat × Stream)) : List (Nat × St) := l.map (fun p => (p.1, p.2.state))

theorem find_state (l l' : List (Nat × Stream)) (k : Nat) (h : stl l' = stl l) :
    (l'.find? (·.1 == k)).map (·.2.state) = (l.find? (·.1 == k)).map (·.2.state) := by
  induction l generalizing l' with
  | nil => cases l' with
    | nil => rfl
    | cons _ _ => simp [stl] at h
  | cons p t ih =>
    cases l' with
    | nil => simp [stl] at h
    | cons q t' =>
      simp only [stl, List.map_cons, List.cons.injEq, Prod.mk.injEq] at h
      obtain ⟨⟨h1, h2⟩, h3⟩ := h
      simp only [List.find?_cons, h1]
      split
      · simp [h2]
      · exact ih t' h3

/-- Two connections that agree on everything the abstraction and the
invariant read, except stream fields other than the state. -/
structure SameSt (c' c : Conn) : Prop where
  st : stl c'.streams = stl c.streams
  cl : c'.isClient = c.isClient
  lp : c'.lastPeer = c.lastPeer
  ml : c'.maxLocalSid = c.maxLocalSid
  co : c'.continuing = c.continuing
  br : c'.blockRefuse = c.blockRefuse
  rb : c'.resetByUs = c.resetByUs
  gs : c'.goawaySent = c.goawaySent

theorem get_state {c c' : Conn} (h : SameSt c' c) (k : Nat) :
    (get c' k).map (·.state) = (get c k).map (·.state) := by
  unfold Flare.L3.H2.Conn.get
  simp only [Option.map_map]
  exact find_state _ _ k h.st

theorem get_state_some {c c' : Conn} (h : SameSt c' c) {k : Nat} {s' : Stream} (hs : get c' k = some s') :
    ∃ s, get c k = some s ∧ s.state = s'.state := by
  have := get_state h k
  rw [hs] at this
  cases hg : get c k with
  | none => rw [hg] at this; cases this
  | some s => rw [hg] at this; simp at this; exact ⟨s, rfl, this.symm⟩

theorem abs_sameSt {c c' : Conn} (h : SameSt c' c) : abs c' = abs c := by
  funext k
  have hg := get_state h k
  unfold abs idleAbs
  rw [h.cl, h.lp, h.ml]
  cases h1 : get c' k <;> cases h2 : get c k <;> rw [h1, h2] at hg <;> simp_all

theorem inv_sameSt {c c' : Conn} (h : SameSt c' c) (hI : Inv c) : Inv c' := by
  have ha := abs_sameSt h
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, by rw [h.gs]; exact ga⟩
  · unfold NoDupK at nd ⊢
    have : c'.streams.map (·.1) = c.streams.map (·.1) := by
      have h1 := congrArg (List.map (·.1)) h.st
      simp only [stl, List.map_map] at h1; exact h1
    rw [this]; exact nd
  · intro k s' hs'
    obtain ⟨s, hs, -⟩ := get_state_some h hs'
    have := keys k s hs; unfold keyOK at this ⊢; rw [h.cl, h.ml, h.lp]; exact this
  · intro k s' hs' he
    obtain ⟨s, hs, hst⟩ := get_state_some h hs'
    rw [h.co, h.cl, h.br]; exact idle k s hs (by rw [hst, he])
  · intro hc k s' hs'
    obtain ⟨s, hs, hst⟩ := get_state_some h hs'
    rw [← hst]; exact srv (by rw [← h.cl]; exact hc) k s hs
  · intro a b
    rw [h.co] at a ⊢; rw [h.br] at b
    obtain ⟨s, hs, hst⟩ := blk0 a b
    have := get_state h c.continuing
    rw [hs] at this
    cases hg : get c' c.continuing with
    | none => rw [hg] at this; cases this
    | some s' => rw [hg] at this; simp at this; exact ⟨s', rfl, by rw [this]; exact hst⟩
  · intro a b; rw [h.co] at a ⊢; rw [h.br] at b; rw [ha]; exact blk1 a b
  · intro a; rw [h.br]; exact cliRef (by rw [← h.cl]; exact a)
  · intro k hk; rw [h.rb] at hk; rw [ha]; exact rbu k hk

theorem stl_applyDelta (d : Int) (l : List (Nat × Stream)) : stl (applyDelta d l).1 = stl l := by
  induction l with
  | nil => rfl
  | cons p t ih =>
    unfold applyDelta
    split
    · simp only [stl, List.map_cons] at ih ⊢; rw [ih]
    · split
      · rfl
      · simp only [stl, List.map_cons] at ih ⊢; rw [ih]

theorem applySetting_cases (c : Conn) (id v : Nat) :
    (∃ c', applySetting c id v = .inl c' ∧ SameSt c' c ∧ c'.goawaySent = c.goawaySent) ∨
    (∃ c'' e, applySetting c id v = .inr (connErr c'' e) ∧ c''.goawaySent = c.goawaySent) := by
  unfold applySetting
  simp only []
  split
  · exact Or.inr ⟨c, _, rfl, rfl⟩
  split
  · split
    · split
      · exact Or.inl ⟨_, rfl, ⟨stl_applyDelta _ _, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩, rfl⟩
      · exact Or.inr ⟨_, _, rfl, rfl⟩
    · exact Or.inl ⟨_, rfl, ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩, rfl⟩
  split
  · exact Or.inl ⟨_, rfl, ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩, rfl⟩
  split
  · exact Or.inl ⟨_, rfl, ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩, rfl⟩
  split
  · exact Or.inl ⟨_, rfl, ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩, rfl⟩
  · exact Or.inl ⟨_, rfl, ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩, rfl⟩

theorem SameSt.trans {a b c : Conn} (h1 : SameSt a b) (h2 : SameSt b c) : SameSt a c :=
  ⟨h1.st.trans h2.st, h1.cl.trans h2.cl, h1.lp.trans h2.lp, h1.ml.trans h2.ml, h1.co.trans h2.co,
    h1.br.trans h2.br, h1.rb.trans h2.rb, h1.gs.trans h2.gs⟩

theorem SameSt.refl (c : Conn) : SameSt c c := ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem applySettings_cases (l : List (Nat × Nat)) : ∀ c : Conn,
    (∃ c', applySettings c l = .inl c' ∧ SameSt c' c ∧ c'.goawaySent = c.goawaySent) ∨
    (∃ c'' e, applySettings c l = .inr (connErr c'' e) ∧ c''.goawaySent = c.goawaySent) := by
  induction l with
  | nil => intro c; exact Or.inl ⟨c, rfl, SameSt.refl c, rfl⟩
  | cons p t ih =>
    intro c
    obtain ⟨id, v⟩ := p
    unfold applySettings
    rcases applySetting_cases c id v with ⟨c', h, hs, hg⟩ | ⟨c'', e, h, hg⟩
    · rw [h]; simp only []
      rcases ih c' with ⟨c2, h2, hs2, hg2⟩ | ⟨c3, e3, h3, hg3⟩
      · exact Or.inl ⟨c2, h2, hs2.trans hs, hg2.trans hg⟩
      · exact Or.inr ⟨c3, e3, h3, hg3.trans hg⟩
    · rw [h]; simp only []
      exact Or.inr ⟨c'', e, rfl, hg⟩

/-! ## Stream-0 frames -/

theorem sgood_conn0 (c : Conn) (k : Nat) (c'' : Conn) (e : Nat) (hg : c''.goawaySent = false) :
    SGood c k .other (connErr c'' e) := by
  unfold SGood SGoodV; rw [verdict_connErr _ _ _ hg]; simp [connCodes]

theorem sgood_same (c c' : Conn) (k : Nat) (o : List Out) (hI : Inv c) (hs : SameSt c' c)
    (ho : ∀ x ∈ o, x = .settingsAck ∨ x = .pingAck) : SGood c k .other (c', o) := by
  have hr : rsCode k o = none := by
    clear hs hI
    induction o with
    | nil => rfl
    | cons x t ih =>
      rcases ho x (by simp) with rfl | rfl <;> simp only [rsCode] <;>
        exact ih (fun y hy => ho y (by simp [hy]))
  have hg : gaCode o = none := by
    clear hs hI hr
    induction o with
    | nil => rfl
    | cons x t ih =>
      rcases ho x (by simp) with rfl | rfl <;> simp only [gaCode] <;>
        exact ih (fun y hy => ho y (by simp [hy]))
  have hv : verdict o k = .ok := by simp [verdict, hg, hr]
  unfold SGood SGoodV
  simp only [hv, recvOK, okPost]
  rw [abs_sameSt hs]
  refine ⟨by simp, others_refl _ _, ⟨?_, ?_, ?_⟩, inv_sameSt hs hI⟩
  · intro j n hj; rcases ho _ hj with h | h <;> cases h
  · intro j e hj; rcases ho _ hj with h | h <;> cases h
  · intro j n hj; rcases ho _ hj with h | h <;> cases h

theorem sgood_settings (c : Conn) (f : Fr) (hI : Inv c) (hg : c.goawaySent = false) (k : Nat) :
    SGood c k .other (settingsH c f) := by
  unfold settingsH
  split
  · exact sgood_same c _ k [] hI ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩ (by simp)
  · rcases applySettings_cases f.settings c with ⟨c', h, hs, _⟩ | ⟨c'', e, h, hg'⟩
    · rw [h]; exact sgood_same c c' k _ hI hs (by simp)
    · rw [h]; exact sgood_conn0 c k c'' e (hg'.trans hg)

/-! ## The frame label -/

/-- The spec reading of `f` once the preface is done. -/
def hlab (c : Conn) (f : Fr) : Nat × RK :=
  if c.continuing ≠ 0 then
    if f.ty = tCONT ∧ f.sid = c.continuing then (f.sid, if f.eh then .hdrEnd c.blockES else .contMid)
    else (f.sid, .other)
  else if f.sid = 0 then (0, .other)
  else if f.ty = tHEADERS then (f.sid, if f.eh then .hdr f.f1 else .hdrBegin)
  else if f.ty = tDATA then (f.sid, .data f.f1)
  else if f.ty = tRST then (f.sid, .rst)
  else if f.ty = tWU then (f.sid, .wu)
  else if f.ty = tPRIORITY then (f.sid, .prio)
  else if f.ty = tPUSH then (f.sid, .push)
  else if f.ty = tCONT then (f.sid, .cont)
  else (f.sid, .other)

/-- Whether `f` breaks the connection preface (§3.4). -/
def prefaceBad (c : Conn) (f : Fr) : Bool := !c.peerSettingsSeen && !(f.ty == tSETTINGS && !f.f1)

/-- The spec reading of `f`. -/
def flab (c : Conn) (f : Fr) : Nat × RK :=
  if f.plen > c.localMaxFrame || prefaceBad c f then (f.sid, .other) else hlab c f

/-- Frame-level PROTOCOL_ERROR obligations, once the preface is done. -/
def needProtoH (c : Conn) (f : Fr) : Bool :=
  (c.continuing != 0 && !(f.ty == tCONT && f.sid == c.continuing)) ||
  (c.continuing == 0 && f.sid == 0 &&
    (f.ty == tHEADERS || f.ty == tDATA || f.ty == tPRIORITY || f.ty == tRST || f.ty == tCONT ||
     f.ty == tPUSH)) ||
  (c.continuing == 0 && f.sid != 0 && (f.ty == tSETTINGS || f.ty == tPING || f.ty == tGOAWAY))

/-- Frame-level requirements: size, then preface / framing errors. -/
def FReq (c : Conn) (f : Fr) (r : Conn × List Out) : Prop :=
  (f.plen > c.localMaxFrame → gaCode r.2 = some eFRAME_SIZE) ∧
  (f.plen ≤ c.localMaxFrame → (prefaceBad c f || needProtoH c f) = true → gaCode r.2 = some ePROTOCOL)

theorem gaCode_connErr (c : Conn) (e : Nat) (hg : c.goawaySent = false) : gaCode (connErr c e).2 = some e := by
  simp [connErr, hg, gaCode]

theorem handleW_F (dec : Dec) (c : Conn) (f : Fr) : handleW F dec c f = handle F dec c f := by
  unfold handleW
  cases h : handle F dec c f with
  | error e => simp [F]
  | ok r => simp [F]

theorem idCheck_nonhdr (fx : Fix) (c : Conn) (f : Fr) (h : f.ty ≠ tHEADERS) : idCheck fx c f = .inr c := by
  unfold idCheck; simp [h]


/-! ## Frame-shape outcomes -/

section shapes
variable (c : Conn) (f : Fr)

theorem sh_ping1 (h : f.ty = tPING) (hs : f.sid ≠ 0) : shapeCheck F c f = some (connErr c ePROTOCOL) := by
  unfold shapeCheck; simp [h, hs]
theorem sh_ping6 (h : f.ty = tPING) (hs : f.sid = 0) (hp : f.plen ≠ 8) :
    shapeCheck F c f = some (connErr c eFRAME_SIZE) := by
  unfold shapeCheck; simp [h, hs, hp]
theorem sh_ping0 (h : f.ty = tPING) (hs : f.sid = 0) (hp : f.plen = 8) : shapeCheck F c f = none := by
  unfold shapeCheck; simp [h, hs, hp]
theorem sh_ga1 (h : f.ty = tGOAWAY) (hs : f.sid ≠ 0) : shapeCheck F c f = some (connErr c ePROTOCOL) := by
  unfold shapeCheck; simp [h, hs, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_ga0 (h : f.ty = tGOAWAY) (hs : f.sid = 0) : shapeCheck F c f = none := by
  unfold shapeCheck; simp [h, hs, F, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_set1 (h : f.ty = tSETTINGS) (hs : f.sid ≠ 0) : shapeCheck F c f = some (connErr c ePROTOCOL) := by
  unfold shapeCheck; simp [h, hs, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_set6 (h : f.ty = tSETTINGS) (hs : f.sid = 0) (hb : (f.f1 && f.plen ≠ 0) = true ∨ f.plen % 6 ≠ 0) :
    shapeCheck F c f = some (connErr c eFRAME_SIZE) := by
  unfold shapeCheck; simp only [h, hs, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
  cases hf : f.f1 <;> by_cases hp0 : f.plen = 0 <;> by_cases hp6 : f.plen % 6 = 0 <;> simp_all
theorem sh_set0 (h : f.ty = tSETTINGS) (hs : f.sid = 0) (hb : ¬((f.f1 && f.plen ≠ 0) = true ∨ f.plen % 6 ≠ 0)) :
    shapeCheck F c f = none := by
  unfold shapeCheck; simp only [h, hs, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
  cases hf : f.f1 <;> by_cases hp0 : f.plen = 0 <;> by_cases hp6 : f.plen % 6 = 0 <;> simp_all
theorem sh_pri1 (h : f.ty = tPRIORITY) (hs : f.sid = 0) : shapeCheck F c f = some (connErr c ePROTOCOL) := by
  unfold shapeCheck; simp [h, hs, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_pri6 (h : f.ty = tPRIORITY) (hs : f.sid ≠ 0) (hp : f.plen ≠ 5) :
    shapeCheck F c f = some (connErr c eFRAME_SIZE) := by
  unfold shapeCheck; simp [h, hs, hp, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_priI (h : f.ty = tPRIORITY) (hs : f.sid ≠ 0) (hp : f.plen = 5) (hw : f.word % 2147483648 = f.sid)
    (hi : (!mem c f.sid && isIdleId F c f.sid) = true) : shapeCheck F c f = some (connErr c ePROTOCOL) := by
  have h16 : F.h2_16 = true := rfl
  unfold shapeCheck; cases hm : mem c f.sid <;> cases hid : isIdleId F c f.sid <;> simp_all [tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_priR (h : f.ty = tPRIORITY) (hs : f.sid ≠ 0) (hp : f.plen = 5) (hw : f.word % 2147483648 = f.sid)
    (hi : ¬(!mem c f.sid && isIdleId F c f.sid) = true) :
    shapeCheck F c f = some (closeIfKnown (rstC c f.sid) f.sid, [.rst f.sid ePROTOCOL]) := by
  have h16 : F.h2_16 = true := rfl
  unfold shapeCheck; cases hm : mem c f.sid <;> cases hid : isIdleId F c f.sid <;> simp_all [tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_pri0 (h : f.ty = tPRIORITY) (hs : f.sid ≠ 0) (hp : f.plen = 5) (hw : f.word % 2147483648 ≠ f.sid) :
    shapeCheck F c f = none := by
  unfold shapeCheck; simp [h, hs, hp, hw, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_rst1 (h : f.ty = tRST) (hs : f.sid = 0) : shapeCheck F c f = some (connErr c ePROTOCOL) := by
  unfold shapeCheck; simp [h, hs, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_rst6 (h : f.ty = tRST) (hs : f.sid ≠ 0) (hp : f.plen ≠ 4) :
    shapeCheck F c f = some (connErr c eFRAME_SIZE) := by
  unfold shapeCheck; simp [h, hs, hp, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_rstI (h : f.ty = tRST) (hs : f.sid ≠ 0) (hp : f.plen = 4)
    (hi : (!mem c f.sid && isIdleId F c f.sid) = true) : shapeCheck F c f = some (connErr c ePROTOCOL) := by
  unfold shapeCheck; cases hm : mem c f.sid <;> cases hid : isIdleId F c f.sid <;> simp_all [tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_rst0 (h : f.ty = tRST) (hs : f.sid ≠ 0) (hp : f.plen = 4)
    (hi : ¬(!mem c f.sid && isIdleId F c f.sid) = true) : shapeCheck F c f = none := by
  unfold shapeCheck; cases hm : mem c f.sid <;> cases hid : isIdleId F c f.sid <;> simp_all [tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_wu6 (h : f.ty = tWU) (hp : f.plen ≠ 4) : shapeCheck F c f = some (connErr c eFRAME_SIZE) := by
  unfold shapeCheck; simp [h, hp, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_wu0 (h : f.ty = tWU) (hp : f.plen = 4) : shapeCheck F c f = none := by
  unfold shapeCheck; simp [h, hp, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_data1 (h : f.ty = tDATA) (hs : f.sid = 0) : shapeCheck F c f = some (connErr c ePROTOCOL) := by
  unfold shapeCheck; simp [h, hs, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_data0 (h : f.ty = tDATA) (hs : f.sid ≠ 0) : shapeCheck F c f = none := by
  unfold shapeCheck; simp [h, hs, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_push (h : f.ty = tPUSH) : shapeCheck F c f = some (connErr c ePROTOCOL) := by
  unfold shapeCheck; simp [h, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
theorem sh_other (h1 : f.ty ≠ tPING) (h2 : f.ty ≠ tGOAWAY) (h3 : f.ty ≠ tSETTINGS) (h4 : f.ty ≠ tPRIORITY)
    (h5 : f.ty ≠ tRST) (h6 : f.ty ≠ tWU) (h7 : f.ty ≠ tDATA) (h8 : f.ty ≠ tPUSH) : shapeCheck F c f = none := by
  unfold shapeCheck; simp [h1, h2, h3, h4, h5, h6, h7, h8]

theorem wuH_zero (h : f.sid = 0) :
    (∃ e, wuH F c f = connErr c e) ∨ (∃ c', wuH F c f = (c', []) ∧ SameSt c' c) := by
  unfold wuH
  simp only [h, ↓reduceIte]
  split
  · exact Or.inl ⟨_, rfl⟩
  · split
    · exact Or.inl ⟨_, rfl⟩
    · exact Or.inr ⟨_, rfl, ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩⟩

end shapes

/-! ## `handle_frame` -/

/-- What `handle` must produce for `f` once the preface is done. -/
def HGood (c : Conn) (f : Fr) (r : Conn × List Out) : Prop :=
  SGood c (hlab c f).1 (hlab c f).2 r ∧ (needProtoH c f = true → gaCode r.2 = some ePROTOCOL)

theorem hgood_conn (c : Conn) (f : Fr) (e : Nat) (hg : c.goawaySent = false)
    (he : (connAny e || connCodes (pid c (hlab c f).1) (abs c (hlab c f).1) (hlab c f).2 e) = true)
    (hp : needProtoH c f = true → e = ePROTOCOL) : HGood c f (connErr c e) :=
  ⟨sgood_conn c _ _ e hg he, fun h => by rw [gaCode_connErr c e hg, hp h]⟩

macro "tyconst" : tactic => `(tactic| simp only [tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING,
  tSETTINGS, tGOAWAY] at *)

theorem fixed_handle (dec : Dec) (c : Conn) (f : Fr) (hI : Inv c) (hg : c.goawaySent = false)
    (hsz : f.plen ≤ c.localMaxFrame) : ∃ r, handle F dec c f = .ok r ∧ HGood c f r := by
  unfold handle
  by_cases hc : c.continuing ≠ 0
  · rw [if_pos hc]
    by_cases hct : f.ty = tCONT ∧ f.sid = c.continuing
    · refine ⟨_, rfl, ?_, ?_⟩
      · have : hlab c f = (f.sid, if f.eh then .hdrEnd c.blockES else .contMid) := by simp [hlab, hc, hct]
        rw [this]; exact sgood_cont dec c f hI hg hc hct.1 hct.2
      · intro hn; simp [needProtoH, hct.1, hct.2, hc] at hn
    · have hcb : contBranch F dec c f = connErr c ePROTOCOL := by
        unfold contBranch; rw [if_pos]; by_cases h1 : f.ty = tCONT
        · simp [h1] at hct ⊢; exact hct
        · simp [h1]
      refine ⟨_, rfl, ?_⟩
      rw [hcb]
      apply hgood_conn c f _ hg
      · have : hlab c f = (f.sid, .other) := by simp [hlab, hc, hct]
        rw [this]; simp [connCodes]
      · intro _; rfl
  have h0 : c.continuing = 0 := by omega
  rw [if_neg hc]
  have hsz' : ¬ f.plen > c.localMaxFrame := by omega
  have hl0 : f.sid = 0 → hlab c f = (0, .other) := fun h => by simp [hlab, h0, h]
  have hm0 : mem c 0 = false := by
    cases hgm : get c 0 with
    | none => simp [mem, hgm]
    | some s => have := (hI.keys 0 s hgm).1; omega
  -- a connection error answering a frame read as `other`
  have hco : ∀ e, (hlab c f).2 = .other → (needProtoH c f = true → e = ePROTOCOL) → HGood c f (connErr c e) := by
    intro e ho hp
    apply hgood_conn c f e hg _ hp
    rw [ho]; simp [connCodes]
  -- an accepted frame read as `other` that leaves the streams alone
  have hsa : ∀ c' o, (hlab c f).2 = .other → needProtoH c f = false → SameSt c' c →
      (∀ x ∈ o, x = .settingsAck ∨ x = .pingAck) → HGood c f (c', o) := by
    intro c' o ho hn hs hx
    refine ⟨?_, fun h => by rw [hn] at h; cases h⟩
    rw [ho]; exact sgood_same c c' _ o hI hs hx
  by_cases hPING : f.ty = tPING
  · have hn : f.sid = 0 → needProtoH c f = false := fun h => by simp [needProtoH, h0, h, hPING, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    have ho : (hlab c f).2 = .other := by
      by_cases h : f.sid = 0
      · rw [hl0 h]
      · simp [hlab, h0, h, hPING, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    by_cases hsid : f.sid ≠ 0
    · have hs := sh_ping1 c f hPING hsid
      rw [hs]; exact ⟨_, rfl, hco _ ho (fun _ => rfl)⟩
    have hsid : f.sid = 0 := by omega
    by_cases hpl : f.plen ≠ 8
    · have hs := sh_ping6 c f hPING hsid hpl
      rw [hs]; exact ⟨_, rfl, hco _ ho (fun h => by rw [hn hsid] at h; cases h)⟩
    have hs := sh_ping0 c f hPING hsid (by omega)
    have hd : dispatch F dec c f = .ok (if f.f1 then (c, []) else (c, [.pingAck])) := by
      simp [dispatch, hPING, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    rw [hs]; simp only [if_neg hsz', idCheck_nonhdr F c f (by rw [hPING]; decide), hd]
    refine ⟨_, rfl, ?_⟩
    split
    · exact hsa _ _ ho (hn hsid) (SameSt.refl c) (by simp)
    · exact hsa _ _ ho (hn hsid) (SameSt.refl c) (by simp)
  by_cases hGA : f.ty = tGOAWAY
  · have hn : f.sid = 0 → needProtoH c f = false := fun h => by simp [needProtoH, h0, h, hGA, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    have ho : (hlab c f).2 = .other := by
      by_cases h : f.sid = 0
      · rw [hl0 h]
      · simp [hlab, h0, h, hGA, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    by_cases hsid : f.sid ≠ 0
    · have hs := sh_ga1 c f hGA hsid
      rw [hs]; exact ⟨_, rfl, hco _ ho (fun _ => rfl)⟩
    have hsid : f.sid = 0 := by omega
    have hs := sh_ga0 c f hGA hsid
    have hd : dispatch F dec c f = .ok ({ c with goawayReceived := true }, []) := by
      simp [dispatch, hGA, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    rw [hs]; simp only [if_neg hsz', idCheck_nonhdr F c f (by rw [hGA]; decide), hd]
    exact ⟨_, rfl, hsa _ _ ho (hn hsid) ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩ (by simp)⟩
  by_cases hSET : f.ty = tSETTINGS
  · have hn : f.sid = 0 → needProtoH c f = false := fun h => by simp [needProtoH, h0, h, hSET, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    have ho : (hlab c f).2 = .other := by
      by_cases h : f.sid = 0
      · rw [hl0 h]
      · simp [hlab, h0, h, hSET, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    by_cases hsid : f.sid ≠ 0
    · have hs := sh_set1 c f hSET hsid
      rw [hs]; exact ⟨_, rfl, hco _ ho (fun _ => rfl)⟩
    have hsid : f.sid = 0 := by omega
    by_cases hb : (f.f1 && f.plen ≠ 0) = true ∨ f.plen % 6 ≠ 0
    · have hs := sh_set6 c f hSET hsid hb
      rw [hs]; exact ⟨_, rfl, hco _ ho (fun h => by rw [hn hsid] at h; cases h)⟩
    have hs := sh_set0 c f hSET hsid hb
    have hd : dispatch F dec c f = .ok (settingsH c f) := by simp [dispatch, hSET, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    rw [hs]; simp only [if_neg hsz', idCheck_nonhdr F c f (by rw [hSET]; decide), hd]
    refine ⟨_, rfl, ?_, fun h => by rw [hn hsid] at h; cases h⟩
    rw [ho]; exact sgood_settings c f hI hg _
  by_cases hPRI : f.ty = tPRIORITY
  · by_cases hsid : f.sid = 0
    · have hs := sh_pri1 c f hPRI hsid
      rw [hs]; exact ⟨_, rfl, hco _ (by rw [hl0 hsid]) (fun _ => rfl)⟩
    have hl : hlab c f = (f.sid, .prio) := by simp [hlab, h0, hsid, hPRI, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    have hn : needProtoH c f = false := by simp [needProtoH, h0, hsid, hPRI, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    by_cases hpl : f.plen ≠ 5
    · have hs := sh_pri6 c f hPRI hsid hpl
      rw [hs]; refine ⟨_, rfl, hgood_conn c f _ hg (by simp [connAny]) (fun h => by rw [hn] at h; cases h)⟩
    by_cases hself : f.word % 2147483648 = f.sid
    · by_cases hid : (!mem c f.sid && isIdleId F c f.sid) = true
      · have hs := sh_priI c f hPRI hsid (by omega) hself hid
        rw [hs]; refine ⟨_, rfl, hgood_conn c f _ hg ?_ (fun _ => rfl)⟩
        rw [hl]; simp only
        have : abs c f.sid = .idle := by
          simp only [isIdleId_F, Bool.and_eq_true, Bool.not_eq_true'] at hid
          rw [abs_none (by simpa [mem] using hid.1), hid.2]; rfl
        rw [this]; rfl
      · have hs := sh_priR c f hPRI hsid (by omega) hself hid
        rw [hs]; refine ⟨_, rfl, ?_, fun h => by rw [hn] at h; cases h⟩
        rw [hl]
        apply sgood_closeRst c _ _ _ hI h0
        · apply abs_ne_idle_of hI h0
          simp only [isIdleId_F, Bool.and_eq_true, Bool.not_eq_true', not_and] at hid
          cases hm : mem c f.sid
          · right; cases hi : idleAbs c f.sid
            · rfl
            · exact absurd hi (hid hm)
          · left; rfl
        · intro t ht; simp [strmOK, ht]
    have hs := sh_pri0 c f hPRI hsid (by omega) hself
    have hd : dispatch F dec c f = .ok (c, []) := by simp [dispatch, hPRI, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    rw [hs]; simp only [if_neg hsz', idCheck_nonhdr F c f (by rw [hPRI]; decide), hd]
    refine ⟨_, rfl, ?_, fun h => by rw [hn] at h; cases h⟩
    rw [hl]
    exact sgood_keep c _ _ _ c hI rfl rfl (okPost_prio _ _ _ (Or.inr trivial)) (by simp) (by simp) (by simp)
  by_cases hRST : f.ty = tRST
  · by_cases hsid : f.sid = 0
    · have hs := sh_rst1 c f hRST hsid
      rw [hs]; exact ⟨_, rfl, hco _ (by rw [hl0 hsid]) (fun _ => rfl)⟩
    have hl : hlab c f = (f.sid, .rst) := by simp [hlab, h0, hsid, hRST, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    have hn : needProtoH c f = false := by simp [needProtoH, h0, hsid, hRST, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    by_cases hpl : f.plen ≠ 4
    · have hs := sh_rst6 c f hRST hsid hpl
      rw [hs]; refine ⟨_, rfl, hgood_conn c f _ hg (by simp [connAny]) (fun h => by rw [hn] at h; cases h)⟩
    by_cases hid : (!mem c f.sid && isIdleId F c f.sid) = true
    · have hs := sh_rstI c f hRST hsid (by omega) hid
      rw [hs]; refine ⟨_, rfl, hgood_conn c f _ hg ?_ (fun _ => rfl)⟩
      rw [hl]; simp only
      have : abs c f.sid = .idle := by
        simp only [isIdleId_F, Bool.and_eq_true, Bool.not_eq_true'] at hid
        rw [abs_none (by simpa [mem] using hid.1), hid.2]; rfl
      rw [this]; rfl
    have hs := sh_rst0 c f hRST hsid (by omega) hid
    have hd : dispatch F dec c f = .ok (rstH c f) := by simp [dispatch, hRST, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    rw [hs]; simp only [if_neg hsz', idCheck_nonhdr F c f (by rw [hRST]; decide), hd]
    refine ⟨_, rfl, ?_, fun h => by rw [hn] at h; cases h⟩
    rw [hl]
    apply sgood_rstH c f hI hg h0
    apply abs_ne_idle_of hI h0
    simp only [isIdleId_F, Bool.and_eq_true, Bool.not_eq_true', not_and] at hid
    cases hm : mem c f.sid
    · right; cases hi : idleAbs c f.sid
      · rfl
      · exact absurd hi (hid hm)
    · left; rfl
  by_cases hWU : f.ty = tWU
  · have hn : needProtoH c f = false := by
      by_cases hsid : f.sid = 0 <;> simp [needProtoH, h0, hsid, hWU, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    by_cases hpl : f.plen ≠ 4
    · have hs := sh_wu6 c f hWU hpl
      rw [hs]; refine ⟨_, rfl, hgood_conn c f _ hg (by simp [connAny]) (fun h => by rw [hn] at h; cases h)⟩
    have hs := sh_wu0 c f hWU (by omega)
    have hd : dispatch F dec c f = .ok (wuH F c f) := by simp [dispatch, hWU, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    rw [hs]; simp only [if_neg hsz', idCheck_nonhdr F c f (by rw [hWU]; decide), hd]
    refine ⟨_, rfl, ?_, fun h => by rw [hn] at h; cases h⟩
    by_cases hsid : f.sid = 0
    · rw [hl0 hsid]
      rcases wuH_zero c f hsid with ⟨e, he⟩ | ⟨c', he, hs'⟩
      · rw [he]; exact sgood_conn0 c 0 c _ hg
      · rw [he]; exact sgood_same c _ 0 [] hI hs' (by simp)
    · have hl : hlab c f = (f.sid, .wu) := by simp [hlab, h0, hsid, hWU, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
      rw [hl]; exact sgood_wuH c f hI hg h0 hsid
  by_cases hDATA : f.ty = tDATA
  · by_cases hsid : f.sid = 0
    · have hs := sh_data1 c f hDATA hsid
      rw [hs]; exact ⟨_, rfl, hco _ (by rw [hl0 hsid]) (fun _ => rfl)⟩
    have hl : hlab c f = (f.sid, .data f.f1) := by simp [hlab, h0, hsid, hDATA, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    have hn : needProtoH c f = false := by simp [needProtoH, h0, hsid, hDATA, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    have hs := sh_data0 c f hDATA hsid
    have hd : dispatch F dec c f = .ok (dataH F c f) := by simp [dispatch, hDATA, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    rw [hs]; simp only [if_neg hsz', idCheck_nonhdr F c f (by rw [hDATA]; decide), hd]
    refine ⟨_, rfl, ?_, fun h => by rw [hn] at h; cases h⟩
    rw [hl]; exact sgood_dataH c f hI hg h0 hsid
  by_cases hPUSH : f.ty = tPUSH
  · have hs := sh_push c f hPUSH
    rw [hs]; refine ⟨_, rfl, hgood_conn c f _ hg ?_ (fun _ => rfl)⟩
    by_cases hsid : f.sid = 0
    · rw [hl0 hsid]; simp [connCodes]
    · have hl : hlab c f = (f.sid, .push) := by simp [hlab, h0, hsid, hPUSH, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
      rw [hl]; simp [connCodes]
  have hs := sh_other c f hPING hGA hSET hPRI hRST hWU hDATA hPUSH
  by_cases hHDR : f.ty = tHEADERS
  · by_cases hsid : f.sid = 0
    · have hn : needProtoH c f = true := by simp [needProtoH, h0, hsid, hHDR, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
      rw [hs]; simp only [if_neg hsz']
      cases hcl : c.isClient
      · by_cases hlp : c.lastPeer = 0
        · have hid : idCheck F c f = .inr c := by unfold idCheck; simp [hHDR, hcl, hsid, hlp, F]
          have hh : headersH F dec c f = .ok (connErr c ePROTOCOL) := by simp [headersH, hsid, F]
          rw [hid]; simp only [dispatch_headers dec c f F hHDR, hh]
          exact ⟨_, rfl, hco _ (by rw [hl0 hsid]) (fun _ => rfl)⟩
        have hid : idCheck F c f = .inl (connErr c ePROTOCOL) := by
          unfold idCheck; simp [hHDR, hcl, hsid, hm0, F, hlp]
        rw [hid]; exact ⟨_, rfl, hco _ (by rw [hl0 hsid]) (fun _ => rfl)⟩
      · have hid : idCheck F c f = .inr c := by unfold idCheck; simp [hcl]
        have hh : headersH F dec c f = .ok (connErr c ePROTOCOL) := by simp [headersH, hsid, F]
        rw [hid]; simp only [dispatch_headers dec c f F hHDR, hh]
        exact ⟨_, rfl, hco _ (by rw [hl0 hsid]) (fun _ => rfl)⟩
    have hl : hlab c f = (f.sid, if f.eh then .hdr f.f1 else .hdrBegin) := by simp [hlab, h0, hsid, hHDR]
    have hn : needProtoH c f = false := by simp [needProtoH, h0, hsid, hHDR, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    rw [hs]; simp only [if_neg hsz']
    have hex : ∃ r, (match idCheck F c f with | .inl r => Except.ok r | .inr c => dispatch F dec c f) = .ok r := by
      cases idCheck F c f with
      | inl r => exact ⟨r, rfl⟩
      | inr c' =>
        simp only [dispatch_headers dec c' f F hHDR]
        unfold headersH; rw [if_neg hsid]
        repeat' split
        all_goals exact ⟨_, rfl⟩
    obtain ⟨r, hr⟩ := hex
    refine ⟨r, hr, ?_, fun h => by rw [hn] at h; cases h⟩
    rw [hl]; exact sgood_headers dec c f r hI hg h0 hHDR hsid hr
  by_cases hCONT : f.ty = tCONT
  · have hd : dispatch F dec c f = .ok (connErr c ePROTOCOL) := by simp [dispatch, hCONT, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
    rw [hs]; simp only [if_neg hsz', idCheck_nonhdr F c f hHDR, hd]
    refine ⟨_, rfl, hgood_conn c f _ hg ?_ (fun _ => rfl)⟩
    by_cases hsid : f.sid = 0
    · rw [hl0 hsid]; simp [connCodes]
    · have hl : hlab c f = (f.sid, .cont) := by simp [hlab, h0, hsid, hCONT, tHEADERS, tDATA, tRST, tWU, tPRIORITY, tPUSH, tCONT, tPING, tSETTINGS, tGOAWAY]
      rw [hl]; simp [connCodes]
  have hd : dispatch F dec c f = .ok (c, []) := by
    simp [dispatch, hPING, hGA, hSET, hRST, hWU, hDATA, hHDR, hCONT]
  have ho : (hlab c f).2 = .other := by
    by_cases h : f.sid = 0
    · rw [hl0 h]
    · simp [hlab, h0, h, hHDR, hDATA, hRST, hWU, hPRI, hPUSH, hCONT]
  have hn : needProtoH c f = false := by
    by_cases h : f.sid = 0 <;>
      simp [needProtoH, h0, h, hHDR, hDATA, hRST, hWU, hPRI, hPUSH, hCONT, hSET, hPING, hGA]
  rw [hs]; simp only [if_neg hsz', idCheck_nonhdr F c f hHDR, hd]
  exact ⟨_, rfl, hsa _ _ ho hn (SameSt.refl c) (by simp)⟩

/-! ## The drivers -/

theorem fixed_preface (dec : Dec) (c : Conn) (f : Fr) (hI : Inv c) (hg : c.goawaySent = false)
    (hsz : f.plen ≤ c.localMaxFrame) :
    ∃ r, prefaceGate F dec c f = .ok r ∧ SGood c (flab c f).1 (flab c f).2 r ∧ FReq c f r := by
  have hsz' : ¬ f.plen > c.localMaxFrame := by omega
  unfold prefaceGate
  by_cases hps : c.peerSettingsSeen = true
  · have hpb : prefaceBad c f = false := by simp [prefaceBad, hps]
    have hfl : flab c f = hlab c f := by simp [flab, hsz', hpb]
    rw [if_neg (by simp [hps]), handleW_F]
    obtain ⟨r, hr, hs, hp⟩ := fixed_handle dec c f hI hg hsz
    refine ⟨r, hr, by rw [hfl]; exact hs, fun h => absurd h hsz', fun _ h => hp (by simpa [hpb] using h)⟩
  · have hps : c.peerSettingsSeen = false := by simpa using hps
    rw [if_pos (by simp [hps])]
    by_cases hset : (f.ty = tSETTINGS ∧ f.f1 = false)
    · have hpb : prefaceBad c f = false := by simp [prefaceBad, hset.1, hset.2]
      have hfl : flab c f = hlab c f := by simp [flab, hsz', hpb]
      rw [if_pos (by simp [hset.1, hset.2]), handleW_F]
      have hI' : Inv { c with peerSettingsSeen := true } := inv_congr (c := c) rfl hI
      obtain ⟨r, hr, hs, hp⟩ := fixed_handle dec { c with peerSettingsSeen := true } f hI' hg hsz
      have hnp : needProtoH { c with peerSettingsSeen := true } f = needProtoH c f := rfl
      refine ⟨r, hr, by rw [hfl]; exact hs, fun h => absurd h hsz', fun _ h => hp (by rw [hnp]; simpa [hpb] using h)⟩
    · have hpb : prefaceBad c f = true := by
        simp only [prefaceBad, hps, Bool.not_false, Bool.true_and, Bool.not_eq_true']
        simp only [not_and] at hset
        cases hf : f.f1
        · have : f.ty ≠ tSETTINGS := fun h => hset h hf
          simp [this]
        · simp
      have hfl : flab c f = (f.sid, .other) := by simp [flab, hpb]
      rw [if_neg (by simpa using hset)]
      have h8 : F.h2_08 = true := rfl
      rw [if_pos h8]
      refine ⟨_, rfl, by rw [hfl]; exact sgood_conn0 c _ c _ hg, fun h => absurd h hsz',
        fun _ _ => gaCode_connErr c _ hg⟩

/-- **The fixed model meets §5.1 on every inbound frame**: from an `Inv`
state with no GOAWAY sent, the frame is handled without raising, the
reply and new state satisfy the §5.1 obligation for the frame's spec
reading, and the frame-level rules hold. -/
theorem fixed_frame (dec : Dec) (c : Conn) (f : Fr) (hI : Inv c) (hg : c.goawaySent = false) :
    ∃ r, step F dec c (.frame f) = .ok r ∧ SGood c (flab c f).1 (flab c f).2 r ∧ FReq c f r := by
  unfold step
  by_cases hsz : f.plen > c.localMaxFrame
  · have hfl : flab c f = (f.sid, .other) := by simp [flab, hsz]
    have hr : (if c.isClient then driveClient F dec c f else driveFrame F dec c f) = .ok (connErr c eFRAME_SIZE) := by
      split
      · unfold driveClient; rw [if_pos hsz]; rfl
      · unfold driveFrame; rw [if_neg (by simp [hg]), if_pos hsz]
    simp only at hr ⊢
    rw [hr]
    exact ⟨_, rfl, by rw [hfl]; exact sgood_conn0 c _ c _ hg, fun _ => gaCode_connErr c _ hg,
      fun h => absurd h (by omega)⟩
  · have hpg : (if c.isClient then driveClient F dec c f else driveFrame F dec c f) = prefaceGate F dec c f := by
      split
      · unfold driveClient; rw [if_neg hsz]; have h17 : F.h2_17 = true := rfl; simp [h17]
      · unfold driveFrame; rw [if_neg (by simp [hg]), if_neg hsz]
    simp only at hpg ⊢
    rw [hpg]
    exact fixed_preface dec c f hI hg (by omega)

end Flare.L3.H2.Refine
