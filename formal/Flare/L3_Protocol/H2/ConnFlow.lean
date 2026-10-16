import Flare.L3_Protocol.H2.ConnWindow

/-!
# Connection flow control (RFC 9113 §6.9, §6.9.1)

Two trace-level requirements, both stated over what the receiver emits
(`ConnSpec`), proved for every HPACK outcome and every interleaving of
inbound frames and local actions, starting from a fresh connection:

* `h2_01_fixed`: with the H2-01 fix, `ConnWindowOK` holds. A DATA frame
  that overruns the connection window the peer has been granted is
  answered with a connection error (§6.9.1: "A receiver MUST treat the
  receipt of a frame that exceeds the flow-control window as a connection
  error of type FLOW_CONTROL_ERROR").
* `h2_09_fixed`: with the H2-01 and H2-09 fixes, as long as no GOAWAY has
  been emitted, the peer's view of the connection window plus the credit
  flare deliberately withholds is the initial 65535. Every DATA octet the
  receiver discards is credited back (§6.9: frames that are not processed
  still count against the window, so the receiver has to return that
  credit; otherwise the window leaks shut).

The proof is one per-step lemma. Every handler either emits a GOAWAY or
leaves `goawaySent` alone; handlers for non-DATA frames neither touch
`withheld` nor emit connection-level WINDOW_UPDATE; the DATA branch moves
exactly the frame's length into `withheld` + connection WINDOW_UPDATE.
-/
namespace Flare.L3.H2.Conn
open Flare.L3.H2.Validate (Header)

/-! ## Reply arithmetic -/

theorem wu0_append (a b : List Out) : wu0 (a ++ b) = wu0 a + wu0 b := by
  induction a with
  | nil => simp [wu0]
  | cons x t ih =>
    cases x with
    | wu k n => cases k <;> simp [wu0, ih] <;> omega
    | _ => simp [wu0, ih]

theorem wu0_wu0If (n : Nat) : wu0 (wu0If n) = n := by
  unfold wu0If; split <;> simp [wu0] <;> omega

/-! ## Handler footprint

`K g w r`: the reply emits a GOAWAY, or it keeps `goawaySent = g` and
`withheld = w` and returns no connection-level credit. -/

def K (g : Bool) (w : Nat) (r : Conn × List Out) : Prop :=
  hasGoaway r.2 = true ∨ (r.1.goawaySent = g ∧ r.1.withheld = w ∧ wu0 r.2 = 0)

def KE (g : Bool) (w : Nat) : Res → Prop
  | .ok r => K g w r
  | .error _ => True

def KO (g : Bool) (w : Nat) : Option (Conn × List Out) → Prop
  | none => True
  | some r => K g w r

def KS (g : Bool) (w : Nat) : (Conn × List Out) ⊕ Conn → Prop
  | .inl r => K g w r
  | .inr c => c.goawaySent = g ∧ c.withheld = w ∧ c.recvW = c.recvW

def KN (g : Bool) (w : Nat) : (Conn × List Out) ⊕ Nat → Prop
  | .inl r => K g w r
  | .inr _ => True

def KT (g : Bool) (w : Nat) : Conn ⊕ (Conn × List Out) → Prop
  | .inl c => c.goawaySent = g ∧ c.withheld = w
  | .inr r => K g w r

theorem k_connErr (c : Conn) (e : Nat) : K c.goawaySent c.withheld (connErr c e) := by
  unfold connErr; split
  · exact Or.inr ⟨rfl, rfl, rfl⟩
  · exact Or.inl rfl

theorem k_rst (c : Conn) (k e : Nat) : K c.goawaySent c.withheld (c, [.rst k e]) :=
  Or.inr ⟨rfl, rfl, rfl⟩

theorem k_nil (c : Conn) : K c.goawaySent c.withheld (c, []) := Or.inr ⟨rfl, rfl, rfl⟩

theorem closeIfKnown_gw (c : Conn) (k : Nat) :
    (closeIfKnown c k).goawaySent = c.goawaySent ∧ (closeIfKnown c k).withheld = c.withheld ∧
    (closeIfKnown c k).recvW = c.recvW := by
  unfold closeIfKnown; split <;> exact ⟨rfl, rfl, rfl⟩

theorem ensure_gw (c : Conn) (k : Nat) :
    (ensure c k).1.goawaySent = c.goawaySent ∧ (ensure c k).1.withheld = c.withheld := by
  unfold ensure; split
  · exact ⟨rfl, rfl⟩
  · split <;> exact ⟨rfl, rfl⟩

theorem k_closeRst (c : Conn) (k e : Nat) :
    K c.goawaySent c.withheld (closeIfKnown (rstC c k) k, [.rst k e]) := by
  have := closeIfKnown_gw (rstC c k) k
  exact Or.inr ⟨this.1, this.2.1, rfl⟩

theorem k_rstClose (c : Conn) (k e : Nat) (s : Stream) :
    K c.goawaySent c.withheld (rstClose c k e s) := Or.inr ⟨rfl, rfl, rfl⟩

theorem k_of_eq {g g' : Bool} {w w' : Nat} {r : Conn × List Out} (hg : g = g') (hw : w = w')
    (h : K g w r) : K g' w' r := by subst hg; subst hw; exact h

theorem k_commitTail (c : Conn) (k : Nat) (s : Stream) (isTr es : Bool) (hdrs : List Header) :
    K c.goawaySent c.withheld (commitTail c k s isTr es hdrs) := by
  unfold commitTail
  simp only
  repeat' split
  all_goals first
    | exact k_rstClose _ _ _ _
    | exact Or.inr ⟨rfl, rfl, rfl⟩

theorem k_commit (dec : Dec) (c : Conn) (k : Nat) :
    K c.goawaySent c.withheld (commit dec c k) := by
  unfold commit
  simp only
  have he := ensure_gw { c with block := [], blockES := false, decLog := c.decLog ++ [c.block], blockRefuse := 0 } k
  split
  · exact k_connErr _ _
  · exact k_connErr _ _
  · split
    · exact k_closeRst _ _ _
    · repeat' split
      all_goals first
        | exact k_of_eq he.1 he.2 (k_rstClose _ _ _ _)
        | exact k_of_eq he.1 he.2 (k_commitTail _ _ _ _ _ _)
        | exact Or.inr ⟨he.1, he.2, rfl⟩

theorem k_contBranch (dec : Dec) (c : Conn) (f : Fr) :
    K c.goawaySent c.withheld (contBranch dec c f) := by
  unfold contBranch
  split
  · exact k_connErr _ _
  · simp only
    repeat' split
    all_goals first
      | exact k_connErr _ _
      | exact Or.inr ⟨rfl, rfl, rfl⟩
      | exact k_commit _ _ _

theorem k_shapeCheck (c : Conn) (f : Fr) : KO c.goawaySent c.withheld (shapeCheck c f) := by
  unfold shapeCheck
  repeat' split
  all_goals first
    | trivial
    | exact k_connErr _ _
    | exact k_closeRst _ _ _

theorem k_idCheck (c : Conn) (f : Fr) : KS c.goawaySent c.withheld (idCheck c f) := by
  unfold idCheck
  repeat' split
  all_goals first
    | exact k_connErr _ _
    | exact ⟨rfl, rfl, rfl⟩

theorem k_applySetting (c : Conn) (id v : Nat) : KT c.goawaySent c.withheld (applySetting c id v) := by
  unfold applySetting
  simp only
  repeat' split
  all_goals first
    | exact k_connErr _ _
    | exact ⟨rfl, rfl⟩

theorem k_applySettings (c : Conn) (l : List (Nat × Nat)) :
    KT c.goawaySent c.withheld (applySettings c l) := by
  induction l generalizing c with
  | nil => exact ⟨rfl, rfl⟩
  | cons p t ih =>
    obtain ⟨id, v⟩ := p
    have hs := k_applySetting c id v
    unfold applySettings
    split
    · rename_i c1 hc1; rw [hc1] at hs
      have := ih c1
      revert this; generalize applySettings c1 t = r; intro this
      cases r with
      | inl c2 => exact ⟨this.1.trans hs.1, this.2.trans hs.2⟩
      | inr r => exact k_of_eq hs.1 hs.2 this
    · rename_i r1 hr1; rw [hr1] at hs; exact hs

theorem k_settingsH (c : Conn) (f : Fr) : K c.goawaySent c.withheld (settingsH c f) := by
  unfold settingsH
  split
  · exact Or.inr ⟨rfl, rfl, rfl⟩
  · have hs := k_applySettings c f.settings
    split
    · rename_i c' hc; rw [hc] at hs; exact Or.inr ⟨hs.1, hs.2, rfl⟩
    · rename_i r hr; rw [hr] at hs; exact hs

theorem k_wuH (c : Conn) (f : Fr) : K c.goawaySent c.withheld (wuH c f) := by
  unfold wuH
  simp only
  repeat' split
  all_goals first
    | exact k_connErr _ _
    | exact k_closeRst _ _ _
    | exact k_rstClose _ _ _ _
    | exact Or.inr ⟨rfl, rfl, rfl⟩

theorem k_headersPre (c : Conn) (f : Fr) : KN c.goawaySent c.withheld (headersPre c f) := by
  unfold headersPre
  repeat' split
  all_goals first
    | exact k_connErr _ _
    | trivial

theorem k_headersOpen (dec : Dec) (c : Conn) (f : Fr) (refuse : Nat) :
    K c.goawaySent c.withheld (headersOpen dec c f refuse) := by
  unfold headersOpen
  simp only
  have he := ensure_gw { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid
  have h1 : (if refuse = 0 then
      put (ensure { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid).1
        f.sid (ensure { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid).2
      else { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 }).goawaySent
        = c.goawaySent ∧
      (if refuse = 0 then
      put (ensure { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid).1
        f.sid (ensure { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid).2
      else { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 }).withheld
        = c.withheld := by
    split
    · exact he
    · exact ⟨rfl, rfl⟩
  split
  · exact Or.inr ⟨h1.1, h1.2, rfl⟩
  · exact k_of_eq h1.1 h1.2 (k_commit _ _ _)

theorem k_headersH (dec : Dec) (c : Conn) (f : Fr) :
    KE c.goawaySent c.withheld (headersH dec c f) := by
  have hp : ∀ r, headersPre c f = .inl r → K c.goawaySent c.withheld r := by
    intro r hr; have := k_headersPre c f; rw [hr] at this; exact this
  unfold headersH
  repeat' split
  all_goals first
    | exact k_connErr _ _
    | trivial
    | exact k_headersOpen _ _ _ _
    | (apply hp; assumption)

theorem k_rstH (c : Conn) (f : Fr) : K c.goawaySent c.withheld (rstH c f) := by
  unfold rstH rstFlood
  have := closeIfKnown_gw c f.sid
  split
  · exact Or.inl rfl
  · exact Or.inr ⟨this.1, this.2.1, rfl⟩

/-! ## The DATA branch -/

/-- `D g w n r`: a GOAWAY, or `goawaySent = g` and exactly `n` octets
moved into `withheld` + connection credit. -/
def D (g : Bool) (w n : Nat) (r : Conn × List Out) : Prop :=
  hasGoaway r.2 = true ∨ (r.1.goawaySent = g ∧ (r.1.withheld + wu0 r.2 = w + n))

theorem d_rstCloseX (c : Conn) (k e : Nat) (s : Stream) (x : List Out) (n : Nat)
    (hx : wu0 x = n) : D c.goawaySent c.withheld n (rstCloseX c k e s x) :=
  Or.inr ⟨rfl, by show c.withheld + wu0 x = c.withheld + n; rw [hx]⟩

theorem d_dataCredit (c : Conn) (f : Fr) (cr : Nat) (hs : f.sid ≠ 0) :
    D c.goawaySent c.withheld f.plen (dataCredit c f cr) := by
  have ho : ∀ n, wu0 [Out.wu f.sid n] = 0 := by
    intro n; cases h : f.sid with
    | zero => exact absurd h hs
    | succ m => simp [wu0]
  have ho2 : ∀ n t, wu0 (Out.wu f.sid n :: t) = wu0 t := by
    intro n t; cases h : f.sid with
    | zero => exact absurd h hs
    | succ m => simp [wu0]
  have hz : ∀ t, wu0 ((if cr > 0 then [Out.wu f.sid cr] else []) ++ t) = wu0 t := by
    intro t; split
    · exact ho2 cr t
    · rfl
  have hz0 : wu0 (if cr > 0 then [Out.wu f.sid cr] else []) = 0 := by
    have := hz []; simp only [List.append_nil] at this; rw [this]; rfl
  unfold dataCredit
  simp only
  split
  · rename_i hp
    split
    · exact Or.inr ⟨rfl, by show c.withheld + f.plen + wu0 _ = _; rw [hz0]; omega⟩
    · refine Or.inr ⟨by split <;> rfl, ?_⟩
      rw [hz]; split <;> simp [wu0] <;> omega
  · exact Or.inr ⟨rfl, by show c.withheld + 0 = c.withheld + f.plen; omega⟩

theorem d_dataFinish (c : Conn) (f : Fr) (s : Stream) (cr : Nat) (hs : f.sid ≠ 0) :
    D c.goawaySent c.withheld f.plen (dataFinish c f s cr) := by
  unfold dataFinish
  split
  · exact d_rstCloseX _ _ _ _ _ _ (wu0_wu0If _)
  · exact d_dataCredit _ f _ hs

theorem d_dataAccept (c : Conn) (f : Fr) (s : Stream) (n : Nat) (hs : f.sid ≠ 0) :
    D c.goawaySent c.withheld f.plen (dataAccept c f s n) := by
  unfold dataAccept
  split
  · exact d_rstCloseX _ _ _ _ _ _ (wu0_wu0If _)
  · have := d_dataFinish (if (!c.isClient) = true then { c with buffered := c.buffered + n } else c)
      f { s with recvW := s.recvW + (f.plen - deferOf s n),
                 pendingCredit := s.pendingCredit + deferOf s n } (f.plen - deferOf s n) hs
    have hg : (if (!c.isClient) = true then { c with buffered := c.buffered + n } else c).goawaySent
        = c.goawaySent := by split <;> rfl
    have hw : (if (!c.isClient) = true then { c with buffered := c.buffered + n } else c).withheld
        = c.withheld := by split <;> rfl
    rw [hg, hw] at this; exact this

theorem d_dataBody (c : Conn) (f : Fr) (s : Stream) (n : Nat) (hs : f.sid ≠ 0) :
    D c.goawaySent c.withheld f.plen (dataBody c f s n) := by
  unfold dataBody
  repeat' split
  all_goals first
    | exact d_rstCloseX _ _ _ _ _ _ (wu0_wu0If _)
    | exact d_dataAccept _ _ _ _ hs

theorem d_dataH (c : Conn) (f : Fr) (hs : f.sid ≠ 0) (hg : c.goawaySent = false) :
    D c.goawaySent c.withheld f.plen (dataH c f) := by
  have hce : ∀ e, D c.goawaySent c.withheld f.plen (connErr c e) := by
    intro e; unfold connErr; rw [hg]; exact Or.inl rfl
  unfold dataH
  split
  · exact Or.inr ⟨rfl, by show c.withheld + wu0 (wu0If f.plen) = _; rw [wu0_wu0If]⟩
  · split
    · split <;> exact hce _
    · repeat' split
      all_goals first
        | exact hce _
        | exact d_rstCloseX _ _ _ _ _ _ (wu0_wu0If _)
        | exact d_dataBody _ _ _ _ hs

/-! ## One inbound frame -/

theorem k_dispatch (dec : Dec) (c : Conn) (f : Fr) (hd : f.ty ≠ tDATA) :
    KE c.goawaySent c.withheld (dispatch dec c f) := by
  unfold dispatch
  repeat' split
  all_goals first
    | exact k_settingsH c f
    | exact k_wuH c f
    | exact k_headersH dec c f
    | exact k_rstH c f
    | exact k_connErr _ _
    | exact absurd ‹_› hd
    | exact Or.inr ⟨rfl, rfl, rfl⟩

theorem k_handle (dec : Dec) (c : Conn) (f : Fr) (hd : f.ty ≠ tDATA) :
    KE c.goawaySent c.withheld (handle dec c f) := by
  unfold handle
  split
  · exact k_contBranch dec c f
  · have hs := k_shapeCheck c f
    split
    · rename_i r' hr; rw [hr] at hs; exact hs
    · split
      · exact k_connErr _ _
      · have hi := k_idCheck c f
        split
        · rename_i r' hid; rw [hid] at hi; exact hi
        · rename_i c' hid; rw [hid] at hi
          have := k_dispatch dec c' f hd
          rw [hi.1, hi.2.1] at this; exact this

/-- A DATA frame `handle` does not route to the DATA branch is a
connection error. -/
theorem handle_data_other (dec : Dec) (c : Conn) (f : Fr) (hd : f.ty = tDATA)
    (hl : f.plen ≤ c.localMaxFrame) (hr : reachesData c f = false) (hg : c.goawaySent = false) :
    handle dec c f = .ok (connErr c ePROTOCOL) := by
  unfold reachesData at hr
  by_cases hc : c.continuing = 0
  · have h0 : f.sid = 0 := by
      simp [hc, hd, hl, tDATA] at hr; exact hr
    simp [handle, hc, shapeCheck, hd, h0, tDATA, tPING, tGOAWAY, tSETTINGS, tPRIORITY, tRST, tWU]
  · simp [handle, hc, contBranch, hd, tDATA, tCONT]

theorem handle_data (dec : Dec) (c : Conn) (f : Fr) (hr : reachesData c f = true) :
    handle dec c f = .ok (dataH c f) := by
  unfold reachesData at hr
  simp only [Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, decide_eq_true_eq] at hr
  obtain ⟨⟨⟨hc, hd⟩, h0⟩, hl⟩ := hr
  have hid : idCheck c f = .inr c := by simp [idCheck, hd, tDATA, tHEADERS]
  simp [handle, hc, shapeCheck, hd, h0, Nat.not_lt.mpr hl, hid, dispatch,
    tDATA, tPING, tGOAWAY, tSETTINGS, tPRIORITY, tRST, tWU, tPUSH, tHEADERS, tCONT]

/-- The per-frame obligation, for `handle` from a live connection. -/
def FrameOK (c : Conn) (f : Fr) (r : Conn × List Out) : Prop :=
  hasGoaway r.2 = true ∨
  (r.1.goawaySent = false ∧
    (if reachesData c f then r.1.withheld + wu0 r.2 = c.withheld + f.plen
     else r.1.withheld = c.withheld ∧ wu0 r.2 = 0 ∧ flowLen (.frame f) = 0))

theorem frameOK_handle (dec : Dec) (c : Conn) (f : Fr) (r : Conn × List Out)
    (hg : c.goawaySent = false) (hl : f.plen ≤ c.localMaxFrame) (h : handle dec c f = .ok r) :
    FrameOK c f r := by
  by_cases hrd : reachesData c f = true
  · rw [handle_data dec c f hrd, Except.ok.injEq] at h
    subst h
    have hs : f.sid ≠ 0 := by
      unfold reachesData at hrd; simp only [Bool.and_eq_true, bne_iff_ne] at hrd; exact hrd.1.2
    rcases d_dataH c f hs hg with h1 | ⟨h1, h2⟩
    · exact Or.inl h1
    · exact Or.inr ⟨h1.trans hg, by rw [if_pos hrd]; exact h2⟩
  · have hrd' : reachesData c f = false := by simpa using hrd
    by_cases hd : f.ty = tDATA
    · rw [handle_data_other dec c f hd hl hrd' hg, Except.ok.injEq] at h
      subst h
      left; simp [connErr, hg, hasGoaway, isGoaway]
    · have := k_handle dec c f hd
      rw [h] at this
      rcases this with h1 | ⟨h1, h2, h3⟩
      · exact Or.inl h1
      · refine Or.inr ⟨h1.trans hg, ?_⟩
        rw [if_neg hrd]
        exact ⟨h2, h3, by simp [flowLen, hd]⟩

/-! ## One step of the whole connection -/

/-- What the monitors need from one step taken while no GOAWAY has been
emitted. -/
def StepOK (c : Conn) (e : Ev) (r : Conn × List Out) : Prop :=
  hasGoaway r.2 = true ∨
  (r.1.goawaySent = false ∧ r.1.recvW = c.recvW - flowLen e + wu0 r.2 ∧
    (flowLen e > 0 → (flowLen e : Int) ≤ c.recvW) ∧
    (r.1.withheld + wu0 r.2 = c.withheld + flowLen e))

theorem stepOK_handleW (dec : Dec) (c : Conn) (f : Fr)
    (r : Conn × List Out) (hg : c.goawaySent = false) (hl : f.plen ≤ c.localMaxFrame)
    (h : handleW dec c f = .ok r) : StepOK c (.frame f) r := by
  unfold handleW at h
  split at h
  · rw [Except.ok.injEq] at h; subst h; left; simp [connErr, hg, hasGoaway, isGoaway]
  · rename_i hn
    split at h
    · rename_i c' o hh
      rw [Except.ok.injEq] at h; subst h
      rcases frameOK_handle dec c f (c', o) hg hl hh with hgo | ⟨hg', hk⟩
      · exact Or.inl hgo
      · right
        refine ⟨hg', ?_, ?_, ?_⟩ <;> by_cases hrd : reachesData c f = true
        · have hd : f.ty = tDATA := by
            unfold reachesData at hrd; simp only [Bool.and_eq_true, beq_iff_eq] at hrd; exact hrd.1.1.2
          simp [hrd, flowLen, hd]
        · have hrd' : reachesData c f = false := by simpa using hrd
          rw [if_neg hrd] at hk
          simp [hrd', hk.2.2]
        · have hd : f.ty = tDATA := by
            unfold reachesData at hrd; simp only [Bool.and_eq_true, beq_iff_eq] at hrd; exact hrd.1.1.2
          intro _
          simp only [hrd, Bool.true_and, decide_eq_true_eq, Bool.not_eq_true'] at hn
          simp [flowLen, hd] <;> omega
        · rw [if_neg hrd] at hk; simp [hk.2.2]
        · rw [if_pos hrd] at hk
          have hd : f.ty = tDATA := by
            unfold reachesData at hrd; simp only [Bool.and_eq_true, beq_iff_eq] at hrd; exact hrd.1.1.2
          simp only [flowLen, hd, if_true]; exact hk
        · rw [if_neg hrd] at hk
          simp only; rw [hk.1, hk.2.1, hk.2.2]
    · cases h

theorem stepOK_prefaceGate (dec : Dec) (c : Conn) (f : Fr)
    (r : Conn × List Out) (hg : c.goawaySent = false) (hl' : f.plen ≤ c.localMaxFrame)
    (h : prefaceGate dec c f = .ok r) : StepOK c (.frame f) r := by
  unfold prefaceGate at h
  split at h
  · split at h
    · exact stepOK_handleW dec { c with peerSettingsSeen := true } f r hg hl' h
    · rw [Except.ok.injEq] at h; subst h; left; simp [connErr, hg, hasGoaway, isGoaway]
  · exact stepOK_handleW dec c f r hg hl' h

theorem stepOK_step (dec : Dec) (c : Conn) (e : Ev)
    (r : Conn × List Out) (hg : c.goawaySent = false) (h : step dec c e = .ok r) :
    StepOK c e r := by
  cases e with
  | frame f =>
    simp only [step] at h
    split at h
    · unfold driveClient at h
      split at h
      · rw [Except.ok.injEq] at h; subst h; left; simp [connErr, hg, hasGoaway, isGoaway]
      · rename_i hl
        have hl' : f.plen ≤ c.localMaxFrame := by omega
        exact stepOK_prefaceGate dec c f r hg hl' h
    · simp only [driveFrame, hg, Bool.false_eq_true, ↓reduceIte] at h
      split at h
      · rw [Except.ok.injEq] at h; subst h; left; simp [connErr, hg, hasGoaway, isGoaway]
      · rename_i hl
        have hl' : f.plen ≤ c.localMaxFrame := by omega
        exact stepOK_prefaceGate dec c f r hg hl' h
  | release n =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold release
    simp only [if_true]
    split
    · right; refine ⟨hg, ?_, ?_, ?_⟩
      · simp [wu0, flowLen]
      · simp [flowLen]
      · simp [wu0, flowLen]
    · right; refine ⟨hg, ?_, ?_, ?_⟩
      · simp [wu0, flowLen]
      · simp [flowLen]
      · simp [wu0, flowLen]
  | respond k n =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold respond
    repeat' split
    all_goals (right; refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [wu0, flowLen, put, hg])
  | send k n =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold send
    simp only
    repeat' split
    all_goals (right; refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [wu0, flowLen, put, hg])
  | openLocal k es =>
    simp only [step, Except.ok.injEq] at h; subst h
    right; refine ⟨hg, ?_, ?_, ?_⟩ <;> simp [wu0, flowLen, openLocal, put]
  | pop k =>
    simp only [step, Except.ok.injEq] at h; subst h
    right; refine ⟨hg, ?_, ?_, ?_⟩ <;> simp [wu0, flowLen, erase]
  | endLocal k =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold endLocal
    repeat' split
    all_goals (right; refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [wu0, flowLen, put, hg])
  | stream k =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold enableStream
    split <;> (right; refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [wu0, flowLen, put, hg])
  | drain k =>
    simp only [step, Except.ok.injEq] at h; subst h
    unfold drain
    split
    · right; refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [wu0, flowLen, hg]
    · rename_i hk
      split
      · right; refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [wu0, flowLen, hg]
      · have hw : ∀ n, wu0 [Out.wu k n] = 0 := by
          intro n; cases k with
          | zero => exact absurd rfl hk
          | succ m => simp [wu0]
        split <;> (right; refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [wu0, flowLen, put, hg, hw])

/-! ## Trace theorems -/

/-- Invariant carried along a run: while no GOAWAY has been emitted,
`recvW` is the window the peer sees, and it plus `withheld` is the
initial window. -/
def Live (alive : Bool) (w : Int) (c : Conn) : Prop :=
  alive = true → c.goawaySent = false ∧ c.recvW = w ∧ (c.recvW + c.withheld = 65535)

theorem run_live (dec : Dec) :
    ∀ (es : List Ev) (c c'' : Conn) (tr : List (Ev × List Out)) (alive : Bool) (w : Int),
      Live alive w c → run dec c es = some (c'', tr) →
      connWindowOK alive w tr = true ∧ Live (alive && !tr.any (fun p => hasGoaway p.2)) (peerW w tr) c'' := by
  intro es
  induction es with
  | nil =>
    intro c c'' tr alive w hL hr
    simp only [run, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨rfl, rfl⟩ := hr
    exact ⟨rfl, by simpa [peerW] using hL⟩
  | cons e es ih =>
    intro c c'' tr alive w hL hr
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
        cases ha : alive
        · have hL' : Live false (w - flowLen e + wu0 o) c' := fun h => by cases h
          have := ih c' c3 tr' false _ hL' hr'
          simp only [connWindowOK, Bool.false_and, Bool.not_false, Bool.true_and, peerW, List.any_cons]
          simpa using this
        · obtain ⟨hg, hw, hc⟩ := hL ha
          have hst := stepOK_step dec c e (c', o) hg hs
          by_cases hgo : hasGoaway o = true
          · have hL' : Live false (w - flowLen e + wu0 o) c' := fun h => by cases h
            have := ih c' c3 tr' false _ hL' hr'
            simp only [connWindowOK, hgo, peerW, List.any_cons]
            simpa using this
          · rcases hst with hst | ⟨hg', hrw, hle, h9⟩
            · exact absurd hst hgo
            · have hL' : Live true (w - flowLen e + wu0 o) c' := by
                intro _
                refine ⟨hg', by rw [hrw, hw], ?_⟩
                have e1 := h9; have e2 := hc
                simp only at e1 hrw ⊢
                rw [hrw]; omega
              have := ih c' c3 tr' true _ hL' hr'
              have hgo' : hasGoaway o = false := by simpa using hgo
              refine ⟨?_, ?_⟩
              · simp only [connWindowOK, hgo', Bool.and_true, Bool.not_false, Bool.true_and,
                  Bool.and_eq_true, decide_eq_true_eq]
                refine ⟨?_, this.1⟩
                simp only [Bool.not_eq_true', Bool.and_eq_false_iff, decide_eq_false_iff_not]
                by_cases hf : flowLen e > 0
                · right; have := hle hf; omega
                · left; exact hf
              · simpa [peerW, List.any_cons, hgo'] using this.2

/-- **H2-01.** Every run from a fresh connection satisfies the §6.9.1
monitor. -/
theorem h2_01_fixed (dec : Dec) (c : Conn) (hF : Fresh c)
    (es : List Ev) (c'' : Conn) (tr : List (Ev × List Out)) (hr : run dec c es = some (c'', tr)) :
    ConnWindowOK tr := by
  have hL : Live true 65535 c := by
    intro _
    obtain ⟨-, -, h3, -, h5, -, h7, -⟩ := hF
    exact ⟨h5, h3, by rw [h3, h7]; rfl⟩
  exact (run_live dec es c c'' tr true 65535 hL hr).1

/-- **H2-09.** While no GOAWAY has been emitted, the peer's connection
window plus the withheld credit is the initial window: no DATA octet's
credit is lost. -/
theorem h2_09_fixed (dec : Dec) (c : Conn)
    (hF : Fresh c) (es : List Ev) (c'' : Conn) (tr : List (Ev × List Out))
    (hr : run dec c es = some (c'', tr)) (hno : tr.any (fun p => hasGoaway p.2) = false) :
    peerW 65535 tr + c''.withheld = 65535 := by
  have hL : Live true 65535 c := by
    intro _
    obtain ⟨-, -, h3, -, h5, -, h7, -⟩ := hF
    exact ⟨h5, h3, by rw [h3, h7]; rfl⟩
  have := (run_live dec es c c'' tr true 65535 hL hr).2
  simp only [hno, Bool.not_false, Bool.and_self] at this
  obtain ⟨-, hw, hc⟩ := this rfl
  rw [← hw]; exact hc

end Flare.L3.H2.Conn
