import Flare.L3_Protocol.H2.RefineRun

/-!
# §5.1 refinement: where the shipped code departs

The code before any fix (flare @59bda50) is `step Fix.none`; it stays the
subject of this classification so the departures remain checkable, while
`Fix.shipped` (see `Conn.lean`) tracks the fixes that have landed. Each guard below names the inputs on
which one fix of `F` changes the model's decision; every guard is a
reported issue:

| guard | issue | inputs |
|---|---|---|
| `g02` | H2-02 | server HEADERS on `sid = lastPeer` not in the table |
| `g03` | H2-03 | client RST_STREAM / WINDOW_UPDATE / DATA on an absent id whose idleness the shipped test misjudges |
| `g15` | H2-15 | the same in server role |
| `g04` | H2-04 | client HEADERS on an id not in the table |
| `g06` | H2-06 | HEADERS on stream 0 |
| `g08` | H2-08 | first frame not SETTINGS |
| `g11` | H2-11 | server HEADERS opening a stream with `SETTINGS_MAX_CONCURRENT_STREAMS = 0` |
| `g12` | H2-12 | client END_STREAM with the last body chunk on a half-closed (remote) stream |
| `g13` | H2-13 | client END_STREAM on a closed stream |
| `g14` | H2-14 | client HEADERS on a half-closed (remote) stream |
| `g16` | H2-16 | self-dependent PRIORITY / zero-increment WINDOW_UPDATE on an idle absent id |
| `g17` | H2-17 | client PUSH_PROMISE |
| `g18` | H2-18 | client frame over the advertised maximum size |
| `g19` | H2-19 | client DATA(END_STREAM) on a half-closed (local) stream |
| `g20` | H2-20 | client DATA on a closed / half-closed (remote) stream whose headers never completed |

`shipped_eq_fixed`: when no guard fires, the shipped step equals the fixed
step. With `fixed_step`, `shipped_classified` and `shipped_run`: wherever
the shipped code fails the §5.1 refinement, a guard fired, i.e. one of
the issues above occurred. `Flare/Bugs/H2_Refine.lean` shows that every
guard does lead to a departure from the spec on a concrete trace.
-/
namespace Flare.L3.H2.Refine
open Flare.L3.H2.Conn Flare.L3.H2.StreamSpec

def idDiff (c : Conn) (k : Nat) : Bool := isIdleId Fix.none c k != isIdleId F c k

def g18 (c : Conn) (f : Fr) : Bool := c.isClient && decide (f.plen > c.localMaxFrame)
def g17 (c : Conn) (f : Fr) : Bool := c.isClient && decide (f.plen ≤ c.localMaxFrame) && f.ty == tPUSH
def g08 (c : Conn) (f : Fr) : Bool := !c.peerSettingsSeen && !(f.ty == tSETTINGS && !f.f1)
def g16 (c : Conn) (f : Fr) : Bool :=
  !mem c f.sid && isIdleId F c f.sid && f.sid != 0 &&
  ((f.ty == tPRIORITY && f.word % 2147483648 == f.sid) || (f.ty == tWU && f.word % 2147483648 == 0))
def gId (c : Conn) (f : Fr) : Bool :=
  (f.ty == tRST || f.ty == tWU || f.ty == tDATA) && f.sid != 0 && !mem c f.sid && idDiff c f.sid
def g03 (c : Conn) (f : Fr) : Bool := c.isClient && gId c f
def g15 (c : Conn) (f : Fr) : Bool := !c.isClient && gId c f
def g02 (c : Conn) (f : Fr) : Bool := f.ty == tHEADERS && !c.isClient && f.sid == c.lastPeer && !mem c f.sid
def g06 (_c : Conn) (f : Fr) : Bool := f.ty == tHEADERS && f.sid == 0
def g04 (c : Conn) (f : Fr) : Bool := f.ty == tHEADERS && c.isClient && f.sid != 0 && !mem c f.sid
def g14 (c : Conn) (f : Fr) : Bool := f.ty == tHEADERS && c.isClient && (get c f.sid).any (·.state == .hcr)
def g11 (c : Conn) (f : Fr) : Bool := f.ty == tHEADERS && !c.isClient && c.maxConcurrent == 0 && !mem c f.sid
def g19 (c : Conn) (f : Fr) : Bool := f.ty == tDATA && c.isClient && f.f1 && (get c f.sid).any (·.state == .hcl)
def g20 (c : Conn) (f : Fr) : Bool :=
  f.ty == tDATA && c.isClient && (get c f.sid).any (fun s => (s.state == .closed || s.state == .hcr) && !s.headersComplete)
def g12 (c : Conn) (k : Nat) (empty : Bool) : Bool := !empty && (get c k).any (·.state == .hcr)
def g13 (c : Conn) (k : Nat) : Bool := (get c k).any (·.state == .closed)

/-- Some guard fires on this input. -/
def guard (c : Conn) : Ev → Bool
  | .frame f => g02 c f || g03 c f || g04 c f || g06 c f || g08 c f || g11 c f || g14 c f || g15 c f ||
      g16 c f || g17 c f || g18 c f || g19 c f || g20 c f
  | .endLocal k e => g12 c k e || g13 c k
  | _ => false

/-! ## Handler by handler -/

theorem commit_eq (dec : Dec) (c : Conn) (k : Nat) : commit Fix.none dec c k = commit F dec c k := rfl

theorem contBranch_eq (dec : Dec) (c : Conn) (f : Fr) : contBranch Fix.none dec c f = contBranch F dec c f := rfl

theorem isIdleId_eq (c : Conn) (k : Nat) (h : idDiff c k = false) : isIdleId Fix.none c k = isIdleId F c k := by
  unfold idDiff at h; simpa using h

theorem shapeCheck_eq (c : Conn) (f : Fr) (h16 : g16 c f = false) (hid : gId c f = false) :
    shapeCheck Fix.none c f = shapeCheck F c f := by
  have hF16 : F.h2_16 = true := rfl
  have hN16 : Fix.none.h2_16 = false := rfl
  have hN7 : Fix.none.h2_07 = F.h2_07 := rfl
  unfold shapeCheck
  rw [hN7, hF16, hN16]
  split
  · rfl
  split
  · rfl
  split
  · rfl
  split
  · rename_i hp
    split
    · rfl
    split
    · rfl
    split
    · rename_i hw
      simp only [Bool.false_and, Bool.false_eq_true, if_false, Bool.true_and]
      rw [if_neg]
      intro hc; simp only [Bool.and_eq_true, Bool.not_eq_true'] at hc
      simp [g16, hc.1, hc.2, hp, hw] at h16
      rename_i h0 _; exact h0 h16
    · rfl
  split
  · rename_i hr
    split
    · rfl
    split
    · rfl
    have : (!mem c f.sid && isIdleId Fix.none c f.sid) = (!mem c f.sid && isIdleId F c f.sid) := by
      cases hm : mem c f.sid
      · rename_i h0 _
        rw [isIdleId_eq c f.sid (by simp [gId, hr, hm, h0] at hid; simpa using hid)]
      · rfl
    rw [this]
  rfl

theorem idCheck_eq (c : Conn) (f : Fr) (h : g02 c f = false) : idCheck Fix.none c f = idCheck F c f := by
  unfold idCheck
  split
  · rename_i hh
    simp only [Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_true'] at hh
    have hc : (decide (f.sid < c.lastPeer) && !mem c f.sid) =
        (decide (f.sid ≤ c.lastPeer) && decide (0 < c.lastPeer) && !mem c f.sid) := by
      by_cases hs : f.sid = c.lastPeer
      · have : mem c f.sid = true := by
          cases hm : mem c f.sid
          · exfalso
            have : g02 c f = true := by simp [g02, hh.1, hh.2, hm]; exact hs
            rw [h] at this; cases this
          · rfl
        simp [this]
      · have h1 : decide (f.sid < c.lastPeer) = decide (f.sid ≤ c.lastPeer) := by
          simp only [decide_eq_decide]; omega
        by_cases hlt : f.sid < c.lastPeer
        · have h3 : decide (0 < c.lastPeer) = true := by simp; omega
          rw [h1, h3]; simp
        · have h3 : decide (f.sid ≤ c.lastPeer) = false := by simp; omega
          rw [h1, h3]; simp
    rw [show Fix.none.h2_02 = false from rfl, show F.h2_02 = true from rfl]
    simp only [Bool.false_eq_true, if_false, if_true]
    rw [hc]
  · rfl

theorem wuH_eq (c : Conn) (f : Fr) (hty : f.ty = tWU) (h16 : g16 c f = false) (hid : gId c f = false) :
    wuH Fix.none c f = wuH F c f := by
  unfold wuH
  simp only []
  split
  · rename_i hi
    split
    · rfl
    rename_i hs
    have hf : (F.h2_16 && !mem c f.sid && isIdleId F c f.sid) = false := by
      cases hm : mem c f.sid <;> cases hii : isIdleId F c f.sid <;> try rfl
      simp [g16, hm, hii, hty, hi, hs, tWU, tPRIORITY] at h16
    rw [hf]; rfl
  split
  · rfl
  rename_i hi hs
  cases hg : get c f.sid with
  | some _ => rfl
  | none =>
    simp only []
    have hm : mem c f.sid = false := (mem_false c f.sid).2 hg
    rw [isIdleId_eq c f.sid (by simp [gId, hty, hs, hm, tWU] at hid; simpa using hid)]

theorem headersH_eq (dec : Dec) (c : Conn) (f : Fr) (hty : f.ty = tHEADERS) (h06 : g06 c f = false)
    (h04 : g04 c f = false) (h14 : g14 c f = false) (h11 : g11 c f = false) :
    headersH Fix.none dec c f = headersH F dec c f := by
  have hs0 : f.sid ≠ 0 := by intro h; simp [g06, hty, h] at h06
  unfold headersH
  rw [if_neg hs0, if_neg hs0]
  have hF4 : (F.h2_04 && c.isClient && !mem c f.sid) = false := by
    cases hc : c.isClient <;> cases hm : mem c f.sid <;> try rfl
    simp [g04, hty, hc, hm, hs0] at h04
  rw [hF4]
  simp only [Bool.false_eq_true, if_false, show Fix.none.h2_04 = false from rfl, Bool.false_and]
  have hpre : headersPre Fix.none c f = headersPre F c f := by
    unfold headersPre
    cases hg : get c f.sid with
    | none => rfl
    | some p =>
      simp only []
      by_cases hcl : c.isClient = true
      · have : p.state ≠ .hcr := by
          intro he; simp [g14, hty, hcl, hg, he] at h14
        simp [hcl, this, Fix.none, F]
      · simp at hcl; simp [hcl]
  rw [hpre]
  have href : ∀ r, headersRefuse Fix.none c f r = headersRefuse F c f r := by
    intro r
    unfold headersRefuse
    by_cases hc : (r = 0 && !c.isClient && !mem c f.sid) = true
    · simp only [Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_true'] at hc
      have : c.maxConcurrent > 0 := by
        cases hmc : c.maxConcurrent
        · simp [g11, hty, hc.1.2, hc.2, hmc] at h11
        · omega
      simp [this, Fix.none, F]
    · simp only [Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_true', not_and] at hc
      by_cases h1 : r = 0
      · by_cases h2 : c.isClient = false
        · have h3 := hc ⟨h1, h2⟩; simp [h1, h2, h3]
        · simp [h1, h2]
      · simp [h1]
  cases headersPre F c f with
  | inl _ => rfl
  | inr r => simp only [href r]; rfl

theorem dataFinish_eq (c : Conn) (f : Fr) (s : Stream) (cr : Nat)
    (h : (f.f1 && c.isClient && s.state == .hcl) = false) : dataFinish Fix.none c f s cr = dataFinish F c f s cr := by
  unfold dataFinish
  have : (F.h2_19 && f.f1 && c.isClient && s.state == .hcl) = false := by
    simpa [show F.h2_19 = true from rfl] using h
  rw [this]; rfl

theorem dataAccept_eq (c : Conn) (f : Fr) (s : Stream) (n : Nat)
    (h : (f.f1 && c.isClient && s.state == .hcl) = false) : dataAccept Fix.none c f s n = dataAccept F c f s n := by
  unfold dataAccept
  split
  · rfl
  · exact dataFinish_eq _ _ _ _ (by cases hc : c.isClient <;> simp_all)

theorem dataBody_eq (c : Conn) (f : Fr) (s : Stream) (n : Nat)
    (h : (f.f1 && c.isClient && s.state == .hcl) = false) : dataBody Fix.none c f s n = dataBody F c f s n := by
  unfold dataBody
  split
  · rfl
  split
  · rfl
  split
  · rfl
  · exact dataAccept_eq _ _ _ _ h

theorem dataH_eq (c : Conn) (f : Fr) (hty : f.ty = tDATA) (hs0 : f.sid ≠ 0) (hid : gId c f = false)
    (h19 : g19 c f = false) (h20 : g20 c f = false) : dataH Fix.none c f = dataH F c f := by
  unfold dataH
  split
  · rfl
  cases hg : get c f.sid with
  | none =>
    simp only []
    have hm : mem c f.sid = false := (mem_false c f.sid).2 hg
    rw [isIdleId_eq c f.sid (by simp [gId, hty, hs0, hm, tDATA] at hid; simpa using hid)]
  | some s =>
    simp only []
    have hF20 : (F.h2_20 && (s.state == .closed || s.state == .hcr)) = true ↔ (s.state = .closed ∨ s.state = .hcr) := by
      simp [show F.h2_20 = true from rfl]
    by_cases hch : s.state = .closed ∨ s.state = .hcr
    · rw [if_pos (hF20.2 hch)]
      have : ¬ (c.isClient = true ∧ s.headersComplete = false) := by
        rintro ⟨a, b⟩
        simp only [g20, hty, a, hg, b, beq_self_eq_true, Bool.true_and, Option.any_some, Bool.not_false,
          Bool.and_true] at h20
        rcases hch with e | e <;> simp [e] at h20
      have hc' : (c.isClient && !s.headersComplete) = false := by
        cases hc : c.isClient <;> cases hh : s.headersComplete <;> simp_all
      simp only [show Fix.none.h2_20 = false from rfl, Bool.false_and, Bool.false_eq_true, if_false, hc']
      rcases hch with e | e <;> simp [e]
    · rw [if_neg (fun h => hch (hF20.1 h))]
      simp only [show Fix.none.h2_20 = false from rfl, Bool.false_and, Bool.false_eq_true, if_false]
      split
      · rfl
      split
      · rfl
      cases stripLen f false with
      | none => rfl
      | some body =>
        simp only []
        apply dataBody_eq
        cases hf : f.f1 <;> cases hc : c.isClient <;> cases hst : s.state <;> try rfl
        simp [g19, hty, hf, hc, hg, hst] at h19

/-- The guards `dispatch` can meet. -/
def gD (c : Conn) (f : Fr) : Bool :=
  g03 c f || g04 c f || g06 c f || g11 c f || g14 c f || g15 c f || g16 c f || g19 c f || g20 c f

theorem gId_false {c : Conn} {f : Fr} (h03 : g03 c f = false) (h15 : g15 c f = false) : gId c f = false := by
  unfold g03 at h03; unfold g15 at h15; cases hc : c.isClient <;> simp_all

theorem dispatch_eq (dec : Dec) (c : Conn) (f : Fr) (hs0 : f.ty = tDATA → f.sid ≠ 0) (hg : gD c f = false) :
    dispatch Fix.none dec c f = dispatch F dec c f := by
  simp only [gD, Bool.or_eq_false_iff] at hg
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨h03, h04⟩, h06⟩, h11⟩, h14⟩, h15⟩, h16⟩, h19⟩, h20⟩ := hg
  have hid := gId_false h03 h15
  unfold dispatch
  split
  · rfl
  split
  · rfl
  split
  · rename_i hw; rw [wuH_eq c f hw h16 hid]
  split
  · rename_i hh; exact headersH_eq dec c f hh h06 h04 h14 h11
  split
  · rfl
  split
  · rename_i hd; rw [dataH_eq c f hd (hs0 hd) hid h19 h20]
  · rfl

theorem shapeCheck_data (fx : Fix) (c : Conn) (f : Fr) (hd : f.ty = tDATA) (h0 : f.sid = 0) :
    shapeCheck fx c f = some (connErr c ePROTOCOL) := by
  unfold shapeCheck; simp [hd, h0, tPING, tGOAWAY, tSETTINGS, tPRIORITY, tRST, tWU, tDATA]

theorem idCheck_inr (fx : Fix) (c c1 : Conn) (f : Fr) (h : idCheck fx c f = .inr c1) :
    c1.streams = c.streams ∧ c1.isClient = c.isClient ∧ c1.maxConcurrent = c.maxConcurrent ∧
    (f.ty ≠ tHEADERS → c1 = c) := by
  unfold idCheck at h
  split at h
  · rename_i hh
    have hn : ¬ f.ty ≠ tHEADERS := by simp only [Bool.and_eq_true, decide_eq_true_eq] at hh; exact fun h => h hh.1
    repeat' split at h
    all_goals first
      | (cases h; done)
      | (simp only [Sum.inr.injEq] at h; subst h
         exact ⟨rfl, rfl, rfl, fun h' => absurd h' hn⟩)
  · simp only [Sum.inr.injEq] at h; subst h; exact ⟨rfl, rfl, rfl, fun _ => rfl⟩

theorem gD_congr (c c1 : Conn) (f : Fr) (hs : c1.streams = c.streams) (hc : c1.isClient = c.isClient)
    (hm : c1.maxConcurrent = c.maxConcurrent) (hty : f.ty = tHEADERS) (h : gD c f = false) : gD c1 f = false := by
  have hg : get c1 = get c := get_congr hs
  have hme : mem c1 = mem c := by funext k; unfold mem; rw [hg]
  simp only [gD, Bool.or_eq_false_iff] at h ⊢
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨h03, h04⟩, h06⟩, h11⟩, h14⟩, h15⟩, h16⟩, h19⟩, h20⟩ := h
  refine ⟨⟨⟨⟨⟨⟨⟨⟨?_, ?_⟩, h06⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩
  all_goals first
    | (simp only [g04, g11, g14, hc, hme, hg, hm] at *; assumption)
    | simp [g03, g15, gId, g16, g19, g20, hty, tRST, tWU, tDATA, tPRIORITY, tHEADERS]

/-- The guards `handle` can meet (everything but the driver-level
H2-08/17/18). -/
def gH (c : Conn) (f : Fr) : Bool := g02 c f || gD c f

theorem handle_eq (dec : Dec) (c : Conn) (f : Fr) (hg : gH c f = false) :
    handle Fix.none dec c f = handle F dec c f := by
  simp only [gH, Bool.or_eq_false_iff] at hg
  obtain ⟨h02, hD⟩ := hg
  have hD' := hD
  simp only [gD, Bool.or_eq_false_iff] at hD'
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨h03, -⟩, -⟩, -⟩, -⟩, h15⟩, h16⟩, -⟩, -⟩ := hD'
  unfold handle
  split
  · rfl
  rw [shapeCheck_eq c f h16 (gId_false h03 h15)]
  cases hsc : shapeCheck F c f with
  | some _ => rfl
  | none =>
    simp only []
    split
    · rfl
    rw [idCheck_eq c f h02]
    generalize hid : idCheck F c f = x
    cases x with
    | inl _ => rfl
    | inr c1 =>
      obtain ⟨h1, h2, h3, h4⟩ := idCheck_inr F c c1 f hid
      apply dispatch_eq
      · intro hd h0; rw [shapeCheck_data F c f hd h0] at hsc; cases hsc
      · by_cases hty : f.ty = tHEADERS
        · exact gD_congr c c1 f h1 h2 h3 hty hD
        · rw [h4 hty]; exact hD

theorem handleW_none (dec : Dec) (c : Conn) (f : Fr) : handleW Fix.none dec c f = handle Fix.none dec c f := by
  unfold handleW
  cases h : handle Fix.none dec c f with
  | error e => simp [Fix.none]
  | ok r => simp [Fix.none]

theorem prefaceGate_eq (dec : Dec) (c : Conn) (f : Fr) (h08 : g08 c f = false) (hg : gH c f = false) :
    prefaceGate Fix.none dec c f = prefaceGate F dec c f := by
  unfold prefaceGate
  rw [handleW_none, handleW_none, handleW_F, handleW_F]
  split
  · split
    · exact handle_eq dec _ f hg
    · rename_i hp hs
      exfalso
      simp only [g08, hp, Bool.true_and, Bool.not_eq_false'] at h08
      exact hs (by simpa using h08)
  · exact handle_eq dec c f hg

theorem endLocal_eq (c : Conn) (k : Nat) (e : Bool) (h12 : g12 c k e = false) (h13 : g13 c k = false) :
    endLocal Fix.none c k e = endLocal F c k e := by
  unfold endLocal
  cases hg : get c k with
  | none => rfl
  | some s =>
    simp only []
    have hc : s.state ≠ .closed := by intro he; simp [g13, hg, he] at h13
    have hr : e = false → s.state ≠ .hcr := by intro he hh; simp [g12, hg, he, hh] at h12
    simp only [show Fix.none.h2_13 = false from rfl, show F.h2_13 = true from rfl,
      show Fix.none.h2_12 = false from rfl, show F.h2_12 = true from rfl]
    have : (s.state == .closed) = false := by simp [hc]
    rw [this]
    cases e
    · have : (s.state == .hcr) = false := by simp [hr rfl]
      simp [this]
    · simp

/-- **No guard, no departure.** -/
theorem shipped_eq_fixed (dec : Dec) (c : Conn) (e : Ev) (hg : guard c e = false) :
    step Fix.none dec c e = step F dec c e := by
  cases e with
  | frame f =>
    simp only [guard, Bool.or_eq_false_iff] at hg
    obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h02, h03⟩, h04⟩, h06⟩, h08⟩, h11⟩, h14⟩, h15⟩, h16⟩, h17⟩, h18⟩, h19⟩, h20⟩ := hg
    have hH : gH c f = false := by simp [gH, gD, *]
    simp only [step]
    split
    · rename_i hc
      unfold driveClient
      split
      · rename_i hs; exfalso; simp [g18, hc, hs] at h18
      rename_i hs
      have hp : f.ty ≠ tPUSH := by intro he; simp [g17, hc, he] at h17; omega
      simp only [show Fix.none.h2_17 = false from rfl, show F.h2_17 = true from rfl, Bool.not_false,
        Bool.true_and, Bool.not_true, Bool.false_and, Bool.false_eq_true, if_false, decide_eq_true_eq, hp]
      exact prefaceGate_eq dec c f h08 hH
    · unfold driveFrame
      split
      · rfl
      split
      · rfl
      exact prefaceGate_eq dec c f h08 hH
  | endLocal k em =>
    simp only [guard, Bool.or_eq_false_iff] at hg
    simp only [step, endLocal_eq c k em hg.1 hg.2]
  | release n => rfl
  | respond k n => rfl
  | send k n => rfl
  | openLocal k es => rfl
  | pop k => rfl
  | stream k => rfl
  | drain k => rfl

/-- **Classification, one step.** Where no reported issue occurs, the
shipped step is the fixed step, hence refines the §5.1 spec. -/
theorem shipped_classified (dec : Dec) (c : Conn) (e : Ev) (hI : Inv c) (hok : LocalOK c e)
    (hg : guard c e = false) :
    ∃ r, step Fix.none dec c e = .ok r ∧
      (hasGoaway r.2 = true → ∃ ls, (StreamSpec.lts c.isClient).Run (some (abs c)) ls none) ∧
      (hasGoaway r.2 = false → Inv r.1 ∧ r.1.isClient = c.isClient ∧ ∃ ls, SRun c.isClient (abs c) ls (abs r.1)) := by
  rw [shipped_eq_fixed dec c e hg]; exact fixed_step dec c e hI hok

/-- The shipped code on a trace, stopping at the first GOAWAY. -/
def runS (dec : Dec) : Conn → List Ev → Option (Conn × Bool)
  | c, [] => some (c, false)
  | c, e :: es =>
    match step Fix.none dec c e with
    | .error _ => none
    | .ok (c', o) => if hasGoaway o then some (c', true) else runS dec c' es

/-- No guard fires along the (fixed-model) run. -/
def Clean (dec : Dec) : Conn → List Ev → Prop
  | _, [] => True
  | c, e :: es => guard c e = false ∧ ∀ r, step F dec c e = .ok r → hasGoaway r.2 = false → Clean dec r.1 es

theorem runS_eq (dec : Dec) : ∀ (es : List Ev) (c : Conn), Clean dec c es → runS dec c es = runG dec c es := by
  intro es
  induction es with
  | nil => intro c _; rfl
  | cons e es ih =>
    intro c hc
    obtain ⟨hg, hrest⟩ := hc
    simp only [runS, runG, shipped_eq_fixed dec c e hg]
    cases h : step F dec c e with
    | error _ => rfl
    | ok r =>
      obtain ⟨c1, o⟩ := r
      simp only []
      cases hga : hasGoaway o with
      | true => rfl
      | false => simp only [Bool.false_eq_true, if_false]; exact ih c1 (hrest _ h hga)

/-- **Classification, whole runs.** From a fresh connection, an admissible
trace on which none of the reported issues occurs is matched by a run of
the §5.1 spec in the shipped code too. -/
theorem shipped_run (dec : Dec) (c : Conn) (es : List Ev) (hf : Conn.Fresh c) (hadm : Adm dec c es)
    (hcl : Clean dec c es) :
    ∃ c' b, runS dec c es = some (c', b) ∧
      ∃ s₀ ls, (StreamSpec.lts c.isClient).init s₀ ∧
        (StreamSpec.lts c.isClient).Run s₀ ls (if b then none else some (abs c')) := by
  rw [runS_eq dec es c hcl]; exact fixed_refines dec c es hf hadm

end Flare.L3.H2.Refine
