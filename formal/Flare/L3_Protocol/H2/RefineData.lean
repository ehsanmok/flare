import Flare.L3_Protocol.H2.RefineAbs

/-!
# §5.1 refinement: WINDOW_UPDATE, RST_STREAM, PRIORITY and DATA

Per-handler proofs that the fixed model `F` answers a frame on stream `k`
as §5.1 prescribes for the spec state `abs c k` (`SGood`), from a live
state with no header block open.
-/
namespace Flare.L3.H2.Refine
open Flare.L3.H2.Conn Flare.L3.H2.StreamSpec

attribute [local simp] ePROTOCOL eSTREAM_CLOSED eFLOW eCALM eCOMPRESSION eFRAME_SIZE eREFUSED eNO

theorem ofSt_ne_resL (t : St) : ofSt t ≠ .resL := by cases t <;> simp [ofSt]

theorem entry_nonidle {c : Conn} {k : Nat} {s : Stream} (hI : Inv c) (h0 : c.continuing = 0)
    (hs : get c k = some s) : s.state ≠ .idle := by
  intro he
  have := (hI.idle k s hs he).1
  have hk := (hI.keys k s hs).1
  omega

theorem abs_ne_idle_of {c : Conn} {k : Nat} (hI : Inv c) (h0 : c.continuing = 0)
    (h : mem c k = true ∨ idleAbs c k = false) : abs c k ≠ .idle := by
  unfold abs
  cases hg : get c k with
  | some s => simp only; have := entry_nonidle hI h0 hg; cases hs : s.state <;> simp_all [ofSt]
  | none =>
    simp only
    rcases h with h | h
    · simp [mem, hg] at h
    · simp [h]

theorem gaCode_wu0 (l : List Out) (h : ∀ o ∈ l, ∃ n, o = .wu 0 n) : gaCode l = none := by
  induction l with
  | nil => rfl
  | cons o t ih =>
    obtain ⟨n, rfl⟩ := h o (List.mem_cons_self ..)
    simp [gaCode, ih (fun o ho => h o (List.mem_cons_of_mem _ ho))]

theorem rsCode_wu0 (k : Nat) (l : List Out) (h : ∀ o ∈ l, ∃ n, o = .wu 0 n) : rsCode k l = none := by
  induction l with
  | nil => rfl
  | cons o t ih =>
    obtain ⟨n, rfl⟩ := h o (List.mem_cons_self ..)
    simp [rsCode, ih (fun o ho => h o (List.mem_cons_of_mem _ ho))]

theorem wu0If_shape (n : Nat) : ∀ o ∈ wu0If n, ∃ m, o = .wu 0 m := by
  intro o ho; unfold wu0If at ho; split at ho <;> simp_all

/-- A stream error on a stream in the table. -/
theorem sgood_rstCloseX (c : Conn) (k code : Nat) (s0 s : Stream) (extra : List Out) (rk : RK)
    (hI : Inv c) (h0 : c.continuing = 0) (hs0 : get c k = some s0)
    (hrk : strmOK (ofSt s0.state) rk = true) (hx : ∀ o ∈ extra, ∃ n, o = .wu 0 n) :
    SGood c k rk (rstCloseX c k code s extra) := by
  have hk := hI.keys k s0 hs0
  unfold SGood SGoodV rstCloseX
  have hv : verdict (Out.rst k code :: extra) k = .strm code := by
    simp [verdict, gaCode, gaCode_wu0 extra hx, rsCode]
  simp only [hv]
  refine ⟨?_, ?_, ⟨?_, ?_, ?_⟩, inv_rstClose c k s hI hk h0⟩
  · rw [abs_some hs0, abs_put_self]; simp only [recvOK, hrk, Bool.true_and]; rfl
  · intro j hj; left; rw [abs_put_other _ _ _ _ hj, abs_rstC]
  · intro j n hj hj0
    simp only [List.mem_cons] at hj
    rcases hj with hj | hj
    · cases hj
    · obtain ⟨m, hm⟩ := hx _ hj; cases hm; exact absurd rfl hj0
  · intro j e hj
    simp only [List.mem_cons] at hj
    rcases hj with hj | hj
    · cases hj; rfl
    · obtain ⟨m, hm⟩ := hx _ hj; cases hm
  · intro j n hj
    simp only [List.mem_cons] at hj
    rcases hj with hj | hj
    · cases hj
    · obtain ⟨m, hm⟩ := hx _ hj; cases hm

theorem sgood_rstClose (c : Conn) (k code : Nat) (s0 s : Stream) (rk : RK)
    (hI : Inv c) (h0 : c.continuing = 0) (hs0 : get c k = some s0)
    (hrk : strmOK (ofSt s0.state) rk = true) : SGood c k rk (rstClose c k code s) :=
  sgood_rstCloseX c k code s0 s [] rk hI h0 hs0 hrk (by simp)

/-- `closeIfKnown (rstC c k) k` with `RST_STREAM(k)` on a stream that is
not idle. -/
theorem sgood_closeRst (c : Conn) (k code : Nat) (rk : RK) (hI : Inv c) (h0 : c.continuing = 0)
    (hni : abs c k ≠ .idle) (hrk : ∀ t, t ≠ .idle → strmOK t rk = true) :
    SGood c k rk (closeIfKnown (rstC c k) k, [.rst k code]) := by
  have hcl : (∃ s, get c k = some s) ∨ abs c k = .closed := by
    cases hg : get c k with
    | some s => exact Or.inl ⟨s, rfl⟩
    | none =>
      right; rw [abs_none hg] at hni ⊢; split <;> simp_all
  unfold SGood SGoodV
  have hv : verdict [Out.rst k code] k = .strm code := by simp [verdict, gaCode, rsCode]
  simp only [hv]
  refine ⟨?_, ?_, ⟨?_, ?_, ?_⟩, inv_closeRst c k hI h0 hcl⟩
  · rw [abs_closeRst]; simp only [true_and]
    have hpost : (if (get c k).isSome = true then SS.closed else abs c k) = .closed := by
      cases hg : get c k with
      | some s => rfl
      | none => rcases hcl with ⟨s, hs⟩ | h
                · rw [hg] at hs; cases hs
                · simp [h]
    rw [hpost]; simp [recvOK, hrk _ hni]
  · intro j hj; left; rw [abs_closeRst]; simp [hj]
  · intro j n hj; simp at hj
  · intro j e hj; simp at hj; exact hj.1
  · intro j n hj; simp at hj

/-- Accepting a frame and storing `s` at `k`. -/
theorem sgood_put_ok (c : Conn) (k : Nat) (s : Stream) (o : List Out) (rk : RK) (c1 : Conn)
    (hI : Inv c) (h0 : c.continuing = 0) (hk : keyOK c k) (hiv : iv c1 = iv c)
    (hni : s.state ≠ .idle) (hsrv : c.isClient = false → s.state ≠ .hcl)
    (hrbu : k ∈ c.resetByUs → s.state = .closed)
    (hv : verdict o k = .ok)
    (hpost : okPost (pid c k) (room c) (abs c k) rk (ofSt s.state) = true)
    (hsend : ∀ j n, Out.wu j n ∈ o → j ≠ 0 → j = k ∧ wuOK (ofSt s.state) = true)
    (hrst : ∀ j e, Out.rst j e ∉ o) (hdata : ∀ j n, Out.data j n ∉ o) :
    SGood c k rk (put c1 k s, o) := by
  have ha : abs (put c1 k s) = abs (put c k s) := by
    funext j; rw [abs_put, abs_put, abs_congr hiv]
  unfold SGood SGoodV
  simp only [hv]
  refine ⟨?_, ?_, ⟨?_, fun j e h => absurd h (hrst j e), hdata⟩, ?_⟩
  · rw [ha, abs_put_self]; simpa [recvOK] using hpost
  · rw [ha]; exact others_put c k s
  · intro j n hj hj0
    obtain ⟨rfl, hw⟩ := hsend j n hj hj0
    rw [ha, abs_put_self]; exact hw
  · have := inv_put0 c k s hI hk h0 hni hsrv hrbu
    have hiv' : iv (put c1 k s) = iv (put c k s) := by
      simp only [iv, put, IV.mk.injEq] at hiv ⊢; obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := hiv
      exact ⟨by rw [h1], h2, h3, h4, h5, h6, h7, h8⟩
    exact inv_congr hiv' this

/-- Accepting a frame without touching the table. -/
theorem sgood_keep (c : Conn) (k : Nat) (o : List Out) (rk : RK) (c1 : Conn)
    (hI : Inv c) (hiv : iv c1 = iv c) (hv : verdict o k = .ok)
    (hpost : okPost (pid c k) (room c) (abs c k) rk (abs c k) = true)
    (hsend : ∀ j n, Out.wu j n ∈ o → j = 0) (hrst : ∀ j e, Out.rst j e ∉ o)
    (hdata : ∀ j n, Out.data j n ∉ o) : SGood c k rk (c1, o) := by
  unfold SGood SGoodV
  simp only [hv]
  rw [abs_congr hiv]
  refine ⟨by simpa [recvOK] using hpost, others_refl _ _, ⟨?_, fun j e h => absurd h (hrst j e), hdata⟩,
    inv_congr hiv hI⟩
  intro j n hj hj0; exact absurd (hsend j n hj) hj0

/-! ## WINDOW_UPDATE on a stream -/

theorem okPost_wu (b r : Bool) (t : St) (ht : t ≠ .idle) : okPost b r (ofSt t) .wu (ofSt t) = true := by
  cases t <;> simp_all [ofSt, okPost]

theorem okPost_prio (b r : Bool) (s : SS) (hs : s ≠ .resR ∧ s ≠ .resL ∨ True) : okPost b r s .prio s = true := by
  cases s <;> simp [okPost]

theorem sgood_wuH (c : Conn) (f : Fr) (hI : Inv c) (hg : c.goawaySent = false) (h0 : c.continuing = 0)
    (hk : f.sid ≠ 0) : SGood c f.sid .wu (wuH F c f) := by
  unfold wuH
  simp only [isIdleId_F]
  split
  · try rw [if_neg hk]
    split
    · rename_i h
      simp only [F, Bool.true_and, Bool.and_eq_true, Bool.not_eq_true'] at h
      apply sgood_conn c _ _ _ hg
      have : abs c f.sid = .idle := by
        rw [abs_none ((mem_false c f.sid).mp h.1), h.2]; rfl
      simp [this, connCodes]
    · rename_i h
      apply sgood_closeRst c f.sid _ _ hI h0
      · apply abs_ne_idle_of hI h0
        simp only [F, Bool.true_and, Bool.and_eq_true, Bool.not_eq_true', not_and] at h
        cases hm : mem c f.sid
        · right; cases hi : idleAbs c f.sid
          · rfl
          · exact absurd hi (h hm)
        · left; rfl
      · intro t ht; cases t <;> simp_all [strmOK]
  · try rw [if_neg hk]
    split
    · rename_i hnone
      split
      · rename_i hi
        apply sgood_conn c _ _ _ hg
        rw [abs_none hnone, hi]; simp [connCodes]
      · rename_i hi
        apply sgood_keep c _ _ _ c hI rfl (by rfl)
        · rw [abs_none hnone]; simp [hi, okPost]
        · simp
        · simp
        · simp
    · rename_i s hs
      split
      · exact sgood_rstClose c f.sid eFLOW s s .wu hI h0 hs
          (by have := entry_nonidle hI h0 hs; cases ht : s.state <;> simp_all [ofSt, strmOK])
      · apply sgood_put_ok c f.sid _ [] .wu c hI h0 (hI.keys _ _ hs) rfl
        · exact entry_nonidle (s := s) hI h0 hs
        · intro hc; exact hI.srv hc _ s hs
        · intro hr; have := hI.rbu _ hr; rw [abs_some hs] at this
          cases ht : s.state <;> simp_all [ofSt]
        · rfl
        · rw [abs_some hs]; exact okPost_wu _ _ _ (entry_nonidle (s := s) hI h0 hs)
        · simp
        · simp
        · simp

/-! ## RST_STREAM -/

theorem sgood_rstH (c : Conn) (f : Fr) (hI : Inv c) (hg : c.goawaySent = false) (h0 : c.continuing = 0)
    (hni : abs c f.sid ≠ .idle) : SGood c f.sid .rst (rstH c f) := by
  unfold rstH rstFlood
  have hgs : (closeIfKnown c f.sid).goawaySent = c.goawaySent := by
    unfold closeIfKnown; split <;> rfl
  split
  · rename_i h
    unfold SGood SGoodV
    simp only [verdict, gaCode]; simp [connAny, eCALM]
  · have hpost : abs (closeIfKnown c f.sid) f.sid = .closed := by
      rw [abs_closeIfKnown]
      cases hgk : get c f.sid with
      | some s => simp
      | none => simp only [Option.isSome_none, Bool.false_eq_true, and_false, if_false]
                rw [abs_none hgk] at hni ⊢; split <;> simp_all
    have hinv : Inv (closeIfKnown c f.sid) := by
      unfold closeIfKnown
      cases hgk : get c f.sid with
      | some s =>
        exact inv_put0 c _ _ hI (hI.keys _ _ hgk) h0 (by simp) (by simp) (fun _ => rfl)
      | none => exact hI
    unfold SGood SGoodV
    simp only [verdict, gaCode, rsCode]
    have hiv : iv { closeIfKnown c f.sid with rstCount := (closeIfKnown c f.sid).rstCount + 1 } =
      iv (closeIfKnown c f.sid) := rfl
    rw [abs_congr hiv]
    refine ⟨?_, ?_, sends_nil _ _, inv_congr hiv hinv⟩
    · rw [hpost]; simp only [recvOK]
      cases h : abs c f.sid <;> simp_all [okPost]
    · intro j hj; left; rw [abs_closeIfKnown]; simp [hj]

/-! ## DATA -/

theorem sgood_congr {c : Conn} {k : Nat} {rk : RK} {r r' : Conn × List Out} (hiv : iv r'.1 = iv r.1)
    (ho : r'.2 = r.2) (h : SGood c k rk r) : SGood c k rk r' := by
  unfold SGood at *
  rw [ho]
  generalize verdict r.2 k = v at h ⊢
  unfold SGoodV at *
  rw [abs_congr hiv]
  cases v
  all_goals first
    | exact h
    | (obtain ⟨a, b, ⟨d, e, g⟩, i⟩ := h
       exact ⟨a, b, ⟨fun j n hj h0 => by rw [abs_congr hiv]; exact d j n (ho ▸ hj) h0,
         fun j e' hj => e j e' (ho ▸ hj), fun j n hj => g j n (ho ▸ hj)⟩, inv_congr hiv i⟩)

theorem rstCloseX_congr (c c' : Conn) (k code : Nat) (s : Stream) (x : List Out) (hiv : iv c' = iv c) :
    iv (rstCloseX c' k code s x).1 = iv (rstCloseX c k code s x).1 ∧
    (rstCloseX c' k code s x).2 = (rstCloseX c k code s x).2 := by
  simp only [iv, IV.mk.injEq] at hiv
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := hiv
  refine ⟨?_, rfl⟩
  simp only [rstCloseX, iv, put, rstC, IV.mk.injEq]
  exact ⟨by rw [h1], h2, h3, h4, h5, h6, by rw [h7], h8⟩

theorem dataCredit_iv (c : Conn) (f : Fr) (cr : Nat) : iv (dataCredit c f cr).1 = iv c := by
  unfold dataCredit; simp only []; split <;> (try split) <;> (try split) <;> rfl

theorem dataCredit_out (c : Conn) (f : Fr) (cr : Nat) :
    ∀ o ∈ (dataCredit c f cr).2, (o = .wu f.sid cr ∧ cr > 0) ∨ ∃ n, o = .wu 0 n := by
  intro o ho
  unfold dataCredit at ho
  simp only [] at ho
  split at ho
  · split at ho
    · simp only at ho; split at ho
      · simp at ho; left; exact ⟨ho, by omega⟩
      · simp at ho
    · simp only [List.mem_append] at ho
      rcases ho with ho | ho
      · split at ho
        · simp at ho; left; exact ⟨ho, by omega⟩
        · simp at ho
      · simp at ho; right; exact ⟨_, ho⟩
  · simp at ho

theorem okPost_data (b r : Bool) (cl es : Bool) (t : St) (ht : t = .open_ ∨ t = .hcl)
    (hsrv : cl = false → t ≠ .hcl) :
    okPost b r (ofSt t) (.data es)
      (ofSt (if es then (if (cl && t == .hcl) = true then St.closed else St.hcr) else t)) = true := by
  rcases ht with rfl | rfl <;> cases es <;> cases cl <;> simp_all [ofSt, okPost, esTo]

theorem sgood_finish (c c1 : Conn) (f : Fr) (s s4 : Stream) (cr' : Nat) (hI : Inv c) (h0 : c.continuing = 0)
    (hs : get c f.sid = some s) (hst : s.state = .open_ ∨ s.state = .hcl) (hr : f.sid ∉ c.resetByUs)
    (hiv1 : iv c1 = iv c)
    (hst4 : s4.state = (if f.f1 then (if (c1.isClient && s.state == .hcl) = true then St.closed else St.hcr)
        else s.state))
    (hcr : cr' > 0 → ¬ (f.f1 = true ∧ c1.isClient = true ∧ s.state = .hcl)) :
    SGood c f.sid (.data f.f1) (dataCredit (put c1 f.sid s4) f cr') := by
  have hc1cl : c1.isClient = c.isClient := by
    have := congrArg IV.isClient hiv1; simpa [iv] using this
  rw [hc1cl] at hst4 hcr
  have hsrv : c.isClient = false → s.state ≠ .hcl := fun hc => hI.srv hc _ _ hs
  have hivr : iv (dataCredit (put c1 f.sid s4) f cr').1 = iv (put c f.sid s4) := by
    rw [dataCredit_iv]
    simp only [iv, put, IV.mk.injEq] at hiv1 ⊢
    obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := hiv1
    exact ⟨by rw [h1], h2, h3, h4, h5, h6, h7, h8⟩
  apply sgood_congr (r := (put c f.sid s4, (dataCredit (put c1 f.sid s4) f cr').2)) hivr rfl
  have hout := dataCredit_out (put c1 f.sid s4) f cr'
  apply sgood_put_ok c f.sid s4 _ (.data f.f1) c hI h0 (hI.keys _ _ hs) rfl
  · rw [hst4]; rcases hst with h | h <;> split <;> simp_all
  · intro hc; rw [hst4]; have := hsrv hc; split <;> simp_all
  · intro h; exact absurd h hr
  · have hga : gaCode (dataCredit (put c1 f.sid s4) f cr').2 = none := by
      generalize (dataCredit (put c1 f.sid s4) f cr').2 = o at hout
      induction o with
      | nil => rfl
      | cons x t ih =>
        rcases hout x (List.mem_cons_self ..) with ⟨rfl, -⟩ | ⟨n, rfl⟩ <;>
          simp [gaCode, ih (fun o ho => hout o (List.mem_cons_of_mem _ ho))]
    have hrs : rsCode f.sid (dataCredit (put c1 f.sid s4) f cr').2 = none := by
      generalize (dataCredit (put c1 f.sid s4) f cr').2 = o at hout
      induction o with
      | nil => rfl
      | cons x t ih =>
        rcases hout x (List.mem_cons_self ..) with ⟨rfl, -⟩ | ⟨n, rfl⟩ <;>
          simp [rsCode, ih (fun o ho => hout o (List.mem_cons_of_mem _ ho))]
    simp [verdict, hga, hrs]
  · rw [abs_some hs, hst4]; exact okPost_data _ _ _ _ _ hst hsrv
  · intro j n hj hj0
    rcases hout _ hj with ⟨he, hpos⟩ | ⟨m, hm⟩
    · cases he
      refine ⟨rfl, ?_⟩
      rw [hst4]
      have := hcr hpos
      rcases hst with h | h <;> cases hf : f.f1 <;> cases hcc : c.isClient <;>
        simp_all [ofSt, wuOK, sendPost]
    · cases hm; exact absurd rfl hj0
  · intro j e hj; rcases hout _ hj with ⟨he, -⟩ | ⟨m, hm⟩
    · cases he
    · cases hm
  · intro j e hj; rcases hout _ hj with ⟨he, -⟩ | ⟨m, hm⟩
    · cases he
    · cases hm

theorem sgood_dataBody (c : Conn) (f : Fr) (s : Stream) (body : Nat) (hI : Inv c) (h0 : c.continuing = 0)
    (hs : get c f.sid = some s) (hst : s.state = .open_ ∨ s.state = .hcl) (hr : f.sid ∉ c.resetByUs) :
    SGood c f.sid (.data f.f1) (dataBody F c f { s with recvW := s.recvW - f.plen } body) := by
  have hrk : strmOK (ofSt s.state) (.data f.f1) = true := by rcases hst with h | h <;> simp [h, ofSt, strmOK]
  have hsrv : c.isClient = false → s.state ≠ .hcl := fun hc => hI.srv hc _ _ hs
  unfold dataBody
  split
  · exact sgood_rstCloseX c _ _ s _ _ _ hI h0 hs hrk (by simp [F])
  split
  · exact sgood_rstCloseX c _ _ s _ _ _ hI h0 hs hrk (wu0If_shape _)
  split
  · exact sgood_rstCloseX c _ _ s _ _ _ hI h0 hs hrk (wu0If_shape _)
  unfold dataAccept
  split
  · exact sgood_rstCloseX c _ _ s _ _ _ hI h0 hs hrk (wu0If_shape _)
  unfold dataFinish
  have hiv1 : iv (if (!c.isClient) = true then { c with buffered := c.buffered + body } else c) = iv c := by
    split <;> rfl
  split
  · obtain ⟨e1, e2⟩ := rstCloseX_congr c _ f.sid ePROTOCOL _ _ hiv1
    exact sgood_congr e1 e2 (sgood_rstCloseX c f.sid ePROTOCOL s _ _ _ hI h0 hs hrk (by simp [F]))
  · exact sgood_finish c _ f s _ _ hI h0 hs hst hr hiv1 (by split <;> rfl)
      (by intro hpos hcon; obtain ⟨a, b, d⟩ := hcon
          have hb : c.isClient = true := by revert b; split <;> simp
          rw [if_pos (by simp [F, a, hb, d])] at hpos; exact Nat.lt_irrefl 0 hpos)

theorem sgood_dataH (c : Conn) (f : Fr) (hI : Inv c) (hg : c.goawaySent = false) (h0 : c.continuing = 0)
    (hk : f.sid ≠ 0) : SGood c f.sid (.data f.f1) (dataH F c f) := by
  unfold dataH
  simp only [isIdleId_F]
  split
  · rename_i hr
    have hcl := hI.rbu _ hr
    apply sgood_keep c _ _ _ c hI rfl
    · rw [verdict, gaCode_wu0 _ (wu0If_shape _), rsCode_wu0 _ _ (wu0If_shape _)]
    · rw [hcl]; simp [okPost]
    · intro j n hj; obtain ⟨m, hm⟩ := wu0If_shape _ _ hj; cases hm; rfl
    · intro j e hj; obtain ⟨m, hm⟩ := wu0If_shape _ _ hj; cases hm
    · intro j n hj; obtain ⟨m, hm⟩ := wu0If_shape _ _ hj; cases hm
  · rename_i hr
    split
    · rename_i hnone
      split
      · rename_i hi
        apply sgood_conn c _ _ _ hg; rw [abs_none hnone, hi]; simp [connCodes]
      · rename_i hi
        apply sgood_conn c _ _ _ hg; rw [abs_none hnone]; simp [hi, connCodes]
    · rename_i s hs
      have hni := entry_nonidle hI h0 hs
      split
      · rename_i hcl
        apply sgood_conn c _ _ _ hg
        rw [abs_some hs]
        simp only [F, Bool.true_and, Bool.or_eq_true, beq_iff_eq] at hcl
        rcases hcl with h | h <;> simp [h, ofSt, connCodes]
      · rename_i hcl
        simp only [F, Bool.true_and, Bool.or_eq_true, beq_iff_eq, not_or] at hcl
        have hst : s.state = .open_ ∨ s.state = .hcl := by
          cases ht : s.state <;> simp_all
        have hconn : ∀ e, (connAny e || connCodes (pid c f.sid) (abs c f.sid) (.data f.f1) e) = true := by
          intro e; rw [abs_some hs]; rcases hst with h | h <;> simp [h, ofSt, connCodes]
        split
        · exact sgood_conn c _ _ _ hg (hconn _)
        split
        · exact sgood_conn c _ _ _ hg (hconn _)
        split
        · exact sgood_conn c _ _ _ hg (hconn _)
        · exact sgood_dataBody c f s _ hI h0 hs hst hr
