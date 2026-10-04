import Flare.L3_Protocol.H2.RefineData

/-!
# §5.1 refinement: header blocks

HEADERS (single-frame or opening a block), CONTINUATION, and the commit
of a completed block (`_commit_header_block`), for the fixed model `F`.
A block that spans frames is one HEADERS for the spec: `hdrBegin` leaves
the stream as it was (or, for a new stream that is refused, closed), and
the CONTINUATION with END_HEADERS performs the transition (`hdrEnd`).
-/
namespace Flare.L3.H2.Refine
open Flare.L3.H2.Conn Flare.L3.H2.StreamSpec

attribute [local simp] ePROTOCOL eSTREAM_CLOSED eFLOW eCALM eCOMPRESSION eFRAME_SIZE eREFUSED eNO

theorem abs_cont (c : Conn) (k : Nat) : abs { c with continuing := k } = abs c := rfl

theorem abs_ne_resL (c : Conn) (k : Nat) : abs c k ≠ .resL := by
  unfold abs; split
  · exact ofSt_ne_resL _
  · split <;> simp

/-- The invariant of a state with a block open on `k`, seen with the
block closed: idle entries may only sit at `k`. -/
theorem inv_put_pending (c : Conn) (k : Nat) (s : Stream) (hP : Inv { c with continuing := k })
    (h0 : c.continuing = 0) (hk : keyOK c k) (hni : s.state ≠ .idle)
    (hsrv : c.isClient = false → s.state ≠ .hcl) (hrbu : k ∈ c.resetByUs → s.state = .closed) :
    Inv (put c k s) := by
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hP
  refine ⟨nodupK_putL _ _ _ nd, ?_, ?_, ?_, ?_, ?_, cliRef, ?_, ga⟩
  · intro j t h; rw [get_put] at h; split at h
    · rename_i hj; subst hj; exact hk
    · exact keys j t h
  · intro j t h he; rw [get_put] at h; split at h
    · cases h; exact absurd he hni
    · rename_i hj; exact absurd (idle j t h he).1.symm hj
  · intro hc j t h; rw [get_put] at h; split at h
    · cases h; exact hsrv hc
    · exact srv hc j t h
  · intro a; exact absurd h0 a
  · intro a; exact absurd h0 a
  · intro j hj; rw [abs_put]; split
    · rename_i h; subst h; rw [hrbu hj]; rfl
    · exact rbu j hj

theorem inv_rstClose_pending (c : Conn) (k : Nat) (s : Stream) (hP : Inv { c with continuing := k })
    (h0 : c.continuing = 0) (hk : keyOK c k) :
    Inv (put (rstC c k) k { s with state := .closed }) := by
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hP
  refine ⟨nodupK_putL _ _ _ nd, ?_, ?_, ?_, ?_, ?_, cliRef, ?_, ga⟩
  · intro j t h; rw [get_put] at h; split at h
    · rename_i hj; subst hj; exact hk
    · exact keys j t h
  · intro j t h he; rw [get_put] at h; split at h
    · cases h; cases he
    · rename_i hj; exact absurd (idle j t h he).1.symm hj
  · intro hc j t h; rw [get_put] at h; split at h
    · cases h; simp
    · exact srv hc j t h
  · intro a; exact absurd h0 a
  · intro a; exact absurd h0 a
  · intro j hj
    rcases rstC_rbu c k j hj with hj | hj
    · rw [abs_put]; split
      · rfl
      · rw [abs_rstC]; exact rbu j hj
    · subst hj; rw [abs_put_self]; rfl

/-! ## Completing a block -/

/-- What completing a block on `k` (END_STREAM flag `es`) may produce. -/
def CGoodV (c : Conn) (k : Nat) (es : Bool) (v : V) (r : Conn × List Out) : Prop :=
  match v with
  | .conn e => connAny e = true
  | .strm _ => abs r.1 k = .closed ∧ (∀ j, j ≠ k → abs r.1 j = abs c j) ∧ Sends k r ∧ Inv r.1
  | .ok => (∃ s, get c k = some s ∧ okPost true true (ofSt s.state) (.hdrEnd es) (abs r.1 k) = true) ∧
      (∀ j, j ≠ k → abs r.1 j = abs c j) ∧ Sends k r ∧ Inv r.1

def CGood (c : Conn) (k : Nat) (es : Bool) (r : Conn × List Out) : Prop :=
  CGoodV c k es (verdict r.2 k) r

theorem cgood_rstClose (c c1 : Conn) (k code : Nat) (s : Stream) (es : Bool)
    (hP : Inv { c with continuing := k }) (h0 : c.continuing = 0) (hk : keyOK c k)
    (hiv : iv c1 = iv c) :
    CGood c k es (rstClose c1 k code s) := by
  unfold CGood CGoodV rstClose rstCloseX
  have hv : verdict [Out.rst k code] k = .strm code := by simp [verdict, gaCode, rsCode]
  simp only [hv]
  have hivp : iv (put (rstC c1 k) k { s with state := .closed }) = iv (put (rstC c k) k { s with state := .closed }) := by
    simp only [iv, IV.mk.injEq] at hiv
    obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := hiv
    simp only [iv, put, rstC, IV.mk.injEq]
    exact ⟨by rw [h1], h2, h3, h4, h5, h6, by rw [h7], h8⟩
  rw [abs_congr hivp]
  have hinv := inv_rstClose_pending c k s hP h0 hk
  refine ⟨by rw [abs_put_self]; rfl, fun j hj => by rw [abs_put_other _ _ _ _ hj, abs_rstC], ⟨?_, ?_, ?_⟩,
    inv_congr hivp hinv⟩
  · intro j n hj; simp at hj
  · intro j e hj; simp at hj; exact hj.1
  · intro j n hj; simp at hj

theorem cgood_put (c c1 : Conn) (k : Nat) (s0 s : Stream) (es : Bool)
    (hP : Inv { c with continuing := k }) (h0 : c.continuing = 0) (hk : keyOK c k)
    (hiv : iv c1 = iv c) (hs0 : get c k = some s0)
    (hni : s.state ≠ .idle) (hsrv : c.isClient = false → s.state ≠ .hcl) (hnr : k ∉ c.resetByUs)
    (hpost : okPost true true (ofSt s0.state) (.hdrEnd es) (ofSt s.state) = true) :
    CGood c k es (put c1 k s, []) := by
  unfold CGood CGoodV
  have hv : verdict [] k = .ok := rfl
  simp only [hv]
  have hivp : iv (put c1 k s) = iv (put c k s) := by
    simp only [iv, IV.mk.injEq] at hiv
    obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := hiv
    simp only [iv, put, IV.mk.injEq]
    exact ⟨by rw [h1], h2, h3, h4, h5, h6, h7, h8⟩
  rw [abs_congr hivp]
  have hinv := inv_put_pending c k s hP h0 hk hni hsrv (fun h => absurd h hnr)
  refine ⟨⟨s0, hs0, by rw [abs_put_self]; exact hpost⟩, fun j hj => abs_put_other _ _ _ _ hj, sends_nil _ _,
    inv_congr hivp hinv⟩

theorem clientCheck_info (hs : List Validate.Header) (isTr es ba : Bool) (h : clientCheck hs isTr es ba = .info) :
    es = false := by
  unfold clientCheck at h
  simp only at h
  repeat' split at h
  all_goals (cases es <;> simp_all)

theorem okPost_hdrEnd (t : St) (es : Bool) (ht : t = .idle ∨ t = .open_ ∨ t = .hcl) (cl : Bool)
    (hcl : cl = true → t ≠ .idle) (hsrv : cl = false → t ≠ .hcl) :
    okPost true true (ofSt t) (.hdrEnd es)
      (ofSt (if es then (if (cl && t == .hcl) = true then St.closed else St.hcr)
        else (if (cl && t == .hcl) = true then t else St.open_))) = true := by
  rcases ht with rfl | rfl | rfl <;> cases es <;> cases cl <;> simp_all [ofSt, okPost, esTo]

theorem cgood_tail_gen (c c1 : Conn) (k : Nat) (s0 s : Stream) (es b : Bool)
    (hP : Inv { c with continuing := k }) (h0 : c.continuing = 0) (hk : keyOK c k)
    (hiv : iv c1 = iv c) (hs0 : get c k = some s0) (hst : s.state = s0.state)
    (h3 : s0.state = .idle ∨ s0.state = .open_ ∨ s0.state = .hcl)
    (hcli : c.isClient = true → s0.state ≠ .idle) (hsrv : c.isClient = false → s0.state ≠ .hcl)
    (hnr : k ∉ c.resetByUs) :
    CGood c k es (if es = true then
        (if b = true then rstClose c1 k ePROTOCOL s
         else (put c1 k { s with dataComplete := true, state := if (c.isClient && s.state == St.hcl) = true then St.closed else St.hcr }, []))
      else (put c1 k { s with state := if (c.isClient && s.state == St.hcl) = true then s.state else St.open_ }, [])) := by
  have hpost := okPost_hdrEnd s0.state es h3 c.isClient hcli hsrv
  cases es
  · simp only [Bool.false_eq_true, if_false] at hpost ⊢
    apply cgood_put c c1 k s0 _ false hP h0 hk hiv hs0
    · simp only; rw [hst]; split
      · rename_i h; simp at h; rw [h.2]; simp
      · simp
    · intro hc; simp only; rw [hst]; have := hsrv hc; split <;> simp_all
    · exact hnr
    · simp only; rw [hst]; exact hpost
  · simp only [if_true] at hpost ⊢
    split
    · exact cgood_rstClose c c1 k _ _ true hP h0 hk hiv
    · apply cgood_put c c1 k s0 _ true hP h0 hk hiv hs0
      · simp only; split <;> simp
      · intro hc; simp only; rw [hst]; have := hsrv hc; split <;> simp_all
      · exact hnr
      · simp only; rw [hst]; exact hpost

theorem cgood_commitTail (c c1 : Conn) (k : Nat) (s0 s : Stream) (isTr es : Bool) (hdrs : List Validate.Header)
    (hP : Inv { c with continuing := k }) (h0 : c.continuing = 0) (hk : keyOK c k)
    (hiv : iv c1 = iv c) (hs0 : get c k = some s0) (hst : s.state = s0.state)
    (h3 : s0.state = .idle ∨ s0.state = .open_ ∨ s0.state = .hcl)
    (hcli : c.isClient = true → s0.state ≠ .idle) (hsrv : c.isClient = false → s0.state ≠ .hcl)
    (hnr : k ∉ c.resetByUs) :
    CGood c k es (commitTail F c1 k s isTr es hdrs) := by
  have hcl1 : c1.isClient = c.isClient := by have := congrArg IV.isClient hiv; simpa [iv] using this
  unfold commitTail
  simp only [F, Bool.false_eq_true, false_and, Bool.false_and, if_false, hcl1]
  exact cgood_tail_gen c c1 k s0 _ es _ hP h0 hk hiv hs0 hst h3 hcli hsrv hnr

theorem cgood_commit (dec : Dec) (c : Conn) (k : Nat) (hP : Inv { c with continuing := k })
    (h0 : c.continuing = 0) (hk0 : k ≠ 0) (hg : c.goawaySent = false) :
    CGood c k c.blockES (commit F dec c k) := by
  unfold commit
  simp only []
  split
  · unfold CGood CGoodV connErr; simp [hg, verdict, gaCode, connAny]
  · unfold CGood CGoodV connErr; simp [hg, verdict, gaCode, connAny]
  · rename_i hdrs _
    split
    · rename_i hrf
      unfold CGood CGoodV
      have hv : verdict [Out.rst k c.blockRefuse] k = .strm c.blockRefuse := by simp [verdict, gaCode, rsCode]
      simp only [hv]
      have hb1 := hP.blk1 (by simpa using hk0) hrf
      rw [abs_cont] at hb1
      have hc0 : Inv { c with blockRefuse := 0 } := by
        obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hP
        refine ⟨nd, keys, ?_, srv, ?_, ?_, fun _ => rfl, rbu, ga⟩
        · intro j t h he; exact absurd (idle j t h he).2.2 hrf
        · intro a; exact absurd h0 a
        · intro a; exact absurd h0 a
      generalize hc' : ({ c with block := [], blockES := false, decLog := c.decLog ++ [c.block], blockRefuse := 0 } : Conn) = c'
      have hiv : iv c' = iv { c with blockRefuse := 0 } := by rw [← hc']; rfl
      have hab : abs c' = abs c := by rw [abs_congr hiv]; rfl
      have hknown : (∃ s, get c' k = some s) ∨ abs c' k = .closed := by
        rw [hab]
        rcases hb1 with h | h
        · exact Or.inr h
        · left; unfold abs at h
          cases hg' : get c k with
          | some s => exact ⟨s, by rw [get_congr (congrArg IV.streams hiv)]; exact hg'⟩
          | none => rw [hg'] at h; simp only at h; split at h <;> cases h
      refine ⟨?_, ?_, ⟨?_, ?_, ?_⟩, inv_closeRst c' k (inv_congr hiv hc0) (by rw [← hc']; exact h0) hknown⟩
      · rw [abs_closeRst]
        simp only [true_and]
        split
        · rfl
        · rcases hknown with ⟨s, hs⟩ | h
          · rename_i hn; rw [hs] at hn; simp at hn
          · exact h
      · intro j hj; rw [abs_closeRst]; simp [hj, hab]
      · intro j n hj; simp at hj
      · intro j e hj; simp at hj; exact hj.1
      · intro j n hj; simp at hj
    · rename_i hrf
      simp only [Decidable.not_not] at hrf
      obtain ⟨s0, hs0, h3⟩ := hP.blk0 (by simpa using hk0) hrf
      have hk : keyOK c k := hP.keys _ _ hs0
      have hs0' : get c k = some s0 := hs0
      have hnr : k ∉ c.resetByUs := by
        intro hr; have h2 : abs c k = .closed := hP.rbu k hr; rw [abs_some hs0'] at h2
        have this := h2
        rcases h3 with h | h | h <;> simp [h, ofSt] at this
      have hcli : c.isClient = true → s0.state ≠ .idle := by
        intro hc he; have := (hP.idle _ _ hs0 he).2.1; simp_all
      have hsrv : c.isClient = false → s0.state ≠ .hcl := fun hc => hP.srv hc _ _ hs0
      have hs0 : get c k = some s0 := hs0
      generalize hc' : ({ c with block := [], blockES := false, decLog := c.decLog ++ [c.block], blockRefuse := 0 } : Conn) = c'
      have hiv : iv c' = iv c := by rw [← hc']; simp only [iv, hrf]
      have hg' : get c' k = some s0 := by rw [get_congr (congrArg IV.streams hiv)]; exact hs0
      have hens : ensure c' k = (c', s0) := ensure_snd_get _ _ _ hg'
      simp only [hens]
      have hcl' : c'.isClient = c.isClient := by rw [← hc']
      split
      · exact cgood_rstClose c c' k _ _ _ hP h0 hk hiv
      · split
        · split
          · exact cgood_rstClose c c' k _ _ _ hP h0 hk hiv
          · exact cgood_commitTail c c' k s0 _ _ _ hdrs hP h0 hk hiv hs0 rfl h3 hcli hsrv hnr
        · split
          · exact cgood_rstClose c c' k _ _ _ hP h0 hk hiv
          · rename_i hinfo
            have hes := clientCheck_info _ _ _ _ hinfo
            rename_i hcl _
            simp only [Bool.not_eq_true'] at hcl
            simp only [Bool.not_eq_false] at hcl
            apply cgood_put c c' k s0 _ _ hP h0 hk hiv hs0
            · exact hcli (by rw [← hcl']; simpa using hcl)
            · intro hc; rw [← hcl'] at hc; simp_all
            · exact hnr
            · rw [hes]
              rcases h3 with h | h | h
              · exact absurd h (hcli (by rw [← hcl']; simpa using hcl))
              · simp [h, ofSt, okPost, esTo]
              · simp [h, ofSt, okPost, esTo]
          · exact cgood_commitTail c c' k s0 _ _ _ hdrs hP h0 hk hiv hs0 rfl h3 hcli hsrv hnr

/-! ## From a completed block to the spec obligation -/

theorem okPost_hdrEnd_any (b r b' r' : Bool) (t : SS) (es : Bool) (s' : SS) :
    okPost b r t (.hdrEnd es) s' = okPost b' r' t (.hdrEnd es) s' := by
  cases t <;> rfl

theorem okPost_hdr_hdrEnd (b r : Bool) (t : St) (ht : t = .open_ ∨ t = .hcl) (es : Bool) (s' : SS) :
    okPost b r (ofSt t) (.hdr es) s' = okPost true true (ofSt t) (.hdrEnd es) s' := by
  rcases ht with rfl | rfl <;> rfl

theorem cgood_sgood (c c' : Conn) (k : Nat) (es : Bool) (rk : RK) (r : Conn × List Out)
    (hc : CGood c' k es r) (hk : abs c' k = abs c k) (hoth : Others (abs c) (abs c') k)
    (hstr : strmOK (abs c k) rk = true)
    (hok : ∀ s s', get c' k = some s → okPost true true (ofSt s.state) (.hdrEnd es) s' = true →
      okPost (pid c k) (room c) (abs c k) rk s' = true) :
    SGood c k rk r := by
  unfold CGood at hc; unfold SGood
  generalize verdict r.2 k = v at hc ⊢
  cases v with
  | conn e => unfold CGoodV at hc; unfold SGoodV; simp [hc]
  | strm e =>
    unfold CGoodV at hc; unfold SGoodV
    obtain ⟨h1, h2, h3, h4⟩ := hc
    refine ⟨?_, others_trans hoth h2, h3, h4⟩
    simp [recvOK, hstr, h1]
  | ok =>
    unfold CGoodV at hc; unfold SGoodV
    obtain ⟨⟨s, hs, hp⟩, h2, h3, h4⟩ := hc
    exact ⟨by simp only [recvOK]; exact hok s _ hs hp, others_trans hoth h2, h3, h4⟩

/-! ## Opening a block -/

theorem inv_setRefuse (c : Conn) (rf : Nat) (hI : Inv c) (h0 : c.continuing = 0)
    (hcl : c.isClient = true → rf = 0) : Inv { c with blockRefuse := rf } := by
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
  refine ⟨nd, keys, ?_, srv, ?_, ?_, hcl, rbu, ga⟩
  · intro j t h he
    have := (idle j t h he).1; have hk := (keys j t h).1; simp only at *; omega
  · intro a; exact absurd h0 a
  · intro a; exact absurd h0 a

/-- Opening a block on `k` whose stream is (now) in the table. -/
theorem inv_begin0 (X : Conn) (k : Nat) (s : Stream) (hI : Inv X) (h0 : X.continuing = 0)
    (hr0 : X.blockRefuse = 0) (hk : keyOK X k)
    (hcase : (get X k = some s ∧ (s.state = .open_ ∨ s.state = .hcl)) ∨
      (get X k = none ∧ s.state = .idle ∧ X.isClient = false ∧ k ∉ X.resetByUs)) :
    Inv { put X k s with continuing := k } := by
  have hk0 : k ≠ 0 := by unfold keyOK at hk; omega
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
  refine ⟨nodupK_putL _ _ _ nd, ?_, ?_, ?_, ?_, ?_, cliRef, ?_, ga⟩
  · intro j t h; show keyOK X j
    have h' : get (put X k s) j = some t := h
    rw [get_put] at h'; split at h'
    · rename_i hj; subst hj; exact hk
    · exact keys j t h'
  · intro j t h he
    have h' : get (put X k s) j = some t := h
    rw [get_put] at h'; split at h'
    · rename_i hj; subst hj; cases h'
      rcases hcase with ⟨_, h | h⟩ | ⟨_, _, hc⟩
      · rw [h] at he; cases he
      · rw [h] at he; cases he
      · exact ⟨rfl, hc.1, hr0⟩
    · have := (idle j t h' he).1; have hj := (keys j t h').1; omega
  · intro hc j t h
    have h' : get (put X k s) j = some t := h
    rw [get_put] at h'; split at h'
    · cases h'
      rcases hcase with ⟨hg, h | h⟩ | ⟨_, h, _⟩
      · rw [h]; simp
      · exact srv hc k s hg
      · rw [h]; simp
    · exact srv hc j t h'
  · intro _ _
    show ∃ t, get (put X k s) k = some t ∧ _
    rw [get_put]; simp only [if_true]
    refine ⟨s, rfl, ?_⟩
    rcases hcase with ⟨_, h | h⟩ | ⟨_, h, _⟩ <;> simp [h]
  · intro _ b; exact absurd hr0 b
  · intro j hj
    show abs (put X k s) j = .closed
    rw [abs_put]; split
    · rename_i h; subst h
      have := rbu j hj
      rcases hcase with ⟨hg, h | h⟩ | ⟨hg, _, _, hn⟩
      · rw [abs_some hg, h] at this; cases this
      · rw [abs_some hg, h] at this; cases this
      · exact absurd hj hn
    · exact rbu j hj

/-- Opening a refused block on `k`. -/
theorem inv_beginR (X : Conn) (k : Nat) (hI : Inv X) (h0 : X.continuing = 0) (hr : X.blockRefuse ≠ 0)
    (hk0 : k ≠ 0) (ha : abs X k = .closed ∨ abs X k = .open_) :
    Inv { X with continuing := k } := by
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
  refine ⟨nd, keys, ?_, srv, ?_, ?_, cliRef, rbu, ga⟩
  · intro j t h he; exact absurd (idle j t h he).2.2 hr
  · intro _ b; exact absurd b hr
  · intro _ _; exact ha

theorem ensure_none (c : Conn) (k : Nat) (hI : Inv c) (h : get c k = none) :
    get (ensure c k).1 k = none ∧ (ensure c k).2.state = .idle := by
  unfold ensure; rw [h]; simp only
  split
  · refine ⟨?_, trivial⟩
    rw [get_filter c _ k hI.nd, h]
  · exact ⟨h, trivial⟩

theorem ensure_fields (c : Conn) (k : Nat) :
    (ensure c k).1.isClient = c.isClient ∧ (ensure c k).1.lastPeer = c.lastPeer ∧
    (ensure c k).1.maxLocalSid = c.maxLocalSid ∧ (ensure c k).1.continuing = c.continuing ∧
    (ensure c k).1.blockRefuse = c.blockRefuse ∧ (ensure c k).1.blockES = c.blockES ∧
    (ensure c k).1.goawaySent = c.goawaySent ∧ (ensure c k).1.resetByUs = c.resetByUs := by
  unfold ensure; split
  · simp
  · split <;> simp

theorem sgood_begin (c0 Y : Conn) (k : Nat) (hP : Inv { Y with continuing := k })
    (hpost : okPost (pid c0 k) (room c0) (abs c0 k) .hdrBegin (abs Y k) = true)
    (hoth : Others (abs c0) (abs Y) k) :
    SGood c0 k .hdrBegin ({ Y with continuing := k }, []) := by
  unfold SGood SGoodV
  have hv : verdict [] k = .ok := rfl
  simp only [hv]
  exact ⟨by simp only [recvOK]; exact hpost, hoth, sends_nil _ _, hP⟩

theorem sgood_hdr_commit (dec : Dec) (c0 Y : Conn) (k : Nat) (es : Bool) (hP : Inv { Y with continuing := k })
    (h0 : Y.continuing = 0) (hk0 : k ≠ 0) (hg : Y.goawaySent = false) (hes : Y.blockES = es)
    (hk : abs Y k = abs c0 k) (hoth : Others (abs c0) (abs Y) k)
    (hstr : strmOK (abs c0 k) (.hdr es) = true)
    (hok : ∀ s s', get Y k = some s → okPost true true (ofSt s.state) (.hdrEnd es) s' = true →
      okPost (pid c0 k) (room c0) (abs c0 k) (.hdr es) s' = true) :
    SGood c0 k (.hdr es) (commit F dec Y k) := by
  have := cgood_commit dec Y k hP h0 hk0 hg
  rw [hes] at this
  exact cgood_sgood c0 Y k es _ _ this hk hoth hstr hok

theorem sgood_headersOpen (dec : Dec) (c0 c1 : Conn) (f : Fr) (refuse : Nat)
    (hI1 : Inv c1) (h01 : c1.continuing = 0) (hg1 : c1.goawaySent = false) (hk : keyOK c1 f.sid)
    (hoth : Others (abs c0) (abs c1) f.sid)
    (hcli : c1.isClient = true → refuse = 0)
    (hcase : (∃ p, get c1 f.sid = some p ∧ (p.state = .open_ ∨ p.state = .hcl) ∧
        abs c0 f.sid = ofSt p.state ∧ (refuse ≠ 0 → p.state = .open_)) ∨
      (get c1 f.sid = none ∧ abs c0 f.sid = .idle ∧ pid c0 f.sid = true ∧ c1.isClient = false ∧
        f.sid ∉ c1.resetByUs ∧ (refuse = 0 → room c0 = true))) :
    SGood c0 f.sid (if f.eh then .hdr f.f1 else .hdrBegin) (headersOpen F dec c1 f refuse) := by
  have hk0 : f.sid ≠ 0 := by unfold keyOK at hk; omega
  have hI2 : Inv { c1 with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } :=
    inv_congr (c := { c1 with blockRefuse := refuse }) rfl (inv_setRefuse c1 refuse hI1 h01 hcli)
  unfold headersOpen
  simp only []
  generalize hc2 : ({ c1 with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } : Conn) = c2 at hI2
  have hiv2 : iv c2 = iv { c1 with blockRefuse := refuse } := by rw [← hc2]; rfl
  have hab2 : abs c2 = abs c1 := by rw [abs_congr hiv2]; rfl
  have hg2 : c2.goawaySent = false := by rw [← hc2]; exact hg1
  have hes2 : c2.blockES = f.f1 := by rw [← hc2]
  have hr2 : c2.blockRefuse = refuse := by rw [← hc2]
  have hc02 : c2.continuing = 0 := by rw [← hc2]; exact h01
  have hcl2 : c2.isClient = c1.isClient := by rw [← hc2]
  have hget2 : get c2 = get c1 := by rw [← hc2]; rfl
  have hk2 : keyOK c2 f.sid := by unfold keyOK at hk ⊢; rw [← hc2]; exact hk
  have hrbu2 : c2.resetByUs = c1.resetByUs := by rw [← hc2]
  have hoth2 : Others (abs c0) (abs c2) f.sid := by rw [hab2]; exact hoth
  by_cases hr : refuse = 0
  · rw [if_pos hr]
    rcases hcase with ⟨p, hp, hst, ha0, _⟩ | ⟨hn, ha0, hpid, hsrv, hnr, hroom⟩
    · have hp2 : get c2 f.sid = some p := by rw [hget2]; exact hp
      rw [ensure_snd_get _ _ _ hp2]
      simp only []
      have hP := inv_begin0 c2 f.sid p hI2 hc02 (by rw [hr2, hr]) hk2 (Or.inl ⟨hp2, hst⟩)
      have hab : abs (put c2 f.sid p) f.sid = abs c0 f.sid := by rw [abs_put_self, ha0]
      have hothp : Others (abs c0) (abs (put c2 f.sid p)) f.sid :=
        others_trans hoth2 (fun j hj => abs_put_other _ _ _ _ hj)
      cases heh : f.eh
      · simp only [Bool.not_false, if_true, Bool.false_eq_true, if_false]
        apply sgood_begin c0 _ _ hP _ hothp
        rw [hab, ha0]; rcases hst with h | h <;> simp [h, ofSt, okPost]
      · simp only [Bool.not_true, Bool.false_eq_true, if_false, if_true]
        apply sgood_hdr_commit dec c0 _ _ _ hP hc02 hk0 hg2 hes2 hab hothp
        · rw [ha0]; rcases hst with h | h <;> simp [h, ofSt, strmOK]
        · intro s s' hs hpo
          rw [get_put] at hs; simp only [if_true] at hs; cases hs
          rw [ha0, okPost_hdr_hdrEnd _ _ _ hst]; exact hpo
    · have hn2 : get c2 f.sid = none := by rw [hget2]; exact hn
      obtain ⟨hnX, hidX⟩ := ensure_none c2 f.sid hI2 hn2
      obtain ⟨fc, flp, fml, fco, frf, fes, fga, frb⟩ := ensure_fields c2 f.sid
      have hIX := inv_ensure c2 f.sid hI2
      have habX := abs_ensure c2 f.sid hI2
      have hkX : keyOK (ensure c2 f.sid).1 f.sid := by unfold keyOK at hk2 ⊢; rw [fc, flp, fml]; exact hk2
      have hP := inv_begin0 _ f.sid _ hIX (by rw [fco, hc02]) (by rw [frf, hr2, hr]) hkX
        (Or.inr ⟨hnX, hidX, by rw [fc, hcl2, hsrv], by rw [frb, hrbu2]; exact hnr⟩)
      have hab : abs (put (ensure c2 f.sid).1 f.sid (ensure c2 f.sid).2) f.sid = abs c0 f.sid := by
        rw [abs_put_self, ha0, hidX]; rfl
      have hothp : Others (abs c0) (abs (put (ensure c2 f.sid).1 f.sid (ensure c2 f.sid).2)) f.sid :=
        others_trans hoth2 (fun j hj => by rw [abs_put_other _ _ _ _ hj, habX])
      have hrm := hroom hr
      cases heh : f.eh
      · simp only [Bool.not_false, if_true, Bool.false_eq_true, if_false]
        apply sgood_begin c0 _ _ hP _ hothp
        rw [hab, ha0]; simp [okPost, hpid, hrm]
      · simp only [Bool.not_true, Bool.false_eq_true, if_false, if_true]
        apply sgood_hdr_commit dec c0 _ _ _ hP (by simp only [put]; rw [fco, hc02]) hk0
          (by simp only [put]; rw [fga, hg2]) (by simp only [put]; rw [fes, hes2]) hab hothp
        · rw [ha0]; simp [strmOK]
        · intro s s' hs hpo
          rw [get_put] at hs; simp only [if_true] at hs; cases hs
          rw [hidX] at hpo; rw [ha0]
          simp only [ofSt, okPost] at hpo ⊢; simp [hpid, hrm, hpo]
  · rw [if_neg hr]
    have hb : abs c2 f.sid = .closed ∨ abs c2 f.sid = .open_ := by
      rcases hcase with ⟨p, hp, hst, ha0, hop⟩ | ⟨hn, ha0, hpid, hsrv, hnr, hroom⟩
      · right; rw [hab2, abs_some hp, hop hr]; rfl
      · left; rw [hab2, abs_none hn, idleAbs_key hk]; rfl
    have hP := inv_beginR c2 f.sid hI2 hc02 (by rw [hr2]; exact hr) hk0 hb
    cases heh : f.eh
    · simp only [Bool.not_false, if_true, Bool.false_eq_true, if_false]
      apply sgood_begin c0 _ _ hP _ hoth2
      rcases hcase with ⟨p, hp, hst, ha0, hop⟩ | ⟨hn, ha0, hpid, hsrv, hnr, hroom⟩
      · rw [hab2, abs_some hp, ha0, hop hr]; simp [ofSt, okPost]
      · rw [hab2, abs_none hn, idleAbs_key hk, ha0]; simp [okPost, hpid]
    · simp only [Bool.not_true, Bool.false_eq_true, if_false, if_true]
      rcases hcase with ⟨p, hp, hst, ha0, hop⟩ | ⟨hn, ha0, hpid, hsrv, hnr, hroom⟩
      · apply sgood_hdr_commit dec c0 _ _ _ hP hc02 hk0 hg2 hes2 (by rw [hab2, abs_some hp, ha0])
          hoth2
        · rw [ha0, hop hr]; simp [ofSt, strmOK]
        · intro s s' hs hpo
          rw [hget2, hp] at hs; cases hs
          rw [ha0, okPost_hdr_hdrEnd _ _ _ hst]; exact hpo
      · have := cgood_commit dec c2 f.sid hP hc02 hk0 hg2
        rw [hes2] at this
        unfold CGood at this; unfold SGood
        generalize verdict (commit F dec c2 f.sid).2 f.sid = v at this ⊢
        cases v with
        | conn e => unfold CGoodV at this; unfold SGoodV; simp [this]
        | strm e =>
          unfold CGoodV at this; unfold SGoodV
          obtain ⟨h1, h2, h3, h4⟩ := this
          refine ⟨?_, others_trans hoth2 h2, h3, h4⟩
          simp [recvOK, h1, ha0, strmOK]
        | ok =>
          unfold CGoodV at this
          obtain ⟨⟨s, hs, _⟩, _⟩ := this
          rw [hget2, hn] at hs; cases hs

/-! ## CONTINUATION -/

theorem sgood_cont (dec : Dec) (c : Conn) (f : Fr) (hI : Inv c) (hg : c.goawaySent = false)
    (hc : c.continuing ≠ 0) (hty : f.ty = tCONT) (hs : f.sid = c.continuing) :
    SGood c f.sid (if f.eh then .hdrEnd c.blockES else .contMid) (contBranch F dec c f) := by
  have hcond : ¬((decide (f.ty ≠ tCONT) || decide (f.sid ≠ c.continuing)) = true) := by simp [hty, hs]
  have hconn : ∀ (c' : Conn) (e : Nat) (rk : RK), c'.goawaySent = false → connAny e = true →
      SGood c f.sid rk (connErr c' e) := by
    intro c' e rk hg' he
    unfold SGood SGoodV; rw [verdict_connErr _ _ _ hg']; simp [he]
  have hiv : iv { c with blockConts := c.blockConts + 1, block := c.block ++ f.frag } = iv c := rfl
  unfold contBranch
  rw [if_neg hcond]
  cases heh : f.eh
  · simp only [Bool.not_false, if_true, Bool.false_eq_true, if_false]
    split
    · exact hconn _ _ _ hg (by simp [connAny])
    split
    · exact hconn _ _ _ hg (by simp [connAny])
    split
    · exact hconn _ _ _ hg (by simp [connAny])
    unfold SGood SGoodV
    have hv : verdict [] f.sid = .ok := rfl
    simp only [hv, recvOK, okPost]
    refine ⟨by rw [abs_congr hiv]; simp, by rw [abs_congr hiv]; exact others_refl _ _, sends_nil _ _,
      inv_congr hiv hI⟩
  · simp only [Bool.not_true, Bool.false_eq_true, if_false, if_true]
    split
    · exact hconn _ _ _ hg (by simp [connAny])
    split
    · exact hconn _ _ _ hg (by simp [connAny])
    split
    · exact hconn _ _ _ hg (by simp [connAny])
    have hP : Inv { { c with blockConts := c.blockConts + 1, block := c.block ++ f.frag, continuing := 0 } with
        continuing := f.sid } := inv_congr (by simp only [iv, hs]) hI
    have hk0 : f.sid ≠ 0 := by rw [hs]; exact hc
    have := cgood_commit dec _ f.sid hP rfl hk0 hg
    have habc : abs { c with blockConts := c.blockConts + 1, block := c.block ++ f.frag, continuing := 0 } = abs c := rfl
    apply cgood_sgood c _ f.sid c.blockES _ _ this (by rw [habc]) (by rw [habc]; exact others_refl _ _)
    · simp [strmOK, abs_ne_resL]
    · intro s s' hs' hpo; rw [okPost_hdrEnd_any _ _ true true]
      rw [show abs c f.sid = ofSt s.state from by rw [← habc]; exact abs_some hs']; exact hpo

/-! ## HEADERS -/

theorem inv_bump (c : Conn) (k : Nat) (hI : Inv c) (h0 : c.continuing = 0) (hs : c.isClient = false)
    (hk : k > c.lastPeer) : Inv { c with lastPeer := k } := by
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
  refine ⟨nd, ?_, idle, srv, ?_, ?_, cliRef, ?_, ga⟩
  · intro j t h; have := keys j t h; unfold keyOK at this ⊢; simp only [hs] at this ⊢
    simp only [Bool.false_eq_true, if_false] at this ⊢; omega
  · intro a; exact absurd h0 a
  · intro a; exact absurd h0 a
  · intro j hj; have := rbu j hj
    unfold abs at this ⊢
    show (match get c j with | some s => ofSt s.state | none => if idleAbs { c with lastPeer := k } j then _ else _) = _
    cases hg : get c j with
    | some s => rw [hg] at this; exact this
    | none =>
      rw [hg] at this; simp only at this ⊢
      have e : idleAbs c j = false := by
        cases h' : idleAbs c j
        · rfl
        · rw [h'] at this; cases this
      have e2 : idleAbs { c with lastPeer := k } j = false := by
        unfold idleAbs at e ⊢; simp only [hs, Bool.false_eq_true, if_false] at e ⊢
        simp at e ⊢; omega
      rw [e2]; rfl

theorem others_bump (c : Conn) (k : Nat) (hs : c.isClient = false) (hk : k > c.lastPeer) :
    Others (abs c) (abs { c with lastPeer := k }) k := by
  intro j hj
  have hg' : get { c with lastPeer := k } j = get c j := rfl
  cases hg : get c j with
  | some s => left; rw [abs_some (c := { c with lastPeer := k }) (by rw [hg', hg]), abs_some hg]
  | none =>
    rw [abs_none (c := { c with lastPeer := k }) (by rw [hg', hg]), abs_none hg]
    unfold idleAbs; simp only [hs, Bool.false_eq_true, if_false]
    by_cases h1 : j > k ∨ j % 2 = 0
    · left
      have e1 : (decide (j > k) || j % 2 == 0) = true := by simp; omega
      have e2 : (decide (j > c.lastPeer) || j % 2 == 0) = true := by simp; omega
      rw [if_pos e1, if_pos e2]
    · by_cases h2 : j > c.lastPeer
      · right
        have e1 : (decide (j > k) || j % 2 == 0) = false := by simp; omega
        have e2 : (decide (j > c.lastPeer) || j % 2 == 0) = true := by simp; omega
        rw [e1, e2]; exact ⟨rfl, rfl, by omega⟩
      · left
        have e1 : (decide (j > k) || j % 2 == 0) = false := by simp; omega
        have e2 : (decide (j > c.lastPeer) || j % 2 == 0) = false := by simp; omega
        rw [e1, e2]

theorem dispatch_headers (dec : Dec) (c : Conn) (f : Fr) (fx : Fix) (hty : f.ty = tHEADERS) :
    dispatch fx dec c f = headersH fx dec c f := by
  unfold dispatch; simp [hty, tSETTINGS, tPING, tWU, tHEADERS]

/-- HEADERS on a stream other than 0 while no block is open, after the
frame-shape and size checks (which HEADERS passes). -/
theorem sgood_headers (dec : Dec) (c0 : Conn) (f : Fr) (r : Conn × List Out) (hI : Inv c0)
    (hg : c0.goawaySent = false) (h0 : c0.continuing = 0) (hty : f.ty = tHEADERS) (hk0 : f.sid ≠ 0)
    (h : (match idCheck F c0 f with | .inl r => Except.ok r | .inr c => dispatch F dec c f) = .ok r) :
    SGood c0 f.sid (if f.eh then .hdr f.f1 else .hdrBegin) r := by
  have hconn : ∀ (c' : Conn) (e : Nat), c'.goawaySent = false →
      (connAny e || connCodes (pid c0 f.sid) (abs c0 f.sid) (if f.eh then .hdr f.f1 else .hdrBegin) e) = true →
      SGood c0 f.sid (if f.eh then .hdr f.f1 else .hdrBegin) (connErr c' e) := by
    intro c' e hg' he
    unfold SGood SGoodV; rw [verdict_connErr _ _ _ hg']; exact he
  have hcc : ∀ (t : SS) (e : Nat), t = .open_ ∨ t = .hcl →
      connCodes (pid c0 f.sid) t (if f.eh then .hdr f.f1 else .hdrBegin) e = true := by
    intro t e ht; rcases ht with rfl | rfl <;> cases f.eh <;> rfl
  have tail : ∀ (c1 : Conn) (X : Conn × List Out) (b : Bool),
      (if b = true then Except.ok (connErr c1 ePROTOCOL) else
        match stripLen f true with | none => Except.ok (connErr c1 ePROTOCOL) | some _ => Except.ok X) =
        (Except.ok r : Res) → r = connErr c1 ePROTOCOL ∨ r = X := by
    intro c1 X b hh
    split at hh
    · simp only [Except.ok.injEq] at hh; exact Or.inl hh.symm
    · split at hh <;> simp only [Except.ok.injEq] at hh
      · exact Or.inl hh.symm
      · exact Or.inr hh.symm
  -- the post-idCheck part, for a connection `c1` that has the same streams
  have post : ∀ c1 : Conn, Inv c1 → c1.continuing = 0 → c1.goawaySent = false → get c1 = get c0 →
      c1.isClient = c0.isClient → keyOK c1 f.sid ∨ get c0 f.sid = none →
      Others (abs c0) (abs c1) f.sid →
      (get c0 f.sid = none → c0.isClient = false → abs c0 f.sid = .idle ∧ pid c0 f.sid = true ∧
        keyOK c1 f.sid ∧ f.sid ∉ c1.resetByUs ∧ activeCount c1 = activeCount c0 ∧
        c1.maxConcurrent = c0.maxConcurrent) →
      headersH F dec c1 f = .ok r → SGood c0 f.sid (if f.eh then .hdr f.f1 else .hdrBegin) r := by
    intro c1 hI1 h01 hg1 hget hcl hk1 hoth hnew hh
    unfold headersH at hh
    rw [if_neg hk0] at hh
    cases hp : get c0 f.sid with
    | some p =>
      have hm : mem c1 f.sid = true := by simp [mem, hget, hp]
      have hp1 : get c1 f.sid = some p := by rw [hget]; exact hp
      have hni := entry_nonidle hI h0 hp
      have ha0 := abs_some hp
      simp only [hm, Bool.not_true, Bool.and_false, Bool.false_eq_true, if_false] at hh
      unfold headersPre at hh; rw [hp1] at hh; simp only at hh
      by_cases hcl0 : p.state = .closed
      · rw [if_pos hcl0] at hh; simp only [Except.ok.injEq] at hh; subst hh
        apply hconn _ _ hg1; rw [ha0, hcl0]; cases f.eh <;> rfl
      rw [if_neg hcl0] at hh
      by_cases hcr : p.state = .hcr
      · have : ((!c1.isClient || F.h2_14) && decide (p.state = St.hcr)) = true := by simp [F, hcr]
        rw [if_pos this] at hh; simp only [Except.ok.injEq] at hh; subst hh
        apply hconn _ _ hg1; rw [ha0, hcr]; cases f.eh <;> rfl
      have : ¬((!c1.isClient || F.h2_14) && decide (p.state = St.hcr)) = true := by simp [F, hcr]
      rw [if_neg this] at hh
      have hst : p.state = .open_ ∨ p.state = .hcl := by
        cases hps : p.state <;> simp_all
      have hcc' : connCodes (pid c0 f.sid) (abs c0 f.sid) (if f.eh then .hdr f.f1 else .hdrBegin) 1 = true :=
        hcc _ _ (by rw [ha0]; rcases hst with h | h <;> simp [h, ofSt])
      have hk1' : keyOK c1 f.sid := by
        rcases hk1 with h | h
        · exact h
        · rw [hp] at h; cases h
      rw [show (if (!c1.isClient && p.headersComplete && !f.f1) = true then (Sum.inr ePROTOCOL : (Conn × List Out) ⊕ Nat)
          else Sum.inr 0) = Sum.inr (if (!c1.isClient && p.headersComplete && !f.f1) = true then ePROTOCOL else 0)
          from by split <;> rfl] at hh
      simp only [] at hh
      rcases tail c1 _ _ hh with rfl | rfl
      · apply hconn _ _ hg1; simp [hcc']
      apply sgood_headersOpen dec c0 c1 f _ hI1 h01 hg1 hk1' hoth
      · intro hc; unfold headersRefuse; rw [hc]; simp [hm]
      · left
        refine ⟨p, hp1, hst, ha0, ?_⟩
        intro hr
        unfold headersRefuse at hr; simp only [hm] at hr
        rcases hst with h | h
        · exact h
        · exfalso
          have hsrv : c1.isClient = false := by
            cases hcc1 : c1.isClient
            · rfl
            · simp [hcc1] at hr
          exact hI.srv (by rw [← hcl]; exact hsrv) _ _ hp h
    | none =>
      cases hc : c0.isClient
      · have hc1 : c1.isClient = false := by rw [hcl, hc]
        obtain ⟨ha0, hpid, hk1', hnr, hact, hmax⟩ := hnew hp hc
        have hm : mem c1 f.sid = false := by simp [mem, hget, hp]
        have hn1 : get c1 f.sid = none := by rw [hget]; exact hp
        simp only [hc1, Bool.false_and, Bool.false_eq_true, if_false] at hh
        unfold headersPre at hh; rw [hn1] at hh; simp only at hh
        rcases tail c1 _ _ hh with rfl | rfl
        · apply hconn _ _ hg1; rw [ha0, hpid]; cases f.eh <;> rfl
        apply sgood_headersOpen dec c0 c1 f _ hI1 h01 hg1 hk1' hoth
        · intro h; rw [hc1] at h; cases h
        · right
          refine ⟨hn1, ha0, hpid, hc1, hnr, ?_⟩
          intro hr
          unfold headersRefuse at hr; simp only [hm, hc1, F] at hr
          unfold room; rw [hc]; simp only [Bool.false_or, decide_eq_true_eq]
          split at hr
          · simp [eREFUSED] at hr
          · rename_i hh; simp at hh; rw [← hact, ← hmax]; omega
      · have hc1 : c1.isClient = true := by rw [hcl, hc]
        have hm : mem c1 f.sid = false := by simp [mem, hget, hp]
        simp only [hc1, hm, F, Bool.not_false, Bool.and_self, if_true, Except.ok.injEq] at hh
        subst hh
        apply hconn _ _ hg1
        rw [abs_none hp]
        have : pid c0 f.sid = false := by simp [pid, peerId, hc]
        rw [this]; split <;> cases f.eh <;> rfl
  -- idCheck
  have hpe : ∀ s, get c0 f.sid = some s → f.sid % 2 = 1 := fun s hs => (hI.keys _ s hs).1
  cases hc : c0.isClient
  · have hid : idCheck F c0 f =
        (if f.sid ≠ 0 && f.sid % 2 = 0 then .inl (connErr c0 ePROTOCOL)
         else if decide (f.sid ≤ c0.lastPeer) && !mem c0 f.sid then .inl (connErr c0 ePROTOCOL)
         else .inr (if f.sid > c0.lastPeer then { c0 with lastPeer := f.sid } else c0)) := by
      unfold idCheck; simp [hty, hc, F]
    rw [hid] at h
    by_cases hev : f.sid % 2 = 0
    · rw [if_pos (by simp [hk0, hev])] at h; simp only [Except.ok.injEq] at h; subst h
      apply hconn _ _ hg
      have hn : get c0 f.sid = none := by
        cases hs : get c0 f.sid with
        | none => rfl
        | some s => have := hpe s hs; omega
      rw [abs_none hn]; unfold idleAbs; rw [hc]; simp [hev]; cases f.eh <;> simp [connCodes]
    rw [if_neg (by simp [hev])] at h
    by_cases hle : f.sid ≤ c0.lastPeer ∧ mem c0 f.sid = false
    · rw [if_pos (by simp [hle.1, hle.2])] at h; simp only [Except.ok.injEq] at h; subst h
      apply hconn _ _ hg
      have hn : get c0 f.sid = none := by simpa [mem] using hle.2
      rw [abs_none hn]; unfold idleAbs; rw [hc]
      have : (decide (f.sid > c0.lastPeer) || f.sid % 2 == 0) = false := by simp; omega
      rw [this]; simp only [Bool.false_eq_true, if_false]; cases f.eh <;> rfl
    rw [if_neg (by simpa using hle)] at h
    simp only [] at h
    rw [dispatch_headers dec _ f F hty] at h
    by_cases hgt : f.sid > c0.lastPeer
    · rw [if_pos hgt] at h
      apply post _ (inv_bump c0 f.sid hI h0 hc hgt) h0 hg rfl rfl _ (others_bump c0 f.sid hc hgt) _ h
      · left; unfold keyOK; simp only [hc, Bool.false_eq_true, if_false]; omega
      · intro hn _
        refine ⟨?_, ?_, ?_, ?_, rfl, rfl⟩
        · rw [abs_none hn]; unfold idleAbs; rw [hc]; simp; omega
        · simp [pid, peerId, hc]; omega
        · unfold keyOK; simp only [hc, Bool.false_eq_true, if_false]; omega
        · intro hr; have := hI.rbu _ hr; rw [abs_none hn] at this; unfold idleAbs at this; rw [hc] at this
          simp at this; omega
    · rw [if_neg hgt] at h
      apply post _ hI h0 hg rfl rfl _ (others_refl _ _) _ h
      · cases hs : get c0 f.sid with
        | none => right; rfl
        | some s => left; exact hI.keys _ s hs
      · intro hn _
        exfalso; apply hle; exact ⟨by omega, by simp [mem, hn]⟩
  · have hid : idCheck F c0 f = .inr c0 := by unfold idCheck; simp [hc]
    rw [hid] at h; simp only [] at h
    rw [dispatch_headers dec _ f F hty] at h
    apply post _ hI h0 hg rfl rfl _ (others_refl _ _) _ h
    · cases hs : get c0 f.sid with
      | none => right; rfl
      | some s => left; exact hI.keys _ s hs
    · intro _ h'; rw [hc] at h'; cases h'

end Flare.L3.H2.Refine
