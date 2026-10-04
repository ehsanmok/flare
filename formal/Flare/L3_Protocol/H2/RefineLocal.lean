import Flare.L3_Protocol.H2.RefineFrame

/-!
# §5.1 refinement: local actions

The local actions of the model (`Ev` other than `frame`) are the
application driving the endpoint. Their preconditions (`LocalOK`) are the
API contracts flare's callers keep (environment facts, stated as `Prop`
hypotheses):

* `respond k n` (server): the request on `k` is complete (half-closed
  remote): `emit_response` is called from the request handler;
* `send k n` (server): `k` is open or half-closed (remote);
* `openLocal k es` (client): `k` is a fresh odd id above every id used
  so far (`_next_stream_id` in client.mojo);
* `pop k` (client): `take_response` / `discard_stream` run once the
  response is complete or the stream was reset: `k` is absent,
  half-closed (remote) or closed;
* `endLocal k e` (client): `k` is in the table and not already
  half-closed (local);
* `stream k`, `drain k` (client): the streaming body reader runs only
  on the client;
* `release`: no precondition.

`fixed_local`: in the fixed model each such step preserves `Inv` and is
matched by a run of the §5.1 spec made of `send` labels (HEADERS, DATA,
WINDOW_UPDATE, forgetting a finished stream); a step that changes no
stream state is matched by the empty run.
-/
namespace Flare.L3.H2.Refine
open Flare.L3.H2.Conn Flare.L3.H2.StreamSpec

def LocalOK (c : Conn) : Ev → Prop
  | .frame _ => True
  | .release _ => True
  | .respond k _ => c.isClient = false ∧ ∃ s, get c k = some s ∧ s.state = .hcr
  | .send k _ => c.isClient = false ∧ ∃ s, get c k = some s ∧ (s.state = .open_ ∨ s.state = .hcr)
  | .openLocal k _ => c.isClient = true ∧ k % 2 = 1 ∧ k > c.maxLocalSid
  | .pop k => c.isClient = true ∧ ∀ s, get c k = some s → s.state = .hcr ∨ s.state = .closed
  | .endLocal k _ => c.isClient = true ∧ ∃ s, get c k = some s ∧ s.state ≠ .hcl
  | .stream _ => c.isClient = true
  | .drain _ => c.isClient = true

abbrev SRun (client : Bool) (M : Nat → SS) (ls : List Lab) (M' : Nat → SS) : Prop :=
  (StreamSpec.lts client).Run (some M) ls (some M')

theorem srun_nil (client : Bool) {M M' : Nat → SS} (h : M' = M) : SRun client M [] M' := by
  subst h; exact .nil _

theorem srun_send (client : Bool) {M M' : Nat → SS} (k : Nat) (sk : SK)
    (hp : sendPost (M k) sk = some (M' k)) (ho : Others M M' k) : SRun client M [.send k sk] M' :=
  .cons (s' := some M') ⟨M, rfl, hp, ho⟩ (.nil _)

theorem srun_send2 (client : Bool) {M M' : Nat → SS} (k : Nat) (sk1 sk2 : SK)
    (hp1 : sendPost (M k) sk1 = some (M k)) (hp2 : sendPost (M k) sk2 = some (M' k)) (ho : Others M M' k) :
    SRun client M [.send k sk1, .send k sk2] M' :=
  .cons (s' := some M) ⟨M, rfl, hp1, others_refl _ _⟩ (.cons (s' := some M') ⟨M, rfl, hp2, ho⟩ (.nil _))

theorem stl_putL_same (l : List (Nat × Stream)) (k : Nat) (s' : Stream)
    (h : (l.find? (·.1 == k)).map (·.2.state) = some s'.state) : stl (putL l k s') = stl l := by
  induction l with
  | nil => simp at h
  | cons p t ih =>
    unfold putL
    by_cases hp : p.1 = k
    · rw [if_pos hp]
      simp [List.find?_cons, hp] at h
      simp only [stl, List.map_cons, hp, h]
    · rw [if_neg hp]
      have hb : (p.1 == k) = false := by simp [hp]
      simp only [List.find?_cons, hb] at h
      have := ih h
      simp only [stl, List.map_cons] at this ⊢
      rw [this]

theorem sameSt_put (c c' : Conn) (k : Nat) (s s' : Stream) (hg : get c k = some s) (hst : s'.state = s.state)
    (hc : c'.streams = c.streams) (h2 : c'.isClient = c.isClient) (h3 : c'.lastPeer = c.lastPeer)
    (h4 : c'.maxLocalSid = c.maxLocalSid) (h5 : c'.continuing = c.continuing) (h6 : c'.blockRefuse = c.blockRefuse)
    (h7 : c'.resetByUs = c.resetByUs) (h8 : c'.goawaySent = c.goawaySent) : SameSt (put c' k s') c := by
  refine ⟨?_, h2, h3, h4, h5, h6, h7, h8⟩
  show stl (putL c'.streams k s') = stl c.streams
  rw [hc]
  apply stl_putL_same
  have : (get c k).map (·.state) = some s.state := by rw [hg]; rfl
  unfold Flare.L3.H2.Conn.get at this; rw [Option.map_map] at this
  rw [hst]; exact this

theorem get_erase_self (c : Conn) (k : Nat) : get (erase c k) k = none := by
  show ((c.streams.filter (·.1 != k)).find? (·.1 == k)).map (·.2) = none
  rw [Option.map_eq_none_iff, List.find?_eq_none]
  intro p hp; simp at hp ⊢; exact hp.2

theorem abs_erase (c : Conn) (k : Nat) :
    abs (erase c k) = fun j => if j = k then (if idleAbs c k then .idle else .closed) else abs c j := by
  funext j
  by_cases h : j = k
  · subst h; rw [if_pos rfl, abs_none (get_erase_self c j)]; rfl
  · rw [if_neg h]; unfold abs; rw [get_erase_other c k j h]; rfl

theorem cont_not (c : Conn) (k : Nat) (s : Stream) (hI : Inv c) (hs : get c k = some s)
    (hst : s.state = .hcr ∨ s.state = .closed) (hcl : c.isClient = true ∨ s.state = .hcr) : c.continuing ≠ k := by
  intro he
  have hk0 : k ≠ 0 := by have := (hI.keys k s hs).1; omega
  by_cases hr : c.blockRefuse = 0
  · obtain ⟨t, ht, h3⟩ := hI.blk0 (by omega) hr
    rw [he, hs] at ht; cases ht
    rcases hst with h | h <;> rcases h3 with h' | h' | h' <;> rw [h] at h' <;> cases h'
  · rcases hcl with h | h
    · exact hr (hI.cliRef h)
    · have := hI.blk1 (by omega) hr
      rw [he, abs_some hs, h] at this; rcases this with h' | h' <;> cases h'

theorem fixed_local (dec : Dec) (c : Conn) (e : Ev) (hI : Inv c) (hok : LocalOK c e)
    (hne : ∀ f, e ≠ .frame f) :
    ∃ c' o, step F dec c e = .ok (c', o) ∧ Inv c' ∧ ∃ ls, SRun c.isClient (abs c) ls (abs c') := by
  cases e with
  | frame f => exact absurd rfl (hne f)
  | release n =>
    have hiv : iv (release F c n).1 = iv c := by simp only [release]; split <;> rfl
    exact ⟨(release F c n).1, (release F c n).2, rfl, inv_congr hiv hI, [], srun_nil _ (abs_congr hiv)⟩
  | respond k n =>
    obtain ⟨hsrv, s, hs, hst⟩ := hok
    simp only [step]
    unfold respond; rw [hs]; simp only []
    split
    · exact ⟨_, _, rfl, hI, [], srun_nil _ rfl⟩
    · refine ⟨_, _, rfl, ?_, ?_⟩
      · have hk := hI.keys k s hs
        have hnc := cont_not c k s hI hs (Or.inl hst) (Or.inr hst)
        have := inv_put c k { s with state := .closed, sendW := s.sendW - n } hI hk (fun h => by simp at h)
          (fun _ => by simp) (fun h => absurd h hnc) (fun h => absurd h hnc) (fun _ => rfl)
        exact inv_congr (c := put c k { s with state := .closed, sendW := s.sendW - n }) rfl this
      · have ha : abs (put { c with sendW := c.sendW - n } k { s with state := .closed, sendW := s.sendW - n }) =
            abs (put c k { s with state := .closed, sendW := s.sendW - n }) := abs_congr rfl
        rw [ha]
        have hM : abs c k = .hcr := by rw [abs_some hs, hst]; rfl
        by_cases hn : n > 0
        · refine ⟨[.send k (.hdr false), .send k (.data true)], srun_send2 _ k _ _ ?_ ?_ (others_put c k _)⟩
          · rw [hM]; rfl
          · rw [hM, abs_put_self]; rfl
        · refine ⟨[.send k (.hdr true)], srun_send _ k _ ?_ (others_put c k _)⟩
          rw [hM, abs_put_self]; rfl
  | send k n =>
    obtain ⟨hsrv, s, hs, hst⟩ := hok
    have hss : SameSt (send c k n).1 c := by
      unfold send; rw [hs]; simp only []; split
      · exact SameSt.refl c
      · exact sameSt_put c _ k s _ hs rfl rfl rfl rfl rfl rfl rfl rfl rfl
    have ha := abs_sameSt hss
    refine ⟨(send c k n).1, (send c k n).2, rfl, inv_sameSt hss hI, ?_⟩
    cases (send c k n).2 with
    | nil => exact ⟨[], srun_nil _ ha⟩
    | cons _ _ =>
      refine ⟨[.send k (.data false)], srun_send _ k _ ?_ ?_⟩
      · rw [ha, abs_some hs]; rcases hst with h | h <;> rw [h] <;> rfl
      · rw [ha]; exact others_refl _ _
  | openLocal k es =>
    obtain ⟨hcl, hodd, hgt⟩ := hok
    simp only [step]
    have hn : get c k = none := by
      cases hg : get c k with
      | none => rfl
      | some s => have := (hI.keys k s hg).2; simp [hcl] at this; omega
    have hidle : abs c k = .idle := by
      rw [abs_none hn]; unfold idleAbs; simp [hcl]; omega
    have hol : openLocal c k es = put { c with maxLocalSid := k } k
        { state := if es then St.hcl else St.open_, sendW := c.peerInitW, recvW := c.initW } := by
      simp [openLocal, hgt]
    rw [hol]
    generalize hc1 : ({ c with maxLocalSid := k } : Conn) = c1
    have hc1g : get c1 = get c := by rw [← hc1]; rfl
    have hc1c : c1.isClient = true := by rw [← hc1]; exact hcl
    have hc1m : c1.maxLocalSid = k := by rw [← hc1]
    generalize hs1 : ({ state := if es then St.hcl else St.open_, sendW := c.peerInitW, recvW := c.initW } : Stream) = s1
    have hs1n : s1.state ≠ .idle := by rw [← hs1]; split <;> simp
    have habs1 : ∀ j, j ≠ k → abs c1 j = abs c j ∨ (abs c j = .idle ∧ abs c1 j = .closed ∧ j < k) := by
      intro j hj
      unfold abs; rw [hc1g]
      cases hg : get c j with
      | some t => left; rfl
      | none =>
        simp only []
        unfold idleAbs; rw [hc1c, hcl, hc1m]; simp only [if_true]
        by_cases h1 : j > k ∨ j % 2 = 0
        · left
          have e1 : (decide (j > k) || j % 2 == 0) = true := by simp; omega
          have e2 : (decide (j > c.maxLocalSid) || j % 2 == 0) = true := by simp; omega
          rw [if_pos e1, if_pos e2]
        · by_cases h2 : j > c.maxLocalSid
          · right
            have e1 : (decide (j > k) || j % 2 == 0) = false := by simp; omega
            have e2 : (decide (j > c.maxLocalSid) || j % 2 == 0) = true := by simp; omega
            rw [e1, e2]; exact ⟨rfl, rfl, by omega⟩
          · left
            have e1 : (decide (j > k) || j % 2 == 0) = false := by simp; omega
            have e2 : (decide (j > c.maxLocalSid) || j % 2 == 0) = false := by simp; omega
            rw [e1, e2]
    refine ⟨_, _, rfl, ?_, [.send k (.hdr es)], srun_send _ k _ ?_ ?_⟩
    · obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
      refine ⟨nodupK_putL _ _ _ (by rw [← hc1]; exact nd), ?_, ?_, ?_, ?_, ?_, ?_, ?_, by rw [← hc1]; exact ga⟩
      · intro j t h; rw [get_put, hc1g] at h; unfold keyOK
        rw [show (put c1 k s1).isClient = true from hc1c, show (put c1 k s1).maxLocalSid = k from hc1m]
        simp only [if_true]
        split at h
        · rename_i hj; subst hj; exact ⟨hodd, Nat.le_refl _⟩
        · have := keys j t h; unfold keyOK at this; simp [hcl] at this; omega
      · intro j t h he; rw [get_put, hc1g] at h; split at h
        · cases h; exact absurd he hs1n
        · have := (idle j t h he).2.1; rw [hcl] at this; cases this
      · intro h; rw [show (put c1 k s1).isClient = true from hc1c] at h; cases h
      · intro a b
        have a' : c.continuing ≠ 0 := by rw [← hc1] at a; exact a
        have b' : c.blockRefuse = 0 := by rw [← hc1] at b; exact b
        obtain ⟨t, ht, h3⟩ := blk0 a' b'
        have hne : c.continuing ≠ k := by
          intro he; rw [he, hn] at ht; cases ht
        show ∃ t, get (put c1 k s1) c1.continuing = some t ∧ _
        have : c1.continuing = c.continuing := by rw [← hc1]
        rw [this, get_put, if_neg hne, hc1g]; exact ⟨t, ht, h3⟩
      · intro a b; have := cliRef hcl; rw [← hc1] at b; exact absurd this b
      · intro h; rw [← hc1]; exact cliRef hcl
      · intro j hj
        have hj' : j ∈ c.resetByUs := by rw [← hc1] at hj; exact hj
        have := rbu j hj'
        show abs (put c1 k s1) j = .closed
        rw [abs_put]; split
        · rename_i h; subst h; rw [hidle] at this; cases this
        · rename_i h
          rcases habs1 j h with h' | ⟨h1, -, -⟩
          · rw [h', this]
          · rw [h1] at this; cases this
    · rw [hidle, abs_put_self, ← hs1]; cases es <;> rfl
    · intro j hj; rw [abs_put_other _ _ _ _ hj]; exact habs1 j hj
  | pop k =>
    obtain ⟨hcl, hst⟩ := hok
    simp only [step]
    refine ⟨_, _, rfl, ?_, ?_⟩
    · obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
      have hsub : ∀ j t, get (erase c k) j = some t → j ≠ k ∧ get c j = some t := by
        intro j t h
        by_cases hj : j = k
        · subst hj; rw [get_erase_self] at h; cases h
        · rw [get_erase_other c k j hj] at h; exact ⟨hj, h⟩
      refine ⟨nodupK_filter _ _ nd, fun j t h => keys j t (hsub j t h).2, fun j t h => idle j t (hsub j t h).2,
        fun hc j t h => srv hc j t (hsub j t h).2, ?_, ?_, cliRef, ?_, ga⟩
      · intro a b
        obtain ⟨t, ht, h3⟩ := blk0 a b
        refine ⟨t, ?_, h3⟩
        have hne : c.continuing ≠ k := by
          intro he; rw [he] at ht
          rcases hst t ht with h | h <;> rcases h3 with h' | h' | h' <;> rw [h] at h' <;> cases h'
        show get (erase c k) c.continuing = some t
        rw [get_erase_other c k _ hne]; exact ht
      · intro a b; exact absurd (cliRef hcl) b
      · intro j hj
        have := rbu j hj
        show abs (erase c k) j = .closed
        rw [abs_erase]
        show (if j = k then (if idleAbs c k then SS.idle else SS.closed) else abs c j) = .closed
        by_cases hjk : j = k
        · rw [if_pos hjk]; subst hjk
          cases hg : get c j with
          | some t => rw [idleAbs_key (keys j t hg)]; rfl
          | none => rw [abs_none hg] at this; split at this
                    · cases this
                    · rename_i h; simp only [Bool.not_eq_true] at h; rw [h]; rfl
        · rw [if_neg hjk]; exact this
    · cases hg : get c k with
      | none =>
        refine ⟨[], srun_nil _ ?_⟩
        rw [abs_erase]; funext j; split
        · rename_i h; subst h; rw [abs_none hg]
        · rfl
      | some t =>
        refine ⟨[.send k .forget], srun_send _ k _ ?_ ?_⟩
        · rw [abs_erase, abs_some hg]; simp only [if_true]
          rw [idleAbs_key (hI.keys k t hg)]
          rcases hst t hg with h | h <;> rw [h] <;> rfl
        · intro j hj; left; rw [abs_erase]; simp [hj]
  | endLocal k em =>
    obtain ⟨hcl, s, hs, hst⟩ := hok
    simp only [step]
    unfold endLocal; rw [hs]; simp only []
    have h13 : F.h2_13 = true := rfl
    have h12 : F.h2_12 = true := rfl
    rw [h13, h12]
    by_cases hc : s.state = .closed
    · rw [if_pos (by simp [hc])]
      exact ⟨_, _, rfl, hI, [], srun_nil _ rfl⟩
    rw [if_neg (by simp [hc])]
    refine ⟨_, _, rfl, ?_, [.send k (.data true)], srun_send _ k _ ?_ (others_put c k _)⟩
    · apply inv_put c k _ hI (hI.keys k s hs)
      · intro h; simp only [] at h; split at h <;> simp at h
      · intro h; rw [hcl] at h; cases h
      · intro he _
        simp only []
        have : s.state ≠ .hcr := fun h => cont_not c k s hI hs (Or.inl h) (Or.inl hcl) he
        simp [this]
      · intro _ b; exact absurd (hI.cliRef hcl) b
      · intro hr
        have := hI.rbu k hr; rw [abs_some hs] at this
        exfalso; apply hc
        cases hs' : s.state <;> rw [hs'] at this <;> first | rfl | cases this
    · have hni : s.state ≠ .idle := fun he => by
        have := (hI.idle k s hs he).2.1; rw [hcl] at this; cases this
      rw [abs_some hs, abs_put_self]; simp only []
      cases hs' : s.state <;> simp_all [ofSt, sendPost, esTo]
  | stream k =>
    simp only [step]
    unfold enableStream
    cases hg : get c k with
    | none => exact ⟨_, _, rfl, hI, [], srun_nil _ rfl⟩
    | some s =>
      have hss : SameSt (put c k { s with deferCredit := true }) c := sameSt_put c c k s _ hg rfl rfl rfl rfl rfl rfl rfl rfl rfl
      exact ⟨_, _, rfl, inv_sameSt hss hI, [], srun_nil _ (abs_sameSt hss)⟩
  | drain k =>
    simp only [step]
    unfold drain
    split
    · exact ⟨_, _, rfl, hI, [], srun_nil _ rfl⟩
    cases hg : get c k with
    | none => exact ⟨_, _, rfl, hI, [], srun_nil _ rfl⟩
    | some s =>
      simp only []
      have hss : SameSt (put c k { s with buf := [], pendingCredit := 0, recvW := s.recvW + s.pendingCredit }) c :=
        sameSt_put c c k s _ hg rfl rfl rfl rfl rfl rfl rfl rfl rfl
      refine ⟨_, _, rfl, inv_sameSt hss hI, ?_⟩
      have ha := abs_sameSt hss
      by_cases hw : (decide (s.pendingCredit > 0) && !s.dataComplete && s.state != .closed) = true
      · refine ⟨[.send k .wu], srun_send _ k _ ?_ (by rw [ha]; exact others_refl _ _)⟩
        rw [ha, abs_some hg]
        simp only [Bool.and_eq_true, bne_iff_ne, ne_eq] at hw
        have hni : s.state ≠ .idle := by
          intro he; have := (hI.idle k s hg he).2.1; rw [hok] at this; cases this
        cases hs' : s.state <;> simp_all [ofSt, sendPost]
      · exact ⟨[], srun_nil _ ha⟩

end Flare.L3.H2.Refine
