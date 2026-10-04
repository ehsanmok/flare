import Flare.L3_Protocol.H2.ConnSpec

/-!
# Send-window bound (RFC 9113 §6.9.1, §6.9.2)

"A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets."
`WinInv` says the connection send window is in `0 .. 2^31-1`, the peer's
SETTINGS_INITIAL_WINDOW_SIZE is in `0 .. 2^31-1`, and every stream send
window is at most `2^31-1`.

`win_reachable`: `WinInv` holds in every reachable state, for every fix
selection (the fixes do not touch send windows), every HPACK outcome and
every interleaving of inbound frames and local actions (`send`,
`respond`, `openLocal`, `pop`, `release`). Stream send windows may go
negative (§6.9.2 allows it after a SETTINGS decrease).
-/
namespace Flare.L3.H2.Conn
open Flare.L3.H2.Validate (Header)

def SOK (l : List (Nat × Stream)) : Prop := ∀ p ∈ l, p.2.sendW ≤ MAX_WINDOW

def WI (sw pi : Int) (l : List (Nat × Stream)) : Prop :=
  0 ≤ sw ∧ sw ≤ MAX_WINDOW ∧ 0 ≤ pi ∧ pi ≤ MAX_WINDOW ∧ SOK l

def WinInv (c : Conn) : Prop := WI c.sendW c.peerInitW c.streams

/-- A freshly configured connection (`Http2Connection.with_config`,
server.mojo:182-214, and the client constructor). -/
def Fresh (c : Conn) : Prop :=
  c.streams = [] ∧ c.sendW = 65535 ∧ c.recvW = 65535 ∧ c.peerInitW = 65535 ∧
  c.goawaySent = false ∧ c.continuing = 0 ∧ c.withheld = 0 ∧ c.buffered = 0 ∧
  c.lastPeer = 0 ∧ c.resetByUs = [] ∧ c.blockRefuse = 0 ∧ c.maxLocalSid = 0

theorem fresh_win (c : Conn) (h : Fresh c) : WinInv c := by
  obtain ⟨h1, h2, -, h4, -⟩ := h
  refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> simp [h1, h2, h4, MAX_WINDOW, SOK]

/-! ## Stream-table lemmas -/

theorem sok_putL (l : List (Nat × Stream)) (k : Nat) (s : Stream) (hl : SOK l)
    (hs : s.sendW ≤ MAX_WINDOW) : SOK (putL l k s) := by
  induction l with
  | nil => simpa [putL, SOK] using hs
  | cons p t ih =>
    have hp := hl p (List.mem_cons_self ..)
    have ht : SOK t := fun q hq => hl q (List.mem_cons_of_mem _ hq)
    unfold putL
    split
    · intro q hq
      simp only [List.mem_cons] at hq
      rcases hq with rfl | hq
      · exact hs
      · exact ht q hq
    · intro q hq
      simp only [List.mem_cons] at hq
      rcases hq with rfl | hq
      · exact hp
      · exact ih ht q hq

theorem sok_filter (l : List (Nat × Stream)) (p : Nat × Stream → Bool) (hl : SOK l) :
    SOK (l.filter p) := fun q hq => hl q (List.mem_filter.mp hq).1

theorem get_sok (c : Conn) (k : Nat) (s : Stream) (hl : SOK c.streams) (hg : get c k = some s) :
    s.sendW ≤ MAX_WINDOW := by
  unfold get at hg
  cases h : c.streams.find? (·.1 == k) with
  | none => rw [h] at hg; cases hg
  | some p =>
    rw [h] at hg
    simp only [Option.map_some, Option.some.injEq] at hg
    subst hg
    exact hl p (List.mem_of_find?_eq_some h)

theorem win_put (c : Conn) (k : Nat) (s : Stream) (h : WinInv c) (hs : s.sendW ≤ MAX_WINDOW) :
    WinInv (put c k s) :=
  ⟨h.1, h.2.1, h.2.2.1, h.2.2.2.1, sok_putL _ k s h.2.2.2.2 hs⟩

theorem win_get (c : Conn) (k : Nat) (s : Stream) (h : WinInv c) (hg : get c k = some s) :
    s.sendW ≤ MAX_WINDOW := get_sok c k s h.2.2.2.2 hg

theorem win_connErr (c : Conn) (e : Nat) (h : WinInv c) : WinInv (connErr c e).1 := by
  unfold connErr; split <;> exact h

theorem win_rstC (c : Conn) (k : Nat) (h : WinInv c) : WinInv (rstC c k) := h

theorem win_closeIfKnown (c : Conn) (k : Nat) (h : WinInv c) : WinInv (closeIfKnown c k) := by
  unfold closeIfKnown
  split
  · rename_i s hg; exact win_put _ _ _ h (win_get c k s h hg)
  · exact h

theorem win_rstClose (c : Conn) (k e : Nat) (s : Stream) (h : WinInv c) (hs : s.sendW ≤ MAX_WINDOW) :
    WinInv (rstClose c k e s).1 := win_put _ _ _ (win_rstC c k h) hs

theorem win_ensure (c : Conn) (k : Nat) (h : WinInv c) :
    WinInv (ensure c k).1 ∧ (ensure c k).2.sendW ≤ MAX_WINDOW := by
  unfold ensure
  split
  · rename_i s hg; exact ⟨h, win_get c k s h hg⟩
  · split
    · exact ⟨⟨h.1, h.2.1, h.2.2.1, h.2.2.2.1, sok_filter _ _ h.2.2.2.2⟩, h.2.2.2.1⟩
    · exact ⟨h, h.2.2.2.1⟩

/-! ## Result predicates (goal-directed case analysis) -/

def WinE : Res → Prop
  | .ok r => WinInv r.1
  | .error _ => True

def WinS : (Conn × List Out) ⊕ Conn → Prop
  | .inl r => WinInv r.1
  | .inr c => WinInv c

def WinSN : (Conn × List Out) ⊕ Nat → Prop
  | .inl r => WinInv r.1
  | .inr _ => True

def WinO : Option (Conn × List Out) → Prop
  | none => True
  | some r => WinInv r.1

def WinT : Conn ⊕ (Conn × List Out) → Prop
  | .inl c => WinInv c
  | .inr r => WinInv r.1

/-! ## Handlers -/

theorem win_rstCloseX (c : Conn) (k e : Nat) (s : Stream) (x : List Out) (h : WinInv c)
    (hs : s.sendW ≤ MAX_WINDOW) : WinInv (rstCloseX c k e s x).1 := win_put _ _ _ (win_rstC c k h) hs

theorem win_commitTail (fx : Fix) (c : Conn) (k : Nat) (s : Stream) (isTr es : Bool)
    (hdrs : List Header) (h : WinInv c) (hs : s.sendW ≤ MAX_WINDOW) :
    WinInv (commitTail fx c k s isTr es hdrs).1 := by
  unfold commitTail rstClose
  simp only
  repeat' split
  all_goals first
    | exact win_rstCloseX _ _ _ _ _ h hs
    | exact win_put _ _ _ h hs

theorem win_commit (fx : Fix) (dec : Dec) (c : Conn) (k : Nat) (h : WinInv c) :
    WinInv (commit fx dec c k).1 := by
  unfold commit
  simp only
  split
  · exact win_connErr _ _ h
  · exact win_connErr _ _ h
  · split
    · exact win_closeIfKnown _ _ (win_rstC _ _ h)
    · obtain ⟨he, hs⟩ := win_ensure { c with block := [], blockES := false, decLog := c.decLog ++ [c.block], blockRefuse := 0 } k h
      split
      · exact win_rstClose _ _ _ _ he hs
      · split
        · split
          · exact win_rstClose _ _ _ _ he hs
          · exact win_commitTail _ _ _ _ _ _ _ he hs
        · split
          · exact win_rstClose _ _ _ _ he hs
          · exact win_put _ _ _ he hs
          · exact win_commitTail _ _ _ _ _ _ _ he hs

theorem win_contBranch (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h : WinInv c) :
    WinInv (contBranch fx dec c f).1 := by
  unfold contBranch
  split
  · exact win_connErr _ _ h
  · simp only
    split
    · exact win_connErr _ _ h
    · split
      · exact win_connErr _ _ h
      · split
        · exact win_connErr _ _ h
        · split
          · exact h
          · exact win_commit _ _ _ _ h

theorem win_shapeCheck (fx : Fix) (c : Conn) (f : Fr) (h : WinInv c) : WinO (shapeCheck fx c f) := by
  unfold shapeCheck
  repeat' split
  all_goals first
    | trivial
    | exact win_connErr _ _ h
    | exact win_closeIfKnown _ _ (win_rstC _ _ h)

theorem win_idCheck (fx : Fix) (c : Conn) (f : Fr) (h : WinInv c) : WinS (idCheck fx c f) := by
  unfold idCheck
  repeat' split
  all_goals first
    | exact win_connErr _ _ h
    | exact h

theorem sok_applyDelta (d : Int) (l : List (Nat × Stream)) (hl : SOK l) : SOK (applyDelta d l).1 := by
  induction l with
  | nil => simp [applyDelta, SOK]
  | cons p t ih =>
    have hp := hl p (List.mem_cons_self ..)
    have ht : SOK t := fun q hq => hl q (List.mem_cons_of_mem _ hq)
    unfold applyDelta
    split
    · intro q hq
      simp only [List.mem_cons] at hq
      rcases hq with rfl | hq
      · exact hp
      · exact ih ht q hq
    · split
      · exact hl
      · rename_i _ hgt
        intro q hq
        simp only [List.mem_cons] at hq
        rcases hq with rfl | hq
        · simp only; omega
        · exact ih ht q hq

theorem settingError_window (v : Nat) (h : settingError 4 v = 0) : v ≤ 2147483647 := by
  by_cases hv : v ≤ 2147483647
  · exact hv
  · have : v > 2147483647 := by omega
    simp [settingError, this, eFLOW] at h

theorem win_applySetting (c : Conn) (id v : Nat) (h : WinInv c) : WinT (applySetting c id v) := by
  unfold applySetting
  simp only
  split
  · exact win_connErr _ _ h
  · rename_i hbad
    split
    · rename_i h4
      subst h4
      have hv := settingError_window v (by simpa using hbad)
      have hw : WI c.sendW (v : Int) c.streams :=
        ⟨h.1, h.2.1, by omega, by simp [MAX_WINDOW]; omega, h.2.2.2.2⟩
      have hw' : WI c.sendW (v : Int) (applyDelta ((v : Int) - c.peerInitW) c.streams).1 :=
        ⟨hw.1, hw.2.1, hw.2.2.1, hw.2.2.2.1, sok_applyDelta _ _ h.2.2.2.2⟩
      split
      · split
        · exact hw'
        · exact win_connErr _ _ hw'
      · exact hw
    · repeat' split
      all_goals exact h

theorem win_applySettings (c : Conn) (l : List (Nat × Nat)) (h : WinInv c) :
    WinT (applySettings c l) := by
  induction l generalizing c with
  | nil => exact h
  | cons p t ih =>
    obtain ⟨id, v⟩ := p
    have hs := win_applySetting c id v h
    unfold applySettings
    split
    · rename_i c1 hc1; rw [hc1] at hs; exact ih c1 hs
    · rename_i r1 hr1; rw [hr1] at hs; exact hs

theorem win_settingsH (c : Conn) (f : Fr) (h : WinInv c) : WinInv (settingsH c f).1 := by
  unfold settingsH
  split
  · exact h
  · have hs := win_applySettings c f.settings h
    split
    · rename_i c' hc; rw [hc] at hs; exact hs
    · rename_i r hr; rw [hr] at hs; exact hs

theorem win_wuH (fx : Fix) (c : Conn) (f : Fr) (h : WinInv c) : WinInv (wuH fx c f).1 := by
  unfold wuH
  simp only
  split
  · split
    · exact win_connErr _ _ h
    · split
      · exact win_connErr _ _ h
      · exact win_closeIfKnown _ _ (win_rstC _ _ h)
  · split
    · split
      · exact win_connErr _ _ h
      · rename_i hinc _ hle
        have h1 := h.1
        refine ⟨?_, ?_, h.2.2.1, h.2.2.2.1, h.2.2.2.2⟩
        · show 0 ≤ c.sendW + ↑(f.word % 2147483648); omega
        · show c.sendW + ↑(f.word % 2147483648) ≤ MAX_WINDOW; omega
    · split
      · split
        · exact win_connErr _ _ h
        · exact h
      · rename_i s hg
        split
        · exact win_rstClose _ _ _ _ h (win_get c f.sid s h hg)
        · rename_i hle
          exact win_put _ _ _ h (by show s.sendW + ↑(f.word % 2147483648) ≤ MAX_WINDOW; omega)

theorem win_ensure_put (c : Conn) (k : Nat) (h : WinInv c) :
    WinInv (put (ensure c k).1 k (ensure c k).2) :=
  win_put _ _ _ (win_ensure c k h).1 (win_ensure c k h).2

theorem win_headersPre (fx : Fix) (c : Conn) (f : Fr) (h : WinInv c) : WinSN (headersPre fx c f) := by
  unfold headersPre
  repeat' split
  all_goals first
    | exact win_connErr _ _ h
    | trivial

theorem win_headersOpen (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (refuse : Nat) (h : WinInv c) :
    WinInv (headersOpen fx dec c f refuse).1 := by
  unfold headersOpen
  simp only
  have h1 : WinInv (if refuse = 0 then
      put (ensure { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid).1
        f.sid (ensure { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 } f.sid).2
      else { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 }) := by
    split
    · exact win_ensure_put _ _ h
    · exact h
  split
  · exact h1
  · exact win_commit _ _ _ _ h1

theorem win_headersH (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h : WinInv c) :
    WinE (headersH fx dec c f) := by
  have hp : ∀ r, headersPre fx c f = .inl r → WinInv r.1 := by
    intro r hr; have := win_headersPre fx c f h; rw [hr] at this; exact this
  unfold headersH
  repeat' split
  all_goals first
    | exact win_connErr _ _ h
    | trivial
    | exact win_headersOpen _ _ _ _ _ h
    | (apply hp; assumption)

theorem win_dataCredit (c : Conn) (f : Fr) (n : Nat) (h : WinInv c) : WinInv (dataCredit c f n).1 := by
  unfold dataCredit
  split
  · simp only
    split
    · exact h
    · split <;> exact h
  · exact h

theorem win_dataFinish (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (cr : Nat) (h : WinInv c)
    (hs : s.sendW ≤ MAX_WINDOW) : WinInv (dataFinish fx c f s cr).1 := by
  unfold dataFinish
  split
  · exact win_rstCloseX _ _ _ _ _ h hs
  · exact win_dataCredit _ _ _ (win_put _ _ _ h (by split <;> exact hs))

theorem win_dataAccept (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (n : Nat) (h : WinInv c)
    (hs : s.sendW ≤ MAX_WINDOW) : WinInv (dataAccept fx c f s n).1 := by
  unfold dataAccept
  split
  · exact win_rstCloseX _ _ _ _ _ h hs
  · exact win_dataFinish _ _ _ _ _ (by split <;> exact h) hs

theorem win_dataBody (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (n : Nat) (h : WinInv c)
    (hs : s.sendW ≤ MAX_WINDOW) : WinInv (dataBody fx c f s n).1 := by
  unfold dataBody
  repeat' split
  all_goals first
    | exact win_rstCloseX _ _ _ _ _ h hs
    | exact win_dataAccept _ _ _ _ _ h hs

theorem win_dataH (fx : Fix) (c : Conn) (f : Fr) (h : WinInv c) : WinInv (dataH fx c f).1 := by
  unfold dataH
  split
  · exact h
  · split
    · split <;> exact win_connErr _ _ h
    · rename_i s hg
      have hs := win_get c f.sid s h hg
      repeat' split
      all_goals first
        | exact win_connErr _ _ h
        | exact win_dataBody _ _ _ _ _ h hs

theorem win_rstH (c : Conn) (f : Fr) (h : WinInv c) : WinInv (rstH c f).1 := by
  unfold rstH rstFlood
  have := win_closeIfKnown c f.sid h
  split <;> exact this

theorem win_dispatch (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h : WinInv c) :
    WinE (dispatch fx dec c f) := by
  unfold dispatch
  split
  · exact win_settingsH c f h
  · split
    · show WinInv _; split <;> exact h
    · split
      · exact win_wuH fx c f h
      · split
        · exact win_headersH fx dec c f h
        · split
          · exact win_connErr _ _ h
          · split
            · exact win_dataH fx c f h
            · split
              · exact h
              · split
                · exact win_rstH c f h
                · exact h

theorem win_handle (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h : WinInv c) :
    WinE (handle fx dec c f) := by
  unfold handle
  split
  · exact win_contBranch fx dec c f h
  · have hs := win_shapeCheck fx c f h
    split
    · rename_i r' hr; rw [hr] at hs; exact hs
    · split
      · exact win_connErr _ _ h
      · have hi := win_idCheck fx c f h
        split
        · rename_i r' hid; rw [hid] at hi; exact hi
        · rename_i c' hid; rw [hid] at hi; exact win_dispatch fx dec c' f hi

theorem win_handleW (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h : WinInv c) :
    WinE (handleW fx dec c f) := by
  unfold handleW
  split
  · exact win_connErr _ _ h
  · have hh := win_handle fx dec c f h
    split
    · rename_i c' o heq; rw [heq] at hh; exact hh
    · trivial

theorem win_prefaceGate (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h : WinInv c) :
    WinE (prefaceGate fx dec c f) := by
  unfold prefaceGate
  split
  · split
    · exact win_handleW fx dec _ f h
    · split
      · exact win_connErr _ _ h
      · exact win_handleW fx dec c f h
  · exact win_handleW fx dec c f h

theorem win_driveFrame (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h : WinInv c) :
    WinE (driveFrame fx dec c f) := by
  unfold driveFrame
  split
  · exact h
  · split
    · exact win_connErr _ _ h
    · exact win_prefaceGate fx dec c f h

theorem win_driveClient (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h : WinInv c) :
    WinE (driveClient fx dec c f) := by
  unfold driveClient
  split
  · split
    · exact win_connErr _ _ h
    · trivial
  · split
    · exact h
    · exact win_prefaceGate fx dec c f h

theorem win_send (c : Conn) (k n : Nat) (h : WinInv c) : WinInv (send c k n).1 := by
  unfold send
  split
  · exact h
  · rename_i s hg
    have hs := win_get c k s h hg
    have h1 := h.1
    have h2 := h.2.1
    simp only
    split
    · exact h
    · rename_i hb
      have hble : budget c s ≤ c.sendW := by unfold budget; split <;> omega
      have hsent : ∀ m : Nat, (m : Int) ≤ c.sendW →
          WinInv (put { c with sendW := c.sendW - m } k { s with sendW := s.sendW - m }) := by
        intro m hm
        apply win_put _ _ _ _ (by show s.sendW - ↑m ≤ MAX_WINDOW; omega)
        refine ⟨?_, ?_, h.2.2.1, h.2.2.2.1, h.2.2.2.2⟩
        · show 0 ≤ c.sendW - ↑m; omega
        · show c.sendW - ↑m ≤ MAX_WINDOW; omega
      apply hsent
      generalize budget c s = b at hb hble ⊢
      split <;> omega

theorem win_respond (c : Conn) (k n : Nat) (h : WinInv c) : WinInv (respond c k n).1 := by
  unfold respond
  split
  · exact h
  · rename_i s hg
    have hs := win_get c k s h hg
    have h1 := h.1
    have h2 := h.2.1
    split
    · exact h
    · rename_i hn
      have hn' : n = 0 ∨ (n : Int) ≤ c.sendW := by
        by_cases hn0 : n > 0
        · right
          simp only [hn0, decide_true, Bool.true_and, Bool.or_eq_true, decide_eq_true_eq,
            not_or] at hn
          have := hn.1
          unfold budget at this
          split at this <;> omega
        · left; omega
      apply win_put _ _ _ _ (by show s.sendW - ↑n ≤ MAX_WINDOW; omega)
      refine ⟨?_, ?_, h.2.2.1, h.2.2.2.1, h.2.2.2.2⟩
      · show 0 ≤ c.sendW - ↑n; omega
      · show c.sendW - ↑n ≤ MAX_WINDOW; omega

theorem win_step (fx : Fix) (dec : Dec) (c : Conn) (e : Ev) (r : Conn × List Out) (h : WinInv c)
    (hr : step fx dec c e = .ok r) : WinInv r.1 := by
  cases e with
  | frame f =>
    simp only [step] at hr
    split at hr
    · have := win_driveClient fx dec c f h
      rw [hr] at this; exact this
    · have := win_driveFrame fx dec c f h
      rw [hr] at this; exact this
  | release n =>
    simp only [step, Except.ok.injEq] at hr; subst hr
    unfold release; simp only; split <;> exact h
  | respond k n => simp only [step, Except.ok.injEq] at hr; subst hr; exact win_respond c k n h
  | send k n => simp only [step, Except.ok.injEq] at hr; subst hr; exact win_send c k n h
  | openLocal k es =>
    simp only [step, Except.ok.injEq] at hr; subst hr
    exact win_put _ _ _ h h.2.2.2.1
  | pop k =>
    simp only [step, Except.ok.injEq] at hr; subst hr
    exact ⟨h.1, h.2.1, h.2.2.1, h.2.2.2.1, sok_filter _ _ h.2.2.2.2⟩
  | endLocal k em =>
    simp only [step, Except.ok.injEq] at hr; subst hr
    unfold endLocal; split
    · exact h
    · rename_i s hg
      split
      · exact h
      · exact win_put _ _ _ h (win_get c k s h hg)
  | stream k =>
    simp only [step, Except.ok.injEq] at hr; subst hr
    unfold enableStream; split
    · exact h
    · rename_i s hg; exact win_put _ _ _ h (win_get c k s h hg)
  | drain k =>
    simp only [step, Except.ok.injEq] at hr; subst hr
    unfold drain; split
    · exact h
    · split
      · exact h
      · rename_i s hg; exact win_put _ _ _ h (win_get c k s h hg)

/-- **Window bound.** In every reachable state of every fix selection,
the connection send window is in `0 .. 2^31-1`, the peer's initial window
is in `0 .. 2^31-1`, and every stream send window is at most `2^31-1`. -/
theorem win_reachable (fx : Fix) : ∀ c, (lts fx Fresh).Reachable c → WinInv c := by
  have hI : (lts fx Fresh).Inductive WinInv :=
    ⟨fun s h => fresh_win s h, fun s l s' hp ⟨o, hs⟩ => win_step fx l.1 s l.2 (s', o) hp hs⟩
  exact hI.reachable

end Flare.L3.H2.Conn
