import Flare.L3_Protocol.H2.StreamTable
import Flare.L3_Protocol.H2.StreamSpec
import Flare.L3_Protocol.H2.ConnSeq

/-!
# §5.1 refinement: abstraction, verdicts, invariant

The abstraction `abs c : Nat → SS` maps the connection model to the §5.1
spec state of every stream id:

* an id in the stream table has the state recorded there;
* an id not in the table is *idle* if it was never opened: above our
  highest opened id or even (client role, push disabled), above the
  peer's highest id or even (server role); otherwise it is *closed*
  (opened earlier, then dropped or pruned, or implicitly closed by a
  higher id, §5.1.1).

The verdict of a reply on stream `k` (`verdict`) is read off the frames
flare queues: a GOAWAY is a connection error with its code, else a
RST_STREAM on `k` is a stream error, else the frame was accepted.

`F` is the model with every fix that touches stream state; `Inv` is the
invariant of its reachable, live states.
-/
namespace Flare.L3.H2.Refine
open Flare.L3.H2.Conn Flare.L3.H2.StreamSpec

attribute [local simp] ePROTOCOL eSTREAM_CLOSED eFLOW eCALM eCOMPRESSION eFRAME_SIZE eREFUSED eNO

/-- The fixed model: every fix that bears on §5.1. -/
def F : Fix :=
  { h2_02 := true, h2_03 := true, h2_04 := true, h2_06 := true, h2_08 := true, h2_11 := true,
    h2_12 := true, h2_13 := true, h2_14 := true, h2_15 := true, h2_16 := true, h2_17 := true,
    h2_18 := true, h2_19 := true, h2_20 := true }

def ofSt : St → SS
  | .idle => .idle
  | .open_ => .open_
  | .hcl => .hcl
  | .hcr => .hcr
  | .closed => .closed

def idleAbs (c : Conn) (k : Nat) : Bool :=
  if c.isClient then decide (k > c.maxLocalSid) || k % 2 == 0
  else decide (k > c.lastPeer) || k % 2 == 0

theorem isIdleId_F (c : Conn) (k : Nat) : isIdleId F c k = idleAbs c k := by
  unfold isIdleId idleAbs F; cases c.isClient <;> simp

/-- The fields the abstraction and the invariant read. -/
structure IV where
  streams : List (Nat × Stream)
  isClient : Bool
  lastPeer : Nat
  maxLocalSid : Nat
  continuing : Nat
  blockRefuse : Nat
  resetByUs : List Nat
  goawaySent : Bool

def iv (c : Conn) : IV :=
  ⟨c.streams, c.isClient, c.lastPeer, c.maxLocalSid, c.continuing, c.blockRefuse, c.resetByUs, c.goawaySent⟩

def abs (c : Conn) (k : Nat) : SS :=
  match get c k with
  | some s => ofSt s.state
  | none => if idleAbs c k then .idle else .closed

def room (c : Conn) : Bool := c.isClient || decide (activeCount c < c.maxConcurrent)

def pid (c : Conn) (k : Nat) : Bool := peerId c.isClient k

/-! ## Verdicts -/

def gaCode : List Out → Option Nat
  | [] => none
  | .goaway _ e :: _ => some e
  | _ :: t => gaCode t

def rsCode (k : Nat) : List Out → Option Nat
  | [] => none
  | .rst j e :: t => if j = k then some e else rsCode k t
  | _ :: t => rsCode k t

def verdict (o : List Out) (k : Nat) : V :=
  match gaCode o with
  | some e => .conn e
  | none =>
    match rsCode k o with
    | some e => .strm e
    | none => .ok

/-! ## Invariant -/

def keyOK (c : Conn) (k : Nat) : Prop :=
  k % 2 = 1 ∧ (if c.isClient then k ≤ c.maxLocalSid else k ≤ c.lastPeer)

structure Inv (c : Conn) : Prop where
  nd : NoDupK c.streams
  keys : ∀ k s, get c k = some s → keyOK c k
  idle : ∀ k s, get c k = some s → s.state = .idle →
    c.continuing = k ∧ c.isClient = false ∧ c.blockRefuse = 0
  srv : c.isClient = false → ∀ k s, get c k = some s → s.state ≠ .hcl
  blk0 : c.continuing ≠ 0 → c.blockRefuse = 0 →
    ∃ s, get c c.continuing = some s ∧ (s.state = .idle ∨ s.state = .open_ ∨ s.state = .hcl)
  blk1 : c.continuing ≠ 0 → c.blockRefuse ≠ 0 →
    abs c c.continuing = .closed ∨ abs c c.continuing = .open_
  cliRef : c.isClient = true → c.blockRefuse = 0
  rbu : ∀ k ∈ c.resetByUs, abs c k = .closed
  ga : c.goawaySent = false

/-- What a live reply must satisfy besides the verdict: our stream
WINDOW_UPDATEs go to streams that may receive them, RST_STREAM only on
the frame's stream, no DATA. -/
def Sends (k : Nat) (r : Conn × List Out) : Prop :=
  (∀ j n, Out.wu j n ∈ r.2 → j ≠ 0 → wuOK (abs r.1 j) = true) ∧
  (∀ j e, Out.rst j e ∈ r.2 → j = k) ∧
  (∀ j n, Out.data j n ∉ r.2)

/-- The §5.1 obligation for a reply `r` to a frame the spec reads as `rk`
on stream `k`, from `c`. -/
def SGoodV (c : Conn) (k : Nat) (rk : RK) (v : V) (r : Conn × List Out) : Prop :=
  match v with
  | .conn e => (connAny e || connCodes (pid c k) (abs c k) rk e) = true
  | v => recvOK (pid c k) (room c) (abs c k) rk v (abs r.1 k) = true ∧
      Others (abs c) (abs r.1) k ∧ Sends k r ∧ Inv r.1

def SGood (c : Conn) (k : Nat) (rk : RK) (r : Conn × List Out) : Prop :=
  SGoodV c k rk (verdict r.2 k) r

/-! ## Congruences -/

theorem get_congr {c c' : Conn} (h : c'.streams = c.streams) : get c' = get c := by
  funext k; unfold Flare.L3.H2.Conn.get; rw [h]

theorem abs_congr {c c' : Conn} (h : iv c' = iv c) : abs c' = abs c := by
  simp only [iv, IV.mk.injEq] at h
  obtain ⟨h1, h2, h3, h4, -, -, -, -⟩ := h
  funext k; unfold abs idleAbs; rw [get_congr h1, h2, h3, h4]

theorem room_congr {c c' : Conn} (h1 : c'.streams = c.streams) (h2 : c'.isClient = c.isClient)
    (h3 : c'.maxConcurrent = c.maxConcurrent) : room c' = room c := by
  unfold room activeCount; rw [h1, h2, h3]

theorem inv_congr {c c' : Conn} (h : iv c' = iv c) (hI : Inv c) : Inv c' := by
  have ha := abs_congr h
  simp only [iv, IV.mk.injEq] at h
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := h
  have hg := get_congr h1
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, by rw [h8]; exact ga⟩
  · rw [h1]; exact nd
  · intro k s hs; rw [hg] at hs; have := keys k s hs; unfold keyOK at *; rw [h2, h3, h4]; exact this
  · intro k s hs he; rw [hg] at hs; rw [h5, h2, h6]; exact idle k s hs he
  · intro hc k s hs; rw [hg] at hs; exact srv (h2 ▸ hc) k s hs
  · intro a b; rw [h5] at a ⊢; rw [h6] at b; rw [hg]; exact blk0 a b
  · intro a b; rw [h5] at a ⊢; rw [h6] at b; rw [ha]; exact blk1 a b
  · intro a; rw [h6]; exact cliRef (h2 ▸ a)
  · intro k hk; rw [h7] at hk; rw [ha]; exact rbu k hk

theorem sends_congr {k : Nat} {c c' : Conn} {o : List Out} (h : iv c' = iv c) (hs : Sends k (c, o)) :
    Sends k (c', o) := by
  obtain ⟨a, b, d⟩ := hs
  exact ⟨fun j n hj h0 => by rw [abs_congr h]; exact a j n hj h0, b, d⟩

/-! ## The abstraction under table updates -/

theorem abs_put_self (c : Conn) (k : Nat) (s : Stream) : abs (put c k s) k = ofSt s.state := by
  simp [abs]

theorem abs_put_other (c : Conn) (k j : Nat) (s : Stream) (h : j ≠ k) :
    abs (put c k s) j = abs c j := by
  simp only [abs, get_put_other _ _ _ _ h]; rfl

theorem abs_put (c : Conn) (k j : Nat) (s : Stream) :
    abs (put c k s) j = if j = k then ofSt s.state else abs c j := by
  by_cases h : j = k
  · subst h; simp [abs_put_self]
  · simp [h, abs_put_other _ _ _ _ h]

theorem abs_some {c : Conn} {k : Nat} {s : Stream} (h : get c k = some s) : abs c k = ofSt s.state := by
  simp [abs, h]

theorem abs_none {c : Conn} {k : Nat} (h : get c k = none) :
    abs c k = if idleAbs c k then .idle else .closed := by
  simp [abs, h]

theorem idleAbs_key {c : Conn} {k : Nat} (h : keyOK c k) : idleAbs c k = false := by
  unfold keyOK at h; unfold idleAbs
  cases hc : c.isClient <;> simp only [hc, if_true, if_false, Bool.false_eq_true] at h ⊢ <;>
    simp <;> omega

theorem abs_ensure (c : Conn) (k : Nat) (hI : Inv c) : abs (ensure c k).1 = abs c := by
  unfold ensure
  split
  · rfl
  · split
    · funext j
      have hg := get_filter c (fun p => p.2.state != .closed) j hI.nd
      unfold abs
      have hcl : idleAbs { c with streams := c.streams.filter (fun p => p.2.state != .closed) } j =
          idleAbs c j := rfl
      rw [hg, hcl]
      cases hj : get c j with
      | none => rfl
      | some s =>
        simp only
        by_cases hs : s.state = .closed
        · simp only [hs, bne_self_eq_false, Bool.false_eq_true, if_false]
          rw [idleAbs_key (hI.keys j s hj)]; rfl
        · have : (s.state != .closed) = true := by simpa using hs
          simp [this]
    · rfl

theorem ensure_snd_get (c : Conn) (k : Nat) (s : Stream) (h : get c k = some s) : ensure c k = (c, s) := by
  simp [ensure, h]

theorem inv_ensure (c : Conn) (k : Nat) (hI : Inv c) : Inv (ensure c k).1 := by
  unfold ensure
  split
  · exact hI
  · split
    · have ha := abs_ensure c k hI
      simp only [ensure] at ha
      rename_i hnone _
      rw [hnone] at ha; simp only [*, if_true] at ha
      have hg : ∀ j, get { c with streams := c.streams.filter (fun p => p.2.state != .closed) } j =
          match get c j with | some s => if (s.state != .closed) = true then some s else none | none => none :=
        fun j => get_filter c _ j hI.nd
      have hsub : ∀ j s, get { c with streams := c.streams.filter (fun p => p.2.state != .closed) } j = some s →
          get c j = some s := by
        intro j s h; rw [hg] at h
        cases hj : get c j with
        | none => rw [hj] at h; cases h
        | some s' => rw [hj] at h; simp only at h; split at h <;> simp_all
      obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
      refine ⟨nodupK_filter _ _ nd, fun j s h => keys j s (hsub j s h),
        fun j s h => idle j s (hsub j s h), fun hc j s h => srv hc j s (hsub j s h), ?_,
        fun a b => by rw [ha]; exact blk1 a b, cliRef, fun j hj => by rw [ha]; exact rbu j hj, ga⟩
      intro a b
      obtain ⟨s, hs, hst⟩ := blk0 a b
      refine ⟨s, ?_, hst⟩
      rw [hg]; simp only [hs]
      have : (s.state != .closed) = true := by rcases hst with h | h | h <;> simp [h]
      simp [this]
    · exact hI

/-! ## Invariant under table updates -/

theorem inv_put (c : Conn) (k : Nat) (s : Stream) (hI : Inv c) (hk : keyOK c k)
    (hidle : s.state = .idle → c.continuing = k ∧ c.isClient = false ∧ c.blockRefuse = 0)
    (hsrv : c.isClient = false → s.state ≠ .hcl)
    (hblk0 : c.continuing = k → c.blockRefuse = 0 → s.state = .idle ∨ s.state = .open_ ∨ s.state = .hcl)
    (hblk1 : c.continuing = k → c.blockRefuse ≠ 0 → ofSt s.state = .closed ∨ ofSt s.state = .open_)
    (hrbu : k ∈ c.resetByUs → s.state = .closed) : Inv (put c k s) := by
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
  refine ⟨nodupK_putL _ _ _ nd, ?_, ?_, ?_, ?_, ?_, cliRef, ?_, ga⟩
  · intro j t h
    rw [get_put] at h
    split at h
    · rename_i hj; subst hj; exact hk
    · exact keys j t h
  · intro j t h he
    rw [get_put] at h
    split at h
    · rename_i hj; subst hj; cases h; exact hidle he
    · exact idle j t h he
  · intro hc j t h
    rw [get_put] at h
    split at h
    · cases h; exact hsrv hc
    · exact srv hc j t h
  · intro a b
    show ∃ t, get (put c k s) c.continuing = some t ∧ _
    rw [get_put]
    split
    · rename_i hj; exact ⟨s, rfl, hblk0 hj b⟩
    · exact blk0 a b
  · intro a b
    show abs (put c k s) c.continuing = _ ∨ abs (put c k s) c.continuing = _
    rw [abs_put]
    split
    · rename_i hj; exact hblk1 hj b
    · exact blk1 a b
  · intro j hj
    rw [abs_put]
    split
    · rename_i h; subst h; rw [hrbu hj]; rfl
    · exact rbu j hj

/-- `inv_put` while no header block is open. -/
theorem inv_put0 (c : Conn) (k : Nat) (s : Stream) (hI : Inv c) (hk : keyOK c k) (h0 : c.continuing = 0)
    (hidle : s.state ≠ .idle) (hsrv : c.isClient = false → s.state ≠ .hcl)
    (hrbu : k ∈ c.resetByUs → s.state = .closed) : Inv (put c k s) := by
  have hk0 : k ≠ 0 := by unfold keyOK at hk; omega
  refine inv_put c k s hI hk (fun h => absurd h hidle) hsrv ?_ ?_ hrbu <;>
    intro h <;> exact absurd (h0 ▸ h).symm hk0

theorem rstC_iv (c : Conn) (k : Nat) :
    iv (rstC c k) = { iv c with resetByUs := (rstC c k).resetByUs } := rfl

theorem rstC_rbu (c : Conn) (k j : Nat) (h : j ∈ (rstC c k).resetByUs) : j ∈ c.resetByUs ∨ j = k := by
  unfold rstC at h; simp only at h
  split at h
  · have := List.mem_of_mem_tail h; simpa using this
  · simpa using h

theorem abs_rstC (c : Conn) (k : Nat) : abs (rstC c k) = abs c := rfl

/-- Close `k` (it is in the table) and remember it as reset by us. -/
theorem inv_rstClose (c : Conn) (k : Nat) (s : Stream) (hI : Inv c) (hk : keyOK c k)
    (h0 : c.continuing = 0) : Inv (put (rstC c k) k { s with state := .closed }) := by
  have hk0 : k ≠ 0 := by unfold keyOK at hk; omega
  obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
  have hI' : Inv (rstC c k) ∨ True := Or.inr trivial
  clear hI'
  refine ⟨nodupK_putL _ _ _ nd, ?_, ?_, ?_, ?_, ?_, cliRef, ?_, ga⟩
  · intro j t h
    rw [get_put] at h
    split at h
    · rename_i hj; subst hj; exact hk
    · exact keys j t h
  · intro j t h he
    rw [get_put] at h
    split at h
    · cases h; cases he
    · exact idle j t h he
  · intro hc j t h
    rw [get_put] at h
    split at h
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

/-- `closeIfKnown (rstC c k) k` on a stream that is in the table or
abstractly closed. -/
theorem inv_closeRst (c : Conn) (k : Nat) (hI : Inv c) (h0 : c.continuing = 0)
    (hk : (∃ s, get c k = some s) ∨ abs c k = .closed) : Inv (closeIfKnown (rstC c k) k) := by
  unfold closeIfKnown
  have hgk : get (rstC c k) k = get c k := rfl
  rw [hgk]
  cases hg : get c k with
  | some s =>
    simp only
    exact inv_rstClose c k s hI (hI.keys k s hg) h0
  | none =>
    simp only
    have hcl : abs c k = .closed := by
      rcases hk with ⟨s, hs⟩ | h
      · rw [hg] at hs; cases hs
      · exact h
    obtain ⟨nd, keys, idle, srv, blk0, blk1, cliRef, rbu, ga⟩ := hI
    refine ⟨nd, keys, idle, srv, blk0, ?_, cliRef, ?_, ga⟩
    · intro a; exact absurd h0 a
    · intro j hj
      rw [abs_rstC]
      rcases rstC_rbu c k j hj with hj | hj
      · exact rbu j hj
      · subst hj; exact hcl

theorem abs_closeRst (c : Conn) (k : Nat) :
    abs (closeIfKnown (rstC c k) k) =
      fun j => if j = k ∧ (get c k).isSome then .closed else abs c j := by
  funext j
  unfold closeIfKnown
  have hgk : get (rstC c k) k = get c k := rfl
  rw [hgk]
  cases hg : get c k with
  | some s =>
    simp only [Option.isSome_some, and_true]
    rw [abs_put, abs_rstC]; split <;> rfl
  | none => simp [abs_rstC]

theorem abs_closeIfKnown (c : Conn) (k : Nat) :
    abs (closeIfKnown c k) = fun j => if j = k ∧ (get c k).isSome then .closed else abs c j := by
  funext j
  unfold closeIfKnown
  cases hg : get c k with
  | some s => simp only [Option.isSome_some, and_true]; rw [abs_put]; split <;> rfl
  | none => simp

/-! ## Verdict lemmas -/

theorem verdict_connErr (c : Conn) (e k : Nat) (hg : c.goawaySent = false) :
    verdict (connErr c e).2 k = .conn e := by
  simp [connErr, hg, verdict, gaCode]

theorem sgood_conn (c : Conn) (k : Nat) (rk : RK) (e : Nat) (hg : c.goawaySent = false)
    (h : (connAny e || connCodes (pid c k) (abs c k) rk e) = true) : SGood c k rk (connErr c e) := by
  unfold SGood; rw [verdict_connErr c e k hg]; exact h

/-- Others are untouched. -/
theorem others_refl (M : Nat → SS) (k : Nat) : Others M M k := fun _ _ => Or.inl rfl

theorem others_put (c : Conn) (k : Nat) (s : Stream) : Others (abs c) (abs (put c k s)) k :=
  fun j hj => Or.inl (abs_put_other c k j s hj)

theorem others_trans {M1 M2 M3 : Nat → SS} {k : Nat} (h1 : Others M1 M2 k) (h2 : ∀ j, j ≠ k → M3 j = M2 j) :
    Others M1 M3 k := by
  intro j hj; rw [h2 j hj]; exact h1 j hj

theorem sends_nil (k : Nat) (c : Conn) : Sends k (c, []) := by
  refine ⟨?_, ?_, ?_⟩ <;> simp

end Flare.L3.H2.Refine
