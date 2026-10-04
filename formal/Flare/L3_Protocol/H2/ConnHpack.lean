import Flare.L3_Protocol.H2.ConnSeq
import Flare.L3_Protocol.H2.HpackPeer

/-!
# The connection with its stateful HPACK decoder

`Conn.step` takes the decoder outcome as a function `Dec`. Here the
decoder is the real stateful one (`Hpack.decode` over a table that
persists across the connection): at every step `decAt` decodes against
the table left by all blocks the connection has handed over so far
(`Conn.decLog`). `runD` runs the connection with that decoder.

* `seq_runD`: header-block sequencing (`ConnSeq.seq_run`) for any
  state-dependent decoder.
* `decFold_blocks`: decoding the peer's encoded blocks in order gives, for
  every block that decodes, (a view of) exactly the peer's fields.
* `lookup_sound_conn`: **across the whole connection**, while no GOAWAY is
  emitted (server role, or client role with the H2-17 fix), the decoder
  has seen exactly the peer's blocks, and every header list it returned
  is the peer's field list (up to `_octets_to_string`). A desynchronised
  table can only fail a decode, which `commit` answers with
  GOAWAY(COMPRESSION_ERROR) (`commit_fail`).
-/
namespace Flare.L3.H2.Conn
open Flare.L3.H2.Hpack

/-- The HPACK outcome of `HpackDecoder.decode` for `Dec`
(`hpack.mojo:356-441`; a budget error is `.budget`, any other error `.fail`). -/
def decOf (C : Codec) (budget : Nat) (t : Table) : Dec := fun b =>
  match decode C true t b budget with
  | .ok (_, hs) => .ok hs
  | .error .budget => .budget
  | .error _ => .fail

/-- The decoder over a sequence of blocks: the final table (`none` once a
block failed) and each decoded block's header list. -/
def decFold (C : Codec) (budget : Nat) : Table → List Bytes → Option Table × List (List Entry)
  | t, [] => (some t, [])
  | t, b :: bs =>
    match decode C true t b budget with
    | .ok (t', hs) => ((decFold C budget t' bs).1, hs :: (decFold C budget t' bs).2)
    | .error _ => (none, [])

/-- The stateful decoder at connection state `c`. -/
def decAt (C : Codec) (budget : Nat) (c : Conn) : Dec :=
  match (decFold C budget Table.init c.decLog).1 with
  | some t => decOf C budget t
  | none => fun _ => .fail

/-- `run`, with the decoder chosen from the current state. -/
def runD (fx : Fix) (D : Conn → Dec) : Conn → List Ev → Option (Conn × List (Ev × List Out))
  | c, [] => some (c, [])
  | c, e :: es =>
    match step fx (D c) c e with
    | .error _ => none
    | .ok (c', o) =>
      match runD fx D c' es with
      | none => none
      | some (c'', tr) => some (c'', (e, o) :: tr)

theorem runD_const (fx : Fix) (dec : Dec) :
    ∀ (c : Conn) (es : List Ev), runD fx (fun _ => dec) c es = run fx dec c es := by
  intro c es
  induction es generalizing c with
  | nil => rfl
  | cons e es ih => simp only [runD, run, ih]; try rfl

/-- Sequencing for a state-dependent decoder. -/
theorem seq_runD (fx : Fix) (D : Conn → Dec) :
    ∀ (es : List Ev) (c c'' : Conn) (tr : List (Ev × List Out)),
      runD fx D c es = some (c'', tr) → c.goawaySent = false →
      (fx.h2_17 = true ∨ c.isClient = false) → tr.all (fun p => !hasGoaway p.2) = true →
      (pendOf c'', c''.decLog) = rrun (pendOf c, c.decLog) (framesOf es) ∧
      c''.goawaySent = false ∧ c''.isClient = c.isClient := by
  intro es
  induction es with
  | nil =>
    intro c c'' tr hr hg _ _
    simp only [runD, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨rfl, rfl⟩ := hr
    exact ⟨rfl, hg, rfl⟩
  | cons e es ih =>
    intro c c'' tr hr hg hfx hno
    simp only [runD] at hr
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
          rcases seq_step fx (D c) c f (c', o) hg hfx hs with h1 | ⟨h1, h2, h3⟩
          · rw [h1] at hno; cases hno.1
          · have := ih c' c3 tr' hr' (h2.trans hg) (by rw [h3]; exact hfx) hno.2
            refine ⟨?_, this.2.1, this.2.2.trans h3⟩
            rw [this.1]; simp only [framesOf, rrun]; rw [← h1]
        | _ =>
          have hb : HB c c' := hb_local fx (D c) c _ (c', o) (by intro f hf; cases hf) hs
          have hp : pendOf c' = pendOf c := by simp [pendOf, hb.2.1, hb.2.2.1]
          have := ih c' c3 tr' hr' (hb.2.2.2.1.trans hg) (by rw [hb.2.2.2.2]; exact hfx) hno.2
          refine ⟨?_, this.2.1, this.2.2.trans hb.2.2.2.2⟩
          rw [this.1, hp, hb.1]; rfl

/-! ## Blocks in order -/

/-- The peer over a sequence of blocks. -/
def pblocks (p : Peer) : List (List Rep) → Option (Peer × List (List Entry))
  | [] => some (p, [])
  | rs :: rss =>
    match pblock p rs with
    | none => none
    | some (p1, fs) => (pblocks p1 rss).map fun (p2, fss) => (p2, fs :: fss)

/-- Every decoded block is a view of the peer's block at the same position. -/
abbrev Sound (fss got : List (List Entry)) : Prop :=
  ∀ (i : Nat) (hs : List Entry), got[i]? = some hs → ∃ fs, fss[i]? = some fs ∧ Pw fs hs

theorem decFold_blocks (C : Codec) (hC : C.Correct) (henc : Bytes → Bytes)
    (hH : ∀ s, C.huff (henc s) = some s) (budget : Nat) :
    ∀ (rss : List (List Rep)) (p p' : Peer) (fss : List (List Entry)) (t : Table),
      PInv p t → pblocks p rss = some (p', fss) → (∀ rs ∈ rss, ∀ r ∈ rs, RepOK henc r) →
      Sound fss (decFold C budget t (rss.map (encBlock C henc))).2 ∧
      (∀ t', (decFold C budget t (rss.map (encBlock C henc))).1 = some t' →
        PInv p' t' ∧ (decFold C budget t (rss.map (encBlock C henc))).2.length = fss.length) := by
  intro rss
  induction rss with
  | nil =>
    intro p p' fss t hp hb _
    simp only [pblocks, Option.some.injEq, Prod.mk.injEq] at hb
    obtain ⟨rfl, rfl⟩ := hb
    refine ⟨fun i hs h => by simp [decFold] at h, fun t' ht => ?_⟩
    simp only [List.map_nil, decFold, Option.some.injEq] at ht
    subst ht; exact ⟨hp, rfl⟩
  | cons rs rss ih =>
    intro p p' fss t hp hb hv
    simp only [pblocks] at hb
    split at hb
    · cases hb
    · rename_i p1 fs hpb
      cases hb2 : pblocks p1 rss with
      | none => rw [hb2] at hb; cases hb
      | some q =>
        obtain ⟨p2, fss2⟩ := q
        rw [hb2] at hb
        simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hb
        obtain ⟨rfl, rfl⟩ := hb
        simp only [List.map_cons, decFold]
        split
        · rename_i t1 hs hd
          obtain ⟨hpw, hp1⟩ := decode_block C hC henc hH budget rs p p1 fs t t1 hs
            (hv rs (List.mem_cons_self ..)) hp hpb hd
          have := ih p1 p2 fss2 t1 hp1 hb2 (fun rs' h => hv rs' (List.mem_cons_of_mem _ h))
          refine ⟨?_, fun t' ht => ?_⟩
          · intro i hs' h
            cases i with
            | zero => simp at h; subst h; exact ⟨fs, rfl, hpw⟩
            | succ i => simp at h; obtain ⟨fs', h1, h2⟩ := this.1 i hs' h; exact ⟨fs', by simpa using h1, h2⟩
          · have := this.2 t' ht
            exact ⟨this.1, by simp [this.2]⟩
        · exact ⟨fun i hs h => by simp at h, fun t' ht => by cases ht⟩

theorem decFold_append (C : Codec) (budget : Nat) :
    ∀ (t : Table) (l : List Bytes) (b : Bytes) (t1 : Table),
      (decFold C budget t l).1 = some t1 →
      decFold C budget t (l ++ [b]) =
        match decode C true t1 b budget with
        | .ok (t2, hs) => (some t2, (decFold C budget t l).2 ++ [hs])
        | .error _ => (none, (decFold C budget t l).2) := by
  intro t l
  induction l generalizing t with
  | nil =>
    intro b t1 h
    simp only [decFold, Option.some.injEq] at h; subst h
    simp only [List.nil_append, decFold]
  | cons x xs ih =>
    intro b t1 h
    cases hdx : decode C true t x budget with
    | error e => simp [decFold, hdx] at h
    | ok r =>
      obtain ⟨t', hs⟩ := r
      simp only [decFold, hdx, List.cons_append] at h ⊢
      rw [ih t' b t1 h]
      split <;> simp

/-- What the connection receives from `decAt` is exactly the next entry of
the fold over its log (so `Sound` covers every header list `commit` acts
on). -/
theorem decAt_ok (C : Codec) (budget : Nat) (c : Conn) (b : Bytes) (hs : List Entry)
    (h : decAt C budget c b = .ok hs) :
    (decFold C budget Table.init (c.decLog ++ [b])).2 = (decFold C budget Table.init c.decLog).2 ++ [hs] := by
  unfold decAt at h
  cases ht : (decFold C budget Table.init c.decLog).1 with
  | none => rw [ht] at h; cases h
  | some t1 =>
    rw [ht] at h
    rw [decFold_append C budget Table.init c.decLog b t1 ht]
    unfold decOf at h
    simp only at h
    cases hd : decode C true t1 b budget with
    | ok r => obtain ⟨t2, hs2⟩ := r; rw [hd] at h; cases h; rfl
    | error e => rw [hd] at h; cases e <;> cases h

/-- A failed decode is a GOAWAY(COMPRESSION_ERROR) (state.mojo:781-800). -/
theorem commit_fail (fx : Fix) (dec : Dec) (c : Conn) (k : Nat) (h : dec c.block = .fail)
    (hg : c.goawaySent = false) : IsConnError (commit fx dec c k).2 eCOMPRESSION := by
  simp [commit, h, connErr, hg, IsConnError]

/-- **No wrong header, across the whole connection.** Run the connection
with its stateful decoder against a peer that sends the blocks `rss`
(possibly Huffman-coded, fragmented over HEADERS / PUSH_PROMISE /
CONTINUATION). While no GOAWAY is emitted — in server role, or client role
with the H2-17 fix — the decoder has been handed exactly the peer's
blocks, in order, and every header list it returned is the peer's field
list for that block (each octet string verbatim or through
`_octets_to_string`). -/
theorem lookup_sound_conn (fx : Fix) (C : Codec) (hC : C.Correct) (henc : Bytes → Bytes)
    (hH : ∀ s, C.huff (henc s) = some s) (budget : Nat) (es : List Ev) (c0 c'' : Conn)
    (tr : List (Ev × List Out)) (rss : List (List Rep)) (pd : Option (Nat × Bytes)) (p' : Peer)
    (fss : List (List Entry))
    (hr : runD fx (decAt C budget) c0 es = some (c'', tr))
    (hg : c0.goawaySent = false) (hd : c0.decLog = []) (hc : c0.continuing = 0)
    (hfx : fx.h2_17 = true ∨ c0.isClient = false)
    (hno : tr.all (fun p => !hasGoaway p.2) = true)
    (hfr : rrun (none, []) (framesOf es) = (pd, rss.map (encBlock C henc)))
    (hpeer : pblocks Peer.init rss = some (p', fss))
    (hv : ∀ rs ∈ rss, ∀ r ∈ rs, RepOK henc r) :
    c''.decLog = rss.map (encBlock C henc) ∧
    Sound fss (decFold C budget Table.init c''.decLog).2 := by
  have hs := seq_runD fx (decAt C budget) es c0 c'' tr hr hg hfx hno
  have hp0 : pendOf c0 = none := by simp [pendOf, hc]
  rw [hp0, hd, hfr] at hs
  have hlog : c''.decLog = rss.map (encBlock C henc) := (Prod.mk.inj hs.1).2
  refine ⟨hlog, ?_⟩
  rw [hlog]
  exact (decFold_blocks C hC henc hH budget rss Peer.init p' fss Table.init pinv_init hpeer hv).1

end Flare.L3.H2.Conn
