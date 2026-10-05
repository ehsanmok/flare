import Flare.L3_Protocol.H2.HpackTable

/-!
# Encoder/decoder table synchronisation (RFC 7541 §2.3.2, §4)

HPACK only works if the decoder's dynamic table mirrors the encoder's
entry for entry. The peer's encoder indexes the *wire octets*; flare's
decoder stores `_octets_to_string(octets)` (`hpack.mojo:48-76`). Before the
HPACK-01 fix that rewrote any block containing a byte `≥ 0x80` with
`utf8_lossy_string` (`octetsToStringOld`); it now keeps the octets
unchanged (`octetsToString`, `sync_exact_shipped`).

Model: `conv : Bytes → Bytes` is the octet conversion. The peer's table is
the RFC 7541 table over raw entries (`specInsert`); flare's is `Table`
over converted entries.

* `sync_exact`: if `conv` fixes every inserted entry (always true for
  ASCII, and for valid UTF-8), flare's table equals the peer's at every
  step, so every index resolves to the peer's header.
* `prefix_inv`: for *any* length-non-decreasing `conv` (which
  `utf8Lossy` is: `utf8Lossy_length_ge`), flare's table is always a
  converted *prefix* of the peer's. Consequently `lookup_sound`: an index
  flare resolves names the peer's entry at that index (modulo
  conversion). The suspected "wrong header" outcome of HP-1 is therefore
  impossible; the actual outcome is an out-of-range index, i.e.
  COMPRESSION_ERROR on a legal block (see `Flare.Bugs.HPACK_01`).
-/
namespace Flare.L3.H2.Hpack

/-! ## `_octets_to_string` and a local `utf8_lossy_string` -/

def isCont (b : UInt8) : Bool := 0x80 ≤ b && b ≤ 0xBF

/-- Classification of the sequence at the head of `l`: `(true, n)` is a
well-formed `n`-byte sequence, `(false, n)` a maximal ill-formed subpart of
`n` bytes.
mirrors flare/http/proto/utf8.mojo:31-90 @59bda50 -/
def step : Bytes → Bool × Nat
  | [] => (false, 1)
  | b :: r =>
    if b ≤ 0x7F then (true, 1)
    else if 0xC2 ≤ b ∧ b ≤ 0xDF then
      match r with
      | c :: _ => if isCont c then (true, 2) else (false, 1)
      | [] => (false, 1)
    else if 0xE0 ≤ b ∧ b ≤ 0xEF then
      let lo : UInt8 := if b = 0xE0 then 0xA0 else 0x80
      let hi : UInt8 := if b = 0xED then 0x9F else 0xBF
      match r with
      | c1 :: r1 =>
        if c1 < lo ∨ c1 > hi then (false, 1)
        else match r1 with
          | c2 :: _ => if isCont c2 then (true, 3) else (false, 2)
          | [] => (false, 2)
      | [] => (false, 1)
    else if 0xF0 ≤ b ∧ b ≤ 0xF4 then
      let lo : UInt8 := if b = 0xF0 then 0x90 else 0x80
      let hi : UInt8 := if b = 0xF4 then 0x8F else 0xBF
      match r with
      | c1 :: r1 =>
        if c1 < lo ∨ c1 > hi then (false, 1)
        else match r1 with
          | c2 :: r2 =>
            if !isCont c2 then (false, 2)
            else match r2 with
              | c3 :: _ => if isCont c3 then (true, 4) else (false, 3)
              | [] => (false, 3)
          | [] => (false, 2)
      | [] => (false, 1)
    else (false, 1)

theorem step_bounds (b : UInt8) (r : Bytes) :
    1 ≤ (step (b :: r)).2 ∧ (step (b :: r)).2 ≤ (b :: r).length ∧
    ((step (b :: r)).1 = false → (step (b :: r)).2 ≤ 3) := by
  unfold step
  repeat' (first | split | simp_all | omega)

/-- `utf8_lossy_string` as a single pass (its first phase only locates the
first bad index; copying well-formed sequences from there is what the
second phase does, so one pass computes the same bytes).
mirrors flare/http/proto/utf8.mojo:93-139 @59bda50 -/
def utf8Lossy (l : Bytes) : Bytes :=
  match l with
  | [] => []
  | b :: r =>
    let s := step (b :: r)
    if s.1 then (b :: r).take s.2 ++ utf8Lossy ((b :: r).drop s.2)
    else [0xEF, 0xBF, 0xBD] ++ utf8Lossy ((b :: r).drop s.2)
termination_by l.length
decreasing_by
  all_goals
    have := step_bounds b r
    simp only [List.length_drop, List.length_cons] at *
    omega

theorem utf8Lossy_length_ge (l : Bytes) : l.length ≤ (utf8Lossy l).length := by
  suffices H : ∀ n, ∀ l : Bytes, l.length ≤ n → l.length ≤ (utf8Lossy l).length from
    H _ l (Nat.le_refl _)
  intro n
  induction n with
  | zero => intro l hl; match l with | [] => simp [utf8Lossy] | _ :: _ => simp at hl
  | succ n ih0 =>
    intro l h
    have ih : ∀ m, m < n + 1 → ∀ l' : Bytes, l'.length = m → l'.length ≤ (utf8Lossy l').length :=
      fun m hm l' hl' => ih0 l' (by omega)
    match l with
    | [] => simp [utf8Lossy]
    | b :: r =>
      rw [utf8Lossy]
      have hb := step_bounds b r
      cases hst : step (b :: r) with
      | mk ok w =>
        rw [hst] at hb
        simp only at hb ⊢
        have hrec := ih ((b :: r).drop w).length (by simp at h ⊢; omega) ((b :: r).drop w) rfl
        simp only [List.length_drop, List.length_cons] at hrec h
        cases ok with
        | true =>
          simp only [if_true, List.length_append, List.length_take, List.length_cons]
          omega
        | false =>
          have := hb.2.2 rfl
          simp only [Bool.false_eq_true, if_false, List.length_append, List.length_cons,
            List.length_nil]
          omega

/-- The pre-fix conversion. mirrors flare/http2/hpack.mojo:49-63 @59bda50.
Any block containing an octet `≥ 0x80` was rebuilt through
`utf8_lossy_string`, so each malformed octet grew to U+FFFD (3 octets).
Kept so that `Flare.Bugs.HPACK_01` can state the bug about a named
definition; the shipped decoder no longer uses it. -/
def octetsToStringOld (b : Bytes) : Bytes :=
  if b.any (fun x => x ≥ 0x80) then utf8Lossy b else b

theorem octetsToStringOld_length_ge (b : Bytes) : b.length ≤ (octetsToStringOld b).length := by
  unfold octetsToStringOld; split
  · exact utf8Lossy_length_ge b
  · exact Nat.le_refl _

theorem octetsToStringOld_ascii (b : Bytes) (h : ∀ x ∈ b, x < 0x80) :
    octetsToStringOld b = b := by
  unfold octetsToStringOld
  have : b.any (fun x => x ≥ 0x80) = false := by
    rw [List.any_eq_false]; intro x hx; have := h x hx; simp; exact this
  simp [this]

/-- The shipped conversion. mirrors flare/http2/hpack.mojo:48-76 (HPACK-01 fix):
the octets are stored unchanged (`String(unsafe_from_utf8=b)`), so the table
holds exactly the peer's entry sizes (RFC 7541 §4.1). -/
def octetsToString (b : Bytes) : Bytes := b

theorem octetsToString_id (b : Bytes) : octetsToString b = b := rfl

theorem octetsToString_length_ge (b : Bytes) : b.length ≤ (octetsToString b).length :=
  Nat.le_refl _

theorem octetsToString_ascii (b : Bytes) (_h : ∀ x ∈ b, x < 0x80) : octetsToString b = b := rfl

/-! ## Correspondence -/

def convE (c : Bytes → Bytes) (e : Entry) : Entry := ⟨c e.name, c e.value⟩

def Expanding (c : Bytes → Bytes) : Prop := ∀ b, b.length ≤ (c b).length

theorem entrySize_conv (c : Bytes → Bytes) (hc : Expanding c) (e : Entry) :
    entrySize e ≤ entrySize (convE c e) := by
  have := hc e.name; have := hc e.value
  simp [entrySize, convE]; omega

theorem tsize_map_ge (c : Bytes → Bytes) (hc : Expanding c) (l : List Entry) :
    tsize l ≤ tsize (l.map (convE c)) := by
  induction l with
  | nil => simp [tsize]
  | cons x xs ih => have := entrySize_conv c hc x; simp [tsize]; omega

/-- flare's table is the converted image of a prefix of the peer's. -/
def Corr (c : Bytes → Bytes) (peer dec : List Entry) : Prop :=
  ∃ k, dec = (peer.take k).map (convE c)

/-- Eviction keeps the correspondence when flare's room is at least the
peer's. -/
theorem evict_prefix (c : Bytes → Bytes) (hc : Expanding c) (P : List Entry) (k : Nat)
    (rP rD m : Nat) (hr : rP ≤ rD) (hm : rD ≤ m) :
    ∃ j, specEvict ((P.take k).map (convE c)) rD m
      = ((specEvict P rP m).take j).map (convE c) := by
  generalize hD : (P.take k).map (convE c) = D
  have hDlen : D.length = min k P.length := by rw [← hD]; simp
  have hjD := fitLen_le D rD m D.length
  have hfitD := fitLen_fits D rD m D.length hm
  unfold specEvict
  generalize hj : fitLen D rD m D.length = j at hjD hfitD ⊢
  have h1 : D.take j = (P.take j).map (convE c) := by
    rw [← hD, List.map_take, List.take_take, List.map_take, show min j k = j by omega]
  have hfitP : tsize (P.take j) + rP ≤ m := by
    have := tsize_map_ge c hc (P.take j); rw [h1] at hfitD; omega
  have hji := fitLen_max P rP m P.length j (by omega) hfitP
  refine ⟨j, ?_⟩
  rw [h1, List.take_take, show min j (fitLen P rP m P.length) = j by omega]

theorem corr_insert (c : Bytes → Bytes) (hc : Expanding c) (P : List Entry) (t : Table)
    (e : Entry) (hi : Inv t) (hcorr : Corr c P t.dyn) :
    Corr c (specInsert P t.maxSize e) (insert t (convE c e)).dyn := by
  rw [(insert_spec t _ hi.size_eq).1]
  obtain ⟨k, hk⟩ := hcorr
  unfold specInsert
  have hs := entrySize_conv c hc e
  by_cases h1 : entrySize (convE c e) > t.maxSize
  · rw [if_pos h1]; exact ⟨0, by simp⟩
  · rw [if_neg h1, if_neg (by omega), hk]
    obtain ⟨j, hj⟩ := evict_prefix c hc P k (entrySize e) (entrySize (convE c e)) t.maxSize hs
      (by omega)
    exact ⟨j + 1, by rw [hj]; simp⟩

theorem corr_sizeUpdate (c : Bytes → Bytes) (hc : Expanding c) (P : List Entry) (t t' : Table)
    (n : Nat) (hi : Inv t) (hcorr : Corr c P t.dyn) (hu : sizeUpdate t n 0 = .ok t') :
    Corr c (specEvict P 0 n) t'.dyn := by
  unfold sizeUpdate at hu
  split at hu; · cases hu
  simp at hu; subst hu
  have h' : ({ t with maxSize := n } : Table).size = tsize ({ t with maxSize := n } : Table).dyn :=
    hi.size_eq
  rw [evict_spec _ _ h']
  obtain ⟨k, hk⟩ := hcorr
  simp only [hk]
  obtain ⟨j, hj⟩ := evict_prefix c hc P k 0 0 n (Nat.le_refl _) (Nat.zero_le _)
  exact ⟨j, hj⟩

/-! ## Joint LTS over peer-encoder and flare-decoder tables -/

/-- Table-changing HPACK events, as the peer's encoder performs them:
an incremental-indexing insert of raw octets, or a size update. -/
inductive Ev where
  | ins (e : Entry)
  | upd (n : Nat)

/-- Joint state: the peer encoder's table (RFC view over raw octets) and
flare's decoder table. -/
structure Joint where
  peer : List Entry
  peerMax : Nat
  dec : Table

/-- One event applied to both sides; flare stores `conv`-ed octets. A size
update flare rejects stops the run (`none`). -/
def jstep (c : Bytes → Bytes) (j : Joint) : Ev → Option Joint
  | .ins e => some { j with peer := specInsert j.peer j.peerMax e, dec := insert j.dec (convE c e) }
  | .upd n => match sizeUpdate j.dec n 0 with
    | .ok t' => some { peer := specEvict j.peer 0 n, peerMax := n, dec := t' }
    | _ => none

def jinit : Joint := { peer := [], peerMax := 4096, dec := Table.init }

def JInv (c : Bytes → Bytes) (j : Joint) : Prop :=
  Inv j.dec ∧ j.dec.maxSize = j.peerMax ∧ Corr c j.peer j.dec.dyn

theorem jinv_init (c : Bytes → Bytes) : JInv c jinit :=
  ⟨inv_init, rfl, ⟨0, by simp [jinit, Table.init]⟩⟩

theorem jinv_step (c : Bytes → Bytes) (hc : Expanding c) (j j' : Joint) (ev : Ev)
    (h : JInv c j) (hs : jstep c j ev = some j') : JInv c j' := by
  obtain ⟨hi, hm, hcorr⟩ := h
  cases ev with
  | ins e =>
    simp [jstep] at hs; subst hs
    have := insert_spec j.dec (convE c e) hi.size_eq
    refine ⟨inv_insert _ _ hi, by simp [this.2.2.1, hm], ?_⟩
    simp only; rw [← hm]; exact corr_insert c hc _ _ _ hi hcorr
  | upd n =>
    simp only [jstep] at hs
    split at hs
    · rename_i t' hu
      simp at hs; subst hs
      have ⟨hi', hm', _, _⟩ := inv_sizeUpdate _ _ _ _ hi hu
      exact ⟨hi', hm', corr_sizeUpdate c hc _ _ _ _ hi hcorr hu⟩
    · cases hs

/-- The joint system as an LTS (Flare.LTS vocabulary). -/
def jointLTS (c : Bytes → Bytes) : LTS Joint Ev := LTS.ofFn (· = jinit) (jstep c)

/-- **Prefix invariant.** Under any length-non-decreasing octet
conversion, in every reachable state flare's table is a converted prefix
of the peer encoder's table. -/
theorem prefix_inv (c : Bytes → Bytes) (hc : Expanding c) :
    ∀ j, (jointLTS c).Reachable j → JInv c j := by
  have hI : (jointLTS c).Inductive (JInv c) :=
    ⟨fun s h => by subst h; exact jinv_init c, fun s l s' hp hs => jinv_step c hc s s' l hp hs⟩
  exact hI.reachable

/-- **No wrong header.** If flare resolves dynamic index `idx`, the peer's
table holds, at the same index, the entry flare's is converted from. -/
theorem lookup_sound (c : Bytes → Bytes) (hc : Expanding c) (j : Joint)
    (hr : (jointLTS c).Reachable j) (idx : Nat) (e : Entry)
    (hl : lookup j.dec idx = .dyn e) :
    ∃ e₀, j.peer[idx - 62]? = some e₀ ∧ e = convE c e₀ := by
  obtain ⟨_, _, ⟨k, hk⟩⟩ := prefix_inv c hc j hr
  rw [lookup_spec] at hl
  unfold specLookup at hl
  split at hl; · cases hl
  split at hl; · cases hl
  split at hl
  · rename_i hlt
    simp only [Look.dyn.injEq] at hl
    have this : (j.dec.dyn)[idx - 62]? = some (j.dec.dyn[idx - 62]) := List.getElem?_eq_getElem hlt
    rw [hl] at this
    rw [hk] at this
    simp only [List.getElem?_map, List.getElem?_take] at this
    split at this
    · cases h : j.peer[idx - 62]? with
      | none => rw [h] at this; cases this
      | some e₀ =>
        rw [h] at this
        simp only [Option.map_some, Option.some.injEq] at this
        exact ⟨e₀, rfl, this.symm⟩
    · cases this
  · cases hl

/-- **Exact synchronisation.** When every inserted entry is fixed by the
conversion (ASCII octets, `octetsToString_ascii`), flare's table *is* the
peer's RFC 7541 table at every step. -/
theorem sync_exact (c : Bytes → Bytes) (j : Joint) (evs : List Ev) (j' : Joint)
    (hfix : ∀ e, Ev.ins e ∈ evs → convE c e = e)
    (h0 : j.dec.dyn = j.peer ∧ j.dec.maxSize = j.peerMax ∧ Inv j.dec)
    (hr : (jointLTS c).Run j evs j') :
    j'.dec.dyn = j'.peer ∧ j'.dec.maxSize = j'.peerMax ∧ Inv j'.dec := by
  revert hfix h0
  induction hr with
  | nil => intro _ h0; exact h0
  | @cons s s1 s2 l ls hs _ ih =>
    intro hfix h0
    apply ih (fun e he => hfix e (List.mem_cons_of_mem _ he))
    obtain ⟨hd, hm, hi⟩ := h0
    cases l with
    | ins e =>
      simp [jointLTS, LTS.ofFn, jstep] at hs; subst hs
      have := insert_spec s.dec (convE c e) hi.size_eq
      rw [hfix e (List.mem_cons_self ..)] at this ⊢
      exact ⟨by rw [this.1, hd, hm], by simp [this.2.2.1, hm], inv_insert _ _ hi⟩
    | upd n =>
      simp only [jointLTS, LTS.ofFn, jstep] at hs
      split at hs
      · rename_i t' hu
        simp at hs; subst hs
        have ⟨hi', hm', _, _⟩ := inv_sizeUpdate _ _ _ _ hi hu
        refine ⟨?_, hm', hi'⟩
        unfold sizeUpdate at hu
        split at hu; · cases hu
        simp at hu; subst hu
        have h' : ({ s.dec with maxSize := n } : Table).size
            = tsize ({ s.dec with maxSize := n } : Table).dyn := hi.size_eq
        rw [evict_spec _ _ h']; simp [hd]
      · cases hs

/-- With flare's real conversion the joint system satisfies the prefix
invariant (no wrong header can ever be returned). -/
theorem prefix_inv_flare : ∀ j, (jointLTS octetsToString).Reachable j → JInv octetsToString j :=
  prefix_inv octetsToString octetsToString_length_ge

/-- The pre-fix conversion satisfied the same prefix invariant: wrong
headers were never returned, only out-of-range indices (HPACK-01). -/
theorem prefix_inv_old :
    ∀ j, (jointLTS octetsToStringOld).Reachable j → JInv octetsToStringOld j :=
  prefix_inv octetsToStringOld octetsToStringOld_length_ge

/-- **Shipped decoder.** With the byte-exact conversion flare's table equals
the peer's RFC 7541 table at every step, whatever octets the peer sends. -/
theorem sync_exact_shipped (j : Joint) (evs : List Ev) (j' : Joint)
    (h0 : j.dec.dyn = j.peer ∧ j.dec.maxSize = j.peerMax ∧ Inv j.dec)
    (hr : (jointLTS octetsToString).Run j evs j') :
    j'.dec.dyn = j'.peer ∧ j'.dec.maxSize = j'.peerMax ∧ Inv j'.dec :=
  sync_exact octetsToString j evs j' (fun _ _ => rfl) h0 hr

end Flare.L3.H2.Hpack
