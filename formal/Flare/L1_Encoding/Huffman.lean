import Flare.L1_Encoding.HuffmanTable
import Flare.L1_Encoding.HuffmanRfc
/-!
# HPACK Huffman codec (RFC 7541 §5.2, Appendix B)

Spec (bit strings, MSB first):
* `encode : Bytes → Bytes`: concatenate the Appendix B codes of the input
  bytes, pad with 1-bits to a byte boundary, pack.
* `decodeBits : List Bool → Bytes × Option Error`: repeatedly strip the
  unique code that is a prefix of the remaining bits; EOS is an error; when
  no code matches, the rest must be at most 7 one-bits.
  `decodeFull` runs it on the bytes' bits and `decode : Bytes → Option Bytes`
  keeps only successful results.

Impl (transliterations of flare/http/hpack_huffman.mojo and
flare/http/hpack_huffman_simd.mojo, 64-bit accumulator as `UInt64`):
`encodeImpl`, `decodeImpl` (scalar), `decodeSimdImpl` (256-entry fast table
+ long-code walker + tail walker), `decodeDispatch`.

Main results:
* `decode_eq_some_iff`: `decode x = some out` iff the bits of `x` are the
  codes of `out` followed by at most 7 one-bits (RFC 7541 §5.2: EOS in the
  string, padding longer than 7 bits, and padding that is not a prefix of
  EOS are all errors); `decode_encode`.
* `decodeBits_eos`, `decodeBits_padding_too_long`,
  `decodeBits_invalid_padding`: the error kind for each §5.2 violation.
* `encodeImpl_eq`, `decodeImpl_eq`, `decodeSimdImpl_eq`: the Mojo loops
  compute the spec (so `decodeImpl_encodeImpl` and SIMD/scalar agreement,
  including the partial output on error).
-/
namespace Flare.L1.Huffman

set_option maxRecDepth 100000

/-! ## Bit strings -/

/-- Value of a bit string, most significant bit first. -/
def val : List Bool → Nat
  | [] => 0
  | b :: bs => b.toNat * 2 ^ bs.length + val bs

/-- The low `L` bits of `v`, most significant first. -/
def bitsOf (v : Nat) : Nat → List Bool
  | 0 => []
  | L + 1 => decide (v / 2 ^ L % 2 = 1) :: bitsOf v L

theorem val_lt (r : List Bool) : val r < 2 ^ r.length := by
  induction r with
  | nil => simp [val]
  | cons b bs ih =>
    simp only [val, List.length_cons, Nat.pow_succ]
    have : b.toNat ≤ 1 := by cases b <;> simp
    have : b.toNat * 2 ^ bs.length ≤ 1 * 2 ^ bs.length := Nat.mul_le_mul_right _ this
    omega

theorem val_append (a c : List Bool) : val (a ++ c) = val a * 2 ^ c.length + val c := by
  induction a with
  | nil => simp [val]
  | cons b bs ih =>
    simp only [List.cons_append, val, List.length_append, ih, Nat.pow_add, Nat.add_mul,
      Nat.mul_assoc]
    omega

theorem val_split (r : List Bool) (L : Nat) :
    val r = val (r.take L) * 2 ^ (r.length - L) + val (r.drop L) := by
  have := val_append (r.take L) (r.drop L)
  rw [List.take_append_drop, List.length_drop] at this; exact this

theorem val_take (r : List Bool) (L : Nat) (_h : L ≤ r.length) :
    val (r.take L) = val r / 2 ^ (r.length - L) := by
  have := val_lt (r.drop L)
  rw [List.length_drop] at this
  rw [val_split r L, Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.two_pow_pos _),
    Nat.div_eq_of_lt this]; simp

theorem val_drop (r : List Bool) (L : Nat) : val (r.drop L) = val r % 2 ^ (r.length - L) := by
  have := val_lt (r.drop L)
  rw [List.length_drop] at this
  rw [val_split r L, Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt this]

theorem val_inj (a c : List Bool) (hl : a.length = c.length) (h : val a = val c) : a = c := by
  induction a generalizing c with
  | nil => cases c <;> simp_all
  | cons x xs ih =>
    cases c with
    | nil => simp at hl
    | cons y ys =>
      simp only [List.length_cons, Nat.add_right_cancel_iff] at hl
      simp only [val] at h
      have h1 := val_lt xs
      have h2 := val_lt ys
      have hx : x.toNat = y.toNat := by
        have e1 : (x.toNat * 2 ^ xs.length + val xs) / 2 ^ xs.length = x.toNat := by
          rw [Nat.mul_comm, Nat.mul_add_div (Nat.two_pow_pos _), Nat.div_eq_of_lt h1]; simp
        have e2 : (y.toNat * 2 ^ ys.length + val ys) / 2 ^ ys.length = y.toNat := by
          rw [Nat.mul_comm, Nat.mul_add_div (Nat.two_pow_pos _), Nat.div_eq_of_lt h2]; simp
        rw [← e1, ← e2, h, hl]
      have hxy : x = y := by cases x <;> cases y <;> simp_all
      subst hxy
      rw [ih ys hl (by rw [hl] at h; omega)]

theorem length_bitsOf (v L : Nat) : (bitsOf v L).length = L := by
  induction L <;> simp [bitsOf, *]

theorem val_bitsOf (v L : Nat) : val (bitsOf v L) = v % 2 ^ L := by
  induction L with
  | zero => simp [bitsOf, val, Nat.mod_one]
  | succ L ih =>
    simp only [bitsOf, val, length_bitsOf, ih, Nat.mod_pow_succ]
    have : v / 2 ^ L % 2 < 2 := Nat.mod_lt _ (by omega)
    rcases (by omega : v / 2 ^ L % 2 = 0 ∨ v / 2 ^ L % 2 = 1) with e | e <;> simp [e] <;> omega

theorem bitsOf_val (r : List Bool) : bitsOf (val r) r.length = r :=
  val_inj _ _ (length_bitsOf _ _) (by rw [val_bitsOf, Nat.mod_eq_of_lt (val_lt r)])

theorem val_replicate_true (k : Nat) : val (List.replicate k true) = 2 ^ k - 1 := by
  induction k with
  | zero => rfl
  | succ k ih =>
    simp only [List.replicate_succ, val, List.length_replicate, ih, Bool.toNat_true, Nat.pow_succ]
    have := Nat.two_pow_pos k; omega

theorem val_eq_ones_iff (r : List Bool) : val r = 2 ^ r.length - 1 ↔ r.all id = true := by
  induction r with
  | nil => simp [val]
  | cons b bs ih =>
    have h1 := val_lt bs
    cases b <;> simp only [val, List.length_cons, Nat.pow_succ, Bool.toNat_false,
      Bool.toNat_true, List.all_cons, id, Bool.false_and, Bool.true_and] <;>
      constructor <;> intro h
    · have := Nat.two_pow_pos bs.length; omega
    · simp at h
    · exact ih.mp (by omega)
    · have := ih.mpr h; omega

/-! ## Bytes ↔ bits -/

/-- The bits of a byte string, MSB first. -/
def unpack (bs : Bytes) : List Bool := bs.flatMap fun b => bitsOf b.toNat 8

/-- Group bits into bytes, MSB first (a trailing partial byte is dropped). -/
def pack (r : List Bool) : Bytes :=
  if 8 ≤ r.length then UInt8.ofNat (val (r.take 8)) :: pack (r.drop 8) else []
termination_by r.length

theorem pack_cons8 (a c : List Bool) (h : a.length = 8) :
    pack (a ++ c) = UInt8.ofNat (val a) :: pack c := by
  rw [pack, if_pos (by simp; omega)]
  rw [List.take_left' h, List.drop_left' h]

theorem pack_nil : pack [] = [] := by rw [pack]; simp

theorem pack_append (a c : List Bool) (h : a.length % 8 = 0) :
    pack (a ++ c) = pack a ++ pack c := by
  induction hn : a.length using Nat.strongRecOn generalizing a with
  | _ n ih =>
    by_cases h0 : a.length = 0
    · rw [List.eq_nil_of_length_eq_zero h0, pack_nil]; rfl
    · have h8 : (a.take 8).length = 8 := by simp; omega
      have ha := (List.take_append_drop 8 a).symm
      generalize a.take 8 = a1 at ha h8
      generalize a.drop 8 = a2 at ha
      subst ha
      simp only [List.length_append, h8] at h hn
      rw [List.append_assoc, pack_cons8 _ _ h8, pack_cons8 _ _ h8,
        ih a2.length (by omega) a2 (by omega) rfl, List.cons_append]

theorem unpack_pack (r : List Bool) (h : r.length % 8 = 0) : unpack (pack r) = r := by
  induction hn : r.length using Nat.strongRecOn generalizing r with
  | _ n ih =>
    by_cases h0 : r.length = 0
    · rw [List.eq_nil_of_length_eq_zero h0, pack_nil]; rfl
    · have h8 : (r.take 8).length = 8 := by simp; omega
      have ha := (List.take_append_drop 8 r).symm
      generalize r.take 8 = a1 at ha h8
      generalize r.drop 8 = a2 at ha
      subst ha
      simp only [List.length_append, h8] at h hn
      rw [pack_cons8 _ _ h8]
      simp only [unpack, List.flatMap_cons]
      have hv := val_lt a1
      rw [h8] at hv
      have e : (UInt8.ofNat (val a1)).toNat = val a1 := by
        rw [UInt8.toNat_ofNat']; exact Nat.mod_eq_of_lt hv
      rw [e, ← h8, bitsOf_val, h8]
      congr 1
      exact ih a2.length (by omega) a2 (by omega) rfl

theorem unpack_append (a c : Bytes) : unpack (a ++ c) = unpack a ++ unpack c := by
  simp [unpack, List.flatMap_append]

theorem length_unpack (a : Bytes) : (unpack a).length = 8 * a.length := by
  induction a with
  | nil => rfl
  | cons b bs ih =>
    simp only [unpack, List.flatMap_cons, List.length_append, length_bitsOf] at ih ⊢
    rw [ih]; simp; omega

/-! ## The code -/

/-- `(code, length)` of symbol `s` (`_hpack_table_code`, `_hpack_table_length`). -/
def code (s : Nat) : Nat × Nat := TBL.getD s (0, 0)

/-- The code of symbol `s` as a bit string. -/
def codeBits (s : Nat) : List Bool := bitsOf (code s).1 (code s).2

theorem code_fits (s : Nat) (h : s < 257) :
    5 ≤ (code s).2 ∧ (code s).2 ≤ 30 ∧ (code s).1 < 2 ^ (code s).2 := by
  have hm : TBL.getD s (0, 0) ∈ TBL := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [table_size]; exact h)]
    exact List.getElem_mem _
  exact fits _ hm

theorem length_codeBits (s : Nat) : (codeBits s).length = (code s).2 := length_bitsOf _ _

theorem val_codeBits (s : Nat) (h : s < 257) : val (codeBits s) = (code s).1 := by
  rw [codeBits, val_bitsOf, Nat.mod_eq_of_lt (code_fits s h).2.2]

theorem NotPrefix_symm (a b : Nat × Nat) (h : NotPrefix a b) : NotPrefix b a := by
  unfold NotPrefix at *
  by_cases h1 : a.2 ≤ b.2 <;> by_cases h2 : b.2 ≤ a.2 <;> simp only [h1, h2, if_true, if_false] at h ⊢
  · have e2 : b.2 - a.2 = 0 := by omega
    have e3 : a.2 - b.2 = 0 := by omega
    rw [e2, Nat.shiftRight_zero] at h; rw [e3, Nat.shiftRight_zero]; exact fun x => h x.symm
  · exact h
  · exact h
  · omega

theorem notPrefix_of_ne (s t : Nat) (hs : s < 257) (ht : t < 257) (h : s ≠ t) :
    NotPrefix (code s) (code t) := by
  have hp := List.pairwise_iff_getElem.mp prefix_free
  have hl := table_size
  have gs : code s = TBL[s]'(by omega) := by
    simp [code, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (show s < TBL.length by omega)]
  have gt : code t = TBL[t]'(by omega) := by
    simp [code, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (show t < TBL.length by omega)]
  rw [gs, gt]
  rcases Nat.lt_or_gt_of_ne h with h' | h'
  · exact hp s t (by omega) (by omega) h'
  · exact NotPrefix_symm _ _ (hp t s (by omega) (by omega) h')

theorem code_inj (s t : Nat) (hs : s < 257) (ht : t < 257) (h : code s = code t) : s = t := by
  by_cases e : s = t
  · exact e
  · have := notPrefix_of_ne s t hs ht e
    unfold NotPrefix at this
    rw [h] at this
    simp at this

/-! ## Spec encoder -/

def encodeBits (input : Bytes) : List Bool := input.flatMap fun b => codeBits b.toNat

/-- Number of 1-bits that complete a bit string of length `n` to a byte. -/
def padLen (n : Nat) : Nat := (8 - n % 8) % 8

def padBits (r : List Bool) : List Bool := r ++ List.replicate (padLen r.length) true

/-- RFC 7541 §5.2 Huffman encoding of a string literal. -/
def encode (input : Bytes) : Bytes := pack (padBits (encodeBits input))

theorem padBits_length (r : List Bool) : (padBits r).length % 8 = 0 := by
  simp [padBits, padLen]; omega

/-! ## Spec decoder -/

inductive Error | eosInInput | paddingTooLong | invalidPadding
  deriving DecidableEq, Repr

/-- The symbol whose code is `(c, L)`, if any. -/
def symOf (c L : Nat) : Option Nat := (List.range 257).find? fun s => code s == (c, L)

theorem symOf_some (c L s : Nat) (h : symOf c L = some s) : s < 257 ∧ code s = (c, L) := by
  have h1 := List.find?_some h
  have h2 := List.mem_of_find?_eq_some h
  simp at h1 h2; exact ⟨h2, h1⟩

theorem symOf_of_code (c L s : Nat) (hs : s < 257) (h : code s = (c, L)) : symOf c L = some s := by
  cases e : symOf c L with
  | none =>
    have := List.find?_eq_none.mp e s (by simp; exact hs)
    simp [h] at this
  | some t =>
    obtain ⟨ht, hc⟩ := symOf_some c L t e
    rw [code_inj t s ht hs (hc.trans h.symm)]

/-- Mojo `range(5, 31)`: the code lengths the bit walker tries. -/
def LENS : List Nat := List.range' 5 26

/-- First length in `Ls` at which a code matches the head of `r`; stops at
the first length longer than `r` (the walker's `break`). -/
def matchFrom (r : List Bool) : List Nat → Option (Nat × Nat)
  | [] => none
  | L :: Ls =>
    if r.length < L then none
    else match symOf (val (r.take L)) L with
      | some s => some (s, L)
      | none => matchFrom r Ls

def matchSym (r : List Bool) : Option (Nat × Nat) := matchFrom r LENS

/-- `L`-bit head of `r` is the code of `s`. -/
def Hit (r : List Bool) (L s : Nat) : Prop := L ≤ r.length ∧ s < 257 ∧ code s = (val (r.take L), L)

theorem matchFrom_some (r : List Bool) (Ls : List Nat) (s L : Nat)
    (h : matchFrom r Ls = some (s, L)) : L ∈ Ls ∧ Hit r L s := by
  induction Ls with
  | nil => simp [matchFrom] at h
  | cons L0 Ls ih =>
    simp only [matchFrom] at h
    split at h
    · cases h
    · split at h
      · next s' e =>
        cases h
        obtain ⟨h1, h2⟩ := symOf_some _ _ _ e
        exact ⟨List.mem_cons_self, by omega, h1, h2⟩
      · obtain ⟨h1, h2⟩ := ih h; exact ⟨List.mem_cons_of_mem _ h1, h2⟩

theorem hit_unique (r : List Bool) (L1 s1 L2 s2 : Nat) (h1 : Hit r L1 s1) (h2 : Hit r L2 s2) :
    s1 = s2 ∧ L1 = L2 := by
  obtain ⟨hl1, hs1, hc1⟩ := h1
  obtain ⟨hl2, hs2, hc2⟩ := h2
  by_cases e : s1 = s2
  · subst e; rw [hc1] at hc2; simp at hc2; exact ⟨rfl, hc2.2⟩
  · exfalso
    have np := notPrefix_of_ne s1 s2 hs1 hs2 e
    unfold NotPrefix at np
    rw [hc1, hc2] at np
    simp only at np
    have key : ∀ A B, A ≤ B → B ≤ r.length → val (r.take A) = val (r.take B) >>> (B - A) := by
      intro A B hab hb
      have : r.take A = (r.take B).take A := by rw [List.take_take, Nat.min_eq_left hab]
      rw [this, val_take _ _ (by simp; omega), Nat.shiftRight_eq_div_pow, List.length_take,
        Nat.min_eq_left hb]
    by_cases hle : L1 ≤ L2
    · rw [if_pos hle] at np; exact np (key L1 L2 hle hl2).symm
    · rw [if_neg hle] at np; exact np (key L2 L1 (by omega) hl1).symm

theorem matchFrom_of_hit (r : List Bool) (Ls : List Nat) (hs : Ls.Pairwise (· < ·))
    (L s : Nat) (hL : L ∈ Ls) (h : Hit r L s) : matchFrom r Ls = some (s, L) := by
  induction Ls with
  | nil => simp at hL
  | cons L0 Ls ih =>
    simp only [List.pairwise_cons] at hs
    simp only [matchFrom]
    have hL0 : L0 ≤ L := by
      rcases List.mem_cons.mp hL with e | e
      · omega
      · exact Nat.le_of_lt (hs.1 L e)
    rw [if_neg (by have := h.1; omega)]
    cases e : symOf (val (r.take L0)) L0 with
    | some s0 =>
      obtain ⟨h1, h2⟩ := symOf_some _ _ _ e
      obtain ⟨e1, e2⟩ := hit_unique r L0 s0 L s ⟨by have := h.1; omega, h1, h2⟩ h
      subst e1 e2; rfl
    | none =>
      have hne : L ≠ L0 := by
        intro e'; subst e'
        rw [symOf_of_code _ _ _ h.2.1 h.2.2] at e; cases e
      exact ih hs.2 (by rcases List.mem_cons.mp hL with e | e; exact absurd e hne; exact e)

theorem lens_sorted : LENS.Pairwise (· < ·) := by decide

theorem mem_lens (L : Nat) : L ∈ LENS ↔ 5 ≤ L ∧ L ≤ 30 := by
  simp only [LENS, List.mem_range'_1]; omega

theorem matchSym_some (r : List Bool) (s L : Nat) (h : matchSym r = some (s, L)) :
    5 ≤ L ∧ Hit r L s := by
  obtain ⟨h1, h2⟩ := matchFrom_some r LENS s L h
  exact ⟨((mem_lens L).mp h1).1, h2⟩

theorem matchSym_of_hit (r : List Bool) (L s : Nat) (h : Hit r L s) : matchSym r = some (s, L) := by
  have hL : L ∈ LENS := by
    have := code_fits s h.2.1; rw [h.2.2] at this; exact (mem_lens L).mpr ⟨this.1, this.2.1⟩
  exact matchFrom_of_hit r LENS lens_sorted L s hL h

theorem matchSym_none (r : List Bool) (h : matchSym r = none) (L s : Nat) : ¬ Hit r L s := by
  intro hh; rw [matchSym_of_hit r L s hh] at h; cases h

theorem hit_take (r : List Bool) (L s : Nat) (h : Hit r L s) : r.take L = codeBits s := by
  obtain ⟨h1, h2, h3⟩ := h
  apply val_inj
  · simp [length_codeBits, h3]; omega
  · rw [val_codeBits s h2, h3]

theorem hit_codeBits (s : Nat) (hs : s < 257) (rest : List Bool) :
    Hit (codeBits s ++ rest) (code s).2 s := by
  refine ⟨by simp [length_codeBits], hs, ?_⟩
  rw [List.take_left' (length_codeBits s), val_codeBits s hs]

theorem hit_append (r m : List Bool) (L s : Nat) (h : Hit r L s) : Hit (r ++ m) L s := by
  obtain ⟨h1, h2, h3⟩ := h
  refine ⟨by simp; omega, h2, ?_⟩
  rw [List.take_append_of_le_length h1]; exact h3

theorem matchSym_append (r m : List Bool) (s L : Nat) (h : matchSym r = some (s, L)) :
    matchSym (r ++ m) = some (s, L) :=
  matchSym_of_hit _ _ _ (hit_append r m L s (matchSym_some r s L h).2)

/-- Completeness: every string of 30 or more bits starts with a code. -/
theorem matchSym_isSome (r : List Bool) (h : 30 ≤ r.length) : ∃ s L, matchSym r = some (s, L) := by
  have hv := val_lt (r.take 30)
  rw [List.length_take, Nat.min_eq_left h] at hv
  obtain ⟨p, hp, h1, h2⟩ := covers_mem 0 (2 ^ 30) _ _ canon_covers (Nat.zero_le _) hv
  obtain ⟨s, hs, rfl⟩ := List.mem_map.mp hp
  have hs' := canon_lt s hs
  obtain ⟨f1, f2, f3⟩ := code_fits s hs'
  simp only [ival] at h1 h2
  refine ⟨s, (code s).2, matchSym_of_hit _ _ _ ⟨by omega, hs', ?_⟩⟩
  have e : r.take (code s).2 = (r.take 30).take (code s).2 := by
    rw [List.take_take, Nat.min_eq_left f2]
  rw [e, val_take _ _ (by simp; omega)]
  simp only [List.length_take, Nat.min_eq_left h]
  have hp : 0 < 2 ^ (30 - (code s).2) := Nat.two_pow_pos _
  unfold code at *
  ext
  · simp only
    apply Nat.le_antisymm
    · exact (Nat.le_div_iff_mul_le hp).mpr h1
    · exact Nat.lt_succ_iff.mp ((Nat.div_lt_iff_lt_mul hp).mpr (by rw [Nat.succ_eq_add_one]; exact h2))
  · rfl

theorem matchSym_none_length (r : List Bool) (h : matchSym r = none) : r.length < 30 := by
  by_cases hc : 30 ≤ r.length
  · obtain ⟨s, L, e⟩ := matchSym_isSome r hc
    rw [h] at e; cases e
  · omega

/-- RFC 7541 §5.2 decoding of a bit string: emitted bytes, then the error
(if any) that stopped decoding. -/
def decodeBits (r : List Bool) : Bytes × Option Error :=
  match _h : matchSym r with
  | some (s, L) =>
    if s = 256 then ([], some .eosInInput)
    else
      let res := decodeBits (r.drop L)
      (UInt8.ofNat s :: res.1, res.2)
  | none =>
    if 7 < r.length then ([], some .paddingTooLong)
    else if r.all id then ([], none) else ([], some .invalidPadding)
termination_by r.length
decreasing_by
  have := matchSym_some r s L _h
  have := this.2.1
  simp; omega

def decodeFull (input : Bytes) : Bytes × Option Error := decodeBits (unpack input)

def decode (input : Bytes) : Option Bytes :=
  match decodeFull input with
  | (out, none) => some out
  | _ => none

theorem decodeBits_hit (r : List Bool) (s L : Nat) (h : matchSym r = some (s, L)) :
    decodeBits r = if s = 256 then ([], some .eosInInput)
      else (UInt8.ofNat s :: (decodeBits (r.drop L)).1, (decodeBits (r.drop L)).2) := by
  rw [decodeBits]; split
  · next s' L' e => rw [h] at e; cases e; rfl
  · next e => rw [h] at e; cases e

theorem decodeBits_none (r : List Bool) (h : matchSym r = none) :
    decodeBits r = if 7 < r.length then ([], some .paddingTooLong)
      else if r.all id then ([], none) else ([], some .invalidPadding) := by
  rw [decodeBits]; split
  · next s' L' e => rw [h] at e; cases e
  · rfl

/-- No code is a prefix of a run of fewer than 30 one-bits. -/
theorem matchSym_ones (k : Nat) (hk : k < 30) : matchSym (List.replicate k true) = none := by
  cases e : matchSym (List.replicate k true) with
  | none => rfl
  | some p =>
    obtain ⟨s, L⟩ := p
    obtain ⟨h5, h1, h2, h3⟩ := matchSym_some _ s L e
    exfalso
    simp only [List.length_replicate] at h1
    rw [List.take_replicate, Nat.min_eq_left h1, val_replicate_true] at h3
    have hm : TBL.getD s (0, 0) ∈ TBL := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [table_size]; exact h2)]
      exact List.getElem_mem _
    unfold code at h3; rw [h3] at hm
    exact ones_not_code L (by omega) (by omega) hm

theorem decodeBits_encode (out : Bytes) (p : List Bool) (hp : p.length ≤ 7) (ha : p.all id = true) :
    decodeBits (encodeBits out ++ p) = (out, none) := by
  induction out with
  | nil =>
    have hp' : p = List.replicate p.length true := by
      apply List.eq_replicate_iff.mpr; simp at ha
      exact ⟨rfl, fun b hb => by cases b; exact absurd hb ha; rfl⟩
    simp only [encodeBits, List.flatMap_nil, List.nil_append]
    rw [decodeBits_none p (by rw [hp']; exact matchSym_ones _ (by omega)),
      if_neg (by omega), if_pos ha]
  | cons b bs ih =>
    have hb : b.toNat < 257 := by have := b.toNat_lt; omega
    have hm : matchSym (encodeBits (b :: bs) ++ p) = some (b.toNat, (code b.toNat).2) := by
      apply matchSym_of_hit
      simp only [encodeBits, List.flatMap_cons, List.append_assoc]
      exact hit_codeBits _ hb _
    rw [decodeBits_hit _ _ _ hm, if_neg (by have := b.toNat_lt; omega)]
    have : (encodeBits (b :: bs) ++ p).drop (code b.toNat).2 = encodeBits bs ++ p := by
      simp only [encodeBits, List.flatMap_cons, List.append_assoc]
      exact List.drop_left' (length_codeBits _)
    rw [this, ih]; simp

theorem decodeBits_sound (r : List Bool) (out : Bytes) (h : decodeBits r = (out, none)) :
    ∃ p, r = encodeBits out ++ p ∧ p.length ≤ 7 ∧ p.all id = true := by
  induction hn : r.length using Nat.strongRecOn generalizing r out with
  | _ n ih =>
    cases e : matchSym r with
    | none =>
      rw [decodeBits_none r e] at h
      split at h
      · cases h
      · split at h
        · cases h; exact ⟨r, by simp [encodeBits], by omega, by assumption⟩
        · cases h
    | some p =>
      obtain ⟨s, L⟩ := p
      rw [decodeBits_hit r s L e] at h
      split at h
      · cases h
      · next hs =>
        obtain ⟨h5, hl, hs', hc⟩ := matchSym_some r s L e
        simp only [Prod.mk.injEq] at h
        obtain ⟨hout, herr⟩ := h
        subst hout
        obtain ⟨p, hp, hp7, hpa⟩ := ih _ (by subst hn; simp; omega) (r.drop L) _
          (by rw [← herr]) rfl
        refine ⟨p, ?_, hp7, hpa⟩
        have hb : (UInt8.ofNat s).toNat = s := by
          rw [UInt8.toNat_ofNat']; exact Nat.mod_eq_of_lt (by omega)
        simp only [encodeBits, List.flatMap_cons, hb, List.append_assoc]
        rw [← encodeBits, ← hp, ← hit_take r L s ⟨hl, hs', hc⟩, List.take_append_drop]

/-- RFC 7541 §5.2: a byte string decodes to `out` exactly when its bits are
the codes of `out` followed by at most 7 one-bits (the most significant bits
of EOS). EOS inside the string, longer padding, or padding with a 0-bit are
all decoding errors. -/
theorem decode_eq_some_iff (input out : Bytes) :
    decode input = some out ↔
      ∃ p, unpack input = encodeBits out ++ p ∧ p.length ≤ 7 ∧ p.all id = true := by
  constructor
  · intro h
    unfold decode decodeFull at h
    split at h
    · next o e => cases h; exact decodeBits_sound _ _ e
    · cases h
  · rintro ⟨p, hp, h7, ha⟩
    unfold decode decodeFull; rw [hp, decodeBits_encode out p h7 ha]

theorem decode_encode (input : Bytes) : decode (encode input) = some input := by
  refine (decode_eq_some_iff _ _).mpr ⟨List.replicate (padLen (encodeBits input).length) true, ?_,
    by simp [padLen]; omega, by simp⟩
  rw [encode, unpack_pack _ (padBits_length _)]; rfl

/-- EOS anywhere at a code boundary stops decoding with `EOS_IN_INPUT` after
emitting the symbols before it. -/
theorem decodeBits_eos (out : Bytes) (rest : List Bool) :
    decodeBits (encodeBits out ++ codeBits 256 ++ rest) = (out, some .eosInInput) := by
  induction out with
  | nil =>
    simp only [encodeBits, List.flatMap_nil, List.nil_append]
    rw [decodeBits_hit _ 256 (code 256).2 (matchSym_of_hit _ _ _ (hit_codeBits 256 (by omega) _)),
      if_pos rfl]
  | cons b bs ih =>
    have hb : b.toNat < 257 := by have := b.toNat_lt; omega
    have hm : matchSym (encodeBits (b :: bs) ++ codeBits 256 ++ rest) =
        some (b.toNat, (code b.toNat).2) := by
      apply matchSym_of_hit
      simp only [encodeBits, List.flatMap_cons, List.append_assoc]
      exact hit_codeBits _ hb _
    rw [decodeBits_hit _ _ _ hm, if_neg (by have := b.toNat_lt; omega)]
    have : (encodeBits (b :: bs) ++ codeBits 256 ++ rest).drop (code b.toNat).2 =
        encodeBits bs ++ codeBits 256 ++ rest := by
      simp only [encodeBits, List.flatMap_cons, List.append_assoc]
      exact List.drop_left' (length_codeBits _)
    rw [this, ih]; simp

theorem decodeBits_prefix (out : Bytes) (r : List Bool) :
    decodeBits (encodeBits out ++ r) = (out ++ (decodeBits r).1, (decodeBits r).2) := by
  induction out with
  | nil => simp [encodeBits]
  | cons b bs ih =>
    have hb : b.toNat < 257 := by have := b.toNat_lt; omega
    have hm : matchSym (encodeBits (b :: bs) ++ r) = some (b.toNat, (code b.toNat).2) := by
      apply matchSym_of_hit
      simp only [encodeBits, List.flatMap_cons, List.append_assoc]
      exact hit_codeBits _ hb _
    rw [decodeBits_hit _ _ _ hm, if_neg (by have := b.toNat_lt; omega)]
    have : (encodeBits (b :: bs) ++ r).drop (code b.toNat).2 = encodeBits bs ++ r := by
      simp only [encodeBits, List.flatMap_cons, List.append_assoc]
      exact List.drop_left' (length_codeBits _)
    rw [this, ih]; simp

/-- Padding of 8..29 one-bits after the last symbol: `PADDING_TOO_LONG`. -/
theorem decodeBits_padding_too_long (out : Bytes) (k : Nat) (h1 : 8 ≤ k) (h2 : k < 30) :
    decodeBits (encodeBits out ++ List.replicate k true) = (out, some .paddingTooLong) := by
  rw [decodeBits_prefix, decodeBits_none _ (matchSym_ones k h2), if_pos (by simp; omega)]; simp

/-- 30 or more one-bits after the last symbol contain EOS: `EOS_IN_INPUT`. -/
theorem decodeBits_padding_eos (out : Bytes) (k : Nat) (h1 : 30 ≤ k) :
    decodeBits (encodeBits out ++ List.replicate k true) = (out, some .eosInInput) := by
  have e : List.replicate k true = codeBits 256 ++ List.replicate (k - 30) true := by
    have : codeBits 256 = List.replicate 30 true := by decide
    rw [this, List.replicate_append_replicate]; congr 1; omega
  rw [e, ← List.append_assoc, decodeBits_eos]

/-- At most 7 trailing bits that contain a 0 and start no code:
`INVALID_PADDING`. -/
theorem decodeBits_invalid_padding (out : Bytes) (p : List Bool) (h7 : p.length ≤ 7)
    (hz : p.all id = false) (hm : matchSym p = none) :
    decodeBits (encodeBits out ++ p) = (out, some .invalidPadding) := by
  rw [decodeBits_prefix, decodeBits_none _ hm, if_neg (by omega), if_neg (by simp [hz])]; simp

/-- Fewer than 5 bits never start a code, so any short tail with a 0-bit is
`INVALID_PADDING`. -/
theorem matchSym_short (p : List Bool) (h : p.length < 5) : matchSym p = none := by
  cases e : matchSym p with
  | none => rfl
  | some q => obtain ⟨s, L⟩ := q; have := matchSym_some p s L e; have := this.2.1; omega

/-! ## UInt64 accumulator arithmetic -/

theorem ofNat_toNat_lt (k : Nat) (h : k < 2 ^ 64) : (UInt64.ofNat k).toNat = k := by
  rw [UInt64.toNat_ofNat']; exact Nat.mod_eq_of_lt h

theorem two_pow_lt64 (k : Nat) (h : k ≤ 63) : 2 ^ k < 2 ^ 64 :=
  Nat.pow_lt_pow_right (by omega) (by omega)

/-- `(k * A + c) % (k * m) = k * (A % m) + c` for `c < k`. -/
theorem mul_add_mod_mul (k A c m : Nat) (hc : c < k) (hm : 0 < m) :
    (k * A + c) % (k * m) = k * (A % m) + c := by
  have hA := Nat.div_add_mod A m
  have hlt : k * (A % m) + c < k * m := by
    have : A % m + 1 ≤ m := Nat.mod_lt _ hm
    have : k * (A % m + 1) ≤ k * m := Nat.mul_le_mul_left _ this
    rw [Nat.mul_add] at this; omega
  have e : k * A + c = k * (A % m) + c + (k * m) * (A / m) := by
    conv => lhs; rw [← hA]
    rw [Nat.mul_add, Nat.mul_assoc]; omega
  rw [e, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hlt]

/-- The encoder's `bits = (bits << clen) | code`, seen modulo `2^(n + L)`. -/
theorem shl_or_mod (x : UInt64) (L n c : Nat) (hc : c < 2 ^ L) (hL : L < 64) (hnL : n + L ≤ 64) :
    ((x <<< UInt64.ofNat L) ||| UInt64.ofNat c).toNat % 2 ^ (n + L) = (x.toNat % 2 ^ n) * 2 ^ L + c := by
  have hc64 : c < 2 ^ 64 := Nat.lt_of_lt_of_le hc (Nat.pow_le_pow_right (by omega) (by omega))
  rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, ofNat_toNat_lt L (by
      have := two_pow_lt64 6 (by omega); have : L < 2 ^ 6 := by omega
      omega), ofNat_toNat_lt c hc64, Nat.mod_eq_of_lt hL, Nat.shiftLeft_eq]
  have e64 : (2 : Nat) ^ 64 = 2 ^ L * 2 ^ (64 - L) := by rw [← Nat.pow_add]; congr 1; omega
  rw [e64, Nat.mul_comm x.toNat, Nat.mul_mod_mul_left, ← Nat.two_pow_add_eq_or_of_lt hc,
    Nat.pow_add, Nat.mul_comm (2 ^ n), mul_add_mod_mul _ _ _ _ hc (Nat.two_pow_pos _),
    Nat.mod_mod_of_dvd _ (Nat.pow_dvd_pow 2 (by omega)), Nat.mul_comm]

/-- The decoder's `bits = (bits << 8) | byte` on a small accumulator. -/
theorem shl8_or (x : UInt64) (b : UInt8) (hx : x.toNat < 2 ^ 56) :
    ((x <<< 8) ||| b.toUInt64).toNat = x.toNat * 256 + b.toNat := by
  rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, Nat.shiftLeft_eq]
  have : (8 : UInt64).toNat % 64 = 8 := rfl
  rw [this, Nat.mod_eq_of_lt (by have := b.toNat_lt; omega), Nat.mul_comm,
    ← Nat.two_pow_add_eq_or_of_lt (b.toNat_lt)]

/-- `(bits >> (n - L)) & ((1 << L) - 1)` reads the first `L` buffered bits. -/
theorem extract (bits : UInt64) (buf : List Bool) (hb : bits.toNat = val buf) (hn : buf.length ≤ 63)
    (L : Nat) (hL : L ≤ buf.length) :
    ((bits >>> UInt64.ofNat (buf.length - L)) &&& UInt64.ofNat (2 ^ L - 1)).toNat = val (buf.take L) := by
  have h1 : buf.length - L < 2 ^ 64 := by have := two_pow_lt64 6 (by omega); omega
  have h2 : 2 ^ L - 1 < 2 ^ 64 := by have := two_pow_lt64 L (by omega); omega
  rw [UInt64.toNat_and, UInt64.toNat_shiftRight, ofNat_toNat_lt _ h1, ofNat_toNat_lt _ h2,
    Nat.mod_eq_of_lt (by omega), Nat.shiftRight_eq_div_pow, Nat.and_two_pow_sub_one_eq_mod, hb,
    val_take _ _ hL]
  apply Nat.mod_eq_of_lt
  apply (Nat.div_lt_iff_lt_mul (Nat.two_pow_pos _)).mpr
  rw [← Nat.pow_add, show L + (buf.length - L) = buf.length by omega]; exact val_lt buf

theorem mask_val (bits : UInt64) (buf : List Bool) (hb : bits.toNat = val buf) (hn : buf.length ≤ 63)
    (L : Nat) : (if 0 < buf.length - L then bits &&& UInt64.ofNat (2 ^ (buf.length - L) - 1) else 0).toNat =
      val (buf.drop L) := by
  split
  · have h2 : 2 ^ (buf.length - L) - 1 < 2 ^ 64 := by
      have := two_pow_lt64 (buf.length - L) (by omega); omega
    rw [UInt64.toNat_and, ofNat_toNat_lt _ h2, Nat.and_two_pow_sub_one_eq_mod, hb, val_drop]
  · rw [List.drop_eq_nil_of_le (by omega)]; rfl

/-! ## Impl: table accessors and the canonical decode tables -/

/-- mirrors flare/http/hpack_huffman.mojo:119-641 @59bda50 (`_hpack_table_code`) -/
def tableCode (s : Nat) : Nat := (code s).1

/-- mirrors flare/http/hpack_huffman.mojo:643-667 @59bda50 (`_hpack_table_length`;
equal to the hex-string decoder `tableLengthImpl` on `0..256` by `tableLengthImpl_eq`) -/
def tableLength (s : Nat) : Nat := (code s).2

/-- mirrors flare/http/hpack_huffman.mojo:744-764 @59bda50 (`_make_canon_table`) -/
def canonTableImpl : List Int :=
  let step (acc : List Int × Int) (L : Nat) : List Int × Int :=
    let fc := (List.range 257).foldl (fun (fc : Int × Int) sym =>
      if tableLength sym = L then
        let c : Int := tableCode sym
        (if fc.1 < 0 || c < fc.1 then c else fc.1, fc.2 + 1)
      else fc) (-1, 0)
    (((acc.1.set L (if fc.1 ≥ 0 then fc.1 else 0)).set (31 + L) fc.2).set (62 + L) acc.2, acc.2 + fc.2)
  ((List.range 31).foldl step (List.replicate 93 0, 0)).1

/-- mirrors flare/http/hpack_huffman.mojo:767-776 @59bda50 (`_make_canon_syms`) -/
def canonSymsImpl : List Int :=
  let t := canonTableImpl
  (List.range 257).foldl (fun out sym =>
    let L := tableLength sym
    let idx : Int := t.getD (62 + L) 0 + ((tableCode sym : Int) - t.getD L 0)
    out.set idx.toNat (sym : Int)) (List.replicate 257 (-1))

def CT : List Int :=
  [0, 0, 0, 0, 0, 0, 20, 92, 248, 0, 1016, 2042, 4090, 8184, 16380, 32764, 0, 0, 0, 524272,
  1048550, 2097116, 4194258, 8388568, 16777194, 33554412, 67108832, 134217694, 268435426, 0,
  1073741820, 0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3, 0, 0, 0, 3, 8, 13, 26, 29, 12, 4,
  15, 19, 29, 0, 4, 0, 0, 0, 0, 0, 0, 10, 36, 68, 74, 74, 79, 82, 84, 90, 92, 95, 95, 95, 95, 98,
  106, 119, 145, 174, 186, 190, 205, 224, 253, 253]

def CS : List Int :=
  [48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51, 52, 53, 54, 55, 56, 57,
  61, 65, 95, 98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71,
  72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118, 119,
  120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39, 43, 124, 35, 62, 0, 36, 64, 91,
  93, 126, 94, 125, 60, 96, 123, 92, 195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161,
  167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156,
  160, 163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232, 233, 1,
  135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157, 158, 165, 166, 168, 174,
  175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142, 144, 145, 148, 159, 171, 206, 215, 225,
  236, 237, 199, 207, 234, 235, 192, 193, 200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242,
  243, 255, 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252,
  253, 254, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28,
  29, 30, 31, 127, 220, 249, 10, 13, 22, 256]

theorem canonTable_eq : canonTableImpl = CT := by decide +kernel

theorem canonSyms_eq : canonSymsImpl = CS := by decide +kernel

/-- mirrors flare/http/hpack_huffman.mojo:783-807 @59bda50 (`_build_decode_lookup`) -/
def lookupImpl (c : Int) (L : Nat) : Int :=
  if L < 5 ∨ 30 < L then -1
  else
    let first := canonTableImpl.getD L 0
    let count := canonTableImpl.getD (31 + L) 0
    let off := c - first
    if off < 0 ∨ count ≤ off then -1
    else canonSymsImpl.getD (canonTableImpl.getD (62 + L) 0 + off).toNat (-1)

theorem CT_nonneg : ∀ i, i < 93 → 0 ≤ CT.getD i 0 := by decide +kernel

theorem CS_range : ∀ L, L < 31 → 5 ≤ L → ∀ k, k < (CT.getD (31 + L) 0).toNat →
    0 ≤ CS.getD (CT.getD (62 + L) 0 + k).toNat (-1) ∧ CS.getD (CT.getD (62 + L) 0 + k).toNat (-1) < 257 ∧
    code (CS.getD (CT.getD (62 + L) 0 + k).toNat (-1)).toNat = ((CT.getD L 0).toNat + k, L) := by
  decide +kernel

theorem CS_complete : ∀ s, s < 257 →
    (CT.getD (code s).2 0).toNat ≤ (code s).1 ∧
    (code s).1 < (CT.getD (code s).2 0).toNat + (CT.getD (31 + (code s).2) 0).toNat := by
  decide +kernel

/-- `_build_decode_lookup` returns the symbol with code `(c, L)`, or -1. -/
theorem lookupImpl_spec (c L : Nat) (h1 : 5 ≤ L) (h2 : L ≤ 30) :
    lookupImpl c L = match symOf c L with | some s => (s : Int) | none => -1 := by
  rw [lookupImpl, canonTable_eq, canonSyms_eq, if_neg (by omega)]
  simp only
  have nf := CT_nonneg L (by omega)
  have nc := CT_nonneg (31 + L) (by omega)
  have nb := CT_nonneg (62 + L) (by omega)
  by_cases hr : (c : Int) - CT.getD L 0 < 0 ∨ CT.getD (31 + L) 0 ≤ (c : Int) - CT.getD L 0
  · rw [if_pos hr]
    cases e : symOf c L with
    | none => rfl
    | some s =>
      obtain ⟨hs, hc⟩ := symOf_some _ _ _ e
      have := CS_complete s hs
      rw [hc] at this; simp only at this
      omega
  · rw [if_neg hr]
    obtain ⟨k0, hk0⟩ : ∃ k : Nat, (c : Int) - CT.getD L 0 = k := ⟨((c : Int) - CT.getD L 0).toNat, by omega⟩
    obtain ⟨g0, g1, g2⟩ := CS_range L (by omega) h1 k0 (by omega)
    have hs : symOf c L = some (CS.getD (CT.getD (62 + L) 0 + k0).toNat (-1)).toNat := by
      apply symOf_of_code _ _ _ (by omega)
      rw [g2]; simp only [Prod.mk.injEq, and_true]; omega
    rw [hs, hk0]; simp only; omega

/-! ## Impl: scalar decoder -/

/-- `for clen in Ls: if nbits < clen: break; ...` returning the first match.
mirrors flare/http/hpack_huffman.mojo:854-870 @59bda50 -/
def tryLens (bits : UInt64) (nbits : Nat) : List Nat → Option (Int × Nat)
  | [] => none
  | clen :: rest =>
    if nbits < clen then none
    else
      let c := ((bits >>> UInt64.ofNat (nbits - clen)) &&& UInt64.ofNat (2 ^ clen - 1)).toNat
      let sym := lookupImpl c clen
      if 0 ≤ sym then some (sym, clen) else tryLens bits nbits rest

theorem tryLens_some (bits : UInt64) (nbits : Nat) (Ls : List Nat) (sym : Int) (clen : Nat)
    (h : tryLens bits nbits Ls = some (sym, clen)) : clen ∈ Ls ∧ clen ≤ nbits := by
  induction Ls with
  | nil => simp [tryLens] at h
  | cons L Ls ih =>
    simp only [tryLens] at h
    split at h
    · cases h
    · split at h
      · cases h; exact ⟨List.mem_cons_self, by omega⟩
      · obtain ⟨a, b⟩ := ih h; exact ⟨List.mem_cons_of_mem _ a, b⟩

theorem tryLens_eq (bits : UInt64) (buf : List Bool) (hb : bits.toNat = val buf) (hn : buf.length ≤ 63)
    (Ls : List Nat) (hLs : ∀ L ∈ Ls, 5 ≤ L ∧ L ≤ 30) :
    tryLens bits buf.length Ls = (matchFrom buf Ls).map fun p => ((p.1 : Int), p.2) := by
  induction Ls with
  | nil => rfl
  | cons L Ls ih =>
    have hL := hLs L List.mem_cons_self
    simp only [tryLens, matchFrom]
    split
    · rfl
    · rw [extract bits buf hb hn L (by omega), lookupImpl_spec _ _ hL.1 hL.2]
      cases symOf (val (buf.take L)) L with
      | some s => simp
      | none => simp only; exact ih (fun L' h' => hLs L' (List.mem_cons_of_mem _ h'))

theorem lens_bounds : ∀ L ∈ LENS, 5 ≤ L ∧ L ≤ 30 := fun L h => (mem_lens L).mp h

/-- The inner `while True` loop: decode symbols while one matches.
mirrors flare/http/hpack_huffman.mojo:852-872 @59bda50 -/
def drain (bits : UInt64) (nbits : Nat) (out : Bytes) : UInt64 × Nat × Bytes × Option Error :=
  match _h : tryLens bits nbits LENS with
  | none => (bits, nbits, out, none)
  | some (sym, clen) =>
    if sym = 256 then (bits, nbits, out, some .eosInInput)
    else
      let nb := nbits - clen
      drain (if 0 < nb then bits &&& UInt64.ofNat (2 ^ nb - 1) else 0) nb (out ++ [UInt8.ofNat sym.toNat])
termination_by nbits
decreasing_by
  have := tryLens_some _ _ _ _ _ _h
  have := (mem_lens clen).mp this.1
  omega

theorem drain_none (bits : UInt64) (nbits : Nat) (out : Bytes) (h : tryLens bits nbits LENS = none) :
    drain bits nbits out = (bits, nbits, out, none) := by
  rw [drain]; split
  · rfl
  · next e => rw [h] at e; cases e

theorem drain_some (bits : UInt64) (nbits : Nat) (out : Bytes) (sym : Int) (clen : Nat)
    (h : tryLens bits nbits LENS = some (sym, clen)) :
    drain bits nbits out = if sym = 256 then (bits, nbits, out, some .eosInInput) else
      drain (if 0 < nbits - clen then bits &&& UInt64.ofNat (2 ^ (nbits - clen) - 1) else 0)
        (nbits - clen) (out ++ [UInt8.ofNat sym.toNat]) := by
  rw [drain]; split
  · next e => rw [h] at e; cases e
  · next sym' clen' e => rw [h] at e; cases e; rfl

/-- Prefix already-emitted output to a decoding result. -/
def pre (out : Bytes) (d : Bytes × Option Error) : Bytes × Option Error := (out ++ d.1, d.2)

theorem pre_pre (a b : Bytes) (d : Bytes × Option Error) : pre a (pre b d) = pre (a ++ b) d := by
  simp [pre]

theorem decodeBits_step (buf rest : List Bool) (s L : Nat) (h : matchSym buf = some (s, L)) (hs : s ≠ 256)
    (out : Bytes) :
    pre out (decodeBits (buf ++ rest)) = pre (out ++ [UInt8.ofNat s]) (decodeBits (buf.drop L ++ rest)) := by
  have hl := (matchSym_some buf s L h).2.1
  rw [decodeBits_hit _ _ _ (matchSym_append buf rest s L h), if_neg hs,
    List.drop_append_of_le_length hl]
  simp [pre]

theorem decodeBits_eosStep (buf rest : List Bool) (L : Nat) (h : matchSym buf = some (256, L))
    (out : Bytes) : pre out (decodeBits (buf ++ rest)) = (out, some .eosInInput) := by
  rw [decodeBits_hit _ _ _ (matchSym_append buf rest 256 L h), if_pos rfl]; simp [pre]

/-- Refinement of the inner loop: either it stops at an error that the spec
also reports, or it stops on a buffer with no complete code, having emitted
exactly the spec's symbols. -/
theorem drain_spec (buf : List Bool) (bits : UInt64) (out : Bytes) (hb : bits.toNat = val buf)
    (hn : buf.length ≤ 37) :
    match drain bits buf.length out with
    | (b', n', out', none) => ∃ buf', b'.toNat = val buf' ∧ n' = buf'.length ∧
        buf'.length ≤ buf.length ∧ matchSym buf' = none ∧
        ∀ rest, pre out' (decodeBits (buf' ++ rest)) = pre out (decodeBits (buf ++ rest))
    | (_, _, out', some e) => ∀ rest, pre out (decodeBits (buf ++ rest)) = (out', some e) := by
  induction hm : buf.length using Nat.strongRecOn generalizing buf bits out with
  | _ n ih =>
    subst hm
    have hte := tryLens_eq bits buf hb (by omega) LENS lens_bounds
    cases e : tryLens bits buf.length LENS with
    | none =>
      rw [drain_none _ _ _ e]
      rw [e] at hte
      have hms : matchSym buf = none := by
        unfold matchSym; cases h : matchFrom buf LENS <;> simp_all
      exact ⟨buf, hb, rfl, Nat.le_refl _, hms, fun _ => rfl⟩
    | some p =>
      obtain ⟨sym, clen⟩ := p
      rw [drain_some _ _ _ _ _ e]
      rw [e] at hte
      obtain ⟨s, L, hms, hsym, hL⟩ : ∃ s L, matchSym buf = some (s, L) ∧ sym = s ∧ clen = L := by
        unfold matchSym; cases h : matchFrom buf LENS with
        | none => simp [h] at hte
        | some p => obtain ⟨s, L⟩ := p; simp [h] at hte; obtain ⟨h1, h2⟩ := hte; exact ⟨s, L, rfl, by omega, by omega⟩
      subst hsym hL
      have hlen := (matchSym_some buf s clen hms).2.1
      by_cases h256 : ((s : Int) = 256)
      · rw [if_pos h256]
        have : s = 256 := by omega
        subst this
        exact fun rest => decodeBits_eosStep buf rest clen hms out
      · rw [if_neg h256]
        have hs : s ≠ 256 := by omega
        have ih' := ih (buf.drop clen).length (by
            rw [List.length_drop]; have := (matchSym_some buf s clen hms).1; omega)
          (buf.drop clen) _ (out ++ [UInt8.ofNat (s : Int).toNat]) (by
            exact mask_val bits buf hb (by omega) clen)
            (by rw [List.length_drop]; omega) rfl
        simp only [List.length_drop] at ih'
        have hsn : ((s : Int).toNat) = s := by simp
        try rw [hsn] at ih'
        rw [hsn]
        generalize drain _ _ _ = R at ih' ⊢
        obtain ⟨b', n', out', e'⟩ := R
        cases e' with
        | none =>
          obtain ⟨buf', h1, h2, h3, h4, h5⟩ := ih'
          refine ⟨buf', h1, h2, by omega, h4, fun rest => ?_⟩
          rw [h5, decodeBits_step buf rest s clen hms hs]
        | some err =>
          intro rest
          rw [decodeBits_step buf rest s clen hms hs]; exact ih' rest

/-- The final padding checks.
mirrors flare/http/hpack_huffman.mojo:873-880 @59bda50 -/
def finalCheck (bits : UInt64) (nbits : Nat) (out : Bytes) : Bytes × Option Error :=
  if 7 < nbits then (out, some .paddingTooLong)
  else if 0 < nbits ∧ bits ≠ UInt64.ofNat (2 ^ nbits - 1) then (out, some .invalidPadding)
  else (out, none)

theorem finalCheck_spec (buf : List Bool) (bits : UInt64) (out : Bytes) (hb : bits.toNat = val buf)
    (hm : matchSym buf = none) :
    finalCheck bits buf.length out = pre out (decodeBits buf) := by
  rw [finalCheck, decodeBits_none buf hm]
  have h30 := matchSym_none_length buf hm
  have eq0 : (bits = UInt64.ofNat (2 ^ buf.length - 1)) ↔ buf.all id = true := by
    rw [← UInt64.toNat_inj, hb, ofNat_toNat_lt _ (by have := two_pow_lt64 buf.length (by omega); omega)]
    exact val_eq_ones_iff buf
  have eq : (bits ≠ UInt64.ofNat (2 ^ buf.length - 1)) ↔ ¬ buf.all id = true := by
    rw [ne_eq, eq0]
  by_cases h7 : 7 < buf.length
  · simp [h7, pre]
  · rw [if_neg h7, if_neg h7]
    by_cases ha : buf.all id = true
    · rw [if_neg (by rw [eq]; simp [ha]), if_pos ha]; simp [pre]
    · have h0 : 0 < buf.length := by
        cases buf with
        | nil => simp at ha
        | cons _ _ => simp
      rw [if_pos ⟨h0, by rw [eq]; exact ha⟩, if_neg ha]; simp [pre]

/-- The outer `while i < n` loop.
mirrors flare/http/hpack_huffman.mojo:839-880 @59bda50 -/
def decodeLoop (bits : UInt64) (nbits : Nat) (out : Bytes) : Bytes → Bytes × Option Error
  | [] => finalCheck bits nbits out
  | b :: bs =>
    match drain ((bits <<< 8) ||| b.toUInt64) (nbits + 8) out with
    | (_, _, out', some e) => (out', some e)
    | (bits', nbits', out', none) => decodeLoop bits' nbits' out' bs

/-- `huffman_decode(input, output)` with `output` initially empty; returns
the bytes appended and the `HuffmanError` raised, if any.
mirrors flare/http/hpack_huffman.mojo:820-880 @59bda50 -/
def decodeImpl (input : Bytes) : Bytes × Option Error := decodeLoop 0 0 [] input

theorem push_byte (bits : UInt64) (buf : List Bool) (b : UInt8) (hb : bits.toNat = val buf)
    (hn : buf.length ≤ 29) :
    ((bits <<< 8) ||| b.toUInt64).toNat = val (buf ++ bitsOf b.toNat 8) ∧
      (buf ++ bitsOf b.toNat 8).length = buf.length + 8 := by
  have hv := val_lt buf
  have : val buf < 2 ^ 56 := Nat.lt_of_lt_of_le hv (Nat.pow_le_pow_right (by omega) (by omega))
  refine ⟨?_, by simp [length_bitsOf]⟩
  rw [shl8_or _ _ (by rw [hb]; exact this), val_append, length_bitsOf, val_bitsOf, hb,
    Nat.mod_eq_of_lt b.toNat_lt]

theorem decodeLoop_spec (input : Bytes) : ∀ (buf : List Bool) (bits : UInt64) (out : Bytes),
    bits.toNat = val buf → matchSym buf = none →
    decodeLoop bits buf.length out input = pre out (decodeBits (buf ++ unpack input)) := by
  induction input with
  | nil => intro buf bits out hb hm; simp only [decodeLoop, unpack, List.flatMap_nil, List.append_nil]
           exact finalCheck_spec buf bits out hb hm
  | cons b bs ih =>
    intro buf bits out hb hm
    have h30 := matchSym_none_length buf hm
    obtain ⟨hv, hl⟩ := push_byte bits buf b hb (by omega)
    have d := drain_spec (buf ++ bitsOf b.toNat 8) _ out hv (by omega)
    rw [hl] at d
    simp only [decodeLoop]
    have hu : buf ++ unpack (b :: bs) = (buf ++ bitsOf b.toNat 8) ++ unpack bs := by
      simp [unpack, List.flatMap_cons, List.append_assoc]
    rw [hu]
    generalize drain _ _ _ = R at d ⊢
    obtain ⟨b', n', out', e'⟩ := R
    cases e' with
    | none =>
      obtain ⟨buf', h1, h2, -, h4, h5⟩ := d
      simp only
      rw [h2, ih buf' b' out' h1 h4, h5]
    | some err => exact (d _).symm

/-- The scalar decoder computes the spec decoder exactly, including the
bytes emitted before an error. -/
theorem decodeImpl_eq (input : Bytes) : decodeImpl input = decodeFull input := by
  have := decodeLoop_spec input [] 0 [] rfl (matchSym_short [] (by simp))
  simpa [decodeImpl, decodeFull, pre] using this

/-! ## Impl: encoder -/

/-- `while nbits >= 8: nbits -= 8; output.append(UInt8(bits >> nbits & 0xFF))`
mirrors flare/http/hpack_huffman.mojo:724-727 @59bda50 -/
def flush (bits : UInt64) (nbits : Nat) (out : Bytes) : Nat × Bytes :=
  if 8 ≤ nbits then
    flush bits (nbits - 8) (out ++ [((bits >>> UInt64.ofNat (nbits - 8)) &&& 0xFF).toUInt8])
  else (nbits, out)
termination_by nbits

/-- mirrors flare/http/hpack_huffman.mojo:711-737 @59bda50 -/
def encodeLoop (bits : UInt64) (nbits : Nat) (out : Bytes) : Bytes → Bytes
  | [] =>
    if 0 < nbits then
      let padShift := 8 - nbits
      out ++ [(((bits <<< UInt64.ofNat padShift) ||| UInt64.ofNat (2 ^ padShift - 1)) &&& 0xFF).toUInt8]
    else out
  | b :: bs =>
    let c := tableCode b.toNat
    let clen := tableLength b.toNat
    let bits' := (bits <<< UInt64.ofNat clen) ||| UInt64.ofNat c
    let r := flush bits' (nbits + clen) out
    encodeLoop bits' r.1 r.2 bs

/-- `huffman_encode(input, output)` with `output` initially empty.
mirrors flare/http/hpack_huffman.mojo:697-737 @59bda50 -/
def encodeImpl (input : Bytes) : Bytes := encodeLoop 0 0 [] input

/-- mirrors flare/http/hpack_huffman.mojo:684-694 @59bda50 (`huffman_encoded_length`) -/
def encodedLengthImpl (input : Bytes) : Nat :=
  ((input.map fun b => tableLength b.toNat).sum + 7) / 8

theorem byte_of (x : UInt64) : (x &&& 0xFF).toUInt8 = UInt8.ofNat (x.toNat % 256) := by
  apply UInt8.toNat_inj.mp
  rw [UInt64.toNat_toUInt8, UInt64.toNat_and, UInt8.toNat_ofNat']
  have : (0xFF : UInt64).toNat = 2 ^ 8 - 1 := rfl
  rw [this, Nat.and_two_pow_sub_one_eq_mod]

theorem flush_spec (q : List Bool) (bits : UInt64) (out : Bytes) (hb : bits.toNat % 2 ^ q.length = val q)
    (hq : q.length ≤ 63) :
    flush bits q.length out = (q.length % 8, out ++ pack (q.take (8 * (q.length / 8)))) := by
  induction hm : q.length using Nat.strongRecOn generalizing q out with
  | _ n ih =>
    subst hm
    rw [flush]
    split
    · next h8 =>
      have hbyte : ((bits >>> UInt64.ofNat (q.length - 8)) &&& 0xFF).toUInt8 = UInt8.ofNat (val (q.take 8)) := by
        rw [byte_of, UInt64.toNat_shiftRight, ofNat_toNat_lt _ (by have := two_pow_lt64 6 (by omega); omega),
          Nat.mod_eq_of_lt (show q.length - 8 < 64 by omega), Nat.shiftRight_eq_div_pow, val_take _ _ h8, ← hb]
        have e : 2 ^ q.length = 2 ^ (q.length - 8) * 2 ^ 8 := by rw [← Nat.pow_add]; congr 1; omega
        rw [e, Nat.mod_mul_right_div_self]
      have hd : bits.toNat % 2 ^ (q.drop 8).length = val (q.drop 8) := by
        rw [val_drop, ← hb, List.length_drop,
          Nat.mod_mod_of_dvd _ (Nat.pow_dvd_pow 2 (by omega))]
      have := ih (q.drop 8).length (by simp; omega) (q.drop 8) (out ++ [UInt8.ofNat (val (q.take 8))])
        hd (by simp; omega) rfl
      simp only [List.length_drop] at this
      rw [hbyte, this]
      have e2 : 8 * (q.length / 8) = 8 + 8 * ((q.length - 8) / 8) := by omega
      have e3 : (q.length - 8) % 8 = q.length % 8 := by omega
      rw [e2, List.take_add, pack_cons8 _ _ (by simp; omega), e3]; simp
    · next h8 =>
      have : q.length / 8 = 0 := by omega
      rw [this, Nat.mod_eq_of_lt (by omega)]; simp [pack_nil]

theorem encodeLoop_spec (input : Bytes) : ∀ (bits : UInt64) (em pend : List Bool),
    em.length % 8 = 0 → pend.length < 8 → bits.toNat % 2 ^ pend.length = val pend →
    encodeLoop bits pend.length (pack em) input = pack (padBits (em ++ pend ++ encodeBits input)) := by
  induction input with
  | nil =>
    intro bits em pend hem hp hb
    simp only [encodeLoop, encodeBits, List.flatMap_nil, List.append_nil]
    split
    · next h0 =>
      have hbyte := shl_or_mod bits (8 - pend.length) pend.length (2 ^ (8 - pend.length) - 1)
        (by have := Nat.two_pow_pos (8 - pend.length); omega) (by omega) (by omega)
      rw [show pend.length + (8 - pend.length) = 8 by omega] at hbyte
      rw [byte_of, hbyte, hb]
      have hpad : padBits (em ++ pend) = em ++ (pend ++ List.replicate (8 - pend.length) true) := by
        simp only [padBits, List.length_append, List.append_assoc, padLen]
        congr 3; omega
      have hv : val (pend ++ List.replicate (8 - pend.length) true) =
          val pend * 2 ^ (8 - pend.length) + (2 ^ (8 - pend.length) - 1) := by
        rw [val_append, val_replicate_true, List.length_replicate]
      rw [hpad, pack_append _ _ hem, ← List.append_nil (pend ++ _),
        pack_cons8 _ _ (by simp; omega), hv, pack_nil]
    · next h0 =>
      have : pend = [] := List.eq_nil_of_length_eq_zero (by omega)
      subst this
      simp [padBits, padLen, hem]
  | cons b bs ih =>
    intro bits em pend hem hp hb
    have hbl : b.toNat < 257 := by have := b.toNat_lt; omega
    obtain ⟨f1, f2, f3⟩ := code_fits b.toNat hbl
    simp only [encodeLoop, tableCode, tableLength]
    have hc_eq : (code b.toNat).1 = val (codeBits b.toNat) := (val_codeBits _ hbl).symm
    have hl_eq : (code b.toNat).2 = (codeBits b.toNat).length := (length_codeBits _).symm
    rw [hc_eq, hl_eq]
    have f2' : (codeBits b.toNat).length ≤ 30 := by rw [← hl_eq]; exact f2
    have hacc := shl_or_mod bits (codeBits b.toNat).length pend.length (val (codeBits b.toNat))
      (val_lt _) (by omega) (by omega)
    rw [hb, ← val_append] at hacc
    have hq : pend.length + (codeBits b.toNat).length = (pend ++ codeBits b.toNat).length := by simp
    rw [hq] at hacc ⊢
    generalize hbits : ((bits <<< UInt64.ofNat (codeBits b.toNat).length) |||
      UInt64.ofNat (val (codeBits b.toNat))) = bits' at hacc ⊢
    obtain ⟨q, hqd⟩ : ∃ q, q = pend ++ codeBits b.toNat := ⟨_, rfl⟩
    rw [← hqd] at hacc ⊢
    have hql : q.length ≤ 37 := by rw [hqd]; simp; omega
    rw [flush_spec _ _ _ hacc (by omega)]
    simp only
    rw [← pack_append _ _ hem]
    have hlen : (q.drop (8 * (q.length / 8))).length = q.length % 8 := by simp; omega
    have hres : bits'.toNat % 2 ^ (q.drop (8 * (q.length / 8))).length = val (q.drop (8 * (q.length / 8))) := by
      rw [val_drop, ← hacc, List.length_drop, Nat.mod_mod_of_dvd _ (Nat.pow_dvd_pow 2 (by omega))]
    have := ih bits' (em ++ q.take (8 * (q.length / 8))) (q.drop (8 * (q.length / 8)))
      (by simp; omega) (by omega) hres
    rw [hlen] at this
    rw [this, List.append_assoc em, List.take_append_drop, hqd]
    simp [encodeBits, List.append_assoc]

/-- The Mojo encoder computes the spec encoding. -/
theorem encodeImpl_eq (input : Bytes) : encodeImpl input = encode input := by
  have := encodeLoop_spec input 0 [] [] rfl (by simp) rfl
  simpa [encodeImpl, encode, pack_nil] using this

theorem decodeImpl_encodeImpl (input : Bytes) : decodeImpl (encodeImpl input) = (input, none) := by
  rw [decodeImpl_eq, encodeImpl_eq]
  have := decode_encode input
  unfold decode at this
  split at this
  · next o e => cases this; exact e
  · cases this

theorem length_encodeBits (input : Bytes) :
    (encodeBits input).length = (input.map fun b => tableLength b.toNat).sum := by
  induction input with
  | nil => rfl
  | cons b bs ih => simp [encodeBits, length_codeBits, tableLength] at ih ⊢

theorem length_pack (r : List Bool) (h : r.length % 8 = 0) : (pack r).length = r.length / 8 := by
  have := length_unpack (pack r)
  rw [unpack_pack r h] at this; omega

theorem encodedLengthImpl_eq (input : Bytes) : encodedLengthImpl input = (encodeImpl input).length := by
  rw [encodeImpl_eq, encode, length_pack _ (padBits_length _), encodedLengthImpl, ← length_encodeBits]
  simp [padBits, padLen]; omega

/-! ## Impl: fast-table decoder (hpack_huffman_simd.mojo) -/

/-- mirrors flare/http/hpack_huffman_simd.mojo:110-130 @59bda50 (`_make_root_table`) -/
def rootTableImpl : List Nat :=
  (List.range 256).foldl (fun t sym =>
    let clen := tableLength sym
    if clen ≤ 8 then
      let c := tableCode sym
      let shift := 8 - clen
      let base := c <<< shift
      (List.range (1 <<< shift)).foldl (fun t j => t.set (base + j) ((sym <<< 8) ||| clen)) t
    else t) (List.replicate 256 0)

def RT : List Nat :=
  [12293, 12293, 12293, 12293, 12293, 12293, 12293, 12293, 12549, 12549, 12549, 12549, 12549,
  12549, 12549, 12549, 12805, 12805, 12805, 12805, 12805, 12805, 12805, 12805, 24837, 24837,
  24837, 24837, 24837, 24837, 24837, 24837, 25349, 25349, 25349, 25349, 25349, 25349, 25349,
  25349, 25861, 25861, 25861, 25861, 25861, 25861, 25861, 25861, 26885, 26885, 26885, 26885,
  26885, 26885, 26885, 26885, 28421, 28421, 28421, 28421, 28421, 28421, 28421, 28421, 29445,
  29445, 29445, 29445, 29445, 29445, 29445, 29445, 29701, 29701, 29701, 29701, 29701, 29701,
  29701, 29701, 8198, 8198, 8198, 8198, 9478, 9478, 9478, 9478, 11526, 11526, 11526, 11526, 11782,
  11782, 11782, 11782, 12038, 12038, 12038, 12038, 13062, 13062, 13062, 13062, 13318, 13318,
  13318, 13318, 13574, 13574, 13574, 13574, 13830, 13830, 13830, 13830, 14086, 14086, 14086,
  14086, 14342, 14342, 14342, 14342, 14598, 14598, 14598, 14598, 15622, 15622, 15622, 15622,
  16646, 16646, 16646, 16646, 24326, 24326, 24326, 24326, 25094, 25094, 25094, 25094, 25606,
  25606, 25606, 25606, 26118, 26118, 26118, 26118, 26374, 26374, 26374, 26374, 26630, 26630,
  26630, 26630, 27654, 27654, 27654, 27654, 27910, 27910, 27910, 27910, 28166, 28166, 28166,
  28166, 28678, 28678, 28678, 28678, 29190, 29190, 29190, 29190, 29958, 29958, 29958, 29958,
  14855, 14855, 16903, 16903, 17159, 17159, 17415, 17415, 17671, 17671, 17927, 17927, 18183,
  18183, 18439, 18439, 18695, 18695, 18951, 18951, 19207, 19207, 19463, 19463, 19719, 19719,
  19975, 19975, 20231, 20231, 20487, 20487, 20743, 20743, 20999, 20999, 21255, 21255, 21511,
  21511, 21767, 21767, 22023, 22023, 22279, 22279, 22791, 22791, 27143, 27143, 27399, 27399,
  28935, 28935, 30215, 30215, 30471, 30471, 30727, 30727, 30983, 30983, 31239, 31239, 9736, 10760,
  11272, 15112, 22536, 23048, 0, 0]

theorem rootTable_eq : rootTableImpl = RT := by decide +kernel

/-- A nonzero entry names a code of length ≤ 8 that is a prefix of the index. -/
theorem RT_sound : ∀ top, top < 256 → RT.getD top 0 % 256 = 0 ∨
    (5 ≤ RT.getD top 0 % 256 ∧ RT.getD top 0 % 256 ≤ 8 ∧ RT.getD top 0 / 256 < 256 ∧
      code (RT.getD top 0 / 256) = (top / 2 ^ (8 - RT.getD top 0 % 256), RT.getD top 0 % 256)) := by
  decide +kernel

/-- Every code of length ≤ 8 fills all entries it prefixes. -/
theorem RT_complete : ∀ s, s < 256 → (code s).2 ≤ 8 → ∀ j, j < 2 ^ (8 - (code s).2) →
    RT.getD ((code s).1 * 2 ^ (8 - (code s).2) + j) 0 = s * 256 + (code s).2 := by
  decide +kernel

/-- Mojo `range(9, 31)`. -/
def LONG : List Nat := List.range' 9 22

theorem long_bounds : ∀ L ∈ LONG, 5 ≤ L ∧ L ≤ 30 := by
  intro L h; simp only [LONG, List.mem_range'_1] at h; omega

theorem long_sorted : LONG.Pairwise (· < ·) := by decide

def maskS (nb : Nat) : UInt64 := ((1 : UInt64) <<< UInt64.ofNat nb) - 1

theorem maskS_eq (nb : Nat) (h : nb < 64) : maskS nb = UInt64.ofNat (2 ^ nb - 1) := by
  apply UInt64.toNat_inj.mp
  have hp := two_pow_lt64 nb (by omega)
  rw [maskS, UInt64.toNat_sub, UInt64.toNat_shiftLeft, ofNat_toNat_lt _ (by
      have := two_pow_lt64 6 (by omega); omega), Nat.mod_eq_of_lt h,
    ofNat_toNat_lt _ (by omega)]
  have : (1 : UInt64).toNat = 1 := rfl
  rw [this, Nat.shiftLeft_eq, Nat.one_mul, Nat.mod_eq_of_lt hp]
  have := Nat.two_pow_pos nb
  rw [show 2 ^ 64 - 1 + 2 ^ nb = 2 ^ 64 + (2 ^ nb - 1) by omega, Nat.add_mod_left,
    Nat.mod_eq_of_lt (by omega)]

/-- `_ROOT_TABLE[(bits >> (nbits - 8)) & 0xFF]`. -/
def entryAt (bits : UInt64) (nbits : Nat) : Nat :=
  rootTableImpl.getD ((bits >>> UInt64.ofNat (nbits - 8)) &&& 0xFF).toNat 0

/-- The inner `while nbits >= 8` loop: fast-table lookup on the top byte,
long-code walker over lengths 9..30 otherwise.
mirrors flare/http/hpack_huffman_simd.mojo:175-210 @59bda50 -/
def drainFast (bits : UInt64) (nbits : Nat) (out : Bytes) : UInt64 × Nat × Bytes × Option Error :=
  if nbits < 8 then (bits, nbits, out, none)
  else
    if _hc : 0 < entryAt bits nbits &&& 0xFF then
      let nb := nbits - (entryAt bits nbits &&& 0xFF)
      drainFast (if 0 < nb then bits &&& maskS nb else 0) nb (out ++ [UInt8.ofNat (entryAt bits nbits >>> 8)])
    else
      match _h : tryLens bits nbits LONG with
      | none => (bits, nbits, out, none)
      | some (sym, clen2) =>
        if sym = 256 then (bits, nbits, out, some .eosInInput)
        else
          let nb := nbits - clen2
          drainFast (if 0 < nb then bits &&& maskS nb else 0) nb (out ++ [UInt8.ofNat sym.toNat])
termination_by nbits
decreasing_by
  · omega
  · have := tryLens_some _ _ _ _ _ _h
    have := long_bounds clen2 this.1
    omega

theorem drainFast_lt (bits : UInt64) (nbits : Nat) (out : Bytes) (h : nbits < 8) :
    drainFast bits nbits out = (bits, nbits, out, none) := by
  rw [drainFast, if_pos h]

theorem drainFast_hit (bits : UInt64) (nbits : Nat) (out : Bytes) (h : ¬ nbits < 8)
    (hc : 0 < entryAt bits nbits &&& 0xFF) :
    drainFast bits nbits out =
      drainFast (if 0 < nbits - (entryAt bits nbits &&& 0xFF) then
          bits &&& maskS (nbits - (entryAt bits nbits &&& 0xFF)) else 0)
        (nbits - (entryAt bits nbits &&& 0xFF)) (out ++ [UInt8.ofNat (entryAt bits nbits >>> 8)]) := by
  rw [drainFast, if_neg h]; simp only; rw [dif_pos hc]

theorem drainFast_miss_none (bits : UInt64) (nbits : Nat) (out : Bytes) (h : ¬ nbits < 8)
    (hc : ¬ 0 < entryAt bits nbits &&& 0xFF) (ht : tryLens bits nbits LONG = none) :
    drainFast bits nbits out = (bits, nbits, out, none) := by
  rw [drainFast, if_neg h]; simp only; rw [dif_neg hc]
  split
  · rfl
  · next e => rw [ht] at e; cases e

theorem drainFast_miss_some (bits : UInt64) (nbits : Nat) (out : Bytes) (h : ¬ nbits < 8)
    (hc : ¬ 0 < entryAt bits nbits &&& 0xFF) (sym : Int) (clen2 : Nat)
    (ht : tryLens bits nbits LONG = some (sym, clen2)) :
    drainFast bits nbits out = if sym = 256 then (bits, nbits, out, some .eosInInput) else
      drainFast (if 0 < nbits - clen2 then bits &&& maskS (nbits - clen2) else 0) (nbits - clen2)
        (out ++ [UInt8.ofNat sym.toNat]) := by
  rw [drainFast, if_neg h]; simp only; rw [dif_neg hc]
  split
  · next e => rw [ht] at e; cases e
  · next sym' clen' e => rw [ht] at e; cases e; rfl

/-- No code of length ≤ 8 is a hit when the fast-table entry is empty. -/
theorem no_short_hit (buf : List Bool) (h8 : 8 ≤ buf.length)
    (he : RT.getD (val (buf.take 8)) 0 % 256 = 0) (L s : Nat) (hh : Hit buf L s) : 9 ≤ L := by
  obtain ⟨hl, hs, hc⟩ := hh
  by_cases hlt : 9 ≤ L
  · exact hlt
  exfalso
  have hL8 : L ≤ 8 := by omega
  have hs256 : s < 256 := by
    by_cases h' : s < 256
    · exact h'
    · have : s = 256 := by omega
      subst this; rw [show code 256 = (2 ^ 30 - 1, 30) from eos_all_ones] at hc
      simp at hc; omega
  have hcl : (code s).2 = L := by rw [hc]
  have htop : val (buf.take L) = val (buf.take 8) / 2 ^ (8 - L) := by
    have : buf.take L = (buf.take 8).take L := by rw [List.take_take, Nat.min_eq_left hL8]
    rw [this, val_take _ _ (by simp; omega)]; simp; congr 2; omega
  have hv8 := val_lt (buf.take 8)
  simp only [List.length_take, Nat.min_eq_left h8] at hv8
  have hdm := Nat.div_add_mod (val (buf.take 8)) (2 ^ (8 - L))
  have := RT_complete s hs256 (by omega) (val (buf.take 8) % 2 ^ (8 - L))
    (by rw [hcl]; exact Nat.mod_lt _ (Nat.two_pow_pos _))
  rw [hcl, show (code s).1 = val (buf.take L) by rw [hc], htop, Nat.mul_comm, hdm] at this
  rw [this] at he
  have hf := (code_fits s (by omega)).1
  rw [hcl] at hf
  omega

theorem drainFast_spec (buf : List Bool) (bits : UInt64) (out : Bytes) (hb : bits.toNat = val buf)
    (hn : buf.length ≤ 37) :
    match drainFast bits buf.length out with
    | (b', n', out', none) => ∃ buf', b'.toNat = val buf' ∧ n' = buf'.length ∧ buf'.length ≤ 29 ∧
        ∀ rest, pre out' (decodeBits (buf' ++ rest)) = pre out (decodeBits (buf ++ rest))
    | (_, _, out', some e) => ∀ rest, pre out (decodeBits (buf ++ rest)) = (out', some e) := by
  induction hm : buf.length using Nat.strongRecOn generalizing buf bits out with
  | _ n ih =>
    subst hm
    by_cases h8 : buf.length < 8
    · rw [drainFast_lt _ _ _ h8]; exact ⟨buf, hb, rfl, by omega, fun _ => rfl⟩
    · have htop := extract bits buf hb (by omega) 8 (by omega)
      have hent : entryAt bits buf.length = RT.getD (val (buf.take 8)) 0 := by
        rw [entryAt, rootTable_eq, ← htop]; rfl
      have hv8 := val_lt (buf.take 8)
      simp only [List.length_take, Nat.min_eq_left (show 8 ≤ buf.length by omega)] at hv8
      have hand : entryAt bits buf.length &&& 0xFF = RT.getD (val (buf.take 8)) 0 % 256 := by
        rw [hent, show (0xFF : Nat) = 2 ^ 8 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
      -- shared continuation after emitting a symbol
      have cont : ∀ (s L : Nat), matchSym buf = some (s, L) → s ≠ 256 →
          match drainFast (if 0 < buf.length - L then bits &&& maskS (buf.length - L) else 0)
              (buf.length - L) (out ++ [UInt8.ofNat s]) with
          | (b', n', out', none) => ∃ buf', b'.toNat = val buf' ∧ n' = buf'.length ∧ buf'.length ≤ 29 ∧
              ∀ rest, pre out' (decodeBits (buf' ++ rest)) = pre out (decodeBits (buf ++ rest))
          | (_, _, out', some e) => ∀ rest, pre out (decodeBits (buf ++ rest)) = (out', some e) := by
        intro s L hms hs
        have h5 := (matchSym_some buf s L hms).1
        have hlen := (matchSym_some buf s L hms).2.1
        have hmask : (if 0 < buf.length - L then bits &&& maskS (buf.length - L) else 0) =
            (if 0 < buf.length - L then bits &&& UInt64.ofNat (2 ^ (buf.length - L) - 1) else 0) := by
          split
          · rw [maskS_eq _ (by omega)]
          · rfl
        have ih' := ih (buf.drop L).length (by rw [List.length_drop]; omega) (buf.drop L)
          (if 0 < buf.length - L then bits &&& maskS (buf.length - L) else 0) (out ++ [UInt8.ofNat s])
          (by rw [hmask]; exact mask_val bits buf hb (by omega) L) (by simp; omega) rfl
        simp only [List.length_drop] at ih'
        generalize drainFast _ _ _ = R at ih' ⊢
        obtain ⟨b', n', out', e'⟩ := R
        cases e' with
        | none =>
          obtain ⟨buf', h1, h2, h3, h5⟩ := ih'
          exact ⟨buf', h1, h2, h3, fun rest => by rw [h5, decodeBits_step buf rest s L hms hs]⟩
        | some err =>
          intro rest
          rw [decodeBits_step buf rest s L hms hs]; exact ih' rest
      by_cases hc : 0 < entryAt bits buf.length &&& 0xFF
      · rw [drainFast_hit _ _ _ h8 hc]
        rw [hand] at hc ⊢
        rw [hent]
        have hs8 := RT_sound (val (buf.take 8)) hv8
        generalize RT.getD (val (buf.take 8)) 0 = E at hc hs8 ⊢
        rcases hs8 with h0 | ⟨g1, g2, g3, g4⟩
        · omega
        · have e1 : val (buf.take (E % 256)) = val (buf.take 8) / 2 ^ (8 - E % 256) := by
            have : buf.take (E % 256) = (buf.take 8).take (E % 256) := by
              rw [List.take_take, Nat.min_eq_left g2]
            rw [this, val_take _ _ (by rw [List.length_take]; omega), List.length_take,
              Nat.min_eq_left (show 8 ≤ buf.length by omega)]
          have hhit : Hit buf (E % 256) (E / 256) := ⟨by omega, by omega, by rw [g4, e1]⟩
          have hms := matchSym_of_hit _ _ _ hhit
          have := cont _ _ hms (by omega)
          rwa [show E >>> 8 = E / 256 by rw [Nat.shiftRight_eq_div_pow]]
      · have hz : RT.getD (val (buf.take 8)) 0 % 256 = 0 := by omega
        have hte := tryLens_eq bits buf hb (by omega) LONG long_bounds
        -- the long walker finds exactly `matchSym`
        have hlong : matchFrom buf LONG = matchSym buf := by
          cases e : matchSym buf with
          | some p =>
            obtain ⟨s, L⟩ := p
            have hh := (matchSym_some buf s L e).2
            have h9 := no_short_hit buf (by omega) hz L s hh
            have := (code_fits s hh.2.1); rw [hh.2.2] at this
            exact matchFrom_of_hit buf LONG long_sorted L s
              (by simp only [LONG, List.mem_range'_1]; simp at this; omega) hh
          | none =>
            cases e2 : matchFrom buf LONG with
            | none => rfl
            | some p =>
              obtain ⟨s, L⟩ := p
              have := matchSym_of_hit buf L s (matchFrom_some buf LONG s L e2).2
              rw [e] at this; cases this
        rw [hlong] at hte
        cases e : tryLens bits buf.length LONG with
        | none =>
          rw [drainFast_miss_none _ _ _ h8 hc e]
          rw [e] at hte
          exact ⟨buf, hb, rfl, by
            have : matchSym buf = none := by cases h : matchSym buf <;> simp_all
            have := matchSym_none_length buf this; omega, fun _ => rfl⟩
        | some p =>
          obtain ⟨sym, clen2⟩ := p
          rw [drainFast_miss_some _ _ _ h8 hc _ _ e]
          rw [e] at hte
          obtain ⟨s, L, hms, hsym, hL⟩ : ∃ s L, matchSym buf = some (s, L) ∧ sym = s ∧ clen2 = L := by
            cases h : matchSym buf with
            | none => simp [h] at hte
            | some p => obtain ⟨s, L⟩ := p; simp [h] at hte; obtain ⟨h1, h2⟩ := hte; exact ⟨s, L, rfl, by omega, by omega⟩
          subst hsym hL
          by_cases h256 : ((s : Int) = 256)
          · rw [if_pos h256]
            have : s = 256 := by omega
            subst this
            exact fun rest => decodeBits_eosStep buf rest clen2 hms out
          · rw [if_neg h256]
            have := cont s clen2 hms (by omega)
            rwa [show ((s : Int).toNat) = s by simp]

/-- The main `while i < n` loop, the tail walker (the scalar inner loop,
with the mask written `(UInt64(1) << nbits) - 1`, equal by `maskS_eq`), and
the padding checks.
mirrors flare/http/hpack_huffman_simd.mojo:166-247 @59bda50 -/
def simdLoop (bits : UInt64) (nbits : Nat) (out : Bytes) : Bytes → Bytes × Option Error
  | [] =>
    match drain bits nbits out with
    | (_, _, out', some e) => (out', some e)
    | (bits', nbits', out', none) => finalCheck bits' nbits' out'
  | b :: bs =>
    match drainFast ((bits <<< 8) ||| b.toUInt64) (nbits + 8) out with
    | (_, _, out', some e) => (out', some e)
    | (bits', nbits', out', none) => simdLoop bits' nbits' out' bs

/-- `huffman_decode_simd(input, output)` with `output` initially empty.
mirrors flare/http/hpack_huffman_simd.mojo:137-247 @59bda50 -/
def decodeSimdImpl (input : Bytes) : Bytes × Option Error :=
  if input.length = 0 then ([], none) else simdLoop 0 0 [] input

/-- mirrors flare/http/hpack_huffman_simd.mojo:250-276 @59bda50 -/
def decodeDispatch (input : Bytes) (useTable : Bool) : Bytes × Option Error :=
  if useTable = true ∧ 32 ≤ input.length then decodeSimdImpl input else decodeImpl input

theorem simdLoop_spec (input : Bytes) : ∀ (buf : List Bool) (bits : UInt64) (out : Bytes),
    bits.toNat = val buf → buf.length ≤ 29 →
    simdLoop bits buf.length out input = pre out (decodeBits (buf ++ unpack input)) := by
  induction input with
  | nil =>
    intro buf bits out hb hl
    simp only [simdLoop, unpack, List.flatMap_nil, List.append_nil]
    have d := drain_spec buf bits out hb (by omega)
    generalize drain _ _ _ = R at d ⊢
    obtain ⟨b', n', out', e'⟩ := R
    cases e' with
    | none =>
      obtain ⟨buf', h1, h2, -, h4, h5⟩ := d
      simp only
      have h6 := h5 []
      simp only [List.append_nil] at h6
      rw [h2, finalCheck_spec buf' b' out' h1 h4, h6]
    | some err => have := d []; rw [List.append_nil] at this; exact this.symm
  | cons b bs ih =>
    intro buf bits out hb hl
    obtain ⟨hv, hlen⟩ := push_byte bits buf b hb hl
    have d := drainFast_spec (buf ++ bitsOf b.toNat 8) _ out hv (by omega)
    rw [hlen] at d
    simp only [simdLoop]
    have hu : buf ++ unpack (b :: bs) = (buf ++ bitsOf b.toNat 8) ++ unpack bs := by
      simp [unpack, List.flatMap_cons, List.append_assoc]
    rw [hu]
    generalize drainFast _ _ _ = R at d ⊢
    obtain ⟨b', n', out', e'⟩ := R
    cases e' with
    | none =>
      obtain ⟨buf', h1, h2, h3, h5⟩ := d
      simp only
      rw [h2, ih buf' b' out' h1 h3, h5]
    | some err => exact (d _).symm

/-- The fast-table decoder computes the spec decoder exactly. -/
theorem decodeSimdImpl_eq (input : Bytes) : decodeSimdImpl input = decodeFull input := by
  unfold decodeSimdImpl
  split
  · next h =>
    rw [List.eq_nil_of_length_eq_zero h]
    rw [decodeFull, show unpack [] = [] from rfl, decodeBits_none [] (matchSym_short [] (by simp))]
    rfl
  · have := simdLoop_spec input [] 0 [] rfl (by simp)
    simpa [decodeFull, pre] using this

/-- Fast-table and scalar decoders agree on every input (output and error). -/
theorem decodeSimdImpl_eq_decodeImpl (input : Bytes) : decodeSimdImpl input = decodeImpl input := by
  rw [decodeSimdImpl_eq, decodeImpl_eq]

theorem decodeDispatch_eq (input : Bytes) (useTable : Bool) :
    decodeDispatch input useTable = decodeFull input := by
  unfold decodeDispatch; split
  · exact decodeSimdImpl_eq input
  · exact decodeImpl_eq input

/-- Mojo's raising decoders seen as partial functions: `some out` when no
`HuffmanError` is raised. -/
def okOnly (r : Bytes × Option Error) : Option Bytes :=
  match r with
  | (out, none) => some out
  | _ => none

theorem okOnly_decodeSimdImpl (input : Bytes) : okOnly (decodeSimdImpl input) = decode input := by
  rw [decodeSimdImpl_eq]; rfl

theorem okOnly_decodeImpl (input : Bytes) : okOnly (decodeImpl input) = decode input := by
  rw [decodeImpl_eq]; rfl

theorem okOnly_decodeDispatch (input : Bytes) (useTable : Bool) :
    okOnly (decodeDispatch input useTable) = decode input := by
  rw [decodeDispatch_eq]; rfl

end Flare.L1.Huffman
