import Flare.Core
import Flare.L1_Encoding.Bits
/-!
# Base64 (crypto/base64.mojo, crypto/hmac.mojo; RFC 4648 §4, §5)

`base64_encode` emits the standard alphabet with `=` padding;
`base64url_encode` emits the URL-safe alphabet without padding. The two
decoders (`base64_decode`, `base64url_decode`) are the same algorithm
(byte-for-byte identical apart from error strings), modeled once as
`decode`: optional `=` padding (at most two, and only on a length that is a
multiple of 4), either alphabet's two extra characters, and zero trailing
bits in a final partial quantum (RFC 4648 §3.5).

Arithmetic is on bytes and 6-bit indices; it is modeled in `UInt32`, which
is exact for every intermediate (`< 2^14`).

Spec: `sextets d` is the RFC 4648 §4 sequence of 6-bit groups of `d`
(the last group zero-filled), `padLen d` the number of `=` that complete
the last quantum.

Theorems:
* `encodeStd_eq`, `encodeUrl_eq`: the encoders emit the sextets through
  their alphabet, plus `padLen d` `=` for the standard one.
* `decode_encodeStd`, `decode_encodeUrl`: decoding either encoding gives
  back the input.
* `decode_canonical`: whenever `decode s = some d`, `s` minus its padding
  is `encodeUrl d` / `encodeStd d` up to the per-character choice between
  `+`/`-` and `/`/`_`, and the padding is either absent or exactly
  `padLen d` characters (`decode_padding`). These are the only spellings
  the decoder accepts.
-/
namespace Flare.L1.Base64

set_option linter.unusedSimpArgs false

/-- mirrors flare/crypto/base64.mojo:35-37 @59bda50 -/
def TABLE : Bytes :=
  (List.range 26).map (fun i => UInt8.ofNat (65 + i)) ++
  (List.range 26).map (fun i => UInt8.ofNat (97 + i)) ++
  (List.range 10).map (fun i => UInt8.ofNat (48 + i)) ++ [43, 47]

/-- mirrors flare/crypto/hmac.mojo:146-147 @59bda50 -/
def URL_TABLE : Bytes :=
  (List.range 26).map (fun i => UInt8.ofNat (65 + i)) ++
  (List.range 26).map (fun i => UInt8.ofNat (97 + i)) ++
  (List.range 10).map (fun i => UInt8.ofNat (48 + i)) ++ [45, 95]

def tbl (t : Bytes) (i : UInt32) : UInt8 := t.getD i.toNat

/-! ## Spec: sextets -/

def q0 (a : UInt8) : UInt32 := a.toUInt32 >>> 2
def q1 (a b : UInt8) : UInt32 := ((a.toUInt32 &&& 3) <<< 4) ||| (b.toUInt32 >>> 4)
def q2 (b c : UInt8) : UInt32 := ((b.toUInt32 &&& 0xF) <<< 2) ||| (c.toUInt32 >>> 6)
def q3 (c : UInt8) : UInt32 := c.toUInt32 &&& 0x3F

def sextets : Bytes → List UInt32
  | a :: b :: c :: rest => q0 a :: q1 a b :: q2 b c :: q3 c :: sextets rest
  | [a, b] => [q0 a, q1 a b, (b.toUInt32 &&& 0xF) <<< 2]
  | [a] => [q0 a, (a.toUInt32 &&& 3) <<< 4]
  | [] => []

def padLen : Bytes → Nat
  | _ :: _ :: _ :: rest => padLen rest
  | [_, _] => 1
  | [_] => 2
  | [] => 0

/-! ## Implementation -/

/-- mirrors flare/crypto/base64.mojo:41-79 @59bda50 -/
def encodeStd : Bytes → Bytes
  | a :: b :: c :: rest =>
    [tbl TABLE (a.toUInt32 >>> 2), tbl TABLE (((a.toUInt32 &&& 3) <<< 4) ||| (b.toUInt32 >>> 4)),
      tbl TABLE (((b.toUInt32 &&& 0xF) <<< 2) ||| (c.toUInt32 >>> 6)),
      tbl TABLE (c.toUInt32 &&& 0x3F)] ++ encodeStd rest
  | [a, b] =>
    [tbl TABLE (a.toUInt32 >>> 2), tbl TABLE (((a.toUInt32 &&& 3) <<< 4) ||| (b.toUInt32 >>> 4)),
      tbl TABLE ((b.toUInt32 &&& 0xF) <<< 2), 61]
  | [a] => [tbl TABLE (a.toUInt32 >>> 2), tbl TABLE ((a.toUInt32 &&& 3) <<< 4), 61, 61]
  | [] => []

/-- mirrors flare/crypto/hmac.mojo:150-183 @59bda50 -/
def encodeUrl : Bytes → Bytes
  | a :: b :: c :: rest =>
    [tbl URL_TABLE ((a.toUInt32 >>> 2) &&& 63),
      tbl URL_TABLE (((a.toUInt32 <<< 4) ||| (b.toUInt32 >>> 4)) &&& 63),
      tbl URL_TABLE (((b.toUInt32 <<< 2) ||| (c.toUInt32 >>> 6)) &&& 63),
      tbl URL_TABLE (c.toUInt32 &&& 63)] ++ encodeUrl rest
  | [a, b] =>
    [tbl URL_TABLE ((a.toUInt32 >>> 2) &&& 63),
      tbl URL_TABLE (((a.toUInt32 <<< 4) ||| (b.toUInt32 >>> 4)) &&& 63),
      tbl URL_TABLE ((b.toUInt32 <<< 2) &&& 63)]
  | [a] => [tbl URL_TABLE ((a.toUInt32 >>> 2) &&& 63), tbl URL_TABLE ((a.toUInt32 <<< 4) &&& 63)]
  | [] => []

/-- mirrors flare/crypto/base64.mojo:82-101 and flare/crypto/hmac.mojo:187-205 @59bda50 -/
def decodeByte (c : UInt8) : Option UInt32 :=
  if 65 ≤ c ∧ c ≤ 90 then some (c.toUInt32 - 65)
  else if 97 ≤ c ∧ c ≤ 122 then some (c.toUInt32 - 97 + 26)
  else if 48 ≤ c ∧ c ≤ 57 then some (c.toUInt32 - 48 + 52)
  else if c = 43 ∨ c = 45 then some 62
  else if c = 47 ∨ c = 95 then some 63
  else none

def o0 (b0 b1 : UInt32) : UInt8 := (((b0 <<< 2) ||| (b1 >>> 4)) &&& 0xFF).toUInt8
def o1 (b1 b2 : UInt32) : UInt8 := (((b1 <<< 4) ||| (b2 >>> 2)) &&& 0xFF).toUInt8
def o2 (b2 b3 : UInt32) : UInt8 := (((b2 <<< 6) ||| b3) &&& 0xFF).toUInt8

/-- Quantum loop and tail. mirrors flare/crypto/base64.mojo:137-163 @59bda50 -/
def decodeQuads : Bytes → Option Bytes
  | c0 :: c1 :: c2 :: c3 :: rest =>
    match decodeByte c0, decodeByte c1, decodeByte c2, decodeByte c3, decodeQuads rest with
    | some b0, some b1, some b2, some b3, some r => some (o0 b0 b1 :: o1 b1 b2 :: o2 b2 b3 :: r)
    | _, _, _, _, _ => none
  | [c0, c1, c2] =>
    match decodeByte c0, decodeByte c1, decodeByte c2 with
    | some b0, some b1, some b2 => if b2 &&& 3 ≠ 0 then none else some [o0 b0 b1, o1 b1 b2]
    | _, _, _ => none
  | [c0, c1] =>
    match decodeByte c0, decodeByte c1 with
    | some b0, some b1 => if b1 &&& 0xF ≠ 0 then none else some [o0 b0 b1]
    | _, _ => none
  | [_] => none
  | [] => some []

/-- Number of leading `=` (applied to the reversed string). -/
def trailingEq : Bytes → Nat
  | c :: t => if c = 61 then trailingEq t + 1 else 0
  | [] => 0

def padCount (s : Bytes) : Nat := trailingEq s.reverse

def stripPad (s : Bytes) : Bytes := s.take (s.length - padCount s)

/-- mirrors flare/crypto/base64.mojo:104-136 @59bda50 (padding and length checks) -/
def decode (s : Bytes) : Option Bytes :=
  let total := s.length
  let n := total - padCount s
  let pad := total - n
  if pad > 2 ∨ (pad > 0 ∧ total % 4 ≠ 0) then none
  else if n = 0 then some []
  else if n % 4 = 1 then none
  else decodeQuads (s.take n)

/-- `-` ↦ `+`, `_` ↦ `/`. -/
def std (c : UInt8) : UInt8 := if c = 45 then 43 else if c = 95 then 47 else c

/-! ## Table facts (finite checks) -/

theorem decodeByte_tbl : ∀ k, k < 64 →
    decodeByte (TABLE.getD k) = some (UInt32.ofNat k) ∧
      decodeByte (URL_TABLE.getD k) = some (UInt32.ofNat k) ∧
      TABLE.getD k ≠ 61 ∧ URL_TABLE.getD k ≠ 61 ∧ std (URL_TABLE.getD k) = TABLE.getD k := by
  decide

def invOk (c : UInt8) : Bool :=
  match decodeByte c with
  | some i => decide (i.toNat < 64) && TABLE.getD i.toNat == std c
  | none => true

set_option maxRecDepth 4000 in
theorem decodeByte_inv_nat : ∀ n, n < 256 → invOk (UInt8.ofNat n) = true := by
  decide

theorem decodeByte_inv (c : UInt8) (i : UInt32) (h : decodeByte c = some i) :
    i.toNat < 64 ∧ tbl TABLE i = std c := by
  have := decodeByte_inv_nat c.toNat c.toNat_lt
  rw [UInt8.ofNat_toNat] at this
  simp only [invOk, h, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at this
  exact this

/-! ## Word lemmas -/

theorem and_low (v m : UInt32) (k : Nat) (hm : m.toNat = 2 ^ k - 1) (h : v.toNat < 2 ^ k) :
    v &&& m = v := by
  apply UInt32.toNat_inj.mp
  rw [UInt32.toNat_and, hm, Nat.and_two_pow_sub_one_eq_mod]
  exact Nat.mod_eq_of_lt h

theorem lt64_of_mask (v : UInt32) (h : v &&& 63 = v) : v.toNat < 64 := by
  rw [← h, UInt32.toNat_and]
  exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)

theorem decodeByte_tbl' (t : Bytes) (ht : t = TABLE ∨ t = URL_TABLE) (i : UInt32)
    (h : i.toNat < 64) : decodeByte (tbl t i) = some i ∧ tbl t i ≠ 61 := by
  obtain ⟨a, b, c, d, -⟩ := decodeByte_tbl i.toNat h
  unfold tbl
  rcases ht with rfl | rfl
  · exact ⟨by rw [a, UInt32.ofNat_toNat], c⟩
  · exact ⟨by rw [b, UInt32.ofNat_toNat], d⟩

theorem q0_lt (a : UInt8) : (q0 a).toNat < 64 := lt64_of_mask _ (by unfold q0; bit_blast)
theorem q1_lt (a b : UInt8) : (q1 a b).toNat < 64 := lt64_of_mask _ (by unfold q1; bit_blast)
theorem q2_lt (b c : UInt8) : (q2 b c).toNat < 64 := lt64_of_mask _ (by unfold q2; bit_blast)
theorem q3_lt (c : UInt8) : (q3 c).toNat < 64 := lt64_of_mask _ (by unfold q3; bit_blast)
theorem r1_lt (a : UInt8) : ((a.toUInt32 &&& 3) <<< 4).toNat < 64 := lt64_of_mask _ (by bit_blast)
theorem r2_lt (b : UInt8) : ((b.toUInt32 &&& 0xF) <<< 2).toNat < 64 :=
  lt64_of_mask _ (by bit_blast)

theorem sextets_lt (d : Bytes) : ∀ i ∈ sextets d, i.toNat < 64 := by
  induction d using sextets.induct with
  | case1 a b c rest ih =>
    intro i hi
    simp only [sextets, List.mem_cons] at hi
    rcases hi with rfl | rfl | rfl | rfl | hi
    · exact q0_lt a
    · exact q1_lt a b
    · exact q2_lt b c
    · exact q3_lt c
    · exact ih i hi
  | case2 a b =>
    intro i hi; simp only [sextets, List.mem_cons, List.not_mem_nil, or_false] at hi
    rcases hi with rfl | rfl | rfl
    · exact q0_lt a
    · exact q1_lt a b
    · exact r2_lt b
  | case3 a =>
    intro i hi; simp only [sextets, List.mem_cons, List.not_mem_nil, or_false] at hi
    rcases hi with rfl | rfl
    · exact q0_lt a
    · exact r1_lt a
  | case4 => intro i hi; simp [sextets] at hi

/-! ## Encoders emit the sextets -/

theorem encodeStd_eq (d : Bytes) :
    encodeStd d = (sextets d).map (tbl TABLE) ++ List.replicate (padLen d) 61 := by
  induction d using sextets.induct with
  | case1 a b c rest ih => simp only [encodeStd, ih, sextets, padLen, q0, q1, q2, q3]; simp
  | case2 a b => simp [encodeStd, sextets, padLen, q0, q1]
  | case3 a => simp [encodeStd, sextets, padLen, q0]
  | case4 => simp [encodeStd, sextets, padLen]

theorem encodeUrl_eq (d : Bytes) : encodeUrl d = (sextets d).map (tbl URL_TABLE) := by
  induction d using sextets.induct with
  | case1 a b c rest ih =>
    simp only [encodeUrl, ih, sextets, List.map_cons, List.cons_append, List.nil_append]
    rw [show (a.toUInt32 >>> 2) &&& 63 = q0 a by unfold q0; bit_blast,
      show ((a.toUInt32 <<< 4) ||| (b.toUInt32 >>> 4)) &&& 63 = q1 a b by unfold q1; bit_blast,
      show ((b.toUInt32 <<< 2) ||| (c.toUInt32 >>> 6)) &&& 63 = q2 b c by unfold q2; bit_blast,
      show c.toUInt32 &&& 63 = q3 c from rfl]
  | case2 a b =>
    simp only [encodeUrl, sextets, List.map_cons, List.map_nil]
    rw [show (a.toUInt32 >>> 2) &&& 63 = q0 a by unfold q0; bit_blast,
      show ((a.toUInt32 <<< 4) ||| (b.toUInt32 >>> 4)) &&& 63 = q1 a b by unfold q1; bit_blast,
      show (b.toUInt32 <<< (2 : UInt32)) &&& (63 : UInt32) =
        (b.toUInt32 &&& (0xF : UInt32)) <<< (2 : UInt32) by bit_blast]
  | case3 a =>
    simp only [encodeUrl, sextets, List.map_cons, List.map_nil]
    rw [show (a.toUInt32 >>> 2) &&& 63 = q0 a by unfold q0; bit_blast,
      show (a.toUInt32 <<< (4 : UInt32)) &&& (63 : UInt32) =
        (a.toUInt32 &&& (3 : UInt32)) <<< (4 : UInt32) by bit_blast]
  | case4 => simp [encodeUrl, sextets]

/-! ## Decoding the sextets -/

theorem decodeQuads_sextets (t : Bytes) (ht : t = TABLE ∨ t = URL_TABLE) (d : Bytes) :
    decodeQuads ((sextets d).map (tbl t)) = some d := by
  induction d using sextets.induct with
  | case1 a b c rest ih =>
    simp only [sextets, List.map_cons, decodeQuads, ih,
      (decodeByte_tbl' t ht _ (q0_lt a)).1, (decodeByte_tbl' t ht _ (q1_lt a b)).1,
      (decodeByte_tbl' t ht _ (q2_lt b c)).1, (decodeByte_tbl' t ht _ (q3_lt c)).1,
      Option.some.injEq, List.cons.injEq, and_true]
    refine ⟨?_, ?_, ?_⟩
    · unfold o0 q0 q1; bit_blast
    · unfold o1 q1 q2; bit_blast
    · unfold o2 q2 q3; bit_blast
  | case2 a b =>
    simp only [sextets, List.map_cons, List.map_nil, decodeQuads,
      (decodeByte_tbl' t ht _ (q0_lt a)).1, (decodeByte_tbl' t ht _ (q1_lt a b)).1,
      (decodeByte_tbl' t ht _ (r2_lt b)).1]
    rw [if_neg (by rw [show ((b.toUInt32 &&& 0xF) <<< 2) &&& 3 = 0 by bit_blast]; decide)]
    simp only [Option.some.injEq, List.cons.injEq, and_true]
    refine ⟨?_, ?_⟩
    · unfold o0 q0 q1; bit_blast
    · unfold o1 q1; bit_blast
  | case3 a =>
    simp only [sextets, List.map_cons, List.map_nil, decodeQuads,
      (decodeByte_tbl' t ht _ (q0_lt a)).1, (decodeByte_tbl' t ht _ (r1_lt a)).1]
    rw [if_neg (by rw [show ((a.toUInt32 &&& 3) <<< 4) &&& 0xF = 0 by bit_blast]; decide)]
    simp only [Option.some.injEq, List.cons.injEq, and_true]
    unfold o0 q0; bit_blast
  | case4 => simp [sextets, decodeQuads]

theorem sextets_length (d : Bytes) :
    (sextets d).length = 4 * (d.length / 3) + (if d.length % 3 = 0 then 0 else d.length % 3 + 1) ∧
      padLen d = (3 - d.length % 3) % 3 := by
  induction d using sextets.induct with
  | case1 a b c rest ih =>
    simp only [sextets, padLen, List.length_cons] at ih ⊢
    obtain ⟨h1, h2⟩ := ih
    rw [h1, h2]
    constructor
    · have e1 : (rest.length + 1 + 1 + 1) / 3 = rest.length / 3 + 1 := by omega
      have e2 : (rest.length + 1 + 1 + 1) % 3 = rest.length % 3 := by omega
      rw [e1, e2]; omega
    · have e2 : (rest.length + 1 + 1 + 1) % 3 = rest.length % 3 := by omega
      rw [e2]
  | case2 a b => simp [sextets, padLen]
  | case3 a => simp [sextets, padLen]
  | case4 => simp [sextets, padLen]

theorem sextets_facts (d : Bytes) :
    (sextets d).length % 4 ≠ 1 ∧ ((sextets d).length = 0 → d = []) ∧ padLen d ≤ 2 ∧
      (padLen d = 0 ∨ ((sextets d).length + padLen d) % 4 = 0) := by
  obtain ⟨h1, h2⟩ := sextets_length d
  rw [h1, h2]
  refine ⟨?_, ?_, ?_, ?_⟩
  · split <;> omega
  · intro hz
    apply List.eq_nil_of_length_eq_zero
    split at hz <;> omega
  · omega
  · split <;> omega

theorem trailingEq_append (k : Nat) (l : Bytes) :
    trailingEq (List.replicate k 61 ++ l) = k + trailingEq l := by
  induction k with
  | zero => simp
  | succ k ih => simp [List.replicate_succ, trailingEq, ih]; omega

theorem trailingEq_zero (l : Bytes) (h : ∀ c ∈ l, c ≠ 61) : trailingEq l = 0 := by
  cases l with
  | nil => rfl
  | cons c t => simp only [trailingEq]; rw [if_neg (h c (by simp))]

theorem decode_core (core : Bytes) (k : Nat) (d : Bytes) (hno : ∀ c ∈ core, c ≠ 61)
    (hk : k ≤ 2) (hk' : k = 0 ∨ (core.length + k) % 4 = 0) (h1 : core.length % 4 ≠ 1)
    (hq : decodeQuads core = some d) (h0 : core.length = 0 → d = []) :
    decode (core ++ List.replicate k 61) = some d := by
  have hp : padCount (core ++ List.replicate k 61) = k := by
    unfold padCount
    rw [List.reverse_append, List.reverse_replicate, trailingEq_append,
      trailingEq_zero _ (fun c hc => hno c (List.mem_reverse.mp hc))]
    rfl
  unfold decode
  simp only [hp, List.length_append, List.length_replicate, Nat.add_sub_cancel]
  rw [if_neg (by omega)]
  by_cases hz : core.length = 0
  · rw [if_pos hz, h0 hz]
  · rw [if_neg hz, if_neg h1, List.take_left' rfl, hq]

theorem decode_encodeStd (d : Bytes) : decode (encodeStd d) = some d := by
  obtain ⟨h1, h0, hk, hk'⟩ := sextets_facts d
  rw [encodeStd_eq]
  apply decode_core
  · intro c hc
    obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hc
    exact (decodeByte_tbl' TABLE (Or.inl rfl) i (sextets_lt d i hi)).2
  · exact hk
  · simpa using hk'
  · simpa using h1
  · exact decodeQuads_sextets TABLE (Or.inl rfl) d
  · intro hz; exact h0 (by simpa using hz)

theorem decode_encodeUrl (d : Bytes) : decode (encodeUrl d) = some d := by
  obtain ⟨h1, h0, -, -⟩ := sextets_facts d
  rw [encodeUrl_eq, ← List.append_nil ((sextets d).map (tbl URL_TABLE)),
    show ([] : Bytes) = List.replicate 0 61 from rfl]
  apply decode_core
  · intro c hc
    obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hc
    exact (decodeByte_tbl' URL_TABLE (Or.inr rfl) i (sextets_lt d i hi)).2
  · decide
  · exact Or.inl rfl
  · simpa using h1
  · exact decodeQuads_sextets URL_TABLE (Or.inr rfl) d
  · intro hz; exact h0 (by simpa using hz)

/-! ## Canonicity: the only accepted spellings -/

theorem u8rt (x : UInt32) : x.toUInt8.toUInt32 = x &&& 0xFF := by bit_blast

theorem mask64 (i : UInt32) (h : i.toNat < 64) : i = i &&& 63 :=
  (and_low i 63 6 rfl h).symm

theorem decodeQuads_canonical : ∀ (n : Nat) (cs d : Bytes), cs.length ≤ n →
    decodeQuads cs = some d → cs.map std = (sextets d).map (tbl TABLE) := by
  intro n
  induction n with
  | zero =>
    intro cs d hl h
    cases cs with
    | nil => simp only [decodeQuads, Option.some.injEq] at h; subst h; rfl
    | cons => simp at hl
  | succ n ihn =>
  intro cs d hl h
  match cs, hl, h with
  | c0 :: c1 :: c2 :: c3 :: rest, hl, h =>
    have ih : ∀ r, decodeQuads rest = some r → rest.map std = (sextets r).map (tbl TABLE) :=
      fun r hr => ihn rest r (by simp at hl; omega) hr
    simp only [decodeQuads] at h
    split at h
    · next b0 b1 b2 b3 r e0 e1 e2 e3 er =>
      simp only [Option.some.injEq] at h; subst h
      obtain ⟨l0, t0⟩ := decodeByte_inv c0 b0 e0
      obtain ⟨l1, t1⟩ := decodeByte_inv c1 b1 e1
      obtain ⟨l2, t2⟩ := decodeByte_inv c2 b2 e2
      obtain ⟨l3, t3⟩ := decodeByte_inv c3 b3 e3
      simp only [List.map_cons, sextets, ih r er, ← t0, ← t1, ← t2, ← t3, List.cons.injEq,
        and_true]
      rw [mask64 b0 l0, mask64 b1 l1, mask64 b2 l2, mask64 b3 l3]
      refine ⟨?_, ?_, ?_, ?_⟩ <;> congr 1
      · simp only [q0, o0, u8rt]; bit_blast
      · simp only [q1, o0, o1, u8rt]; bit_blast
      · simp only [q2, o1, o2, u8rt]; bit_blast
      · simp only [q3, o2, u8rt]; bit_blast
    · cases h
  | [c0, c1, c2], _, h =>
    simp only [decodeQuads] at h
    split at h
    · next b0 b1 b2 e0 e1 e2 =>
      split at h
      · cases h
      · next hz =>
        simp only [Option.some.injEq, ne_eq, Decidable.not_not] at h hz; subst h
        obtain ⟨l0, t0⟩ := decodeByte_inv c0 b0 e0
        obtain ⟨l1, t1⟩ := decodeByte_inv c1 b1 e1
        obtain ⟨l2, t2⟩ := decodeByte_inv c2 b2 e2
        simp only [List.map_cons, List.map_nil, sextets, ← t0, ← t1, ← t2, List.cons.injEq,
          and_true]
        have e2' : b2 = b2 &&& 0x3C := by
          have k : b2 &&& 63 = (b2 &&& 0x3C) ||| (b2 &&& 3) := by bit_blast
          rw [hz, show (b2 &&& 0x3C) ||| (0 : UInt32) = b2 &&& 0x3C by bit_blast,
            ← mask64 b2 l2] at k
          exact k
        rw [mask64 b0 l0, mask64 b1 l1, e2']
        refine ⟨?_, ?_, ?_⟩ <;> congr 1
        · simp only [q0, o0, u8rt]; bit_blast
        · simp only [q1, o0, o1, u8rt]; bit_blast
        · simp only [o1, u8rt]; bit_blast
    · cases h
  | [c0, c1], _, h =>
    simp only [decodeQuads] at h
    split at h
    · next b0 b1 e0 e1 =>
      split at h
      · cases h
      · next hz =>
        simp only [Option.some.injEq, ne_eq, Decidable.not_not] at h hz; subst h
        obtain ⟨l0, t0⟩ := decodeByte_inv c0 b0 e0
        obtain ⟨l1, t1⟩ := decodeByte_inv c1 b1 e1
        simp only [List.map_cons, List.map_nil, sextets, ← t0, ← t1, List.cons.injEq, and_true]
        have e1' : b1 = b1 &&& 0x30 := by
          have k : b1 &&& 63 = (b1 &&& 0x30) ||| (b1 &&& 0xF) := by bit_blast
          rw [hz, show (b1 &&& 0x30) ||| (0 : UInt32) = b1 &&& 0x30 by bit_blast,
            ← mask64 b1 l1] at k
          exact k
        rw [mask64 b0 l0, e1']
        refine ⟨?_, ?_⟩ <;> congr 1
        · simp only [q0, o0, u8rt]; bit_blast
        · simp only [o0, u8rt]; bit_blast
    · cases h
  | [c], _, h => simp [decodeQuads] at h
  | [], _, h => simp only [decodeQuads, Option.some.injEq] at h; subst h; rfl

/-- Accepted inputs: the unpadded part is the standard encoding of the
result up to `-`/`+` and `_`/`/`. -/
theorem decode_canonical (s d : Bytes) (h : decode s = some d) :
    (stripPad s).map std = (sextets d).map (tbl TABLE) := by
  unfold decode at h
  simp only at h
  split at h
  · cases h
  · split at h
    · next hz =>
      simp only [Option.some.injEq] at h; subst h
      unfold stripPad; rw [hz]; simp [sextets]
    · split at h
      · cases h
      · exact decodeQuads_canonical _ _ _ (Nat.le_refl _) h

/-- Accepted padding: none, or one/two `=` completing a multiple of 4. -/
theorem decode_padding (s d : Bytes) (h : decode s = some d) :
    padCount s ≤ 2 ∧ (padCount s = 0 ∨ s.length % 4 = 0) := by
  unfold decode at h
  simp only at h
  split at h
  · cases h
  · next hp =>
    have : padCount s ≤ s.length := by
      unfold padCount
      have : ∀ l : Bytes, trailingEq l ≤ l.length := by
        intro l; induction l with
        | nil => simp [trailingEq]
        | cons c t ih => simp only [trailingEq, List.length_cons]; split <;> omega
      have := this s.reverse; simpa using this
    omega

end Flare.L1.Base64
