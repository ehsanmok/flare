import Flare.Core.Bytes
import Flare.L3_Protocol.Qpack.Ric
import Flare.L1_Encoding.Huffman

/-!
# QPACK field-section and encoder-stream decoding (RFC 9204 §4.3, §4.5)

Four small models of `flare/qpack/dynamic.mojo` and `flare/qpack/codec.mojo`:

1. `decodeInt`: the HPACK/QPACK prefix integer reader the QPACK code calls
   (`flare/http2/hpack.mojo:101-132`), modelled locally with its 2^31 cap and
   5-continuation-byte limit. Theorem `decodeInt_offset_le`: on success the
   returned offset is at most `len buf`, and only bytes below it are read.
2. Field-line reference resolution (`decode_field_section_dynamic`): Base
   from Required Insert Count + Sign/Delta Base, pre-base / post-base
   absolute indices, and the table lookup. `specResolve` is RFC 9204
   §4.5.1.2 + §4.5.2-§4.5.5 over `Nat`. `implOldResolve` is flare (UInt64 wrap).
   `implResolve` is the shipped (fixed) resolver with the three checks the
   old one lacked, proved equal to the spec (`implResolve_eq_spec`);
   `implOldResolve` is the pre-fix code, which accepts everything the spec
   accepts (`spec_imp_implOld`) but also more (Bugs/QPACK_01).
3. The prefix read at dynamic.mojo:489 (`buf[ric_enc.offset]`), see
   Bugs/QPACK_02.
4. String literals (`_decode_string_literal`, both branches): the H flag,
   the prefix-integer length, then the octets, Huffman-decoded by
   `huffman_decode_simd` when H is set. `implLiteral_eq_spec` shows this is
   RFC 9204 §4.1.2 with RFC 7541 §5.2 Huffman decoding, through the L1
   decoder (`Flare.L1.Huffman.okOnly_decodeSimdImpl`); either way the bytes
   reach `ascii_unchecked_string` unvalidated (Bugs/QPACK_03).
5. Encoder-stream dynamic name reference / Duplicate (dynamic.mojo:319,337)
   inside `apply_encoder_instructions_partial` (Bugs/QPACK_04).
-/
namespace Flare.L3.Qpack.FieldSection

open Flare

/-! ## 1. Prefix integers -/

/-- Continuation loop of `decode_integer`; `k` is the remaining number of
allowed continuation bytes (`m` goes 0,7,...,28; `m ≥ 35` raises).
mirrors flare/http2/hpack.mojo:118-132 @59bda50 -/
def decodeCont (buf : Bytes) : Nat → Nat → Nat → Nat → Option (Nat × Nat)
  | 0, _, _, _ => none
  | k + 1, off, value, m =>
    if off ≥ buf.length then none
    else
      let b := (Bytes.getD buf off).toNat
      let value := value + (b % 128) * 2 ^ m
      if value > 2 ^ 31 then none
      else if b / 128 = 0 then some (value, off + 1)
      else decodeCont buf k (off + 1) value (m + 7)

/-- mirrors flare/http2/hpack.mojo:101-132 @59bda50 -/
def decodeInt (buf : Bytes) (offset prefixBits : Nat) : Option (Nat × Nat) :=
  if offset ≥ buf.length then none
  else
    let maxPrefix := 2 ^ prefixBits - 1
    let b0 := (Bytes.getD buf offset).toNat % 2 ^ prefixBits
    if b0 < maxPrefix then some (b0, offset + 1)
    else decodeCont buf 5 (offset + 1) b0 0

theorem decodeCont_offset_le (buf : Bytes) :
    ∀ k off value m v o, decodeCont buf k off value m = some (v, o) →
      off < o ∧ o ≤ buf.length ∧ v ≤ 2 ^ 31
  | 0, _, _, _, _, _, h => by simp [decodeCont] at h
  | k + 1, off, value, m, v, o, h => by
    unfold decodeCont at h
    by_cases h1 : off ≥ buf.length
    · simp [h1] at h
    · simp only [h1, if_false] at h
      by_cases h2 : value + (Bytes.getD buf off).toNat % 128 * 2 ^ m > 2 ^ 31
      · simp [h2] at h
      · simp only [h2, if_false] at h
        split at h
        · simp at h; omega
        · have := decodeCont_offset_le buf k _ _ _ v o h; omega

/-- A successful prefix-integer read ends at an offset `≤ len buf` strictly
past the start, and its value is at most `2^31`. -/
theorem decodeInt_offset_le (buf : Bytes) (off p v o : Nat)
    (h : decodeInt buf off p = some (v, o)) :
    off < o ∧ o ≤ buf.length := by
  unfold decodeInt at h
  by_cases h1 : off ≥ buf.length
  · simp [h1] at h
  · simp only [h1, if_false] at h
    split at h
    · simp at h
      omega
    · have := decodeCont_offset_le buf 5 _ _ _ v o h; omega

/-! ## 2. Field-line reference resolution -/

/-- A dynamic reference in a field line: pre-base (`1T..` with T=0, or
`01NT..` with T=0) carries a relative index; post-base (`0001....`,
`0000N...`) carries a post-base index. -/
inductive Ref where
  | pre (ip : UInt64)
  | post (ip : UInt64)
  deriving DecidableEq, Repr

/-- Table geometry the resolver sees: `dropped` and `insertCount`. -/
structure Geo where
  dropped : UInt64
  ic : UInt64
  deriving DecidableEq, Repr

/-- Base, as flare computes it (UInt64 wrap). The fixed decoder guards
`delta < ric` before using the `sign` branch (`implResolve`); the pre-fix
decoder did not (`implOldResolve`).
mirrors flare/qpack/dynamic.mojo:473-543 (fixed, QPACK-01) -/
def implBase (ric delta : UInt64) (sign : Bool) : UInt64 :=
  if sign then ric - delta - 1 else ric + delta

/-- PRE-FIX absolute index a reference resolved to, or `none` when flare
raised (flare/qpack/dynamic.mojo @59bda50: no `delta < ric`, `ip < base` or
`abs < ric` checks). Kept so `Bugs/QPACK_01` stays checkable. -/
def implOldResolve (ric delta : UInt64) (sign : Bool) (g : Geo) (r : Ref) : Option UInt64 :=
  let base := implBase ric delta sign
  if ric > g.ic then none
  else
    let abs := match r with
      | .pre ip => base - 1 - ip
      | .post ip => base + ip
    if abs < g.dropped ∨ abs ≥ g.ic then none else some abs

/-- RFC 9204 §4.5.1.2 (Base; Sign=1 with `ReqInsertCount ≤ DeltaBase` is an
error), §4.5.1.1/§2.2.1 (blocked when `ReqInsertCount > insert count`),
§4.5.2-§4.5.5 (relative and post-base indices) and §4.5.1 ("an absolute
index greater than or equal to the Required Insert Count ... MUST treat this
as a connection error"), plus §3.2.4/§2.2.3 (evicted entries are invalid).
Over `Nat`, independent of flare. -/
def specResolve (ric delta : Nat) (sign : Bool) (dropped ic : Nat)
    (isPost : Bool) (ip : Nat) : Option Nat :=
    if sign ∧ ric ≤ delta then none
    else
      let base := if sign then ric - delta - 1 else ric + delta
      if ric > ic then none
      else if isPost then
        if base + ip < ric ∧ dropped ≤ base + ip then some (base + ip) else none
      else
        if ip < base ∧ base - 1 - ip < ric ∧ dropped ≤ base - 1 - ip
        then some (base - 1 - ip) else none

def Ref.isPost : Ref → Bool
  | .pre _ => false
  | .post _ => true

def Ref.ip : Ref → UInt64
  | .pre ip => ip
  | .post ip => ip

/-- The safety property every dynamic reference must satisfy. -/
def RefSafe (ric : UInt64) (res : Option UInt64) : Prop :=
  ∀ a, res = some a → a < ric

/-- The fix: reject Sign=1 with `delta ≥ ric`, reject a pre-base relative
index `≥ base`, and reject any absolute index `≥ ric`.
mirrors flare/qpack/dynamic.mojo:473-508 (fixed, QPACK-01) -/
def fixedAbs (base : UInt64) : Ref → Option UInt64
  | .pre ip => if ip ≥ base then none else some (base - 1 - ip)
  | .post ip => some (base + ip)

def fixedCheck (ric : UInt64) (g : Geo) : Option UInt64 → Option UInt64
  | none => none
  | some abs => if abs ≥ ric ∨ abs < g.dropped ∨ abs ≥ g.ic then none else some abs

/-- The shipped resolver.
mirrors flare/qpack/dynamic.mojo:473-603 (fixed, QPACK-01) -/
def implResolve (ric delta : UInt64) (sign : Bool) (g : Geo) (r : Ref) : Option UInt64 :=
  if sign ∧ delta ≥ ric then none
  else if ric > g.ic then none
  else fixedCheck ric g (fixedAbs (implBase ric delta sign) r)

/-- Bounds the wire guarantees: `delta`, `ip ≤ 2^31` (decodeInt cap); `ric`
and the insert count are far below `2^62`. -/
def Bounded (ric delta : UInt64) (g : Geo) (r : Ref) : Prop :=
  ric.toNat < 2 ^ 62 ∧ delta.toNat < 2 ^ 62 ∧ g.ic.toNat < 2 ^ 62 ∧
  r.ip.toNat < 2 ^ 62 ∧ g.dropped ≤ g.ic

section toNatLemmas
theorem u_lt (a b : UInt64) : a < b ↔ a.toNat < b.toNat := UInt64.lt_iff_toNat_lt
theorem u_le (a b : UInt64) : a ≤ b ↔ a.toNat ≤ b.toNat := UInt64.le_iff_toNat_le
theorem u_add (a b : UInt64) (h : a.toNat + b.toNat < 2 ^ 64) :
    (a + b).toNat = a.toNat + b.toNat := by rw [UInt64.toNat_add]; omega
theorem u_sub (a b : UInt64) (h : b.toNat ≤ a.toNat) :
    (a - b).toNat = a.toNat - b.toNat :=
  UInt64.toNat_sub_of_le _ _ ((u_le _ _).mpr h)
theorem u_one : (1 : UInt64).toNat = 1 := rfl
end toNatLemmas

theorem implResolve_eq_spec (ric delta : UInt64) (sign : Bool) (g : Geo) (r : Ref)
    (hb : Bounded ric delta g r) :
    (implResolve ric delta sign g r).map UInt64.toNat
      = specResolve ric.toNat delta.toNat sign g.dropped.toNat g.ic.toNat r.isPost r.ip.toNat := by
  obtain ⟨hr, hd, hic, hip, hdi⟩ := hb
  rw [u_le] at hdi
  unfold implResolve specResolve
  -- Sign guard
  by_cases hs : sign = true ∧ delta ≥ ric
  · have : sign = true ∧ ric.toNat ≤ delta.toNat := ⟨hs.1, (u_le _ _).mp hs.2⟩
    simp [hs, this]
  have hs' : ¬ (sign = true ∧ ric.toNat ≤ delta.toNat) := fun h => hs ⟨h.1, (u_le _ _).mpr h.2⟩
  rw [if_neg hs, if_neg hs']
  -- base
  have hbase : (implBase ric delta sign).toNat
      = if sign then ric.toNat - delta.toNat - 1 else ric.toNat + delta.toNat := by
    unfold implBase
    cases sign
    · simp; omega
    · simp at hs' ⊢
      have h1 : (ric - delta).toNat = ric.toNat - delta.toNat := u_sub _ _ (by omega)
      rw [u_sub _ _ (by simp; omega), h1]; simp
  generalize hB : implBase ric delta sign = B at hbase
  generalize hBn : (if sign = true then ric.toNat - delta.toNat - 1 else ric.toNat + delta.toNat) = Bn at hbase
  have hBb : Bn < 2 ^ 63 := by rw [← hBn]; split <;> omega
  by_cases hgt : ric > g.ic
  · have : ric.toNat > g.ic.toNat := (u_lt _ _).mp hgt
    simp [hgt, this]
  have hgt' : ¬ ric.toNat > g.ic.toNat := fun h => hgt ((u_lt _ _).mpr h)
  rw [if_neg hgt, if_neg hgt']
  cases r with
  | pre ip =>
    simp only [Ref.isPost, Ref.ip, fixedAbs] at *
    by_cases hge : ip ≥ B
    · have : ¬ ip.toNat < Bn := by rw [← hbase]; exact Nat.not_lt.mpr ((u_le _ _).mp hge)
      simp [hge, this, fixedCheck]
    · have hlt : ip.toNat < Bn := by rw [← hbase]; exact Nat.lt_of_not_le (fun h => hge ((u_le _ _).mpr h))
      rw [if_neg hge]
      try simp only [fixedCheck, Bool.false_eq_true, if_false]
      have hv : (B - 1 - ip).toNat = Bn - 1 - ip.toNat := by
        have h1 : (B - 1).toNat = Bn - 1 := by
          rw [u_sub B 1 (by rw [hbase, u_one]; omega), hbase, u_one]
        rw [u_sub _ _ (by rw [h1]; omega), h1]
      by_cases hc : B - 1 - ip ≥ ric ∨ B - 1 - ip < g.dropped ∨ B - 1 - ip ≥ g.ic
      · have : ¬ (ip.toNat < Bn ∧ Bn - 1 - ip.toNat < ric.toNat ∧ g.dropped.toNat ≤ Bn - 1 - ip.toNat) := by
          simp only [u_le, u_lt, hv] at hc; omega
        simp [this, hc]
      · have : ip.toNat < Bn ∧ Bn - 1 - ip.toNat < ric.toNat ∧ g.dropped.toNat ≤ Bn - 1 - ip.toNat := by
          simp only [u_le, u_lt, hv] at hc; omega
        simp [this, hc, hv]
  | post ip =>
    simp only [Ref.isPost, Ref.ip, fixedAbs, fixedCheck, if_true] at *
    have hv : (B + ip).toNat = Bn + ip.toNat := by rw [u_add _ _ (by omega), hbase]
    by_cases hc : B + ip ≥ ric ∨ B + ip < g.dropped ∨ B + ip ≥ g.ic
    · have : ¬ (Bn + ip.toNat < ric.toNat ∧ g.dropped.toNat ≤ Bn + ip.toNat) := by
        simp only [u_le, u_lt, hv] at hc; omega
      simp [this, hc]
    · have : Bn + ip.toNat < ric.toNat ∧ g.dropped.toNat ≤ Bn + ip.toNat := by
        simp only [u_le, u_lt, hv] at hc; omega
      simp [this, hc, hv]

/-- The fixed resolver satisfies the safety property. -/
theorem fixedCheck_safe (ric : UInt64) (g : Geo) (o : Option UInt64) (a : UInt64)
    (h : fixedCheck ric g o = some a) : a < ric := by
  cases o with
  | none => simp [fixedCheck] at h
  | some v =>
    simp only [fixedCheck] at h
    by_cases hc : v ≥ ric ∨ v < g.dropped ∨ v ≥ g.ic
    · rw [if_pos hc] at h; cases h
    · rw [if_neg hc] at h; cases h
      exact Nat.lt_of_not_le (fun hh => hc (Or.inl hh))

theorem implResolve_safe (ric delta : UInt64) (sign : Bool) (g : Geo) (r : Ref) :
    RefSafe ric (implResolve ric delta sign g r) := by
  intro a h
  unfold implResolve at h
  by_cases h1 : sign = true ∧ delta ≥ ric
  · rw [if_pos h1] at h; cases h
  · rw [if_neg h1] at h
    by_cases h2 : ric > g.ic
    · rw [if_pos h2] at h; cases h
    · rw [if_neg h2] at h; exact fixedCheck_safe _ _ _ _ h

/-- Completeness: whatever the RFC accepts, flare resolves to the same
entry (flare's bug is accepting too much, not too little). -/
theorem spec_imp_implOld (ric delta : UInt64) (sign : Bool) (g : Geo) (r : Ref)
    (hb : Bounded ric delta g r) (a : Nat)
    (hs : specResolve ric.toNat delta.toNat sign g.dropped.toNat g.ic.toNat r.isPost r.ip.toNat = some a) :
    (implOldResolve ric delta sign g r).map UInt64.toNat = some a := by
  have hf := implResolve_eq_spec ric delta sign g r hb
  rw [hs] at hf
  cases hfx : implResolve ric delta sign g r with
  | none => rw [hfx] at hf; simp at hf
  | some v =>
    rw [hfx] at hf; simp at hf
    unfold implResolve at hfx
    unfold implOldResolve
    by_cases h1 : sign = true ∧ delta ≥ ric
    · rw [if_pos h1] at hfx; cases hfx
    rw [if_neg h1] at hfx
    by_cases h2 : ric > g.ic
    · rw [if_pos h2] at hfx; cases hfx
    rw [if_neg h2] at hfx
    simp only [if_neg h2]
    cases r with
    | pre ip =>
      simp only [fixedAbs] at hfx ⊢
      by_cases h3 : ip ≥ implBase ric delta sign
      · rw [if_pos h3] at hfx; cases hfx
      rw [if_neg h3] at hfx
      simp only [fixedCheck] at hfx
      by_cases hc : implBase ric delta sign - 1 - ip ≥ ric ∨ implBase ric delta sign - 1 - ip < g.dropped ∨ implBase ric delta sign - 1 - ip ≥ g.ic
      · rw [if_pos hc] at hfx; cases hfx
      rw [if_neg hc] at hfx; cases hfx
      rw [if_neg (fun hh => hc (Or.inr hh))]; simp [hf]
    | post ip =>
      simp only [fixedAbs, fixedCheck] at hfx ⊢
      by_cases hc : implBase ric delta sign + ip ≥ ric ∨ implBase ric delta sign + ip < g.dropped ∨ implBase ric delta sign + ip ≥ g.ic
      · rw [if_pos hc] at hfx; cases hfx
      rw [if_neg hc] at hfx; cases hfx
      rw [if_neg (fun hh => hc (Or.inr hh))]; simp [hf]

/-- Encoder/decoder relative-index round trip: flare's encoder writes
`rel = base - 1 - abs` (dynamic.mojo:441,447) and the decoder computes
`base - 1 - rel`; for every referenced `abs < base` this is the identity.
mirrors flare/qpack/dynamic.mojo:441,447,512 @59bda50 -/
theorem rel_roundtrip (base abs : Nat) (h : abs < base) :
    base - 1 - (base - 1 - abs) = abs := by omega

/-! ## 3. The prefix read at dynamic.mojo:489 -/

/-- Index read by `buf[ric_enc.offset]` after a successful Required Insert
Count decode, or `none` if flare raised earlier.
mirrors flare/qpack/dynamic.mojo:482-489 @59bda50 -/
def implSignReadIndex (buf : Bytes) (total maxEntries : UInt64) : Option Nat :=
  if buf.length < 2 then none
  else match decodeInt buf 0 8 with
    | none => none
    | some (v, off) =>
      match Ric.implDecode (UInt64.ofNat v) total maxEntries with
      | none => none
      | some _ => some off

/-- Fix: check the cursor before reading the Sign byte. -/
def implFixedSignReadIndex (buf : Bytes) (total maxEntries : UInt64) : Option Nat :=
  match implSignReadIndex buf total maxEntries with
  | some off => if off ≥ buf.length then none else some off
  | none => none

theorem implFixedSignReadIndex_inBounds (buf : Bytes) (t m : UInt64) (i : Nat)
    (h : implFixedSignReadIndex buf t m = some i) : i < buf.length := by
  unfold implFixedSignReadIndex at h
  split at h
  · split at h
    · simp at h
    · simp at h; omega
  · simp at h

/-- Only the Sign read can go out of bounds: the offset is always `≤ len`. -/
theorem implSignReadIndex_le (buf : Bytes) (t m : UInt64) (i : Nat)
    (h : implSignReadIndex buf t m = some i) : i ≤ buf.length := by
  unfold implSignReadIndex at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · rename_i v off hd
      split at h
      · simp at h
      · simp at h; subst h; exact (decodeInt_offset_le _ _ _ _ _ hd).2

/-! ## 4. String literals -/

/-- Bytes handed to `ascii_unchecked_string`, and the end offset. When the
H bit is set the payload goes through `huffman_decode_simd`, which raises
on any RFC 7541 §5.2 error (`okOnly`).
mirrors flare/qpack/codec.mojo:192-234 @59bda50 -/
def implLiteral (buf : Bytes) (offset prefixBits : Nat) (hmask : UInt8) :
    Option (Bytes × Nat) :=
  if offset ≥ buf.length then none
  else match decodeInt buf offset prefixBits with
    | none => none
    | some (n, o) =>
      if o + n > buf.length then none
      else if Bytes.getD buf offset &&& hmask ≠ 0 then
        (Flare.L1.Huffman.okOnly (Flare.L1.Huffman.decodeSimdImpl ((buf.drop o).take n))).map
          fun b => (b, o + n)
      else some ((buf.drop o).take n, o + n)

/-- RFC 9204 §4.1.2: a string literal is the H flag, a prefix-integer
length, and that many octets, Huffman-coded (RFC 7541 §5.2) when H is set. -/
def specLiteral (buf : Bytes) (offset prefixBits : Nat) (hmask : UInt8) :
    Option (Bytes × Nat) :=
  if offset ≥ buf.length then none
  else match decodeInt buf offset prefixBits with
    | none => none
    | some (n, o) =>
      if o + n > buf.length then none
      else if Bytes.getD buf offset &&& hmask ≠ 0 then
        (Flare.L1.Huffman.decode ((buf.drop o).take n)).map fun b => (b, o + n)
      else some ((buf.drop o).take n, o + n)

/-- flare's literal decoder, Huffman branch included, is the RFC decoder. -/
theorem implLiteral_eq_spec (buf : Bytes) (off p : Nat) (m : UInt8) :
    implLiteral buf off p m = specLiteral buf off p m := by
  simp only [implLiteral, specLiteral, Flare.L1.Huffman.okOnly_decodeSimdImpl]

/-- A Huffman literal whose payload is `Huffman.encode s` yields exactly `s`. -/
theorem implLiteral_huffman (buf : Bytes) (off p : Nat) (m : UInt8) (n o : Nat) (s : Bytes)
    (hoff : off < buf.length) (hd : decodeInt buf off p = some (n, o)) (hn : o + n ≤ buf.length)
    (hh : Bytes.getD buf off &&& m ≠ 0) (hp : (buf.drop o).take n = Flare.L1.Huffman.encode s) :
    implLiteral buf off p m = some (s, o + n) := by
  rw [implLiteral_eq_spec]
  unfold specLiteral
  rw [if_neg (Nat.not_le.mpr hoff)]
  simp only [hd]
  rw [if_neg (Nat.not_lt.mpr hn), if_pos hh, hp, Flare.L1.Huffman.decode_encode]
  rfl

/-- `ascii_unchecked_string`'s contract (http/proto/ascii.mojo:63-70): every
byte `< 0x80`. A Mojo `String` must at least be valid UTF-8. -/
def StringOk (b : Bytes) : Prop := (ByteArray.mk b.toArray).validateUTF8 = true

/-- Fix: validate (or build the String with the validating constructor). -/
def implFixedLiteral (buf : Bytes) (offset prefixBits : Nat) (hmask : UInt8) :
    Option (Bytes × Nat) :=
  match implLiteral buf offset prefixBits hmask with
  | some (b, o) => if (ByteArray.mk b.toArray).validateUTF8 then some (b, o) else none
  | none => none

theorem implFixedLiteral_ok (buf : Bytes) (off p : Nat) (m : UInt8) (b : Bytes) (o : Nat)
    (h : implFixedLiteral buf off p m = some (b, o)) : StringOk b := by
  unfold implFixedLiteral at h
  split at h
  · split at h
    · simp at h; obtain ⟨rfl, rfl⟩ := h; unfold StringOk; assumption
    · simp at h
  · simp at h

/-! ## 5. Encoder-stream dynamic name reference / Duplicate -/

inductive Outcome where
  | applied (abs : Nat)
  | stall        -- `apply_encoder_instructions_partial` stops, returns (n, instr_start)
  | streamError  -- raises QPACK_ENCODER_STREAM_ERROR (connection error)
  deriving DecidableEq, Repr

/-- Outcome of an Insert With (dynamic) Name Reference / Duplicate whose
value literal parsed. `get_abs` raises an *untagged* error, which the
partial replayer treats as truncation.
mirrors flare/qpack/dynamic.mojo:319-320,337-338,150-158,281-297 @59bda50 -/
def implDynRef (dropped ic ip : UInt64) : Outcome :=
  let abs := ic - 1 - ip
  if abs < dropped ∨ abs ≥ ic then .stall else .applied abs.toNat

/-- RFC 9204 §4.3.2/§4.3.4 + §3.2.4/§2.2.3: a relative index that does not
name a live entry is a QPACK_ENCODER_STREAM_ERROR connection error. -/
def specDynRef (dropped ic ip : Nat) : Outcome :=
  if ip < ic - dropped then .applied (ic - 1 - ip) else .streamError

/-- Fix: tag the out-of-range case as QPACK_ENCODER_STREAM_ERROR. -/
def implFixedDynRef (dropped ic ip : UInt64) : Outcome :=
  if ip ≥ ic - dropped then .streamError
  else .applied (ic - 1 - ip).toNat

theorem implFixedDynRef_eq_spec (dropped ic ip : UInt64) (hd : dropped ≤ ic) :
    implFixedDynRef dropped ic ip = specDynRef dropped.toNat ic.toNat ip.toNat := by
  rw [u_le] at hd
  unfold implFixedDynRef specDynRef
  have hs : (ic - dropped).toNat = ic.toNat - dropped.toNat := u_sub _ _ hd
  by_cases h : ip ≥ ic - dropped
  · have : ¬ ip.toNat < ic.toNat - dropped.toNat := by rw [← hs]; exact Nat.not_lt.mpr ((u_le _ _).mp h)
    simp [h, this]
  · have hl : ip.toNat < ic.toNat - dropped.toNat := by
      rw [← hs]; exact Nat.lt_of_not_le (fun hh => h ((u_le _ _).mpr hh))
    simp only [h, hl, if_true, if_false]
    congr 1
    have h1 : (ic - 1).toNat = ic.toNat - 1 := u_sub _ _ (by simp; omega)
    rw [u_sub _ _ (by omega), h1]

/-- On in-range references flare already agrees with the spec; the gap is
exactly the out-of-range case. -/
theorem implDynRef_inRange (dropped ic ip : UInt64) (hd : dropped ≤ ic)
    (h : ip.toNat < ic.toNat - dropped.toNat) :
    implDynRef dropped ic ip = specDynRef dropped.toNat ic.toNat ip.toNat := by
  rw [u_le] at hd
  unfold implDynRef specDynRef
  have h1 : (ic - 1).toNat = ic.toNat - 1 := u_sub _ _ (by simp; omega)
  have hv : (ic - 1 - ip).toNat = ic.toNat - 1 - ip.toNat := by rw [u_sub _ _ (by omega), h1]
  have : ¬ (ic - 1 - ip < dropped ∨ ic - 1 - ip ≥ ic) := by
    simp only [u_lt, u_le, hv]; omega
  simp [this, h, hv]

end Flare.L3.Qpack.FieldSection
