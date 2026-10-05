import Flare.Core
import Flare.L1_Encoding.Utf8

/-!
# WebSocket frame codec (RFC 6455 §5)

Models `WsFrame.encode_with_key`, `WsFrame.decode_one` and the SIMD masking
helper `_append_masked` from `flare/ws/frame.mojo`.

* `maskFrom_involutive`: masking twice with the same key is the identity
  (RFC 6455 §5.3).
* `appendMasked_eq`: the 32-byte SIMD loop plus scalar tail computes the
  bytewise `p[i] ^ key[i mod 4]`.
* `decode_encode`: decoding an encoded frame returns it, with the wire
  `masked` bit, and consumes exactly the encoding, followed by any trailing
  bytes. This holds for every payload length below `2^32` that is within
  `max_payload`, so it covers the 125/126, 65535/65536 boundaries of the
  7/16/64-bit length forms. `decode_encode_125` and its siblings are the
  boundary instances.
* `decode_ok_control` and `decode_ok_len`: what `decode_one` guarantees
  about every frame it returns.

The Mojo decoder indexes `data[pos + i]`. Here the same reads are list
patterns. Its `(Int(a) << 8) | Int(b)` over bytes is `a * 256 + b`, because
the shifted bytes occupy disjoint bit ranges, and its OR of four bytes is
zero iff each is zero.
-/
namespace Flare.L3.Ws
open Flare

/-! ## Masking -/

/-- The 4-byte masking key. -/
structure Key where
  k0 : UInt8
  k1 : UInt8
  k2 : UInt8
  k3 : UInt8
  deriving DecidableEq, Repr

/-- `key[i & 3]`.
mirrors flare/ws/frame.mojo:495,633,646 @59bda50 -/
def Key.at (k : Key) (i : Nat) : UInt8 :=
  match i % 4 with
  | 0 => k.k0
  | 1 => k.k1
  | 2 => k.k2
  | _ => k.k3

def Key.bytes (k : Key) : Bytes := [k.k0, k.k1, k.k2, k.k3]

def Key.isZero (k : Key) : Bool := k.k0 == 0 && k.k1 == 0 && k.k2 == 0 && k.k3 == 0

/-- RFC 6455 §5.3: octet `i` is XOR'd with key octet `i mod 4`. `maskFrom k i p`
masks `p` as if it started at payload offset `i`.
mirrors flare/ws/frame.mojo:483-488 (unmask) and :644-647 (scalar tail) @59bda50 -/
def maskFrom (k : Key) : Nat → Bytes → Bytes
  | _, [] => []
  | i, b :: bs => (b ^^^ k.at i) :: maskFrom k (i + 1) bs

theorem xor_xor_cancel (a b : UInt8) : (a ^^^ b) ^^^ b = a := by
  rw [UInt8.xor_assoc, UInt8.xor_self, UInt8.xor_zero]

/-- **Mask involution.** -/
theorem maskFrom_involutive (k : Key) : ∀ (i : Nat) (p : Bytes), maskFrom k i (maskFrom k i p) = p
  | _, [] => rfl
  | i, b :: bs => by simp [maskFrom, xor_xor_cancel, maskFrom_involutive k (i + 1) bs]

theorem maskFrom_length (k : Key) : ∀ (i : Nat) (p : Bytes), (maskFrom k i p).length = p.length
  | _, [] => rfl
  | i, _ :: bs => by simp [maskFrom, maskFrom_length k (i + 1) bs]

theorem maskFrom_append (k : Key) : ∀ (i : Nat) (a b : Bytes),
    maskFrom k i (a ++ b) = maskFrom k i a ++ maskFrom k (i + a.length) b
  | _, [], _ => rfl
  | i, x :: xs, b => by
    have e : i + 1 + xs.length = i + (xs.length + 1) := by omega
    simp only [List.cons_append, maskFrom, maskFrom_append k (i + 1) xs b, List.length_cons, e]

theorem Key.at_congr (k : Key) {i j : Nat} (h : i % 4 = j % 4) : k.at i = k.at j := by
  simp only [Key.at, h]

theorem maskFrom_congr (k : Key) : ∀ {i j : Nat} (p : Bytes), i % 4 = j % 4 → maskFrom k i p = maskFrom k j p
  | _, _, [], _ => rfl
  | i, j, b :: bs, h => by
    simp only [maskFrom, k.at_congr h, maskFrom_congr k (i := i + 1) (j := j + 1) bs (by omega)]

theorem maskFrom_zero_key : ∀ (i : Nat) (p : Bytes), maskFrom ⟨0, 0, 0, 0⟩ i p = p
  | _, [] => rfl
  | i, b :: bs => by
    have : (⟨0, 0, 0, 0⟩ : Key).at i = 0 := by unfold Key.at; split <;> rfl
    simp [maskFrom, this, UInt8.xor_zero, maskFrom_zero_key (i + 1) bs]

theorem Key.eq_zero_of_isZero {k : Key} (h : k.isZero = true) : k = ⟨0, 0, 0, 0⟩ := by
  cases k; simp [Key.isZero] at h; simp [h]

/-- `_append_masked`: 32-byte blocks XOR'd with the tiled key
`tiled[j] = key[j & 3]`, then a scalar tail using the absolute index.
mirrors flare/ws/frame.mojo:612-647 @59bda50 -/
def appendMasked (k : Key) (i : Nat) (rest : Bytes) : Bytes :=
  if 32 ≤ rest.length then maskFrom k 0 (rest.take 32) ++ appendMasked k (i + 32) (rest.drop 32)
  else maskFrom k i rest
termination_by rest.length

/-- **SIMD masking is bytewise masking.** -/
theorem appendMasked_eq (k : Key) (i : Nat) (rest : Bytes) (hi : i % 4 = 0) :
    appendMasked k i rest = maskFrom k i rest := by
  rw [appendMasked]
  split
  · rename_i h
    rw [appendMasked_eq k (i + 32) (rest.drop 32) (by omega)]
    conv => rhs; rw [← List.take_append_drop 32 rest]
    rw [maskFrom_append, maskFrom_congr k _ (show 0 % 4 = i % 4 by omega), List.length_take,
      Nat.min_eq_left h]
  · rfl
termination_by rest.length
decreasing_by simp only [List.length_drop]; omega

/-! ## Frames -/

/-- A decoded frame: header fields and the unmasked payload.
mirrors flare/ws/frame.mojo:140-170 @59bda50 -/
structure Frame where
  fin : Bool
  rsv1 : Bool
  opcode : UInt8
  masked : Bool
  payload : Bytes
  deriving DecidableEq, Repr

/-- mirrors flare/ws/frame.mojo:512-520 @59bda50 -/
def isControl (op : UInt8) : Bool := op &&& 8 != 0

/-- RFC 6455 §5.2: opcodes with a defined meaning. -/
def knownOpcode (op : UInt8) : Bool := op == 0 || op == 1 || op == 2 || op == 8 || op == 9 || op == 10

/-- mirrors flare/ws/frame.mojo:334-337 @59bda50 -/
def be16 (n : Nat) : Bytes := [(n / 256 % 256).toUInt8, (n % 256).toUInt8]

/-- mirrors flare/ws/frame.mojo:323-333 @59bda50 -/
def be64 (n : Nat) : Bytes :=
  [(n / 2 ^ 56 % 256).toUInt8, (n / 2 ^ 48 % 256).toUInt8, (n / 2 ^ 40 % 256).toUInt8,
   (n / 2 ^ 32 % 256).toUInt8, (n / 2 ^ 24 % 256).toUInt8, (n / 2 ^ 16 % 256).toUInt8,
   (n / 2 ^ 8 % 256).toUInt8, (n % 256).toUInt8]

/-- mirrors flare/ws/frame.mojo:292-296 @59bda50 -/
def byte0 (f : Frame) : UInt8 :=
  (f.opcode ||| (if f.fin then 0x80 else 0)) ||| (if f.rsv1 then 0x40 else 0)

/-- mirrors flare/ws/frame.mojo:303-313 @59bda50 -/
def lenCode (plen : Nat) : UInt8 :=
  if plen < 126 then plen.toUInt8 else if plen < 65536 then 126 else 127

/-- mirrors flare/ws/frame.mojo:322-337 @59bda50 -/
def extLen (plen : Nat) : Bytes :=
  if 65536 ≤ plen then be64 plen else if 126 ≤ plen then be16 plen else []

/-- `encode_with_key`. With `mask` and an all-zero key the payload is copied.
mirrors flare/ws/frame.mojo:274-356 @59bda50 -/
def encode (f : Frame) (mask : Bool) (k : Key) : Bytes :=
  let plen := f.payload.length
  [byte0 f, (if mask then 0x80 else 0) ||| lenCode plen] ++ extLen plen ++
    (if mask then k.bytes else []) ++
    (if !mask || k.isZero then f.payload else appendMasked k 0 f.payload)

/-- `encode`: refuses RSV1 and an oversized control payload, then
`encode_with_key`.
mirrors flare/ws/frame.mojo:234-272 @59bda50 -/
def encodeChecked (f : Frame) (mask : Bool) (k : Key) : Option Bytes :=
  if f.rsv1 then none
  else if isControl f.opcode ∧ f.payload.length > 125 then none
  else some (encode f mask k)

/-! ## Decoding -/

inductive LRes where
  | short
  | bad
  | ok (plen : Nat) (rest : Bytes) (hdr : Nat)

/-- Extended payload length.
mirrors flare/ws/frame.mojo:410-447 @59bda50 -/
def parseLen (plen7 : Nat) (r : Bytes) : LRes :=
  if plen7 < 126 then .ok plen7 r 2
  else if plen7 = 126 then
    match r with
    | a :: b :: r' => .ok (a.toNat * 256 + b.toNat) r' 4
    | _ => .short
  else
    match r with
    | a0 :: a1 :: a2 :: a3 :: a4 :: a5 :: a6 :: a7 :: r' =>
      if a0 &&& 0x80 != 0 then .bad
      else if !(a0 == 0 && a1 == 0 && a2 == 0 && a3 == 0) then .bad
      else .ok (a4.toNat * 2 ^ 24 + a5.toNat * 2 ^ 16 + a6.toNat * 2 ^ 8 + a7.toNat) r' 10
    | _ => .short

/-- `decode_one`'s outcome: `needMore` is the "need"/"truncated" `Error` the
readers retry on; `error` is a `WsProtocolError`. -/
inductive DRes where
  | needMore
  | error
  | ok (f : Frame) (consumed : Nat)
  deriving DecidableEq, Repr

/-- The tail of `decode_one` once the header and key are read: control-frame
checks, then the payload.
mirrors flare/ws/frame.mojo:465-508 @59bda50 -/
def finish (fin rsv1 : Bool) (op : UInt8) (masked : Bool) (plen hdr : Nat) (key : Key) (r : Bytes) : DRes :=
  if isControl op && (!fin || plen > 125) then .error
  else if r.length < plen then .needMore
  else
    let raw := r.take plen
    .ok ⟨fin, rsv1, op, masked, if masked then maskFrom key 0 raw else raw⟩ (hdr + plen)

theorem finish_ok {fin rsv1 : Bool} {op : UInt8} {masked : Bool} {plen hdr : Nat} {key : Key} {r : Bytes}
    {f : Frame} {n : Nat} (h : finish fin rsv1 op masked plen hdr key r = .ok f n) :
    f.fin = fin ∧ f.rsv1 = rsv1 ∧ f.opcode = op ∧ f.payload.length = plen ∧
      (isControl op = true → fin = true ∧ plen ≤ 125) ∧ n = hdr + plen := by
  unfold finish at h
  split at h; · cases h
  rename_i hctl
  split at h; · cases h
  rename_i hlen
  cases h
  refine ⟨rfl, rfl, rfl, ?_, ?_, rfl⟩
  · split <;> simp [maskFrom_length] <;> omega
  · intro hic
    simp only [hic, Bool.true_and, Bool.or_eq_true, Bool.not_eq_true', decide_eq_true_eq, not_or] at hctl
    exact ⟨by simpa using hctl.1, by omega⟩

/-- `WsFrame.decode_one` before the WS-01 fix: the opcode is not range-checked.
`decodeKnown` (in `Ws/Recv.lean`) is the shipped decoder.
mirrors flare/ws/frame.mojo:361-508 @59bda50 -/
def decode (allowRsv1 : Bool) (maxP : Nat) : Bytes → DRes
  | b0 :: b1 :: r =>
    if b0 &&& 0x20 != 0 || b0 &&& 0x10 != 0 then .error
    else if b0 &&& 0x40 != 0 && !allowRsv1 then .error
    else
      let fin := b0 &&& 0x80 != 0
      let masked := b1 &&& 0x80 != 0
      let op := b0 &&& 0x0F
      match parseLen (b1 &&& 0x7F).toNat r with
      | .short => .needMore
      | .bad => .error
      | .ok plen r hl =>
        if plen > maxP then .error
        else
          if masked then
            match r with
            | k0 :: k1 :: k2 :: k3 :: r' => finish fin (b0 &&& 0x40 != 0) op true plen (hl + 4) ⟨k0, k1, k2, k3⟩ r'
            | _ => .needMore
          else finish fin (b0 &&& 0x40 != 0) op false plen hl ⟨0, 0, 0, 0⟩ r
  | _ => .needMore

/-! ## Header-bit facts (finite, by `decide`) -/

theorem byte0_bits_all : ∀ (o : Fin 16) (a b : Bool),
    let b0 := (UInt8.ofNat o.val ||| (if a then 0x80 else 0)) ||| (if b then 0x40 else 0)
    (b0 &&& 0x20 != 0) = false ∧ (b0 &&& 0x10 != 0) = false ∧ (b0 &&& 0x80 != 0) = a ∧
      (b0 &&& 0x40 != 0) = b ∧ b0 &&& 0x0F = UInt8.ofNat o.val := by
  decide

theorem byte1_bits_all : ∀ (c : Fin 128) (m : Bool),
    let b1 := (if m then 0x80 else 0) ||| UInt8.ofNat c.val
    (b1 &&& 0x80 != 0) = m ∧ (b1 &&& 0x7F).toNat = c.val := by
  decide

theorem byte0_bits (f : Frame) (ho : f.opcode.toNat < 16) :
    (byte0 f &&& 0x20 != 0) = false ∧ (byte0 f &&& 0x10 != 0) = false ∧
      (byte0 f &&& 0x80 != 0) = f.fin ∧ (byte0 f &&& 0x40 != 0) = f.rsv1 ∧
      byte0 f &&& 0x0F = f.opcode := by
  have h := byte0_bits_all ⟨f.opcode.toNat, ho⟩ f.fin f.rsv1
  have e : UInt8.ofNat f.opcode.toNat = f.opcode := UInt8.ofNat_toNat
  simp only [e] at h
  exact h

theorem byte1_bits (m : Bool) (c : UInt8) (hc : c.toNat < 128) :
    (((if m then 0x80 else 0) ||| c) &&& 0x80 != 0) = m ∧
      (((if m then 0x80 else 0) ||| c) &&& 0x7F).toNat = c.toNat := by
  have h := byte1_bits_all ⟨c.toNat, hc⟩ m
  have e : UInt8.ofNat c.toNat = c := UInt8.ofNat_toNat
  simp only [e] at h
  exact h

theorem toUInt8_toNat {n : Nat} (h : n < 256) : n.toUInt8.toNat = n := by
  simp [Nat.toUInt8, UInt8.toNat_ofNat, Nat.mod_eq_of_lt h]

theorem lenCode_toNat (plen : Nat) :
    (lenCode plen).toNat = if plen < 126 then plen else if plen < 65536 then 126 else 127 := by
  unfold lenCode
  split
  · exact toUInt8_toNat (by omega)
  · split <;> rfl

theorem lenCode_lt (plen : Nat) : (lenCode plen).toNat < 128 := by
  rw [lenCode_toNat]; split <;> (try split) <;> omega

/-- The length field round-trips for every length below `2^32`. -/
theorem parseLen_extLen (plen : Nat) (h : plen < 2 ^ 32) (rest : Bytes) :
    parseLen (lenCode plen).toNat (extLen plen ++ rest) = .ok plen rest (2 + (extLen plen).length) := by
  rw [lenCode_toNat]
  by_cases h1 : plen < 126
  · simp [h1, parseLen, extLen, show ¬ 126 ≤ plen by omega, show ¬ 65536 ≤ plen by omega]
  by_cases h2 : plen < 65536
  · simp only [h1, h2, if_false, if_true, parseLen, show ¬ (126 < 126) by decide, extLen,
      show ¬ 65536 ≤ plen by omega, show 126 ≤ plen by omega, be16, List.cons_append, List.nil_append,
      List.length_cons, List.length_nil]
    rw [toUInt8_toNat (by omega), toUInt8_toNat (by omega)]
    congr 1; omega
  · have hz : ∀ s, 32 ≤ s → plen / 2 ^ s % 256 = 0 := by
      intro s hs
      have : plen / 2 ^ s = 0 := Nat.div_eq_of_lt (Nat.lt_of_lt_of_le h (Nat.pow_le_pow_right (by decide) hs))
      rw [this]
    simp only [h1, h2, if_false, parseLen, show ¬ (127 < 126) by decide, show ¬ (127 = 126) by decide,
      extLen, show 65536 ≤ plen by omega, if_true, be64, List.cons_append, List.nil_append,
      List.length_cons, List.length_nil, hz 56 (by decide), hz 48 (by decide), hz 40 (by decide),
      hz 32 (by decide)]
    rw [toUInt8_toNat (by omega), toUInt8_toNat (by omega), toUInt8_toNat (by omega),
      toUInt8_toNat (by omega)]
    simp only [show (Nat.toUInt8 0 &&& 0x80 != 0) = false by decide,
      show (Nat.toUInt8 0 == 0) = true by decide, Bool.and_self, Bool.not_true, Bool.false_eq_true,
      if_false]
    congr 1; omega

theorem extLen_length (plen : Nat) : (extLen plen).length ≤ 8 := by
  unfold extLen; split
  · simp [be64]
  · split <;> simp [be16]

/-- **Round trip.** Every frame `encode_with_key` produces from a frame with a
valid opcode nibble, an allowed RSV1, a legal control payload, and a
payload `< 2^32` within `max_payload` decodes back to that frame (with the
wire mask bit), consuming exactly the encoding. Trailing bytes are untouched. -/
theorem decode_encode (allowRsv1 : Bool) (maxP : Nat) (f : Frame) (mask : Bool) (k : Key) (rest : Bytes)
    (ho : f.opcode.toNat < 16) (hr : f.rsv1 = true → allowRsv1 = true)
    (hc : isControl f.opcode = true → f.fin = true ∧ f.payload.length ≤ 125)
    (h32 : f.payload.length < 2 ^ 32) (hmax : f.payload.length ≤ maxP) :
    decode allowRsv1 maxP (encode f mask k ++ rest) =
      .ok { f with masked := mask } (encode f mask k).length := by
  obtain ⟨b20, b10, bfin, brsv, bop⟩ := byte0_bits f ho
  obtain ⟨bm, bl⟩ := byte1_bits mask (lenCode f.payload.length) (lenCode_lt _)
  -- The payload as it appears on the wire.
  have hwire : (if !mask || k.isZero then f.payload else appendMasked k 0 f.payload) =
      if mask then maskFrom k 0 f.payload else f.payload := by
    cases mask with
    | false => rfl
    | true =>
      cases hz : k.isZero
      · simp only [Bool.not_true, Bool.or_false, Bool.false_eq_true, if_false, if_true]
        exact appendMasked_eq k 0 _ rfl
      · simp only [Bool.not_true, hz, Bool.or_true, if_true]
        rw [Key.eq_zero_of_isZero hz, maskFrom_zero_key]
  unfold encode
  simp only [hwire, List.cons_append, List.nil_append, List.append_assoc]
  unfold decode
  simp only [b20, b10, Bool.or_false, Bool.false_eq_true, if_false, brsv, bm, bop, bfin, bl]
  have hnr : (f.rsv1 && !allowRsv1) = false := by
    cases h1 : f.rsv1
    · rfl
    · simp [hr h1]
  simp only [hnr, Bool.false_eq_true, if_false]
  rw [parseLen_extLen _ h32]
  simp only [show ¬ (f.payload.length > maxP) by omega, if_false]
  have hcf : (isControl f.opcode && (!f.fin || decide (f.payload.length > 125))) = false := by
    cases hic : isControl f.opcode
    · rfl
    · obtain ⟨h1, h2⟩ := hc hic; simp [h1]; omega
  cases mask with
  | false =>
    simp only [Bool.false_eq_true, if_false, List.nil_append]
    unfold finish
    rw [hcf, if_neg (by simp), if_neg (by simp)]
    simp only [List.take_left', List.length_cons, List.length_append, List.length_nil]
    congr 1; omega
  | true =>
    simp only [if_true, Key.bytes, List.cons_append, List.nil_append]
    unfold finish
    rw [hcf, if_neg (by simp), if_neg (by simp [maskFrom_length])]
    simp only [if_true]
    rw [List.take_left' (maskFrom_length k 0 f.payload), maskFrom_involutive]
    simp only [List.length_cons, List.length_append, List.length_nil, maskFrom_length]
    congr 1; omega

/-! ## Boundary instances -/

section Boundaries
variable (allowRsv1 : Bool) (maxP : Nat) (mask : Bool) (k : Key) (rest : Bytes) (op : UInt8) (p : Bytes)

theorem decode_encode_len (n : Nat) (hn : n < 2 ^ 32) (hp : p.length = n) (hmax : n ≤ maxP)
    (ho : op.toNat < 16) (hc : isControl op = false) :
    decode allowRsv1 maxP (encode ⟨true, false, op, false, p⟩ mask k ++ rest) =
      .ok ⟨true, false, op, mask, p⟩ (encode ⟨true, false, op, false, p⟩ mask k).length :=
  decode_encode allowRsv1 maxP ⟨true, false, op, false, p⟩ mask k rest ho (by simp)
    (by simp [hc]) (by simp [hp, hn]) (by simp [hp, hmax])

/-- 125: largest 7-bit length. -/
theorem lenCode_125 : lenCode 125 = 125 := by decide
/-- 126: smallest 16-bit length. -/
theorem lenCode_126 : lenCode 126 = 126 ∧ extLen 126 = [0, 126] := by decide
/-- 65535: largest 16-bit length. -/
theorem lenCode_65535 : lenCode 65535 = 126 ∧ extLen 65535 = [255, 255] := by decide
/-- 65536: smallest 64-bit length. -/
theorem lenCode_65536 : lenCode 65536 = 127 ∧ extLen 65536 = [0, 0, 0, 0, 0, 1, 0, 0] := by decide

end Boundaries

/-! ## What `decode_one` guarantees -/

theorem decode_ok_shape {allowRsv1 : Bool} {maxP : Nat} {d : Bytes} {f : Frame} {n : Nat}
    (h : decode allowRsv1 maxP d = .ok f n) :
    (isControl f.opcode = true → f.fin = true ∧ f.payload.length ≤ 125) ∧
      f.payload.length ≤ maxP ∧ (f.rsv1 = true → allowRsv1 = true) := by
  unfold decode at h
  split at h
  · rename_i b0 b1 r
    split at h; · cases h
    split at h; · cases h
    rename_i _ hrsv
    have hr : (b0 &&& 0x40 != 0) = true → allowRsv1 = true := by
      intro h1; cases allowRsv1 <;> simp_all
    dsimp only at h
    split at h
    · cases h
    · cases h
    · rename_i plen r' hl _
      split at h; · cases h
      rename_i hmx
      have key : ∀ {fin rsv1 op masked hdr key r}, finish fin rsv1 op masked plen hdr key r = .ok f n →
          (rsv1 = true → allowRsv1 = true) → rsv1 = (b0 &&& 0x40 != 0) →
          (isControl f.opcode = true → f.fin = true ∧ f.payload.length ≤ 125) ∧
            f.payload.length ≤ maxP ∧ (f.rsv1 = true → allowRsv1 = true) := by
        intro fin rsv1 op masked hdr key r hf _ hrs
        obtain ⟨e1, e2, e3, e4, e5, -⟩ := finish_ok hf
        refine ⟨fun hc => ?_, by omega, fun h1 => hr (by rw [← hrs, ← e2]; exact h1)⟩
        rw [e3] at hc; obtain ⟨a, b⟩ := e5 hc; exact ⟨by rw [e1]; exact a, by omega⟩
      split at h
      · split at h
        · exact key h (fun h1 => hr h1) rfl
        · cases h
      · exact key h (fun h1 => hr h1) rfl
  · cases h

end Flare.L3.Ws
