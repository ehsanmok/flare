/-!
# QUIC packet-number reconstruction (RFC 9000 §17.1, Appendix A.3)

`decodePnImpl` transliterates flare's `decode_packet_number`, which was
rewritten from the RFC pseudocode to avoid the `expected_pn - pn_hwin`
underflow in unsigned arithmetic. `rfcDecode` is the RFC pseudocode read
over mathematical integers (where that subtraction can go negative).

Results:
* `decodePnImpl_eq_rfc` : for a 1..4 byte packet number, a truncated value
  that fits the window, and `largest_pn < 2^62`, flare's UInt64 code equals
  the RFC pseudocode exactly.
* `rfcDecode_window` / `decodePnImpl_window` : the window theorem. If the
  true packet number `pn < 2^62` lies in `(expected - hwin, expected + hwin]`
  then decoding its truncation returns `pn`.
-/
namespace Flare.L3.Quic.PacketNumber

/-- mirrors flare/quic/protection.mojo:93-115 @59bda50 -/
def decodePnImpl (tpn : UInt64) (pnLength : Int64) (largest : UInt64) : UInt64 :=
  let pnNbits := pnLength * 8
  let expected := largest + 1
  let win : UInt64 := (1 : UInt64) <<< pnNbits.toUInt64
  let hwin := win >>> 1
  let mask := win - 1
  let cand := (expected &&& ~~~mask) ||| tpn
  let limit := ((1 : UInt64) <<< 62) - win
  if cand + hwin ≤ expected ∧ cand < limit then cand + win
  else if cand > expected + hwin ∧ cand ≥ win then cand - win
  else cand

/-- RFC 9000 Appendix A.3 pseudocode over mathematical integers.
`(expected_pn & ~pn_mask) | truncated_pn` is `expected - expected % win + tpn`
for `tpn < win`. -/
def rfcDecode (tpn len largest : Nat) : Int :=
  let expected : Int := largest + 1
  let win : Int := 2 ^ (8 * len)
  let hwin : Int := win / 2
  let cand : Int := expected - expected % win + tpn
  if cand ≤ expected - hwin ∧ cand < 2 ^ 62 - win then cand + win
  else if cand > expected + hwin ∧ cand ≥ win then cand - win
  else cand

/-- Generic branch lemma: the UInt64 `if` with no-overflow side conditions
computes the integer `if`. -/
theorem branch_toNat (c e w h lim : UInt64) (C E W H : Nat)
    (hc : c.toNat = C) (he : e.toNat = E) (hw : w.toNat = W) (_hh : h.toNat = H)
    (hlim : lim.toNat = 2^62 - W) (hW : W ≤ 2^32) (hH : H = W / 2)
    (hE : E ≤ 2^62) (hC : C < 2^62 + W) :
    ((if c + h ≤ e ∧ c < lim then c + w else if c > e + h ∧ c ≥ w then c - w else c).toNat : Int)
      = (if (C:Int) ≤ E - H ∧ (C:Int) < 2^62 - W then (C:Int) + W
         else if (C:Int) > E + H ∧ (C:Int) ≥ W then (C:Int) - W else C) := by
  have k1 : (c + h).toNat = C + H := by rw [UInt64.toNat_add]; omega
  have k2 : (e + h).toNat = E + H := by rw [UInt64.toNat_add]; omega
  have t1 : (c + h ≤ e ∧ c < lim) ↔ (C + H ≤ E ∧ C < 2^62 - W) := by
    simp only [UInt64.le_iff_toNat_le, UInt64.lt_iff_toNat_lt, k1, he, hc, hlim]
  have t2 : (c > e + h ∧ c ≥ w) ↔ (C > E + H ∧ C ≥ W) := by
    simp only [GT.gt, GE.ge, UInt64.le_iff_toNat_le, UInt64.lt_iff_toNat_lt, k2, hw, hc]
  have r1 : ((C:Int) ≤ E - H ∧ (C:Int) < 2^62 - W) ↔ (C + H ≤ E ∧ C < 2^62 - W) := by omega
  have r2 : ((C:Int) > E + H ∧ (C:Int) ≥ W) ↔ (C > E + H ∧ C ≥ W) := by omega
  simp only [t1, t2, r1, r2]
  by_cases h1 : C + H ≤ E ∧ C < 2^62 - W
  · simp only [h1, and_self, ↓reduceIte]; rw [UInt64.toNat_add]; omega
  · simp only [h1, ↓reduceIte]
    by_cases h2 : C > E + H ∧ C ≥ W
    · simp only [h2, and_self, ↓reduceIte]
      rw [UInt64.toNat_sub_of_le _ _ (by rw [UInt64.le_iff_toNat_le]; omega)]; omega
    · simp only [h2, ↓reduceIte]; omega

/-- `(e & ~(w - 1)) | t = e - e % w + t` for `w = 2^k` and `t < w`. -/
theorem cand_eq (k : Nat) (hk : k ≤ 32) (wU : UInt64) (hw : wU.toNat = 2 ^ k)
    (e t : UInt64) (ht : t < wU) : (e &&& ~~~(wU - 1)) ||| t = (e - e % wU) + t := by
  apply UInt64.toNat_inj.mp
  have hW : 0 < 2 ^ k := Nat.two_pow_pos k
  have hE : e.toNat < 2 ^ 64 := e.toNat_lt
  have hT : t.toNat < 2 ^ k := hw ▸ UInt64.lt_iff_toNat_lt.mp ht
  have hkk : 2 ^ (64 - k) * 2 ^ k = 2 ^ 64 := by rw [← Nat.pow_add]; congr 1; omega
  have hk64 : 2 ^ k ≤ 2 ^ 64 := Nat.pow_le_pow_right (by decide) (by omega)
  have hm1 : (wU - 1).toNat = 2 ^ k - 1 := by
    rw [UInt64.toNat_sub_of_le _ _ (by rw [UInt64.le_iff_toNat_le, hw]; simp; omega), hw]
    simp
  have hnot : (~~~(wU - 1)).toNat = (2 ^ (64 - k) - 1) * 2 ^ k := by
    rw [UInt64.toNat_not, hm1, Nat.sub_mul, hkk, Nat.one_mul]
    simp only [UInt64.size]; omega
  have hlhs : (e.toNat &&& (2 ^ (64 - k) - 1) * 2 ^ k) = e.toNat / 2 ^ k * 2 ^ k := by
    apply Nat.eq_of_testBit_eq; intro i
    rw [Nat.testBit_and, Nat.testBit_mul_two_pow, Nat.testBit_mul_two_pow,
      Nat.testBit_two_pow_sub_one, Nat.testBit_div_two_pow]
    by_cases hi : k ≤ i
    · have hik : i - k + k = i := by omega
      rw [hik]
      by_cases h64 : i < 64
      · have : i - k < 64 - k := by omega
        simp [hi, this]
      · have : e.toNat.testBit i = false :=
          Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le hE (Nat.pow_le_pow_right (by decide) (by omega)))
        simp [this]
    · simp [hi]
  have hor : e.toNat / 2 ^ k * 2 ^ k ||| t.toNat = e.toNat / 2 ^ k * 2 ^ k + t.toNat := by
    rw [← Nat.shiftLeft_eq]; exact (Nat.shiftLeft_add_eq_or_of_lt hT _).symm
  rw [UInt64.toNat_or, UInt64.toNat_and, hnot, hlhs, hor]
  have hmod : (e % wU).toNat = e.toNat % 2 ^ k := by rw [UInt64.toNat_mod, hw]
  have hle : e % wU ≤ e := by rw [UInt64.le_iff_toNat_le, hmod]; exact Nat.mod_le _ _
  rw [UInt64.toNat_add, UInt64.toNat_sub_of_le _ _ hle, hmod]
  have hdm : e.toNat % 2 ^ k + e.toNat / 2 ^ k * 2 ^ k = e.toNat := Nat.mod_add_div' _ _
  have hq : e.toNat / 2 ^ k < 2 ^ (64 - k) := (Nat.div_lt_iff_lt_mul hW).mpr (by omega)
  have hb : (e.toNat / 2 ^ k + 1) * 2 ^ k ≤ 2 ^ (64 - k) * 2 ^ k := Nat.mul_le_mul_right _ hq
  rw [Nat.add_mul, Nat.one_mul, hkk] at hb
  generalize e.toNat / 2 ^ k * 2 ^ k = Q at *
  rw [Nat.mod_eq_of_lt (by omega)]
  omega

/-- Per-length instantiation of the bit-level facts. -/
theorem decodePnImpl_eq_rfc_of (len : Nat) (W : Nat) (wU : UInt64)
    (hWdef : W = 2 ^ (8 * len)) (hwU : wU.toNat = W) (hW : W ≤ 2^32) (hW2 : 2 ≤ W)
    (hwin : (1 : UInt64) <<< ((Int64.ofNat len) * 8).toUInt64 = wU)
    (hcand : ∀ e t : UInt64, t < wU → (e &&& ~~~(wU - 1)) ||| t = (e - e % wU) + t)
    (tpn largest : UInt64) (ht : tpn < wU) (hl : largest.toNat < 2^62) :
    ((decodePnImpl tpn (Int64.ofNat len) largest).toNat : Int)
      = rfcDecode tpn.toNat len largest.toNat := by
  unfold decodePnImpl rfcDecode
  simp only [hwin, hcand _ _ ht]
  have he : (largest + 1).toNat = largest.toNat + 1 := by rw [UInt64.toNat_add]; simp; omega
  have hmod : ((largest + 1) % wU).toNat = (largest.toNat + 1) % W := by
    rw [UInt64.toNat_mod, he, hwU]
  have hT : tpn.toNat < W := by rw [← hwU]; exact UInt64.lt_iff_toNat_lt.mp ht
  have hcN : ((largest + 1) - (largest + 1) % wU + tpn).toNat
      = (largest.toNat + 1) - (largest.toNat + 1) % W + tpn.toNat := by
    have hle : ((largest + 1) % wU) ≤ (largest + 1) := by
      rw [UInt64.le_iff_toNat_le, hmod, he]; exact Nat.mod_le _ _
    rw [UInt64.toNat_add, UInt64.toNat_sub_of_le _ _ hle, hmod, he]
    have := Nat.mod_le (largest.toNat + 1) W
    omega
  have hlim : (((1 : UInt64) <<< 62) - wU).toNat = 2^62 - W := by
    have : ((1 : UInt64) <<< 62).toNat = 2^62 := by decide
    rw [UInt64.toNat_sub_of_le _ _ (by rw [UInt64.le_iff_toNat_le, this, hwU]; omega), this, hwU]
  have hh : (wU >>> 1).toNat = W / 2 := by
    rw [UInt64.toNat_shiftRight, hwU]; simp [Nat.shiftRight_eq_div_pow]
  have hb := branch_toNat _ _ _ _ _ _ _ _ _ hcN he hwU hh hlim hW rfl (by omega)
    (by have := Nat.mod_le (largest.toNat + 1) W; omega)
  rw [hb]
  have hWi : ((2:Int) ^ (8 * len)) = (W : Int) := by rw [hWdef]; simp
  have hm : ((largest.toNat : Int) + 1) % (W:Int) = (((largest.toNat + 1) % W : Nat) : Int) := by
    simp
  simp only [hWi, hm]
  have hmle := Nat.mod_le (largest.toNat + 1) W
  have hcast : (((largest.toNat + 1 - (largest.toNat + 1) % W + tpn.toNat : Nat)) : Int)
      = (largest.toNat : Int) + 1 - (((largest.toNat + 1) % W : Nat) : Int) + tpn.toNat := by
    omega
  have hcast2 : (((W / 2 : Nat)) : Int) = (W : Int) / 2 := by omega
  have hc3 : ((largest.toNat + 1 : Nat) : Int) = (largest.toNat : Int) + 1 := by omega
  rw [hcast, hcast2, hc3]

/-- **Equivalence with the RFC pseudocode.** For packet-number lengths 1..4,
a truncated value inside the window, and `largest_pn < 2^62`, flare's
underflow-free rewrite returns exactly what RFC 9000 A.3 returns. -/
theorem decodePnImpl_eq_rfc (len : Nat) (hlen : 1 ≤ len ∧ len ≤ 4)
    (tpn largest : UInt64) (ht : tpn.toNat < 2 ^ (8 * len)) (hl : largest.toNat < 2^62) :
    ((decodePnImpl tpn (Int64.ofNat len) largest).toNat : Int)
      = rfcDecode tpn.toNat len largest.toNat := by
  have : len = 1 ∨ len = 2 ∨ len = 3 ∨ len = 4 := by omega
  rcases this with rfl | rfl | rfl | rfl
  · exact decodePnImpl_eq_rfc_of 1 256 256 rfl rfl (by decide) (by decide) (by decide)
      (cand_eq 8 (by decide) 256 rfl) tpn largest (UInt64.lt_iff_toNat_lt.mpr ht) hl
  · exact decodePnImpl_eq_rfc_of 2 65536 65536 rfl rfl (by decide) (by decide) (by decide)
      (cand_eq 16 (by decide) 65536 rfl) tpn largest (UInt64.lt_iff_toNat_lt.mpr ht) hl
  · exact decodePnImpl_eq_rfc_of 3 16777216 16777216 rfl rfl (by decide) (by decide) (by decide)
      (cand_eq 24 (by decide) 16777216 rfl) tpn largest (UInt64.lt_iff_toNat_lt.mpr ht) hl
  · exact decodePnImpl_eq_rfc_of 4 4294967296 4294967296 rfl rfl (by decide) (by decide)
      (by decide) (cand_eq 32 (by decide) 4294967296 rfl) tpn largest (UInt64.lt_iff_toNat_lt.mpr ht) hl

/-- **Window theorem for the RFC algorithm.** If the true packet number `pn`
satisfies `expected - hwin < pn ≤ expected + hwin` and `pn < 2^62`, the RFC
algorithm recovers it from its low `8·len` bits. -/
theorem rfcDecode_window (len : Nat) (hlen : 1 ≤ len ∧ len ≤ 4) (pn largest : Nat)
    (hpn : pn < 2^62)
    (hlo : largest + 1 < pn + 2 ^ (8 * len) / 2)
    (hhi : pn ≤ largest + 1 + 2 ^ (8 * len) / 2) :
    rfcDecode (pn % 2 ^ (8 * len)) len largest = pn := by
  have : len = 1 ∨ len = 2 ∨ len = 3 ∨ len = 4 := by omega
  rcases this with rfl | rfl | rfl | rfl <;>
  · simp only [rfcDecode] at *
    simp only [Nat.reduceMul, Nat.reducePow, Nat.reduceDiv, Int.reducePow, Int.reduceMul] at *
    split <;> (try split) <;> omega

/-- **Window theorem for flare's code** (composition of the two above). -/
theorem decodePnImpl_window (len : Nat) (hlen : 1 ≤ len ∧ len ≤ 4) (pn largest : UInt64)
    (hpn : pn.toNat < 2^62) (hl : largest.toNat < 2^62)
    (hlo : largest.toNat + 1 < pn.toNat + 2 ^ (8 * len) / 2)
    (hhi : pn.toNat ≤ largest.toNat + 1 + 2 ^ (8 * len) / 2) :
    decodePnImpl (UInt64.ofNat (pn.toNat % 2 ^ (8 * len))) (Int64.ofNat len) largest = pn := by
  have hW : 2 ^ (8 * len) ≤ 2 ^ 32 := Nat.pow_le_pow_right (by decide) (by omega)
  have htn : (UInt64.ofNat (pn.toNat % 2 ^ (8 * len))).toNat = pn.toNat % 2 ^ (8 * len) := by
    rw [UInt64.toNat_ofNat']; apply Nat.mod_eq_of_lt
    have := Nat.mod_lt pn.toNat (Nat.two_pow_pos (8 * len)); omega
  have h1 := decodePnImpl_eq_rfc len hlen (UInt64.ofNat (pn.toNat % 2 ^ (8 * len))) largest
    (by rw [htn]; exact Nat.mod_lt _ (Nat.two_pow_pos _)) hl
  rw [htn, rfcDecode_window len hlen pn.toNat largest.toNat hpn hlo hhi] at h1
  apply UInt64.toNat_inj.mp; omega

end Flare.L3.Quic.PacketNumber
