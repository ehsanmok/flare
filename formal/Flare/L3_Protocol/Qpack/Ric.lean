/-!
# QPACK Required Insert Count (RFC 9204 §4.5.1.1)

`implEncode` / `implDecode` transliterate flare's UInt64 code. `specDecode`
is the RFC 9204 §4.5.1.1 pseudocode over `Nat` (no wraparound). We prove

* `implDecode_eq_spec`: under no-overflow bounds the UInt64 code computes
  exactly the RFC pseudocode (same result, same error cases);
* `specDecode_encode`: the RFC window theorem: if `0 < ric`,
  `ric ≤ T + ME` and `T < ric + ME` (the entry is not older than the table
  can hold), decoding the encoding returns `ric`;
* `implDecode_encode`: the same for flare's code.
-/
namespace Flare.L3.Qpack.Ric

/-- mirrors flare/qpack/dynamic.mojo:181-185 @59bda50 -/
def implEncode (ric maxEntries : UInt64) : UInt64 :=
  if ric = 0 then 0 else ric % (2 * maxEntries) + 1

/-- mirrors flare/qpack/dynamic.mojo:188-209 @59bda50
(`none` = raised `Error`). -/
def implDecode (enc total maxEntries : UInt64) : Option UInt64 :=
  if enc = 0 then some 0
  else if maxEntries = 0 then none
  else
    let fullRange := 2 * maxEntries
    if enc > fullRange then none
    else
      let maxValue := total + maxEntries
      let maxWrapped := (maxValue / fullRange) * fullRange
      let ric := maxWrapped + enc - 1
      let r :=
        if ric > maxValue then
          if ric ≤ fullRange then none else some (ric - fullRange)
        else some ric
      match r with
      | none => none
      | some ric => if ric = 0 then none else some ric

/-- RFC 9204 §4.5.1.1 encoder, over `Nat`. -/
def specEncode (ric me : Nat) : Nat :=
  if ric = 0 then 0 else ric % (2 * me) + 1

/-- RFC 9204 §4.5.1.1 decoder pseudocode, over `Nat`. -/
def specDecode (enc total me : Nat) : Option Nat :=
  if enc = 0 then some 0
  else if me = 0 then none
  else if enc > 2 * me then none
  else
    let maxValue := total + me
    let ric := maxValue / (2 * me) * (2 * me) + enc - 1
    if ric > maxValue then
      if ric ≤ 2 * me then none
      else if ric - 2 * me = 0 then none else some (ric - 2 * me)
    else if ric = 0 then none else some ric

/-- The UInt64 code equals the RFC pseudocode when no intermediate value can
wrap: `maxEntries < 2^61` and `total < 2^62` (flare caps capacities far
below this; `total` is an insert counter). -/
theorem implDecode_eq_spec (enc total me : UInt64)
    (hme : me.toNat < 2 ^ 61) (ht : total.toNat < 2 ^ 62) :
    (implDecode enc total me).map UInt64.toNat
      = specDecode enc.toNat total.toNat me.toNat := by
  have h2me : (2 * me).toNat = 2 * me.toNat := by
    rw [UInt64.toNat_mul]; simp; omega
  have hmv : (total + me).toNat = total.toNat + me.toNat := by
    rw [UInt64.toNat_add]; omega
  unfold implDecode specDecode
  by_cases he : enc = 0
  · subst he; simp
  have he' : enc.toNat ≠ 0 := by
    intro h; apply he; exact UInt64.toNat_inj.mp (by simpa using h)
  simp only [he, he', if_false]
  by_cases hm : me = 0
  · subst hm; simp
  have hm' : me.toNat ≠ 0 := by
    intro h; apply hm; exact UInt64.toNat_inj.mp (by simpa using h)
  simp only [hm, hm', if_false]
  by_cases hgt : enc > 2 * me
  · have : enc.toNat > 2 * me.toNat := by
      rw [← h2me]; exact UInt64.lt_iff_toNat_lt.mp hgt
    simp [hgt, this]
  have hgt' : ¬ enc.toNat > 2 * me.toNat := fun h =>
    hgt (by show 2 * me < enc; rw [UInt64.lt_iff_toNat_lt, h2me]; exact h)
  have hle : enc.toNat ≤ 2 * me.toNat := by omega
  simp only [hgt, hgt', if_false]
  -- the wrapped base
  have hdiv : ((total + me) / (2 * me)).toNat = (total.toNat + me.toNat) / (2 * me.toNat) := by
    rw [UInt64.toNat_div, hmv, h2me]
  have hmwle : (total.toNat + me.toNat) / (2 * me.toNat) * (2 * me.toNat)
      ≤ total.toNat + me.toNat := Nat.div_mul_le_self _ _
  have hmw : ((total + me) / (2 * me) * (2 * me)).toNat
      = (total.toNat + me.toNat) / (2 * me.toNat) * (2 * me.toNat) := by
    rw [UInt64.toNat_mul, hdiv, h2me]; apply Nat.mod_eq_of_lt; omega
  have hsum : ((total + me) / (2 * me) * (2 * me) + enc).toNat
      = (total.toNat + me.toNat) / (2 * me.toNat) * (2 * me.toNat) + enc.toNat := by
    rw [UInt64.toNat_add, hmw]; apply Nat.mod_eq_of_lt; omega
  have hone : (1 : UInt64) ≤ (total + me) / (2 * me) * (2 * me) + enc := by
    rw [UInt64.le_iff_toNat_le, hsum]; simp; omega
  have hric : ((total + me) / (2 * me) * (2 * me) + enc - 1).toNat
      = (total.toNat + me.toNat) / (2 * me.toNat) * (2 * me.toNat) + enc.toNat - 1 := by
    rw [UInt64.toNat_sub_of_le _ _ hone, hsum]; simp
  generalize hR : (total + me) / (2 * me) * (2 * me) + enc - 1 = R at hric
  generalize hRn : (total.toNat + me.toNat) / (2 * me.toNat) * (2 * me.toNat) + enc.toNat - 1 = Rn at hric
  have hRbound : Rn ≤ total.toNat + me.toNat + 2 * me.toNat := by omega
  by_cases h1 : R > total + me
  · have h1' : Rn > total.toNat + me.toNat := by
      rw [← hric, ← hmv]; exact UInt64.lt_iff_toNat_lt.mp h1
    simp only [h1, h1', if_true]
    by_cases h2 : R ≤ 2 * me
    · have h2' : Rn ≤ 2 * me.toNat := by
        rw [← hric, ← h2me]; exact UInt64.le_iff_toNat_le.mp h2
      simp [h2, h2']
    · have h2' : ¬ Rn ≤ 2 * me.toNat := by
        intro h; apply h2; show R ≤ 2 * me; rw [UInt64.le_iff_toNat_le, hric, h2me]; exact h
      have hle2 : 2 * me ≤ R := by
        rw [UInt64.le_iff_toNat_le, hric, h2me]; omega
      have hsub : (R - 2 * me).toNat = Rn - 2 * me.toNat := by
        rw [UInt64.toNat_sub_of_le _ _ hle2, hric, h2me]
      simp only [h2, h2', if_false]
      by_cases hz : R - 2 * me = 0
      · have : Rn - 2 * me.toNat = 0 := by rw [← hsub, hz]; rfl
        simp [hz, this]
      · have : Rn - 2 * me.toNat ≠ 0 := by
          intro h; apply hz; apply UInt64.toNat_inj.mp; rw [hsub, h]; rfl
        simp [hz, this, hsub]
  · have h1' : ¬ Rn > total.toNat + me.toNat := by
      intro h; apply h1; show total + me < R; rw [UInt64.lt_iff_toNat_lt, hric, hmv]; exact h
    simp only [h1, h1', if_false]
    by_cases hz : R = 0
    · have : Rn = 0 := by rw [← hric, hz]; rfl
      simp [hz, this]
    · have : Rn ≠ 0 := by
        intro h; apply hz; apply UInt64.toNat_inj.mp; rw [hric, h]; rfl
      simp [hz, this, hric]

/-- RFC 9204 §4.5.1.1 window theorem (spec level): within the window
`T - ME < ric ≤ T + ME`, decoding the encoding recovers `ric`. -/
theorem specDecode_encode (ric total me : Nat) (hme : 0 < me)
    (hpos : 0 < ric) (hhi : ric ≤ total + me) (hlo : total < ric + me) :
    specDecode (specEncode ric me) total me = some ric := by
  have hfr : 0 < 2 * me := by omega
  unfold specEncode specDecode
  have hr0 : ric ≠ 0 := by omega
  simp only [hr0, if_false]
  have hmod := Nat.mod_lt ric hfr
  have he0 : ric % (2 * me) + 1 ≠ 0 := by omega
  have hme0 : me ≠ 0 := by omega
  simp only [he0, hme0, if_false]
  have hgt : ¬ ric % (2 * me) + 1 > 2 * me := by omega
  simp only [hgt, if_false]
  -- write ric = q*F + m and maxValue = q'*F + m'
  have hric := Nat.div_add_mod' ric (2 * me)
  have hmv := Nat.div_add_mod' (total + me) (2 * me)
  have hmv' := Nat.mod_lt (total + me) hfr
  generalize ric / (2 * me) = q at hric
  generalize ric % (2 * me) = m at hric hmod he0 hgt ⊢
  generalize (total + me) / (2 * me) = q' at hmv ⊢
  generalize (total + me) % (2 * me) = m' at hmv hmv'
  generalize hF : 2 * me = F at *
  -- ric ∈ (maxValue - F, maxValue], so q' = q (if m ≤ m') or q' = q + 1
  have hcase : q' = q ∨ q' = q + 1 := by
    have h1 : q * F ≤ q' * F + m' := by
      have : q * F + m ≤ q' * F + m' := by omega
      omega
    have h2 : q' * F + m' < q * F + m + F := by omega
    have hq1 : q ≤ q' := by
      rcases Nat.lt_or_ge q' q with h | h
      · have : (q' + 1) * F ≤ q * F := Nat.mul_le_mul_right F h
        rw [Nat.add_mul, Nat.one_mul] at this; omega
      · exact h
    have hq2 : q' ≤ q + 1 := by
      rcases Nat.lt_or_ge (q + 1) q' with h | h
      · have : (q + 1 + 1) * F ≤ q' * F := Nat.mul_le_mul_right F h
        rw [Nat.add_mul, Nat.add_mul, Nat.one_mul] at this; omega
      · exact h
    omega
  rcases hcase with h | h
  · subst h
    rw [if_neg (by omega), if_neg (by omega)]; exact congrArg some (by omega)
  · subst h
    rw [Nat.add_mul, Nat.one_mul] at hmv ⊢
    by_cases hm : m ≤ m'
    · exfalso; omega
    · rw [if_pos (by omega), if_neg (by omega), if_neg (by omega)]; congr 1; omega

theorem implEncode_toNat (ric me : UInt64) (hme0 : 0 < me.toNat) (hme : me.toNat < 2 ^ 61) :
    (implEncode ric me).toNat = specEncode ric.toNat me.toNat := by
  unfold implEncode specEncode
  have h2me : (2 * me).toNat = 2 * me.toNat := by
    rw [UInt64.toNat_mul]; simp; omega
  by_cases h : ric = 0
  · subst h; simp
  · have h' : ric.toNat ≠ 0 := by
      intro e; apply h; exact UInt64.toNat_inj.mp (by simpa using e)
    simp only [h, h', if_false]
    rw [UInt64.toNat_add, UInt64.toNat_mod, h2me]
    have := Nat.mod_lt ric.toNat (by omega : 0 < 2 * me.toNat)
    simp; omega

/-- Window theorem for flare's UInt64 code (encoder and decoder as
transliterated). -/
theorem implDecode_encode (ric total me : UInt64)
    (hme0 : 0 < me.toNat) (hme : me.toNat < 2 ^ 61) (ht : total.toNat < 2 ^ 62)
    (hpos : 0 < ric.toNat) (hhi : ric.toNat ≤ total.toNat + me.toNat)
    (hlo : total.toNat < ric.toNat + me.toNat) :
    implDecode (implEncode ric me) total me = some ric := by
  have h := implDecode_eq_spec (implEncode ric me) total me hme ht
  rw [implEncode_toNat ric me hme0 hme, specDecode_encode _ _ _ hme0 hpos hhi hlo] at h
  cases hd : implDecode (implEncode ric me) total me with
  | none => rw [hd] at h; simp at h
  | some v =>
    rw [hd] at h; simp at h
    rw [UInt64.toNat_inj.mp h]

end Flare.L3.Qpack.Ric
