/-!
# QUIC ACK range expansion (RFC 9000 §19.3.1)

`expand_ack_ranges` turns a decoded ACK frame into the list of packet
numbers whose in-flight records loss recovery retires. The model works
over `Nat`. That is faithful because every subtraction in the Mojo code
is guarded (`largest >= first_len`, `cur_lo < step` breaks,
`next_largest >= length`), and `gap + 2` cannot wrap: `gap` is a QUIC
varint, so it is below 2^62.

Results:
* `expand_sound`: every number in the output lies in a range the ACK
  claims (RFC 9000 §19.3.1 arithmetic over the integers). Clamping
  malformed ranges at 0 never makes flare retire a packet the peer did
  not claim.
* `expand_len_le`: the output never exceeds the cap (256 in flare).
-/

namespace Flare.L3.Quic.AckExpand

/-- The inner `while p >= lo` loop. Returns the extended output and
whether the function returned early (cap reached or `p == 0`).
mirrors flare/quic/state.mojo:402-407 and 420-425 @59bda50 -/
def emitLoop (cap lo : Nat) : Nat → List Nat → List Nat × Bool
  | 0, out => if lo ≤ 0 then (out ++ [0], true) else (out, false)
  | p + 1, out =>
    if lo ≤ p + 1 then
      if (out ++ [p + 1]).length ≥ cap then (out ++ [p + 1], true)
      else emitLoop cap lo p (out ++ [p + 1])
    else (out, false)

/-- The loop over the additional ranges `(gap, length)`.
mirrors flare/quic/state.mojo:408-426 @59bda50 -/
def rangesLoop (cap : Nat) (curLo : Nat) (out : List Nat) :
    List (Nat × Nat) → List Nat
  | [] => out
  | (gap, len) :: rs =>
    if curLo < gap + 2 then out
    else
      let nl := curLo - (gap + 2)
      let nlo := nl - len
      match emitLoop cap nlo nl out with
      | (o, true) => o
      | (o, false) => rangesLoop cap nlo o rs

/-- mirrors flare/quic/state.mojo:388-427 @59bda50 (`_ACK_EXPAND_CAP` = 256
at state.mojo:380) -/
def expand (cap largest first : Nat) (ranges : List (Nat × Nat)) : List Nat :=
  match emitLoop cap (largest - first) largest [] with
  | (o, true) => o
  | (o, false) => rangesLoop cap (largest - first) o ranges

/-! ## Spec: the claimed intervals, computed over `Int` -/

/-- RFC 9000 §19.3.1: each range starts `gap + 2` below the previous
smallest and spans `length + 1` numbers. -/
def intervalsFrom (lo : Int) : List (Nat × Nat) → List (Int × Int)
  | [] => []
  | (g, l) :: rs =>
    let hi := lo - g - 2
    (hi - l, hi) :: intervalsFrom (hi - l) rs

def intervals (largest first : Nat) (ranges : List (Nat × Nat)) : List (Int × Int) :=
  ((largest : Int) - first, (largest : Int)) :: intervalsFrom ((largest : Int) - first) ranges

/-- `n` lies in an interval the ACK claims. -/
def Claimed (largest first : Nat) (ranges : List (Nat × Nat)) (n : Nat) : Prop :=
  ∃ iv ∈ intervals largest first ranges, iv.1 ≤ (n : Int) ∧ (n : Int) ≤ iv.2

/-! ## Soundness -/

theorem emitLoop_mem (cap lo : Nat) :
    ∀ p out n, n ∈ (emitLoop cap lo p out).1 → n ∈ out ∨ (lo ≤ n ∧ n ≤ p) := by
  intro p
  induction p with
  | zero =>
    intro out n h
    simp only [emitLoop] at h
    split at h
    · simp only [List.mem_append, List.mem_singleton] at h
      rcases h with h | h
      · exact .inl h
      · right; omega
    · exact .inl h
  | succ p ih =>
    intro out n h
    simp only [emitLoop] at h
    split at h
    · split at h
      · simp only [List.mem_append, List.mem_singleton] at h
        rcases h with h | h
        · exact .inl h
        · right; omega
      · rcases ih _ _ h with h' | h'
        · simp only [List.mem_append, List.mem_singleton] at h'
          rcases h' with h' | h'
          · exact .inl h'
          · right; omega
        · right; omega
    · exact .inl h

theorem rangesLoop_mem (cap : Nat) :
    ∀ (rs : List (Nat × Nat)) (curLo : Nat) (L : Int) (out : List Nat) (n : Nat),
      ((curLo : Int) = L ∨ (curLo = 0 ∧ L ≤ 0)) →
      n ∈ rangesLoop cap curLo out rs →
      n ∈ out ∨ ∃ iv ∈ intervalsFrom L rs, iv.1 ≤ (n : Int) ∧ (n : Int) ≤ iv.2 := by
  intro rs
  induction rs with
  | nil => intro _ _ _ _ _ h; exact .inl h
  | cons r rs ih =>
    obtain ⟨g, l⟩ := r
    intro curLo L out n hinv h
    simp only [rangesLoop] at h
    split at h
    · exact .inl h
    · rename_i hstep
      have hL : (curLo : Int) = L := by omega
      have key : ∀ m, m ∈ (emitLoop cap (curLo - (g + 2) - l) (curLo - (g + 2)) out).1 →
          m ∈ out ∨ ((L - g - 2 - l : Int) ≤ m ∧ (m : Int) ≤ L - g - 2) := by
        intro m hm
        rcases emitLoop_mem cap _ _ _ _ hm with h1 | h1
        · exact .inl h1
        · right; omega
      have hiv : ∀ m, ((L - g - 2 - l : Int) ≤ m ∧ (m : Int) ≤ L - g - 2) →
          ∃ iv ∈ intervalsFrom L ((g, l) :: rs), iv.1 ≤ (m : Int) ∧ (m : Int) ≤ iv.2 := by
        intro m hm
        exact ⟨(L - g - 2 - l, L - g - 2), by simp [intervalsFrom], hm⟩
      revert h
      generalize hE : emitLoop cap (curLo - (g + 2) - l) (curLo - (g + 2)) out = e
      obtain ⟨o, b⟩ := e
      intro h
      have ho : ∀ m, m ∈ o → m ∈ out ∨ ∃ iv ∈ intervalsFrom L ((g, l) :: rs),
          iv.1 ≤ (m : Int) ∧ (m : Int) ≤ iv.2 := by
        intro m hm
        have := key m (by rw [hE]; exact hm)
        rcases this with h1 | h1
        · exact .inl h1
        · exact .inr (hiv m h1)
      cases b with
      | true => exact ho n h
      | false =>
        simp only at h
        rcases ih _ (L - g - 2 - l) o n (by omega) h with h1 | h1
        · exact ho n h1
        · obtain ⟨iv, hmem, hb⟩ := h1
          exact .inr ⟨iv, by simp [intervalsFrom, hmem], hb⟩

/-- Every packet number flare retires for an ACK is one the ACK claims. -/
theorem expand_sound (cap largest first : Nat) (ranges : List (Nat × Nat)) :
    ∀ n ∈ expand cap largest first ranges, Claimed largest first ranges n := by
  intro n h
  unfold expand at h
  have first_iv : ∀ m, (largest - first ≤ m ∧ m ≤ largest) → Claimed largest first ranges m := by
    intro m hm
    exact ⟨((largest : Int) - first, largest), by simp [intervals], by omega, by omega⟩
  revert h
  generalize hE : emitLoop cap (largest - first) largest [] = e
  obtain ⟨o, b⟩ := e
  have ho : ∀ m, m ∈ o → Claimed largest first ranges m := by
    intro m hm
    rcases emitLoop_mem cap _ _ _ _ (by rw [hE]; exact hm) with h1 | h1
    · simp at h1
    · exact first_iv m h1
  intro h
  cases b with
  | true => exact ho n h
  | false =>
    simp only at h
    rcases rangesLoop_mem cap ranges (largest - first) ((largest : Int) - first) o n
      (by omega) h with h1 | h1
    · exact ho n h1
    · obtain ⟨iv, hmem, hb⟩ := h1
      exact ⟨iv, by simp [intervals, hmem], hb⟩

/-! ## Cap -/

theorem emitLoop_len (cap lo : Nat) :
    ∀ p out, out.length < cap →
      (emitLoop cap lo p out).1.length ≤ cap ∧
      ((emitLoop cap lo p out).2 = false → (emitLoop cap lo p out).1.length < cap) := by
  intro p
  induction p with
  | zero =>
    intro out h
    simp only [emitLoop]
    split
    · simp; omega
    · simp; omega
  | succ p ih =>
    intro out h
    simp only [emitLoop]
    split
    · split
      · rename_i h2; simp at h2 ⊢; omega
      · rename_i h2
        exact ih _ (by simp at h2 ⊢; omega)
    · simp; omega

theorem rangesLoop_len (cap : Nat) :
    ∀ (rs : List (Nat × Nat)) curLo out, out.length < cap →
      (rangesLoop cap curLo out rs).length ≤ cap := by
  intro rs
  induction rs with
  | nil => intro _ _ h; simp [rangesLoop]; omega
  | cons r rs ih =>
    obtain ⟨g, l⟩ := r
    intro curLo out h
    simp only [rangesLoop]
    split
    · omega
    · have hl := emitLoop_len cap (curLo - (g + 2) - l) (curLo - (g + 2)) out h
      revert hl
      generalize emitLoop cap (curLo - (g + 2) - l) (curLo - (g + 2)) out = e
      obtain ⟨o, b⟩ := e
      intro hl
      cases b with
      | true => exact hl.1
      | false => exact ih _ _ (hl.2 rfl)

/-- The expansion never exceeds the cap (flare: 256). -/
theorem expand_len_le (cap largest first : Nat) (ranges : List (Nat × Nat)) (hcap : 0 < cap) :
    (expand cap largest first ranges).length ≤ cap := by
  unfold expand
  have hl := emitLoop_len cap (largest - first) largest [] (by simp; omega)
  revert hl
  generalize emitLoop cap (largest - first) largest [] = e
  obtain ⟨o, b⟩ := e
  intro hl
  cases b with
  | true => exact hl.1
  | false => exact rangesLoop_len cap ranges _ _ (hl.2 rfl)

/-! ## Exact output: the descending claimed list, truncated at the cap -/

/-- `p, p-1, ..., lo` (empty if `lo > p`). -/
def desc (lo : Nat) : Nat → List Nat
  | 0 => if lo ≤ 0 then [0] else []
  | p + 1 => if lo ≤ p + 1 then (p + 1) :: desc lo p else []

theorem mem_desc (lo : Nat) : ∀ p n, n ∈ desc lo p ↔ lo ≤ n ∧ n ≤ p := by
  intro p
  induction p with
  | zero => intro n; simp only [desc]; split <;> simp <;> omega
  | succ p ih =>
    intro n; simp only [desc]; split
    · simp only [List.mem_cons, ih]; omega
    · simp; omega

theorem desc_pairwise (lo : Nat) : ∀ p, (desc lo p).Pairwise (· > ·) := by
  intro p
  induction p with
  | zero => simp only [desc]; split <;> simp
  | succ p ih =>
    simp only [desc]; split
    · refine List.pairwise_cons.mpr ⟨fun a h => ?_, ih⟩
      have := (mem_desc lo p a).mp h; omega
    · simp

/-- The intervals flare walks, as `(hi, lo)` pairs, with its guarded
`Nat` arithmetic: a range whose largest would be negative ends the walk. -/
def rangesIvs (curLo : Nat) : List (Nat × Nat) → List (Nat × Nat)
  | [] => []
  | (g, l) :: rs =>
    if curLo < g + 2 then []
    else (curLo - (g + 2), curLo - (g + 2) - l) :: rangesIvs (curLo - (g + 2) - l) rs

def implIvs (largest first : Nat) (ranges : List (Nat × Nat)) : List (Nat × Nat) :=
  (largest, largest - first) :: rangesIvs (largest - first) ranges

def ivList : List (Nat × Nat) → List Nat
  | [] => []
  | (h, l) :: r => desc l h ++ ivList r

/-- Every packet number the walk would produce, newest first, uncapped. -/
def implList (largest first : Nat) (ranges : List (Nat × Nat)) : List Nat :=
  ivList (implIvs largest first ranges)

theorem emitLoop_eq (cap lo : Nat) :
    ∀ p out, out.length < cap →
      (emitLoop cap lo p out).1 = (out ++ desc lo p).take cap ∧
      ((emitLoop cap lo p out).2 = true → cap ≤ (out ++ desc lo p).length ∨ lo = 0) ∧
      ((emitLoop cap lo p out).2 = false → (out ++ desc lo p).length < cap) := by
  intro p
  induction p with
  | zero =>
    intro out h
    simp only [emitLoop, desc]
    split
    · exact ⟨(List.take_of_length_le (by simp; omega)).symm, fun _ => .inr (by omega), by simp⟩
    · simp only [List.append_nil]
      exact ⟨(List.take_of_length_le (by omega)).symm, by simp, fun _ => h⟩
  | succ p ih =>
    intro out h
    simp only [emitLoop, desc]
    split
    · split
      · rename_i h2
        simp only [List.length_append, List.length_singleton] at h2
        refine ⟨?_, fun _ => .inl (by simp; omega), by simp⟩
        rw [show out ++ (p + 1) :: desc lo p = (out ++ [p + 1]) ++ desc lo p by simp]
        exact (List.take_left' (by simp; omega)).symm
      · rename_i h2
        have := ih (out ++ [p + 1]) (by simp at h2 ⊢; omega)
        simp only [List.append_assoc, List.singleton_append] at this
        exact this
    · simp only [List.append_nil]
      exact ⟨(List.take_of_length_le (by omega)).symm, by simp, fun _ => h⟩

theorem rangesIvs_zero (rs : List (Nat × Nat)) : rangesIvs 0 rs = [] := by
  cases rs with
  | nil => rfl
  | cons r rs => obtain ⟨g, l⟩ := r; simp [rangesIvs]

theorem rangesLoop_eq (cap : Nat) :
    ∀ (rs : List (Nat × Nat)) curLo out, out.length < cap →
      rangesLoop cap curLo out rs = (out ++ ivList (rangesIvs curLo rs)).take cap := by
  intro rs
  induction rs with
  | nil => intro _ out h; simp [rangesLoop, rangesIvs, ivList, List.take_of_length_le (Nat.le_of_lt h)]
  | cons r rs ih =>
    obtain ⟨g, l⟩ := r
    intro curLo out h
    simp only [rangesLoop, rangesIvs]
    split
    · simp [ivList, List.take_of_length_le (Nat.le_of_lt h)]
    · have hE := emitLoop_eq cap (curLo - (g + 2) - l) (curLo - (g + 2)) out h
      revert hE
      generalize emitLoop cap (curLo - (g + 2) - l) (curLo - (g + 2)) out = e
      obtain ⟨o, b⟩ := e
      intro ⟨h1, h2, h3⟩
      simp only at h1 h2 h3
      simp only [ivList, ← List.append_assoc]
      cases b with
      | true =>
        simp only
        rcases h2 rfl with hc | h0
        · rw [h1, List.take_append_of_le_length hc]
        · rw [h1, h0, rangesIvs_zero]; simp [ivList]
      | false =>
        simp only
        have hlt := h3 rfl
        have ho : o = out ++ desc (curLo - (g + 2) - l) (curLo - (g + 2)) := by
          rw [h1]; exact List.take_of_length_le (Nat.le_of_lt hlt)
        rw [ih _ o (by rw [ho]; exact hlt), ho]

/-- **Exact behaviour.** For every ACK, flare's expansion is the first
`cap` entries of `implList`, the newest-first list of the numbers in the
ranges it walks. -/
theorem expand_eq_take (cap largest first : Nat) (ranges : List (Nat × Nat)) (hcap : 0 < cap) :
    expand cap largest first ranges = (implList largest first ranges).take cap := by
  unfold expand implList implIvs
  have hE := emitLoop_eq cap (largest - first) largest [] (by simp; omega)
  revert hE
  generalize emitLoop cap (largest - first) largest [] = e
  obtain ⟨o, b⟩ := e
  intro ⟨h1, h2, h3⟩
  simp only [List.nil_append] at h1 h2 h3
  simp only [ivList]
  cases b with
  | true =>
    simp only
    rcases h2 rfl with hc | h0
    · rw [h1, List.take_append_of_le_length hc]
    · rw [h1, h0, rangesIvs_zero]; simp [ivList]
  | false =>
    simp only
    have hlt := h3 rfl
    have ho : o = desc (largest - first) largest := by
      rw [h1]; exact List.take_of_length_le (Nat.le_of_lt hlt)
    rw [rangesLoop_eq cap ranges _ o (by rw [ho]; exact hlt), ho]

/-- The ACK is well formed (RFC 9000 §19.3.1): no computed packet number
is negative. This is the condition the QUIC-03 fix enforces. -/
def WellFormed (largest first : Nat) (ranges : List (Nat × Nat)) : Prop :=
  ∀ iv ∈ intervals largest first ranges, 0 ≤ iv.1

theorem mem_ivList (ivs : List (Nat × Nat)) (n : Nat) :
    n ∈ ivList ivs ↔ ∃ iv ∈ ivs, iv.2 ≤ n ∧ n ≤ iv.1 := by
  induction ivs with
  | nil => simp [ivList]
  | cons iv ivs ih =>
    obtain ⟨h, l⟩ := iv
    simp only [ivList, List.mem_append, mem_desc, ih, List.mem_cons]
    constructor
    · rintro (h1 | ⟨iv, hm, hb⟩)
      · exact ⟨(h, l), .inl rfl, h1⟩
      · exact ⟨iv, .inr hm, hb⟩
    · rintro ⟨iv, (rfl | hm), hb⟩
      · exact .inl hb
      · exact .inr ⟨iv, hm, hb⟩

/-- Under well-formedness flare's `Nat` walk produces exactly the RFC
intervals. -/
theorem rangesIvs_eq :
    ∀ (rs : List (Nat × Nat)) (curLo : Nat) (L : Int), (curLo : Int) = L →
      (∀ iv ∈ intervalsFrom L rs, 0 ≤ iv.1) →
      (rangesIvs curLo rs).map (fun p => ((p.2 : Int), (p.1 : Int))) = intervalsFrom L rs := by
  intro rs
  induction rs with
  | nil => intro _ _ _ _; rfl
  | cons r rs ih =>
    obtain ⟨g, l⟩ := r
    intro curLo L hL hwf
    have h0 := hwf (L - g - 2 - l, L - g - 2) (by simp [intervalsFrom])
    simp only at h0
    simp only [rangesIvs, intervalsFrom]
    rw [if_neg (by omega)]
    simp only [List.map_cons, List.cons.injEq]
    refine ⟨by simp only [Prod.mk.injEq]; omega, ih _ _ (by omega) ?_⟩
    intro iv hiv; exact hwf iv (by simp [intervalsFrom, hiv])

theorem implIvs_eq (largest first : Nat) (ranges : List (Nat × Nat))
    (hwf : WellFormed largest first ranges) :
    (implIvs largest first ranges).map (fun p => ((p.2 : Int), (p.1 : Int))) =
      intervals largest first ranges := by
  have h0 := hwf ((largest : Int) - first, largest) (by simp [intervals])
  simp only at h0
  simp only [implIvs, intervals, List.map_cons, List.cons.injEq]
  refine ⟨by simp only [Prod.mk.injEq]; exact ⟨by omega, trivial⟩, rangesIvs_eq _ _ _ (by omega) ?_⟩
  intro iv hiv; exact hwf iv (by simp [intervals, hiv])

/-- For a well-formed ACK, `implList` holds exactly the claimed numbers. -/
theorem mem_implList (largest first : Nat) (ranges : List (Nat × Nat))
    (hwf : WellFormed largest first ranges) (n : Nat) :
    n ∈ implList largest first ranges ↔ Claimed largest first ranges n := by
  unfold implList Claimed
  rw [mem_ivList, ← implIvs_eq largest first ranges hwf]
  constructor
  · rintro ⟨iv, hm, hb⟩
    exact ⟨((iv.2 : Int), (iv.1 : Int)), List.mem_map.mpr ⟨iv, hm, rfl⟩, by simp; omega⟩
  · rintro ⟨iv, hm, hb⟩
    obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hm
    exact ⟨p, hp, by simp at hb; omega⟩

theorem ivs_below :
    ∀ (rs : List (Nat × Nat)) curLo n, n ∈ ivList (rangesIvs curLo rs) → n < curLo := by
  intro rs
  induction rs with
  | nil => intro _ _ h; simp [rangesIvs, ivList] at h
  | cons r rs ih =>
    obtain ⟨g, l⟩ := r
    intro curLo n h
    simp only [rangesIvs] at h
    split at h
    · simp [ivList] at h
    · simp only [ivList, List.mem_append, mem_desc] at h
      rcases h with h | h
      · omega
      · have := ih _ _ h; omega

theorem rangesIvs_pairwise :
    ∀ (rs : List (Nat × Nat)) curLo, (ivList (rangesIvs curLo rs)).Pairwise (· > ·) := by
  intro rs
  induction rs with
  | nil => intro _; simp [rangesIvs, ivList]
  | cons r rs ih =>
    obtain ⟨g, l⟩ := r
    intro curLo
    simp only [rangesIvs]
    split
    · simp [ivList]
    · simp only [ivList]
      refine List.pairwise_append.mpr ⟨desc_pairwise _ _, ih _, fun a ha b hb => ?_⟩
      have h1 := (mem_desc _ _ a).mp ha
      have h2 := ivs_below rs _ b hb
      omega

/-- `implList` is strictly decreasing, for every ACK. -/
theorem implList_pairwise (largest first : Nat) (ranges : List (Nat × Nat)) :
    (implList largest first ranges).Pairwise (· > ·) := by
  simp only [implList, implIvs, ivList]
  refine List.pairwise_append.mpr ⟨desc_pairwise _ _, rangesIvs_pairwise _ _, fun a ha b hb => ?_⟩
  have h1 := (mem_desc _ _ a).mp ha
  have h2 := ivs_below ranges _ b hb
  omega

/-- **Completeness.** For a well-formed ACK claiming at most `cap`
packets, every claimed packet number is in flare's output. -/
theorem expand_complete (cap largest first : Nat) (ranges : List (Nat × Nat)) (hcap : 0 < cap)
    (hwf : WellFormed largest first ranges)
    (hsmall : (implList largest first ranges).length ≤ cap) (n : Nat)
    (hn : Claimed largest first ranges n) : n ∈ expand cap largest first ranges := by
  rw [expand_eq_take cap _ _ _ hcap, List.take_of_length_le hsmall]
  exact (mem_implList _ _ _ hwf n).mpr hn

/-- **What the cap drops.** A claimed packet number missing from the
output is smaller than every number in the output: above the cap flare
keeps the `cap` newest claimed numbers and drops the rest. -/
theorem expand_drops_oldest (cap largest first : Nat) (ranges : List (Nat × Nat)) (hcap : 0 < cap)
    (hwf : WellFormed largest first ranges) (n : Nat)
    (hn : Claimed largest first ranges n) (hmiss : n ∉ expand cap largest first ranges) :
    ∀ m ∈ expand cap largest first ranges, n < m := by
  rw [expand_eq_take cap _ _ _ hcap] at hmiss ⊢
  have hmem := (mem_implList _ _ _ hwf n).mpr hn
  rw [← List.take_append_drop cap (implList largest first ranges)] at hmem
  have hpw := implList_pairwise largest first ranges
  rw [← List.take_append_drop cap (implList largest first ranges)] at hpw
  have hd : n ∈ (implList largest first ranges).drop cap := by
    rcases List.mem_append.mp hmem with h | h
    · exact absurd h hmiss
    · exact h
  intro m hm
  exact (List.pairwise_append.mp hpw).2.2 m hm n hd

/-- The number of claimed packets in a well-formed ACK equals the length
of `implList`, and flare retires `min cap` of them. -/
theorem expand_length (cap largest first : Nat) (ranges : List (Nat × Nat)) (hcap : 0 < cap) :
    (expand cap largest first ranges).length = min cap (implList largest first ranges).length := by
  rw [expand_eq_take cap _ _ _ hcap, List.length_take]

end Flare.L3.Quic.AckExpand
