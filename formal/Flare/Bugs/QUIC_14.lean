import Flare.L3_Protocol.Quic.AckGen

/-!
# QUIC-14: ACK ranges forget dropped packets, which are then re-accepted

Status: resolved. `_ack_record` now stores a floor (one above the highest
dropped number) in an odd trailing slot of the flat list and `_ack_contains`
treats every number below it as seen (flare/quic/_server_support.mojo
`_ack_floor`, `_ack_record`, `_ack_contains`). The counterexample below is about
the pre-fix `containsOld`; `AckGen.contains` / `recordSt` are the shipped code.

Pre-fix behaviour (flare/quic/_server_support.mojo:60-124 @59bda50): `_ack_record` keeps the 32
highest merged ranges and drops the rest; `_ack_contains` treats a number
below every stored range as already seen only while the list is full
(`len(flat) >= 2 * _ACK_MAX_RANGES`). Once a later packet fills a gap and two
ranges merge, the list holds 31 ranges, the guard is off, and a packet
number from a dropped range reads as unseen. flare/quic/server.mojo:844
then dispatches it a second time (the client at client.mojo:868-895 shares
the helpers).

Spec clause: RFC 9000 §13.2.3: "A receiver MUST retain an ACK Range unless
it can ensure that it will not subsequently accept packets with numbers in
that range"; §12.3: a duplicate packet MUST NOT be processed again
(packet numbers are never reused within a space).

Counterexample: receive 0, 2, 4, ..., 64 (33 ranges, so [0,0] is dropped),
then 3 (merges [2,2], [3,3] and [4,4]): `contains 0 = false`.

Fix: keep a floor, one above the highest number ever dropped, and treat
anything below it as seen (`recordSt`, `contains`).
Repro: formal/repro/QUIC-14_ack_ranges_forget_dropped_packets.mojo.
-/
namespace Flare.Bugs.QUIC_14
open Flare.L3.Quic.AckGen

/-- The pre-fix duplicate test: only the stored ranges, plus "below every
range" while the list is full (flare/quic/_server_support.mojo:60-73
@59bda50). -/
def containsOld (flat : Ranges) (pn : Nat) : Bool :=
  flat.any (fun p => decide (p.1 ≤ pn ∧ pn ≤ p.2)) ||
    (decide (cap ≤ flat.length) && flat.all (fun p => decide (pn < p.1)))

/-- The pre-fix 1-RTT receive step on the range list: duplicates dropped,
otherwise recorded (flare/quic/server.mojo:844-855). -/
def step (flat : Ranges) (pn : Nat) : Ranges := if containsOld flat pn then flat else record flat pn

def run (pns : List Nat) : Ranges := pns.foldl step []

def trace : List Nat := (List.range 33).map (2 * ·) ++ [3]

/-- **Counterexample**: packet 0 was received, yet after the trace it reads
as unseen and would be dispatched again. -/
theorem impl_reaccepts : 0 ∈ trace ∧ containsOld (run trace) 0 = false := by
  native_decide

/-! ## Fixed: ranges plus a floor (`AckGen.St`, `contains`, `recordSt`) -/

def stepF (s : St) (pn : Nat) : St := if contains s pn then s else recordSt s pn

def runF (pns : List Nat) : St := pns.foldl stepF {}

theorem fixed_trace : contains (runF trace) 0 = true := by native_decide

def Inv (s : St) (R : List Nat) : Prop := Canon s.flat ∧ ∀ n ∈ R, MemR n s.flat ∨ n < s.floor

theorem contains_of {s : St} {n : Nat} (h : MemR n s.flat ∨ n < s.floor) : contains s n = true := by
  unfold contains
  rcases h with ⟨p, hp, hb⟩ | h
  · simp only [Bool.or_eq_true, List.any_eq_true, decide_eq_true_eq]
    exact .inl ⟨p, hp, hb⟩
  · simp [h]

theorem memR_or_floor_of_contains {s : St} {n : Nat} (h : contains s n = true) :
    MemR n s.flat ∨ n < s.floor := by
  unfold contains at h
  simp only [Bool.or_eq_true, List.any_eq_true, decide_eq_true_eq] at h
  rcases h with ⟨p, hp, hb⟩ | h
  · exact .inl ⟨p, hp, hb⟩
  · exact .inr h

theorem drop_head_max : ∀ (l : Ranges) (q : Nat × Nat) (r : Ranges), Canon l → l = q :: r →
    ∀ x ∈ l, x.2 ≤ q.2 := by
  intro l q r hc he x hx
  subst he
  rcases List.mem_cons.mp hx with rfl | hx
  · exact Nat.le_refl _
  · have := canon_below q r hc x hx
    have := (canon_valid _ hc) q List.mem_cons_self
    omega

theorem recordSt_inv (s : St) (R : List Nat) (pn : Nat) (h : Inv s R) : Inv (recordSt s pn) (pn :: R) := by
  have hv := canon_valid _ h.1
  have hm := merged_inv s.flat pn hv
  refine ⟨record_canon _ _ hv, fun n hn => ?_⟩
  have hin : MemR n (merged s.flat pn) ∨ n < s.floor := by
    rcases List.mem_cons.mp hn with rfl | hn
    · exact .inl ((hm.2 n).mpr (.inr rfl))
    · rcases h.2 n hn with h1 | h1
      · exact .inl ((hm.2 n).mpr (.inl h1))
      · exact .inr h1
  have e := List.take_append_drop cap (merged s.flat pn)
  rcases hin with ⟨p, hp, hb⟩ | hlt
  · rw [← e] at hp
    rcases List.mem_append.mp hp with hp | hp
    · exact .inl ⟨p, hp, hb⟩
    · right
      simp only [recordSt, floorAfter]
      have hcd := canon_drop _ cap hm.1
      generalize hd : (merged s.flat pn).drop cap = d at hp hcd
      cases d with
      | nil => cases hp
      | cons q r =>
        have := drop_head_max (q :: r) q r hcd rfl p hp
        simp only; omega
  · right
    simp only [recordSt, floorAfter]
    split <;> omega

theorem stepF_inv (s : St) (R : List Nat) (pn : Nat) (h : Inv s R) : Inv (stepF s pn) (pn :: R) := by
  unfold stepF
  split
  · rename_i hc
    refine ⟨h.1, fun n hn => ?_⟩
    rcases List.mem_cons.mp hn with rfl | hn
    · exact memR_or_floor_of_contains hc
    · exact h.2 n hn
  · exact recordSt_inv s R pn h

theorem runF_go (pns : List Nat) : ∀ (s : St) (R : List Nat), Inv s R →
    Inv (pns.foldl stepF s) (pns.reverse ++ R) := by
  induction pns with
  | nil => intro s R h; simpa using h
  | cons p ps ih =>
    intro s R h
    have := ih (stepF s p) (p :: R) (stepF_inv s R p h)
    simpa using this

/-- **Fix meets spec**: over any packet trace, every packet number already
received reads as seen, so no packet is processed twice. -/
theorem fixed_never_reaccepts (pns : List Nat) : ∀ n ∈ pns, contains (runF pns) n = true := by
  intro n hn
  have := (runF_go pns {} [] ⟨trivial, fun _ h => by cases h⟩).2 n (by simpa using hn)
  exact contains_of this

/-- The fix only adds the floor: the stored ranges, and so every ACK frame
sent, are unchanged. -/
theorem recordSt_flat (s : St) (pn : Nat) : (recordSt s pn).flat = record s.flat pn := rfl

end Flare.Bugs.QUIC_14
