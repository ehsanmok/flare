/-!
# QUIC loss recovery: `bytes_in_flight` accounting (RFC 9002 §B.2)

RFC 9002 defines `bytes_in_flight` as the sum of the sizes of the
in-flight packets. flare's `LossRecovery` keeps it as a separate counter.
`on_sent` adds to it. `on_ack` / `on_ack_ranges`, `detect_lost` and
`fire_pto` subtract as they retire records (`_retire`).

flare retires a record by clearing its `live` flag and drops the dead
prefix later (`head`, `_compact`). The model's `sent` is the live records
of `sent[head:]` in order; tombstones and compaction do not change it.
`sent` is in packet-number order (packet numbers grow with each
`on_sent`), so the binary searches and early loop exits of `on_ack_ranges`
and `detect_lost` visit exactly the records their predicates select.

The model keeps only the fields that touch the counter: the packet list
(number, send time, size) and the counter, both over `Nat`. Congestion
control, RTT estimation and frame bytes are left out, since none of them
feeds back into the counter. The retire predicates of `on_ack_ranges`
(packet number inside an acknowledged range) and `detect_lost` (packet /
time threshold)
are abstracted to an arbitrary `p : Sent → Bool`, so the results hold for
every such predicate.

Results:
* `inv_onSent`, `inv_onAck`, `inv_detectLost`, `inv_firePto`: every
  operation preserves `bytes_in_flight = Σ sent.size`.
* `retire_noUnderflow`, `firePto_noUnderflow`: under the invariant, no
  `UInt64` subtraction in these loops can underflow.

Assumption: the sum of in-flight sizes stays below 2^64, so `on_sent`'s
`+=` does not wrap. Each record is one UDP datagram, and the congestion
window bounds how many are outstanding.
-/

namespace Flare.L3.Quic.LossRecovery

structure Sent where
  pn : Nat
  time : Nat
  size : Nat
deriving Repr, DecidableEq

structure LR where
  sent : List Sent
  inflight : Nat

def sumSz : List Sent → Nat
  | [] => 0
  | x :: xs => x.size + sumSz xs

theorem sumSz_append (a b : List Sent) : sumSz (a ++ b) = sumSz a + sumSz b := by
  induction a with
  | nil => simp [sumSz]
  | cons x xs ih => simp [sumSz, ih]; omega

def Inv (r : LR) : Prop := r.inflight = sumSz r.sent

/-- mirrors flare/quic/_loss_recovery.mojo#LossRecovery.__init__ sha=20fe0e1c8da6 at=0a183352 -/
def init : LR := ⟨[], 0⟩

theorem inv_init : Inv init := rfl

/-- mirrors flare/quic/_loss_recovery.mojo#LossRecovery.on_sent sha=230a0db3a85a at=0a183352 -/
def onSent (r : LR) (pn now size frameLen : Nat) : LR :=
  let sz := if size > 0 then size else frameLen
  ⟨r.sent ++ [⟨pn, now, sz⟩], r.inflight + sz⟩

theorem inv_onSent (r : LR) (pn now size frameLen : Nat) (h : Inv r) :
    Inv (onSent r pn now size frameLen) := by
  simp only [Inv, onSent, sumSz_append, sumSz] at h ⊢
  omega

/-- The shared retire loop of `on_ack` and `detect_lost`: walk `sent` in
order, subtract the size of each retired record, keep the rest.
mirrors flare/quic/_loss_recovery.mojo#LossRecovery.on_ack_ranges+LossRecovery.detect_lost+LossRecovery._retire sha=eb379c3f0939 at=0a183352 -/
def retireLoop (p : Sent → Bool) : List Sent → Nat → List Sent → Nat × List Sent
  | [], inflight, keep => (inflight, keep)
  | x :: xs, inflight, keep =>
    if p x then retireLoop p xs (inflight - x.size) keep
    else retireLoop p xs inflight (keep ++ [x])

/-- Every subtraction the loop performs has `inflight ≥ size`. -/
def NoUnderflow (p : Sent → Bool) : List Sent → Nat → Prop
  | [], _ => True
  | x :: xs, inflight =>
    if p x then x.size ≤ inflight ∧ NoUnderflow p xs (inflight - x.size)
    else NoUnderflow p xs inflight

theorem retireLoop_inv (p : Sent → Bool) :
    ∀ xs inflight keep, inflight = sumSz keep + sumSz xs →
      (retireLoop p xs inflight keep).1 = sumSz (retireLoop p xs inflight keep).2 := by
  intro xs
  induction xs with
  | nil => intro inflight keep h; simp [retireLoop, sumSz] at h ⊢; omega
  | cons x xs ih =>
    intro inflight keep h
    simp only [retireLoop]
    split
    · exact ih _ _ (by simp [sumSz] at h; omega)
    · exact ih _ _ (by simp [sumSz, sumSz_append] at h ⊢; omega)

theorem retireLoop_noUnderflow (p : Sent → Bool) :
    ∀ xs inflight (keep : List Sent), inflight = sumSz keep + sumSz xs → NoUnderflow p xs inflight := by
  intro xs
  induction xs with
  | nil => intro _ _ _; trivial
  | cons x xs ih =>
    intro inflight keep h
    simp only [NoUnderflow]
    split
    · refine ⟨by simp [sumSz] at h; omega, ih _ keep (by simp [sumSz] at h; omega)⟩
    · exact ih _ (keep ++ [x]) (by simp [sumSz, sumSz_append] at h ⊢; omega)

def retire (p : Sent → Bool) (r : LR) : LR :=
  let res := retireLoop p r.sent r.inflight []
  ⟨res.2, res.1⟩

theorem inv_retire (p : Sent → Bool) (r : LR) (h : Inv r) : Inv (retire p r) :=
  retireLoop_inv p r.sent r.inflight [] (by simp [Inv] at h; simp [sumSz, h])

theorem retire_noUnderflow (p : Sent → Bool) (r : LR) (h : Inv r) :
    NoUnderflow p r.sent r.inflight :=
  retireLoop_noUnderflow p r.sent r.inflight [] (by simp [Inv] at h; simp [sumSz, h])

def inRanges : List Nat → Nat → Bool
  | lo :: hi :: rs, pn => (lo ≤ pn && pn ≤ hi) || inRanges rs pn
  | _, _ => false

/-- `on_ack_ranges`: flat `[lo, hi]` pairs, descending. No ranges or
nothing in flight: no change. The top of the first range is clamped below
`next_pn`; a first range wholly at or past `next_pn` ends the call. Then
every record in `[bottom, top]` inside a range is retired.
mirrors flare/quic/_loss_recovery.mojo#LossRecovery.on_ack_ranges sha=5fe79d3d2d73 at=0a183352 -/
def onAckRanges (r : LR) (ranges : List Nat) (nextPn : Nat) : LR :=
  match ranges with
  | lo0 :: hi0 :: _ =>
    if r.sent.isEmpty then r
    else if hi0 ≥ nextPn ∧ nextPn = 0 then r
    else
      let top := if hi0 ≥ nextPn then nextPn - 1 else hi0
      if top < lo0 then r
      else
        let bottom := ranges.getD (ranges.length - 2) 0
        retire (fun s => bottom ≤ s.pn && s.pn ≤ top && inRanges ranges s.pn) r
  | _ => r

/-- `on_ack`: each acknowledged number as a one-packet range, descending.
mirrors flare/quic/_loss_recovery.mojo#LossRecovery.on_ack sha=8e0188da00cf at=0a183352 -/
def onAck (r : LR) (acked : List Nat) (nextPn : Nat := 2 ^ 64 - 1) : LR :=
  onAckRanges r ((acked.mergeSort (fun a b => decide (b ≤ a))).flatMap (fun x => [x, x])) nextPn

theorem inv_onAckRanges (r : LR) (ranges : List Nat) (nextPn : Nat) (h : Inv r) :
    Inv (onAckRanges r ranges nextPn) := by
  unfold onAckRanges
  split
  · repeat (first | exact h | exact inv_retire _ r h | (simp only []; split) | split)
  · exact h

theorem inv_onAck (r : LR) (acked : List Nat) (h : Inv r) : Inv (onAck r acked) :=
  inv_onAckRanges r _ _ h

theorem inv_onAck_next (r : LR) (acked : List Nat) (nextPn : Nat) (h : Inv r) :
    Inv (onAck r acked nextPn) :=
  inv_onAckRanges r _ _ h

/-- `detect_lost` with its loss predicate abstracted.
mirrors flare/quic/_loss_recovery.mojo#LossRecovery.detect_lost sha=f263c5040ba2 at=0a183352 -/
def detectLost (lost : Sent → Bool) (r : LR) : LR := retire lost r

theorem inv_detectLost (lost : Sent → Bool) (r : LR) (h : Inv r) :
    Inv (detectLost lost r) := inv_retire lost r h

/-- Remove index `i`. mirrors flare/quic/_loss_recovery.mojo#LossRecovery.fire_pto sha=af7a00e7c016 at=0a183352 -/
def removeAt : List Sent → Nat → List Sent
  | [], _ => []
  | _ :: xs, 0 => xs
  | x :: xs, i + 1 => x :: removeAt xs i

def sizeAt : List Sent → Nat → Nat
  | [], _ => 0
  | x :: _, 0 => x.size
  | _ :: xs, i + 1 => sizeAt xs i

theorem sum_removeAt (l : List Sent) (i : Nat) (hi : i < l.length) :
    sumSz (removeAt l i) + sizeAt l i = sumSz l := by
  induction l generalizing i with
  | nil => simp at hi
  | cons x xs ih =>
    cases i with
    | zero => simp [removeAt, sizeAt, sumSz]; omega
    | succ i =>
      simp at hi
      have := ih i (by omega)
      simp [removeAt, sizeAt, sumSz]; omega

/-- `fire_pto` with the oldest-index search (the first live record)
abstracted to any valid index `idx` (or none when `sent` is empty).
mirrors flare/quic/_loss_recovery.mojo#LossRecovery.fire_pto sha=af7a00e7c016 at=0a183352 -/
def firePto (r : LR) (idx : Nat) : LR :=
  if idx < r.sent.length then ⟨removeAt r.sent idx, r.inflight - sizeAt r.sent idx⟩ else r

theorem inv_firePto (r : LR) (idx : Nat) (h : Inv r) : Inv (firePto r idx) := by
  unfold firePto; split
  · rename_i hi
    have := sum_removeAt r.sent idx hi
    simp only [Inv] at h ⊢; omega
  · exact h

theorem firePto_noUnderflow (r : LR) (idx : Nat) (h : Inv r) (hi : idx < r.sent.length) :
    sizeAt r.sent idx ≤ r.inflight := by
  have := sum_removeAt r.sent idx hi
  simp only [Inv] at h; omega

/-- Any operation sequence from `init` keeps the invariant. -/
inductive Op
  | sent (pn now size frameLen : Nat)
  | ack (acked : List Nat) (nextPn : Nat)
  | lost (p : Sent → Bool)
  | pto (idx : Nat)

def Op.apply : Op → LR → LR
  | .sent pn now size fl, r => onSent r pn now size fl
  | .ack a n, r => onAck r a n
  | .lost p, r => detectLost p r
  | .pto i, r => firePto r i

theorem inv_run (ops : List Op) : Inv (ops.foldl (fun r o => o.apply r) init) := by
  suffices ∀ r, Inv r → Inv (ops.foldl (fun r o => o.apply r) r) from this _ inv_init
  induction ops with
  | nil => intro r h; exact h
  | cons o os ih =>
    intro r h
    apply ih
    cases o with
    | sent => exact inv_onSent _ _ _ _ _ h
    | ack => exact inv_onAck_next _ _ _ h
    | lost => exact inv_detectLost _ _ h
    | pto => exact inv_firePto _ _ h

end Flare.L3.Quic.LossRecovery
