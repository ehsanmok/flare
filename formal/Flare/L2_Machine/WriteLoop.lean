import Flare.Core

/-!
# Write / read loops over a kernel oracle

`TcpStream.write_all`, `UnixStream.write_all`, `TcpStream.read_exact` and
`writev_buf_all` are loops around one syscall each. The kernel is an
oracle `o k len : Int`: the result of the `k`-th call when `len` bytes
are offered. A result `< 0` stands for a non-EINTR error (EINTR is
retried inside `write`/`read`, which only re-asks the oracle), so it
raises. Contracts come from `Flare.Assumptions`.

Each loop is run with explicit fuel; `outOfFuel` after any amount of fuel
means the loop does not terminate.
-/
namespace Flare.L2.WriteLoop
open Flare.Assumptions

/-- Outcome of a byte loop. -/
inductive Res where
  | done (n : Nat)
  | err
  | outOfFuel (n : Nat)
  deriving DecidableEq, Repr

/-- One `TcpStream.write`: `send` result `r`; `r > 0` and `r = 0` are both
returned, `r < 0` raises (EINTR retry is absorbed into the oracle).
mirrors flare/tcp/stream.mojo:458-495 @59bda50 -/
def write (r : Int) : Option Nat := if r < 0 then none else some r.toNat

/-- `TcpStream.write_all`: `while sent < total: sent += write(...)`.
mirrors flare/tcp/stream.mojo:497-519 @59bda50 -/
def writeAll (total : Nat) (o : Nat → Nat → Int) : Nat → Nat → Nat → Res
  | 0, _, sent => if sent < total then .outOfFuel sent else .done sent
  | fuel + 1, k, sent =>
    if sent < total then
      match write (o k (total - sent)) with
      | none => .err
      | some n => writeAll total o fuel (k + 1) (sent + n)
    else .done sent

/-- `UnixStream.write_all` decrements `remaining` instead of incrementing
`sent`; `write` returns `sent >= 0` and raises otherwise, so the loop is
`writeAll` up to the change of variable `remaining = total - sent`.
mirrors flare/uds/stream.mojo:140-163 @59bda50 -/
def udsWriteAll (total : Nat) (o : Nat → Nat → Int) : Nat → Nat → Nat → Res
  | 0, _, rem => if rem > 0 then .outOfFuel (total - rem) else .done (total - rem)
  | fuel + 1, k, rem =>
    if rem > 0 then
      let r := o k rem
      if r < 0 then .err else udsWriteAll total o fuel (k + 1) (rem - r.toNat)
    else .done (total - rem)

/-- The oracle obeys the strong send contract on every non-empty call. -/
def Strong (o : Nat → Nat → Int) : Prop := ∀ k len, 0 < len → SendContractStrong len (o k len)
/-- The oracle obeys the POSIX (weak) send contract. -/
def Weak (o : Nat → Nat → Int) : Prop := ∀ k len, 0 < len → SendContract len (o k len)

/-- Termination + exactness under the strong contract: with fuel at least
`total - sent`, `write_all` either sends exactly `total` bytes or raises.
Measure: `total - sent` strictly decreases. -/
theorem writeAll_terminates_strong (total : Nat) (o : Nat → Nat → Int) (h : Strong o) :
    ∀ fuel k sent, sent ≤ total → total - sent ≤ fuel →
      writeAll total o fuel k sent = .done total ∨ writeAll total o fuel k sent = .err := by
  intro fuel
  induction fuel with
  | zero =>
    intro k sent hs hf
    have : ¬ sent < total := by omega
    left; simp [writeAll, this]; omega
  | succ f ih =>
    intro k sent hs hf
    simp only [writeAll]
    by_cases hlt : sent < total
    · rw [if_pos hlt]
      have hc := h k (total - sent) (by omega)
      unfold SendContractStrong at hc
      rcases hc with hneg | ⟨h1, h2⟩
      · right; simp [write, hneg]
      · have : ¬ o k (total - sent) < 0 := by omega
        simp only [write, this, if_false]
        exact ih (k + 1) _ (by omega) (by omega)
    · rw [if_neg hlt]; left; congr; omega

/-- `write_all` never overshoots: whatever it returns, `sent ≤ total`
under the weak contract (it may loop, but never counts phantom bytes). -/
theorem writeAll_no_overshoot (total : Nat) (o : Nat → Nat → Int) (h : Weak o) :
    ∀ fuel k sent n, sent ≤ total →
      (writeAll total o fuel k sent = .done n ∨ writeAll total o fuel k sent = .outOfFuel n) →
      n ≤ total := by
  intro fuel
  induction fuel with
  | zero =>
    intro k sent n hs hr
    simp only [writeAll] at hr
    split at hr <;> simp at hr <;> omega
  | succ f ih =>
    intro k sent n hs hr
    simp only [writeAll] at hr
    by_cases hlt : sent < total
    · rw [if_pos hlt] at hr
      have hc := h k (total - sent) (by omega)
      unfold SendContract at hc
      rcases hc with hneg | ⟨h1, h2⟩
      · simp [write, hneg] at hr
      · have : ¬ o k (total - sent) < 0 := by omega
        simp only [write, this, if_false] at hr
        exact ih (k + 1) _ n (by omega) hr
    · rw [if_neg hlt] at hr; simp at hr; omega

/-- The UDS loop agrees with the TCP loop (change of variable). -/
theorem udsWriteAll_eq (total : Nat) (o : Nat → Nat → Int) (h : Weak o) :
    ∀ fuel k sent, sent ≤ total →
      udsWriteAll total o fuel k (total - sent) = writeAll total o fuel k sent := by
  intro fuel
  induction fuel with
  | zero =>
    intro k sent hs
    simp only [udsWriteAll, writeAll]
    by_cases hlt : sent < total
    · rw [if_pos (by omega), if_pos hlt]; congr 1; omega
    · rw [if_neg (by omega), if_neg hlt]; congr 1; omega
  | succ f ih =>
    intro k sent hs
    simp only [udsWriteAll, writeAll]
    by_cases hlt : sent < total
    · rw [if_pos (by omega), if_pos hlt]
      have hc := h k (total - sent) (by omega)
      unfold SendContract at hc
      rcases hc with hneg | ⟨h1, h2⟩
      · simp [write, hneg]
      · have hn : ¬ o k (total - sent) < 0 := by omega
        simp only [write, hn, if_false]
        have := ih (k + 1) (sent + (o k (total - sent)).toNat) (by omega)
        rw [← this]; congr 1; omega
    · rw [if_neg (by omega), if_neg hlt]; congr 1; omega

/-- The constant-zero oracle: POSIX-legal, never makes progress. -/
def zeroOracle : Nat → Nat → Int := fun _ _ => 0

theorem zeroOracle_weak : Weak zeroOracle := by
  intro k len _; unfold SendContract zeroOracle; omega

/-- **Non-termination under the weak contract**: for every fuel the loop
is still running with nothing sent (the state `sent = 0` repeats). -/
theorem writeAll_livelock_weak (total : Nat) (htot : 0 < total) :
    ∀ fuel k, writeAll total zeroOracle fuel k 0 = .outOfFuel 0 := by
  intro fuel
  induction fuel with
  | zero => intro k; simp [writeAll, htot]
  | succ f ih =>
    intro k
    simp only [writeAll, if_pos htot, zeroOracle, write]
    simpa using ih (k + 1)

/-- Fixed `write_all`: treat a 0 return for a non-empty chunk as an error.
mirrors flare/tcp/stream.mojo:497-519 @59bda50 (with the minimal fix) -/
def writeAllFixed (total : Nat) (o : Nat → Nat → Int) : Nat → Nat → Nat → Res
  | 0, _, sent => if sent < total then .outOfFuel sent else .done sent
  | fuel + 1, k, sent =>
    if sent < total then
      match write (o k (total - sent)) with
      | none => .err
      | some 0 => .err
      | some n => writeAllFixed total o fuel (k + 1) (sent + n)
    else .done sent

/-- The fixed loop terminates under the *weak* contract. -/
theorem writeAllFixed_terminates_weak (total : Nat) (o : Nat → Nat → Int) (h : Weak o) :
    ∀ fuel k sent, sent ≤ total → total - sent ≤ fuel →
      writeAllFixed total o fuel k sent = .done total ∨
      writeAllFixed total o fuel k sent = .err := by
  intro fuel
  induction fuel with
  | zero =>
    intro k sent hs hf
    have : ¬ sent < total := by omega
    left; simp [writeAllFixed, this]; omega
  | succ f ih =>
    intro k sent hs hf
    simp only [writeAllFixed]
    by_cases hlt : sent < total
    · rw [if_pos hlt]
      have hc := h k (total - sent) (by omega)
      unfold SendContract at hc
      rcases hc with hneg | ⟨h1, h2⟩
      · right; simp [write, hneg]
      · have hn : ¬ o k (total - sent) < 0 := by omega
        simp only [write, hn, if_false]
        by_cases h0 : o k (total - sent) = 0
        · right; simp [h0]
        · have hpos : (o k (total - sent)).toNat ≠ 0 := by omega
          obtain ⟨m, hm⟩ : ∃ m, (o k (total - sent)).toNat = m + 1 :=
            ⟨_, (Nat.succ_pred_eq_of_ne_zero hpos).symm⟩
          rw [hm]
          exact ih (k + 1) _ (by omega) (by omega)
    · rw [if_neg hlt]; left; congr; omega

/-! ## read_exact -/

/-- `TcpStream.read_exact`: `n = read(...)`; `n = 0` raises (EOF),
`n < 0` raises, else `received += n`.
mirrors flare/tcp/stream.mojo:429-456 @59bda50 -/
def readExact (size : Nat) (o : Nat → Nat → Int) : Nat → Nat → Nat → Res
  | 0, _, rcv => if rcv < size then .outOfFuel rcv else .done rcv
  | fuel + 1, k, rcv =>
    if rcv < size then
      let r := o k (size - rcv)
      if r ≤ 0 then .err else readExact size o fuel (k + 1) (rcv + r.toNat)
    else .done rcv

/-- Termination with `received = size` (or a raise) under `RecvContract`;
`received` strictly increases on every iteration. -/
theorem readExact_terminates (size : Nat) (o : Nat → Nat → Int)
    (h : ∀ k len, 0 < len → RecvContract len (o k len)) :
    ∀ fuel k rcv, rcv ≤ size → size - rcv ≤ fuel →
      readExact size o fuel k rcv = .done size ∨ readExact size o fuel k rcv = .err := by
  intro fuel
  induction fuel with
  | zero =>
    intro k rcv hs hf
    have : ¬ rcv < size := by omega
    left; simp [readExact, this]; omega
  | succ f ih =>
    intro k rcv hs hf
    simp only [readExact]
    by_cases hlt : rcv < size
    · rw [if_pos hlt]
      by_cases hle : o k (size - rcv) ≤ 0
      · right; simp [hle]
      · simp only [hle, if_false]
        have hc := h k (size - rcv) (by omega)
        unfold RecvContract at hc
        exact ih (k + 1) _ (by omega) (by omega)
    · rw [if_neg hlt]; left; congr; omega

/-! ## writev_buf_all -/

/-- Consume `c` bytes from the cells `rest` (lengths from `first` on).
Returns the number of cells fully consumed and the new remaining cells
(the first one possibly shortened). Mirrors the inner `while consumed > 0
and i < n` loop.
mirrors flare/runtime/iovec.mojo:344-361 @59bda50 -/
def consume : Nat → List Nat → Nat × List Nat
  | _, [] => (0, [])
  | 0, rest => (0, rest)
  | c + 1, l :: ls =>
    if l ≤ c + 1 then
      let r := consume (c + 1 - l) ls
      (r.1 + 1, r.2)
    else (0, (l - (c + 1)) :: ls)

def sum : List Nat → Nat
  | [] => 0
  | x :: xs => x + sum xs

theorem consume_sum : ∀ (rest : List Nat) (c : Nat), c ≤ sum rest →
    sum (consume c rest).2 = sum rest - c := by
  intro rest
  induction rest with
  | nil => intro c h; simp [consume, sum]
  | cons l ls ih =>
    intro c h
    cases c with
    | zero => simp [consume]
    | succ c =>
      simp only [consume]
      by_cases hl : l ≤ c + 1
      · rw [if_pos hl]; simp only [sum] at h ⊢
        rw [ih _ (by omega)]; omega
      · rw [if_neg hl]; simp only [sum] at h ⊢; omega

/-- Cells are only ever dropped from the front: `first` advances by
`(consume ..).1` and `first + |rest|` is invariant. -/
theorem consume_length : ∀ (rest : List Nat) (c : Nat),
    (consume c rest).1 + (consume c rest).2.length = rest.length := by
  intro rest
  induction rest with
  | nil => intro c; simp [consume]
  | cons l ls ih =>
    intro c
    cases c with
    | zero => simp [consume]
    | succ c =>
      simp only [consume]
      by_cases hl : l ≤ c + 1
      · rw [if_pos hl]; simp only [List.length_cons]; have := ih (c + 1 - l); omega
      · rw [if_neg hl]; simp

/-- Loop state of `writev_buf_all`. -/
structure VState where
  first : Nat
  rest : List Nat
  remaining : Int
  deriving DecidableEq, Repr

/-- `writev_buf_all`: `sent = writev(...)`; `sent <= 0` → **return**
(silently); else `remaining -= sent` and advance through the cells.
`writev_buf` itself raises on `-1`, so the oracle's `< 0` is `err`.
mirrors flare/runtime/iovec.mojo:312-361 @59bda50 -/
def writevAll (o : Nat → Nat → Int) : Nat → Nat → VState → Res × VState
  | 0, _, s => (if s.remaining > 0 then .outOfFuel 0 else .done 0, s)
  | fuel + 1, k, s =>
    if s.remaining > 0 then
      let r := o k (sum s.rest)
      if r < 0 then (.err, s)
      else if r = 0 then (.done 0, s)
      else
        let c := consume r.toNat s.rest
        writevAll o fuel (k + 1)
          { first := s.first + c.1, rest := c.2, remaining := s.remaining - r }
    else (.done 0, s)

/-- Loop invariant: `remaining = Σ_{i ≥ first} len_i` and `first + |rest| = n`. -/
def VInv (n : Nat) (s : VState) : Prop := s.remaining = sum s.rest ∧ s.first + s.rest.length = n

/-- Under the strong contract (for the writev total) and the caller
precondition `total_bytes = Σ len_i`, `writev_buf_all` returns normally
only with every byte written, keeps the invariant, and `first` is
monotone and `≤ n`. -/
theorem writevAll_strong (n : Nat) (o : Nat → Nat → Int) (h : Strong o) :
    ∀ fuel k s, VInv n s → (sum s.rest) ≤ fuel →
      ((writevAll o fuel k s).1 = .err ∨
        ((writevAll o fuel k s).1 = .done 0 ∧ (writevAll o fuel k s).2.remaining = 0)) ∧
      VInv n (writevAll o fuel k s).2 ∧ s.first ≤ (writevAll o fuel k s).2.first := by
  intro fuel
  induction fuel with
  | zero =>
    intro k s hi hf
    obtain ⟨h1, h2⟩ := hi
    have : s.remaining = 0 := by omega
    simp [writevAll, this, VInv, h2]; omega
  | succ f ih =>
    intro k s hi hf
    obtain ⟨h1, h2⟩ := hi
    simp only [writevAll]
    by_cases hp : s.remaining > 0
    · rw [if_pos hp]
      have hc := h k (sum s.rest) (by omega)
      unfold SendContractStrong at hc
      rcases hc with hneg | ⟨c1, c2⟩
      · simp [hneg, VInv, h1, h2]
      · have hn : ¬ o k (sum s.rest) < 0 := by omega
        have hz : ¬ o k (sum s.rest) = 0 := by omega
        simp only [hn, hz, if_false]
        have hs := consume_sum s.rest (o k (sum s.rest)).toNat (by omega)
        have hl := consume_length s.rest (o k (sum s.rest)).toNat
        have := ih (k + 1) ⟨s.first + (consume (o k (sum s.rest)).toNat s.rest).1,
            (consume (o k (sum s.rest)).toNat s.rest).2, s.remaining - o k (sum s.rest)⟩
          ⟨by simp only; omega, by simp only; omega⟩ (by simp only; omega)
        obtain ⟨a, b, c⟩ := this
        exact ⟨a, b, by simp only at c; omega⟩
    · rw [if_neg hp]
      have : s.remaining = 0 := by omega
      simp [this, VInv, h2]; omega

/-- Caller-precondition note: if `total_bytes` understates the cells, the
loop returns normally with bytes still queued (silent truncation). -/
theorem writevAll_understated :
    let s : VState := { first := 0, rest := [4, 4], remaining := 4 }
    writevAll (fun _ len => (len : Int)) 3 0 s = (.done 0, { first := 2, rest := [], remaining := -4 }) := by
  decide

/-- ... and if it overstates them, the loop sees `writev` of zero cells
return 0 and returns silently. -/
theorem writevAll_overstated :
    let s : VState := { first := 0, rest := [4], remaining := 6 }
    writevAll (fun _ len => (len : Int)) 3 0 s = (.done 0, { first := 1, rest := [], remaining := 2 }) := by
  decide

end Flare.L2.WriteLoop
