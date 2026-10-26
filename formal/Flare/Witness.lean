import Flare.Core
import Flare.L1_Encoding
import Flare.L2_Machine
import Flare.L4_App

/-!
# Witnesses: the hypotheses of the headline theorems can hold

A theorem under hypotheses that no environment satisfies is vacuously true,
and `lake build` cannot tell. Every environment contract and parameter bundle
that a headline theorem takes as a hypothesis gets a concrete instance here,
so each of those theorems says something about at least one model.

A witness shows only that the hypotheses are consistent. Whether the real
libc, kernel or framer satisfies them is the trust base (`Flare/Core/Assumptions.lean`)
or a separate refinement.
-/
namespace Flare.Witness

open Flare.Assumptions

/-! ## Environment contracts (`Flare/Core/Assumptions.lean`) -/

theorem recvContract_sat (cap : Nat) : RecvContract cap cap := by
  unfold RecvContract; omega

theorem sendContractStrong_sat (len : Nat) (h : 0 < len) : SendContractStrong len len := by
  unfold SendContractStrong; omega

theorem monotoneClock_sat (n : Nat) : MonotoneClock (List.range n) :=
  (List.pairwise_lt_range (n := n)).imp Nat.le_of_lt

/-- An oracle that writes everything it is offered obeys the strong send
contract (`writeAll_terminates_strong`, `writevAll_strong`), and the same
oracle obeys the receive contract (`readExact_terminates`). -/
def fullOracle : Nat → Nat → Int := fun _ len => len

theorem fullOracle_strong : L2.WriteLoop.Strong fullOracle := by
  intro _ len h; unfold SendContractStrong fullOracle; omega

theorem fullOracle_recv : ∀ k len, 0 < len → RecvContract len (fullOracle k len) := by
  intro _ len _; unfold RecvContract fullOracle; omega

/-! ## HTTP/1.1 connection: framing oracle and fair scheduling

`MachineHttp.server_*` and the `ConnSM` theorems assume `Oracle.WF`, and
`ConnLive.eventually_served` adds `Oracle.Ext` and `Fair`. `fixedParams`
frames every request as its first `k` bytes; for `k > 0` requests do
complete, so the conclusions are not about a framer that never dispatches. -/

section ConnSM
open L4.ConnSM

def fixedFrame (k : Nat) (b : Bytes) : Frame Unit :=
  if 0 < k ∧ k ≤ b.length then .complete () k else .needMore

def fixedParams (k : Nat) : Params Unit where
  frame := fixedFrame k
  hasBuf b := decide (0 < k ∧ k ≤ b.length)
  ser _ := []
  closeAfter _ := false
  wsMismatch _ := false
  handlerOk _ := true
  maxKA := 100
  keepAlive := true
  cap := 8192

theorem fixedParams_wf (k : Nat) : Oracle.WF (fixedParams k) where
  complete_le b r n h := by
    simp only [fixedParams, fixedFrame] at h
    split at h <;> simp_all
  complete_self b r n h := by
    simp only [fixedParams, fixedFrame] at h ⊢
    split at h
    · cases h; rw [if_pos (by simp; omega)]
    · cases h
  complete_buf b r n h := by
    simp only [fixedParams, fixedFrame] at h ⊢
    split at h
    · simpa using ‹_›
    · cases h

theorem fixedParams_ext (k : Nat) : L4.ConnLive.Oracle.Ext (fixedParams k) := by
  intro b c r n h
  simp only [fixedParams, fixedFrame] at h ⊢
  split at h
  · cases h; rw [if_pos (by simp; omega)]
  · cases h

theorem fixedParams_completes (k : Nat) (b : Bytes) (h0 : 0 < k) (hk : k ≤ b.length) :
    (fixedParams k).frame b = .complete () k := by
  simp [fixedParams, fixedFrame, h0, hk]

/-- Readable and writable readiness, alternating forever. -/
def alternating (n : Nat) : Ev :=
  if n % 2 = 0 then .readable false else .writable 1

theorem alternating_fair {Req : Type} (P : Params Req) (s0 : St Req) :
    L4.ConnLive.Fair P s0 alternating where
  read n _ _ _ := by
    refine ⟨if n % 2 = 0 then n else n + 1, ?_, ?_⟩
    · split <;> omega
    · refine Or.inr (Or.inr ⟨false, ?_⟩)
      unfold alternating; split <;> simp_all <;> omega
  write n _ _ := by
    refine ⟨if n % 2 = 0 then n + 1 else n, ?_, ?_⟩
    · split <;> omega
    · refine Or.inr (Or.inr ⟨1, by decide, ?_⟩)
      unfold alternating; split <;> simp_all <;> omega

end ConnSM

/-! ## Retry policy -/

/-- A policy with a 100 ms initial backoff, doubling to a 2 s cap (flare's
default multiplier and cap) is sane. -/
theorem retry_sane : L4.Retry.Sane ⟨3, true, 100, 2, 2000⟩ where
  init_pos := by decide
  mult_ge := by decide
  max_pos := by decide
  max_mul := by decide
  init_mul := by decide

/-! ## `inet_pton` / `inet_ntop` (`Address.InetEnv.Valid`)

A toy environment that prints each address byte as eight `0`/`1` digits,
after a `.` (IPv4) or a `:` (IPv6) that also tells the two families apart. -/

section Inet
open L1.Address

def bitDigit (n i : Nat) : UInt8 := if n / 2 ^ i % 2 = 1 then 49 else 48
def digitVal (c : UInt8) : Nat := if c = 49 then 1 else 0

def enc8 (x : UInt8) : Bytes :=
  [7, 6, 5, 4, 3, 2, 1, 0].map (bitDigit x.toNat)

def decBits : Bytes → Bytes
  | a7 :: a6 :: a5 :: a4 :: a3 :: a2 :: a1 :: a0 :: t =>
    UInt8.ofNat (digitVal a7 * 128 + digitVal a6 * 64 + digitVal a5 * 32 + digitVal a4 * 16 +
      digitVal a3 * 8 + digitVal a2 * 4 + digitVal a1 * 2 + digitVal a0) :: decBits t
  | _ => []

set_option maxRecDepth 8000 in
theorem bits_sum : ∀ n, n < 256 →
    digitVal (bitDigit n 7) * 128 + digitVal (bitDigit n 6) * 64 + digitVal (bitDigit n 5) * 32 +
      digitVal (bitDigit n 4) * 16 + digitVal (bitDigit n 3) * 8 + digitVal (bitDigit n 2) * 4 +
      digitVal (bitDigit n 1) * 2 + digitVal (bitDigit n 0) = n := by
  decide

theorem decBits_enc (x : Bytes) : decBits (x.flatMap enc8) = x := by
  induction x with
  | nil => rfl
  | cons a t ih =>
    simp only [List.flatMap_cons, enc8, List.map_cons, List.map_nil, List.cons_append,
      List.nil_append, decBits, ih, bits_sum a.toNat a.toNat_lt, UInt8.ofNat_toNat]

theorem bitDigit_mem (n i : Nat) : bitDigit n i = 48 ∨ bitDigit n i = 49 := by
  unfold bitDigit; split <;> simp

theorem enc8_digits (x : Bytes) : ∀ c ∈ x.flatMap enc8, c = 48 ∨ c = 49 := by
  intro c hc
  simp only [List.mem_flatMap, enc8, List.mem_map] at hc
  obtain ⟨_, _, i, _, rfl⟩ := hc
  exact bitDigit_mem _ i

def toyInet : InetEnv where
  pton4 | 46 :: t => some (decBits t) | _ => none
  ntop4 x := 46 :: x.flatMap enc8
  pton6 | 58 :: t => some (decBits t) | _ => none
  ntop6 x := 58 :: x.flatMap enc8

theorem toyInet_valid : toyInet.Valid where
  pton4_ntop4 x _ := by simp [toyInet, decBits_enc]
  ntop4_ne x := by simp [toyInet]
  ntop4_chars x c hc := by
    simp only [toyInet, List.mem_cons] at hc
    rcases hc with rfl | hc
    · exact Or.inr (by decide)
    · rcases enc8_digits x c hc with rfl | rfl <;> exact Or.inl (by decide)
  pton6_ntop6 x _ := by simp [toyInet, decBits_enc]
  pton4_ntop6 x := by simp [toyInet]
  ntop6_ne x := by simp [toyInet]
  ntop6_chars x c hc := by
    simp only [toyInet, List.mem_cons] at hc
    rcases hc with rfl | hc
    · exact Or.inr (Or.inl (by decide))
    · rcases enc8_digits x c hc with rfl | rfl <;> exact Or.inl (by decide)

end Inet

end Flare.Witness
