import Flare.Core
import Flare.L1_Encoding
import Flare.L2_Machine
import Flare.L4_App
import Flare.MachineHttp
import Flare.MachineWorkers

/-!
# Witnesses: the hypotheses of the headline theorems can hold

A theorem under hypotheses that no environment satisfies is vacuously true,
and `lake build` cannot tell. Every environment contract and parameter bundle
that a headline theorem takes as a hypothesis gets a concrete instance here,
so each of those theorems says something about at least one model. Where a
conclusion quantifies over live connections, idle closes or an open breaker,
a concrete trace reaches such a state, so it is not only about the empty
case.

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

/-- No audited theorem assumes `MonotoneClock` (`ServerConfig.closeTime_le`
does, and is not audited); the witness keeps the contract honest anyway. -/
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

/-! ## Other parameter and environment bundles -/

/-- `StatusError.parse_render` holds for a decimal parser that reads every
`dec n`. flare's `atol10` stops at `2^63` (`MojoAtol.atol10_rejects`), so it
does not meet `AtolDec`; `parse_render_mojo` is the statement about it. -/
theorem atolDec_sat : L1.StatusError.AtolDec (fun b => some (L1.Decimal.decVal b : Int)) := by
  intro n; simp [L1.Decimal.decVal_dec]

theorem drawOk_sat : L4.Retry.DrawOk id := by
  intro n h; simp only [id]; omega

theorem rateLimit_sane : L4.RateLimit.Sane 10 100 ⟨0, 0⟩ 1000 := by
  constructor <;> decide

theorem rateLimit_saneFix : L4.RateLimit.SaneFix 10 100 ⟨0, 0⟩ 1000 := by
  constructor <;> decide

theorem recvfromFills_sat (bufLen saLen : Nat) (sa stack : Nat → UInt8) :
    L2.Udp.RecvfromFills bufLen saLen sa stack
      (fun i => if i < min bufLen saLen then sa i else if i < bufLen then 0 else stack i) :=
  fun _ => rfl

theorem connectFacts_sat (p : L2.UdsListener.Peer) : L2.UdsListener.ConnectFacts p .ok := by
  refine ⟨fun h => ?_, fun _ => rfl⟩; cases h

theorem inodesUnique_sat (mine : Nat × Nat) (fs : L2.UdsListener.FS) :
    L2.UdsListener.InodesUnique mine fs (fs = some mine) := Iff.rfl

theorem powMask_sat : L2.IoUring.PowMask 4095 := ⟨12, by decide, by decide⟩

theorem clockBound_sat : L2.TimerWheel.ClockBound [.schedule 5 10, .advance 20] := by
  simp [L2.TimerWheel.ClockBound]

/-- `ServerConfig.default` meets `body_timer_le_request`'s premises. -/
theorem serverConfig_default :
    L4.ServerConfig.check L4.ServerConfig.default ∧ L4.ServerConfig.default.requestTimeoutMs > 0 ∧
      L4.ServerConfig.default.readBodyTimeoutMs > 0 := by decide

/-! ## Reachable states with something to say

`runFn f s0 ls` runs an `LTS.ofFn` step function along `ls`; a state it
returns is reachable. -/

def runFn {S L : Type} (f : S → L → Option S) : S → List L → Option S
  | s, [] => some s
  | s, l :: ls => (f s l).bind (runFn f · ls)

theorem runFn_run {S L : Type} (init : S → Prop) (f : S → L → Option S) :
    ∀ (ls : List L) (s s' : S), runFn f s ls = some s' → (LTS.ofFn init f).Run s ls s'
  | [], s, s', h => by cases h; exact .nil _
  | l :: ls, s, s', h => by
    simp only [runFn] at h
    cases e : f s l with
    | none => rw [e] at h; cases h
    | some s1 => rw [e] at h; exact .cons e (runFn_run init f ls s1 s' h)

theorem runFn_reachable {S L : Type} {init : S → Prop} {f : S → L → Option S} {s0 s : S}
    (h0 : init s0) (ls : List L) (h : runFn f s0 ls = some s) : (LTS.ofFn init f).Reachable s :=
  ⟨s0, ls, h0, runFn_run init f ls s0 s h⟩

/-- Reachable from `s0` along `ls`, and `p` holds there. -/
theorem reach_of {S L : Type} {init : S → Prop} {f : S → L → Option S} {s0 : S} (h0 : init s0)
    (ls : List L) (p : S → Bool) (h : (runFn f s0 ls).map p = some true) :
    ∃ s, (LTS.ofFn init f).Reachable s ∧ p s = true := by
  cases e : runFn f s0 ls with
  | none => rw [e] at h; cases h
  | some s => rw [e] at h; exact ⟨s, runFn_reachable h0 ls e, by simpa using h⟩

section Traces
open Machine

/-- The breaker opens and then admits a half-open probe, so
`cooldown_respected` and `single_probe` are not only about the closed
state. -/
theorem breaker_opens_then_probes :
    ∃ s s', (L4.CircuitBreaker.lts 1 10).Reachable s ∧ (L4.CircuitBreaker.lts 1 10).step s (.arrive 2 10) s' ∧
      s.cell.st = .opn ∧ s'.cell.st = .half := by
  obtain ⟨s, hr, hp⟩ := reach_of (f := L4.CircuitBreaker.step 1 10) (init := (· = L4.CircuitBreaker.initS))
    rfl [.arrive 1 0, .finish 1 0 true]
    (fun s => s.cell.st == .opn && (L4.CircuitBreaker.step 1 10 s (.arrive 2 10)).any (·.cell.st == .half))
    (by decide)
  simp only [Bool.and_eq_true, beq_iff_eq, Option.any_eq_true] at hp
  obtain ⟨ho, s', hs, hh⟩ := hp
  exact ⟨s, s', hr, hs, ho, hh⟩

/-- An idle timer closes a connection under flare's parameters, so the
`∀ k ∈ c.kills` conclusions of `no_stale_timer` and `no_early_close` are
exercised. -/
theorem machine_kills :
    ∃ c, (lts counter flareP).Reachable c ∧ c.kills ≠ [] := by
  obtain ⟨c, hr, hp⟩ := reach_of (f := step counter flareP) (init := (· = initCfg)) rfl
    [.poll 0 [listenerToken], .accept 5 true, .acceptDone, .poll 10 [], .poll 11 []]
    (fun c => !c.kills.isEmpty) (by decide)
  exact ⟨c, hr, by simpa using hp⟩

/-- The HTTP server with `fixedParams 1` reaches a live connection that has
dispatched a request and queued its response, so `server_conns_inv`,
`server_responses_fifo` and `server_ka_bound` hold of a connection that did
something. -/
theorem http_served :
    ∃ c l, (lts (MachineHttp.http (fixedParams 1) 10 10) flareP).Reachable c ∧
      c.conns 5 = some l ∧ l.st.segs ≠ [] ∧ l.st.log ≠ [] := by
  obtain ⟨c, hr, hp⟩ := reach_of (f := step (MachineHttp.http (fixedParams 1) 10 10) flareP)
    (init := (· = initCfg)) rfl
    [.poll 0 [listenerToken], .accept 5 true, .acceptDone, .poll 1 [5], .dispatch (.arrive [7]),
     .poll 2 [5], .dispatch (.readable false)]
    (fun c => (c.conns 5).any (fun l => !l.st.segs.isEmpty && !l.st.log.isEmpty)) (by decide)
  simp only [Option.any_eq_true, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff] at hp
  obtain ⟨l, hl, hs, hg⟩ := hp
  exact ⟨c, l, hr, hl, hs, hg⟩

/-- Two workers each hold a live connection, so `sys_disjoint` is not only
about empty fd tables. -/
theorem workers_both_live :
    ∃ w, (sysLts counter (fun (_ : Fin 2) => flareP)).Reachable w ∧
      ((w 0).conns 5).isSome = true ∧ ((w 1).conns 6).isSome = true := by
  obtain ⟨w, hr, hp⟩ := reach_of (f := sysStep counter (fun (_ : Fin 2) => flareP))
    (init := (· = fun _ => initCfg)) rfl
    [(0, .poll 0 [listenerToken]), (0, .accept 5 true), (0, .acceptDone),
     (1, .poll 0 [listenerToken]), (1, .accept 6 true), (1, .acceptDone)]
    (fun w => ((w 0).conns 5).isSome && ((w 1).conns 6).isSome) (by decide)
  simp only [Bool.and_eq_true] at hp
  exact ⟨w, hr, hp⟩

end Traces

/-- Every premise of `ConnLive.eventually_served` at once: a connection that
has received one byte, with `fixedParams 1` and alternating readiness, has a
whole request available at step 0. -/
theorem eventually_served_premises :
    let P := fixedParams 1
    let s0 := L4.ConnSM.step P L4.ConnSM.init (.arrive [7])
    L4.ConnSM.Oracle.WF P ∧ L4.ConnSM.Inv P s0 ∧ L4.ConnLive.Oracle.Ext P ∧
      L4.ConnLive.Fair P s0 alternating ∧ L4.ConnLive.Avail P () (L4.ConnLive.trace P s0 alternating 0) :=
  ⟨fixedParams_wf 1,
   L4.ConnSM.inv_step _ (fixedParams_wf 1) _ _ (L4.ConnSM.inv_init _),
   fixedParams_ext 1, alternating_fair _ _, by decide, by decide, 1, by decide⟩

end Flare.Witness
