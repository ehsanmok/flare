/-!
# Buffer-ring receive ledger (http/_bufring_ledger.mojo, issue #37)

The io_uring buffer-ring server loop registers `ringSize` provided buffers.
For each receive the kernel takes one out of the ring and reports its id in
a completion carrying `IORING_CQE_F_BUFFER`. The loop must give that buffer
back exactly once, whatever it then does with the completion: stage the
bytes, drop a completion for a connection that is already gone, or close the
connection on error or EOF. If a single path forgets, the ring drains for
good and every later receive fails with `-ENOBUFS`. Issue #37 was the drop
path forgetting.

The loop asks `classify_recv` for every receive completion; `BufLedger`
counts the buffers so a trace of kernel fills and loop completions can be
checked.

Theorems:
* `classify_ok`: every decision meets `RecvOk`. It returns the buffer
  exactly when the completion took one, drops exactly the completions of
  dead connections, and stages exactly data that arrived in a buffer for a
  live connection.
* `run_conserved`: from a full ring, every valid trace keeps
  `inRing + inCq = ringSize`, so no buffer is lost or returned twice.
* `run_inRing_le`, `run_drained`: the ring never holds more than
  `ringSize`, and it is full again once every held completion is processed.
-/
namespace Flare.Kernels.BufLedger

inductive Action where
  | stage | drop | close
  deriving DecidableEq, Repr

structure Decision where
  action : Action
  returnBuf : Bool
  deriving DecidableEq, Repr

/-- [spec] What the loop must do with a receive completion for a connection
that is `live` (still in its table), with result `res` (bytes, 0 on EOF,
`-errno`), carrying a provided buffer iff `hasBuf`. The buffer goes back
exactly when the completion took one. Only completions of dead connections
are dropped. Only bytes that arrived in a buffer for a live connection are
staged. Everything else closes the connection. -/
def RecvOk (live : Bool) (res : Int) (hasBuf : Bool) (d : Decision) : Prop :=
  d.returnBuf = hasBuf ∧
  (d.action = .drop ↔ live = false) ∧
  (d.action = .stage ↔ (live = true ∧ 0 < res ∧ hasBuf = true))

/-- mirrors flare/http/_bufring_ledger.mojo#classify_recv+RecvDecision+RECV_STAGE+RECV_DROP+RECV_CLOSE sha=c23df4589e00 at=ea1b9282 -/
def classify (live : Bool) (res : Int) (hasBuf : Bool) : Decision :=
  if live = false then ⟨.drop, hasBuf⟩
  else if res ≤ 0 ∨ hasBuf = false then ⟨.close, hasBuf⟩
  else ⟨.stage, hasBuf⟩

/-- mirrors flare/http/_bufring_ledger.mojo#BufLedger sha=0a67045fc0a0 at=ea1b9282 -/
structure Ledger where
  ringSize : Nat
  inRing : Nat
  inCq : Nat
  enobufs : Nat
  deriving DecidableEq, Repr

/-- mirrors flare/http/_bufring_ledger.mojo#BufLedger.__init__ sha=d1c46c5e9a52 at=ea1b9282 -/
def Ledger.init (n : Nat) : Ledger := ⟨n, n, 0, 0⟩

/-- mirrors flare/http/_bufring_ledger.mojo#BufLedger.on_fill sha=e6d27b605276 at=ea1b9282 -/
def Ledger.onFill (s : Ledger) : Ledger × Bool :=
  if s.inRing = 0 then ({ s with enobufs := s.enobufs + 1 }, false)
  else ({ s with inRing := s.inRing - 1, inCq := s.inCq + 1 }, true)

/-- mirrors flare/http/_bufring_ledger.mojo#BufLedger.on_complete sha=e5046e6d348a at=ea1b9282 -/
def Ledger.onComplete (s : Ledger) (live : Bool) (res : Int) (hasBuf : Bool) :
    Ledger × Decision :=
  let d := classify live res hasBuf
  let s1 := if hasBuf then { s with inCq := s.inCq - 1 } else s
  let s2 := if d.returnBuf then { s1 with inRing := s1.inRing + 1 } else s1
  (s2, d)

/-- [spec] Every provided buffer is either in the ring or held by exactly one
completion the loop has not processed yet. -/
def Conserved (s : Ledger) : Prop := s.inRing + s.inCq = s.ringSize

instance (l : Bool) (r : Int) (h : Bool) (d : Decision) : Decidable (RecvOk l r h d) := by
  unfold RecvOk; infer_instance

instance (s : Ledger) : Decidable (Conserved s) := by unfold Conserved; infer_instance

inductive Event where
  | fill
  | complete (live : Bool) (res : Int) (hasBuf : Bool)
  deriving DecidableEq, Repr

/-- The kernel only hands the loop a buffer-carrying completion for a buffer
it took out of the ring. -/
def Enabled (s : Ledger) : Event → Prop
  | .fill => True
  | .complete _ _ hasBuf => hasBuf = true → 0 < s.inCq

def step (s : Ledger) : Event → Ledger
  | .fill => s.onFill.1
  | .complete l r h => (s.onComplete l r h).1

def run (s : Ledger) : List Event → Ledger
  | [] => s
  | e :: es => run (step s e) es

def Valid (s : Ledger) : List Event → Prop
  | [] => True
  | e :: es => Enabled s e ∧ Valid (step s e) es

theorem classify_returnBuf (l : Bool) (r : Int) (h : Bool) :
    (classify l r h).returnBuf = h := by
  unfold classify; split
  · rfl
  · split <;> rfl

theorem classify_ok (l : Bool) (r : Int) (h : Bool) : RecvOk l r h (classify l r h) := by
  unfold RecvOk classify
  cases l <;> cases h <;> simp
  by_cases hr : r ≤ 0 <;> simp [hr] <;> omega

theorem step_conserved (s : Ledger) (e : Event) (hc : Conserved s) (he : Enabled s e) :
    Conserved (step s e) := by
  unfold Conserved at *
  cases e with
  | fill =>
    simp only [step, Ledger.onFill]
    split <;> simp_all <;> omega
  | complete l r h =>
    simp only [step, Ledger.onComplete, classify_returnBuf]
    cases h <;> simp_all [Enabled] <;> omega

theorem run_conserved_from (s : Ledger) (es : List Event) (hc : Conserved s)
    (hv : Valid s es) : Conserved (run s es) := by
  induction es generalizing s with
  | nil => exact hc
  | cons e es ih => exact ih _ (step_conserved s e hc hv.1) hv.2

theorem step_ringSize (s : Ledger) (e : Event) : (step s e).ringSize = s.ringSize := by
  cases e with
  | fill => simp only [step, Ledger.onFill]; split <;> rfl
  | complete l r h =>
    simp only [step, Ledger.onComplete]; cases h <;> cases (classify l r _).returnBuf <;> rfl

theorem run_ringSize (s : Ledger) (es : List Event) : (run s es).ringSize = s.ringSize := by
  induction es generalizing s with
  | nil => rfl
  | cons e es ih => simp only [run]; rw [ih, step_ringSize]

theorem run_conserved (n : Nat) (es : List Event) (hv : Valid (Ledger.init n) es) :
    (run (Ledger.init n) es).inRing + (run (Ledger.init n) es).inCq = n := by
  have h := run_conserved_from _ es (by simp [Conserved, Ledger.init]) hv
  unfold Conserved at h; rw [run_ringSize] at h; exact h

theorem run_inRing_le (n : Nat) (es : List Event) (hv : Valid (Ledger.init n) es) :
    (run (Ledger.init n) es).inRing ≤ n := by
  have := run_conserved n es hv; omega

theorem run_drained (n : Nat) (es : List Event) (hv : Valid (Ledger.init n) es)
    (h0 : (run (Ledger.init n) es).inCq = 0) : (run (Ledger.init n) es).inRing = n := by
  have := run_conserved n es hv; omega

/-! ## Before the fix (issue #37, `_server_reactor_uring.mojo` @ 6e32b279^)

The loop returned the buffer only after staging bytes; a stale completion
(connection already gone) and an error or EOF completion kept theirs. -/

end Flare.Kernels.BufLedger
