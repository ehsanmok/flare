import Flare.L4_App.ConnSM

/-!
# Liveness of the HTTP/1.1 connection machine under fair event delivery

`ConnSM` proves safety. Here: once a whole request is buffered (in
`read_buf` or still in the kernel queue), the machine dispatches exactly
that request and finishes writing its response, or the connection closes
with `should_close` set, provided the reactor keeps delivering the events
the handle waits for.

**Traces.** `trace fix P s0 σ n` is the state after the first `n` events of
an infinite event sequence `σ`, starting from a state satisfying `Inv`.

**Fairness (`Fair`, a hypothesis about the reactor and the kernel).**
* Readability: while the handle is reading and either the kernel has data
  (`kq ≠ []`), a FIN is pending, or `read_buf` already holds a whole
  request, a readable event is eventually delivered (or the handle stops
  reading or is done). The last case is what the reactor does for
  pipelined requests: after a flush, or after the inline cycle cap, it
  drives `on_readable` again when `has_buffered_request()` holds
  (flare/http/_unified_reactor_impl.mojo:220-235, 832-855); that call is a
  `readable` event in this model.
* Writability: while the handle is writing, a writable event with room for
  at least one byte is eventually delivered (or the handle stops writing or
  is done). This is the kernel draining the socket towards a reading peer.

**Framing (`Oracle.Ext`).** A complete request stays complete, with the same
request and length, when more bytes arrive behind it. Any HTTP/1.1 framer
that decides a message from its own bytes has this property.

**Results.**
* `eventually_served`: from any trace position where the handle is reading,
  not done, and `read_buf ++ kq` frames as a complete request `r`, some
  later position is either done, or has dispatched exactly `r` next
  (`segs` gained `r` and nothing else), is back in STATE_READING and has
  written every queued response byte (`wire = flat log`).
* `trace_done_sc`: whenever the connection is done, `should_close` is set.
* `done_reason`: a step that makes the handle done is a timer expiry, an
  I/O error, a peer FIN with no whole request buffered, or the flush of a
  response queued with `should_close` (an error reply: 400/408/413/500, a
  `Connection: close` verdict, the keep-alive cap, `keep_alive=False`, or a
  FIN after a whole request).
-/
namespace Flare.L4.ConnLive

open Flare.L4.ConnSM

variable {Req : Type}

/-- Framing is decided by a prefix: bytes appended behind a complete
request do not change it. -/
def Oracle.Ext (P : Params Req) : Prop :=
  ∀ b c r n, P.frame b = .complete r n → P.frame (b ++ c) = .complete r n

def trace (fix : Bool) (P : Params Req) (s0 : St Req) (σ : Nat → Ev) : Nat → St Req
  | 0 => s0
  | n + 1 => step fix P (trace fix P s0 σ n) (σ n)

/-- Fair delivery of readiness events (see the module doc). -/
structure Fair (fix : Bool) (P : Params Req) (s0 : St Req) (σ : Nat → Ev) : Prop where
  read : ∀ n, (trace fix P s0 σ n).done = false → (trace fix P s0 σ n).phase = .reading →
    ((trace fix P s0 σ n).kq ≠ [] ∨ (trace fix P s0 σ n).kfin = true ∨
      P.hasBuf (trace fix P s0 σ n).rbuf = true) →
    ∃ m, n ≤ m ∧ ((trace fix P s0 σ m).done = true ∨ (trace fix P s0 σ m).phase ≠ .reading ∨
      ∃ late, σ m = .readable late)
  write : ∀ n, (trace fix P s0 σ n).done = false → (trace fix P s0 σ n).phase = .writing →
    ∃ m, n ≤ m ∧ ((trace fix P s0 σ m).done = true ∨ (trace fix P s0 σ m).phase ≠ .writing ∨
      ∃ k, 0 < k ∧ σ m = .writable k)

theorem trace_inv (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (s0 : St Req) (σ : Nat → Ev)
    (h0 : Inv P s0) : ∀ n, Inv P (trace fix P s0 σ n)
  | 0 => h0
  | n + 1 => inv_step fix P hP _ _ (trace_inv fix P hP s0 σ h0 n)

/-! ## Field lemmas for the pieces of `on_readable` -/

theorem dispatch_out (fix : Bool) (P : Params Req) (s : St Req) (r : Req) (n : Nat) :
    (dispatch fix P s r n).phase = .writing ∧ (dispatch fix P s r n).done = s.done ∧
      (dispatch fix P s r n).segs = s.segs ++ [(s.rbuf.take n, r)] := by
  unfold dispatch
  split
  · cases fix <;> simp [finalise]
  · split
    · simp [finalise, applyKA]
    · simp [queueError, applyKA]

theorem parse_done (fix : Bool) (P : Params Req) (late : Bool) (s : St Req) :
    (parse fix P late s).done = s.done := by
  unfold parse
  split
  · rfl
  · split
    · rfl
    · rfl
    · exact (dispatch_out fix P s _ _).2.1

/-- `parse` on a buffer that frames as a complete request `r`: it enters
STATE_WRITING, stays not done, and either dispatches exactly `r` or queues
an error with `should_close`. -/
theorem parse_complete (fix : Bool) (P : Params Req) (late : Bool) (t : St Req) (r : Req)
    (n : Nat) (hf : P.frame t.rbuf = .complete r n) :
    (parse fix P late t).phase = .writing ∧ (parse fix P late t).done = t.done ∧
      ((parse fix P late t).segs.map Prod.snd = t.segs.map Prod.snd ++ [r] ∨
        (parse fix P late t).shouldClose = true) := by
  unfold parse
  split
  · simp [queueError]
  · rw [hf]
    obtain ⟨h1, h2, h3⟩ := dispatch_out fix P t r n
    exact ⟨h1, h2, Or.inl (by simp [h3])⟩

/-! ## Phase A: from a buffered request to STATE_WRITING -/

/-- Reading, not done, with `read_buf ++ kq` framing as request `r`. -/
def Avail (P : Params Req) (r : Req) (s : St Req) : Prop :=
  s.phase = .reading ∧ s.done = false ∧ ∃ n, P.frame (s.rbuf ++ s.kq) = .complete r n

/-- Left the buffered state: done, or writing with `r` dispatched next (or
an error reply queued with `should_close`). -/
def Wr (S : List Req) (r : Req) (s : St Req) : Prop :=
  s.phase = .writing ∧ s.done = false ∧
    (s.segs.map Prod.snd = S ++ [r] ∨ s.shouldClose = true)

def ExitA (S : List Req) (r : Req) (s : St Req) : Prop := s.done = true ∨ Wr S r s

theorem avail_readable (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (r : Req) (s : St Req)
    (late : Bool) (h : Avail P r s) :
    ExitA (s.segs.map Prod.snd) r (step fix P s (.readable late)) := by
  obtain ⟨hph, hd, n, hf⟩ := h
  right
  simp only [step, hd, Bool.false_eq_true, if_false, stepCH, onReadable, hph, ne_eq,
    not_true_eq_false]
  split
  · exact ⟨rfl, by simpa [queueError] using hd, Or.inr rfl⟩
  · split
    · rename_i hfin
      have hb := hP.complete_buf _ _ _ hf
      rw [if_pos hb]
      obtain ⟨a, b, c⟩ := parse_complete fix P late
        { drained s with shouldClose := true, peerEof := true } r n (by simpa using hf)
      exact ⟨a, by rw [b]; simpa using hd, by simpa using c⟩
    · obtain ⟨a, b, c⟩ := parse_complete fix P late (drained s) r n (by simpa using hf)
      exact ⟨a, by rw [b]; simpa using hd, by simpa using c⟩

theorem avail_step (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (hx : Oracle.Ext P)
    (r : Req) (s : St Req) (e : Ev) (h : Avail P r s) :
    ExitA (s.segs.map Prod.snd) r (step fix P s e) ∨
      (Avail P r (step fix P s e) ∧ (step fix P s e).segs = s.segs) := by
  have h' := h
  obtain ⟨hph, hd, n, hf⟩ := h
  cases e with
  | arrive b =>
    right
    simp only [step, hd, Bool.false_eq_true, if_false, stepCH]
    split
    · exact ⟨h', rfl⟩
    · refine ⟨⟨hph, rfl, n, ?_⟩, rfl⟩
      simpa [List.append_assoc] using hx _ b r n hf
  | fin =>
    right
    simp only [step, hd, Bool.false_eq_true, if_false, stepCH]
    exact ⟨⟨hph, rfl, n, hf⟩, by simp⟩
  | readable late => left; exact avail_readable fix P hP r s late h'
  | writable k =>
    right
    have : onWritable P k s = s := by unfold onWritable; simp [hph]
    simp only [step, hd, Bool.false_eq_true, if_false, stepCH, this]
    exact ⟨h', by simp⟩
  | timeout => left; left; simp [step, hd, stepCH, onTimeout]
  | ioError => left; left; simp [step, hd, stepCH]

/-! ## Phase B: flushing the response -/

def mu (s : St Req) : Nat := s.wbuf.length - s.wpos

/-- Done, or `r` dispatched next, back to reading and every queued byte
written. -/
def Goal (P : Params Req) (S : List Req) (r : Req) (s : St Req) : Prop :=
  s.done = true ∨ (s.segs.map Prod.snd = S ++ [r] ∧ s.phase = .reading ∧ s.wire = flat P s.log)

theorem wr_step (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (S : List Req) (r : Req)
    (s : St Req) (e : Ev) (hi : Inv P s) (h : Wr S r s) :
    Goal P S r (step fix P s e) ∨
      (Wr S r (step fix P s e) ∧ mu (step fix P s e) ≤ mu s ∧
        ∀ k, 0 < k → e = .writable k → mu (step fix P s e) < mu s) := by
  have h' := h
  obtain ⟨hph, hd, hseg⟩ := h
  cases e with
  | arrive b =>
    right
    simp only [step, hd, Bool.false_eq_true, if_false, stepCH]
    split
    · exact ⟨h', Nat.le_refl _, fun _ _ he => by cases he⟩
    · exact ⟨⟨hph, rfl, hseg⟩, Nat.le_refl _, fun _ _ he => by cases he⟩
  | fin =>
    right
    simp only [step, hd, Bool.false_eq_true, if_false, stepCH]
    exact ⟨⟨hph, rfl, hseg⟩, Nat.le_refl _, fun _ _ he => by cases he⟩
  | readable late =>
    right
    have : onReadable fix P late s = s := by unfold onReadable; simp [hph]
    simp only [step, hd, Bool.false_eq_true, if_false, stepCH, this]
    exact ⟨h', Nat.le_refl _, fun _ _ he => by cases he⟩
  | writable k =>
    have hi' := inv_step fix P hP s (.writable k) hi
    simp only [step, hd, Bool.false_eq_true, if_false, stepCH] at hi' ⊢
    unfold onWritable at hi' ⊢
    simp only [hph, ne_eq, not_true_eq_false, if_false] at hi' ⊢
    split
    · rename_i hlt
      right
      refine ⟨⟨rfl, hd, hseg⟩, ?_, ?_⟩
      · simp only [mu, sendN] at hlt ⊢; omega
      · intro k' hk he
        cases he
        simp only [mu, sendN] at hlt ⊢; omega
    · rename_i hge
      split
      · left; left; rfl
      · rename_i hsc
        left; right
        have hwr := (hi'.wire_read (by simp [hge, hsc])).1
        simp only [hge, hsc, if_false, Bool.false_eq_true] at hwr
        refine ⟨?_, rfl, hwr⟩
        rcases hseg with hs | hs
        · exact hs
        · exact absurd hs (by simpa using hsc)
  | timeout => left; left; simp [step, hd, stepCH, onTimeout]
  | ioError => left; left; simp [step, hd, stepCH]

theorem step_done (fix : Bool) (P : Params Req) (s : St Req) (e : Ev) (h : s.done = true) :
    step fix P s e = s := by simp [step, h]

theorem trace_done (fix : Bool) (P : Params Req) (s0 : St Req) (σ : Nat → Ev) (j : Nat)
    (h : (trace fix P s0 σ j).done = true) : ∀ d, trace fix P s0 σ (j + d) = trace fix P s0 σ j
  | 0 => rfl
  | d + 1 => by
    show step fix P (trace fix P s0 σ (j + d)) (σ (j + d)) = _
    rw [trace_done fix P s0 σ j h d, step_done fix P _ _ h]

section
variable (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (s0 : St Req) (σ : Nat → Ev)
  (h0 : Inv P s0)

include hP h0 in
theorem wr_run (S : List Req) (r : Req) (j : Nat) (hw : Wr S r (trace fix P s0 σ j)) :
    ∀ d, (∃ i, j ≤ i ∧ Goal P S r (trace fix P s0 σ i)) ∨
      (Wr S r (trace fix P s0 σ (j + d)) ∧ mu (trace fix P s0 σ (j + d)) ≤ mu (trace fix P s0 σ j))
  | 0 => Or.inr ⟨hw, Nat.le_refl _⟩
  | d + 1 => by
    rcases wr_run S r j hw d with hg | ⟨hw', hm⟩
    · exact Or.inl hg
    · rcases wr_step fix P hP S r _ (σ (j + d)) (trace_inv fix P hP s0 σ h0 _) hw' with hg | ⟨h1, h2, -⟩
      · exact Or.inl ⟨j + d + 1, by omega, hg⟩
      · exact Or.inr ⟨h1, Nat.le_trans h2 hm⟩

include hP h0 in
theorem phaseB (hf : Fair fix P s0 σ) (S : List Req) (r : Req) :
    ∀ μ j, Wr S r (trace fix P s0 σ j) → mu (trace fix P s0 σ j) ≤ μ →
      ∃ m, j ≤ m ∧ Goal P S r (trace fix P s0 σ m) := by
  intro μ
  induction μ with
  | zero => ?_
  | succ μ ih => ?_
  all_goals
    intro j hw hμ
    obtain ⟨m1, hjm, halt⟩ := hf.write j hw.2.1 hw.1
    rcases wr_run fix P hP s0 σ h0 S r j hw (m1 - j) with ⟨i, hi, hg⟩ | ⟨hw1, hm1⟩
    · exact ⟨i, hi, hg⟩
    rw [show j + (m1 - j) = m1 by omega] at hw1 hm1
    rcases halt with hd | hph | ⟨k, hk, he⟩
    · rw [hw1.2.1] at hd; cases hd
    · exact absurd hw1.1 hph
    rcases wr_step fix P hP S r _ (σ m1) (trace_inv fix P hP s0 σ h0 _) hw1 with hg | ⟨h1, -, h3⟩
    · exact ⟨m1 + 1, by omega, hg⟩
    have hlt := h3 k hk he
  · exfalso
    change mu (step fix P (trace fix P s0 σ m1) (σ m1)) < _ at hlt
    omega
  · have := ih (m1 + 1) h1 (by change mu (step fix P (trace fix P s0 σ m1) (σ m1)) ≤ μ; omega)
    obtain ⟨m, hm, hg⟩ := this
    exact ⟨m, by omega, hg⟩

include hP in
theorem avail_run (hx : Oracle.Ext P) (r : Req) (j : Nat) (ha : Avail P r (trace fix P s0 σ j)) :
    ∀ d, (∃ i, j ≤ i ∧
        ExitA ((trace fix P s0 σ j).segs.map Prod.snd) r (trace fix P s0 σ i)) ∨
      (Avail P r (trace fix P s0 σ (j + d)) ∧
        (trace fix P s0 σ (j + d)).segs = (trace fix P s0 σ j).segs)
  | 0 => Or.inr ⟨ha, rfl⟩
  | d + 1 => by
    rcases avail_run hx r j ha d with hg | ⟨ha', hs⟩
    · exact Or.inl hg
    · rcases avail_step fix P hP hx r _ (σ (j + d)) ha' with hx' | ⟨h1, h2⟩
      · rw [hs] at hx'; exact Or.inl ⟨j + d + 1, by omega, hx'⟩
      · exact Or.inr ⟨h1, h2.trans hs⟩

include hP h0 in
/-- **Liveness.** Under fair event delivery, a whole request `r` buffered
while reading is dispatched next and its response is written in full
(the handle is back in STATE_READING with `wire = flat log`), or the
connection becomes done (with `should_close`, `trace_done_sc`). -/
theorem eventually_served (hx : Oracle.Ext P) (hf : Fair fix P s0 σ) (n : Nat) (r : Req)
    (ha : Avail P r (trace fix P s0 σ n)) :
    ∃ m, n ≤ m ∧ ((trace fix P s0 σ m).done = true ∨
      ((trace fix P s0 σ m).segs.map Prod.snd = (trace fix P s0 σ n).segs.map Prod.snd ++ [r] ∧
        (trace fix P s0 σ m).phase = .reading ∧
        (trace fix P s0 σ m).wire = flat P (trace fix P s0 σ m).log)) := by
  have hexit : ∃ i, n ≤ i ∧
      ExitA ((trace fix P s0 σ n).segs.map Prod.snd) r (trace fix P s0 σ i) := by
    obtain ⟨hph, hd, len, hfr⟩ := ha
    have hready : (trace fix P s0 σ n).kq ≠ [] ∨ (trace fix P s0 σ n).kfin = true ∨
        P.hasBuf (trace fix P s0 σ n).rbuf = true := by
      by_cases hk : (trace fix P s0 σ n).kq = []
      · right; right
        rw [hk, List.append_nil] at hfr
        exact hP.complete_buf _ _ _ hfr
      · left; exact hk
    obtain ⟨m1, hnm, halt⟩ := hf.read n hd hph hready
    rcases avail_run fix P hP s0 σ hx r n ⟨hph, hd, len, hfr⟩ (m1 - n) with hg | ⟨ha1, hs1⟩
    · exact hg
    rw [show n + (m1 - n) = m1 by omega] at ha1 hs1
    rcases halt with hdd | hph' | ⟨late, he⟩
    · rw [ha1.2.1] at hdd; cases hdd
    · exact absurd ha1.1 hph'
    have := avail_readable fix P hP r _ late ha1
    rw [hs1, ← he] at this
    exact ⟨m1 + 1, by omega, this⟩
  obtain ⟨i, hni, hdone | hw⟩ := hexit
  · exact ⟨i, hni, Or.inl hdone⟩
  obtain ⟨m, him, hg⟩ := phaseB fix P hP s0 σ h0 hf _ r _ i hw (Nat.le_refl _)
  exact ⟨m, by omega, hg⟩

end

/-! ## Why a connection is done -/

theorem queueError_done (P : Params Req) (s : St Req) (o : Out Req) :
    (queueError P s o).done = s.done := rfl

/-- **Close reasons.** A step that makes the handle done is a timer
expiry, an I/O error, a peer FIN with no whole request buffered, or the
flush of a response queued with `should_close`; in every case
`should_close` is set. -/
theorem done_reason (fix : Bool) (P : Params Req) (s : St Req) (e : Ev) (hd : s.done = false)
    (h : (step fix P s e).done = true) :
    (step fix P s e).shouldClose = true ∧
    (e = .timeout ∨ e = .ioError ∨
      (∃ late, e = .readable late ∧ s.kfin = true ∧ P.hasBuf (s.rbuf ++ s.kq) = false) ∨
      (∃ k, e = .writable k ∧ s.phase = .writing ∧ s.shouldClose = true)) := by
  simp only [step, hd, Bool.false_eq_true, if_false] at h ⊢
  cases e with
  | arrive b =>
    simp only [stepCH] at h; split at h
    · rw [hd] at h; cases h
    · simp [hd] at h
  | fin => simp [stepCH, hd] at h
  | readable late =>
    have key : s.kfin = true ∧ P.hasBuf (s.rbuf ++ s.kq) = false ∧
        (stepCH fix P s (.readable late)).shouldClose = true := by
      simp only [stepCH, onReadable] at h ⊢
      split at h
      · rw [hd] at h; cases h
      · split at h
        · simp [queueError, hd] at h
        · split at h
          · split at h
            · rw [parse_done] at h; simp [hd] at h
            · rename_i hph hcap hfin hb
              refine ⟨hfin, by simpa using hb, ?_⟩
              rw [if_neg hph, if_neg hcap, if_pos hfin, if_neg hb]
          · rw [parse_done] at h; simp [hd] at h
    exact ⟨key.2.2, Or.inr (Or.inr (Or.inl ⟨late, rfl, key.1, key.2.1⟩))⟩
  | writable k =>
    have key : s.phase = .writing ∧ s.shouldClose = true := by
      simp only [stepCH, onWritable] at h
      split at h
      · rw [hd] at h; cases h
      · split at h
        · simp [hd] at h
        · split at h
          · rename_i hph _ hsc; exact ⟨by simpa using hph, hsc⟩
          · rw [hd] at h; cases h
    refine ⟨?_, Or.inr (Or.inr (Or.inr ⟨k, rfl, key.1, key.2⟩))⟩
    simp only [stepCH]
    unfold onWritable
    split
    · exact key.2
    · split
      · exact key.2
      · split <;> exact key.2
  | timeout => exact ⟨rfl, Or.inl rfl⟩
  | ioError => exact ⟨rfl, Or.inr (Or.inl rfl)⟩

/-- Along any trace from a state where `done → should_close`, every done
state has `should_close`. -/
theorem trace_done_sc (fix : Bool) (P : Params Req) (s0 : St Req) (σ : Nat → Ev)
    (h0 : s0.done = true → s0.shouldClose = true) :
    ∀ n, (trace fix P s0 σ n).done = true → (trace fix P s0 σ n).shouldClose = true
  | 0 => h0
  | n + 1 => by
    intro h
    show (step fix P (trace fix P s0 σ n) (σ n)).shouldClose = true
    cases hd : (trace fix P s0 σ n).done
    · exact (done_reason fix P _ _ hd h).1
    · rw [step_done fix P _ _ hd]; exact trace_done_sc fix P s0 σ h0 n hd

end Flare.L4.ConnLive
