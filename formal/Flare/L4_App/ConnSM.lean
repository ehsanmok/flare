import Flare.Core

/-!
# The HTTP/1.1 per-connection state machine (`ConnHandle`)

Model of flare/http/_reactor/conn_handle.mojo (`ConnHandle.on_readable`,
`on_writable`, `on_timeout`, `_check_request_complete`,
`_apply_keepalive_policy`, `_finalise_response`, `_queue_error`,
`_transition_to_writing`) and the `StepResult` contract of
flare/http/_reactor/keepalive_scan.mojo, as an LTS over socket events.

## Abstractions

* **Framing oracle.** HTTP/1.1 framing (owned by the L3 model) is a
  parameter `frame : Bytes → Frame Req` returning `needMore`,
  `complete r n` (request `r` occupies the first `n` bytes) or
  `error status`. `Oracle.WF` states the properties the proofs use: a
  complete request has `0 < n ≤ len` and is determined by its own `n` bytes.
  `hasBuf` abstracts `has_buffered_request` (used only on peer FIN); the only
  property needed is that a complete request counts as buffered.
* **Responses.** A queued response is an `Out` record (which request it
  answers, if any; its kind; the `Connection:` value it carries).
  Serialisation is a parameter `ser`. The byte-level body decisions of
  `serialize_response_into` are modelled separately in `Framing` below.
* **Handler.** `handlerOk r` says whether the handler returns or raises;
  `closeAfter r` is the request's own close verdict (`_compute_close_after`
  or `_wants_close`, modelled in `Flare.Bugs.APP_02/03`); `wsMismatch r`
  is `config.ws.handler and _is_ws_version_mismatch(req)`.
* **Kernel.** `kq` is the socket receive queue and `kfin` a pending FIN.
  `on_readable` drains `kq` completely (the recv loop runs to EAGAIN). No
  data arrives after a FIN (TCP).
* **Time.** The absolute request budget (`request_timeout_ms`) is the flag
  `late` on a readable event; the arithmetic is in
  `Flare.L4.ServerConfig.closeTime_le`.
* Out of scope here: streaming bodies (`body_src`), TLS cross-interest,
  h2c upgrade and WebSocket hand-off (`done` with `idle_timeout_ms=0`).

## Deviations (documented)

* When a flush completes with `should_close`, the Mojo code returns
  `done=True` and leaves `state = STATE_WRITING`; the reactor frees the
  handle at once. The model moves to `closing` (the field is never read
  again).
* After a handler error the Mojo code leaves the request bytes in
  `read_buf` (the connection is closing); the model drops them. The bytes are
  never parsed again because `should_close` is set (`segs_frozen`).
* The size cap is checked once after the whole drain rather than per 8 KiB
  chunk; both answer 413 and close.
-/
namespace Flare.L4.ConnSM

inductive Phase | reading | writing | closing
  deriving DecidableEq, Repr

inductive Frame (Req : Type) where
  | needMore
  | complete (r : Req) (n : Nat)
  | error (status : Nat)
  deriving DecidableEq, Repr

inductive Kind | ok | err (status : Nat) | ws426
  deriving DecidableEq, Repr

/-- A queued response: the request it answers (`none` for a framing error
raised before a request was delimited), its kind, and whether its
`Connection:` header says `keep-alive` (`false` = `close`). -/
structure Out (Req : Type) where
  req : Option Req
  kind : Kind
  keepAlive : Bool
  deriving DecidableEq, Repr

structure Params (Req : Type) where
  frame : Bytes → Frame Req
  hasBuf : Bytes → Bool
  ser : Out Req → Bytes
  closeAfter : Req → Bool
  wsMismatch : Req → Bool
  handlerOk : Req → Bool
  maxKA : Nat
  keepAlive : Bool
  cap : Nat

/-- Properties of the framing oracle the proofs rely on. -/
structure Oracle.WF {Req : Type} (P : Params Req) : Prop where
  complete_le : ∀ b r n, P.frame b = .complete r n → n ≤ b.length
  complete_self : ∀ b r n, P.frame b = .complete r n → P.frame (b.take n) = .complete r n
  complete_buf : ∀ b r n, P.frame b = .complete r n → P.hasBuf b = true

structure St (Req : Type) where
  phase : Phase
  kq : Bytes
  kfin : Bool
  rbuf : Bytes
  wbuf : Bytes
  wpos : Nat
  ka : Nat
  shouldClose : Bool
  peerEof : Bool
  done : Bool
  /-- ghost: every byte that arrived -/
  inp : Bytes
  /-- ghost: dispatched requests with the bytes they occupied, in order -/
  segs : List (Bytes × Req)
  /-- ghost: queued responses, in order -/
  log : List (Out Req)
  /-- ghost: bytes sent on the wire -/
  wire : Bytes
  deriving DecidableEq, Repr

inductive Ev where
  | arrive (b : Bytes)
  | fin
  | readable (late : Bool)
  | writable (n : Nat)
  | timeout
  | ioError
  deriving DecidableEq, Repr

variable {Req : Type}

/-- `ConnHandle.__init__`: STATE_READING, empty buffers.
mirrors flare/http/_reactor/conn_handle.mojo:354-398 @59bda50 -/
def init : St Req :=
  { phase := .reading, kq := [], kfin := false, rbuf := [], wbuf := [], wpos := 0,
    ka := 0, shouldClose := false, peerEof := false, done := false,
    inp := [], segs := [], log := [], wire := [] }

def flat (P : Params Req) (l : List (Out Req)) : Bytes := (l.map P.ser).flatten

def segBytes (s : St Req) : Bytes := (s.segs.map Prod.fst).flatten

/-- `_queue_error` then `_transition_to_writing`: mark close, queue a
`Connection: close` error response, enter STATE_WRITING.
mirrors flare/http/_reactor/conn_handle.mojo:1576-1580,1423-1435 @59bda50 -/
def queueError (P : Params Req) (s : St Req) (o : Out Req) : St Req :=
  { s with shouldClose := true, wbuf := P.ser o, wpos := 0, phase := .writing,
           log := s.log ++ [o] }

/-- `_finalise_response` (buffered path): drop the request's bytes from
`read_buf`, serialise, enter STATE_WRITING. `close_after` only selects the
`Connection:` header; `should_close` is not touched here.
mirrors flare/http/_reactor/conn_handle.mojo:718-756 @59bda50 -/
def finalise (P : Params Req) (s : St Req) (r : Req) (n : Nat) (o : Out Req) : St Req :=
  { s with rbuf := s.rbuf.drop n, segs := s.segs ++ [(s.rbuf.take n, r)],
           wbuf := P.ser o, wpos := 0, phase := .writing, log := s.log ++ [o] }

/-- `_apply_keepalive_policy`.
mirrors flare/http/_reactor/conn_handle.mojo:697-715 @59bda50 -/
def applyKA (P : Params Req) (s : St Req) (closeAfter : Bool) : St Req × Bool :=
  let final := closeAfter || decide (P.maxKA ≤ s.ka + 1) || !P.keepAlive || s.peerEof
  ({ s with ka := s.ka + 1, shouldClose := final }, final)

/-- Dispatch of a complete request in `on_readable`: the WebSocket
version-mismatch branch (426), else keep-alive policy then handler, with a
raising handler mapped through `_queue_error`. `fix = true` is the shipped
code (`should_close = True` on the 426 branch, APP-01 fixed); `fix = false` is
the pre-fix code, kept so the counterexample in `Flare.Bugs.APP_01` stays
checkable.
mirrors flare/http/_reactor/conn_handle.mojo:846-860,911-920 (fixed, APP-01) -/
def dispatch (fix : Bool) (P : Params Req) (s : St Req) (r : Req) (n : Nat) : St Req :=
  if P.wsMismatch r then
    finalise P (if fix then { s with shouldClose := true } else s) r n ⟨some r, .ws426, false⟩
  else
    let s1 := (applyKA P s (P.closeAfter r)).1
    let final := (applyKA P s (P.closeAfter r)).2
    if P.handlerOk r then finalise P s1 r n ⟨some r, .ok, !final⟩
    else
      { queueError P s1 ⟨some r, .err 500, false⟩ with
          rbuf := s.rbuf.drop n, segs := s.segs ++ [(s.rbuf.take n, r)] }

/-- `_check_request_complete` (request budget, then framing) followed by
dispatch.
mirrors flare/http/_reactor/conn_handle.mojo:579-695 @59bda50 -/
def parse (fix : Bool) (P : Params Req) (late : Bool) (s : St Req) : St Req :=
  if late && !s.rbuf.isEmpty then queueError P s ⟨none, .err 408, false⟩
  else match P.frame s.rbuf with
    | .needMore => s
    | .error st => queueError P s ⟨none, .err st, false⟩
    | .complete r n => dispatch fix P s r n

/-- The recv loop of `_drain_recv`: move the kernel queue into `read_buf`.
mirrors flare/http/_reactor/conn_handle.mojo:439-477 @59bda50 -/
@[simp] def drained (s : St Req) : St Req := { s with rbuf := s.rbuf ++ s.kq, kq := [] }

/-- `on_readable`: ignored outside STATE_READING; drain the socket
(`_drain_recv`: size cap, FIN handling with the half-close rule), then parse.
mirrors flare/http/_reactor/conn_handle.mojo:760-916,422-477 @59bda50 -/
def onReadable (fix : Bool) (P : Params Req) (late : Bool) (s : St Req) : St Req :=
  if s.phase ≠ .reading then s
  else if !s.kq.isEmpty && decide (P.cap < (s.rbuf ++ s.kq).length) then
    queueError P (drained s) ⟨none, .err 413, false⟩
  else if s.kfin then
    if P.hasBuf (s.rbuf ++ s.kq) then
      parse fix P late { drained s with shouldClose := true, peerEof := true }
    else { drained s with shouldClose := true, done := true }
  else parse fix P late (drained s)

/-- Bytes one `send` accepts: at most the kernel's `n`, at most what remains. -/
def sendN (n : Nat) (s : St Req) : Nat := min n (s.wbuf.length - s.wpos)

/-- `on_writable` (buffered path): send up to `n` bytes (`n = 0` is EAGAIN);
partial → stay; flushed → close if `should_close`, else back to reading.
mirrors flare/http/_reactor/conn_handle.mojo:1262-1375 @59bda50 -/
def onWritable (_P : Params Req) (n : Nat) (s : St Req) : St Req :=
  if s.phase ≠ .writing then s
  else if s.wpos + sendN n s < s.wbuf.length then
    { s with wpos := s.wpos + sendN n s, wire := s.wire ++ (s.wbuf.drop s.wpos).take (sendN n s) }
  else if s.shouldClose then
    { s with wire := s.wire ++ (s.wbuf.drop s.wpos).take (sendN n s), wbuf := [], wpos := 0,
             phase := .closing, done := true }
  else
    { s with wire := s.wire ++ (s.wbuf.drop s.wpos).take (sendN n s), wbuf := [], wpos := 0,
             phase := .reading }

/-- `on_timeout`: unconditionally STATE_CLOSING, `should_close`, `done`.
mirrors flare/http/_reactor/conn_handle.mojo:1403-1411 @59bda50 -/
def onTimeout (s : St Req) : St Req :=
  { s with phase := .closing, shouldClose := true, done := true }

/-- One event delivered to the handle (methods of `ConnHandle`, plus the
kernel's receive queue).
mirrors flare/http/_reactor/conn_handle.mojo:760,1262,1403 @59bda50 -/
def stepCH (fix : Bool) (P : Params Req) (s : St Req) : Ev → St Req
  | .arrive b => if s.kfin then s else { s with kq := s.kq ++ b, inp := s.inp ++ b }
  | .fin => { s with kfin := true }
  | .readable late => onReadable fix P late s
  | .writable n => onWritable P n s
  | .timeout => onTimeout s
  | .ioError => { s with shouldClose := true, done := true }

/-- The reactor frees the handle once a step returns `done`
(`_cleanup_conn`), so a done handle sees no further events. -/
def step (fix : Bool) (P : Params Req) (s : St Req) (e : Ev) : St Req :=
  if s.done then s else stepCH fix P s e

def lts (fix : Bool) (P : Params Req) : LTS (St Req) Ev :=
  LTS.ofFn (· = init) (fun s e => some (step fix P s e))

theorem lts_step_iff (fix : Bool) (P : Params Req) (s s' : St Req) (e : Ev) :
    (lts fix P).step s e s' ↔ step fix P s e = s' := by
  simp [lts, LTS.ofFn]

def run (fix : Bool) (P : Params Req) (s : St Req) (es : List Ev) : St Req :=
  es.foldl (step fix P) s

theorem run_run (fix : Bool) (P : Params Req) :
    ∀ (es : List Ev) (s : St Req), (lts fix P).Run s es (run fix P s es)
  | [], s => .nil s
  | e :: es, s => .cons ((lts_step_iff fix P _ _ e).2 rfl) (run_run fix P es (step fix P s e))

/-- Every state the executable machine reaches from `init` is reachable. -/
theorem reachable_run (fix : Bool) (P : Params Req) (es : List Ev) :
    (lts fix P).Reachable (run fix P init es) :=
  ⟨init, es, rfl, run_run fix P es init⟩

/-! ## Invariant -/

/-- The connection invariant.
* `input`: every byte that arrived is, in order, a dispatched request's
  bytes, then unparsed buffered bytes, then the kernel queue (FIFO
  consumption, nothing skipped or reordered).
* `segs_ok`: each dispatched request is what the oracle reads off exactly
  its own bytes.
* `answers`: the requests answered by queued responses are exactly the
  dispatched requests, in the same order (one response each, none to the
  wrong request; framing-error responses carry no request).
* `wire_*`: the bytes sent are the queued responses in order, the current
  one possibly cut at `wpos`.
* `quiet`: reading with `should_close` set only happens after a FIN with an
  incomplete request.
* `ka_le`, `ka_ok`: the keep-alive counter bound. -/
structure Inv (P : Params Req) (s : St Req) : Prop where
  input : s.inp = segBytes s ++ s.rbuf ++ s.kq
  segs_ok : ∀ p ∈ s.segs, P.frame p.1 = .complete p.2 p.1.length
  answers : s.log.filterMap Out.req = s.segs.map Prod.snd
  wire_read : s.phase = .reading → s.wire = flat P s.log ∧ s.wbuf = [] ∧ s.wpos = 0
  wire_write : s.phase = .writing → ∃ ini last, s.log = ini ++ [last] ∧
    s.wbuf = P.ser last ∧ s.wpos ≤ s.wbuf.length ∧ s.wire = flat P ini ++ s.wbuf.take s.wpos
  wire_close : s.phase = .closing → s.wire <+: flat P s.log
  quiet : s.phase = .reading → s.done = false → s.shouldClose = true →
    s.kfin = true ∧ s.kq = [] ∧ P.frame s.rbuf = .needMore
  ka_le : s.ka ≤ max P.maxKA 1
  ka_ok : s.phase ≠ .closing → s.shouldClose = false → s.ka = 0 ∨ s.ka < P.maxKA

theorem inv_init (P : Params Req) : Inv P (init : St Req) := by
  constructor <;> simp [init, segBytes, flat]

/-! ### Lemmas for the pieces -/

theorem flat_append (P : Params Req) (l : List (Out Req)) (o : Out Req) :
    flat P (l ++ [o]) = flat P l ++ P.ser o := by simp [flat]

theorem segBytes_append (s : St Req) (b : Bytes) (r : Req) :
    ((s.segs ++ [(b, r)]).map Prod.fst).flatten = segBytes s ++ b := by
  simp [segBytes]

/-- What a reading state must satisfy for any "queue a response and enter
writing" step to re-establish `Inv`. -/
structure Base (P : Params Req) (s : St Req) : Prop where
  input : s.inp = segBytes s ++ s.rbuf ++ s.kq
  segs_ok : ∀ p ∈ s.segs, P.frame p.1 = .complete p.2 p.1.length
  answers : s.log.filterMap Out.req = s.segs.map Prod.snd
  wire : s.wire = flat P s.log

theorem Inv.base (P : Params Req) (s : St Req) (h : Inv P s) (hph : s.phase = .reading) :
    Base P s := ⟨h.input, h.segs_ok, h.answers, (h.wire_read hph).1⟩

/-- The two ways a response is queued: a framing error (no request consumed)
or a delimited request `r` occupying `n` bytes. -/
inductive Consumed (P : Params Req) (s s' : St Req) (o : Out Req) : Prop where
  | none (hr : s'.rbuf = s.rbuf) (hs : s'.segs = s.segs) (ho : o.req = Option.none)
  | req (r : Req) (n : Nat) (hf : P.frame s.rbuf = .complete r n)
      (hr : s'.rbuf = s.rbuf.drop n) (hs : s'.segs = s.segs ++ [(s.rbuf.take n, r)])
      (ho : o.req = some r)

/-- Every "queue a response, enter writing" step re-establishes `Inv`. -/
theorem inv_enter_writing (P : Params Req) (hP : Oracle.WF P) (s s' : St Req) (o : Out Req)
    (hb : Base P s) (hc : Consumed P s s' o)
    (h1 : s'.phase = .writing) (h2 : s'.log = s.log ++ [o]) (h3 : s'.wbuf = P.ser o)
    (h4 : s'.wpos = 0) (h5 : s'.wire = s.wire) (h6 : s'.inp = s.inp) (h7 : s'.kq = s.kq)
    (hka : s'.ka ≤ max P.maxKA 1)
    (hok : s'.shouldClose = false → s'.ka = 0 ∨ s'.ka < P.maxKA) : Inv P s' := by
  obtain ⟨hi, hs, ha, hw⟩ := hb
  constructor
  · rcases hc with ⟨hr, hsg, -⟩ | ⟨r, n, hf, hr, hsg, -⟩
    · simp [segBytes, h6, h7, hr, hsg, hi]
    · rw [h6, h7, hr, segBytes, hsg, segBytes_append, hi]
      simp [List.append_assoc, List.take_append_drop]
  · rcases hc with ⟨hr, hsg, -⟩ | ⟨r, n, hf, hr, hsg, -⟩
    · rw [hsg]; exact hs
    · rw [hsg]; intro p hp
      simp only [List.mem_append, List.mem_singleton] at hp
      rcases hp with hp | rfl
      · exact hs p hp
      · simp only [List.length_take, Nat.min_eq_left (hP.complete_le _ _ _ hf)]
        exact hP.complete_self _ _ _ hf
  · rcases hc with ⟨hr, hsg, ho⟩ | ⟨r, n, hf, hr, hsg, ho⟩
    · simp [h2, hsg, List.filterMap_append, ho, ha]
    · simp [h2, hsg, List.filterMap_append, ho, ha]
  · intro h; rw [h1] at h; cases h
  · intro _; exact ⟨s.log, o, h2, h3, by simp [h4], by simp [h4, h5, hw]⟩
  · intro h; rw [h1] at h; cases h
  · intro h; rw [h1] at h; cases h
  · exact hka
  · intro _ h; exact hok h

theorem dispatch_ka (P : Params Req) (s : St Req) (hph : s.phase = .reading)
    (hsc : s.shouldClose = false) (h : Inv P s) :
    s.ka + 1 ≤ max P.maxKA 1 := by
  rcases h.ka_ok (by simp [hph]) hsc with h0 | h0 <;> omega

theorem inv_queueError (P : Params Req) (hP : Oracle.WF P) (s : St Req) (o : Out Req)
    (hb : Base P s) (hka : s.ka ≤ max P.maxKA 1) (ho : o.req = none) :
    Inv P (queueError P s o) :=
  inv_enter_writing P hP s _ o hb (.none rfl rfl ho) rfl rfl rfl rfl rfl rfl rfl hka
    (by simp [queueError])

theorem inv_dispatch (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (s : St Req) (r : Req)
    (n : Nat) (hb : Base P s) (hok0 : s.ka = 0 ∨ s.ka < P.maxKA)
    (hf : P.frame s.rbuf = .complete r n) : Inv P (dispatch fix P s r n) := by
  have hk1 : s.ka + 1 ≤ max P.maxKA 1 := by omega
  have hk0 : s.ka ≤ max P.maxKA 1 := by omega
  unfold dispatch
  split
  · cases fix <;>
    exact inv_enter_writing P hP _ _ _ ⟨hb.input, hb.segs_ok, hb.answers, hb.wire⟩
      (.req r n hf rfl rfl rfl) rfl rfl rfl rfl rfl rfl rfl hk0
      (by intro _; simpa [finalise] using hok0)
  · have hbA : Base P (applyKA P s (P.closeAfter r)).1 :=
      ⟨by simpa [applyKA, segBytes] using hb.input, by simpa [applyKA] using hb.segs_ok,
       by simpa [applyKA] using hb.answers, by simpa [applyKA] using hb.wire⟩
    have hokA : ∀ (s' : St Req), s'.ka = s.ka + 1 →
        s'.shouldClose = (applyKA P s (P.closeAfter r)).2 →
        s'.shouldClose = false → s'.ka = 0 ∨ s'.ka < P.maxKA := by
      intro s' e1 e2 e3
      rw [e2] at e3
      simp only [applyKA, Bool.or_eq_false_iff, decide_eq_false_iff_not] at e3
      right; omega
    split
    · exact inv_enter_writing P hP _ _ _ hbA (.req r n (by simpa [applyKA] using hf) rfl
        (by simp [finalise, applyKA]) rfl) rfl rfl rfl rfl rfl rfl rfl
        (by simpa [finalise, applyKA] using hk1)
        (hokA _ (by simp [finalise, applyKA]) (by simp [finalise, applyKA]))
    · exact inv_enter_writing P hP (applyKA P s (P.closeAfter r)).1 _ _ hbA
        (.req r n (by simpa [applyKA] using hf) (by simp [applyKA]) (by simp [applyKA]) rfl)
        rfl rfl rfl rfl rfl rfl rfl (by simpa [queueError, applyKA] using hk1)
        (by simp [queueError])

theorem inv_parse (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (late : Bool) (s : St Req)
    (hb : Base P s) (hka : s.ka ≤ max P.maxKA 1)
    (hk : ∀ r n, P.frame s.rbuf = .complete r n → s.ka = 0 ∨ s.ka < P.maxKA)
    (hstay : P.frame s.rbuf = .needMore → Inv P s) : Inv P (parse fix P late s) := by
  unfold parse
  split
  · exact inv_queueError P hP s ⟨none, .err 408, false⟩ hb hka rfl
  · split
    · rename_i h; exact hstay h
    · rename_i st _; exact inv_queueError P hP s ⟨none, .err st, false⟩ hb hka rfl
    · rename_i r n h; exact inv_dispatch fix P hP s r n hb (hk r n h) h

theorem Inv.wire_prefix (P : Params Req) (s : St Req) (h : Inv P s) : s.wire <+: flat P s.log := by
  cases hph : s.phase
  · rw [(h.wire_read hph).1]; exact List.prefix_refl _
  · obtain ⟨ini, last, hl, hw, -, hwire⟩ := h.wire_write hph
    rw [hwire, hl, flat_append, ← hw]
    exact List.prefix_append_right_inj _ |>.mpr (List.take_prefix _ _)
  · exact h.wire_close hph

theorem inv_onReadable (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (late : Bool)
    (s : St Req) (h : Inv P s) (hd : s.done = false) : Inv P (onReadable fix P late s) := by
  unfold onReadable
  split
  · exact h
  · rename_i hph; simp only [ne_eq, Decidable.not_not] at hph
    have hw := h.wire_read hph
    -- reading with should_close: a FIN was seen, nothing more is queued
    have hq := h.quiet hph hd
    -- any state that drained the kernel queue and changed only flags
    have hbase : ∀ t : St Req, t.inp = s.inp → t.segs = s.segs → t.rbuf = s.rbuf ++ s.kq →
        t.kq = [] → t.log = s.log → t.wire = s.wire → Base P t := by
      intro t e1 e2 e3 e4 e5 e6
      refine ⟨?_, ?_, ?_, ?_⟩
      · rw [e1, e3, e4, h.input]; simp [segBytes, e2]
      · rw [e2]; exact h.segs_ok
      · rw [e5, e2]; exact h.answers
      · rw [e6, e5]; exact hw.1
    have hstay : ∀ t : St Req, Base P t → t.phase = .reading → t.wbuf = [] → t.wpos = 0 →
        t.ka = s.ka →
        (t.done = false → t.shouldClose = true →
          t.kfin = true ∧ t.kq = [] ∧ P.frame t.rbuf = .needMore) →
        (t.shouldClose = false → s.shouldClose = false) → Inv P t := by
      intro t hb ep ew ewp ek hqt hsct
      refine ⟨hb.input, hb.segs_ok, hb.answers, fun _ => ⟨hb.wire, ew, ewp⟩, ?_, ?_, fun _ => hqt,
        by rw [ek]; exact h.ka_le, ?_⟩
      · intro hp; rw [ep] at hp; cases hp
      · intro hp; rw [ep] at hp; cases hp
      · intro _ hh; rw [ek]; exact h.ka_ok (by simp [hph]) (hsct hh)
    split
    · exact inv_queueError P hP _ ⟨none, .err 413, false⟩
        (hbase _ rfl rfl rfl rfl rfl rfl) (by simpa using h.ka_le) rfl
    · rename_i hcap
      split
      · rename_i hfin
        split
        · have hb := hbase { drained s with shouldClose := true, peerEof := true }
            rfl rfl rfl rfl rfl rfl
          apply inv_parse fix P hP late _ hb (by simpa using h.ka_le)
          · intro r n hf
            cases hsc : s.shouldClose
            · simpa using h.ka_ok (by simp [hph]) hsc
            · obtain ⟨-, hkq, hnm⟩ := hq hsc
              simp only [drained, hkq, List.append_nil] at hf; rw [hnm] at hf; cases hf
          · intro hnm
            exact hstay _ hb (by simpa using hph) (by simpa using hw.2.1) (by simpa using hw.2.2) rfl
              (fun _ _ => ⟨hfin, rfl, hnm⟩) (by intro hh; simp at hh)
        · exact hstay _ (hbase { drained s with shouldClose := true, done := true }
              rfl rfl rfl rfl rfl rfl) (by simpa using hph) (by simpa using hw.2.1) (by simpa using hw.2.2) rfl
            (by intro hh; simp at hh) (by intro hh; simp at hh)
      · rename_i hfin
        have hsc : s.shouldClose = false := by
          cases hsc : s.shouldClose
          · rfl
          · exact absurd (hq hsc).1 (by simpa using hfin)
        have hb := hbase (drained s) rfl rfl rfl rfl rfl rfl
        apply inv_parse fix P hP late _ hb (by simpa using h.ka_le)
        · intro _ _ _; simpa using h.ka_ok (by simp [hph]) hsc
        · intro hnm
          exact hstay _ hb (by simpa using hph) (by simpa using hw.2.1) (by simpa using hw.2.2)
            rfl (by intro _ hh; simp [hsc] at hh) (fun _ => hsc)

theorem inv_onWritable (P : Params Req) (n : Nat) (s : St Req) (h : Inv P s) :
    Inv P (onWritable P n s) := by
  unfold onWritable
  split
  · exact h
  · rename_i hph; simp only [ne_eq, Decidable.not_not] at hph
    obtain ⟨ini, last, hl, hwb, hle, hwire⟩ := h.wire_write hph
    have hcat : s.wire ++ List.take (sendN n s) (List.drop s.wpos s.wbuf)
        = flat P ini ++ s.wbuf.take (s.wpos + sendN n s) := by
      rw [hwire, List.take_add, List.append_assoc]
    split
    · constructor
      · simpa [segBytes] using h.input
      · exact h.segs_ok
      · exact h.answers
      · intro hp; simp [hph] at hp
      · intro _
        refine ⟨ini, last, hl, hwb, by simp; omega, ?_⟩
        simp only; rw [hcat]
      · intro hp; simp [hph] at hp
      · intro hp; simp [hph] at hp
      · exact h.ka_le
      · intro _ hsc; exact h.ka_ok (by simp [hph]) hsc
    · rename_i hfull
      have hall : s.wire ++ List.take (sendN n s) (List.drop s.wpos s.wbuf)
          = flat P s.log := by
        rw [hcat, List.take_of_length_le (by omega), hl, flat_append, hwb]
      split
      · constructor
        · simpa [segBytes] using h.input
        · exact h.segs_ok
        · exact h.answers
        · intro hp; simp at hp
        · intro hp; simp at hp
        · intro _; simp only; rw [hall]; exact List.prefix_refl _
        · intro hp; simp at hp
        · exact h.ka_le
        · intro hp; simp at hp
      · rename_i hsc
        constructor
        · simpa [segBytes] using h.input
        · exact h.segs_ok
        · exact h.answers
        · intro _; exact ⟨hall, rfl, rfl⟩
        · intro hp; simp at hp
        · intro hp; simp at hp
        · intro _ _ hh; simp [hsc] at hh
        · exact h.ka_le
        · intro _ hh; exact h.ka_ok (by simp [hph]) hh

theorem inv_stepCH (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (s : St Req) (e : Ev)
    (h : Inv P s) (hd : s.done = false) : Inv P (stepCH fix P s e) := by
  cases e with
  | arrive b =>
    simp only [stepCH]
    split
    · exact h
    · rename_i hfin
      constructor
      · simp [h.input, segBytes, List.append_assoc]
      · exact h.segs_ok
      · exact h.answers
      · exact h.wire_read
      · exact h.wire_write
      · exact h.wire_close
      · intro hp hd' hsc
        exact absurd (h.quiet hp hd' hsc).1 (by simpa using hfin)
      · exact h.ka_le
      · exact h.ka_ok
  | fin =>
    simp only [stepCH]
    constructor
    · exact h.input
    · exact h.segs_ok
    · exact h.answers
    · exact h.wire_read
    · exact h.wire_write
    · exact h.wire_close
    · intro hp hd' hsc
      obtain ⟨-, h2, h3⟩ := h.quiet hp hd' hsc
      exact ⟨rfl, h2, h3⟩
    · exact h.ka_le
    · exact h.ka_ok
  | readable late => exact inv_onReadable fix P hP late s h hd
  | writable n => exact inv_onWritable P n s h
  | timeout =>
    simp only [stepCH, onTimeout]
    constructor
    · exact h.input
    · exact h.segs_ok
    · exact h.answers
    · intro hp; simp at hp
    · intro hp; simp at hp
    · intro _; exact h.wire_prefix
    · intro hp; simp at hp
    · exact h.ka_le
    · intro hp; simp at hp
  | ioError =>
    simp only [stepCH]
    constructor
    · exact h.input
    · exact h.segs_ok
    · exact h.answers
    · exact h.wire_read
    · exact h.wire_write
    · exact h.wire_close
    · intro _ hh; simp at hh
    · exact h.ka_le
    · intro _ hh; simp at hh

theorem inv_step (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (s : St Req) (e : Ev)
    (h : Inv P s) : Inv P (step fix P s e) := by
  unfold step
  split
  · exact h
  · rename_i hd; exact inv_stepCH fix P hP s e h (by simpa using hd)

/-- `Inv` is an inductive invariant of the connection LTS (impl and fixed). -/
theorem inv_inductive (fix : Bool) (P : Params Req) (hP : Oracle.WF P) :
    (lts fix P).Inductive (Inv P) where
  init := by intro s hs; rw [hs]; exact inv_init P
  step := by
    intro s e s' h hs
    rw [lts_step_iff] at hs; rw [← hs]; exact inv_step fix P hP s e h

theorem inv_reachable (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (s : St Req)
    (h : (lts fix P).Reachable s) : Inv P s :=
  (inv_inductive fix P hP).reachable s h

/-! ## Headline properties -/

/-- **One response per request, FIFO.** In every reachable state the
requests answered by queued responses are exactly the dispatched requests in
order, every dispatched request is the oracle's reading of exactly its own
bytes, and those bytes tile a prefix of the input stream in order. -/
theorem responses_fifo (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (s : St Req)
    (h : (lts fix P).Reachable s) :
    s.log.filterMap Out.req = s.segs.map Prod.snd ∧
    (∀ p ∈ s.segs, P.frame p.1 = .complete p.2 p.1.length) ∧
    s.inp = (s.segs.map Prod.fst).flatten ++ s.rbuf ++ s.kq := by
  have hi := inv_reachable fix P hP s h
  exact ⟨hi.answers, hi.segs_ok, hi.input⟩

/-- **Wire order.** The bytes sent are always a prefix of the queued
responses' bytes in order; while reading (between requests) they are exactly
all of them. -/
theorem wire_is_responses (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (s : St Req)
    (h : (lts fix P).Reachable s) :
    s.wire <+: flat P s.log ∧ (s.phase = .reading → s.wire = flat P s.log) := by
  have hi := inv_reachable fix P hP s h
  exact ⟨hi.wire_prefix, fun hp => (hi.wire_read hp).1⟩

/-- **Partial writes.** On a writable event the bytes appended to the wire
are exactly the next `k = min n remaining` bytes of the current response
from offset `wpos`; the machine leaves STATE_WRITING iff the whole response
has then been sent. -/
theorem writable_resumes (fix : Bool) (P : Params Req) (s : St Req) (n : Nat)
    (hph : s.phase = .writing) (hd : s.done = false) :
    let k := min n (s.wbuf.length - s.wpos)
    (step fix P s (.writable n)).wire = s.wire ++ (s.wbuf.drop s.wpos).take k ∧
    ((step fix P s (.writable n)).phase = .writing ↔ s.wpos + k < s.wbuf.length) := by
  simp only [step, hd, stepCH, onWritable, hph]
  by_cases h1 : s.wpos + min n (s.wbuf.length - s.wpos) < s.wbuf.length
  · simp [h1, sendN]
  · by_cases h2 : s.shouldClose <;> simp [h1, h2, sendN]

/-- **Timeouts close.** `on_timeout` always yields STATE_CLOSING with
`should_close` and `done`, whatever the state. -/
theorem timeout_closes (fix : Bool) (P : Params Req) (s : St Req) :
    (stepCH fix P s .timeout).phase = .closing ∧ (stepCH fix P s .timeout).done = true ∧
    (stepCH fix P s .timeout).shouldClose = true := by
  simp [stepCH, onTimeout]

/-- **No request is read after `should_close`.** From any state satisfying
the invariant with `should_close` set, one step dispatches nothing and keeps
`should_close`. -/
theorem segs_frozen (fix : Bool) (P : Params Req) (s : St Req) (e : Ev) (h : Inv P s)
    (hsc : s.shouldClose = true) :
    (step fix P s e).segs = s.segs ∧ (step fix P s e).shouldClose = true := by
  unfold step
  split
  · exact ⟨rfl, hsc⟩
  · rename_i hd; simp only [Bool.not_eq_true] at hd
    cases e with
    | arrive b => simp only [stepCH]; split <;> simp [hsc]
    | fin => simp [stepCH, hsc]
    | readable late =>
      simp only [stepCH, onReadable]
      split
      · exact ⟨rfl, hsc⟩
      · rename_i hph; simp only [ne_eq, Decidable.not_not] at hph
        obtain ⟨hfin, hkq, hnm⟩ := h.quiet hph hd hsc
        simp only [drained, hkq, List.isEmpty_nil, Bool.not_true, Bool.false_and,
          Bool.false_eq_true, if_false, hfin, if_true, List.append_nil]
        split
        · unfold parse
          split
          · simp [queueError]
          · simp [hnm]
        · simp
    | writable n =>
      simp only [stepCH, onWritable]
      split
      · exact ⟨rfl, hsc⟩
      · split <;> (try split) <;> simp [hsc]
    | timeout => simp [stepCH, onTimeout]
    | ioError => simp [stepCH]

/-- Over whole runs: once `should_close` is set in a reachable state, no
later request is ever dispatched. -/
theorem run_segs_frozen (fix : Bool) (P : Params Req) (hP : Oracle.WF P) :
    ∀ (es : List Ev) (s : St Req), Inv P s → s.shouldClose = true →
      (run fix P s es).segs = s.segs := by
  intro es
  induction es with
  | nil => intro s _ _; rfl
  | cons e es ih =>
    intro s h hsc
    simp only [run, List.foldl_cons]
    have ⟨h1, h2⟩ := segs_frozen fix P s e h hsc
    have := ih (step fix P s e) (inv_step fix P hP s e h) h2
    simp only [run] at this
    rw [this, h1]

/-- **Keep-alive bound.** `keepalive_count ≤ max max_keepalive_requests 1`
in every reachable state, hence `≤ max_keepalive_requests` for any config
that passes `ServerConfig.check` (`max_keepalive_requests ≥ 1`). -/
theorem ka_bound (fix : Bool) (P : Params Req) (hP : Oracle.WF P) (s : St Req)
    (h : (lts fix P).Reachable s) (h1 : 1 ≤ P.maxKA) : s.ka ≤ P.maxKA := by
  have := (inv_reachable fix P hP s h).ka_le; omega

/-! ## Close header honoured (RFC 9112 §9.6) -/

/-- Spec: once a response carrying `Connection: close` has been queued, the
connection is committed to closing. -/
def CloseHonoured (s : St Req) : Prop :=
  ∀ o ∈ s.log, o.keepAlive = false → s.shouldClose = true

theorem closeHonoured_init : CloseHonoured (init : St Req) := by
  intro o ho; simp [init] at ho

theorem parse_peerEof (fix : Bool) (P : Params Req) (late : Bool) (s : St Req) :
    (parse fix P late s).peerEof = s.peerEof := by
  unfold parse; split
  · rfl
  · split
    · rfl
    · rfl
    · unfold dispatch; split
      · cases fix <;> rfl
      · split <;> rfl

/-- `parse` keeps `should_close` once it is set together with `peer_eof`
(the half-close path). -/
theorem parse_sc (fix : Bool) (P : Params Req) (late : Bool) (s : St Req)
    (h1 : s.shouldClose = true) (h2 : s.peerEof = true) :
    (parse fix P late s).shouldClose = true := by
  unfold parse; split
  · rfl
  · split
    · exact h1
    · rfl
    · unfold dispatch; split
      · cases fix
        · exact h1
        · rfl
      · split
        · simp [finalise, applyKA, h2]
        · rfl

theorem closeHonoured_parse (P : Params Req) (late : Bool) (s : St Req)
    (hc : CloseHonoured s) (hsp : s.shouldClose = true → s.peerEof = true) :
    CloseHonoured (parse true P late s) := by
  have hkeep : ∀ (s' : St Req), s'.shouldClose = true → CloseHonoured s' :=
    fun _ hs _ _ _ => hs
  unfold parse
  split
  · exact hkeep _ rfl
  · split
    · exact hc
    · exact hkeep _ rfl
    · unfold dispatch
      split
      · exact hkeep _ rfl
      · split
        · intro o ho hk
          simp only [finalise, List.mem_append, List.mem_singleton] at ho
          rcases ho with ho | rfl
          · simp [finalise, applyKA, hsp (hc o ho hk)]
          · have hb : ∀ b : Bool, (!b) = false → b = true := by decide
            exact hb _ hk
        · exact hkeep _ rfl

/-- With the APP-01 fix, `CloseHonoured` holds in every reachable state. -/
theorem closeHonoured_step (P : Params Req) (s : St Req) (e : Ev) (h : Inv P s)
    (hc : CloseHonoured s) (hpe : s.peerEof = true → s.shouldClose = true) :
    CloseHonoured (step true P s e) ∧
      ((step true P s e).peerEof = true → (step true P s e).shouldClose = true) := by
  unfold step
  split
  · exact ⟨hc, hpe⟩
  · rename_i hd; simp only [Bool.not_eq_true] at hd
    cases e with
    | arrive b => simp only [stepCH]; split <;> exact ⟨hc, hpe⟩
    | fin => exact ⟨hc, hpe⟩
    | readable late =>
      simp only [stepCH, onReadable]
      split
      · exact ⟨hc, hpe⟩
      · rename_i hph; simp only [ne_eq, Decidable.not_not] at hph
        split
        · exact ⟨fun _ _ _ => rfl, fun _ => rfl⟩
        · split
          · split
            · exact ⟨closeHonoured_parse P late _ (fun _ _ _ => rfl) (fun _ => rfl),
                fun _ => parse_sc true P late _ rfl rfl⟩
            · exact ⟨fun _ _ _ => rfl, fun _ => rfl⟩
          · rename_i hfin
            have hsc : s.shouldClose = false := by
              cases hsc : s.shouldClose
              · rfl
              · exact absurd (h.quiet hph hd hsc).1 (by simpa using hfin)
            have hpe0 : s.peerEof = false := by
              cases hp : s.peerEof
              · rfl
              · have := hpe hp; rw [hsc] at this; cases this
            refine ⟨closeHonoured_parse P late _ (fun o ho hk => hc o ho hk)
              (by intro hh; simp [hsc] at hh), ?_⟩
            intro hpe'
            rw [parse_peerEof] at hpe'
            simp [hpe0] at hpe'
    | writable n =>
      simp only [stepCH, onWritable]
      split
      · exact ⟨hc, hpe⟩
      · split
        · exact ⟨hc, hpe⟩
        · split
          · exact ⟨hc, hpe⟩
          · exact ⟨hc, hpe⟩
    | timeout => exact ⟨fun _ _ _ => rfl, fun _ => rfl⟩
    | ioError => exact ⟨fun _ _ _ => rfl, fun _ => rfl⟩

/-- **Fixed machine (APP-01 fix): no request after a `Connection: close`
response.** In every reachable state of the fixed machine, if some queued
response says `Connection: close`, then no future run dispatches another
request. -/
theorem fixed_no_request_after_close_header (P : Params Req) (hP : Oracle.WF P) (s : St Req)
    (h : (lts true P).Reachable s) :
    CloseHonoured s ∧
      ∀ o ∈ s.log, o.keepAlive = false → ∀ es, (run true P s es).segs = s.segs := by
  have key : ∀ s, (lts true P).Reachable s →
      Inv P s ∧ CloseHonoured s ∧ (s.peerEof = true → s.shouldClose = true) := by
    have hind : (lts true P).Inductive
        (fun s => Inv P s ∧ CloseHonoured s ∧ (s.peerEof = true → s.shouldClose = true)) := {
      init := by
        intro s hs; rw [hs]
        exact ⟨inv_init P, closeHonoured_init, by simp [init]⟩
      step := by
        intro s e s' ⟨hi, hc, hpe⟩ hs
        rw [lts_step_iff] at hs; rw [← hs]
        exact ⟨inv_step true P hP s e hi, closeHonoured_step P s e hi hc hpe⟩ }
    exact hind.reachable
  obtain ⟨hi, hc, -⟩ := key s h
  exact ⟨hc, fun o ho hk es => run_segs_frozen true P hP es s hi (hc o ho hk)⟩

/-! ## Body framing of a serialised response (RFC 9110 §6.4.1, §8.6; RFC 9112 §6.3) -/

namespace Framing

/-- `_wire_status`: 100-599, else 500.
mirrors flare/http/_reactor/write_path.mojo:151-155 @59bda50 -/
def wireStatus (st : Int) : Int := if st < 100 ∨ st > 599 then 500 else st

/-- What `serialize_response_into` emits: a `Content-Length` field (and
its value) and whether the body bytes follow the head.
mirrors flare/http/_reactor/write_path.mojo:222-235 @59bda50 -/
structure Emitted where
  emitLen : Bool
  lengthValue : Nat
  emitBody : Bool
  deriving DecidableEq, Repr

/-- mirrors flare/http/_reactor/write_path.mojo:222-235 @59bda50 -/
def serialize (status : Int) (bodyLen : Nat) (declared : Option Nat) (head lengthKnown : Bool) :
    Emitted :=
  let st := wireStatus status
  let noLenField := decide (st < 200) || decide (st = 204)
  let noContent := noLenField || head || decide (st = 304)
  let (lenValue, noLenField) :=
    if noContent then
      match declared with
      | some d => (d, noLenField)
      | none => (bodyLen, noLenField || !lengthKnown)
    else (bodyLen, noLenField)
  { emitLen := !noLenField, lengthValue := lenValue, emitBody := !noContent && decide (0 < bodyLen) }

/-- RFC 9110 §6.4.1 / RFC 9112 §6.3: responses to HEAD and 1xx, 204, 304
responses carry no content. -/
def NoContent (status : Int) (head : Bool) : Prop :=
  head = true ∨ status < 200 ∨ status = 204 ∨ status = 304

/-- Spec for the serialiser: no body for `NoContent`; no `Content-Length`
on 1xx/204 (RFC 9110 §8.6); otherwise the body is sent with its length. -/
theorem serialize_spec (status : Int) (bodyLen : Nat) (declared : Option Nat)
    (head lengthKnown : Bool) (hs : 100 ≤ status ∧ status ≤ 599) :
    let e := serialize status bodyLen declared head lengthKnown
    (NoContent status head → e.emitBody = false) ∧
    ((status < 200 ∨ status = 204) → e.emitLen = false) ∧
    (¬ NoContent status head → e.emitBody = decide (0 < bodyLen) ∧ e.emitLen = true ∧
      e.lengthValue = bodyLen) := by
  have hw : wireStatus status = status := by unfold wireStatus; split <;> omega
  simp only [serialize, hw, NoContent]
  refine ⟨?_, ?_, ?_⟩
  · intro h
    rcases h with h | h | h | h <;> simp [h]
  · intro h
    rcases h with h | h
    · have : decide (status < 200) = true := by simp [h]
      split <;> (try split) <;> simp [this]
    · split <;> (try split) <;> simp [h]
  · intro h
    simp only [not_or] at h
    obtain ⟨h1, h2, h3, h4⟩ := h
    have e1 : head = false := by simpa using h1
    simp [e1, h2, h3, h4]

/-- Which `head_request` flag each reactor path hands the serialiser:
the normal handler path passes `self.head_request`
(conn_handle.mojo:747-754); `_queue_error` → `_serialize_response` passes
the flag too (fixed, APP-05; pre-fix it passed nothing, default `False`).
mirrors flare/http/_reactor/conn_handle.mojo:747-754 and 1590-1620
(fixed, APP-05) -/
inductive Path | handler | errorReply
  deriving DecidableEq, Repr

/-- The flag as shipped (fixed, APP-05): `_serialize_response` passes
`self.head_request`, which is set from the parsed method and, for errors
raised before the request is parsed, from the buffered `HEAD ` prefix
(`_note_head_from_buf`). -/
def headFlag (_p : Path) (isHead : Bool) : Bool := isHead

/-- The pre-fix flags (APP-05): the error path ignored the method.
mirrors flare/http/_reactor/conn_handle.mojo:747-754,1576-1594 @59bda50 -/
def headFlagOld (p : Path) (isHead : Bool) : Bool :=
  match p with
  | .handler => isHead
  | .errorReply => false

/-- Spec for a whole path: a response to a HEAD request has no body. -/
def HeadSpec (f : Path → Bool → Bool) : Prop :=
  ∀ p status bodyLen declared lengthKnown, 100 ≤ status ∧ status ≤ 599 →
    (serialize status bodyLen declared (f p true) lengthKnown).emitBody = false

theorem headFlag_spec : HeadSpec headFlag := by
  intro p status bodyLen declared lk hs
  exact (serialize_spec status bodyLen declared true lk hs).1 (Or.inl rfl)

/-- The static fast path (fixed, APP-04): `on_readable_static` copies the
pre-encoded response, but for HEAD only the head (bytes up to the first
CRLFCRLF).
mirrors flare/http/_reactor/conn_handle.mojo:1174-1220 (fixed, APP-04) and
flare/http/_reactor/write_path.mojo:107-175 (fixed, APP-04) -/
def staticBytes (head body : Bytes) (isHead : Bool) : Bytes :=
  if isHead then head else head ++ body

/-- The pre-fix static path (APP-04): it copied head and body whatever the
method. Kept so the counterexample in `Flare.Bugs.APP_04` stays checkable.
mirrors flare/http/_reactor/conn_handle.mojo:1174-1211 @59bda50 -/
def staticBytesOld (head body : Bytes) (_isHead : Bool) : Bytes := head ++ body

/-- Spec: the bytes queued for HEAD are exactly the head. -/
def StaticHeadSpec (f : Bytes → Bytes → Bool → Bytes) : Prop :=
  ∀ head body, f head body true = head

theorem staticBytes_spec : StaticHeadSpec staticBytes := by
  intro head body; simp [staticBytes]

theorem staticBytes_get (head body : Bytes) :
    staticBytes head body false = head ++ body := by simp [staticBytes]

end Framing

end Flare.L4.ConnSM
