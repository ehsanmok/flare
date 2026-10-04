import Flare.L4_App.ConnSM

/-!
# Streaming response bodies and TLS cross-interest in the connection machine

Two parts of `ConnHandle` that `ConnSM` leaves out.

## Streaming bodies (`Stream`)

A handler that returns a streaming `Response` hands its chunk source to the
connection (`_finalise_response`, flare/http/_reactor/conn_handle.mojo:
731-743): `write_buf` holds the chunked head, `body_src` the source.
`on_writable` (1262-1351) flushes, and while the source is attached and the
buffer is empty refills it with `_stream_refill` (1605-1642): up to
`STREAM_BATCH_CHUNKS` chunks or `STREAM_BATCH_BYTES` bytes, framed with
`frame_chunk_into`; an empty chunk ends the batch ("alive but idle"); end of
stream queues the terminator and drops the source; a raising source closes
the connection. At most `STREAM_EDGE_PASSES` passes run per writable edge.

The source is a list of poll results (`Poll`), consumed one per
`next()` call; `data []` is an idle poll. Chunk framing and the terminator
are parameters (L3). The kernel accepts at most `k` bytes per writable
event (`k = 0` is EAGAIN on the first send).

* `inv_onWritable`: `Inv` is preserved. It says the wire followed by the
  unsent rest of `write_buf` is exactly the head followed by the rendering
  of the polls consumed so far, in source order; the consumed polls and the
  remaining source tile the original source; and once the stream is back in
  STATE_READING the terminator has been consumed and everything is on the
  wire.
* `wire_exact_at_end`: back in STATE_READING, the wire is exactly the head,
  the framed non-empty chunks in source order, then the terminator.
* `interest`: while the handle is still writing and not done the step asks
  for writability only; it never returns with no interest unless done.

## TLS cross-interest (`Tls`)

`SSL_read` may need the socket writable (`SSL_IO_WANT_WRITE`,
conn_handle.mojo:501-507) and `SSL_write` may need it readable
(`SSL_IO_WANT_READ`, 1231-1235). Both set `tls_cross_interest` and arm read
and write. The reactor clears the flag and sends an edge to the read driver
when it is readable, or writable with the flag set
(flare/http/_unified_reactor_impl.mojo:812-826); the read driver's
`on_readable` returns `want_write` in STATE_WRITING (conn_handle.mojo:
776-779) and the inline cycle then runs `on_writable`
(_unified_reactor_impl.mojo:184-190). The TLS layer is an oracle: each edge
carries the plaintext `SSL_read` returns before it stops and why it stops,
and how many bytes `SSL_write` takes before it stops and why.

* `blocked_interest`: whenever the pending operation stops on the opposite
  direction, the flag is set and both interests are armed.
* `retry_read`, `retry_write`: with the flag set, an edge of either kind
  retries the blocked operation (`SSL_read` while reading, `SSL_write`
  while writing).
* `read_fifo`, `inv_route`: plaintext is appended to `read_buf` in the order
  `SSL_read` returns it, and the wire is always the response prefix up to
  `write_pos`.
* `interest_nonempty`: after any routed edge a live handle has some
  interest armed, and while a response is unsent it has write interest.
-/
namespace Flare.L4.ConnStream

open Flare.L4.ConnSM (Phase)

namespace Stream

inductive Poll
  | data (b : Bytes)
  | eos
  | fail
  deriving DecidableEq, Repr

structure Params where
  frame : Bytes → Bytes
  term : Bytes
  maxChunks : Nat
  maxBytes : Nat
  passes : Nat

/-- Bytes a consumed poll puts on the wire. -/
def render (p : Params) : Poll → Bytes
  | .data b => if b = [] then [] else p.frame b
  | .eos => p.term
  | .fail => []

def renderAll (p : Params) (l : List Poll) : Bytes := (l.map (render p)).flatten

/-- The batch loop of `_stream_refill`, from `framed` chunks and buffer
`buf`: `none` when the source raises, else the new buffer, the rest of the
source, whether the source is still attached, and the polls consumed.
mirrors flare/http/_reactor/conn_handle.mojo:1621-1642 @59bda50 -/
def batch (p : Params) : Nat → Bytes → List Poll → Option (Bytes × List Poll × Bool × List Poll)
  | _, buf, [] => some (buf, [], true, [])
  | framed, buf, q :: rest =>
    if framed < p.maxChunks ∧ buf.length < p.maxBytes then
      match q with
      | .eos => some (buf ++ p.term, rest, false, [.eos])
      | .fail => none
      | .data b =>
        if b = [] then some (buf, rest, true, [.data b])
        else match batch p (framed + 1) (buf ++ p.frame b) rest with
          | some (buf', rest', live', seen') => some (buf', rest', live', .data b :: seen')
          | none => none
    else some (buf, q :: rest, true, [])

theorem batch_spec (p : Params) : ∀ (src : List Poll) (framed : Nat) (buf : Bytes) buf' rest live seen,
    batch p framed buf src = some (buf', rest, live, seen) →
      src = seen ++ rest ∧ buf' = buf ++ renderAll p seen ∧ (live = false → Poll.eos ∈ seen)
  | [], framed, buf, buf', rest, live, seen, h => by
    simp only [batch, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl, rfl, rfl⟩ := h
    simp [renderAll]
  | q :: src, framed, buf, buf', rest, live, seen, h => by
    simp only [batch] at h
    split at h
    · split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl, rfl, rfl⟩ := h
        simp [renderAll, render]
      · cases h
      · rename_i b
        split at h
        · rename_i hb
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl, rfl, rfl⟩ := h
          simp [renderAll, render, hb]
        · rename_i hb
          split at h
          · rename_i buf2 rest2 live2 seen2 hrec
            simp only [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl, rfl, rfl⟩ := h
            obtain ⟨h1, h2, h3⟩ := batch_spec p src (framed + 1) _ _ _ _ _ hrec
            refine ⟨by simp [h1], ?_, fun hl => List.mem_cons_of_mem _ (h3 hl)⟩
            simp [h2, renderAll, render, hb]
          · cases h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl, rfl⟩ := h
      simp [renderAll]

structure St where
  phase : Phase
  wbuf : Bytes
  wpos : Nat
  src : List Poll
  live : Bool
  shouldClose : Bool
  done : Bool
  /-- ghost: bytes sent -/
  wire : Bytes
  /-- ghost: polls consumed, in order -/
  seen : List Poll

/-- `StepResult` interest bits. -/
structure Res where
  wantRead : Bool
  wantWrite : Bool
  done : Bool

/-- Flush complete and no source: close or back to keep-alive reading.
mirrors flare/http/_reactor/conn_handle.mojo:1364-1375 @59bda50 -/
def finish (s : St) : St × Res :=
  if s.shouldClose then ({ s with phase := .closing, done := true }, ⟨false, false, true⟩)
  else ({ s with phase := .reading }, ⟨true, false, false⟩)

/-- The flush/refill loop of `on_writable` with `fuel` refills left in this
edge and `budget` bytes the kernel still accepts.
mirrors flare/http/_reactor/conn_handle.mojo:1286-1351 @59bda50 -/
def wloop (p : Params) : Nat → Nat → St → St × Res
  | fuel, budget, s =>
    let x := min budget (s.wbuf.length - s.wpos)
    let s1 := { s with wpos := s.wpos + x, wire := s.wire ++ (s.wbuf.drop s.wpos).take x }
    if s1.wpos < s1.wbuf.length then (s1, ⟨false, true, false⟩)
    else
      let s2 := { s1 with wbuf := [], wpos := 0 }
      if !s2.live then finish s2
      else match fuel with
        | 0 => (s2, ⟨false, true, false⟩)
        | f + 1 =>
          match batch p 0 [] s2.src with
          | none => ({ s2 with shouldClose := true, done := true, phase := .closing },
                     ⟨false, false, true⟩)
          | some (buf, rest, live, seen) =>
            let s3 := { s2 with wbuf := buf, wpos := 0, src := rest, live := live,
                                seen := s2.seen ++ seen }
            if live && buf.isEmpty then (s3, ⟨false, true, false⟩)
            else wloop p f (budget - x) s3

/-- `on_writable` (cleartext) with a possibly attached chunk source.
mirrors flare/http/_reactor/conn_handle.mojo:1262-1375 @59bda50 -/
def onWritable (p : Params) (k : Nat) (s : St) : St × Res :=
  if s.phase ≠ .writing then (s, ⟨decide (s.phase = .reading), false, false⟩)
  else wloop p (p.passes - 1) k s

/-- The state `_finalise_response` leaves for a streaming response: the
chunked head queued, the source attached. -/
def start (head : Bytes) (src : List Poll) (sc : Bool) : St :=
  ⟨.writing, head, 0, src, true, sc, false, [], []⟩

structure Inv (p : Params) (head : Bytes) (orig : List Poll) (s : St) : Prop where
  bytes : s.wire ++ s.wbuf.drop s.wpos = head ++ renderAll p s.seen
  tile : s.seen ++ s.src = orig
  wpos_le : s.wpos ≤ s.wbuf.length
  ended : s.live = false → Poll.eos ∈ s.seen
  reading : s.phase = .reading → s.live = false ∧ s.wbuf = [] ∧ s.wpos = 0

theorem inv_start (p : Params) (head : Bytes) (src : List Poll) (sc : Bool) :
    Inv p head src (start head src sc) :=
  ⟨by simp [start, renderAll], by simp [start], by simp [start], by simp [start],
   by simp [start]⟩

theorem inv_finish (p : Params) (head : Bytes) (orig : List Poll) (s : St) (h : Inv p head orig s)
    (hl : s.live = false) (hw : s.wbuf = [] ∧ s.wpos = 0) : Inv p head orig (finish s).1 := by
  unfold finish
  split
  · exact ⟨h.bytes, h.tile, h.wpos_le, h.ended, fun hp => by simp at hp⟩
  · exact ⟨h.bytes, h.tile, h.wpos_le, h.ended, fun _ => ⟨hl, hw⟩⟩

theorem inv_emptied (p : Params) (head : Bytes) (orig : List Poll) (budget : Nat) (s : St)
    (hph : s.phase = .writing) (h : Inv p head orig s)
    (hge : ¬ s.wpos + min budget (s.wbuf.length - s.wpos) < s.wbuf.length) :
    Inv p head orig { s with wbuf := [], wpos := 0, wire := s.wire ++ (s.wbuf.drop s.wpos).take (min budget (s.wbuf.length - s.wpos)) } := by
  have hsent : s.wire ++ (s.wbuf.drop s.wpos).take (min budget (s.wbuf.length - s.wpos)) ++
      s.wbuf.drop (s.wpos + min budget (s.wbuf.length - s.wpos)) = head ++ renderAll p s.seen := by
    rw [← h.bytes, List.append_assoc, ← List.drop_drop, List.take_append_drop]
  have hwl := h.wpos_le
  have hnil : s.wbuf.drop (s.wpos + min budget (s.wbuf.length - s.wpos)) = [] :=
    List.drop_eq_nil_of_le (by omega)
  rw [hnil, List.append_nil] at hsent
  exact ⟨by simpa using hsent, h.tile, by simp, h.ended, fun hp => by simp [hph] at hp⟩

theorem inv_partial (p : Params) (head : Bytes) (orig : List Poll) (budget : Nat) (s : St)
    (hph : s.phase = .writing) (h : Inv p head orig s)
    (hlt : s.wpos + min budget (s.wbuf.length - s.wpos) < s.wbuf.length) :
    Inv p head orig { s with wpos := s.wpos + min budget (s.wbuf.length - s.wpos), wire := s.wire ++ (s.wbuf.drop s.wpos).take (min budget (s.wbuf.length - s.wpos)) } := by
  have hsent : s.wire ++ (s.wbuf.drop s.wpos).take (min budget (s.wbuf.length - s.wpos)) ++
      s.wbuf.drop (s.wpos + min budget (s.wbuf.length - s.wpos)) = head ++ renderAll p s.seen := by
    rw [← h.bytes, List.append_assoc, ← List.drop_drop, List.take_append_drop]
  exact ⟨by simpa using hsent, h.tile, by simp; omega, h.ended, fun hp => by simp [hph] at hp⟩

theorem inv_refilled (p : Params) (head : Bytes) (orig : List Poll) (s : St)
    (hph : s.phase = .writing) (h : Inv p head orig s) (hw : s.wbuf = [] ∧ s.wpos = 0)
    (buf : Bytes) (rest : List Poll) (live : Bool) (seen : List Poll)
    (hbat : batch p 0 [] s.src = some (buf, rest, live, seen)) :
    Inv p head orig { s with wbuf := buf, wpos := 0, src := rest, live := live, seen := s.seen ++ seen } := by
  obtain ⟨h1, h2, h3⟩ := batch_spec p _ 0 [] buf rest live seen hbat
  have hb := h.bytes
  rw [hw.1, hw.2] at hb
  refine ⟨?_, ?_, by simp, ?_, fun hp => by simp [hph] at hp⟩
  · simp only [List.drop_zero]
    rw [h2]
    simp only [List.drop_nil, List.append_nil] at hb
    simp [hb, renderAll, List.append_assoc]
  · simp only [List.append_assoc]; rw [← h1]; exact h.tile
  · intro hl'; exact List.mem_append_right _ (h3 hl')

theorem inv_wloop (p : Params) (head : Bytes) (orig : List Poll) :
    ∀ fuel budget (s : St), s.phase = .writing → Inv p head orig s →
      Inv p head orig (wloop p fuel budget s).1 := by
  intro fuel
  induction fuel with
  | zero =>
    intro budget s hph h
    rw [wloop]; dsimp only
    split
    · exact inv_partial p head orig budget s hph h (by assumption)
    · rename_i hge
      have hb2 := inv_emptied p head orig budget s hph h hge
      split
      · rename_i hl
        exact inv_finish p head orig _ hb2 (by simpa using hl) ⟨rfl, rfl⟩
      · exact hb2
  | succ f ih =>
    intro budget s hph h
    rw [wloop]; dsimp only
    split
    · exact inv_partial p head orig budget s hph h (by assumption)
    · rename_i hge
      have hb2 := inv_emptied p head orig budget s hph h hge
      split
      · rename_i hl
        exact inv_finish p head orig _ hb2 (by simpa using hl) ⟨rfl, rfl⟩
      · split
        · exact ⟨hb2.bytes, hb2.tile, hb2.wpos_le, hb2.ended, fun hp => by simp at hp⟩
        · rename_i buf rest live seen hbat
          have hb3 := inv_refilled p head orig _ (by simp [hph]) hb2 ⟨rfl, rfl⟩ buf rest live seen hbat
          split
          · exact hb3
          · exact ih _ _ (by simp [hph]) hb3

theorem inv_onWritable (p : Params) (head : Bytes) (orig : List Poll) (k : Nat) (s : St)
    (h : Inv p head orig s) : Inv p head orig (onWritable p k s).1 := by
  unfold onWritable
  split
  · exact h
  · rename_i hph
    exact inv_wloop p head orig _ _ _ (by simpa using hph) h

/-- **No loss, no reordering.** Back in STATE_READING, the bytes sent are
exactly the chunked head, then every non-empty chunk the source produced,
framed, in order, then the terminator; the polls consumed are a prefix of
the source and include end-of-stream. -/
theorem wire_exact_at_end (p : Params) (head : Bytes) (orig : List Poll) (s : St)
    (h : Inv p head orig s) (hr : s.phase = .reading) :
    s.wire = head ++ renderAll p s.seen ∧ s.seen <+: orig ∧ Poll.eos ∈ s.seen := by
  obtain ⟨hl, hw, hp⟩ := h.reading hr
  refine ⟨?_, ⟨s.src, h.tile⟩, h.ended hl⟩
  have := h.bytes
  rw [hw, hp] at this
  simpa using this

/-- At every point the bytes sent are a prefix of head plus the rendering of
the whole source. -/
theorem wire_prefix (p : Params) (head : Bytes) (orig : List Poll) (s : St)
    (h : Inv p head orig s) : s.wire <+: head ++ renderAll p orig := by
  have hb := h.bytes
  have ht := h.tile
  refine ⟨s.wbuf.drop s.wpos ++ renderAll p s.src, ?_⟩
  rw [← List.append_assoc, hb, ← ht]
  simp [renderAll, List.append_assoc]

theorem finish_interest (s : St) :
    let r := finish s
    (r.2.done = false → r.1.phase = .writing → r.2.wantWrite = true ∧ r.2.wantRead = false) ∧
    (r.2.done = false → r.1.phase = .reading → r.2.wantRead = true) ∧
    (r.2.done = true → r.1.done = true ∧ r.1.shouldClose = true) ∧
    (r.1.phase ≠ .writing → r.2.wantWrite = false) := by
  unfold finish
  split
  · rename_i hsc; simp [hsc]
  · simp

theorem wloop_interest (p : Params) :
    ∀ fuel budget (s : St), s.phase = .writing →
      let r := wloop p fuel budget s
      (r.2.done = false → r.1.phase = .writing → r.2.wantWrite = true ∧ r.2.wantRead = false) ∧
      (r.2.done = false → r.1.phase = .reading → r.2.wantRead = true) ∧
      (r.2.done = true → r.1.done = true ∧ r.1.shouldClose = true) ∧
      (r.1.phase ≠ .writing → r.2.wantWrite = false) := by
  intro fuel
  induction fuel with
  | zero =>
    intro budget s hph
    rw [wloop]; dsimp only
    split
    · simp [hph]
    · split
      · exact finish_interest _
      · simp [hph]
  | succ f ih =>
    intro budget s hph
    rw [wloop]; dsimp only
    split
    · simp [hph]
    · split
      · exact finish_interest _
      · split
        · simp
        · split
          · simp [hph]
          · exact ih _ _ (by simp [hph])

/-- **Interest.** After `on_writable` on a writing handle: still writing and
not done means write interest only; back to reading means read interest;
done means `should_close`; never write interest outside STATE_WRITING. -/
theorem interest (p : Params) (k : Nat) (s : St) (hph : s.phase = .writing) :
    let r := onWritable p k s
    (r.2.done = false → r.1.phase = .writing → r.2.wantWrite = true ∧ r.2.wantRead = false) ∧
    (r.2.done = false → r.1.phase = .reading → r.2.wantRead = true) ∧
    (r.2.done = true → r.1.done = true ∧ r.1.shouldClose = true) := by
  have := wloop_interest p (p.passes - 1) k s hph
  simp only [onWritable, hph, ne_eq, not_true_eq_false, if_false]
  exact ⟨this.1, this.2.1, this.2.2.1⟩

end Stream

namespace Tls

/-- Why `SSL_read` stopped. -/
inductive RStop | wantRead | wantWrite | closed
  deriving DecidableEq, Repr

/-- Why `SSL_write` stopped (only consulted when bytes remain). -/
inductive WStop | wantWrite | wantRead
  deriving DecidableEq, Repr

/-- One reactor edge: its kind, and the TLS oracle's answers if the
handle calls into it. -/
structure Edge where
  readable : Bool
  writable : Bool
  plain : Bytes
  rstop : RStop
  sent : Nat
  wstop : WStop

structure St where
  phase : Phase
  cross : Bool
  rbuf : Bytes
  wbuf : Bytes
  wpos : Nat
  wantR : Bool
  wantW : Bool
  done : Bool
  /-- ghost: plaintext received -/
  inp : Bytes
  /-- ghost: plaintext sent -/
  wire : Bytes

/-- `_drain_recv_tls`: append the plaintext; on WANT_WRITE set the flag and
arm both; on close_notify finish (the half-close rule is in `ConnSM`).
mirrors flare/http/_reactor/conn_handle.mojo:479-520 @59bda50 -/
def drain (s : St) (e : Edge) : St :=
  let s1 := { s with rbuf := s.rbuf ++ e.plain, inp := s.inp ++ e.plain }
  match e.rstop with
  | .wantRead => { s1 with wantR := true, wantW := false }
  | .wantWrite => { s1 with cross := true, wantR := true, wantW := true }
  | .closed => { s1 with done := true }

/-- `_flush_write_buf_tls` plus the partial / flushed handling of
`on_writable`: on WANT_READ set the flag and arm both.
mirrors flare/http/_reactor/conn_handle.mojo:1213-1240,1314-1375 @59bda50 -/
def flush (s : St) (e : Edge) : St :=
  let x := min e.sent (s.wbuf.length - s.wpos)
  let s1 := { s with wpos := s.wpos + x, wire := s.wire ++ (s.wbuf.drop s.wpos).take x }
  if s1.wpos < s1.wbuf.length then
    match e.wstop with
    | .wantWrite => { s1 with wantR := false, wantW := true }
    | .wantRead => { s1 with cross := true, wantR := true, wantW := true }
  else { s1 with phase := .reading, wbuf := [], wpos := 0, wantR := true, wantW := false }

/-- `_drive_h1`: `on_readable` drains while reading; while writing it
returns `want_write` and the inline cycle runs `on_writable`.
mirrors flare/http/_unified_reactor_impl.mojo:174-190 @59bda50,
flare/http/_reactor/conn_handle.mojo:776-779 @59bda50 -/
def readDriver (s : St) (e : Edge) : St :=
  match s.phase with
  | .reading => drain s e
  | .writing => flush s e
  | .closing => s

/-- `_drive_h1_writable`: `on_writable`; outside STATE_WRITING it only
re-arms read.
mirrors flare/http/_unified_reactor_impl.mojo:243-258 @59bda50 -/
def writeDriver (s : St) (e : Edge) : St :=
  match s.phase with
  | .writing => flush s e
  | _ => { s with wantR := decide (s.phase = .reading), wantW := false }

/-- The reactor's KIND_H1 dispatch: clear the flag, then the read driver on
a readable edge or on a writable edge with the flag set, else the write
driver on a writable edge.
mirrors flare/http/_unified_reactor_impl.mojo:812-831 @59bda50 -/
def route (s : St) (e : Edge) : St :=
  if s.done then s
  else
    let s0 := { s with cross := false }
    if e.readable || (s.cross && e.writable) then readDriver s0 e
    else if e.writable then writeDriver s0 e
    else s

structure Inv (s : St) : Prop where
  wpos_le : s.wpos ≤ s.wbuf.length
  wire : s.wire = s.wbuf.take s.wpos ∨ s.phase ≠ .writing
  some_interest : s.done = false → s.wantR = true ∨ s.wantW = true
  write_armed : s.done = false → s.phase = .writing → s.wpos < s.wbuf.length →
    s.wantW = true
  closing : s.phase = .closing → s.done = true

/-- **Blocked on the opposite direction ⇒ flag and both interests.** -/
theorem blocked_interest (s : St) (e : Edge) :
    (s.phase = .reading → e.rstop = .wantWrite → s.done = false →
      let t := drain s e; t.cross = true ∧ t.wantR = true ∧ t.wantW = true) ∧
    (s.wpos + min e.sent (s.wbuf.length - s.wpos) < s.wbuf.length → e.wstop = .wantRead →
      let t := flush s e; t.cross = true ∧ t.wantR = true ∧ t.wantW = true) := by
  refine ⟨fun _ hr _ => by simp [drain, hr], fun hlt hw => ?_⟩
  simp only [flush]
  rw [if_pos (by simpa using hlt), hw]
  simp

/-- **Either edge retries a blocked read.** With the flag set while
reading, a readable or a writable edge calls `SSL_read` again. -/
theorem retry_read (s : St) (e : Edge) (hd : s.done = false) (hc : s.cross = true)
    (hph : s.phase = .reading) (he : e.readable = true ∨ e.writable = true) :
    route s e = drain { s with cross := false } e := by
  unfold route
  have : (e.readable || (s.cross && e.writable)) = true := by
    rcases he with h | h <;> simp [h, hc]
  simp [hd, this, readDriver, hph]

/-- **Either edge retries a blocked write.** While writing, a readable
edge, or a writable edge with the flag set, reaches `SSL_write` through
the read driver; a writable edge without the flag reaches it through the
write driver. -/
theorem retry_write (s : St) (e : Edge) (hd : s.done = false) (hph : s.phase = .writing)
    (he : e.readable = true ∨ e.writable = true) :
    route s e = flush { s with cross := false } e := by
  unfold route
  simp only [hd, Bool.false_eq_true, if_false]
  split
  · simp [readDriver, hph]
  · rename_i hn
    have hw : e.writable = true := by
      rcases he with h | h
      · simp [h] at hn
      · exact h
    simp [hw, writeDriver, hph]

/-- **Plaintext FIFO.** Reading appends exactly what `SSL_read` returned. -/
theorem read_fifo (s : St) (e : Edge) (hd : s.done = false) (hph : s.phase = .reading)
    (he : e.readable = true ∨ (s.cross = true ∧ e.writable = true)) :
    (route s e).rbuf = s.rbuf ++ e.plain ∧ (route s e).inp = s.inp ++ e.plain := by
  unfold route
  have : (e.readable || (s.cross && e.writable)) = true := by
    rcases he with h | ⟨h1, h2⟩ <;> simp [*]
  simp only [hd, Bool.false_eq_true, if_false, this, if_true, readDriver, hph]
  unfold drain; split <;> simp

theorem inv_flush (s : St) (e : Edge) (h : Inv s) (hph : s.phase = .writing) :
    Inv (flush s e) := by
  have hw : s.wire = s.wbuf.take s.wpos := by
    rcases h.wire with h1 | h1
    · exact h1
    · exact absurd hph h1
  have hcat : s.wire ++ (s.wbuf.drop s.wpos).take (min e.sent (s.wbuf.length - s.wpos)) =
      s.wbuf.take (s.wpos + min e.sent (s.wbuf.length - s.wpos)) := by
    rw [hw, List.take_add]
  unfold flush
  dsimp only
  split
  · rename_i hlt
    split
    · exact ⟨by simp; omega, Or.inl (by simpa using hcat), fun _ => Or.inr rfl,
        fun _ _ _ => rfl, fun hp => by simp [hph] at hp⟩
    · exact ⟨by simp; omega, Or.inl (by simpa using hcat), fun _ => Or.inr rfl,
        fun _ _ _ => rfl, fun hp => by simp [hph] at hp⟩
  · exact ⟨by simp, Or.inr (by simp), fun _ => Or.inl rfl, fun _ hp => by simp at hp,
      fun hp => by simp at hp⟩

theorem inv_drain (s : St) (e : Edge) (h : Inv s) (hph : s.phase = .reading) :
    Inv (drain s e) := by
  unfold drain
  split
  · exact ⟨h.wpos_le, Or.inr (by simp [hph]), fun _ => Or.inl rfl, fun _ hp => by simp [hph] at hp,
      fun hp => by simp [hph] at hp⟩
  · exact ⟨h.wpos_le, Or.inr (by simp [hph]), fun _ => Or.inl rfl, fun _ hp => by simp [hph] at hp,
      fun hp => by simp [hph] at hp⟩
  · exact ⟨h.wpos_le, Or.inr (by simp [hph]), fun hd => by simp at hd,
      fun hd => by simp at hd, fun _ => rfl⟩

theorem inv_readDriver (s : St) (e : Edge) (h : Inv s) : Inv (readDriver s e) := by
  cases hp : s.phase
  · have : readDriver s e = drain s e := by simp [readDriver, hp]
    rw [this]; exact inv_drain s e h hp
  · have : readDriver s e = flush s e := by simp [readDriver, hp]
    rw [this]; exact inv_flush s e h hp
  · have : readDriver s e = s := by simp [readDriver, hp]
    rw [this]; exact h

theorem inv_writeDriver (s : St) (e : Edge) (h : Inv s) (hd : s.done = false) :
    Inv (writeDriver s e) := by
  cases hp : s.phase
  · have : writeDriver s e = { s with wantR := true, wantW := false } := by
      simp [writeDriver, hp]
    rw [this]
    exact ⟨h.wpos_le, Or.inr (by simp [hp]), fun _ => Or.inl rfl,
      fun _ hq => by simp [hp] at hq, fun hq => by simp [hp] at hq⟩
  · have : writeDriver s e = flush s e := by simp [writeDriver, hp]
    rw [this]; exact inv_flush s e h hp
  · exact absurd (h.closing hp) (by simp [hd])

/-- `Inv` holds after every routed edge: the wire is the response prefix
up to `write_pos`, a live handle always has some interest armed, and an
unsent response always has write interest. -/
theorem inv_route (s : St) (e : Edge) (h : Inv s) : Inv (route s e) := by
  unfold route
  split
  · exact h
  · rename_i hd
    have hd' : s.done = false := by simpa using hd
    have h0 : Inv { s with cross := false } :=
      ⟨h.wpos_le, h.wire, h.some_interest, h.write_armed, h.closing⟩
    split
    · exact inv_readDriver _ e h0
    · split
      · exact inv_writeDriver _ e h0 hd'
      · exact h

theorem interest_nonempty (s : St) (e : Edge) (h : Inv s) (hd : (route s e).done = false) :
    ((route s e).wantR = true ∨ (route s e).wantW = true) ∧
    ((route s e).phase = .writing → (route s e).wpos < (route s e).wbuf.length →
      (route s e).wantW = true) := by
  have hi := inv_route s e h
  exact ⟨hi.some_interest hd, hi.write_armed hd⟩

end Tls

end Flare.L4.ConnStream
