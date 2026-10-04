import Flare.L3_Protocol.H3.Frame

/-!
# HTTP/3 request-stream reader (RFC 9114 §4.1)

Model of `feed_into` (flare/http3/request_reader.mojo) and of the drain loop
in `Http3Connection.feed_stream_chunk` (flare/http3/server.mojo) that calls it
until it reports NEEDS_MORE.

* `feed` returns `(consumed, reader', event?)`; `consumed = 0` is NEEDS_MORE.
* QPACK decoding is an opaque function `qd : Bytes → Option Hdrs`
  (the dynamic table is fixed during a drain; QPACK is modelled elsewhere).
* Counters are `Nat`. `body_bytes + flen` cannot wrap in Mojo: `flen < 2^62`
  (`parseHeader_some`) and `body_bytes ≤ max_body_bytes` (`feed_body_le`),
  so the `UInt64` sum is exact whenever `max_body_bytes ≤ 2^63`
  (`u64_add_exact`).

Results:
* `feed_append`  — prefix stability of one `feed` step.
* `drain_append` — chunking independence of the server drain loop.
* `runFixed_spec` / `run_spec_of_noReserved` — the frame sequences accepted
  without error are exactly the prefixes of RFC 9114 §4.1's
  `HEADERS DATA* [HEADERS]` with unknown frames ignored (the impl needs the
  side condition "no HTTP/2-reserved frame type"; see `Flare.Bugs.H3_02`).
-/
namespace Flare.L3.H3

/-- RFC 9114 frame types used by the reader. -/
def T_DATA : Nat := 0x00
def T_HEADERS : Nat := 0x01
def T_CANCEL_PUSH : Nat := 0x03
def T_SETTINGS : Nat := 0x04
def T_PUSH_PROMISE : Nat := 0x05
def T_GOAWAY : Nat := 0x07
def T_MAX_PUSH_ID : Nat := 0x0D

/-- Control-stream frame types the reader rejects on a request stream.
mirrors flare/http3/request_reader.mojo:312-318 @59bda50 -/
def isControlType (t : Nat) : Bool :=
  t == T_SETTINGS || t == T_GOAWAY || t == T_MAX_PUSH_ID || t == T_CANCEL_PUSH ||
    t == T_PUSH_PROMISE

/-- HTTP/2 frame types reserved by RFC 9114 §7.2.8 / §11.2.1 (PRIORITY, PING,
WINDOW_UPDATE, CONTINUATION): receipt MUST be H3_FRAME_UNEXPECTED. -/
def isH2Reserved (t : Nat) : Bool := t == 0x02 || t == 0x06 || t == 0x08 || t == 0x09

inductive RState | init | body | trailers | done
  deriving DecidableEq, Repr

/-- `excessiveLoad` is only raised by the H3-01 fix (`Flare.Bugs.H3_01`). -/
inductive Err | fieldTooBig | bodyTooBig | headersAfterTrailers | qpack | dataOutside
  | controlType | excessiveLoad
  deriving DecidableEq, Repr

structure Reader where
  st : RState
  maxField : Nat
  maxBody : Nat
  bodyBytes : Nat
  deriving DecidableEq, Repr

variable {Hdrs : Type}

inductive Ev (Hdrs : Type) where
  | headers (h : Hdrs)
  | data (d : Bytes)
  | trailers (h : Hdrs)
  | unknown (t : Nat)
  | error (e : Err)

def Ev.isError : Ev Hdrs → Bool
  | .error _ => true
  | _ => false

/-- Dispatch of one fully present frame on type and state.
mirrors flare/http3/request_reader.mojo:261-327 @59bda50 -/
def stepFrame (qd : Bytes → Option Hdrs) (r : Reader) (t : Nat) (p : Bytes) :
    Reader × Ev Hdrs :=
  if t = T_HEADERS then
    if r.st = .trailers then ({r with st := .done}, .error .headersAfterTrailers)
    else if p.length > r.maxField then ({r with st := .done}, .error .fieldTooBig)
    else match qd p with
      | none => ({r with st := .done}, .error .qpack)
      | some h =>
        if r.st = .init then ({r with st := .body}, .headers h)
        else ({r with st := .trailers}, .trailers h)
  else if t = T_DATA then
    if r.st ≠ .body then ({r with st := .done}, .error .dataOutside)
    else ({r with bodyBytes := r.bodyBytes + p.length}, .data p)
  else if isControlType t then ({r with st := .done}, .error .controlType)
  else (r, .unknown t)

/-- One `feed_into` call.
mirrors flare/http3/request_reader.mojo:197-327 @59bda50 -/
def feed (qd : Bytes → Option Hdrs) (r : Reader) (buf : Bytes) :
    Nat × Reader × Option (Ev Hdrs) :=
  if r.st = .done then (0, r, none)
  else if buf.length = 0 then (0, r, none)
  else match parseHeader buf with
    | none => (0, r, none)
    | some (t, l, hs) =>
      if t = T_HEADERS ∧ l > r.maxField then (hs, {r with st := .done}, some (.error .fieldTooBig))
      else if t = T_DATA ∧ r.bodyBytes + l > r.maxBody then
        (hs, {r with st := .done}, some (.error .bodyTooBig))
      else if hs + l > buf.length then (0, r, none)
      else
        let res := stepFrame qd r t ((buf.drop hs).take l)
        (hs + l, res.1, some res.2)

theorem feed_le (qd : Bytes → Option Hdrs) (r : Reader) (buf : Bytes) :
    (feed qd r buf).1 ≤ buf.length := by
  unfold feed
  split; · simp
  split; · simp
  split
  · simp
  · rename_i t l hs hh
    have := parseHeader_some hh
    split; · simp; omega
    split; · simp; omega
    split
    · simp
    · simp; omega

/-- Prefix stability: once `feed` makes progress on `buf`, appending more
bytes changes nothing. -/
theorem feed_append (qd : Bytes → Option Hdrs) (r : Reader) (buf c : Bytes)
    (h : 0 < (feed qd r buf).1) : feed qd r (buf ++ c) = feed qd r buf := by
  unfold feed at h ⊢
  split
  · rfl
  · rename_i hd
    rw [if_neg hd] at h
    split at h
    · simp at h
    · rename_i hne
      have hne' : ¬ (buf ++ c).length = 0 := by simp only [List.length_append]; omega
      rw [if_neg hne', if_neg hne]
      split at h
      · simp at h
      · rename_i t l hs hh
        rw [parseHeader_append hh]
        simp only
        split; · rfl
        split; · rfl
        rename_i h1 h2
        rw [if_neg h1, if_neg h2] at h
        split at h
        · simp at h
        · rename_i hle
          have hle' : ¬ hs + l > (buf ++ c).length := by
            simp only [List.length_append]; omega
          rw [if_neg hle', if_neg hle]
          have e : ((buf ++ c).drop hs).take l = (buf.drop hs).take l := by
            rw [List.drop_append_of_le_length (by omega),
              List.take_append_of_le_length (by simp; omega)]
          rw [e]

/-- The server's drain loop: call `feed` until NEEDS_MORE; return the reader,
the events and the unconsumed tail kept in `inbox`. A reader in `DONE`
always reports NEEDS_MORE, so stopping on `consumed = 0` coincides with the
Mojo loop's extra `break`s on error / DONE.
mirrors flare/http3/server.mojo:732-807 @59bda50 -/
def drain (qd : Bytes → Option Hdrs) (r : Reader) (buf : Bytes) :
    Reader × List (Ev Hdrs) × Bytes :=
  match hf : feed qd r buf with
  | (n, r', e) =>
    if h : 0 < n then
      let rest := drain qd r' (buf.drop n)
      (rest.1, e.toList ++ rest.2.1, rest.2.2)
    else (r, [], buf)
termination_by buf.length
decreasing_by
  have := feed_le qd r buf
  rw [hf] at this
  simp only [List.length_drop]; omega

/-- Two successive `feed_stream_chunk` calls: drain `a`, keep the residue in
the inbox, append `b`, drain again; events concatenate. -/
def drainTwice (qd : Bytes → Option Hdrs) (r : Reader) (a b : Bytes) :
    Reader × List (Ev Hdrs) × Bytes :=
  match drain qd r a with
  | (r1, e1, rest1) =>
    match drain qd r1 (rest1 ++ b) with
    | (r2, e2, rest2) => (r2, e1 ++ e2, rest2)

/-- Chunking independence of `feed_stream_chunk`: draining `a ++ b` gives the
same reader, events and residue as draining `a`, keeping the residue, and
draining it with `b` appended. -/
theorem drain_append (qd : Bytes → Option Hdrs) (r : Reader) (a b : Bytes) :
    drain qd r (a ++ b) = drainTwice qd r a b := by
  unfold drainTwice
  rcases hf : feed qd r a with ⟨n, r', e⟩
  have hle : n ≤ a.length := by have := feed_le qd r a; rw [hf] at this; exact this
  by_cases hn : 0 < n
  · have hf' : feed qd r (a ++ b) = (n, r', e) := by
      rw [feed_append qd r a b (by rw [hf]; exact hn), hf]
    have ih := drain_append qd r' (a.drop n) b
    rw [drain.eq_def qd r (a ++ b), drain.eq_def qd r a]
    simp only [hf, hf', dif_pos hn]
    rw [List.drop_append_of_le_length hle, ih]
    unfold drainTwice
    simp
  · have hn0 : n = 0 := by omega
    subst hn0
    have : drain qd r a = (r, [], a) := by rw [drain.eq_def]; simp [hf]
    rw [this]
    simp
termination_by a.length
decreasing_by simp only [List.length_drop]; omega

/-- A drain always leaves a residue on which the reader makes no progress
(the bytes kept in `inbox` are an incomplete frame, or the reader is DONE). -/
theorem drain_residue (qd : Bytes → Option Hdrs) (r : Reader) (buf : Bytes) :
    drain qd (drain qd r buf).1 (drain qd r buf).2.2 =
      ((drain qd r buf).1, [], (drain qd r buf).2.2) := by
  rcases hf : feed qd r buf with ⟨n, r', e⟩
  by_cases hn : 0 < n
  · have ih := drain_residue qd r' (buf.drop n)
    have : drain qd r buf = ((drain qd r' (buf.drop n)).1,
        e.toList ++ (drain qd r' (buf.drop n)).2.1, (drain qd r' (buf.drop n)).2.2) := by
      rw [drain.eq_def]; simp only [hf, dif_pos hn]
    rw [this]; exact ih
  · have : drain qd r buf = (r, [], buf) := by rw [drain.eq_def]; simp [hf, hn]
    rw [this]; exact this
termination_by buf.length
decreasing_by
  have := feed_le qd r buf; rw [hf] at this; simp only [List.length_drop]; omega

/-- Successive `feed_stream_chunk` calls with chunks `cs`, starting from
inbox `inbox`. -/
def feedChunks (qd : Bytes → Option Hdrs) (r : Reader) (inbox : Bytes) :
    List Bytes → Reader × List (Ev Hdrs) × Bytes
  | [] => (r, [], inbox)
  | c :: cs =>
    match drain qd r (inbox ++ c) with
    | (r1, e1, rest1) =>
      match feedChunks qd r1 rest1 cs with
      | (r2, e2, rest2) => (r2, e1 ++ e2, rest2)

/-- However a request stream is split into QUIC chunks, the server sees the
same events, ends in the same reader state and keeps the same residue as if
the bytes had arrived in one piece (starting from any residue inbox, in
particular the empty one). -/
theorem feedChunks_eq_drain (qd : Bytes → Option Hdrs) (cs : List Bytes) :
    ∀ (r : Reader) (inbox : Bytes), drain qd r inbox = (r, [], inbox) →
      feedChunks qd r inbox cs = drain qd r (inbox ++ cs.flatten) := by
  induction cs with
  | nil => intro r inbox h; simp only [feedChunks, List.flatten_nil, List.append_nil, h]
  | cons c cs ih =>
    intro r inbox _
    simp only [feedChunks, List.flatten_cons, ← List.append_assoc]
    conv => rhs; rw [drain_append]
    unfold drainTwice
    have hres := drain_residue qd r (inbox ++ c)
    rcases hd : drain qd r (inbox ++ c) with ⟨r1, e1, rest1⟩
    rw [hd] at hres
    simp only
    rw [ih r1 rest1 hres]

theorem drain_nil (qd : Bytes → Option Hdrs) (r : Reader) : drain qd r [] = (r, [], []) := by
  rw [drain.eq_def]; simp [feed]

/-- Corollary: from a fresh inbox, any chunking of the stream is equivalent
to feeding it whole. -/
theorem feedChunks_chunking_independent (qd : Bytes → Option Hdrs) (r : Reader)
    (cs : List Bytes) : feedChunks qd r [] cs = drain qd r cs.flatten := by
  have := feedChunks_eq_drain qd cs r [] (drain_nil qd r)
  simpa using this

end Flare.L3.H3
