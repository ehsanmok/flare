/-!
# QUIC stream states (RFC 9000 §2.1, §3, §4.6, §19.4-§19.13)

What a peer may say about a stream, and what each flare endpoint checks.

Stream ids (§2.1): bit 0 is the initiator (0 client, 1 server), bit 1 the
direction (0 bidirectional, 1 unidirectional). A unidirectional stream has
only a send part at its initiator and only a receive part at the other end.

`spec` is the per-frame acceptance rule of RFC 9000:
* §4.6: a frame naming a peer-initiated stream above the count we
  advertised is STREAM_LIMIT_ERROR;
* §19.8: STREAM on a stream we cannot receive on, or on a locally
  initiated stream not yet created, is STREAM_STATE_ERROR;
* §19.4: RESET_STREAM on a send-only stream, STREAM_STATE_ERROR;
* §19.5: STOP_SENDING on a receive-only stream or on a locally initiated
  stream not yet created, STREAM_STATE_ERROR;
* §19.10: MAX_STREAM_DATA, the same two cases, STREAM_STATE_ERROR;
* §19.13: STREAM_DATA_BLOCKED on a send-only stream, STREAM_STATE_ERROR.

`server` is the server's check (STREAM in `_route_http3_stream_chunks`, with the
unidirectional limit of QUIC-16; the other four frames in `check_stream_frame_id`,
state.mojo, QUIC-15); `client` is the client's (QUIC-17). `checked` is the
bit-level check; `checked_eq_spec` proves it is the spec, and
`serverFixed_eq_spec` / `clientFixed_eq_spec` instantiate it.

The second half models the per-stream state. RESET_STREAM (receive half) and
STOP_SENDING (send half) are recorded separately (QUIC-18). `Halves` is the
RFC's split (§3.1 sending, §3.2 receiving) and is what the code records, in the
`peer_reset` / `send_reset` fields of `Stream`; the client reads those two
(`resetSeenH`, `sendRefusedH`). `halves_reset_iff` / `halves_stop_iff` prove
the state records each event no matter what follows.
-/
namespace Flare.L3.Quic.Streams

inductive Role | client | server
  deriving DecidableEq, Repr

inductive Kind | stream | resetStream | stopSending | maxStreamData | streamDataBlocked
  deriving DecidableEq, Repr

inductive Err | state | limit
  deriving DecidableEq, Repr

def serverInit (sid : Nat) : Bool := sid % 2 = 1
def isUni (sid : Nat) : Bool := sid / 2 % 2 = 1

def isLocal : Role → Nat → Bool
  | .client, sid => !serverInit sid
  | .server, sid => serverInit sid

/-- The stream has a receive part at role `r`. -/
def hasRecv (r : Role) (sid : Nat) : Bool := !isUni sid || !isLocal r sid
/-- The stream has a send part at role `r`. -/
def hasSend (r : Role) (sid : Nat) : Bool := !isUni sid || isLocal r sid

structure Ctx where
  /-- locally initiated streams opened so far -/
  opened : Nat → Bool
  /-- MAX_STREAMS (bidirectional) we have advertised -/
  maxBidi : Nat
  /-- MAX_STREAMS (unidirectional) we have advertised -/
  maxUni : Nat

def overLimit (r : Role) (c : Ctx) (sid : Nat) : Bool :=
  !isLocal r sid && decide ((if isUni sid then c.maxUni else c.maxBidi) < sid / 4 + 1)

/-- RFC 9000 §4.6, §19.4, §19.5, §19.8, §19.10, §19.13. -/
def spec (r : Role) (c : Ctx) (k : Kind) (sid : Nat) : Option Err :=
  let fresh := isLocal r sid && !c.opened sid
  if overLimit r c sid then some .limit
  else match k with
  | .stream => if !hasRecv r sid || fresh then some .state else none
  | .resetStream => if !hasRecv r sid then some .state else none
  | .stopSending => if !hasSend r sid || fresh then some .state else none
  | .maxStreamData => if !hasSend r sid || fresh then some .state else none
  | .streamDataBlocked => if !hasRecv r sid then some .state else none

/-- The check the fixes add, on the two low bits of the stream id. -/
def checked (r : Role) (c : Ctx) (k : Kind) (sid : Nat) : Option Err :=
  let mine := decide (sid % 2 = (if r = .server then 1 else 0))
  let uni := decide (2 ≤ sid % 4)
  if !mine && decide ((if uni then c.maxUni else c.maxBidi) < sid / 4 + 1) then some .limit
  else match k with
  | .stream | .resetStream | .streamDataBlocked =>
    if (uni && mine) || (k == .stream && mine && !c.opened sid) then some .state else none
  | .stopSending | .maxStreamData =>
    if (uni && !mine) || (mine && !c.opened sid) then some .state else none

theorem bits (r : Role) (sid : Nat) :
    isLocal r sid = decide (sid % 2 = (if r = .server then 1 else 0)) ∧
    isUni sid = decide (2 ≤ sid % 4) := by
  constructor
  · cases r <;> simp only [isLocal, serverInit, reduceCtorEq, if_false, if_true] <;>
      by_cases h : sid % 2 = 1 <;> simp [h] <;> omega
  · unfold isUni
    by_cases h : sid / 2 % 2 = 1 <;> simp [h] <;> omega

theorem checked_eq_spec (r : Role) (c : Ctx) (k : Kind) (sid : Nat) :
    checked r c k sid = spec r c k sid := by
  obtain ⟨h1, h2⟩ := bits r sid
  unfold checked spec overLimit hasRecv hasSend
  rw [h1, h2]
  cases k <;> simp

/-! ## The server -/

/-- STREAM: mirrors flare/quic/server.mojo#QuicListener._route_http3_stream_chunks sha=efd4a176d4c2 at=59bda50f; the other
four frames: mirrors flare/quic/state.mojo#apply_max_stream_data+apply_reset_stream+apply_stop_sending+_ConnFrameHandler.on_max_streams+_ConnFrameHandler.on_data_blocked+_ConnFrameHandler.on_stream_data_blocked+_ConnFrameHandler.on_streams_blocked sha=3afbe9a553df at=59bda50f (no
check; RESET_STREAM / STOP_SENDING / MAX_STREAM_DATA touch a known stream,
STREAM_DATA_BLOCKED is ignored). -/
def server (c : Ctx) (k : Kind) (sid : Nat) : Option Err :=
  match k with
  | .stream =>
    if sid % 2 = 1 then some .state
    else if sid % 4 = 0 ∧ c.maxBidi < sid / 4 + 1 then some .limit
    else if sid % 4 = 2 ∧ c.maxUni < sid / 4 + 1 then some .limit
    else none
  | _ => checked .server c k sid

/-- The streams flare's server has opened: none until its first 1-RTT
flight, then exactly its HTTP/3 control stream 3 (RFC 9114 §6.2.1), which
`_drain_1rtt_coalesced` sends and records with `mark_local_stream_opened`.
It answers requests on the client's bidirectional streams.
mirrors flare/quic/state.mojo#mark_local_stream_opened sha=5c6368f1a77a at=74fe61fd and
flare/quic/server.mojo#QuicListener._drain_1rtt_coalesced sha=febb6014ce9a at=74fe61fd -/
def ServerOpened (sent : Bool) (c : Ctx) : Prop := ∀ sid, c.opened sid = (sent && sid == 3)

theorem serverFixed_eq_spec (sent : Bool) (c : Ctx) (hc : ServerOpened sent c) (k : Kind) (sid : Nat) :
    server c k sid = spec .server c k sid := by
  rw [← checked_eq_spec]
  cases k with
  | stream =>
    unfold server checked
    by_cases h1 : sid % 2 = 1
    · by_cases hu : sid % 4 = 3
      · simp [h1, hu]
      · have h3 : sid ≠ 3 := by omega
        have ho : c.opened sid = false := by rw [hc sid]; simp [h3]
        have hu' : ¬ 2 ≤ sid % 4 := by omega
        simp [h1, hu', ho]
    · by_cases h2 : sid % 4 = 0
      · by_cases h3 : c.maxBidi < sid / 4 + 1 <;> simp [h1, h2, h3]
      · have h4 : sid % 4 = 2 := by omega
        by_cases h3 : c.maxUni < sid / 4 + 1 <;> simp [h1, h4, h3]
  | _ => rfl

/-! ## The client -/

/-- mirrors flare/quic/client.mojo#QuicClientConnection._dispatch_frames sha=1dabb9c8280e at=59bda50f (`_dispatch_frames`
hands every frame to the shared state machine, whose frame handlers run
`check_stream_frame_id`, QUIC-17) -/
def client (c : Ctx) (k : Kind) (sid : Nat) : Option Err :=
  checked .client c k sid

theorem clientFixed_eq_spec (c : Ctx) (k : Kind) (sid : Nat) :
    client c k sid = spec .client c k sid := checked_eq_spec _ _ _ _

/-! ## The two halves of a stream -/

inductive Ev
  /-- RESET_STREAM received (receive half) -/
  | resetIn
  /-- STOP_SENDING received (send half) -/
  | stopIn
  /-- STREAM with FIN received -/
  | finIn
  /-- we reset our send half (`cancel_stream`) -/
  | resetOut
  deriving DecidableEq, Repr

/-- The RFC's two halves (§3.1, §3.2), reduced to the facts the client
reads: the peer reset its send half, and our send half is reset. -/
structure Halves where
  recvReset : Bool := false
  sendReset : Bool := false
  deriving DecidableEq, Repr

/-- mirrors flare/quic/state.mojo#apply_reset_stream+apply_stop_sending sha=dfde8aa9b69d at=cc5a947e and
flare/quic/client.mojo#QuicClientConnection.cancel_stream sha=c8a6473218d3 at=cc5a947e (fixed, QUIC-18: each sets only its own
flag, `peer_reset` / `send_reset`) -/
def stepHalves (h : Halves) : Ev → Halves
  | .resetIn => { h with recvReset := true }
  | .stopIn => { h with sendReset := true }
  | .finIn => h
  | .resetOut => { h with sendReset := true }

def runHalves (evs : List Ev) : Halves := evs.foldl stepHalves {}

/-- mirrors flare/quic/client.mojo#QuicClientConnection.stream_reset sha=f0dc7dbddb34 at=cc5a947e (fixed, QUIC-18) -/
def resetSeenH (h : Halves) : Bool := h.recvReset

/-- mirrors flare/quic/client.mojo#QuicClientConnection.send_stream sha=0131f865bdae at=cc5a947e's reset check (fixed, QUIC-18) -/
def sendRefusedH (h : Halves) : Bool := h.sendReset

theorem runHalves_go (evs : List Ev) : ∀ h : Halves,
    (evs.foldl stepHalves h).recvReset = (h.recvReset || evs.contains .resetIn) ∧
    (evs.foldl stepHalves h).sendReset =
      (h.sendReset || evs.contains .stopIn || evs.contains .resetOut) := by
  induction evs with
  | nil => intro h; simp
  | cons e es ih =>
    intro h
    rw [List.foldl_cons]
    obtain ⟨a, b⟩ := ih (stepHalves h e)
    rw [a, b]
    cases e <;> simp [stepHalves, Bool.or_assoc, Bool.or_comm, Bool.or_left_comm]

/-- The receive-half reset is seen exactly when RESET_STREAM
arrived, whatever came after it. -/
theorem halves_reset_iff (evs : List Ev) : (runHalves evs).recvReset = evs.contains .resetIn := by
  unfold runHalves
  have := (runHalves_go evs {}).1; simpa using this

/-- The send half refuses data exactly when STOP_SENDING arrived
or we reset it. -/
theorem halves_stop_iff (evs : List Ev) :
    (runHalves evs).sendReset = (evs.contains .stopIn || evs.contains .resetOut) := by
  unfold runHalves
  have := (runHalves_go evs {}).2; simpa using this

end Flare.L3.Quic.Streams
