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

`server` is the server's check (only STREAM is looked at, in
`_route_http3_stream_chunks`); `client` is the client's (none). `checked`
is the bit-level check the fixes add; `checked_eq_spec` proves it is the
spec, and `serverFixed_eq_spec` / `clientFixed_eq_spec` instantiate it.
`server_stream_conforms` proves the server's existing STREAM check is
already exact for bidirectional limits and stream direction.

The second half models the per-stream state. flare keeps one `state` for
both halves of a bidirectional stream (flare/quic/state.mojo:80-107), so
RESET_STREAM (receive half) and STOP_SENDING (send half) overwrite each
other. `Halves` is the RFC's split (§3.1 sending, §3.2 receiving) and
`halves_reset_iff` / `halves_stop_iff` prove the fixed state records each
event no matter what follows.
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

structure ServerFixes where
  /-- QUIC-15: direction / creation / limit checks on the other frames -/
  dir : Bool
  /-- QUIC-16: the unidirectional stream limit on STREAM -/
  uni : Bool

/-- STREAM: mirrors flare/quic/server.mojo:1407-1430 @59bda50; the other
four frames: mirrors flare/quic/state.mojo:454-486, 712-722 @59bda50 (no
check; RESET_STREAM / STOP_SENDING / MAX_STREAM_DATA touch a known stream,
STREAM_DATA_BLOCKED is ignored). -/
def server (fx : ServerFixes) (c : Ctx) (k : Kind) (sid : Nat) : Option Err :=
  match k with
  | .stream =>
    if sid % 2 = 1 then some .state
    else if sid % 4 = 0 ∧ c.maxBidi < sid / 4 + 1 then some .limit
    else if fx.uni ∧ sid % 4 = 2 ∧ c.maxUni < sid / 4 + 1 then some .limit
    else none
  | _ => if fx.dir then checked .server c k sid else none

/-- flare's server opens no stream of its own: it answers on the client's
bidirectional streams and opens no unidirectional stream
(flare/quic/server.mojo has no egress for one). -/
def ServerOpensNone (c : Ctx) : Prop := ∀ sid, c.opened sid = false

/-- The existing STREAM check is the spec for every stream id except a
client unidirectional stream above the advertised limit (QUIC-16). -/
theorem server_stream_conforms (c : Ctx) (hc : ServerOpensNone c) (sid : Nat)
    (hu : sid % 4 = 2 → sid / 4 + 1 ≤ c.maxUni) :
    server ⟨false, false⟩ c .stream sid = spec .server c .stream sid := by
  rw [← checked_eq_spec]
  unfold server checked
  have ho := hc sid
  by_cases h1 : sid % 2 = 1
  · simp [h1, ho]
  · by_cases h2 : sid % 4 = 0
    · by_cases h3 : c.maxBidi < sid / 4 + 1
      · simp [h1, h2, h3, ho]
      · have : ¬ 2 ≤ sid % 4 := by omega
        simp [h1, h2, h3, ho, this]
    · have h4 : sid % 4 = 2 := by omega
      have h5 := hu h4
      have : ¬ c.maxUni < sid / 4 + 1 := by omega
      simp [h1, h2, h4, this]

theorem serverFixed_eq_spec (c : Ctx) (hc : ServerOpensNone c) (k : Kind) (sid : Nat) :
    server ⟨true, true⟩ c k sid = spec .server c k sid := by
  rw [← checked_eq_spec]
  cases k with
  | stream =>
    unfold server checked
    have ho := hc sid
    by_cases h1 : sid % 2 = 1
    · simp [h1, ho]
    · by_cases h2 : sid % 4 = 0
      · have : ¬ 2 ≤ sid % 4 := by omega
        by_cases h3 : c.maxBidi < sid / 4 + 1 <;> simp [h1, h2, h3, ho, this]
      · have h4 : sid % 4 = 2 := by omega
        by_cases h3 : c.maxUni < sid / 4 + 1 <;> simp [h1, h2, h4, h3]
  | _ => rfl

/-! ## The client -/

/-- mirrors flare/quic/client.mojo:902-912 @59bda50 (`_dispatch_frames`
hands every frame to the shared state machine; nothing checks the stream
id) -/
def client (fixed : Bool) (c : Ctx) (k : Kind) (sid : Nat) : Option Err :=
  if fixed then checked .client c k sid else none

theorem clientFixed_eq_spec (c : Ctx) (k : Kind) (sid : Nat) :
    client true c k sid = spec .client c k sid := checked_eq_spec _ _ _ _

/-! ## One state for both halves -/

inductive St | open_ | halfClosedLocal | halfClosedRemote | resetSent | resetRecvd | closed
  deriving DecidableEq, Repr

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

/-- mirrors flare/quic/state.mojo:356-363, 467-486 and
flare/quic/client.mojo:1406-1428 @59bda50 -/
def stepImpl : St → Ev → St
  | _, .resetIn => .resetRecvd
  | _, .stopIn => .resetSent
  | s, .finIn => match s with
    | .open_ => .halfClosedRemote
    | .halfClosedLocal => .closed
    | s => s
  | _, .resetOut => .resetSent

/-- mirrors flare/quic/client.mojo:1455-1460 @59bda50 (`stream_reset`, which
the HTTP/3 client polls at flare/http3/client.mojo:465) -/
def resetSeen (s : St) : Bool := s == .resetRecvd

/-- mirrors flare/quic/client.mojo:1357-1362 @59bda50 (`send_stream`
refuses only in RESET_SENT) -/
def sendRefused (s : St) : Bool := s == .resetSent

def runImpl (evs : List Ev) : St := evs.foldl stepImpl .open_

/-- The RFC's two halves (§3.1, §3.2), reduced to the facts the client
reads: the peer reset its send half, and our send half is reset. -/
structure Halves where
  recvReset : Bool := false
  sendReset : Bool := false
  deriving DecidableEq, Repr

def stepHalves (h : Halves) : Ev → Halves
  | .resetIn => { h with recvReset := true }
  | .stopIn => { h with sendReset := true }
  | .finIn => h
  | .resetOut => { h with sendReset := true }

def runHalves (evs : List Ev) : Halves := evs.foldl stepHalves {}

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

/-- **Fixed**: the receive-half reset is seen exactly when RESET_STREAM
arrived, whatever came after it. -/
theorem halves_reset_iff (evs : List Ev) : (runHalves evs).recvReset = evs.contains .resetIn := by
  unfold runHalves
  have := (runHalves_go evs {}).1; simpa using this

/-- **Fixed**: the send half refuses data exactly when STOP_SENDING arrived
or we reset it. -/
theorem halves_stop_iff (evs : List Ev) :
    (runHalves evs).sendReset = (evs.contains .stopIn || evs.contains .resetOut) := by
  unfold runHalves
  have := (runHalves_go evs {}).2; simpa using this

end Flare.L3.Quic.Streams
