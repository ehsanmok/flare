import Flare.L3_Protocol.Quic.Frame
/-!
# QUIC connection state (RFC 9000 §10, §19.19-§19.20)

A model of the connection-level state of flare's sans-I/O QUIC machine
(flare/quic/state.mojo): `CONN_STATE_HANDSHAKE..CLOSED` and the three ways
they change, namely an inbound frame (`handle_frame_buf` → the
`_ConnFrameHandler` callbacks), the TLS adapter's `mark_handshake_complete`,
and a local `connection_close`. Per-stream state, flow control and the
per-frame validation that can raise (NEW_CONNECTION_ID, PATH_*) leave the
connection state unchanged on success and are abstracted away; a raise is
outside this model.

The spec `specStep` is written from RFC 9000 and is role-aware:
* §19.20: HANDSHAKE_DONE is sent only by servers; "A server MUST treat
  receipt of a HANDSHAKE_DONE frame as a connection error of type
  PROTOCOL_VIOLATION." A client confirms the handshake on it (§4.1.2).
* §10.2: an endpoint that receives CONNECTION_CLOSE enters draining
  (also from closing, §10.2.2); a local close enters closing; the closing
  and draining states only ever lead to closed (§10.2.1/§10.2.2: no
  application data, the only remaining exit is the timer).
* Every other frame leaves the connection state alone.

Results:
* `spec_closing_absorbing` / `specRun_absorbing`: in the spec, once the
  connection is closing, draining or closed it never becomes usable again.
* `implStep` (flare): role-unaware, HANDSHAKE_DONE always sets ESTABLISHED.
  `Flare.Bugs.QUIC_04` (closed connection reopened) and `Flare.Bugs.QUIC_09`
  (server accepts HANDSHAKE_DONE) are counterexamples.
* `implStepFixed_eq_spec`: the minimal fix (guard on HANDSHAKE, reject on
  the server) equals the spec on every state, role and event.
* `markHandshakeComplete_spec`, `localClose_spec`: flare's two other
  transitions already match the spec.
-/
namespace Flare.L3.Quic.Conn
open Flare.L3.Quic.Frame

/-- mirrors flare/quic/state.mojo:127-131 @59bda50 -/
inductive CState | handshake | established | closing | draining | closed
  deriving DecidableEq, Repr

inductive Role | client | server
  deriving DecidableEq, Repr

/-- Inputs to the connection machine. -/
inductive Ev
  | frame (f : Frame)        -- one inbound frame (`handle_frame_buf`)
  | tlsDone                  -- `mark_handshake_complete`
  | localClose               -- `connection_close`
  deriving DecidableEq, Repr

def CState.terminal : CState → Bool
  | .closing | .draining | .closed => true
  | _ => false

/-! ## flare -/

/-- Connection-state effect of one decoded frame.
mirrors flare/quic/state.mojo:430-445 (apply_connection_close: DRAINING),
489-494 (apply_handshake_done: ESTABLISHED, no state or role test),
640-760 (every other callback leaves `conn.state` alone) @59bda50 -/
def frameEffect (s : CState) : Frame → CState
  | .connectionClose .. => .draining
  | .handshakeDone => .established
  | _ => s

/-- mirrors flare/quic/state.mojo:861-873 @59bda50 -/
def markHandshakeComplete (s : CState) : CState :=
  if s = .handshake then .established else s

/-- mirrors flare/quic/state.mojo:890-911 @59bda50 -/
def localClose (s : CState) : CState :=
  if s = .closing ∨ s = .draining ∨ s = .closed then s else .closing

/-- One step of flare's machine; `none` = connection error (never produced
here: flare's connection layer has no role and raises on none of these).
`handle_frame_buf` drops every frame once the connection is CLOSED.
mirrors flare/quic/state.mojo:766-791 @59bda50 -/
def implStep (_role : Role) (s : CState) : Ev → Option CState
  | .frame f => if s = .closed then some s else some (frameEffect s f)
  | .tlsDone => some (markHandshakeComplete s)
  | .localClose => some (localClose s)

/-- Run a sequence of events; stops at the first error. -/
def run (step : Role → CState → Ev → Option CState) (role : Role) :
    CState → List Ev → Option CState
  | s, [] => some s
  | s, e :: es => match step role s e with
    | none => none
    | some s' => run step role s' es

/-- The frames of a decoded payload, as events. -/
def frames (fs : List Frame) : List Ev := fs.map .frame

/-! ## RFC 9000 -/

/-- RFC 9000 §10.2, §19.19, §19.20 connection-state transitions. -/
def specStep (role : Role) (s : CState) (e : Ev) : Option CState :=
  match s, e with
  | .closed, _ => some .closed                              -- §10.2: nothing leaves closed
  | _, .localClose => some (if s.terminal then s else .closing)
  | _, .frame (.connectionClose ..) => some .draining       -- §10.2.2
  | _, .frame .handshakeDone =>
    match role with
    | .server => none                                       -- §19.20 PROTOCOL_VIOLATION
    | .client => some (if s = .handshake then .established else s)
  | _, .tlsDone => some (if s = .handshake then .established else s)
  | _, .frame _ => some s

/-- **Closing / draining / closed are absorbing in the spec.** -/
theorem spec_closing_absorbing (role : Role) (s s' : CState) (e : Ev)
    (hs : s.terminal = true) (h : specStep role s e = some s') : s'.terminal = true := by
  cases s <;> simp [CState.terminal] at hs <;>
    cases e with
    | frame f =>
      cases f <;> cases role <;> simp [specStep] at h <;> subst h <;> rfl
    | tlsDone => simp [specStep] at h; subst h; rfl
    | localClose => simp [specStep, CState.terminal] at h; subst h; rfl

theorem specRun_absorbing (role : Role) (es : List Ev) :
    ∀ s s', s.terminal = true → run specStep role s es = some s' → s'.terminal = true := by
  induction es with
  | nil => intro s s' hs h; simp [run] at h; subst h; exact hs
  | cons e es ih =>
    intro s s' hs h
    simp only [run] at h
    cases hst : specStep role s e with
    | none => rw [hst] at h; cases h
    | some s1 =>
      rw [hst] at h
      exact ih s1 s' (spec_closing_absorbing role s s1 e hs hst) h

/-! ## The minimal fix -/

/-- `apply_handshake_done` only acts in HANDSHAKE (as
`mark_handshake_complete` already does), and the server-side driver treats
HANDSHAKE_DONE as PROTOCOL_VIOLATION. -/
def frameEffectFixed (role : Role) (s : CState) : Frame → Option CState
  | .connectionClose .. => some .draining
  | .handshakeDone =>
    match role with
    | .server => none
    | .client => some (markHandshakeComplete s)
  | _ => some s

def implStepFixed (role : Role) (s : CState) : Ev → Option CState
  | .frame f => if s = .closed then some s else frameEffectFixed role s f
  | .tlsDone => some (markHandshakeComplete s)
  | .localClose => some (localClose s)

/-- **The fix meets the spec**: equal on every role, state and event. -/
theorem implStepFixed_eq_spec (role : Role) (s : CState) (e : Ev) :
    implStepFixed role s e = specStep role s e := by
  cases s <;> cases e with
  | frame f => cases f <;> cases role <;> rfl
  | tlsDone => rfl
  | localClose => rfl

theorem runFixed_eq_spec (role : Role) (es : List Ev) (s : CState) :
    run implStepFixed role s es = run specStep role s es := by
  induction es generalizing s with
  | nil => rfl
  | cons e es ih => simp only [run, implStepFixed_eq_spec, ih]

/-- flare's `mark_handshake_complete` already matches the spec. -/
theorem markHandshakeComplete_spec (role : Role) (s : CState) :
    implStep role s .tlsDone = specStep role s .tlsDone := by
  cases s <;> rfl

/-- flare's local `connection_close` already matches the spec. -/
theorem localClose_spec (role : Role) (s : CState) :
    implStep role s .localClose = specStep role s .localClose := by
  cases s <;> rfl

/-- flare already agrees with the spec on every frame other than
HANDSHAKE_DONE (for either role). -/
theorem implStep_frame_spec (role : Role) (s : CState) (f : Frame)
    (hf : f ≠ .handshakeDone) : implStep role s (.frame f) = specStep role s (.frame f) := by
  cases s <;> cases f <;> first | exact absurd rfl hf | rfl

end Flare.L3.Quic.Conn
