import Flare.Core

/-!
# QUIC timers: idle timeout and the closing / draining period

Two labelled transition systems over a `Nat` clock in milliseconds.

**Idle timeout (RFC 9000 §10.1).** Events are a datagram received for the
connection at `t` (`auth`: some packet in it decrypted and was processed), an
ack-eliciting packet sent at `t`, and the timers advanced to `t`.
`ispecStep` is the RFC: the effective timeout is the minimum of the two
advertised `max_idle_timeout` values (the sole non-zero one if only one is
non-zero, none if both are 0), raised to at least three times the PTO; the
timer restarts on every successfully processed packet and on the first
ack-eliciting send after one. `serverStep` and `clientStep` mirror flare;
`fixedStep` is the fixed timer, which `fixed_run` relates to the spec on
every run.

**Closing and draining (RFC 9000 §10.2, §10.2.1, §10.2.2, §11.1).** Events are
a local close, a CONNECTION_CLOSE from the peer, any other packet attributed
to the connection, the driver having something to send (an ACK, stream data,
a probe), and a timer firing. The output is the list of packets sent.
`cspecStep` is one RFC-conforming behaviour: a local close sends
CONNECTION_CLOSE and enters closing for 3×PTO; in closing only
CONNECTION_CLOSE is sent, once per incoming packet; a peer's
CONNECTION_CLOSE enters draining, where nothing is sent; both end after
3×PTO. `spec_*` prove those properties for every state. `srvStep` and
`cliStep` mirror flare's server and client.
-/
namespace Flare.L3.Quic.Timers

/-- Generic run of a step function over an event list. -/
def run {σ ε : Type} (step : σ → ε → σ) (s : σ) (es : List ε) : σ := es.foldl step s

/-! ## Idle timeout -/

structure IdleParams where
  /-- our max_idle_timeout (ms); 0 = absent -/
  localIdle : Nat
  /-- the peer's max_idle_timeout (ms); 0 = absent -/
  peerIdle : Nat
  /-- current PTO (ms) -/
  pto : Nat

/-- RFC 9000 §10.1: the effective idle timeout, if any. -/
def effective (p : IdleParams) : Option Nat :=
  let m : Option Nat :=
    if p.localIdle = 0 then (if p.peerIdle = 0 then none else some p.peerIdle)
    else if p.peerIdle = 0 then some p.localIdle else some (min p.localIdle p.peerIdle)
  m.map fun v => max v (3 * p.pto)

/-- mirrors flare/quic/_server_support.mojo `_effective_idle_ms` (fixed,
QUIC-20): 0 stands for "no timeout". -/
def effectiveMs (localIdle peerIdle pto : Nat) : Nat :=
  let m := if localIdle = 0 then peerIdle else if peerIdle = 0 then localIdle else min localIdle peerIdle
  if m = 0 then 0 else max m (3 * pto)

/-- The shipped helper computes exactly the spec's effective timeout. -/
theorem effectiveMs_spec (l p pto : Nat) :
    effective ⟨l, p, pto⟩ = if effectiveMs l p pto = 0 then none else some (effectiveMs l p pto) := by
  unfold effective effectiveMs
  by_cases hl : l = 0 <;> by_cases hp : p = 0 <;> simp [hl, hp] <;> split <;> omega

inductive IEv
  | recv (t : Nat) (auth : Bool)
  | sendAE (t : Nat)
  | tick (t : Nat)

/-- Spec state: when the current idle period started, whether an ack-eliciting
packet was sent since the last processed receipt, and whether the
connection has been closed by the idle timer. -/
structure ISpec where
  start : Nat
  sentSince : Bool
  closed : Bool

def ispecStep (p : IdleParams) (s : ISpec) : IEv → ISpec
  | .recv t auth => if s.closed ∨ auth = false then s else { s with start := t, sentSince := false }
  | .sendAE t => if s.closed ∨ s.sentSince then s else { s with start := t, sentSince := true }
  | .tick t =>
    if s.closed then s else
    match effective p with
    | none => s
    | some d => if s.start + d ≤ t then { s with closed := true } else s

/-- Implementation state: the fire time of the armed idle timer. -/
structure IImpl where
  deadline : Nat
  closed : Bool

/-- The pre-fix server timer (QUIC-20): every datagram routed to the slot
re-arms the idle timer at `config.max_idle_timeout_ms` (the wheel clamps 0 to
1), whether or not a packet in it decrypted; sending never re-arms it.
mirrors flare/quic/server.mojo:724-782, 2874-2898, 2929-2930 and
flare/runtime/timer_wheel.mojo:119-144 @59bda50 -/
def serverStep (cfgIdle : Nat) (s : IImpl) : IEv → IImpl
  | .recv t _ => if s.closed then s else { s with deadline := t + max cfgIdle 1 }
  | .sendAE _ => s
  | .tick t => if s.closed then s else if s.deadline ≤ t then { s with closed := true } else s

/-- The pre-fix client (QUIC-21) had no idle timer: `poll` never checked one, and frames are
dispatched with `now_us = 0`, so `last_activity_us` never moves and
`is_idle_timeout_expired` (never called) would return False.
mirrors flare/quic/client.mojo:557-608, 902-912 @59bda50 -/
def clientStep (s : IImpl) (_ : IEv) : IImpl := s

/-- The timer the server now runs (fixed, QUIC-20): armed from the effective
timeout, re-armed only by an authenticated receipt or the first ack-eliciting
send after one, not armed when there is no effective timeout.
mirrors flare/quic/server.mojo `_handle_inbound` (only packets for which
`_process_one_packet` succeeded), `_build_1rtt_response` (first ack-eliciting
send, `idle_sent_since_rx`), `schedule_idle_timeout`, `_client_params_ok` (the
peer's value) and flare/quic/_server_support.mojo `_effective_idle_ms`. The
client runs the same timer (fixed, QUIC-21): flare/quic/client.mojo
`_dispatch_frames` (processed packets, with the monotonic clock),
`_note_ack_eliciting_send`, `_apply_peer_transport_params` (the server's value)
and `_check_idle` (called from `poll`) -/
structure IFix where
  deadline : Option Nat
  sentSince : Bool
  closed : Bool

def fixedStep (p : IdleParams) (s : IFix) : IEv → IFix
  | .recv t auth =>
    if s.closed ∨ auth = false then s
    else { s with deadline := (effective p).map (t + ·), sentSince := false }
  | .sendAE t =>
    if s.closed ∨ s.sentSince then s
    else { s with deadline := (effective p).map (t + ·), sentSince := true }
  | .tick t =>
    if s.closed then s else
    match s.deadline with
    | none => s
    | some d => if d ≤ t then { s with closed := true } else s

/-- The fixed timer tracks the spec state. -/
def R (p : IdleParams) (s : ISpec) (f : IFix) : Prop :=
  f.closed = s.closed ∧ f.sentSince = s.sentSince ∧ f.deadline = (effective p).map (s.start + ·)

theorem fixed_sim (p : IdleParams) (s : ISpec) (f : IFix) (e : IEv) (h : R p s f) :
    R p (ispecStep p s e) (fixedStep p f e) := by
  obtain ⟨h1, h2, h3⟩ := h
  cases e with
  | recv t auth =>
    simp only [ispecStep, fixedStep, h1]
    split <;> simp_all [R]
  | sendAE t =>
    simp only [ispecStep, fixedStep, h1, h2]
    split <;> simp_all [R]
  | tick t =>
    simp only [ispecStep, fixedStep, h1, h3]
    split
    · exact ⟨h1, h2, h3⟩
    · cases hd : effective p with
      | none => simp [R, h1, h2, h3, hd]
      | some d =>
        simp only [Option.map_some]
        split <;> simp_all [R]

theorem fixed_run (p : IdleParams) (es : List IEv) :
    ∀ (s : ISpec) (f : IFix), R p s f → R p (run (ispecStep p) s es) (run (fixedStep p) f es) := by
  induction es with
  | nil => intro s f h; exact h
  | cons e es ih => intro s f h; exact ih _ _ (fixed_sim p s f e h)

/-- Initial states at connection start `t0`. -/
def ispecInit (t0 : Nat) : ISpec := ⟨t0, false, false⟩
def fixedInit (p : IdleParams) (t0 : Nat) : IFix := ⟨(effective p).map (t0 + ·), false, false⟩
/-- The first datagram of a connection arms the idle timer.
mirrors flare/quic/server.mojo:778-781, 2894-2896 @59bda50 -/
def serverInit (cfgIdle t0 : Nat) : IImpl := ⟨t0 + max cfgIdle 1, false⟩

theorem init_R (p : IdleParams) (t0 : Nat) : R p (ispecInit t0) (fixedInit p t0) :=
  ⟨rfl, rfl, rfl⟩

/-- **Fix**: on every run the fixed timer closes exactly when the spec does. -/
theorem fixed_closed_eq_spec (p : IdleParams) (t0 : Nat) (es : List IEv) :
    (run (fixedStep p) (fixedInit p t0) es).closed = (run (ispecStep p) (ispecInit t0) es).closed :=
  (fixed_run p es _ _ (init_R p t0)).1

theorem spec_none_step (p : IdleParams) (hp : effective p = none) (s : ISpec) (e : IEv) :
    (ispecStep p s e).closed = s.closed := by
  cases e with
  | recv t a => simp only [ispecStep]; split <;> rfl
  | sendAE t => simp only [ispecStep]; split <;> rfl
  | tick t => simp only [ispecStep, hp]; split <;> rfl

/-- Without an effective timeout the spec never closes on idleness. -/
theorem spec_none_never (p : IdleParams) (hp : effective p = none) (es : List IEv) :
    ∀ s : ISpec, (run (ispecStep p) s es).closed = s.closed := by
  induction es with
  | nil => intro s; rfl
  | cons e es ih => intro s; simp only [run, List.foldl_cons] at ih ⊢; rw [ih, spec_none_step p hp]

theorem client_never (es : List IEv) (s : IImpl) : run clientStep s es = s := by
  induction es generalizing s with
  | nil => rfl
  | cons e es ih => exact ih s

/-! ## Closing and draining -/

inductive Pkt | cc | other
  deriving DecidableEq, Repr

inductive CEv
  | localClose (t : Nat)
  | peerClose (t : Nat)
  | recvPkt (t : Nat)
  | want (t : Nat)
  | tick (t : Nat)

inductive Phase
  | opened
  | closing (untilT : Nat)
  | draining (untilT : Nat)
  | gone
  deriving DecidableEq, Repr

structure CSt where
  phase : Phase
  /-- packets sent, newest first -/
  out : List Pkt
  deriving DecidableEq, Repr

/-- One RFC 9000 §10.2-conforming behaviour (the MAY single CONNECTION_CLOSE
on receipt of the peer's is not taken; rate limiting is not modelled). -/
def cspecStep (pto : Nat) (s : CSt) : CEv → CSt
  | .localClose t => match s.phase with
    | .opened => ⟨.closing (t + 3 * pto), .cc :: s.out⟩
    | _ => s
  | .peerClose t => match s.phase with
    | .opened => ⟨.draining (t + 3 * pto), s.out⟩
    | .closing u => ⟨.draining u, s.out⟩
    | _ => s
  | .recvPkt t => match s.phase with
    | .closing u => if t < u then ⟨.closing u, .cc :: s.out⟩ else s
    | _ => s
  | .want _ => match s.phase with
    | .opened => ⟨.opened, .other :: s.out⟩
    | _ => s
  | .tick t => match s.phase with
    | .closing u => if u ≤ t then ⟨.gone, s.out⟩ else s
    | .draining u => if u ≤ t then ⟨.gone, s.out⟩ else s
    | _ => s

/-- §11.1 / §10.2: closing a connection sends CONNECTION_CLOSE. -/
theorem spec_cc_on_close (pto t : Nat) (out : List Pkt) :
    (cspecStep pto ⟨.opened, out⟩ (.localClose t)).out = .cc :: out := rfl

/-- §10.2.2: in draining, nothing is sent. -/
theorem spec_draining_silent (pto u : Nat) (out : List Pkt) (e : CEv) :
    (cspecStep pto ⟨.draining u, out⟩ e).out = out := by
  cases e <;> simp only [cspecStep] <;> (try split) <;> rfl

/-- §10.2.1: in closing, only CONNECTION_CLOSE is sent. -/
theorem spec_closing_only_cc (pto u : Nat) (out : List Pkt) (e : CEv) :
    (cspecStep pto ⟨.closing u, out⟩ e).out = out ∨
      (cspecStep pto ⟨.closing u, out⟩ e).out = .cc :: out := by
  cases e <;> simp only [cspecStep] <;> (try split) <;> simp

/-- §10.2: closing and draining persist until their end time, which a local
close or the peer's CONNECTION_CLOSE sets 3×PTO after entry. -/
theorem spec_tick_before (pto u t : Nat) (out : List Pkt) (ht : t < u) :
    (cspecStep pto ⟨.closing u, out⟩ (.tick t)).phase = .closing u ∧
    (cspecStep pto ⟨.draining u, out⟩ (.tick t)).phase = .draining u := by
  simp [cspecStep, Nat.not_le.mpr ht]

/-- Server state: the connection phase, the slot's `alive` flag, packets sent. -/
structure SSt where
  phase : Phase
  alive : Bool
  out : List Pkt
  deriving DecidableEq, Repr

/-- `_close_for` (and the other local-close sites) set CLOSING and
`alive := False` and send nothing; `_drain_and_send` skips a slot that is
not alive; the slot is reclaimed when any timer of the slot next fires (the
idle timer, a PTO or ACK-delay timer); a peer CONNECTION_CLOSE moves the
state to DRAINING but leaves `alive` true, so egress continues.
mirrors flare/quic/server.mojo:2177-2180, 2033-2038, 2925-2938 and
flare/quic/state.mojo:430-445 @59bda50 -/
def srvStep (s : SSt) : CEv → SSt
  | .localClose t => match s.phase with
    | .opened => ⟨.closing t, false, s.out⟩
    | _ => s
  | .peerClose t => match s.phase with
    | .opened => ⟨.draining t, s.alive, s.out⟩
    | _ => s
  | .recvPkt _ => s
  | .want _ => if s.alive ∧ s.phase ≠ .gone then { s with out := .other :: s.out } else s
  | .tick _ => if s.alive = false ∧ s.phase ≠ .gone then { s with phase := .gone } else s

/-- The client: `shutdown` sends CONNECTION_CLOSE and closes the socket; a
peer CONNECTION_CLOSE moves the state to DRAINING, and `_drain_egress`,
`_check_pto`, `keepalive` and `send_stream` never look at the state.
mirrors flare/quic/client.mojo:557-608, 688-706, 1035-1085, 1619-1634,
1758-1778 and flare/quic/state.mojo:430-445 @59bda50 -/
def cliStep (s : CSt) : CEv → CSt
  | .localClose _ => match s.phase with
    | .opened => ⟨.gone, .cc :: s.out⟩
    | _ => s
  | .peerClose t => match s.phase with
    | .opened => ⟨.draining t, s.out⟩
    | _ => s
  | .recvPkt _ => s
  | .want _ => if s.phase = .gone then s else { s with out := .other :: s.out }
  | .tick _ => s

/-- The client's own close conforms: it sends CONNECTION_CLOSE and, having
closed its socket, may end the closing state at once (RFC 9000 §10.2:
endpoints "able to close the UDP socket, MAY end these states earlier"). -/
theorem cli_close_ok (t : Nat) (out : List Pkt) :
    cliStep ⟨.opened, out⟩ (.localClose t) = ⟨.gone, .cc :: out⟩ := rfl

end Flare.L3.Quic.Timers
