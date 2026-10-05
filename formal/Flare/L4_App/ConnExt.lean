import Flare.Core

/-!
# Connection extensions: the h2c upgrade hand-off and the WebSocket upgrade

Two places where an HTTP/1.1 `ConnHandle` leaves the request/response loop.

**h2c (`H2c`).** After `_start_h2c_upgrade` queues the 101, the handle sets
`_h2c_upgrade_pending`; once the 101 has flushed, every `on_writable`
returns `h2c_upgrade = True` with no interest bits
(flare/http/_reactor/conn_handle.mojo:1353-1362). Only `_drive_h1`
(flare/http/_unified_reactor_impl.mojo:174-215) acts on that cue by
migrating the connection to `KIND_H2`, whose first write is the server
SETTINGS frame. A writable edge on a `KIND_H1` connection goes to
`_drive_h1_writable` (:812-855) unless it is a TLS cross-interest edge, and
that driver applies the step through `_apply_step` (:243-258), which with no
interest bits leaves the old write interest armed.

The model keeps what decides the outcome: the connection kind, whether the
upgrade is pending, how many bytes of the 101 are still queued, and whether
write interest is armed. The client sends nothing after the upgrade request
until it sees the server preface (RFC 7540 §3.2), so the only events are
writable edges, which keep coming while write interest is armed
(level-triggered epoll and kqueue). A writable edge flushes what is queued
(the peer has drained its receive buffer).

Spec (RFC 7540 §3.2): once the 101 is on the wire, the connection is HTTP/2
and the server's next bytes are its connection preface; here: after the
writable edge that flushes the 101, the connection is `KIND_H2`.

**WebSocket over TLS (`Ws`).** `on_readable`'s upgrade branch
(conn_handle.mojo:838-875) calls `_handle_ws_upgrade` whenever
`config.ws.handler` is set; that function detaches the raw fd and writes the
101 and every frame with a plain `TcpStream` (:1476-1574). The h2c branch
just below checks `not self.tls` (:881); this one does not. A TLS
connection reaches it through `_migrate_tls`
(flare/http/_unified_reactor_impl.mojo:545-552).

Spec (server.mojo:813-814, conn_handle.mojo:1506-1508: "Cleartext only: a
wss:// connection is terminated by the TLS connection handler, which has no
upgrade seam"): nothing on a TLS connection is written in cleartext.
APP-48 is fixed: the branch is guarded by `not self.tls`, as the h2c branch
below it is; the pre-fix definitions are kept as `upgradeTakenOld` and
`wireOld`.
-/
namespace Flare.L4.ConnExt

namespace H2c

inductive Kind | h1 | h2
  deriving DecidableEq, Repr

structure St where
  kind : Kind
  pending : Bool
  queued : Nat
  armedW : Bool
  deriving DecidableEq, Repr

/-- `on_writable` on the h1 handle: flush everything queued; with the
upgrade pending and nothing left, report `h2c_upgrade` and no interest.
mirrors flare/http/_reactor/conn_handle.mojo:1353-1362 @59bda50 -/
def onWritable (s : St) : St × Bool :=
  let s := { s with queued := 0 }
  (s, s.pending)

/-- `_migrate_h1_to_h2` followed by the first `_drive_h2`: the h2 handle
queues its SETTINGS frame and arms write interest.
mirrors flare/http/_unified_reactor_impl.mojo:197-219 @59bda50 -/
def migrate (s : St) : St := { s with kind := .h2, pending := false, armedW := true }

/-- `_drive_h1` on a connection whose request is already parsed: the
inline `on_writable`, then migration on the `h2c_upgrade` cue.
mirrors flare/http/_unified_reactor_impl.mojo:174-215 @59bda50 -/
def driveH1 (s : St) : St :=
  let (s', up) := onWritable s
  if up then migrate s' else s'

/-- `_drive_h1_writable`: `on_writable`, then `_apply_step`, which with no
interest bits keeps the armed write interest.
mirrors flare/http/_unified_reactor_impl.mojo:243-258 @59bda50 -/
def driveH1Writable (s : St) : St := (onWritable s).1

/-- Routing of a writable edge on a `KIND_H1` connection. `fix = false` is
the pre-fix routing (`preFix`); `fix = true` (`shipped`) also sends the edge
to `_drive_h1` while an upgrade is pending.
mirrors flare/http/_unified_reactor_impl.mojo:812-855 @59bda50 (pre-fix);
mirrors flare/http/_unified_reactor_impl.mojo:806-868 (fixed, APP-47) -/
def route (fix : Bool) (s : St) : St :=
  match s.kind with
  | .h2 => s
  | .h1 => if fix && s.pending then driveH1 s else driveH1Writable s

/-- The routing before the APP-47 fix. -/
abbrev preFix : Bool := false

/-- The routing flare ships: a pending upgrade goes to `_drive_h1`. -/
abbrev shipped : Bool := true

/-- `n` writable edges (each only while write interest is armed). -/
def run (fix : Bool) : Nat → St → St
  | 0, s => s
  | n + 1, s => if s.armedW then run fix n (route fix s) else s

/-- The state after `_drive_h1` handled the upgrade request with a full
send buffer: the 101 is queued, the upgrade pending, write interest armed. -/
def blocked (q : Nat) : St := ⟨.h1, true, q, true⟩

/-- RFC 7540 §3.2: once a writable edge has flushed the 101, the
connection is HTTP/2. -/
def Spec (fix : Bool) : Prop := ∀ q n, 0 < n → (run fix n (blocked q)).kind = .h2

theorem run_impl_stuck (q n : Nat) :
    run false n (blocked q) = if n = 0 then blocked q else ⟨.h1, true, 0, true⟩ := by
  induction n generalizing q with
  | zero => rfl
  | succ n ih =>
    simp only [run, blocked, if_true, route, driveH1Writable, onWritable]
    cases n with
    | zero => rfl
    | succ n =>
      have := ih 0
      simp only [blocked, Nat.add_one_ne_zero, if_false] at this ⊢
      exact this

/-- **flare**: after any number of writable edges the connection is still
`KIND_H1`, still write-armed, and still reports the upgrade: a busy spin
that never sends the preface. -/
theorem impl_spins (q n : Nat) (hn : 0 < n) :
    run false n (blocked q) = ⟨.h1, true, 0, true⟩ := by
  rw [run_impl_stuck]; simp [show n ≠ 0 by omega]

theorem impl_violates : ¬ Spec false := by
  intro h
  have := h 0 1 (by decide)
  rw [impl_spins 0 1 (by decide)] at this
  cases this

theorem run_h2 (fix : Bool) (n : Nat) (s : St) (h : s.kind = .h2) :
    (run fix n s).kind = .h2 := by
  induction n generalizing s with
  | zero => exact h
  | succ n ih =>
    unfold run
    split
    · apply ih; simp [route, h]
    · exact h

/-- **The fix**: the first writable edge migrates, and the connection
stays HTTP/2. -/
theorem fixed_spec : Spec true := by
  intro q n hn
  obtain ⟨m, rfl⟩ : ∃ m, n = m + 1 := ⟨n - 1, by omega⟩
  simp only [run, blocked, if_true]
  exact run_h2 true m _ rfl

end H2c

namespace Ws

/-- Where the 101 and the frames of an accepted WebSocket go. -/
inductive Wire | tls | cleartext
  deriving DecidableEq, Repr

/-- `on_readable` takes the WebSocket branch: a handler is configured, the
connection is not TLS, and the request is a version-13 handshake.
mirrors flare/http/_reactor/conn_handle.mojo:838-885 (fixed, APP-48) -/
def upgradeTaken (wsHandler tls isWs : Bool) : Bool :=
  wsHandler && !tls && isWs

/-- The pre-fix branch condition: it did not look at `self.tls`.
mirrors flare/http/_reactor/conn_handle.mojo:838-875 @59bda50 -/
def upgradeTakenOld (wsHandler _tls isWs : Bool) : Bool :=
  wsHandler && isWs

/-- Where the answer goes, given the branch condition: `_handle_ws_upgrade`
writes on the detached raw fd; every other path goes through the
connection's (TLS or plain) stream.
mirrors flare/http/_reactor/conn_handle.mojo:1476-1574 (fixed, APP-48) -/
def wireWith (taken : Bool → Bool → Bool → Bool) (wsHandler tls isWs : Bool) : Wire :=
  if taken wsHandler tls isWs then .cleartext
  else if tls then .tls else .cleartext

/-- The shipped implementation. -/
def wire : Bool → Bool → Bool → Wire := wireWith upgradeTaken

/-- The pre-fix implementation (APP-48). -/
def wireOld : Bool → Bool → Bool → Wire := wireWith upgradeTakenOld

/-- "Cleartext only": a TLS connection never writes in cleartext. -/
def Spec (w : Bool → Bool → Bool → Wire) : Prop := ∀ ws isWs, w ws true isWs = .tls

/-- **Pre-fix flare**: a valid handshake on a TLS connection with a handler
is answered in cleartext. -/
theorem old_violates : wireOld true true true = .cleartext ∧ ¬ Spec wireOld := by
  refine ⟨rfl, fun h => ?_⟩
  have := h true true
  simp [wireOld, wireWith, upgradeTakenOld] at this

/-- **The shipped branch** keeps every TLS connection inside TLS. -/
theorem spec : Spec wire := by
  intro ws isWs; simp [wire, wireWith, upgradeTaken]

/-- The fix changes nothing on cleartext connections. -/
theorem cleartext_same (ws isWs : Bool) :
    upgradeTaken ws false isWs = upgradeTakenOld ws false isWs := by
  simp [upgradeTaken, upgradeTakenOld]

end Ws

end Flare.L4.ConnExt
