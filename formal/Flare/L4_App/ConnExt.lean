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
`_drive_h1_writable` (:812-855) unless it is a TLS cross-interest edge or an
upgrade is pending (APP-47); that driver applies the step through
`_apply_step` (:243-258), which with no interest bits leaves the old write
interest armed.

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

**WebSocket over TLS (`Ws`).** `on_readable`'s upgrade branch calls
`_handle_ws_upgrade`, which detaches the raw fd and writes the 101 and every
frame with a plain `TcpStream`. A TLS connection reaches `on_readable`
through `_migrate_tls`, so the branch is guarded by `not self.tls`, as the
h2c branch below it is (APP-48).

Spec (server.mojo:813-814, conn_handle.mojo:1506-1508: "Cleartext only: a
wss:// connection is terminated by the TLS connection handler, which has no
upgrade seam"): nothing on a TLS connection is written in cleartext.
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
mirrors flare/http/_reactor/conn_handle.mojo#ConnHandle.on_writable sha=97ab3b583fa2 at=59bda50f -/
def onWritable (s : St) : St × Bool :=
  let s := { s with queued := 0 }
  (s, s.pending)

/-- `_migrate_h1_to_h2` followed by the first `_drive_h2`: the h2 handle
queues its SETTINGS frame and arms write interest.
mirrors flare/http/_unified_reactor_impl.mojo#_drive_h1 sha=6001dd107a8a at=59bda50f -/
def migrate (s : St) : St := { s with kind := .h2, pending := false, armedW := true }

/-- `_drive_h1` on a connection whose request is already parsed: the
inline `on_writable`, then migration on the `h2c_upgrade` cue.
mirrors flare/http/_unified_reactor_impl.mojo#_drive_h1 sha=6001dd107a8a at=59bda50f -/
def driveH1 (s : St) : St :=
  let (s', up) := onWritable s
  if up then migrate s' else s'

/-- `_drive_h1_writable`: `on_writable`, then `_apply_step`, which with no
interest bits keeps the armed write interest.
mirrors flare/http/_unified_reactor_impl.mojo#_drive_h1_writable sha=2454d2dd98b9 at=59bda50f -/
def driveH1Writable (s : St) : St := (onWritable s).1

/-- Routing of a writable edge on a `KIND_H1` connection: while an upgrade is
pending the edge goes to `_drive_h1`.
mirrors flare/http/_unified_reactor_impl.mojo#_unified_handle_conn_event sha=bba7c346f73a at=da6fb43a (fixed, APP-47) -/
def route (s : St) : St :=
  match s.kind with
  | .h2 => s
  | .h1 => if s.pending then driveH1 s else driveH1Writable s

/-- `n` writable edges (each only while write interest is armed). -/
def run : Nat → St → St
  | 0, s => s
  | n + 1, s => if s.armedW then run n (route s) else s

/-- The state after `_drive_h1` handled the upgrade request with a full
send buffer: the 101 is queued, the upgrade pending, write interest armed. -/
def blocked (q : Nat) : St := ⟨.h1, true, q, true⟩

/-- RFC 7540 §3.2: once a writable edge has flushed the 101, the
connection is HTTP/2. -/
def Spec : Prop := ∀ q n, 0 < n → (run n (blocked q)).kind = .h2

theorem run_h2 (n : Nat) (s : St) (h : s.kind = .h2) : (run n s).kind = .h2 := by
  induction n generalizing s with
  | zero => exact h
  | succ n ih =>
    unfold run
    split
    · apply ih; simp [route, h]
    · exact h

/-- The first writable edge migrates, and the connection stays HTTP/2. -/
theorem run_spec : Spec := by
  intro q n hn
  obtain ⟨m, rfl⟩ : ∃ m, n = m + 1 := ⟨n - 1, by omega⟩
  simp only [run, blocked, if_true]
  exact run_h2 m _ rfl

end H2c

namespace Ws

/-- Where the 101 and the frames of an accepted WebSocket go. -/
inductive Wire | tls | cleartext
  deriving DecidableEq, Repr

/-- `on_readable` takes the WebSocket branch: a handler is configured, the
connection is not TLS, and the request is a version-13 handshake.
mirrors flare/http/_reactor/conn_handle.mojo#ConnHandle.on_readable sha=5f85dfb8b98a at=da6fb43a (fixed, APP-48) -/
def upgradeTaken (wsHandler tls isWs : Bool) : Bool :=
  wsHandler && !tls && isWs

/-- Where the answer goes, given the branch condition: `_handle_ws_upgrade`
writes on the detached raw fd; every other path goes through the
connection's (TLS or plain) stream.
mirrors flare/http/_reactor/conn_handle.mojo#ConnHandle._start_h2c_upgrade+ConnHandle._handle_ws_upgrade sha=9774bd2a2578 at=da6fb43a (fixed, APP-48) -/
def wire (wsHandler tls isWs : Bool) : Wire :=
  if upgradeTaken wsHandler tls isWs then .cleartext
  else if tls then .tls else .cleartext

/-- "Cleartext only": a TLS connection never writes in cleartext. -/
def Spec (w : Bool → Bool → Bool → Wire) : Prop := ∀ ws isWs, w ws true isWs = .tls

/-- Every TLS connection stays inside TLS. -/
theorem spec : Spec wire := by
  intro ws isWs; simp [wire, upgradeTaken]

end Ws

end Flare.L4.ConnExt
