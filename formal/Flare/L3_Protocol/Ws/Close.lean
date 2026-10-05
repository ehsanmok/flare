import Flare.L3_Protocol.Ws.Frame

/-!
# WebSocket closing handshake (RFC 6455 §5.5.1, §7.1.5, §7.4)

An endpoint is a step function over the events an application sees: a
received frame, `send_text`/`send_binary`, and `close(code)`. Each step
writes a list of frames. `outs` runs it over a trace.

* `validPayload`: a CLOSE body is empty, or a 2-byte code from the valid
  ranges (1000-1003, 1007-1014, 3000-4999; RFC 6455 §7.4.1, §7.4.2 and the
  IANA registry) followed by UTF-8. `closeReply` is the CLOSE an endpoint
  answers with: the received code (or an empty body), or 1002 when the body
  is invalid.
* `CloseOK` (via `Good`): on every trace, (1) a received CLOSE, while no
  CLOSE has been written, is answered by `closeReply`; (2) once a CLOSE has
  been written, no data frame follows.
* `oldStep` is `WsConnection` before the WS-06 fix (`flare/ws/server.mojo`
  @59bda50): `recv` answers PING and hands CLOSE to the caller without a
  reply, `close()` keeps no state, `send_*` never check. Kept for the
  counterexamples (`Flare.Bugs.WS_06`).
* `fixStep` is the shipped `WsConnection`: it keeps a `close_sent` flag;
  `fixed_closeOK` proves it meets `CloseOK` on every trace.
-/
namespace Flare.L3.Ws.Close

open Flare.L3.Ws (be16)

def validCode (c : Nat) : Bool :=
  (1000 ≤ c && c ≤ 1003) || (1007 ≤ c && c ≤ 1014) || (3000 ≤ c && c ≤ 4999)

def codeOf (p : Bytes) : Nat := (p.getD 0).toNat * 256 + (p.getD 1).toNat

def validPayload (p : Bytes) : Bool :=
  p.isEmpty || (2 ≤ p.length && validCode (codeOf p) && Flare.L1.Utf8.isValidUtf8 (p.drop 2))

def closeReply (p : Bytes) : Bytes := if validPayload p then p.take 2 else be16 1002

structure Out where
  op : UInt8
  payload : Bytes
  deriving DecidableEq, Repr

inductive Act where
  | recv (op : UInt8) (p : Bytes)
  | sendText (p : Bytes)
  | sendBinary (p : Bytes)
  | close (code : Nat)
  deriving DecidableEq, Repr

def outs {σ : Type} (step : σ → Act → σ × List Out) : σ → List Act → List (List Out)
  | _, [] => []
  | s, a :: as => (step s a).2 :: outs step (step s a).1 as

def isCloseOut (o : Out) : Bool := o.op == 8
def isDataOut (o : Out) : Bool := o.op == 0 || o.op == 1 || o.op == 2

/-- `sent`: a CLOSE has already been written. -/
def Good : Bool → List Act → List (List Out) → Prop
  | sent, a :: as, o :: os =>
    (sent = true → ∀ f ∈ o, isDataOut f = false) ∧
    (sent = false → ∀ p, a = .recv 8 p → (⟨8, closeReply p⟩ : Out) ∈ o) ∧
    Good (sent || o.any isCloseOut) as os
  | _, [], [] => True
  | _, _, _ => False

def CloseOK {σ : Type} (step : σ → Act → σ × List Out) (init : σ) : Prop :=
  ∀ acts, Good false acts (outs step init acts)

/-- `WsConnection.recv` (PING answered, everything else returned to the
caller), `send_text`/`send_binary` (no check) and `close` (writes CLOSE,
keeps no state), before the WS-06 fix.
mirrors flare/ws/server.mojo:473-536 and 600-616 @59bda50 -/
def oldStep : Unit → Act → Unit × List Out
  | _, .recv op p => if op = 9 then ((), [⟨10, p⟩]) else ((), [])
  | _, .sendText p => ((), [⟨1, p⟩])
  | _, .sendBinary p => ((), [⟨2, p⟩])
  | _, .close c => ((), [⟨8, be16 c⟩])

/-- The shipped `WsConnection`: `recv` answers a CLOSE (`closeReply`) unless one
was sent, `close()` sends once, `send_*` and `send_frame` raise (write
nothing) after a CLOSE.
mirrors flare/ws/server.mojo:525-720 (fixed, WS-06) -/
def fixStep : Bool → Act → Bool × List Out
  | s, .recv op p =>
    if op = 9 then (s, [⟨10, p⟩])
    else if op = 8 ∧ s = false then (true, [⟨8, closeReply p⟩])
    else (s, [])
  | s, .sendText p => if s then (s, []) else (s, [⟨1, p⟩])
  | s, .sendBinary p => if s then (s, []) else (s, [⟨2, p⟩])
  | s, .close c => if s then (s, []) else (true, [⟨8, be16 c⟩])

theorem fix_state (s : Bool) (a : Act) :
    (s || (fixStep s a).2.any isCloseOut) = (fixStep s a).1 := by
  cases a with
  | recv op p =>
    by_cases h9 : op = 9
    · subst h9; cases s <;> simp [fixStep, isCloseOut]
    · by_cases h8 : op = 8
      · subst h8; cases s <;> simp [fixStep, isCloseOut]
      · cases s <;> simp [fixStep, h9, h8]
  | sendText p => cases s <;> simp [fixStep, isCloseOut]
  | sendBinary p => cases s <;> simp [fixStep, isCloseOut]
  | close c => cases s <;> simp [fixStep, isCloseOut]

theorem fix_noData (a : Act) : ∀ f ∈ (fixStep true a).2, isDataOut f = false := by
  cases a with
  | recv op p =>
    by_cases h9 : op = 9
    · subst h9; simp [fixStep, isDataOut]
    · simp [fixStep, h9]
  | sendText p => simp [fixStep]
  | sendBinary p => simp [fixStep]
  | close c => simp [fixStep]

theorem fix_reply (p : Bytes) : (⟨8, closeReply p⟩ : Out) ∈ (fixStep false (.recv 8 p)).2 := by
  simp [fixStep]

theorem fixed_good : ∀ (acts : List Act) (s : Bool), Good s acts (outs fixStep s acts)
  | [], _ => by simp [outs, Good]
  | a :: as, s => by
    simp only [outs, Good]
    refine ⟨?_, ?_, ?_⟩
    · intro hs; subst hs; exact fix_noData a
    · intro hs p hp; subst hs; subst hp; exact fix_reply p
    · rw [fix_state]; exact fixed_good as _

theorem fixed_closeOK : CloseOK fixStep false := fun acts => fixed_good acts false

end Flare.L3.Ws.Close
