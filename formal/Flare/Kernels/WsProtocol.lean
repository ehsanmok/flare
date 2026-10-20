import Flare.Core.Bytes
import Flare.L1_Encoding.Utf8

/-!
# WebSocket server protocol core (ws/protocol.mojo)

Every server carrier -- HTTP/1.1 on the reactor, HTTP/2 and HTTP/3
tunnels -- hands the frames a client sends to `WsProtocol`, which decides
what is delivered to the application and what is sent back. This file
states what RFC 6455 requires of that decision. The frame decoder itself
is covered by `Flare.L3.Ws` (`decodeKnown`); here a frame has already
been decoded, or decoding failed.

The spec is over a run: the inputs fed in and the outputs produced.

* `SafeRun`: delivered messages respect the cap and, for text, are UTF-8;
  at most one CLOSE is sent; after it nothing else is sent or delivered;
  the session ends at most once and nothing follows the end.
* `MaskRule`, `SequenceRule`, `CapRule`, `Utf8Rule`: the violation that
  ends the session sends the CLOSE code the RFC names.
* `CloseReplyRule`: a CLOSE from the peer, before we sent one, is
  answered with exactly one CLOSE echoing a valid code, or 1002.
* `OutboxBound`: the bytes queued for the peer never exceed the bound by
  more than one frame.

The impl model (`step`, `run`) transliterates the frame-level decisions of
`next_event` / `_on_frame`; the frame decoder's guarantees are the `WF`
hypothesis. Theorems:

* `run_safe`: `SafeRun` holds for every run from a fresh session.
* `mask_rule`, `sequence_rule`, `cap_rule`, `close_reply_rule`: each rule
  holds at every live state; `utf8_rule` for every message completion.
* `outbox_bound`: `OutboxBound max_outbox 131` for the outbox after every
  step: past the bound the session fails, and the step that ends it adds at
  most one PONG and one CLOSE.
-/
namespace Flare.Kernels.WsProtocol
open Flare
open Flare.L1.Utf8 (isValidUtf8)

inductive Op where
  | text | binary | cont | ping | pong | close
  deriving DecidableEq, Repr

structure Frame where
  op : Op
  fin : Bool
  masked : Bool
  payload : Bytes
  deriving DecidableEq, Repr

/-- What the core is fed: a decoded frame, or a frame the decoder refused
(`tooBig` when its declared length exceeded the cap). -/
inductive In where
  | frame (f : Frame)
  | bad (tooBig : Bool)
  deriving DecidableEq, Repr

/-- What the core produces. `sendClose none` is a CLOSE with an empty body. -/
inductive Out where
  | deliver (isText : Bool) (payload : Bytes)
  | sendPong (payload : Bytes)
  | sendClose (code : Option Nat)
  | ended (code : Nat)
  deriving DecidableEq, Repr

def isSendClose : Out → Bool
  | .sendClose _ => true
  | _ => false

def isEnded : Out → Bool
  | .ended _ => true
  | _ => false

def isSend : Out → Bool
  | .sendPong _ => true
  | .sendClose _ => true
  | _ => false

/-- RFC 6455 sec 7.4.1 plus the IANA registry: codes a CLOSE may carry. -/
def validCloseCode (c : Nat) : Bool :=
  (1000 ≤ c ∧ c ≤ 1003) ∨ (1007 ≤ c ∧ c ≤ 1014) ∨ (3000 ≤ c ∧ c ≤ 4999)

/-- [spec] The CLOSE that answers a received CLOSE body (sec 5.5.1, 7.1.7,
7.4.1): empty is echoed empty; a valid code with a UTF-8 reason is
echoed; anything else is answered with 1002. -/
def specCloseReply (body : Bytes) : Option Nat :=
  match body with
  | [] => none
  | [_] => some 1002
  | a :: b :: reason =>
    let c := a.toNat * 256 + b.toNat
    if validCloseCode c ∧ isValidUtf8 reason then some c else some 1002

/-- [spec] Safety of any run. -/
def SafeRun (maxMessage : Nat) (outs : List Out) : Prop :=
  (∀ t p, Out.deliver t p ∈ outs → p.length ≤ maxMessage) ∧
  (∀ p, Out.deliver true p ∈ outs → isValidUtf8 p = true) ∧
  (outs.countP isSendClose ≤ 1) ∧
  (∀ i j, (hij : i < j) → (hj : j < outs.length) →
    isSendClose (outs[i]'(Nat.lt_trans hij hj)) = true →
    isSendClose (outs[j]) = false ∧ (∀ t p, outs[j] ≠ Out.deliver t p) ∧
    (∀ p, outs[j] ≠ Out.sendPong p)) ∧
  (outs.countP isEnded ≤ 1) ∧
  (∀ i, (h : i < outs.length) → isEnded (outs[i]) = true → i + 1 = outs.length)

/-- [spec] An unmasked client frame ends the session with 1002 (sec 5.1). -/
def MaskRule (step : In → List Out) : Prop :=
  ∀ f, f.masked = false → Out.ended 1002 ∈ step (.frame f)

/-- [spec] A CONTINUATION with no message open, or a TEXT/BINARY frame
while one is open, ends the session with 1002 (sec 5.4). `fragOpen` is
whether a fragmented message is in progress. -/
def SequenceRule (step : Bool → In → List Out) : Prop :=
  (∀ f, f.masked = true → f.op = .cont → Out.ended 1002 ∈ step false (.frame f)) ∧
  (∀ f, f.masked = true → (f.op = .text ∨ f.op = .binary) →
    Out.ended 1002 ∈ step true (.frame f))

/-- [spec] A frame the decoder refused for its length ends the session
with 1009 (sec 7.4.1); any other refusal with 1002. -/
def CapRule (step : In → List Out) : Prop :=
  Out.ended 1009 ∈ step (.bad true) ∧ Out.ended 1002 ∈ step (.bad false)

/-- [spec] A complete text message that is not UTF-8 is not delivered and
ends the session with 1007 (sec 8.1). `msg` is the reassembled payload
the final frame completes. -/
def Utf8Rule (complete : Bytes → List Out) : Prop :=
  ∀ msg, isValidUtf8 msg = false →
    Out.ended 1007 ∈ complete msg ∧ ∀ t, Out.deliver t msg ∉ complete msg

/-- [spec] A CLOSE from the peer before we sent one gets exactly one
reply, `specCloseReply` of its body, and ends the session (sec 5.5.1). -/
def CloseReplyRule (step : In → List Out) : Prop :=
  ∀ f, f.masked = true → f.op = .close →
    (step (.frame f)).countP isSendClose = 1 ∧
    Out.sendClose (specCloseReply f.payload) ∈ step (.frame f)

/-- [spec] The bytes waiting for the peer stay within `bound` plus one
frame of at most `frameMax` bytes: a client that does not read cannot
make the server buffer without limit. -/
def OutboxBound (bound frameMax : Nat) (queued : List Nat) : Prop :=
  ∀ q ∈ queued, q ≤ bound + frameMax

/-! ## Impl model -/

/-- Server-to-client frame length on the wire (`WsFrame.encode(mask=False)`). -/
def frameLen (n : Nat) : Nat := 2 + (if n < 126 then 0 else if n < 65536 then 2 else 8) + n

/-- The session state: `close_sent`, `close_received`, `failed`, the open
fragmented message (`_frag_opcode` as `isText`, `_frag`), and the bytes
queued in `outbox`. -/
structure St where
  closeSent : Bool
  closeRecv : Bool
  failed : Bool
  frag : Option (Bool × Bytes)
  queued : Nat

def St.init : St := ⟨false, false, false, none, 0⟩

/-- `WsProtocol.finished` -/
def finished (s : St) : Bool := s.failed || s.closeRecv

/-- The code a CLOSE body carries: `none` for an empty body. -/
def bodyCode : Bytes → Option Nat
  | a :: b :: _ => some (a.toNat * 256 + b.toNat)
  | _ => none

/-- `_close_reply_payload` -/
def replyBody (body : Bytes) : Bytes :=
  match body with
  | [] => []
  | [_] => [3, 234]
  | a :: b :: reason =>
    if validCloseCode (a.toNat * 256 + b.toNat) && isValidUtf8 reason then [a, b] else [3, 234]

/-- `close(code)`: one CLOSE at most. -/
def closeWith (s : St) (code : Nat) : St × List Out :=
  if s.closeSent then (s, [])
  else ({ s with closeSent := true, queued := s.queued + 4 }, [.sendClose (some code)])

/-- `_fail(code)` followed by the `WS_EVENT_CLOSED` event it reports. -/
def fail (s : St) (code : Nat) : St × List Out :=
  let r := closeWith { s with failed := true } code
  (r.1, r.2 ++ [.ended code])

/-- `_message` -/
def message (s : St) (isText : Bool) (p : Bytes) : St × List Out :=
  if isText && !isValidUtf8 p then fail s 1007 else (s, [.deliver isText p])

/-- One decoded input, as `next_event` handles it (the body of its loop and
`_on_frame`). `m` is `max_message`, `mo` is `max_outbox`.
mirrors flare/ws/protocol.mojo#WsProtocol.next_event+WsProtocol._on_frame+WsProtocol._message+WsProtocol._fail+WsProtocol.close+WsProtocol._send+_close_reply_payload+_valid_close_code sha=763db3da93dd at=240066a4 -/
def step (m mo : Nat) (s : St) (i : In) : St × List Out :=
  if finished s then (s, []) else
  match i with
  | .bad tooBig => fail s (if tooBig then 1009 else 1002)
  | .frame f =>
    if f.masked = false then fail s 1002 else
    match f.op with
    | .ping =>
      if s.closeSent then (s, []) else
      let s1 := { s with queued := s.queued + frameLen f.payload.length }
      if s1.queued > mo then
        let r := fail s1 1008
        (r.1, .sendPong f.payload :: r.2)
      else (s1, [.sendPong f.payload])
    | .pong => (s, [])
    | .close =>
      let code := (bodyCode f.payload).getD 1005
      let s1 := { s with closeRecv := true }
      if s.closeSent then (s1, [.ended code])
      else
        let body := replyBody f.payload
        ({ s1 with closeSent := true, queued := s1.queued + frameLen body.length },
         [.sendClose (bodyCode body), .ended code])
    | .cont =>
      match s.frag with
      | none => fail s 1002
      | some (t, d) =>
        if d.length + f.payload.length > m then fail s 1009
        else if f.fin then message { s with frag := none } t (d ++ f.payload)
        else ({ s with frag := some (t, d ++ f.payload) }, [])
    | .text | .binary =>
      match s.frag with
      | some _ => fail s 1002
      | none =>
        if f.fin then message s (f.op == .text) f.payload
        else ({ s with frag := some (f.op == .text, f.payload) }, [])

/-- Feed inputs in order; the outputs of every step, concatenated. -/
def run (m mo : Nat) : St → List In → St × List Out
  | s, [] => (s, [])
  | s, i :: is =>
    let r := step m mo s i
    let r2 := run m mo r.1 is
    (r2.1, r.2 ++ r2.2)

/-- The `outbox` length after each step. -/
def queuedTrace (m mo : Nat) : St → List In → List Nat
  | _, [] => []
  | s, i :: is => let s' := (step m mo s i).1; s'.queued :: queuedTrace m mo s' is

/-- What the frame decoder guarantees about what it hands over: a payload
within `max_message`, and a control payload of at most 125 bytes. -/
def WF (m : Nat) : In → Prop
  | .frame f => f.payload.length ≤ m ∧
      ((f.op = .ping ∨ f.op = .pong ∨ f.op = .close) → f.payload.length ≤ 125)
  | .bad _ => True

/-! ## Per-step rules -/

theorem step_finished (m mo : Nat) (s : St) (i : In) (h : finished s = true) :
    step m mo s i = (s, []) := by
  simp [step, h]

theorem fail_ended (s : St) (c : Nat) : Out.ended c ∈ (fail s c).2 := by
  simp [fail]

theorem mask_rule (m mo : Nat) (s : St) (h : finished s = false) :
    MaskRule (fun i => (step m mo s i).2) := by
  intro f hf
  simp [step, h, hf, fail_ended]

theorem cap_rule (m mo : Nat) (s : St) (h : finished s = false) :
    CapRule (fun i => (step m mo s i).2) := by
  simp [CapRule, step, h, fail_ended]

/-- `s` with a fragmented message open or not. -/
def withFrag (s : St) (b : Bool) : St :=
  { s with frag := if b then some (s.frag.getD (true, [])) else none }

theorem sequence_rule (m mo : Nat) (s : St) (h : finished s = false) :
    SequenceRule (fun b i => (step m mo (withFrag s b) i).2) := by
  have h' : (s.failed || s.closeRecv) = false := h
  constructor
  · intro f hm ho
    simp [step, finished, h', hm, ho, withFrag, fail_ended]
  · intro f hm ho
    rcases ho with ho | ho <;> simp [step, finished, h', hm, ho, withFrag, fail_ended]

theorem utf8_rule (s : St) : Utf8Rule (fun msg => (message s true msg).2) := by
  intro msg hbad
  simp [message, hbad, fail, closeWith]
  split <;> simp

theorem replyBody_code (b : Bytes) : bodyCode (replyBody b) = specCloseReply b := by
  match b with
  | [] => rfl
  | [_] => rfl
  | a :: c :: r =>
    simp only [replyBody, specCloseReply]
    by_cases hv : validCloseCode (a.toNat * 256 + c.toNat) = true <;>
    by_cases hu : isValidUtf8 r = true <;> simp [hv, hu, bodyCode]

theorem close_reply_rule (m mo : Nat) (s : St) (h : finished s = false)
    (hc : s.closeSent = false) : CloseReplyRule (fun i => (step m mo s i).2) := by
  intro f hm ho
  simp [step, h, hm, ho, hc, replyBody_code]
  rfl

/-! ## Whole runs -/

def Quiet (m : Nat) : Out → Prop
  | .sendPong _ => True
  | .deliver t p => p.length ≤ m ∧ (t = true → isValidUtf8 p = true)
  | _ => False

def Tail (t : List Out) : Prop :=
  t = [] ∨ (∃ c, t = [.ended c]) ∨ ∃ x c, t = [.sendClose x, .ended c]

def Inv (m : Nat) (s : St) : Prop :=
  (s.closeSent = true → finished s = true) ∧ (∀ t d, s.frag = some (t, d) → d.length ≤ m)

def StepOk (m : Nat) (r : St × List Out) : Prop :=
  Inv m r.1 ∧
  (((∀ o ∈ r.2, Quiet m o) ∧ finished r.1 = false) ∨
   (∃ q t, r.2 = q ++ t ∧ (∀ o ∈ q, Quiet m o) ∧ Tail t ∧ finished r.1 = true))

theorem fail_ok (m : Nat) (s : St) (c : Nat) (hi : Inv m s) : StepOk m (fail s c) := by
  unfold fail closeWith
  split
  · refine ⟨⟨fun _ => by simp [finished], hi.2⟩, Or.inr ⟨[], [.ended c], by simp, by simp, by simp [Tail], by simp [finished]⟩⟩
  · refine ⟨⟨fun _ => by simp [finished], hi.2⟩,
      Or.inr ⟨[], [.sendClose (some c), .ended c], by simp, by simp, by simp [Tail], by simp [finished]⟩⟩

theorem message_ok (m : Nat) (s : St) (t : Bool) (p : Bytes) (hi : Inv m s)
    (hf : finished s = false) (hp : p.length ≤ m) : StepOk m (message s t p) := by
  unfold message
  split
  · exact fail_ok m s 1007 hi
  · rename_i hu
    refine ⟨hi, Or.inl ⟨?_, hf⟩⟩
    intro o ho
    simp at ho
    subst ho
    refine ⟨hp, fun ht => ?_⟩
    subst ht
    simpa using hu

theorem step_ok (m mo : Nat) (s : St) (i : In) (hi : Inv m s) (hf : finished s = false)
    (hw : WF m i) : StepOk m (step m mo s i) := by
  have hf' : (s.failed || s.closeRecv) = false := hf
  have hcs : s.closeSent = false := by
    cases h : s.closeSent
    · rfl
    · have := hi.1 h; rw [hf] at this; exact absurd this (by simp)
  have hcl : ∀ s' : St, s'.closeSent = false → s'.closeSent = true → finished s' = true := by
    intro s' h1 h2; rw [h1] at h2; exact absurd h2 (by simp)
  cases i with
  | bad b => simp only [step, hf, Bool.false_eq_true, ↓reduceIte]; exact fail_ok m s _ hi
  | frame f =>
    by_cases hm : f.masked = false
    · simp only [step, hf, hm, Bool.false_eq_true, ↓reduceIte]; exact fail_ok m s _ hi
    · have hm' : f.masked = true := by simpa using hm
      obtain ⟨hlen, hctl⟩ := hw
      cases hop : f.op with
      | ping =>
        simp only [step, hf, hm', hop, hcs, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
        split
        · have h1 := fail_ok m { s with queued := s.queued + frameLen f.payload.length } 1008
            ⟨hcl _ (by simp [*]), hi.2⟩
          simp only [hcs] at h1
          refine ⟨h1.1, ?_⟩
          rcases h1.2 with ⟨_, hfin⟩ | ⟨q, t, he, hq', ht, hfin⟩
          · exact absurd hfin (by simp [fail, closeWith, finished])
          · refine Or.inr ⟨.sendPong f.payload :: q, t, by simp [he], ?_, ht, hfin⟩
            intro o ho; simp at ho; rcases ho with rfl | ho
            · trivial
            · exact hq' o ho
        · refine ⟨⟨hcl _ (by simp [*]), hi.2⟩, Or.inl ⟨?_, by simpa [finished] using hf'⟩⟩
          intro o ho; simp at ho; subst ho; trivial
      | pong =>
        simp only [step, hf, hm', hop, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
        exact ⟨hi, Or.inl ⟨by simp, hf⟩⟩
      | close =>
        simp only [step, hf, hm', hop, hcs, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
        exact ⟨⟨fun _ => by simp [finished], hi.2⟩,
          Or.inr ⟨[], [.sendClose (bodyCode (replyBody f.payload)), .ended ((bodyCode f.payload).getD 1005)],
            by simp, by simp, by simp [Tail], by simp [finished]⟩⟩
      | cont =>
        cases hfr : s.frag with
        | none =>
          simp only [step, hf, hm', hop, hfr, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
          exact fail_ok m s _ hi
        | some td =>
          obtain ⟨t, d⟩ := td
          have hd := hi.2 t d hfr
          simp only [step, hf, hm', hop, hfr, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
          split
          · exact fail_ok m s _ hi
          · rename_i hcap
            split
            · exact message_ok m _ t _ ⟨hcl _ (by simp [*]), by simp⟩
                (by simpa [finished] using hf') (by simp; omega)
            · refine ⟨⟨hcl _ (by simp [*]), ?_⟩, Or.inl ⟨by simp, by simpa [finished] using hf'⟩⟩
              intro t' d' he; simp at he; obtain ⟨-, rfl⟩ := he; simp; omega
      | text | binary =>
        cases hfr : s.frag with
        | some _ =>
          simp only [step, hf, hm', hop, hfr, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
          exact fail_ok m s _ hi
        | none =>
          simp only [step, hf, hm', hop, hfr, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
          split
          · exact message_ok m s _ _ hi hf hlen
          · refine ⟨⟨hcl _ (by simp [*]), ?_⟩, Or.inl ⟨by simp, by simpa [finished] using hf'⟩⟩
            intro t' d' he; simp at he; obtain ⟨-, rfl⟩ := he; exact hlen

theorem run_finished (m mo : Nat) (s : St) (ins : List In) (h : finished s = true) :
    run m mo s ins = (s, []) := by
  induction ins with
  | nil => rfl
  | cons i is ih => simp only [run, step_finished m mo s i h, ih, List.nil_append]

theorem run_shape (m mo : Nat) (ins : List In) (hw : ∀ i ∈ ins, WF m i) :
    ∀ s, Inv m s → ∃ q t, (run m mo s ins).2 = q ++ t ∧ (∀ o ∈ q, Quiet m o) ∧ Tail t := by
  induction ins with
  | nil => intro s _; exact ⟨[], [], rfl, by simp, Or.inl rfl⟩
  | cons i is ih =>
    intro s hi
    have hw' : ∀ i ∈ is, WF m i := fun j hj => hw j (List.mem_cons_of_mem _ hj)
    by_cases hf : finished s = true
    · exact ⟨[], [], by simp [run_finished m mo s _ hf], by simp, Or.inl rfl⟩
    · have hf : finished s = false := by simpa using hf
      have hs := step_ok m mo s i hi hf (hw i (by simp))
      rcases hs with ⟨hi', ⟨hq, _⟩ | ⟨q, t, he, hq, ht, hfin⟩⟩
      · obtain ⟨q, t, he, hq', ht⟩ := ih hw' _ hi'
        refine ⟨(step m mo s i).2 ++ q, t, by simp [run, he], ?_, ht⟩
        intro o ho; rcases List.mem_append.1 ho with ho | ho
        · exact hq o ho
        · exact hq' o ho
      · refine ⟨q, t, by simp [run, run_finished m mo _ is hfin, he], hq, ht⟩

theorem quiet_not_close (m : Nat) (o : Out) (h : Quiet m o) :
    isSendClose o = false ∧ isEnded o = false := by
  cases o <;> simp_all [Quiet, isSendClose, isEnded]

theorem shape_safe (m : Nat) (q t : List Out) (hq : ∀ o ∈ q, Quiet m o) (ht : Tail t) :
    SafeRun m (q ++ t) := by
  have hq0 : q.countP isSendClose = 0 :=
    List.countP_eq_zero.2 (fun o ho => by simp [(quiet_not_close m o (hq o ho)).1])
  have hq1 : q.countP isEnded = 0 :=
    List.countP_eq_zero.2 (fun o ho => by simp [(quiet_not_close m o (hq o ho)).2])
  have hdel : ∀ b p, Out.deliver b p ∈ q ++ t → Out.deliver b p ∈ q := by
    intro b p h
    rcases List.mem_append.1 h with h | h
    · exact h
    · rcases ht with rfl | ⟨c, rfl⟩ | ⟨x, c, rfl⟩ <;> simp at h
  -- an index at a close or end lies in the tail
  have hidx : ∀ i (hi : i < (q ++ t).length),
      (isSendClose ((q ++ t)[i]) = true ∨ isEnded ((q ++ t)[i]) = true) → q.length ≤ i := by
    intro i hi hc
    apply Nat.le_of_not_lt
    intro hlt
    rw [List.getElem_append_left hlt] at hc
    have := quiet_not_close m _ (hq _ (List.getElem_mem hlt))
    rcases hc with hc | hc <;> simp_all
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro b p h; have := hq _ (hdel b p h); exact this.1
  · intro p h; have := hq _ (hdel true p h); exact this.2 rfl
  · rw [List.countP_append, hq0]
    rcases ht with rfl | ⟨c, rfl⟩ | ⟨x, c, rfl⟩ <;> simp [List.countP_cons, isSendClose]
  · intro i j hij hj hc
    have hli := hidx i (by omega) (Or.inl hc)
    rw [List.getElem_append_right hli] at hc
    rcases ht with rfl | ⟨c, rfl⟩ | ⟨x, c, rfl⟩
    · simp at hj; omega
    · simp at hj; omega
    · simp at hj
      have hj1 : j - q.length = 1 := by omega
      rw [List.getElem_append_right (by omega)]
      simp [hj1, isSendClose]
  · rw [List.countP_append, hq1]
    rcases ht with rfl | ⟨c, rfl⟩ | ⟨x, c, rfl⟩ <;> simp [isEnded]
  · intro i hi he
    have hli := hidx i hi (Or.inr he)
    rw [List.getElem_append_right hli] at he
    rcases ht with rfl | ⟨c, rfl⟩ | ⟨x, c, rfl⟩
    · simp at hi; omega
    · simp at hi ⊢; omega
    · simp at hi ⊢
      rcases (by omega : i - q.length = 0 ∨ i - q.length = 1) with h0 | h1
      · simp [h0, isEnded] at he
      · omega

/-- Every run from a fresh session over decoder output is safe. -/
theorem run_safe (m mo : Nat) (ins : List In) (hw : ∀ i ∈ ins, WF m i) :
    SafeRun m (run m mo St.init ins).2 := by
  obtain ⟨q, t, he, hq, ht⟩ :=
    run_shape m mo ins hw St.init ⟨fun h => by simp [St.init] at h, fun _ _ h => by simp [St.init] at h⟩
  rw [he]; exact shape_safe m q t hq ht

theorem fail_q (s : St) (c : Nat) :
    (fail s c).1.queued ≤ s.queued + 4 ∧ finished (fail s c).1 = true := by
  unfold fail closeWith; split <;> simp [finished]

theorem message_q (s : St) (t : Bool) (p : Bytes) :
    (message s t p).1.queued ≤ s.queued + 4 ∧
    (finished (message s t p).1 = false → (message s t p).1.queued = s.queued) := by
  unfold message; split
  · exact ⟨(fail_q s 1007).1, fun h => by rw [(fail_q s 1007).2] at h; exact absurd h (by simp)⟩
  · simp

theorem step_queued (m mo : Nat) (s : St) (i : In) (hw : WF m i)
    (hf : finished s = false) (hq : s.queued ≤ mo) :
    (step m mo s i).1.queued ≤ mo + 131 ∧
    (finished (step m mo s i).1 = false → (step m mo s i).1.queued ≤ mo) := by
  have hfe : ∀ s' : St, finished s' = true → finished s' = false → False := by
    intro s' h1 h2; rw [h1] at h2; exact absurd h2 (by simp)
  have hfail : ∀ c, (fail s c).1.queued ≤ mo + 131 ∧
      (finished (fail s c).1 = false → (fail s c).1.queued ≤ mo) := fun c =>
    ⟨by have := (fail_q s c).1; omega, fun h => (hfe _ (fail_q s c).2 h).elim⟩
  have hmsg : ∀ (s' : St) t p, s'.queued = s.queued →
      (message s' t p).1.queued ≤ mo + 131 ∧
      (finished (message s' t p).1 = false → (message s' t p).1.queued ≤ mo) := by
    intro s' t p he
    have := message_q s' t p
    exact ⟨by omega, fun h => by have := this.2 h; omega⟩
  cases i with
  | bad b => simp only [step, hf, Bool.false_eq_true, ↓reduceIte]; exact hfail _
  | frame f =>
    obtain ⟨hlen, hctl⟩ := hw
    by_cases hm : f.masked = false
    · simp only [step, hf, hm, Bool.false_eq_true, ↓reduceIte]; exact hfail _
    · have hm' : f.masked = true := by simpa using hm
      cases hop : f.op with
      | ping =>
        have h125 := hctl (Or.inl hop)
        have hfl : frameLen f.payload.length = 2 + f.payload.length := by
          simp [frameLen, show f.payload.length < 126 by omega]
        simp only [step, hf, hm', hop, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
        split
        · exact ⟨by simp; omega, fun _ => hq⟩
        · split
          · rename_i hover
            have := fail_q { s with queued := s.queued + frameLen f.payload.length } 1008
            exact ⟨by simp at this ⊢; omega, fun h => (hfe _ this.2 h).elim⟩
          · rename_i hok
            exact ⟨by simp; omega, fun _ => by simp; omega⟩
      | pong =>
        simp only [step, hf, hm', hop, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
        exact ⟨by omega, fun _ => hq⟩
      | close =>
        have hrl : (replyBody f.payload).length ≤ 2 := by
          unfold replyBody; split
          · simp
          · simp
          · split <;> simp
        have hfl : frameLen (replyBody f.payload).length ≤ 4 := by
          simp [frameLen, show (replyBody f.payload).length < 126 by omega]; omega
        simp only [step, hf, hm', hop, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
        split
        · exact ⟨by simp; omega, fun h => by simp [finished] at h⟩
        · exact ⟨by simp; omega, fun h => by simp [finished] at h⟩
      | cont =>
        cases hfr : s.frag with
        | none =>
          simp only [step, hf, hm', hop, hfr, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
          exact hfail _
        | some td =>
          obtain ⟨t, d⟩ := td
          simp only [step, hf, hm', hop, hfr, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
          split
          · exact hfail _
          · split
            · exact hmsg _ t _ rfl
            · exact ⟨by simp; omega, fun _ => by simp; omega⟩
      | text | binary =>
        cases hfr : s.frag with
        | some _ =>
          simp only [step, hf, hm', hop, hfr, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
          exact hfail _
        | none =>
          simp only [step, hf, hm', hop, hfr, Bool.false_eq_true, Bool.true_eq_false, ↓reduceIte]
          split
          · exact hmsg s _ _ rfl
          · exact ⟨by simp; omega, fun _ => by simp; omega⟩

theorem trace_bound (m mo : Nat) (ins : List In) (hw : ∀ i ∈ ins, WF m i) :
    ∀ s : St, s.queued ≤ mo + 131 → (finished s = false → s.queued ≤ mo) →
      OutboxBound mo 131 (queuedTrace m mo s ins) := by
  induction ins with
  | nil => intro s _ _ q hq; simp [queuedTrace] at hq
  | cons i is ih =>
    intro s h1 h2
    have hw' : ∀ i ∈ is, WF m i := fun j hj => hw j (List.mem_cons_of_mem _ hj)
    have hnext : (step m mo s i).1.queued ≤ mo + 131 ∧
        (finished (step m mo s i).1 = false → (step m mo s i).1.queued ≤ mo) := by
      by_cases hf : finished s = true
      · rw [step_finished m mo s i hf]
        exact ⟨h1, fun h => by rw [hf] at h; exact absurd h (by simp)⟩
      · have hf : finished s = false := by simpa using hf
        exact step_queued m mo s i (hw i (by simp)) hf (h2 hf)
    intro q hq
    simp only [queuedTrace, List.mem_cons] at hq
    rcases hq with rfl | hq
    · exact hnext.1
    · exact ih hw' _ hnext.1 hnext.2 q hq

/-- A peer that never reads cannot grow `outbox` past `max_outbox` plus one
PONG (at most 127 bytes on the wire) and the 4-byte CLOSE that follows it. -/
theorem outbox_bound (m mo : Nat) (ins : List In) (hw : ∀ i ∈ ins, WF m i) :
    OutboxBound mo 131 (queuedTrace m mo St.init ins) :=
  trace_bound m mo ins hw St.init (by simp [St.init]) (fun _ => by simp [St.init])

end Flare.Kernels.WsProtocol
