import Flare.L3_Protocol.Ws.Frame

/-!
# WebSocket receive paths (RFC 6455 §5.1, §5.2, §5.4, §5.5)

* **Opcode check.** `OpcodeSafe`: every frame the decoder returns has a
  defined opcode. `decodeKnown` adds the check; `decodeKnown_safe` proves it
  safe and `decodeKnown_encode` shows it still round-trips every frame with
  a defined opcode.
* **Mask direction.** `serverAccept` (`WsConnection._recv_one`) refuses
  unmasked frames: `server_safe`. `clientAccept` (`WsClient._recv_one`) has
  no check. `clientAcceptFixed` adds it: `clientFixed_safe`.
* **Message assembly.** `recvMessageOld` models `WsClient.recv_message`
  before the WS-02 fix; `nextMessage` is the shipped reader.
  `Delivered` is the declarative RFC 6455 §5.4 meaning of "the next complete
  message": the data frames consumed are a TEXT/BINARY start plus
  CONTINUATIONs, ending at the first FIN, with control frames interleaved
  anywhere, and the payload is their concatenation. `nextMessage` is the
  reassembling reader, and `nextMessage_delivered` proves it meets `Delivered`.
* **UTF-8.** `text_payload` accepts exactly the RFC 3629 well-formed payloads
  (`textPayload_ok_iff`, from `Flare.L1.Utf8.isValidUtf8_iff`).
-/
namespace Flare.L3.Ws
open Flare

/-! ## Opcode -/

def OpcodeSafe (dec : Bytes → DRes) : Prop :=
  ∀ d f n, dec d = .ok f n → knownOpcode f.opcode = true

/-- `decode_one` with the reserved-opcode check. The Mojo fix raises right
after the RSV checks; this checks after decoding. The only difference is
that a truncated reserved-opcode frame is `needMore` here instead of
`error`. -/
def decodeKnown (allowRsv1 : Bool) (maxP : Nat) (d : Bytes) : DRes :=
  match decode allowRsv1 maxP d with
  | .ok f n => if knownOpcode f.opcode then .ok f n else .error
  | r => r

theorem decodeKnown_safe (allowRsv1 : Bool) (maxP : Nat) : OpcodeSafe (decodeKnown allowRsv1 maxP) := by
  intro d f n h
  unfold decodeKnown at h
  split at h
  · split at h
    · cases h; assumption
    · cases h
  · rename_i r hr; exact absurd h (hr f n)

theorem knownOpcode_lt {op : UInt8} (h : knownOpcode op = true) : op.toNat < 16 := by
  simp only [knownOpcode, Bool.or_eq_true, beq_iff_eq] at h
  rcases h with ((((h | h) | h) | h) | h) | h <;> subst h <;> decide

theorem decodeKnown_encode (allowRsv1 : Bool) (maxP : Nat) (f : Frame) (mask : Bool) (k : Key) (rest : Bytes)
    (ho : knownOpcode f.opcode = true) (hr : f.rsv1 = true → allowRsv1 = true)
    (hc : isControl f.opcode = true → f.fin = true ∧ f.payload.length ≤ 125)
    (h32 : f.payload.length < 2 ^ 32) (hmax : f.payload.length ≤ maxP) :
    decodeKnown allowRsv1 maxP (encode f mask k ++ rest) =
      .ok { f with masked := mask } (encode f mask k).length := by
  unfold decodeKnown
  rw [decode_encode allowRsv1 maxP f mask k rest (knownOpcode_lt ho) hr hc h32 hmax]
  simp [ho]

/-! ## Mask direction -/

/-- `WsConnection._recv_one`: decode, then refuse an unmasked frame.
mirrors flare/ws/server.mojo:541-575 @59bda50 -/
def serverAccept (maxP : Nat) (d : Bytes) : DRes :=
  match decode false maxP d with
  | .ok f n => if f.masked then .ok f n else .error
  | r => r

/-- `WsClient._recv_one`: decode only.
mirrors flare/ws/client.mojo:717-763 @59bda50 -/
def clientAccept (maxP : Nat) (d : Bytes) : DRes := decode false maxP d

/-- `WsClient._recv_one` with the RFC 6455 §5.1 check. -/
def clientAcceptFixed (maxP : Nat) (d : Bytes) : DRes :=
  match decode false maxP d with
  | .ok f n => if f.masked then .error else .ok f n
  | r => r

def ServerSafe (acc : Bytes → DRes) : Prop := ∀ d f n, acc d = .ok f n → f.masked = true
def ClientSafe (acc : Bytes → DRes) : Prop := ∀ d f n, acc d = .ok f n → f.masked = false

theorem server_safe (maxP : Nat) : ServerSafe (serverAccept maxP) := by
  intro d f n h
  unfold serverAccept at h
  split at h
  · split at h
    · cases h; assumption
    · cases h
  · rename_i r hr; exact absurd h (hr f n)

theorem clientFixed_safe (maxP : Nat) : ClientSafe (clientAcceptFixed maxP) := by
  intro d f n h
  unfold clientAcceptFixed at h
  split at h
  · split at h
    · cases h
    · cases h; rename_i hm _; simpa using hm
  · rename_i r hr; exact absurd h (hr f n)

/-! ## Messages -/

inductive Msg where
  | text (b : Bytes)
  | binary (b : Bytes)
  | closed
  | error
  deriving DecidableEq, Repr

def Msg.payload? : Msg → Option Bytes
  | .text b => some b
  | .binary b => some b
  | _ => none

/-- `WsClient.recv`: answers PING and reads on.
mirrors flare/ws/client.mojo:693-715 @59bda50 -/
def recvFrame : List Frame → Option (Frame × List Frame)
  | [] => none
  | f :: fs => if f.opcode = 9 then recvFrame fs else some (f, fs)

/-- `WsClient.recv_message` before the WS-02 fix: CLOSE ends, BINARY is
binary, "TEXT or anything else" is text (UTF-8 checked on that one frame).
Kept for the counterexamples.
mirrors flare/ws/client.mojo:765-794 @59bda50 -/
def recvMessageOld (fs : List Frame) : Option (Msg × List Frame) :=
  match recvFrame fs with
  | none => none
  | some (f, rest) =>
    if f.opcode = 8 then some (.closed, rest)
    else if f.opcode = 2 then some (.binary f.payload, rest)
    else some (if Flare.L1.Utf8.isValidUtf8 f.payload then .text f.payload else .error, rest)

def isData (f : Frame) : Bool := !isControl f.opcode

/-- CONTINUATION frames up to and including the first with FIN set, with
their concatenated payload. -/
inductive Conts : List Frame → Bytes → Prop where
  | one (x : Frame) : x.opcode = 0 → x.fin = true → Conts [x] x.payload
  | cons (x : Frame) (xs : List Frame) (b : Bytes) : x.opcode = 0 → x.fin = false → Conts xs b →
      Conts (x :: xs) (x.payload ++ b)

/-- RFC 6455 §5.4: the data frames of one message, and its payload. -/
def MsgFrames (ds : List Frame) (b : Bytes) : Prop :=
  ∃ d rest, ds = d :: rest ∧ (d.opcode = 1 ∨ d.opcode = 2) ∧
    ((d.fin = true ∧ rest = [] ∧ b = d.payload) ∨
      (d.fin = false ∧ ∃ b', Conts rest b' ∧ b = d.payload ++ b'))

/-- **Spec.** A delivered text/binary message is one RFC 6455 message: the
frames consumed are control frames plus exactly the data frames of a
message, and the payload is theirs. -/
def Delivered (recv : List Frame → Option (Msg × List Frame)) : Prop :=
  ∀ fs m rest b, recv fs = some (m, rest) → m.payload? = some b →
    ∃ consumed, fs = consumed ++ rest ∧ MsgFrames (consumed.filter isData) b

/-- A finished message: text needs valid UTF-8 over the whole payload. -/
def finishMsg (isText : Bool) (b : Bytes) : Msg :=
  if isText then (if Flare.L1.Utf8.isValidUtf8 b then .text b else .error) else .binary b

theorem finishMsg_payload {t : Bool} {B b : Bytes} (h : (finishMsg t B).payload? = some b) : b = B := by
  unfold finishMsg at h
  split at h
  · split at h
    · simp [Msg.payload?] at h; exact h.symm
    · simp [Msg.payload?] at h
  · simp [Msg.payload?] at h; exact h.symm

/-- Reassembly after the first data frame. -/
def collect (isText : Bool) (acc : Bytes) : List Frame → Option (Msg × List Frame)
  | [] => none
  | f :: fs =>
    if f.opcode = 8 then some (.closed, fs)
    else if isControl f.opcode then collect isText acc fs
    else if f.opcode ≠ 0 then some (.error, fs)
    else if f.fin then some (finishMsg isText (acc ++ f.payload), fs)
    else collect isText (acc ++ f.payload) fs

/-- The shipped `recv_message` (with `_recv_data_frame`): skip PING/PONG,
CLOSE ends, TEXT/BINARY starts a message that runs to the CONTINUATION with
FIN; any other data opcode is a protocol error. The size bound on the
reassembled payload (`max_frame_size`) is not modelled: it only turns some
`.text`/`.binary` results into an error.
mirrors flare/ws/client.mojo:765-858 (fixed, WS-02) -/
def nextMessage : List Frame → Option (Msg × List Frame)
  | [] => none
  | f :: fs =>
    if f.opcode = 8 then some (.closed, fs)
    else if isControl f.opcode then nextMessage fs
    else if f.opcode = 1 ∨ f.opcode = 2 then
      (if f.fin then some (finishMsg (f.opcode = 1) f.payload, fs) else collect (f.opcode = 1) f.payload fs)
    else some (.error, fs)

theorem isData_of {f : Frame} (h : isControl f.opcode = false) : isData f = true := by
  simp [isData, h]

theorem not_isData_of {f : Frame} (h : isControl f.opcode = true) : isData f = false := by
  simp [isData, h]

theorem collect_spec (t : Bool) : ∀ (fs : List Frame) (acc : Bytes) (m : Msg) (rest : List Frame) (b : Bytes),
    collect t acc fs = some (m, rest) → m.payload? = some b →
    ∃ consumed B, fs = consumed ++ rest ∧ Conts (consumed.filter isData) B ∧ m = finishMsg t (acc ++ B)
  | [], _, _, _, _, h, _ => by simp [collect] at h
  | f :: fs, acc, m, rest, b, h, hb => by
    unfold collect at h
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, -⟩ := h; simp [Msg.payload?] at hb
    split at h
    · rename_i _ hc
      obtain ⟨c, B, e, hC, hm⟩ := collect_spec t fs acc m rest b h hb
      refine ⟨f :: c, B, by simp [e], ?_, hm⟩
      simp only [List.filter_cons, not_isData_of hc]; exact hC
    rename_i _ hc
    have hc' : isControl f.opcode = false := by simpa using hc
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, -⟩ := h; simp [Msg.payload?] at hb
    rename_i h0
    have h0' : f.opcode = 0 := by simpa using h0
    split at h
    · rename_i hf
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨[f], f.payload, rfl, ?_, rfl⟩
      simp only [List.filter_cons, isData_of hc', if_true, List.filter_nil]
      exact Conts.one f h0' hf
    · rename_i hf
      obtain ⟨c, B, e, hC, hm⟩ := collect_spec t fs (acc ++ f.payload) m rest b h hb
      refine ⟨f :: c, f.payload ++ B, by simp [e], ?_, by rw [hm, List.append_assoc]⟩
      simp only [List.filter_cons, isData_of hc', if_true]
      exact Conts.cons f _ B h0' (by simpa using hf) hC

/-- **The reassembling `recv_message` meets the spec.** -/
theorem nextMessage_delivered : Delivered nextMessage := by
  intro fs
  induction fs with
  | nil => intro m rest b h; simp [nextMessage] at h
  | cons f fs ih =>
    intro m rest b h hb
    unfold nextMessage at h
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, -⟩ := h; simp [Msg.payload?] at hb
    split at h
    · rename_i _ hc
      obtain ⟨c, e, hM⟩ := ih m rest b h hb
      refine ⟨f :: c, by simp [e], ?_⟩
      simp only [List.filter_cons, not_isData_of hc]; exact hM
    rename_i _ hc
    have hc' : isControl f.opcode = false := by simpa using hc
    split at h
    · rename_i hop
      split at h
      · rename_i hf
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        refine ⟨[f], rfl, ?_⟩
        simp only [List.filter_cons, isData_of hc', if_true, List.filter_nil]
        exact ⟨f, [], rfl, hop, Or.inl ⟨hf, rfl, finishMsg_payload hb⟩⟩
      · rename_i hf
        obtain ⟨c, B, e, hC, hm⟩ := collect_spec _ fs f.payload m rest b h hb
        refine ⟨f :: c, by simp [e], ?_⟩
        simp only [List.filter_cons, isData_of hc', if_true]
        rw [hm] at hb
        exact ⟨f, _, rfl, hop, Or.inr ⟨by simpa using hf, B, hC, finishMsg_payload hb⟩⟩
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, -⟩ := h; simp [Msg.payload?] at hb

/-! ## UTF-8 -/

/-- `WsFrame.text_payload` succeeds exactly on RFC 3629 well-formed payloads.
mirrors flare/ws/frame.mojo:522-536 @59bda50 -/
theorem textPayload_ok_iff (p : Bytes) :
    Flare.L1.Utf8.isValidUtf8 p = true ↔ Flare.L1.Utf8.WF p :=
  Flare.L1.Utf8.isValidUtf8_iff p

end Flare.L3.Ws
