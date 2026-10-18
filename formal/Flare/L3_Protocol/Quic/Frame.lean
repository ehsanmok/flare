import Flare.L3_Protocol.Quic.Wire
/-!
# QUIC transport-frame parser (RFC 9000 §12.4, §19)

`parseFrame` transliterates `parse_frame_into` (one frame at the start of
the buffer, returning the parsed frame and the bytes consumed); the
`FrameHandler` callback is replaced by the returned `Frame` value.
`parsePayload` is the `dispatch_frames` drain loop (state.mojo:825-856)
without the state updates.

The Mojo `if t == ...` chain is split in two: `kindOf` is the chain of type
tests (in source order) and `body` dispatches on the resulting `Kind` to one
small parser per frame type. Every proof is then a case split over `Kind`
plus one short lemma per frame type.

Results:
* `parseFrame_good` : the parser never reads past its input and its cursor
  stays in `0..len` (every branch, incl. the ACK range loop).
* `parseFrame_progress` : on success at least one byte is consumed, so the
  drain loop terminates.
* `body_kind` : each branch returns a frame of its own kind.
* `RfcFrameOk` : the frame-level RFC 9000 constraints flare is expected to
  enforce at parse time; `parseFrameFixed_ok` (FrameProps) proves the
  parser enforces them.
-/
namespace Flare.L3.Quic.Frame
open Flare.L3.Quic.Wire

inductive Frame where
  | padding
  | ping
  | ack (largest delay first : UInt64) (ranges : List (UInt64 × UInt64)) (ecn : Bool)
  | resetStream (sid ec finalSize : UInt64)
  | stopSending (sid ec : UInt64)
  | crypto (off : UInt64) (data : Bytes)
  | newToken (data : Bytes)
  | stream (sid off : UInt64) (data : Bytes) (fin : Bool)
  | maxData (v : UInt64)
  | maxStreamData (sid v : UInt64)
  | maxStreams (uni : Bool) (v : UInt64)
  | dataBlocked (v : UInt64)
  | streamDataBlocked (sid v : UInt64)
  | streamsBlocked (uni : Bool) (v : UInt64)
  | newConnectionId (seq retire : UInt64) (cid token : Bytes)
  | retireConnectionId (seq : UInt64)
  | pathChallenge (data : Bytes)
  | pathResponse (data : Bytes)
  | connectionClose (app : Bool) (ec ft : UInt64) (reason : Bytes)
  | handshakeDone
  | datagram (data : Bytes) (hasLen : Bool)
  | ackFrequency (seq threshold delay reorder : UInt64)
  | immediateAck
  | unknown (t : UInt64)
  deriving DecidableEq, Repr, Inhabited

/-- The branches of the `parse_frame_into` dispatch. -/
inductive Kind where
  | padding | ping | ack | resetStream | stopSending | crypto | newToken | stream
  | maxData | maxStreamData | maxStreams | dataBlocked | streamDataBlocked | streamsBlocked
  | newConnectionId | retireConnectionId | pathChallenge | pathResponse | connectionClose
  | handshakeDone | datagram | ackFrequency | immediateAck | unknown
  deriving DecidableEq, Repr

def Frame.kind : Frame → Kind
  | .padding => .padding
  | .ping => .ping
  | .ack .. => .ack
  | .resetStream .. => .resetStream
  | .stopSending .. => .stopSending
  | .crypto .. => .crypto
  | .newToken .. => .newToken
  | .stream .. => .stream
  | .maxData .. => .maxData
  | .maxStreamData .. => .maxStreamData
  | .maxStreams .. => .maxStreams
  | .dataBlocked .. => .dataBlocked
  | .streamDataBlocked .. => .streamDataBlocked
  | .streamsBlocked .. => .streamsBlocked
  | .newConnectionId .. => .newConnectionId
  | .retireConnectionId .. => .retireConnectionId
  | .pathChallenge .. => .pathChallenge
  | .pathResponse .. => .pathResponse
  | .connectionClose .. => .connectionClose
  | .handshakeDone => .handshakeDone
  | .datagram .. => .datagram
  | .ackFrequency .. => .ackFrequency
  | .immediateAck => .immediateAck
  | .unknown .. => .unknown

/-- The type tests of the dispatch, in source order.
mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def kindOf (t : Nat) : Kind :=
  if t = 0x00 then .padding
  else if t = 0x01 then .ping
  else if t = 0x02 ∨ t = 0x03 then .ack
  else if t = 0x04 then .resetStream
  else if t = 0x05 then .stopSending
  else if t = 0x06 then .crypto
  else if t = 0x07 then .newToken
  else if 0x08 ≤ t ∧ t ≤ 0x0F then .stream
  else if t = 0x10 then .maxData
  else if t = 0x11 then .maxStreamData
  else if t = 0x12 ∨ t = 0x13 then .maxStreams
  else if t = 0x14 then .dataBlocked
  else if t = 0x15 then .streamDataBlocked
  else if t = 0x16 ∨ t = 0x17 then .streamsBlocked
  else if t = 0x18 then .newConnectionId
  else if t = 0x19 then .retireConnectionId
  else if t = 0x1A then .pathChallenge
  else if t = 0x1B then .pathResponse
  else if t = 0x1C ∨ t = 0x1D then .connectionClose
  else if t = 0x1E then .handshakeDone
  else if t = 0x30 ∨ t = 0x31 then .datagram
  else if t = 0xAF then .ackFrequency
  else if t = 0x1F then .immediateAck
  else .unknown

/-- The ACK range loop (frame.mojo:773-776). -/
def ackRanges (b : Bytes) : Nat → Parser (List (UInt64 × UInt64))
  | 0 => pure []
  | k + 1 => do
      let gap ← varint b
      let len ← varint b
      let rest ← ackRanges b k
      pure ((gap, len) :: rest)

/-- RFC 9000 §19.3.1: every computed packet number is non-negative.
`smallest = largest - ack_range`, `largest' = previous_smallest - gap - 2`. -/
def ackRangesOk : Int → List (UInt64 × UInt64) → Bool
  | _, [] => true
  | prevSmallest, (gap, len) :: rs =>
    let lg : Int := prevSmallest - gap.toNat - 2
    let sm : Int := lg - len.toNat
    decide (0 ≤ sm) && ackRangesOk sm rs

def ackOk (largest first : UInt64) (ranges : List (UInt64 × UInt64)) : Bool :=
  let sm : Int := (largest.toNat : Int) - first.toNat
  decide (0 ≤ sm) && ackRangesOk sm ranges

/-- Remaining-bytes count `len(buf) - pos`. -/
def remaining (b : Bytes) : Parser Nat := fun pos => .ok (b.length - pos, pos)

/-! ## One parser per frame type -/

/-- ECN counts of ACK_ECN (read; the model drops their values).
mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def ackEcn (b : Bytes) (t : Nat) : Parser Unit :=
  if t = 0x03 then do
    let _ ← varint b
    let _ ← varint b
    let _ ← varint b
    pure ()
  else pure ()

/-- RFC 9000 §19.3.1: reject any computed packet number < 0 (QUIC-03).
mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def ackFinish (t : Nat) (largest delay first : UInt64)
    (ranges : List (UInt64 × UInt64)) : Parser Frame :=
  if ackOk largest first ranges = false then
    fail "FRAME_ENCODING_ERROR: negative ack range"
  else pure (.ack largest delay first ranges (t = 0x03))

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def ackTail (b : Bytes) (t : Nat) (largest delay rc : UInt64) : Parser Frame := do
  let first ← varint b
  let ranges ← ackRanges b rc.toNat
  let _ ← ackEcn b t
  ackFinish t largest delay first ranges

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def ackBody (b : Bytes) (t : Nat) : Parser Frame := do
  let largest ← varint b
  let delay ← varint b
  let rc ← varint b
  if rc > 0x4000 then fail "quic ack: range count exceeds RFC 9000 §19.3 cap"
  else ackTail b t largest delay rc

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def resetBody (b : Bytes) : Parser Frame := do
  let sid ← varint b
  let ec ← varint b
  let fs ← varint b
  pure (.resetStream sid ec fs)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def stopBody (b : Bytes) : Parser Frame := do
  let sid ← varint b
  let ec ← varint b
  pure (.stopSending sid ec)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def cryptoBody (b : Bytes) : Parser Frame := do
  let off ← varint b
  let n ← varint b
  let d ← bytes b n.toNat
  pure (.crypto off d)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def newTokenBody (b : Bytes) : Parser Frame := do
  let n ← varint b
  if n = 0 then fail "quic new_token: empty token"
  else do
    let d ← bytes b n.toNat
    pure (.newToken d)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def streamOff (b : Bytes) (t : Nat) : Parser UInt64 :=
  if t &&& 4 ≠ 0 then varint b else pure 0

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def streamData (b : Bytes) (t : Nat) : Parser Bytes :=
  if t &&& 2 ≠ 0 then do
    let n ← varint b
    bytes b n.toNat
  else do
    let r ← remaining b
    bytes b r

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def streamBody (b : Bytes) (t : Nat) : Parser Frame := do
  let sid ← varint b
  let off ← streamOff b t
  let d ← streamData b t
  pure (.stream sid off d (t &&& 1 ≠ 0))

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def maxDataBody (b : Bytes) : Parser Frame := do
  let v ← varint b
  pure (.maxData v)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def maxStreamDataBody (b : Bytes) : Parser Frame := do
  let sid ← varint b
  let v ← varint b
  pure (.maxStreamData sid v)

/-- RFC 9000 §4.6 / §19.11: at most 2^60 (QUIC-02).
mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def maxStreamsBody (b : Bytes) (t : Nat) : Parser Frame := do
  let v ← varint b
  if v.toNat > 2 ^ 60 then fail "FRAME_ENCODING_ERROR: MAX_STREAMS > 2^60"
  else pure (.maxStreams (t = 0x13) v)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def dataBlockedBody (b : Bytes) : Parser Frame := do
  let v ← varint b
  pure (.dataBlocked v)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def streamDataBlockedBody (b : Bytes) : Parser Frame := do
  let sid ← varint b
  let v ← varint b
  pure (.streamDataBlocked sid v)

/-- RFC 9000 §19.14: at most 2^60 (QUIC-02).
mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def streamsBlockedBody (b : Bytes) (t : Nat) : Parser Frame := do
  let v ← varint b
  if v.toNat > 2 ^ 60 then fail "FRAME_ENCODING_ERROR: STREAMS_BLOCKED > 2^60"
  else pure (.streamsBlocked (t = 0x17) v)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def newCidTail (b : Bytes) (seq retire : UInt64) (cl : UInt8) : Parser Frame := do
  let cid ← bytes b cl.toNat
  let tok ← bytes b 16
  if retire > seq then fail "quic new_connection_id: retire_prior_to > sequence_number"
  else pure (.newConnectionId seq retire cid tok)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def newCidBody (b : Bytes) : Parser Frame := do
  let seq ← varint b
  let retire ← varint b
  let cl ← byte b "quic new_connection_id: truncated cid length"
  if cl.toNat < 1 ∨ cl.toNat > 20 then fail "quic new_connection_id: cid length out of [1, 20]"
  else newCidTail b seq retire cl

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def retireBody (b : Bytes) : Parser Frame := do
  let s ← varint b
  pure (.retireConnectionId s)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def pathChallengeBody (b : Bytes) : Parser Frame := do
  let d ← bytes b 8
  pure (.pathChallenge d)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def pathResponseBody (b : Bytes) : Parser Frame := do
  let d ← bytes b 8
  pure (.pathResponse d)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def closeFt (b : Bytes) (t : Nat) : Parser UInt64 :=
  if t = 0x1C then varint b else pure 0

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def closeBody (b : Bytes) (t : Nat) : Parser Frame := do
  let ec ← varint b
  let ft ← closeFt b t
  let rn ← varint b
  let reason ← bytes b rn.toNat
  pure (.connectionClose (t = 0x1D) ec ft reason)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def datagramLen (b : Bytes) (t : Nat) : Parser Nat :=
  if t = 0x31 then do
    let v ← varint b
    pure v.toNat
  else remaining b

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def datagramBody (b : Bytes) (t : Nat) : Parser Frame := do
  let n ← datagramLen b t
  let d ← bytes b n
  pure (.datagram d (t = 0x31))

/-- ACK_FREQUENCY (draft-ietf-quic-ack-frequency).
mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def ackFrequencyBody (b : Bytes) : Parser Frame := do
  let seq ← varint b
  let threshold ← varint b
  let delay ← varint b
  let reorder ← varint b
  pure (.ackFrequency seq threshold delay reorder)

/-- An unknown frame type raises FRAME_ENCODING_ERROR (RFC 9000 §12.4,
QUIC-01).
mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 (fixed, QUIC-01) -/
def unknownBody (_raw : UInt64) : Parser Frame :=
  fail "FRAME_ENCODING_ERROR: unknown frame type"

/-- Dispatch on the branch selected by `kindOf`. -/
def body (b : Bytes) (raw : UInt64) : Kind → Parser Frame
  | .padding => pure .padding
  | .ping => pure .ping
  | .ack => ackBody b raw.toNat
  | .resetStream => resetBody b
  | .stopSending => stopBody b
  | .crypto => cryptoBody b
  | .newToken => newTokenBody b
  | .stream => streamBody b raw.toNat
  | .maxData => maxDataBody b
  | .maxStreamData => maxStreamDataBody b
  | .maxStreams => maxStreamsBody b raw.toNat
  | .dataBlocked => dataBlockedBody b
  | .streamDataBlocked => streamDataBlockedBody b
  | .streamsBlocked => streamsBlockedBody b raw.toNat
  | .newConnectionId => newCidBody b
  | .retireConnectionId => retireBody b
  | .pathChallenge => pathChallengeBody b
  | .pathResponse => pathResponseBody b
  | .connectionClose => closeBody b raw.toNat
  | .handshakeDone => pure .handshakeDone
  | .datagram => datagramBody b raw.toNat
  | .ackFrequency => ackFrequencyBody b
  | .immediateAck => pure .immediateAck
  | .unknown => unknownBody raw

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 (dispatch on the decoded
type). -/
def frameBody (b : Bytes) (raw : UInt64) : Parser Frame :=
  body b raw (kindOf raw.toNat)

/-- mirrors flare/quic/frame.mojo#parse_frame_into sha=b75548102aad at=98b092d2 -/
def parseFrameAux (b : Bytes) : Parser Frame := do
  let raw ← varint b
  frameBody b raw

/-- flare's parser. -/
def parseFrame (b : Bytes) : Except Err (Frame × Nat) :=
  if b.length = 0 then .error (.raise "quic frame: empty buffer") else parseFrameAux b 0

/-- `dispatch_frames` drain loop: parse `payload[cursor:]` repeatedly.
Fuel = payload length suffices because each frame consumes ≥ 1 byte. -/
def parsePayloadWith (pf : Bytes → Except Err (Frame × Nat)) : Nat → Bytes → Except Err (List Frame)
  | 0, _ => .ok []
  | fuel + 1, p =>
    if p.length = 0 then .ok []
    else match pf p with
      | .error e => .error e
      | .ok (f, n) =>
        if n = 0 then .ok [f]
        else match parsePayloadWith pf fuel (p.drop n) with
          | .error e => .error e
          | .ok fs => .ok (f :: fs)

def parsePayload (p : Bytes) := parsePayloadWith parseFrame p.length p

/-! ## Bounds safety -/

theorem good_remaining (b : Bytes) : Good b (remaining b) := by
  intro pos h
  exact ⟨by simp [remaining], by intro a p h'; simp [remaining] at h'; omega⟩

theorem good_ackRanges (b : Bytes) (k : Nat) : Good b (ackRanges b k) := by
  induction k with
  | zero => exact good_pure _ _
  | succ k ih =>
    simp only [ackRanges]
    exact good_bind _ _ _ (good_varint b) fun _ =>
      good_bind _ _ _ (good_varint b) fun _ =>
      good_bind _ _ _ ih fun _ => good_pure _ _

section good
variable (b : Bytes)

theorem good_v1 {α : Type} (k : UInt64 → Parser α) (h : ∀ v, Good b (k v)) :
    Good b (varint b >>= k) := good_bind _ _ _ (good_varint b) h

theorem good_ackBody (t : Nat) : Good b (ackBody b t) :=
  good_v1 b _ fun _ => good_v1 b _ fun _ => good_v1 b _ fun rc =>
    good_ite _ _ _ _ (good_fail _ _) <|
      good_v1 b _ fun _ => good_bind _ _ _ (good_ackRanges b rc.toNat) fun _ =>
        good_bind _ _ _
          (good_ite _ _ _ _ (good_v1 b _ fun _ => good_v1 b _ fun _ => good_v1 b _ fun _ =>
            good_pure _ _) (good_pure _ _))
          fun _ => good_ite _ _ _ _ (good_fail _ _) (good_pure _ _)

theorem good_streamBody (t : Nat) : Good b (streamBody b t) :=
  good_v1 b _ fun _ =>
    good_bind _ _ _ (good_ite _ _ _ _ (good_varint b) (good_pure _ _)) fun _ =>
    good_bind _ _ _
      (good_ite _ _ _ _ (good_v1 b _ fun _ => good_bytes _ _)
        (good_bind _ _ _ (good_remaining b) fun _ => good_bytes _ _))
      fun _ => good_pure _ _

theorem good_newCidBody : Good b (newCidBody b) :=
  good_v1 b _ fun _ => good_v1 b _ fun _ => good_bind _ _ _ (good_byte b _) fun _ =>
    good_ite _ _ _ _ (good_fail _ _) <|
      good_bind _ _ _ (good_bytes _ _) fun _ => good_bind _ _ _ (good_bytes _ _) fun _ =>
        good_ite _ _ _ _ (good_fail _ _) (good_pure _ _)

theorem good_closeBody (t : Nat) : Good b (closeBody b t) :=
  good_v1 b _ fun _ =>
    good_bind _ _ _ (good_ite _ _ _ _ (good_varint b) (good_pure _ _)) fun _ =>
    good_v1 b _ fun _ => good_bind _ _ _ (good_bytes _ _) fun _ => good_pure _ _

theorem good_datagramBody (t : Nat) : Good b (datagramBody b t) :=
  good_bind _ _ _
    (good_ite _ _ _ _ (good_v1 b _ fun _ => good_pure _ _) (good_remaining b)) fun _ =>
    good_bind _ _ _ (good_bytes _ _) fun _ => good_pure _ _

theorem good_body (raw : UInt64) : ∀ k, Good b (body b raw k)
  | .padding => good_pure _ _
  | .ping => good_pure _ _
  | .ack => good_ackBody b _
  | .resetStream => good_v1 b _ fun _ => good_v1 b _ fun _ => good_v1 b _ fun _ => good_pure _ _
  | .stopSending => good_v1 b _ fun _ => good_v1 b _ fun _ => good_pure _ _
  | .crypto => good_v1 b _ fun _ => good_v1 b _ fun _ =>
      good_bind _ _ _ (good_bytes _ _) fun _ => good_pure _ _
  | .newToken => good_v1 b _ fun _ => good_ite _ _ _ _ (good_fail _ _) <|
      good_bind _ _ _ (good_bytes _ _) fun _ => good_pure _ _
  | .stream => good_streamBody b _
  | .maxData => good_v1 b _ fun _ => good_pure _ _
  | .maxStreamData => good_v1 b _ fun _ => good_v1 b _ fun _ => good_pure _ _
  | .maxStreams => good_v1 b _ fun _ => good_ite _ _ _ _ (good_fail _ _) (good_pure _ _)
  | .dataBlocked => good_v1 b _ fun _ => good_pure _ _
  | .streamDataBlocked => good_v1 b _ fun _ => good_v1 b _ fun _ => good_pure _ _
  | .streamsBlocked => good_v1 b _ fun _ => good_ite _ _ _ _ (good_fail _ _) (good_pure _ _)
  | .newConnectionId => good_newCidBody b
  | .retireConnectionId => good_v1 b _ fun _ => good_pure _ _
  | .pathChallenge => good_bind _ _ _ (good_bytes _ _) fun _ => good_pure _ _
  | .pathResponse => good_bind _ _ _ (good_bytes _ _) fun _ => good_pure _ _
  | .connectionClose => good_closeBody b _
  | .handshakeDone => good_pure _ _
  | .datagram => good_datagramBody b _
  | .ackFrequency => good_v1 b _ fun _ => good_v1 b _ fun _ => good_v1 b _ fun _ =>
      good_v1 b _ fun _ => good_pure _ _
  | .immediateAck => good_pure _ _
  | .unknown => good_fail _ _

end good

theorem frameBody_good (b : Bytes) (raw : UInt64) :
    Good b (frameBody b raw) := good_body b raw (kindOf raw.toNat)

theorem parseFrameAux_good (b : Bytes) : Good b (parseFrameAux b) :=
  good_bind _ _ _ (good_varint b) (frameBody_good b)

/-- **Bounds safety.** `parse_frame_into` never reads outside its buffer,
and the consumed count is at most the buffer length. -/
theorem parseFrame_good (b : Bytes) :
    parseFrame b ≠ .error .oob ∧ ∀ f n, parseFrame b = .ok (f, n) → n ≤ b.length := by
  unfold parseFrame
  split
  · exact ⟨by simp, by intro f n h; cases h⟩
  · have := parseFrameAux_good b 0 (Nat.zero_le _)
    exact ⟨this.1, fun f n h => (this.2 f n h).2⟩

/-! ## Progress -/

theorem parseFrameAux_progress (b : Bytes) (f : Frame) (n : Nat)
    (h : parseFrameAux b 0 = .ok (f, n)) : 0 < n := by
  simp only [parseFrameAux, bind, StateT.bind] at h
  cases hv : varint b 0 with
  | error e => rw [hv] at h; cases h
  | ok r =>
    obtain ⟨raw, p1⟩ := r
    rw [hv] at h
    have h1 := varint_progress b 0 p1 raw hv
    have hp1 : p1 ≤ b.length := ((good_varint b 0 (Nat.zero_le _)).2 raw p1 hv).2
    have := ((frameBody_good b raw) p1 hp1).2 f n h
    omega

/-- **Progress.** A successful parse consumes at least one byte, so the
`dispatch_frames` loop (`cursor += consumed`) strictly advances. -/
theorem parseFrame_progress (b : Bytes) (f : Frame) (n : Nat)
    (h : parseFrame b = .ok (f, n)) : 0 < n := by
  unfold parseFrame at h
  split at h
  · cases h
  · exact parseFrameAux_progress b f n h

/-! ## Postconditions on accepted frames -/

def Sat {α : Type} (P : α → Prop) (p : Parser α) : Prop :=
  ∀ pos a pos', p pos = .ok (a, pos') → P a

theorem sat_pure {α : Type} {P : α → Prop} {a : α} (h : P a) : Sat P (pure a) := by
  intro pos a' p' e; simp [pure, StateT.pure, Except.pure] at e; rw [← e.1]; exact h

theorem sat_fail {α : Type} {P : α → Prop} (m : String) : Sat P (fail (α := α) m) := by
  intro pos a p e; simp [fail] at e

theorem sat_bind_dep {α β : Type} {P : β → Prop} {Q : α → Prop} {p : Parser α}
    {f : α → Parser β} (hp : Sat Q p) (hf : ∀ a, Q a → Sat P (f a)) : Sat P (p >>= f) := by
  intro pos c p' e
  simp only [bind, StateT.bind] at e
  cases hq : p pos with
  | error err => rw [hq] at e; cases e
  | ok r =>
    obtain ⟨a, p1⟩ := r
    rw [hq] at e
    exact hf a (hp pos a p1 hq) p1 c p' e

theorem sat_true {α : Type} (p : Parser α) : Sat (fun _ => True) p := by
  intro _ _ _ _; trivial

theorem sat_bind {α β : Type} {P : β → Prop} {p : Parser α} {f : α → Parser β}
    (hf : ∀ a, Sat P (f a)) : Sat P (p >>= f) :=
  sat_bind_dep (sat_true p) (fun a _ => hf a)

theorem sat_ite_dep {α : Type} {P : α → Prop} {c : Prop} [Decidable c] {p q : Parser α}
    (hp : c → Sat P p) (hq : ¬ c → Sat P q) : Sat P (if c then p else q) := by
  by_cases h : c
  · rw [if_pos h]; exact hp h
  · rw [if_neg h]; exact hq h

theorem sat_ite {α : Type} {P : α → Prop} {c : Prop} [Decidable c] {p q : Parser α}
    (hp : Sat P p) (hq : Sat P q) : Sat P (if c then p else q) :=
  sat_ite_dep (fun _ => hp) (fun _ => hq)

theorem Sat.mono {α : Type} {P Q : α → Prop} {p : Parser α} (h : Sat P p)
    (hpq : ∀ a, P a → Q a) : Sat Q p :=
  fun pos a pos' e => hpq a (h pos a pos' e)

theorem sat_ackRanges_len (b : Bytes) (k : Nat) : Sat (fun l => l.length = k) (ackRanges b k) := by
  induction k with
  | zero => exact sat_pure rfl
  | succ k ih =>
    simp only [ackRanges]
    exact sat_bind fun _ => sat_bind fun _ =>
      sat_bind_dep ih fun l hl => sat_pure (by simp [hl])

/-- Every branch returns a frame of its own kind. -/
theorem body_kind (b : Bytes) (raw : UInt64) :
    ∀ k, Sat (fun f => f.kind = k) (body b raw k)
  | .padding => sat_pure rfl
  | .ping => sat_pure rfl
  | .ack => sat_bind fun _ => sat_bind fun _ => sat_bind fun _ => sat_ite (sat_fail _) <|
      sat_bind fun _ => sat_bind fun _ => sat_bind fun _ => sat_ite (sat_fail _) (sat_pure rfl)
  | .resetStream => sat_bind fun _ => sat_bind fun _ => sat_bind fun _ => sat_pure rfl
  | .stopSending => sat_bind fun _ => sat_bind fun _ => sat_pure rfl
  | .crypto => sat_bind fun _ => sat_bind fun _ => sat_bind fun _ => sat_pure rfl
  | .newToken => sat_bind fun _ => sat_ite (sat_fail _) (sat_bind fun _ => sat_pure rfl)
  | .stream => sat_bind fun _ => sat_bind fun _ => sat_bind fun _ => sat_pure rfl
  | .maxData => sat_bind fun _ => sat_pure rfl
  | .maxStreamData => sat_bind fun _ => sat_bind fun _ => sat_pure rfl
  | .maxStreams => sat_bind fun _ => sat_ite (sat_fail _) (sat_pure rfl)
  | .dataBlocked => sat_bind fun _ => sat_pure rfl
  | .streamDataBlocked => sat_bind fun _ => sat_bind fun _ => sat_pure rfl
  | .streamsBlocked => sat_bind fun _ => sat_ite (sat_fail _) (sat_pure rfl)
  | .newConnectionId => sat_bind fun _ => sat_bind fun _ => sat_bind fun _ =>
      sat_ite (sat_fail _) <| sat_bind fun _ => sat_bind fun _ => sat_ite (sat_fail _) (sat_pure rfl)
  | .retireConnectionId => sat_bind fun _ => sat_pure rfl
  | .pathChallenge => sat_bind fun _ => sat_pure rfl
  | .pathResponse => sat_bind fun _ => sat_pure rfl
  | .connectionClose => sat_bind fun _ => sat_bind fun _ => sat_bind fun _ => sat_bind fun _ =>
      sat_pure rfl
  | .handshakeDone => sat_pure rfl
  | .datagram => sat_bind fun _ => sat_bind fun _ => sat_pure rfl
  | .ackFrequency => sat_bind fun _ => sat_bind fun _ => sat_bind fun _ => sat_bind fun _ =>
      sat_pure rfl
  | .immediateAck => sat_pure rfl
  | .unknown => sat_fail _

/-- A property that holds for every frame of kind `k` holds for whatever the
`k` branch returns. -/
theorem body_sat {P : Frame → Prop} (b : Bytes) (raw : UInt64) (k : Kind)
    (hk : ∀ f : Frame, f.kind = k → P f) : Sat P (body b raw k) :=
  (body_kind b raw k).mono hk

/-- RFC 9000 frame-level constraints that are decidable from one frame. -/
def RfcFrameOk : Frame → Prop
  | .unknown _ => False                                   -- §12.4
  | .maxStreams _ v => v.toNat ≤ 2 ^ 60                    -- §4.6, §19.11
  | .streamsBlocked _ v => v.toNat ≤ 2 ^ 60                -- §19.14
  | .ack largest _ first ranges _ => ackOk largest first ranges = true  -- §19.3.1
  | _ => True

theorem rfcFrameOk_of_kind (f : Frame) (h1 : f.kind ≠ .ack) (h2 : f.kind ≠ .maxStreams)
    (h3 : f.kind ≠ .streamsBlocked) (h4 : f.kind ≠ .unknown) : RfcFrameOk f := by
  cases f <;> first
    | exact True.intro | exact absurd rfl h1 | exact absurd rfl h2 | exact absurd rfl h3
    | exact absurd rfl h4

end Flare.L3.Quic.Frame
