import Flare.Core

/-!
# HTTP/2 frame codec (RFC 9113 §4.1)

`parseFrame` and `encodeFrame` transliterate `flare/http2/frame.mojo`.
Mojo `Int` arithmetic on these values never leaves `0 .. 2^32`, so `Nat`
is exact here (every intermediate is a shift/or of at most four bytes).

Results:
* `parse_encode`: encoding then parsing returns the frame with the
  reserved bit cleared, for every payload shorter than `2^24`, and
  leaves any trailing bytes untouched.
* `parse_short`: fewer than 9 bytes, or fewer than `9 + length`, is
  `none` (keep buffering), never an error.
* `parse_never_raises`: the "length exceeds 24-bit max" raise is dead
  code: a 24-bit field cannot exceed `2^24 - 1`.
* `parse_consumed`: a parsed frame consumes exactly `9 + length` bytes and
  the payload is the next `length` bytes.
* `precheck_bounds`: the server pre-check (`server.mojo:395-405`) only lets
  frames with `length ≤ local_max_frame_size` reach `handle_frame`.
-/
namespace Flare.L3.H2

/-- A parsed frame: header fields plus the owned payload. `length` is the
header field, which `parseFrame` keeps equal to `payload.length`. -/
structure Frame where
  length : Nat
  ty : UInt8
  flags : UInt8
  sid : Nat
  payload : Bytes
  deriving Repr, DecidableEq

def H2_MAX_FRAME_SIZE : Nat := 16777215
def H2_DEFAULT_FRAME_SIZE : Nat := 16384

/-- Result of `parse_frame`: `error` is a Mojo `raise`. -/
inductive ParseRes where
  | needMore
  | frame (f : Frame) (rest : Bytes)
  | error (msg : String)
  deriving Repr, DecidableEq

/-- mirrors flare/http2/frame.mojo:200-233 @59bda50 -/
def parseFrame (buf : Bytes) : ParseRes :=
  match buf with
  | b0 :: b1 :: b2 :: b3 :: b4 :: b5 :: b6 :: b7 :: b8 :: rest =>
    let length := b0.toNat * 65536 + b1.toNat * 256 + b2.toNat
    if length > H2_MAX_FRAME_SIZE then .error "h2: frame length exceeds 24-bit max"
    else if rest.length < length then .needMore
    else
      let sid := b5.toNat * 16777216 + b6.toNat * 65536 + b7.toNat * 256 + b8.toNat
      .frame { length, ty := b3, flags := b4, sid := sid &&& 0x7FFFFFFF,
               payload := rest.take length } (rest.drop length)
  | _ => .needMore

/-- mirrors flare/http2/frame.mojo:239-257 @59bda50 -/
def encodeFrame (f : Frame) : Bytes :=
  let n := f.payload.length
  let sid := f.sid &&& 0x7FFFFFFF
  [UInt8.ofNat (n / 65536 % 256), UInt8.ofNat (n / 256 % 256), UInt8.ofNat (n % 256),
   f.ty, f.flags,
   UInt8.ofNat (sid / 16777216 % 256), UInt8.ofNat (sid / 65536 % 256),
   UInt8.ofNat (sid / 256 % 256), UInt8.ofNat (sid % 256)] ++ f.payload

/-- RFC 9113 §4.1 view of a well-formed frame on the wire: the length
field equals the payload length and the reserved bit is clear. -/
def normalize (f : Frame) : Frame :=
  { f with length := f.payload.length, sid := f.sid % 2147483648 }

private theorem and_mask (x : Nat) : x &&& 0x7FFFFFFF = x % 2147483648 := by
  have := Nat.and_two_pow_sub_one_eq_mod x 31
  simpa using this

private theorem bytes3 (a : Nat) (h : a < 16777216) :
    (a / 65536 % 256 % 256) * 65536 + (a / 256 % 256 % 256) * 256 + a % 256 % 256 = a := by
  omega

private theorem bytes4 (s : Nat) (h : s < 2147483648) :
    (s / 16777216 % 256 % 256) * 16777216 + (s / 65536 % 256 % 256) * 65536
      + (s / 256 % 256 % 256) * 256 + s % 256 % 256 = s := by
  omega

theorem parse_encode (f : Frame) (rest : Bytes) (h : f.payload.length < 2 ^ 24) :
    parseFrame (encodeFrame f ++ rest) = .frame (normalize f) rest := by
  have hm : ∀ n : Nat, (UInt8.ofNat n).toNat = n % 256 := fun n => by simp
  have hn := h
  simp only [encodeFrame, List.cons_append, List.nil_append, parseFrame, hm]
  generalize hp : f.payload = p at *
  rw [bytes3 _ (by simpa using hn)]
  have hs : (f.sid &&& 0x7FFFFFFF) < 2147483648 := by rw [and_mask]; omega
  generalize hsid : f.sid &&& 0x7FFFFFFF = s at *
  rw [bytes4 _ hs]
  have h1 : ¬ p.length > H2_MAX_FRAME_SIZE := by unfold H2_MAX_FRAME_SIZE; omega
  have h2 : ¬ (p ++ rest).length < p.length := by simp
  simp only [h1, h2, if_false]
  have hs' : s &&& 0x7FFFFFFF = s := by rw [and_mask]; omega
  rw [hs', List.take_left' rfl, List.drop_left' rfl]
  simp [normalize, hp, ← hsid, and_mask]

/-- Fewer than 9 bytes: keep buffering. -/
theorem parse_short (buf : Bytes) (h : buf.length < 9) : parseFrame buf = .needMore := by
  unfold parseFrame
  split
  · simp_all; omega
  · rfl

/-- The 24-bit length field never exceeds `H2_MAX_FRAME_SIZE`, so
`parse_frame` never raises. -/
theorem parse_never_raises (buf : Bytes) (m : String) : parseFrame buf ≠ .error m := by
  unfold parseFrame
  split
  · rename_i b0 b1 b2 _ _ _ _ _ _ _
    have := b0.toNat_lt; have := b1.toNat_lt; have := b2.toNat_lt
    have hle : ¬ b0.toNat * 65536 + b1.toNat * 256 + b2.toNat > H2_MAX_FRAME_SIZE := by
      unfold H2_MAX_FRAME_SIZE; omega
    simp only [hle, if_false]
    split <;> simp
  · simp

/-- A parsed frame consumed exactly `9 + length` bytes, its payload is the
`length` bytes after the header, and its length is consistent. -/
theorem parse_consumed (buf : Bytes) (f : Frame) (rest : Bytes)
    (h : parseFrame buf = .frame f rest) :
    f.payload.length = f.length ∧ buf.length = 9 + f.length + rest.length ∧
    buf = buf.take 9 ++ f.payload ++ rest ∧ f.sid < 2 ^ 31 := by
  unfold parseFrame at h
  dsimp only at h
  split at h
  · rename_i b0 b1 b2 b3 b4 b5 b6 b7 b8 r
    split at h
    · cases h
    split at h
    · cases h
    rename_i _ hge
    simp only [ParseRes.frame.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    refine ⟨?_, ?_, ?_, ?_⟩
    · simp; omega
    · simp; omega
    · simp only [List.take, List.cons_append, List.nil_append, List.take_append_drop]
    · simp only [and_mask]; omega
  · cases h

/-- Incomplete payload: a full header whose declared length is not yet
buffered is `needMore`. -/
theorem parse_incomplete (b0 b1 b2 b3 b4 b5 b6 b7 b8 : UInt8) (body : Bytes)
    (hb : body.length < b0.toNat * 65536 + b1.toNat * 256 + b2.toNat) :
    parseFrame ([b0, b1, b2, b3, b4, b5, b6, b7, b8] ++ body) = .needMore := by
  simp only [List.cons_append, List.nil_append, parseFrame]
  have := b0.toNat_lt; have := b1.toNat_lt; have := b2.toNat_lt
  have hle : ¬ b0.toNat * 65536 + b1.toNat * 256 + b2.toNat > H2_MAX_FRAME_SIZE := by
    unfold H2_MAX_FRAME_SIZE; omega
  simp [hle, hb]

/-- The 24-bit length field of the 9-byte header (`server.mojo:399-403`). -/
def declaredLen (buf : Bytes) : Nat :=
  (buf.getD 0).toNat * 65536 + (buf.getD 1).toNat * 256 + (buf.getD 2).toNat

theorem parse_length (buf : Bytes) (f : Frame) (rest : Bytes)
    (h : parseFrame buf = .frame f rest) : 9 ≤ buf.length ∧ f.length = declaredLen buf ∧
      f.payload.length = f.length := by
  have hc := (parse_consumed buf f rest h).1
  unfold parseFrame at h
  dsimp only at h
  split at h
  · split at h
    · cases h
    split at h
    · cases h
    simp only [ParseRes.frame.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    refine ⟨by simp, ?_, hc⟩
    simp [declaredLen, Bytes.getD]
  · cases h

/-! ## Server pre-check (`server.mojo:395-405`) -/

/-- Outcome of one iteration of the server drain loop. -/
inductive DrainRes where
  | refuseFrameSize        -- GOAWAY(FRAME_SIZE_ERROR), inbox cleared
  | needMore
  | deliver (f : Frame) (rest : Bytes)
  deriving Repr, DecidableEq

/-- mirrors flare/http2/server.mojo:395-414 @59bda50 -/
def drainOne (localMax : Nat) (inbox : Bytes) : DrainRes :=
  if 9 ≤ inbox.length ∧ declaredLen inbox > localMax then .refuseFrameSize
  else match parseFrame inbox with
    | .frame f rest => .deliver f rest
    | _ => .needMore

/-- Every frame the server hands to `handle_frame` respects the size it
advertised (RFC 9113 §4.2); an oversized one is refused from its 9-byte
header alone, before any payload is buffered. -/
theorem precheck_bounds (localMax : Nat) (inbox : Bytes) (f : Frame) (rest : Bytes)
    (h : drainOne localMax inbox = .deliver f rest) : f.payload.length ≤ localMax := by
  unfold drainOne at h
  split at h
  · cases h
  · rename_i hn
    split at h
    · rename_i f' r' hp
      cases h
      have := parse_length _ _ _ hp
      omega
    · cases h

/-- An oversized declared length is refused whatever follows the header. -/
theorem precheck_refuses (localMax : Nat) (b0 b1 b2 b3 b4 b5 b6 b7 b8 : UInt8) (body : Bytes)
    (hbig : b0.toNat * 65536 + b1.toNat * 256 + b2.toNat > localMax) :
    drainOne localMax ([b0, b1, b2, b3, b4, b5, b6, b7, b8] ++ body) = .refuseFrameSize := by
  simp only [drainOne, declaredLen, Bytes.getD, List.cons_append, List.nil_append,
    List.getElem?_cons_zero, List.getElem?_cons_succ, Option.getD_some, List.length_cons]
  simp [hbig]

end Flare.L3.H2
