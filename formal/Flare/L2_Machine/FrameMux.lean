import Flare.Core

/-!
# FrameMux: the multiplexed UDS frame codec and the `FrameDemux` reassembler

Wire frame (big-endian): `| u32 payload_len | u64 request_id | u8 kind | payload |`,
`HEADER_LEN = 13`, `MAX_FRAME_PAYLOAD = 64 MiB`.

* `encodeFrame` / `decodeFrame`: the pure codec, with a round-trip theorem.
* `drain`: the reassembly loop of `FrameDemux.feed` over a list (the residual
  after the parse cursor), and `feedLoop`: the same loop over the Mojo
  `(buf, consumed)` pair, proved equal to `drain` (`feedLoop_eq_drain`).
* Spec: a byte string is a concatenation of encoded valid frames followed by
  an *incomplete* residual (`Incomplete`). `drain_sound` / `drain_complete`
  show `drain` computes exactly that decomposition, and `feed_chunking`
  is chunking independence in the `Flare.ChunkingIndependent` shape.
* `feedM`: the real post-state when `feed` raises (used by `Flare.Bugs.NET_04`).
-/
namespace Flare.L2.FrameMux
open Flare

/-- `MAX_FRAME_PAYLOAD = 64 * 1024 * 1024` (frame_mux.mojo:54). -/
abbrev MAX_FRAME_PAYLOAD : Nat := 67108864

/-- Big-endian encoding of `n` into `k` bytes. -/
def be (k n : Nat) : Bytes := (Bytes.toLe k n).reverse
/-- Big-endian decoding. -/
def beDec (bs : Bytes) : Nat := Bytes.leNat bs.reverse

theorem be_length (k n : Nat) : (be k n).length = k := by
  simp [be, Bytes.toLe_length]

theorem beDec_be (k n : Nat) (h : n < 256 ^ k) : beDec (be k n) = n := by
  simp [beDec, be, Bytes.leNat_toLe _ _ h]

structure Frame where
  rid : UInt64
  kind : UInt8
  payload : Bytes
deriving DecidableEq, Repr

/-- A frame the encoder accepts. -/
def Frame.Valid (f : Frame) : Prop := f.payload.length ≤ MAX_FRAME_PAYLOAD

/-- The bytes `encode_frame` appends (the success case). -/
def enc (f : Frame) : Bytes :=
  be 4 f.payload.length ++ be 8 f.rid.toNat ++ f.kind :: f.payload

theorem enc_length (f : Frame) : (enc f).length = 13 + f.payload.length := by
  simp [enc, be_length]; omega

/-- mirrors flare/uds/frame_mux.mojo:97-111 @59bda50 -/
def encodeFrame (rid : UInt64) (kind : UInt8) (p : Bytes) : Except String Bytes :=
  if p.length > MAX_FRAME_PAYLOAD then .error "encode_frame: payload exceeds MAX_FRAME_PAYLOAD"
  else .ok (enc ⟨rid, kind, p⟩)

/-- Header length field of a buffer (first 4 bytes, big-endian). -/
def hdrLen (bs : Bytes) : Nat := beDec (bs.take 4)

/-- The frame whose header starts at offset 0 of `bs`, payload length `L`. -/
def frameAt (bs : Bytes) (L : Nat) : Frame :=
  ⟨UInt64.ofNat (beDec ((bs.drop 4).take 8)), bs.getD 12, (bs.drop 13).take L⟩

/-- Decoder errors. -/
inductive DecErr | short | oversize
deriving DecidableEq, Repr

/-- mirrors flare/uds/frame_mux.mojo:114-130 @59bda50
(`ByteReader` raises on a short read; modelled as `DecErr.short`). -/
def decodeFrame (bs : Bytes) : Except DecErr (Frame × Bytes) :=
  if bs.length < 4 then .error .short
  else if hdrLen bs > MAX_FRAME_PAYLOAD then .error .oversize
  else if bs.length < 13 + hdrLen bs then .error .short
  else .ok (frameAt bs (hdrLen bs), bs.drop (13 + hdrLen bs))

/-! ## Codec lemmas -/

theorem enc_take4 (f : Frame) (rest : Bytes) :
    (enc f ++ rest).take 4 = be 4 f.payload.length := by
  simp only [enc, List.append_assoc]
  rw [List.take_append_of_le_length (by simp [be_length])]
  rw [List.take_of_length_le (by simp [be_length])]

theorem hdrLen_enc (f : Frame) (hf : f.Valid) (rest : Bytes) :
    hdrLen (enc f ++ rest) = f.payload.length := by
  unfold hdrLen; rw [enc_take4, beDec_be]
  unfold Frame.Valid at hf; simp only [MAX_FRAME_PAYLOAD] at hf; omega

theorem enc_drop4 (f : Frame) (rest : Bytes) :
    (enc f ++ rest).drop 4 = be 8 f.rid.toNat ++ (f.kind :: (f.payload ++ rest)) := by
  have e : enc f ++ rest = be 4 f.payload.length ++ (be 8 f.rid.toNat ++ (f.kind :: (f.payload ++ rest))) := by
    simp [enc]
  rw [e]; exact List.drop_left' (be_length _ _)

theorem enc_drop12 (f : Frame) (rest : Bytes) :
    (enc f ++ rest).drop 12 = f.kind :: (f.payload ++ rest) := by
  rw [show (12 : Nat) = 4 + 8 by rfl, ← List.drop_drop, enc_drop4]
  exact List.drop_left' (be_length _ _)

theorem frameAt_enc (f : Frame) (rest : Bytes) :
    frameAt (enc f ++ rest) f.payload.length = f := by
  have g12 : (enc f ++ rest).getD 12 = f.kind := by
    unfold Bytes.getD
    have := @List.getElem?_drop _ (enc f ++ rest) 12 0
    simp only [enc_drop12, Nat.add_zero] at this
    rw [← this]; rfl
  have d13 : (enc f ++ rest).drop 13 = f.payload ++ rest := by
    rw [show (13 : Nat) = 12 + 1 by rfl, ← List.drop_drop, enc_drop12]; rfl
  obtain ⟨rid, kind, p⟩ := f
  simp only [frameAt, enc_drop4, d13, g12]
  rw [List.take_left' (be_length _ _), List.take_left' rfl,
    beDec_be _ _ (by have := rid.toNat_lt; simpa using this), UInt64.ofNat_toNat]

theorem drop_enc (f : Frame) (rest : Bytes) :
    (enc f ++ rest).drop (13 + f.payload.length) = rest := by
  rw [← enc_length, List.drop_left]

/-- Codec round trip. -/
theorem decode_encode (rid : UInt64) (kind : UInt8) (p rest : Bytes)
    (hp : p.length ≤ MAX_FRAME_PAYLOAD) :
    encodeFrame rid kind p = .ok (enc ⟨rid, kind, p⟩) ∧
    decodeFrame (enc ⟨rid, kind, p⟩ ++ rest) = .ok (⟨rid, kind, p⟩, rest) := by
  have hv : Frame.Valid ⟨rid, kind, p⟩ := hp
  have hl := enc_length ⟨rid, kind, p⟩
  refine ⟨by simp [encodeFrame, show ¬ p.length > MAX_FRAME_PAYLOAD by omega], ?_⟩
  unfold decodeFrame
  rw [hdrLen_enc _ hv]
  simp only [List.length_append, hl]
  rw [if_neg (by omega), if_neg (by omega), if_neg (by omega)]
  have h1 := frameAt_enc ⟨rid, kind, p⟩ rest
  have h2 := drop_enc ⟨rid, kind, p⟩ rest
  simp only at h1 h2
  rw [h1, h2]

theorem encode_rejects (rid : UInt64) (kind : UInt8) (p : Bytes)
    (hp : p.length > MAX_FRAME_PAYLOAD) : ∃ e, encodeFrame rid kind p = .error e := by
  simp [encodeFrame, hp]

theorem decode_rejects_oversize (bs : Bytes) (h4 : 4 ≤ bs.length)
    (h : hdrLen bs > MAX_FRAME_PAYLOAD) : decodeFrame bs = .error .oversize := by
  unfold decodeFrame; rw [if_neg (by omega), if_pos h]

/-! ## Reassembly (`FrameDemux.feed`) -/

def errOversize : String := "FrameDemux: frame payload exceeds MAX_FRAME_PAYLOAD"

/-- The `while True` loop of `feed`, on the bytes past the parse cursor.
mirrors flare/uds/frame_mux.mojo:185-205 @59bda50 -/
def drain (bs : Bytes) (acc : List Frame) : Except String (List Frame × Bytes) :=
  if bs.length < 13 then .ok (acc, bs)
  else if hdrLen bs > MAX_FRAME_PAYLOAD then .error errOversize
  else if bs.length < 13 + hdrLen bs then .ok (acc, bs)
  else drain (bs.drop (13 + hdrLen bs)) (acc ++ [frameAt bs (hdrLen bs)])
termination_by bs.length
decreasing_by simp; omega

/-- `_peek_len`: big-endian u32 at offset `at`.
mirrors flare/uds/frame_mux.mojo:155-163 @59bda50 -/
def peekLen (buf : Bytes) (at_ : Nat) : Nat := beDec ((buf.drop at_).take 4)

/-- The loop over `(buf, consumed)` exactly as in Mojo: returns the final
`consumed` and the routed frames, or raises.
mirrors flare/uds/frame_mux.mojo:185-205 @59bda50 -/
def feedLoop (buf : Bytes) (consumed : Nat) (routed : List Frame) :
    Except String (Nat × List Frame) :=
  let avail := buf.length - consumed
  if avail < 13 then .ok (consumed, routed)
  else
    let plen := peekLen buf consumed
    if plen > MAX_FRAME_PAYLOAD then .error errOversize
    else
      let need := 13 + plen
      if avail < need then .ok (consumed, routed)
      else feedLoop buf (consumed + need) (routed ++ [frameAt (buf.drop consumed) plen])
termination_by buf.length - consumed
decreasing_by omega

/-- `feedLoop` is `drain` on the suffix past the cursor, and the cursor stays
within `0 ≤ consumed ≤ total`. -/
theorem feedLoop_eq_drain (buf : Bytes) (c : Nat) (R : List Frame) (hc : c ≤ buf.length) :
    (feedLoop buf c R).map (fun p => (p.2, buf.drop p.1)) = drain (buf.drop c) R ∧
    ∀ c' R', feedLoop buf c R = .ok (c', R') → c ≤ c' ∧ c' ≤ buf.length := by
  induction h : buf.length - c using Nat.strongRecOn generalizing c R with
  | _ n ih =>
    rw [feedLoop, drain]
    have hl : (buf.drop c).length = buf.length - c := by simp
    have hp : peekLen buf c = hdrLen (buf.drop c) := rfl
    simp only [hl, hp]
    by_cases h1 : buf.length - c < 13
    · simp [h1, Except.map]; omega
    · simp only [h1, if_false]
      by_cases h2 : hdrLen (buf.drop c) > MAX_FRAME_PAYLOAD
      · simp [h2, Except.map]
      · simp only [h2, if_false]
        by_cases h3 : buf.length - c < 13 + hdrLen (buf.drop c)
        · simp [h3, Except.map]; omega
        · simp only [h3, if_false]
          have := ih (buf.length - (c + (13 + hdrLen (buf.drop c)))) (by omega)
            (c + (13 + hdrLen (buf.drop c))) (R ++ [frameAt (buf.drop c) (hdrLen (buf.drop c))])
            (by omega) rfl
          rw [List.drop_drop] at *
          refine ⟨this.1, fun c' R' he => ?_⟩
          have := this.2 c' R' he; omega

/-- Demux state: the residual buffer and every frame routed so far (in order). -/
structure St where
  buf : Bytes
  routed : List Frame
deriving DecidableEq, Repr

/-- `FrameDemux.feed` (success path compacts; a raise is `Except.error`).
mirrors flare/uds/frame_mux.mojo:176-218 @59bda50 -/
def feed (s : St) (data : Bytes) : Except String St :=
  (feedLoop (s.buf ++ data) 0 s.routed).map fun p => ⟨(s.buf ++ data).drop p.1, p.2⟩

theorem feed_eq_drain (s : St) (data : Bytes) :
    feed s data = (drain (s.buf ++ data) s.routed).map fun p => ⟨p.2, p.1⟩ := by
  have := (feedLoop_eq_drain (s.buf ++ data) 0 s.routed (Nat.zero_le _)).1
  simp only [List.drop_zero] at this
  rw [← this]; unfold feed
  cases feedLoop (s.buf ++ data) 0 s.routed <;> rfl

/-- The residual is a strict prefix of one frame. -/
def Incomplete (r : Bytes) : Prop :=
  r.length < 13 ∨ (hdrLen r ≤ MAX_FRAME_PAYLOAD ∧ r.length < 13 + hdrLen r)

theorem be_beDec (x : Bytes) : be x.length (beDec x) = x := by
  have := Bytes.toLe_leNat x.reverse
  simp only [List.length_reverse] at this
  simp [be, beDec, this]

/-- Re-encoding the frame found at the head of a buffer gives back its bytes. -/
theorem enc_frameAt (bs : Bytes) (h : 13 + hdrLen bs ≤ bs.length) :
    enc (frameAt bs (hdrLen bs)) = bs.take (13 + hdrLen bs) := by
  have hpl : ((bs.drop 13).take (hdrLen bs)).length = hdrLen bs := by simp; omega
  have h4 : (bs.take 4).length = 4 := by simp; omega
  have h8 : ((bs.drop 4).take 8).length = 8 := by simp; omega
  have hlt := Bytes.leNat_lt ((bs.drop 4).take 8).reverse
  simp only [List.length_reverse, h8] at hlt
  have hrid : (UInt64.ofNat (beDec ((bs.drop 4).take 8))).toNat = beDec ((bs.drop 4).take 8) := by
    have : beDec ((bs.drop 4).take 8) < 2 ^ 64 := by unfold beDec; simpa using hlt
    simp [Nat.mod_eq_of_lt this]
  simp only [enc, frameAt, hpl, hrid]
  have e1 : be 4 (hdrLen bs) = bs.take 4 := by
    have := be_beDec (bs.take 4); rw [h4] at this; exact this
  have e2 : be 8 (beDec ((bs.drop 4).take 8)) = (bs.drop 4).take 8 := by
    have := be_beDec ((bs.drop 4).take 8); rw [h8] at this; exact this
  rw [e1, e2, show 13 + hdrLen bs = 4 + (8 + (1 + hdrLen bs)) by omega, List.take_add,
    List.take_add, List.take_add, List.drop_drop, List.drop_drop]
  simp only [Bytes.getD, List.getElem?_eq_getElem (show 12 < bs.length by omega),
    Option.getD_some, List.append_assoc]
  rw [List.drop_eq_getElem_cons (show 12 < bs.length by omega)]; rfl

/-- Key lemma: `drain` distributes over appended input. -/
theorem drain_append (bs y : Bytes) (acc : List Frame) :
    drain (bs ++ y) acc = (drain bs acc >>= fun p => drain (p.2 ++ y) p.1) := by
  induction h : bs.length using Nat.strongRecOn generalizing bs acc with
  | _ n ih =>
    rw [drain.eq_1 bs]
    by_cases h1 : bs.length < 13
    · simp only [h1, if_true]; rfl
    · have ht : hdrLen (bs ++ y) = hdrLen bs := by
        unfold hdrLen; rw [List.take_append_of_le_length (by omega)]
      simp only [h1, if_false]
      by_cases h2 : hdrLen bs > MAX_FRAME_PAYLOAD
      · simp only [h2, if_true]
        rw [drain]; simp only [List.length_append, ht, h2]
        rw [if_neg (by omega)]; rfl
      · simp only [h2, if_false]
        by_cases h3 : bs.length < 13 + hdrLen bs
        · simp only [h3, if_true]; rfl
        · simp only [h3, if_false]
          rw [drain.eq_1 (bs ++ y)]
          simp only [List.length_append, ht, h2, if_false]
          rw [if_neg (by omega), if_neg (by omega)]
          have hf : frameAt (bs ++ y) (hdrLen bs) = frameAt bs (hdrLen bs) := by
            simp only [frameAt]
            rw [List.drop_append_of_le_length (by omega), List.take_append_of_le_length (by simp; omega),
              List.drop_append_of_le_length (by omega), List.take_append_of_le_length (by simp; omega)]
            simp [Bytes.getD, List.getElem?_append_left (show 12 < bs.length by omega)]
          rw [hf, List.drop_append_of_le_length (by omega)]
          exact ih _ (by simp; omega) _ _ rfl

/-- **Chunking independence** of `FrameDemux.feed`. -/
theorem feed_chunking : ChunkingIndependent feed := by
  intro s a b
  rw [feed_eq_drain, feed_eq_drain, ← List.append_assoc, drain_append]
  cases drain (s.buf ++ a) s.routed with
  | error e => rfl
  | ok p => show _ = feed _ b; rw [feed_eq_drain]; rfl

/-- Soundness against the encoder: `drain` splits its input into encoded valid
frames plus an incomplete residual. -/
theorem drain_sound (bs : Bytes) (acc acc' : List Frame) (r : Bytes)
    (h : drain bs acc = .ok (acc', r)) :
    ∃ fs, acc' = acc ++ fs ∧ bs = (fs.map enc).flatten ++ r ∧ Incomplete r ∧
      ∀ f ∈ fs, f.Valid := by
  induction hn : bs.length using Nat.strongRecOn generalizing bs acc with
  | _ n ih =>
    rw [drain] at h
    by_cases h1 : bs.length < 13
    · simp only [h1, if_true, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨[], by simp, by simp, Or.inl h1, by simp⟩
    · simp only [h1, if_false] at h
      by_cases h2 : hdrLen bs > MAX_FRAME_PAYLOAD
      · simp [h2] at h
      · simp only [h2, if_false] at h
        by_cases h3 : bs.length < 13 + hdrLen bs
        · simp only [h3, if_true, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          exact ⟨[], by simp, by simp, Or.inr ⟨by omega, h3⟩, by simp⟩
        · simp only [h3, if_false] at h
          obtain ⟨fs, h4, h5, h6, h7⟩ := ih _ (by simp; omega) _ _ h rfl
          refine ⟨frameAt bs (hdrLen bs) :: fs, by simp [h4], ?_, h6, ?_⟩
          · have hl : (frameAt bs (hdrLen bs)).payload.length = hdrLen bs := by
              simp [frameAt]; omega
            have he : enc (frameAt bs (hdrLen bs)) = bs.take (13 + hdrLen bs) :=
              enc_frameAt bs (by omega)
            simp only [List.map_cons, List.flatten_cons, List.append_assoc, ← h5, he,
              List.take_append_drop]
          · intro f hf
            rcases List.mem_cons.1 hf with rfl | hf
            · simp [Frame.Valid, frameAt]; omega
            · exact h7 f hf

/-- Completeness: `drain` recovers every encoded valid frame and stops at an
incomplete residual. Together with `drain_sound`, `drain` (and so `feed`)
computes exactly the encoder-level decomposition. -/
theorem drain_complete (fs : List Frame) (r : Bytes) (acc : List Frame)
    (hr : Incomplete r) (hv : ∀ f ∈ fs, f.Valid) :
    drain ((fs.map enc).flatten ++ r) acc = .ok (acc ++ fs, r) := by
  induction fs generalizing acc with
  | nil =>
    rw [drain]; simp only [List.map_nil, List.flatten_nil, List.nil_append, List.append_nil]
    rcases hr with h | ⟨h1, h2⟩
    · simp [h]
    · by_cases h0 : r.length < 13
      · simp [h0]
      · simp only [h0, if_false]; rw [if_neg (by omega), if_pos h2]
  | cons f fs ih =>
    have hf : f.Valid := hv f (by simp)
    simp only [List.map_cons, List.flatten_cons, List.append_assoc]
    rw [drain, hdrLen_enc _ hf]
    have hl := enc_length f
    simp only [List.length_append, hl]
    rw [if_neg (by omega), if_neg (by unfold Frame.Valid at hf; omega), if_neg (by omega),
      frameAt_enc, drop_enc, ih _ (fun g hg => hv g (by simp [hg]))]
    simp

/-! ## Per-stream inboxes (`_route`, `poll`) -/

/-- `_route`: append to the frame's own inbox.
mirrors flare/uds/frame_mux.mojo:165-174 @59bda50 -/
def route (m : UInt64 → List Frame) (f : Frame) : UInt64 → List Frame :=
  fun i => if i = f.rid then m i ++ [f] else m i

def routeAll (m : UInt64 → List Frame) (fs : List Frame) : UInt64 → List Frame :=
  fs.foldl route m

/-- FIFO order and isolation: stream `i`'s inbox gains exactly the frames with
`rid = i`, in arrival order; no other stream's frames reach it. -/
theorem routeAll_eq (m : UInt64 → List Frame) (fs : List Frame) (i : UInt64) :
    routeAll m fs i = m i ++ fs.filter (fun f => decide (f.rid = i)) := by
  induction fs generalizing m with
  | nil => simp [routeAll]
  | cons f fs ih =>
    simp only [routeAll, List.foldl_cons] at *
    rw [ih]; simp only [route, List.filter_cons]
    by_cases h : i = f.rid
    · subst h; simp
    · simp [h, Ne.symm h]

/-- `poll`: pop the oldest frame of a stream.
mirrors flare/uds/frame_mux.mojo:220-234 @59bda50 -/
def poll (m : UInt64 → List Frame) (i : UInt64) : Option Frame × (UInt64 → List Frame) :=
  match m i with
  | [] => (none, m)
  | f :: q => (some f, fun j => if j = i then q else m j)

theorem poll_fifo (m : UInt64 → List Frame) (fs : List Frame) (i : UInt64) (f : Frame)
    (h : (fs.filter fun g => decide (g.rid = i)).head? = some f) (hm : m i = []) :
    (poll (routeAll m fs) i).1 = some f := by
  unfold poll; rw [routeAll_eq, hm, List.nil_append]
  revert h; cases fs.filter (fun g => decide (g.rid = i)) <;> simp

/-! ## `FrameMux.next_id` -/

/-- mirrors flare/uds/frame_mux.mojo:274-280 @59bda50 (counter starts at 1) -/
def nextId (n : UInt64) : UInt64 × UInt64 := (n, n + 1)

/-- The `k`-th allocation (0-based) returns `k + 1` mod 2^64. -/
def idAfter : Nat → UInt64 → UInt64
  | 0, n => n
  | k + 1, n => idAfter k (nextId n).2

theorem idAfter_eq (k : Nat) (n : UInt64) : idAfter k n = n + UInt64.ofNat k := by
  induction k generalizing n with
  | zero => simp [idAfter]
  | succ k ih =>
    simp only [idAfter, nextId, ih]
    rw [UInt64.add_assoc]; congr 1
    apply UInt64.toNat.inj; simp; omega

/-- Ids are unique for the first `2^64 - 1` allocations ... -/
theorem nextId_injective (i j : Nat) (hi : i < 2 ^ 64 - 1) (hj : j < 2 ^ 64 - 1)
    (h : idAfter i 1 = idAfter j 1) : i = j := by
  rw [idAfter_eq, idAfter_eq] at h
  have := congrArg UInt64.toNat h
  simp at this; omega

/-- ... and allocation number `2^64 - 1` hands out `0` (wrap; unreachable in practice). -/
theorem nextId_wraps : idAfter (2 ^ 64 - 1) 1 = 0 := by
  rw [idAfter_eq]; decide

/-! ## Post-state when `feed` raises (used by `Flare.Bugs.NET_04`)

On a raise Mojo leaves `self.buf = old ++ data` (the `_compact` after the
loop never runs) while the frames routed before the bad header stay routed. -/

/-- The loop with the raise made explicit: `(ok?, consumed, routed)`.
mirrors flare/uds/frame_mux.mojo:185-205 @59bda50 -/
def feedLoopM (buf : Bytes) (consumed : Nat) (routed : List Frame) :
    Bool × Nat × List Frame :=
  let avail := buf.length - consumed
  if avail < 13 then (true, consumed, routed)
  else
    let plen := peekLen buf consumed
    if plen > MAX_FRAME_PAYLOAD then (false, consumed, routed)
    else
      let need := 13 + plen
      if avail < need then (true, consumed, routed)
      else feedLoopM buf (consumed + need) (routed ++ [frameAt (buf.drop consumed) plen])
termination_by buf.length - consumed
decreasing_by omega

/-- `feed` with the observable post-state on both paths.
mirrors flare/uds/frame_mux.mojo:176-207 @59bda50 -/
def feedM (s : St) (data : Bytes) : Bool × St :=
  let buf := s.buf ++ data
  match feedLoopM buf 0 s.routed with
  | (true, c, R) => (true, ⟨buf.drop c, R⟩)
  | (false, _, R) => (false, ⟨buf, R⟩)

/-- The minimal fix: compact the consumed prefix before raising. -/
def feedMFixed (s : St) (data : Bytes) : Bool × St :=
  let buf := s.buf ++ data
  match feedLoopM buf 0 s.routed with
  | (true, c, R) => (true, ⟨buf.drop c, R⟩)
  | (false, c, R) => (false, ⟨buf.drop c, R⟩)

theorem feedLoopM_error (buf : Bytes) (c c' : Nat) (R R' : List Frame)
    (h : feedLoopM buf c R = (false, c', R')) :
    13 ≤ (buf.drop c').length ∧ hdrLen (buf.drop c') > MAX_FRAME_PAYLOAD := by
  induction hn : buf.length - c using Nat.strongRecOn generalizing c R with
  | _ n ih =>
    rw [feedLoopM] at h
    by_cases h1 : buf.length - c < 13
    · simp [h1] at h
    · simp only [h1, if_false] at h
      by_cases h2 : peekLen buf c > MAX_FRAME_PAYLOAD
      · simp only [h2, if_true, Prod.mk.injEq] at h
        obtain ⟨-, rfl, -⟩ := h
        exact ⟨by simp; omega, h2⟩
      · simp only [h2, if_false] at h
        by_cases h3 : buf.length - c < 13 + peekLen buf c
        · simp [h3] at h
        · simp only [h3, if_false] at h
          exact ih _ (by omega) _ _ h rfl

/-- On the buggy path the whole input, routed frames included, stays buffered. -/
theorem feedM_error_keeps_routed (s s' : St) (data : Bytes) (h : feedM s data = (false, s')) :
    s'.buf = s.buf ++ data := by
  rcases hm : feedLoopM (s.buf ++ data) 0 s.routed with ⟨b, c, R⟩
  simp only [feedM, hm] at h
  cases b
  · simp only [Prod.mk.injEq] at h; rw [← h.2]
  · simp at h

/-- With the fix, after a protocol error the buffer starts at the bad header,
so every later feed raises at once and routes nothing: a frame is never
delivered twice. -/
theorem feedMFixed_error_stuck (s s' : St) (data d : Bytes) (h : feedMFixed s data = (false, s')) :
    feedMFixed s' d = (false, ⟨s'.buf ++ d, s'.routed⟩) := by
  rcases heq : feedLoopM (s.buf ++ data) 0 s.routed with ⟨b, c, R⟩
  simp only [feedMFixed, heq] at h
  cases b
  · simp only [Prod.mk.injEq] at h
    obtain ⟨-, rfl⟩ := h
    obtain ⟨h1, h2⟩ := feedLoopM_error _ _ _ _ _ heq
    unfold feedMFixed
    have hb : feedLoopM ((s.buf ++ data).drop c ++ d) 0 R = (false, 0, R) := by
      rw [feedLoopM]
      have hp : peekLen ((s.buf ++ data).drop c ++ d) 0 = hdrLen ((s.buf ++ data).drop c) := by
        simp only [peekLen, hdrLen, List.drop_zero]
        rw [List.take_append_of_le_length (by omega)]
      simp only [hp, List.length_append]
      rw [if_neg (by omega), if_pos h2]
    simp [hb]
  · simp at h

end Flare.L2.FrameMux
