import Flare.L3_Protocol.H1.ClientChunked

/-!
# Chunked encoder round trip

flare writes chunked bodies in two places:

* the streaming response serializer
  (`flare/http/streaming_serialize.mojo:116-140, 162-166, 258-300`): each
  non-empty chunk as `hex(len) CRLF data CRLF`, then `0 CRLF`, one
  `name: value CRLF` per trailer, and `CRLF`;
* the client's chunked upload (`flare/http/client.mojo:121-135, 1420-1445,
  1470-1495`): the same chunk framing and `0 CRLF CRLF`.

`encodeBody cs tr` is that byte string (an empty write produces nothing).
For any chunking `cs` (including empty writes) and trailers whose lines hold
no CR (which `HeaderMap` guarantees, `flare/http/headers.mojo:75-85`):

* `decL_roundtrip`: the server's `decode_chunked_body` returns exactly
  `cs.flatten` and stops at the end of the encoding;
* `scan_roundtrip`: the shipped scanner (reactor and pooled client reader)
  accepts it at that end when the total fits `max_body`;
* `cDec_roundtrip`: the client's `_decode_chunked` returns `cs.flatten`
  when the trailers pass its own checks.

Bytes after the encoding (`rest`) never matter, so pipelined data is safe.
-/
namespace Flare.L3.H1.ChunkedEncode
open Flare Flare.L3.H1.Chunked Flare.L3.H1.ClientChunked

/-- mirrors flare/http/streaming_serialize.mojo:116-122 @59bda50 -/
def hexDigit (d : Nat) : UInt8 := if d < 10 then (48 + d).toUInt8 else (87 + d).toUInt8

/-- Lowercase hex, most significant digit first, no leading zeros.
mirrors flare/http/streaming_serialize.mojo:126-140 @59bda50
(and flare/http/client.mojo:121-135 @59bda50 for `n > 0`) -/
def hexLower (n : Nat) : Bytes :=
  if n < 16 then [hexDigit n] else hexLower (n / 16) ++ [hexDigit (n % 16)]
termination_by n
decreasing_by omega

/-- One framed chunk.
mirrors flare/http/streaming_serialize.mojo:268-282 @59bda50 -/
def encChunk (c : Bytes) : Bytes := hexLower c.length ++ 13 :: 10 :: (c ++ [13, 10])

/-- The chunk loop; an empty write is skipped.
mirrors flare/http/streaming_serialize.mojo:258-288 @59bda50 -/
def encChunks : List Bytes → Bytes
  | [] => []
  | c :: cs => (if c = [] then [] else encChunk c) ++ encChunks cs

/-- `_write_header_line` without its CRLF.
mirrors flare/http/streaming_serialize.mojo:162-166 @59bda50 -/
def trailerLine (kv : Bytes × Bytes) : Bytes := kv.1 ++ 58 :: 32 :: kv.2

def encTrailers : List (Bytes × Bytes) → Bytes
  | [] => []
  | kv :: tr => trailerLine kv ++ 13 :: 10 :: encTrailers tr

/-- The whole body: chunks, `0 CRLF`, trailers, `CRLF`.
mirrors flare/http/streaming_serialize.mojo:258-300 @59bda50 -/
def encodeBody (cs : List Bytes) (tr : List (Bytes × Bytes)) : Bytes :=
  encChunks cs ++ 48 :: 13 :: 10 :: (encTrailers tr ++ [13, 10])

/-- The client upload: no trailers, `0\r\n\r\n`.
mirrors flare/http/client.mojo:1420-1445 @59bda50 -/
abbrev encodeUpload (cs : List Bytes) : Bytes := encodeBody cs []

/-! ## Hex digits -/

theorem hexDigit_ok : ∀ d : Fin 16, hexVal (hexDigit d.val) = some d.val ∧ hexDigit d.val ≠ 13 ∧
    hexDigit d.val ≠ 59 ∧ isSWS (hexDigit d.val) = false := by decide

theorem mem_hexLower (n : Nat) : ∀ c ∈ hexLower n, ∃ d, d < 16 ∧ c = hexDigit d := by
  fun_induction hexLower n with
  | case1 n h => intro c hc; simp at hc; exact ⟨n, h, hc⟩
  | case2 n h ih =>
    intro c hc
    rcases List.mem_append.mp hc with hc | hc
    · exact ih c hc
    · simp at hc; exact ⟨n % 16, Nat.mod_lt _ (by decide), hc⟩

theorem hexLower_no13 (n : Nat) : 13 ∉ hexLower n := fun h => by
  obtain ⟨d, hd, e⟩ := mem_hexLower n 13 h
  exact (hexDigit_ok ⟨d, hd⟩).2.1 e.symm

theorem hexLower_no59 (n : Nat) : ∀ c ∈ hexLower n, c ≠ 59 := fun c h => by
  obtain ⟨d, hd, rfl⟩ := mem_hexLower n c h
  exact (hexDigit_ok ⟨d, hd⟩).2.2.1

theorem hexLower_noWS (n : Nat) : ∀ c ∈ hexLower n, isSWS c = false := fun c h => by
  obtain ⟨d, hd, rfl⟩ := mem_hexLower n c h
  exact (hexDigit_ok ⟨d, hd⟩).2.2.2

theorem hexAcc_snoc : ∀ (xs : Bytes) (c : UInt8) (a : Nat),
    hexAcc (xs ++ [c]) a = (hexAcc xs a).bind fun s => (hexVal c).map (s * 16 + ·)
  | [], c, a => by
    simp only [List.nil_append, hexAcc, Option.bind_some]
    cases hexVal c <;> rfl
  | x :: xs, c, a => by
    simp only [List.cons_append, hexAcc]
    cases hexVal x with
    | none => rfl
    | some v => exact hexAcc_snoc xs c _

theorem hexAcc_hexLower (n : Nat) : hexAcc (hexLower n) 0 = some n := by
  fun_induction hexLower n with
  | case1 n h => simp [hexAcc, (hexDigit_ok ⟨n, h⟩).1]
  | case2 n h ih =>
    rw [hexAcc_snoc, ih]
    simp only [Option.bind_some, (hexDigit_ok ⟨n % 16, Nat.mod_lt _ (by decide)⟩).1, Option.map_some]
    congr 1; omega

theorem hexLower_len (n : Nat) : ∀ k, n < 16 ^ k → 1 ≤ k → (hexLower n).length ≤ k := by
  fun_induction hexLower n with
  | case1 n h => intro k _ h1; simp; omega
  | case2 n h ih =>
    intro k hk h1
    obtain ⟨j, rfl⟩ : ∃ j, k = j + 1 := ⟨k - 1, by omega⟩
    have hj : 1 ≤ j := by
      rcases Nat.eq_zero_or_pos j with rfl | hj
      · simp at hk; omega
      · exact hj
    have hd : n / 16 < 16 ^ j := by
      rw [Nat.pow_succ] at hk
      exact Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hk)
    have := ih j hd hj
    simp; omega

theorem hexLower_pos (n : Nat) : 1 ≤ (hexLower n).length := by
  fun_induction hexLower n with
  | case1 => simp
  | case2 => simp

theorem hexAcc_mono : ∀ (xs : Bytes) (a r : Nat), hexAcc xs a = some r → a ≤ r
  | [], a, r, h => by simp [hexAcc] at h; omega
  | x :: xs, a, r, h => by
    simp only [hexAcc] at h
    split at h
    · cases h
    · have := hexAcc_mono xs _ r h
      have : a ≤ a * 16 := Nat.le_mul_of_pos_right a (by decide)
      omega

theorem parseHexD_eq : ∀ (xs : Bytes) (s : Nat), (∀ c ∈ xs, c ≠ 59) → parseHexD xs s = hexAcc xs s
  | [], s, _ => rfl
  | x :: xs, s, h => by
    simp only [parseHexD, hexAcc, if_neg (h x (by simp))]
    cases hexVal x with
    | none => rfl
    | some v => exact parseHexD_eq xs _ (fun c hc => h c (by simp [hc]))

theorem parseSize_eq (mb : Nat) : ∀ (xs : Bytes) (s d r : Nat), (∀ c ∈ xs, c ≠ 59) →
    hexAcc xs s = some r → r ≤ mb → parseSize mb xs s d = some (r, d + xs.length)
  | [], s, d, r, _, h, _ => by simp [hexAcc] at h; subst h; simp [parseSize]
  | x :: xs, s, d, r, h59, h, hr => by
    simp only [hexAcc] at h
    simp only [parseSize, if_neg (h59 x (by simp))]
    cases hv : hexVal x with
    | none => rw [hv] at h; cases h
    | some v =>
      rw [hv] at h
      simp only at h ⊢
      have := hexAcc_mono xs _ r h
      rw [if_neg (by omega), parseSize_eq mb xs _ (d + 1) r (fun c hc => h59 c (by simp [hc])) h hr]
      simp; omega

theorem findCRLF_app : ∀ (xs X : Bytes), 13 ∉ xs → findCRLF (xs ++ 13 :: 10 :: X) = some xs.length
  | [], X, _ => by simp [findCRLF]
  | a :: xs, X, h => by
    have ha : a ≠ 13 := fun e => h (by simp [e])
    have ih := findCRLF_app xs X (fun e => h (by simp [e]))
    obtain ⟨b, t, hbt⟩ : ∃ b t, xs ++ 13 :: 10 :: X = b :: t := by
      cases xs <;> simp
    rw [List.cons_append, hbt, findCRLF, if_neg (fun e => ha e.1), ← hbt, ih]
    simp

/-! ## The chunk layout -/

theorem encChunk_app (c R : Bytes) :
    encChunk c ++ R = hexLower c.length ++ 13 :: 10 :: (c ++ 13 :: 10 :: R) := by
  simp [encChunk]

theorem encChunk_length (c : Bytes) : (encChunk c).length = (hexLower c.length).length + 2 + c.length + 2 := by
  simp [encChunk]; omega

theorem chunk_take (H c R : Bytes) : (H ++ 13 :: 10 :: (c ++ 13 :: 10 :: R)).take H.length = H := by
  simp

theorem chunk_data (H c R : Bytes) : ((H ++ 13 :: 10 :: (c ++ 13 :: 10 :: R)).drop (H.length + 2)).take c.length = c := by
  rw [← List.drop_drop, List.drop_left]; simp

theorem chunk_rest (H c R : Bytes) : (H ++ 13 :: 10 :: (c ++ 13 :: 10 :: R)).drop (H.length + 2 + c.length + 2) = R := by
  rw [← List.drop_drop, ← List.drop_drop, ← List.drop_drop, List.drop_left]
  simp

theorem chunk_crlf (H c R : Bytes) :
    Bytes.getD (H ++ 13 :: 10 :: (c ++ 13 :: 10 :: R)) (H.length + 2 + c.length) = 13 ∧
    Bytes.getD (H ++ 13 :: 10 :: (c ++ 13 :: 10 :: R)) (H.length + 2 + c.length + 1) = 10 := by
  constructor
  · simp only [Bytes.getD, List.getElem?_append_right (show H.length ≤ H.length + 2 + c.length by omega)]
    rw [show H.length + 2 + c.length - H.length = c.length + 2 by omega]
    simp [List.getElem?_append_right]
  · simp only [Bytes.getD, List.getElem?_append_right (show H.length ≤ H.length + 2 + c.length + 1 by omega)]
    rw [show H.length + 2 + c.length + 1 - H.length = c.length + 3 by omega]
    simp [List.getElem?_append_right]

theorem chunk_len (H c R : Bytes) : (H ++ 13 :: 10 :: (c ++ 13 :: 10 :: R)).length = H.length + 2 + c.length + 2 + R.length := by
  simp; omega

/-! ## `decode_chunked_body` -/

theorem decTr_line (L X : Bytes) (h13 : 13 ∉ L) (h2 : 2 ≤ L.length) :
    decTr (L ++ 13 :: 10 :: X) = (decTr X).map (· + (L.length + 2)) := by
  obtain ⟨a, b, t, rfl⟩ : ∃ a b t, L = a :: b :: t := by
    match L, h2 with
    | a :: b :: t, _ => exact ⟨a, b, t, rfl⟩
  have ha : a ≠ 13 := fun e => h13 (by simp [e])
  have hk := findCRLF_app (a :: b :: t) X h13
  simp only [List.cons_append] at hk ⊢
  rw [decTr, if_neg (fun e => ha e.1)]
  split
  · simp_all
  · rename_i k2 hk2; rw [hk] at hk2; cases hk2
    simp

/-- No trailer line holds a CR (`HeaderMap` refuses CR/LF in names and values). -/
def TrailersOK (tr : List (Bytes × Bytes)) : Prop := ∀ kv ∈ tr, 13 ∉ trailerLine kv

theorem trailerLine_len (kv : Bytes × Bytes) : 2 ≤ (trailerLine kv).length := by
  simp [trailerLine]; omega

theorem decTr_trailers : ∀ (tr : List (Bytes × Bytes)) (X : Bytes), TrailersOK tr →
    decTr (encTrailers tr ++ 13 :: 10 :: X) = .ok ((encTrailers tr).length + 2)
  | [], X, _ => by simp [encTrailers]; rw [decTr, if_pos ⟨rfl, rfl⟩]
  | kv :: tr, X, h => by
    have e : encTrailers (kv :: tr) ++ 13 :: 10 :: X = trailerLine kv ++ 13 :: 10 :: (encTrailers tr ++ 13 :: 10 :: X) := by
      simp [encTrailers]
    rw [e, decTr_line _ _ (h kv (by simp)) (trailerLine_len kv),
      decTr_trailers tr X (fun x hx => h x (by simp [hx]))]
    simp [Except.map, encTrailers]; omega

theorem decL_chunk (c R : Bytes) (hc : c ≠ []) :
    decL (encChunk c ++ R) = (decL R).map fun r => (c ++ r.1, r.2 + (encChunk c).length) := by
  have hn : 0 < c.length := List.length_pos_iff.mpr hc
  rw [encChunk_app]
  have hk := findCRLF_app (hexLower c.length) (c ++ 13 :: 10 :: R) (hexLower_no13 _)
  rw [decL_some hk, chunk_take, parseHexD_eq _ _ (hexLower_no59 _), hexAcc_hexLower]
  simp only [show c.length ≠ 0 by omega, if_false]
  rw [if_neg (by rw [chunk_len]; omega), chunk_rest, chunk_data, encChunk_length]

theorem except_map_id {α ε : Type} (x : Except ε α) : x.map (fun r => r) = x := by
  cases x <;> rfl

theorem decL_encChunks : ∀ (cs : List Bytes) (T : Bytes),
    decL (encChunks cs ++ T) = (decL T).map fun r => (cs.flatten ++ r.1, r.2 + (encChunks cs).length)
  | [], T => by simp [encChunks]; exact (except_map_id _).symm
  | c :: cs, T => by
    by_cases hc : c = []
    · subst hc; simp only [encChunks, if_true, List.nil_append, List.flatten_cons]
      exact decL_encChunks cs T
    · simp only [encChunks, if_neg hc, List.append_assoc, List.flatten_cons]
      rw [decL_chunk c _ hc, decL_encChunks cs T]
      cases decL T <;> simp [Except.map]; omega

theorem decL_zero (Y : Bytes) : decL (48 :: 13 :: 10 :: Y) = (decTr Y).map fun e => ([], e + 3) := by
  have hk : findCRLF (48 :: 13 :: 10 :: Y) = some 1 := findCRLF_app [48] Y (by decide)
  rw [decL_some hk, show (48 :: 13 :: 10 :: Y).take 1 = [48] from rfl]
  have : parseHexD [48] 0 = some 0 := by decide
  rw [this]; rfl

/-- **Round trip through the server decoder.** -/
theorem decL_roundtrip (cs : List Bytes) (tr : List (Bytes × Bytes)) (rest : Bytes) (htr : TrailersOK tr) :
    decL (encodeBody cs tr ++ rest) = .ok (cs.flatten, (encodeBody cs tr).length) := by
  simp only [encodeBody, List.append_assoc, List.cons_append]
  rw [decL_encChunks, decL_zero]
  simp only [List.nil_append]
  rw [decTr_trailers tr rest htr]
  simp [Except.map]; omega

theorem decodeBody_roundtrip (cs : List Bytes) (tr : List (Bytes × Bytes)) (pre rest : Bytes) (htr : TrailersOK tr) :
    decodeBody (pre ++ encodeBody cs tr ++ rest) pre.length =
      .ok (cs.flatten, pre.length + (encodeBody cs tr).length) := by
  unfold decodeBody
  rw [List.append_assoc, List.drop_left, decL_roundtrip cs tr rest htr]
  simp [Except.map]; omega

/-! ## The scanner -/

theorem SRes.shift_zero (r : SRes) : r.shift 0 = r := by cases r <;> rfl

theorem SRes.shift_shift (r : SRes) (a b : Nat) : (r.shift a).shift b = r.shift (a + b) := by
  cases r <;> simp [SRes.shift]; omega

theorem scanTr_line (P : Policy) (hP : P = implP) (L X : Bytes) (h13 : 13 ∉ L) (h2 : 2 ≤ L.length) :
    scanTr P (L ++ 13 :: 10 :: X) = (scanTr P X).shift (L.length + 2) := by
  subst hP
  obtain ⟨a, b, t, rfl⟩ : ∃ a b t, L = a :: b :: t := by
    match L, h2 with
    | a :: b :: t, _ => exact ⟨a, b, t, rfl⟩
  have ha : a ≠ 13 := fun e => h13 (by simp [e])
  have hk := findCRLF_app (a :: b :: t) X h13
  simp only [List.cons_append] at hk ⊢
  rw [scanTr, if_neg (fun e => ha e.1)]
  split
  · simp_all
  · rename_i k2 hk2; rw [hk] at hk2; cases hk2
    simp [implP]

theorem scanTr_trailers : ∀ (tr : List (Bytes × Bytes)) (X : Bytes), TrailersOK tr →
    scanTr implP (encTrailers tr ++ 13 :: 10 :: X) = .done ((encTrailers tr).length + 2)
  | [], X, _ => by simp [encTrailers]; rw [scanTr, if_pos ⟨rfl, rfl⟩]
  | kv :: tr, X, h => by
    have e : encTrailers (kv :: tr) ++ 13 :: 10 :: X = trailerLine kv ++ 13 :: 10 :: (encTrailers tr ++ 13 :: 10 :: X) := by
      simp [encTrailers]
    rw [e, scanTr_line implP rfl _ _ (h kv (by simp)) (trailerLine_len kv),
      scanTr_trailers tr X (fun x hx => h x (by simp [hx]))]
    simp [SRes.shift, encTrailers]; omega

theorem scan_chunk (mb tot : Nat) (c R : Bytes) (hc : c ≠ []) (hsz : c.length < 2 ^ 60) (hmb : tot + c.length ≤ mb) :
    scanL implP mb (encChunk c ++ R) tot =
      ((scanL implP mb R (tot + c.length)).1.shift (encChunk c).length,
       (scanL implP mb R (tot + c.length)).2.1 + (encChunk c).length,
       (scanL implP mb R (tot + c.length)).2.2) := by
  have hn : 0 < c.length := List.length_pos_iff.mpr hc
  have hlen : (hexLower c.length).length ≤ 15 :=
    hexLower_len _ 15 (by have : (2 : Nat) ^ 60 = 16 ^ 15 := by decide
                          omega) (by decide)
  have hpos := hexLower_pos c.length
  rw [encChunk_app]
  have hk := findCRLF_app (hexLower c.length) (c ++ 13 :: 10 :: R) (hexLower_no13 _)
  rw [scanL_some hk, chunk_take,
    parseSize_eq mb _ 0 0 c.length (hexLower_no59 _) (hexAcc_hexLower _) (by omega)]
  have hcr := chunk_crlf (hexLower c.length) c R
  simp only [CAP, implP, show ¬ (hexLower c.length).length > 4096 by omega, if_false, Bool.false_eq_true,
    false_and, Nat.zero_add, show (hexLower c.length).length ≠ 0 by omega, show c.length ≠ 0 by omega,
    show ¬ tot + c.length > mb by omega, hcr, ne_eq, not_true_eq_false, or_self]
  rw [if_neg (by rw [chunk_len]; omega), chunk_rest, encChunk_length]

theorem scan_encChunks (mb : Nat) : ∀ (cs : List Bytes) (T : Bytes) (tot : Nat),
    (∀ c ∈ cs, c.length < 2 ^ 60) → tot + cs.flatten.length ≤ mb →
    scanL implP mb (encChunks cs ++ T) tot =
      ((scanL implP mb T (tot + cs.flatten.length)).1.shift (encChunks cs).length,
       (scanL implP mb T (tot + cs.flatten.length)).2.1 + (encChunks cs).length,
       (scanL implP mb T (tot + cs.flatten.length)).2.2)
  | [], T, tot, _, _ => by simp [encChunks, SRes.shift_zero]
  | c :: cs, T, tot, hs, hmb => by
    by_cases hc : c = []
    · subst hc; simp only [encChunks, if_true, List.nil_append, List.flatten_cons]
      exact scan_encChunks mb cs T tot (fun x hx => hs x (by simp [hx]))
        (by rw [List.flatten_cons, List.length_append, List.length_nil, Nat.zero_add] at hmb; exact hmb)
    · have hmb' : tot + c.length + cs.flatten.length ≤ mb := by
        rw [List.flatten_cons, List.length_append] at hmb; omega
      rw [show tot + (c :: cs).flatten.length = tot + c.length + cs.flatten.length by
        rw [List.flatten_cons, List.length_append, Nat.add_assoc]]
      simp only [encChunks, if_neg hc, List.append_assoc]
      rw [scan_chunk mb tot c _ hc (hs c (by simp)) (by omega),
        scan_encChunks mb cs T (tot + c.length) (fun x hx => hs x (by simp [hx])) (by omega)]
      simp only [SRes.shift_shift, List.length_append]
      refine Prod.ext ?_ (Prod.ext ?_ rfl)
      · show SRes.shift _ _ = SRes.shift _ _
        congr 1; omega
      · show _ + _ + _ = _ + _
        omega

theorem scan_zero (mb tot : Nat) (Y : Bytes) :
    scanL implP mb (48 :: 13 :: 10 :: Y) tot = ((scanTr implP Y).shift 3, 0, tot) := by
  have hk : findCRLF (48 :: 13 :: 10 :: Y) = some 1 := findCRLF_app [48] Y (by decide)
  rw [scanL_some hk]
  have : parseSize mb ((48 :: 13 :: 10 :: Y).take 1) 0 0 = some (0, 1) := by
    simp [parseSize, hexVal]
  simp only [this, CAP, implP]
  simp

/-- **The shipped scanner accepts every encoding**, ending exactly at its
last byte, when the decoded total fits `max_body` and each chunk is below
`2^60` bytes. -/
theorem scan_roundtrip (mb : Nat) (cs : List Bytes) (tr : List (Bytes × Bytes)) (rest : Bytes)
    (hs : ∀ c ∈ cs, c.length < 2 ^ 60) (htr : TrailersOK tr) (hmb : cs.flatten.length ≤ mb) :
    scanImpl (encodeBody cs tr ++ rest) 0 mb = .done (encodeBody cs tr).length := by
  simp only [scanEnd, scanResume, List.drop_zero, SRes.shift_zero, encodeBody, List.append_assoc, List.cons_append]
  rw [scan_encChunks mb cs _ 0 hs (by omega), scan_zero]
  simp only [List.nil_append]
  rw [scanTr_trailers tr rest htr]
  simp [SRes.shift]; omega

/-! ## The client decoder `_decode_chunked` -/

theorem takeWhile_all {p : UInt8 → Bool} : ∀ (l : Bytes), (∀ c ∈ l, p c = true) → l.takeWhile p = l
  | [], _ => rfl
  | a :: l, h => by
    rw [List.takeWhile_cons, if_pos (h a (by simp)), takeWhile_all l (fun c hc => h c (by simp [hc]))]

theorem cHex_hexLower (n : Nat) (h : n < 2 ^ 60) : cHex (pyStrip (beforeSemi (hexLower n))) = some n := by
  have hbs : beforeSemi (hexLower n) = hexLower n := by
    unfold beforeSemi
    exact takeWhile_all _ (fun c hc => by simpa using hexLower_no59 n c hc)
  rw [hbs, pyStrip_of_noWS _ (hexLower_noWS n)]
  have hlen : (hexLower n).length ≤ 15 :=
    hexLower_len _ 15 (by have : (2 : Nat) ^ 60 = 16 ^ 15 := by decide
                          omega) (by decide)
  have hpos := hexLower_pos n
  unfold cHex
  rw [if_neg (fun e => by rw [e] at hpos; simp at hpos), if_neg (by omega), hexAcc_hexLower]

theorem cDec_chunk (c R : Bytes) (hc : c ≠ []) (hsz : c.length < 2 ^ 60) :
    cDec (encChunk c ++ R) = (cDec R).map (c ++ ·) := by
  have hn : 0 < c.length := List.length_pos_iff.mpr hc
  rw [encChunk_app]
  have hk := findCRLF_app (hexLower c.length) (c ++ 13 :: 10 :: R) (hexLower_no13 _)
  obtain ⟨a, t, hat⟩ : ∃ a t, hexLower c.length ++ 13 :: 10 :: (c ++ 13 :: 10 :: R) = a :: t := by
    cases hh : hexLower c.length with
    | nil => have := hexLower_pos c.length; rw [hh] at this; simp at this
    | cons a t => exact ⟨a, t ++ 13 :: 10 :: (c ++ 13 :: 10 :: R), rfl⟩
  rw [hat] at hk ⊢
  rw [cDec_cons_eq hk, ← hat, chunk_take, cHex_hexLower _ hsz]
  simp only [show c.length ≠ 0 by omega, if_false]
  rw [List.drop_drop, show (hexLower c.length).length + 2 + (c.length + 2) =
    (hexLower c.length).length + 2 + c.length + 2 by omega, chunk_rest, chunk_data]

/-- The client's trailer check passes. -/
def ClientTrailersOK (tr : List (Bytes × Bytes)) : Prop := ∀ kv ∈ tr, 13 ∉ trailerLine kv ∧ trailerOk (trailerLine kv) = true

theorem cTr_line (L X : Bytes) (h13 : 13 ∉ L) (h1 : L ≠ []) (hok : trailerOk L = true) :
    cTr (L ++ 13 :: 10 :: X) = cTr X := by
  obtain ⟨a, t, rfl⟩ : ∃ a t, L = a :: t := by
    cases L with
    | nil => exact absurd rfl h1
    | cons a t => exact ⟨a, t, rfl⟩
  have hk := findCRLF_app (a :: t) X h13
  simp only [List.cons_append, List.length_cons] at hk ⊢
  rw [cTr]
  split
  · simp_all
  · rename_i hk2; rw [hk] at hk2; cases hk2
  · rename_i k hk2; rw [hk] at hk2; cases hk2
    have e1 : (a :: (t ++ 13 :: 10 :: X)).take (t.length + 1) = a :: t := by simp
    have e2 : (a :: (t ++ 13 :: 10 :: X)).drop (t.length + 1 + 2) = X := by
      rw [show t.length + 1 + 2 = 1 + t.length + 2 by omega, ← List.drop_drop, ← List.drop_drop]; simp
    rw [e1, e2, if_pos hok]

theorem cTr_trailers : ∀ (tr : List (Bytes × Bytes)) (X : Bytes), ClientTrailersOK tr →
    cTr (encTrailers tr ++ 13 :: 10 :: X) = .ok ()
  | [], X, _ => by simp [encTrailers]; rw [cTr]; split <;> simp_all [findCRLF]
  | kv :: tr, X, h => by
    have e : encTrailers (kv :: tr) ++ 13 :: 10 :: X = trailerLine kv ++ 13 :: 10 :: (encTrailers tr ++ 13 :: 10 :: X) := by
      simp [encTrailers]
    have hne : trailerLine kv ≠ [] := fun e => by have := trailerLine_len kv; rw [e] at this; simp at this
    rw [e, cTr_line _ _ (h kv (by simp)).1 hne (h kv (by simp)).2,
      cTr_trailers tr X (fun x hx => h x (by simp [hx]))]

theorem cDec_encChunks : ∀ (cs : List Bytes) (T : Bytes), (∀ c ∈ cs, c.length < 2 ^ 60) →
    cDec (encChunks cs ++ T) = (cDec T).map (cs.flatten ++ ·)
  | [], T, _ => by simp [encChunks]; exact (except_map_id _).symm
  | c :: cs, T, hs => by
    by_cases hc : c = []
    · subst hc; simp only [encChunks, if_true, List.nil_append, List.flatten_cons]
      exact cDec_encChunks cs T (fun x hx => hs x (by simp [hx]))
    · simp only [encChunks, if_neg hc, List.append_assoc, List.flatten_cons]
      rw [cDec_chunk c _ hc (hs c (by simp)), cDec_encChunks cs T (fun x hx => hs x (by simp [hx]))]
      cases cDec T <;> simp [Except.map]

/-- **Round trip through the client decoder.** -/
theorem cDec_roundtrip (cs : List Bytes) (tr : List (Bytes × Bytes)) (rest : Bytes)
    (hs : ∀ c ∈ cs, c.length < 2 ^ 60) (htr : ClientTrailersOK tr) :
    cDec (encodeBody cs tr ++ rest) = .ok cs.flatten := by
  simp only [encodeBody, List.append_assoc, List.cons_append]
  rw [cDec_encChunks cs _ hs]
  simp only [List.nil_append]
  have hk : findCRLF (48 :: 13 :: 10 :: (encTrailers tr ++ 13 :: 10 :: rest)) = some 1 :=
    findCRLF_app [48] _ (by decide)
  rw [cDec_cons_eq hk, show (48 :: 13 :: 10 :: (encTrailers tr ++ 13 :: 10 :: rest)).take 1 = [48] from rfl]
  have : cHex (pyStrip (beforeSemi [48])) = some 0 := by decide
  rw [this]
  simp only [if_true, List.drop_succ_cons, List.drop_zero]
  rw [cTr_trailers tr rest htr]
  simp [Except.map]

/-- The client upload decodes on the server to exactly the written bytes. -/
theorem upload_roundtrip (cs : List Bytes) (rest : Bytes) :
    decL (encodeUpload cs ++ rest) = .ok (cs.flatten, (encodeUpload cs).length) :=
  decL_roundtrip cs [] rest (by intro kv h; simp at h)

end Flare.L3.H1.ChunkedEncode
