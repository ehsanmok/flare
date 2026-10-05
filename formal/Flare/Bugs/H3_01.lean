import Flare.L3_Protocol.H3.RequestReader

/-!
# H3-01: the request reader buffers non-HEADERS/DATA frames without bound

flare/http3/request_reader.mojo:240-259 @59bda50 (before the fix): HEADERS and DATA frames
were checked against `max_field_section_bytes` / `max_body_bytes` from the
frame header alone, but every other type (unknown / grease types, and the
control types that are rejected anyway) reaches `if total > len(buf):
return 0` and reports NEEDS_MORE until the whole declared payload, up to
2^62 - 1 bytes, sits in the caller's buffer. `Http3Connection.feed_stream_chunk`
(flare/http3/server.mojo:732-807) keeps appending to the per-stream inbox;
only QUIC flow control bounds it.

Spec clause: RFC 9114 §7.2.8 (unknown frame types are ignored, so their
payload can be discarded as it arrives) and §10.5 (an endpoint may limit the
resources a peer commits, H3_EXCESSIVE_LOAD). Property `BoundedNeed`: there
is a bound `B(reader)`, depending only on the reader's limits, such that
once `B` bytes are buffered the reader acts.

Counterexample: type 0x21, declared length 2^62 - 1, followed by any
`n < 2^62 - 1` payload bytes: `feed` returns `(0, r, none)`, so no bound
below 2^62 - 1 works.

Fix: a frame of any other type whose declared length exceeds
`max_field_section_bytes` is rejected from its header (H3_EXCESSIVE_LOAD).
Then `B(r) = 16 + max_field_section_bytes + max_body_bytes` suffices
(`feed_bounded`).

Status: resolved. `feedOld` below is the pre-fix reader (the counterexample is
about it); the shipped `Flare.L3.H3.feed` has the check and satisfies
`BoundedNeed` (`feed_bounded`); `feed_eq_feedOld` shows nothing else changed.
Regression test: tests/h3/test_request_reader.mojo
`test_oversized_unknown_frame_is_refused_from_its_header`.
-/
namespace Flare.Bugs.H3_01
open Flare.L3.H3

variable {Hdrs : Type}

/-- Frame header: type 0x21 (grease), length varint 2^62 - 1. -/
def hdr : Bytes := [0x21, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

theorem hdr_parses : parseHeader hdr = some (0x21, 2 ^ 62 - 1, 9) := by decide

/-- The pre-fix reader (flare @59bda50): no limit for types other than
HEADERS and DATA.
mirrors flare/http3/request_reader.mojo:197-327 @59bda50 -/
def feedOld (qd : Bytes → Option Hdrs) (r : Reader) (buf : Bytes) :
    Nat × Reader × Option (Ev Hdrs) :=
  if r.st = .done then (0, r, none)
  else if buf.length = 0 then (0, r, none)
  else match parseHeader buf with
    | none => (0, r, none)
    | some (t, l, hs) =>
      if t = T_HEADERS ∧ l > r.maxField then (hs, {r with st := .done}, some (.error .fieldTooBig))
      else if t = T_DATA ∧ r.bodyBytes + l > r.maxBody then
        (hs, {r with st := .done}, some (.error .bodyTooBig))
      else if hs + l > buf.length then (0, r, none)
      else
        let res := stepFrame qd r t ((buf.drop hs).take l)
        (hs + l, res.1, some res.2)

/-- **Counterexample.** However many payload bytes are buffered (below the
declared 2^62 - 1), the reader asks for more and fires no event. -/
theorem unknown_needs_unbounded_buffer (qd : Bytes → Option Hdrs) (r : Reader)
    (hr : r.st ≠ .done) (n : Nat) (hn : n < 2 ^ 62 - 1) :
    feedOld qd r (hdr ++ List.replicate n 0) = (0, r, none) := by
  unfold feedOld
  have hlen : (hdr ++ List.replicate n (0 : UInt8)).length = 9 + n := by simp [hdr]; omega
  rw [if_neg hr, if_neg (by omega), parseHeader_append hdr_parses]
  simp only [T_HEADERS, T_DATA, hlen]
  rw [if_neg (by omega), if_neg (by omega), if_pos (by omega)]

/-- A buffer of `bound r` bytes is always enough for the reader to act. -/
def BoundedNeed (step : Reader → Bytes → Nat × Reader × Option (Ev Hdrs))
    (bound : Reader → Nat) : Prop :=
  ∀ r buf, r.st ≠ .done → bound r ≤ buf.length → 0 < (step r buf).1

/-- No bound below 2^62 - 1 (for any live reader) works for the pre-fix reader. -/
theorem violates_spec (qd : Bytes → Option Hdrs) (bound : Reader → Nat) (r : Reader)
    (hr : r.st ≠ .done) (hb : bound r < 2 ^ 62 - 1) : ¬ BoundedNeed (feedOld qd) bound := by
  intro h
  have := h r (hdr ++ List.replicate (bound r) 0) hr (by simp)
  rw [unknown_needs_unbounded_buffer qd r hr (bound r) hb] at this
  exact Nat.lt_irrefl 0 this

theorem decVarint_some_of_len (b : Bytes) (h : 8 ≤ b.length) : ∃ v k, decVarint b = some (v, k) := by
  cases b with
  | nil => simp at h
  | cons b0 tl =>
    have := varLen_pos (b0.toNat / 64)
    simp only [decVarint]
    rw [if_neg (by omega)]
    exact ⟨_, _, rfl⟩

theorem parseHeader_some_of_len (b : Bytes) (h : 16 ≤ b.length) :
    ∃ t l hs, parseHeader b = some (t, l, hs) := by
  obtain ⟨t, k1, h1⟩ := decVarint_some_of_len b (by omega)
  have hk1 := decVarint_some h1
  obtain ⟨l, k2, h2⟩ := decVarint_some_of_len (b.drop k1) (by simp; omega)
  refine ⟨t, l, k1 + k2, ?_⟩
  unfold parseHeader
  rw [h1]
  simp only
  rw [if_neg (by simp; omega), h2]

/-- **The shipped reader meets the spec**: `16 + max_field_section_bytes +
max_body_bytes` buffered bytes always make the reader act. -/
theorem feed_bounded (qd : Bytes → Option Hdrs) :
    BoundedNeed (feed qd) (fun r => 16 + r.maxField + r.maxBody) := by
  intro r buf hr hb
  simp only at hb
  obtain ⟨t, l, hs, hh⟩ := parseHeader_some_of_len buf (by omega)
  have hp := parseHeader_some hh
  unfold feed
  rw [if_neg hr, if_neg (by omega), hh]
  simp only
  split; · simp; omega
  rename_i h1
  split; · simp; omega
  rename_i h2
  split; · simp; omega
  rename_i h3
  rw [if_neg]
  · simp; omega
  · intro hgt
    by_cases ht : t = T_HEADERS
    · exact h1 ⟨ht, by omega⟩
    · by_cases hd : t = T_DATA
      · have : ¬ r.bodyBytes + l > r.maxBody := fun h => h2 ⟨hd, h⟩
        omega
      · have : ¬ l > r.maxField := fun h => h3 ⟨ht, hd, h⟩
        omega

/-- The fix changes nothing for frames within the limits. -/
theorem feed_eq_feedOld (qd : Bytes → Option Hdrs) (r : Reader) (buf : Bytes)
    (h : ∀ t l hs, parseHeader buf = some (t, l, hs) → t ≠ T_HEADERS → t ≠ T_DATA →
      l ≤ r.maxField) :
    feed qd r buf = feedOld qd r buf := by
  unfold feed feedOld
  by_cases h0 : r.st = .done
  · rw [if_pos h0, if_pos h0]
  rw [if_neg h0, if_neg h0]
  by_cases h1 : buf.length = 0
  · rw [if_pos h1, if_pos h1]
  rw [if_neg h1, if_neg h1]
  rcases hh : parseHeader buf with _ | ⟨t, l, hs⟩
  · rfl
  simp only
  by_cases a : t = T_HEADERS ∧ l > r.maxField
  · rw [if_pos a, if_pos a]
  rw [if_neg a, if_neg a]
  by_cases b : t = T_DATA ∧ r.bodyBytes + l > r.maxBody
  · rw [if_pos b, if_pos b]
  rw [if_neg b, if_neg b, if_neg]
  rintro ⟨ht, hd, hl⟩
  have := h t l hs hh ht hd
  omega

end Flare.Bugs.H3_01
