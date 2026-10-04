import Flare.L3_Protocol.H1.ChunkedSpec

/-!
# H1-01: chunk-line cap verdict depends on segmentation

* flare file: `flare/http/proto/chunked.mojo:246-251` (chunk-size line) and
  `:270-290` (trailer lines) @59bda50, polled by
  `flare/http/_reactor/conn_handle.mojo:655-678`.
* Spec clause: the reactor's verdict on a byte stream must be a function of
  the bytes, not of how TCP segmented them (`SegIndep`): polling over any
  split equals a one-shot `scan_chunked_end` of the concatenation.
* What goes wrong: the incomplete-line test `n - pos > CHUNK_LINE_MAX`
  counts the pending CR, so a 4096-byte chunk line cut after its CR is
  MALFORMED, while the same bytes in one read are accepted. A complete
  trailer line has no cap, a partial one is capped at 4096.
* Fix (`fixedP`): one byte of slack in both incomplete tests and a cap on
  complete trailer lines.
-/
namespace Flare.Bugs.H1_01
open Flare Flare.L3.H1.Chunked

/-- Segmentation independence of the reactor's polling loop. -/
def SegIndep (P : Policy) : Prop :=
  ∀ (mb h : Nat) (b0 : Bytes) (segs : List Bytes),
    poll P mb b0 h 0 segs = scanEnd P (b0 ++ segs.flatten) h mb

/-- `"1;" ++ 4094 × 'a'`: a chunk-size line of exactly `CHUNK_LINE_MAX` bytes. -/
def line1 : Bytes := Bytes.ofString "1;" ++ List.replicate 4094 97
def body1 : Bytes := line1 ++ Bytes.ofString "\r\nZ\r\n0\r\n\r\n"

/-- Last chunk followed by a 5000-byte trailer line. -/
def body2 : Bytes :=
  Bytes.ofString "0\r\nX: " ++ List.replicate 4997 98 ++ Bytes.ofString "\r\n\r\n"

def mb : Nat := 2 ^ 20

/-- Cut after the CR of the size line: MALFORMED; one read: accepted at 4106. -/
theorem counterexample_size_line :
    poll implP mb (body1.take 4097) 0 0 [body1.drop 4097] = .malformed ∧
    scanImpl body1 0 mb = .done 4106 := by native_decide

/-- Trailer line cut at 4503 bytes: MALFORMED; one read: accepted at 5007. -/
theorem counterexample_trailer :
    poll implP mb (body2.take 4503) 0 0 [body2.drop 4503] = .malformed ∧
    scanImpl body2 0 mb = .done 5007 := by native_decide

theorem counterexample : ¬ SegIndep implP := by
  intro h
  have := h mb 0 (body1.take 4097) [body1.drop 4097]
  rw [counterexample_size_line.1] at this
  simp only [List.flatten_cons, List.flatten_nil, List.append_nil, List.take_append_drop] at this
  have h2 : scanEnd implP body1 0 mb = .done 4106 := counterexample_size_line.2
  rw [h2] at this
  exact SRes.noConfusion this

/-- The fix meets the spec for every buffer, split and `max_body`. -/
theorem fixed_segmentation_independent : SegIndep fixedP :=
  fun mb h b0 segs => fixed_poll_eq_oneShot mb h b0 segs

/-- The fixed scanner accepts the same 4096-byte line in both deliveries. -/
theorem fixed_accepts_size_line :
    poll fixedP mb (body1.take 4097) 0 0 [body1.drop 4097] = .done 4106 := by native_decide

end Flare.Bugs.H1_01
