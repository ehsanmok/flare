import Flare.L2_Machine.FrameMux

/-!
# NET-04: `FrameDemux.feed` re-delivers frames after a protocol error

Status: resolved. `feed` now drops the consumed prefix before raising on an
oversize header; the model's `feedM` mirrors the shipped code and the
counterexample below is about the pre-fix `feedMOld`.

Pre-fix code, flare/uds/frame_mux.mojo:176-207 @59bda50. `feed` routes frames while
advancing a local `consumed` and compacts only after the loop; a header with
a payload length above `MAX_FRAME_PAYLOAD` raises mid-loop, skipping the
compaction. The next `feed` parses the already-routed frames again.
Repro: formal/repro/NET-04_frame_demux_redelivers_after_error.mojo.
-/
namespace Flare.Bugs.NET_04
open Flare.L2.FrameMux

/-- One CHUNK frame for stream 5 (payload `07 07 07`) followed by a header
claiming a `0xFFFFFFFF`-byte payload. -/
def wire : Flare.Bytes :=
  enc ⟨5, 1, [7, 7, 7]⟩ ++ [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0]

def countFor (s : St) (i : UInt64) : Nat :=
  (s.routed.filter fun f => decide (f.rid = i)).length

/-- Pre-fix: feed the wire (raises), then feed nothing (raises again):
stream 5 holds the one wire frame twice. -/
theorem feed_after_error_duplicates :
    let r1 := feedMOld ⟨[], []⟩ wire
    let r2 := feedMOld r1.2 []
    r1.1 = false ∧ r2.1 = false ∧ countFor r2.2 5 = 2 := by
  native_decide

/-- Shipped (compact before raising): the same trace leaves exactly one frame. -/
theorem feedM_trace_once :
    let r1 := feedM ⟨[], []⟩ wire
    let r2 := feedM r1.2 []
    r1.1 = false ∧ r2.1 = false ∧ countFor r2.2 5 = 1 := by
  native_decide

/-- Shipped, in general: once a feed raises, every later feed raises at once and
routes nothing, so no wire frame is ever routed twice. -/
theorem feedFixed_no_duplicates (s s' : St) (data : Flare.Bytes)
    (h : feedM s data = (false, s')) (ds : List Flare.Bytes) :
    (ds.foldl (fun st d => (feedM st d).2) s').routed = s'.routed := by
  induction ds generalizing s s' data with
  | nil => rfl
  | cons d ds ih =>
    simp only [List.foldl_cons]
    have h2 := feedM_error_stuck s s' data d h
    rw [h2]
    exact ih s' _ d h2

end Flare.Bugs.NET_04
