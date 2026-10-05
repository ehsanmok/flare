import Flare.L2_Machine.UdpBatch

/-!
# NET-11: `BatchReceiver` data region size wraps; recvmmsg writes past it

Status: resolved. `BatchReceiver.__init__` now raises when an argument is not
positive or when `capacity * max_payload` / `capacity * 64` overflows `Int`;
`Flare.L2.UdpBatch.accepts` mirrors the shipped checks and the counterexample
below is about the pre-fix `acceptsOld`.

Pre-fix code: flare/udp/batch.mojo:176-206 @59bda50.

Spec: the data region covers every slot `[i*max_payload, (i+1)*max_payload)`,
`i < capacity`, that the iovecs hand to `recvmmsg` (`Covers`).

What goes wrong: the region is `_alloc_zeroed(capacity * max_payload)` with
a 64-bit `Int` product and only `capacity > 0 and max_payload > 0` checked.
For `capacity = 16, max_payload = 2^60` the product wraps to 0: a 0-byte
allocation, while iovec 0 still announces `2^60` bytes. On Linux the next
`recv` writes the datagram over whatever the allocator placed after it.
The arguments are caller-chosen (QUIC passes its configured
`max_udp_payload_size`), so this needs a misconfiguration, not a peer.
Severity low.

Repro: formal/repro/NET-11_batch_receiver_size_overflow.mojo.
-/
namespace Flare.Bugs.NET_11
open Flare.L2.UdpBatch

/-- **Counterexample** (pre-fix check): accepted arguments, wrapped size, slot 0
not covered. -/
theorem allocSize_wraps :
    acceptsOld 16 (2 ^ 60) ∧ allocSize 16 (2 ^ 60) = 0 ∧ ¬ Covers 16 (2 ^ 60) := by
  refine ⟨Flare.L2.UdpBatch.allocSize_wraps.1, Flare.L2.UdpBatch.allocSize_wraps.2, fun h => ?_⟩
  have := h 0 (by decide) (by decide)
  rw [Flare.L2.UdpBatch.allocSize_wraps.2] at this
  omega

/-- **Fix meets spec**: every argument pair the shipped constructor accepts
has an exact size that covers every slot; the counterexample is refused. -/
theorem covers_fixed (cap mp : Int) (h : accepts cap mp) :
    allocSize cap mp = cap * mp ∧ Covers cap mp :=
  ⟨allocSize_fixed cap mp h, Flare.L2.UdpBatch.covers_fixed cap mp h⟩

theorem wrap_refused : ¬ accepts 16 (2 ^ 60) := accepts_refuses_wrap

end Flare.Bugs.NET_11
