import Flare.L3_Protocol.Qpack.FieldSection

/-!
# QPACK-04: invalid encoder-stream reference stalls instead of erroring

flare/qpack/dynamic.mojo:319 and :337 @59bda50 compute
`insert_count() - 1 - ip` in UInt64; for `ip ≥ insert_count` it wraps and
`get_abs` raises an error whose text lacks `QPACK_ENCODER_STREAM_ERROR`.
`apply_encoder_instructions_partial` (dynamic.mojo:281-297) treats every
untagged error as a truncated instruction: it stops and returns the
instruction start, so the bad instruction stays in the caller's carry
buffer and is retried forever. RFC 9204 §4.3.2/§4.3.4 require
QPACK_ENCODER_STREAM_ERROR. (http3/server.mojo:1139 eventually errors once
the carry exceeds capacity + 64 bytes, but a short bad instruction followed
by silence just stalls.)

Status: resolved. `_relative_to_abs` (dynamic.mojo) checks the relative index
against the live entries before subtracting and raises a tagged
QPACK_ENCODER_STREAM_ERROR; `apply_encoder_instructions_partial` re-raises it
(truncated instructions still wait). `implOldDynRef` is the pre-fix behaviour
(the counterexamples are about it); `implDynRef` is the shipped one
(`fixed_meets_spec`). Regression tests: tests/qpack/test_qpack_dynamic.mojo
`test_name_ref_into_an_empty_table_is_an_encoder_stream_error` and three
siblings, tests/h3/test_h3_qpack_dynamic.mojo
`test_bad_name_reference_on_the_encoder_stream_is_a_stream_error`.
-/
namespace Flare.Bugs.QPACK_04
open Flare.L3.Qpack.FieldSection

/-- Empty table, Insert With Name Reference (dynamic, relative index 0). -/
theorem counterexample : implOldDynRef 0 0 0 = .stall := by decide

theorem spec_errors : specDynRef 0 0 0 = .streamError := by decide

/-- Evicted entry: table with one live entry at abs 5 (dropped 5, ic 6),
relative index 1 names abs 4, evicted. -/
theorem counterexample_evicted : implOldDynRef 5 6 1 = .stall := by decide

theorem spec_errors_evicted : specDynRef 5 6 1 = .streamError := by decide

theorem fixed_meets_spec (dropped ic ip : UInt64) (hd : dropped ≤ ic) :
    implDynRef dropped ic ip = specDynRef dropped.toNat ic.toNat ip.toNat :=
  implDynRef_eq_spec dropped ic ip hd

end Flare.Bugs.QPACK_04
