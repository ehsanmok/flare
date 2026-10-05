import Flare.L4_App.ServerConfig

/-!
# APP-06: `max_header_size + max_body_size` wraps, so a config `check` accepts rejects every request with 413

flare/http/_reactor/conn_handle.mojo:448-453 @59bda50 (also 492-497 and
536-541): `len(self.read_buf) > config.max_header_size + config.max_body_size`
in Mojo `Int` (64-bit, wrapping). `ServerConfig.check`
(flare/http/_server/config.mojo:251-329) only requires
`max_body_size >= max_header_size > 0`, so `max_body_size = Int.MAX` (an
"unlimited" body cap) passes, the sum wraps to a negative number and every
non-empty read buffer is "too large".

Spec: a buffer that is at most `max_header_size + max_body_size` bytes (on
mathematical integers) is not over the cap
(`Flare.L4.ServerConfig.overCapSpec`).

Status: resolved. The three read-buffer cap checks (and the legacy
`_parse_http_request`) compare `len - max_header_size > max_body_size`, so
the sum is never formed. The model `overCapImpl` is the shipped test,
`overCapOld` the pre-fix one. Regression tests:
`tests/http/test_server_reactor_state.mojo::test_unlimited_body_cap_serves_request`,
`::test_unlimited_body_cap_bufring_path` and
`::test_body_cap_still_rejects_oversized_input`.
-/
namespace Flare.Bugs.APP_06

open Flare.L4.ServerConfig

def intMax : Int64 := 9223372036854775807

/-- `check` accepts the default config with `max_body_size = Int.MAX`. -/
theorem check_accepts : check { default with maxBodySize := intMax.toInt } := by
  decide

/-- Counterexample (pre-fix): one buffered byte is over the cap as computed, but not
under the spec. -/
theorem overflow_cap_rejects_one_byte :
    overCapOld 1 8192 intMax = true ∧ overCapSpec 1 8192 intMax.toInt = false := by
  decide

/-- `¬ spec (impl x)` for the pre-fix test. -/
theorem violates_spec : overCapOld 1 8192 intMax ≠ overCapSpec 1 8192 intMax.toInt := by
  rw [overflow_cap_rejects_one_byte.1, overflow_cap_rejects_one_byte.2]; decide

/-- The shipped test (`len - max_header_size > max_body_size`) equals the spec for every
non-negative length and header cap and every body cap. -/
theorem capFixed_spec (len maxH maxB : Int64) (hl : 0 ≤ len.toInt) (hh : 0 ≤ maxH.toInt) :
    overCapImpl len maxH maxB = overCapSpec len.toInt maxH.toInt maxB.toInt :=
  overCapImpl_eq_spec len maxH maxB hl hh

end Flare.Bugs.APP_06
