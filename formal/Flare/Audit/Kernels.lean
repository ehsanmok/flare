import Flare.Kernels
/-! Verified kernels (formal/obligations/): axiom footprint of the headline
theorems. Expected: `propext`, `Quot.sound`, `Classical.choice` or none. -/

-- Buffer-ring receive ledger (issue #37)
#print axioms Flare.Kernels.BufLedger.classify_ok
#print axioms Flare.Kernels.BufLedger.run_conserved
#print axioms Flare.Kernels.BufLedger.run_inRing_le
#print axioms Flare.Kernels.BufLedger.run_drained

-- NUL-terminated strings across the FFI boundary (issue #42)
#print axioms Flare.Kernels.CStr.cRead_append_nul
#print axioms Flare.Kernels.CStr.cRead_prefix
#print axioms Flare.Kernels.CStr.verdict_ok
#print axioms Flare.Kernels.CStr.pass_exact
#print axioms Flare.Kernels.CStr.pass_complete
