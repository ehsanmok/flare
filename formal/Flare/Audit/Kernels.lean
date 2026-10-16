import Flare.Kernels
/-! Verified kernels (formal/obligations/): axiom footprint of the headline
theorems. Expected: `propext`, `Quot.sound`, `Classical.choice` or none. -/

-- Buffer-ring receive ledger (issue #37)
#print axioms Flare.Kernels.BufLedger.classify_ok
#print axioms Flare.Kernels.BufLedger.run_conserved
#print axioms Flare.Kernels.BufLedger.run_inRing_le
#print axioms Flare.Kernels.BufLedger.run_drained
