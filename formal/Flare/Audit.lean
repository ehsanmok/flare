import Flare
/-! Headline theorems whose axiom footprint `formal-check` audits.
Each layer appends `#print axioms <name>` lines below. Expected footprint:
`propext`, `Quot.sound`, `Classical.choice`; counterexamples in
`Flare.Bugs.*` may additionally show `Lean.ofReduceBool` (native_decide). -/

#print axioms Flare.Bytes.leNat_toLe
#print axioms Flare.LTS.Inductive.reachable
#print axioms Flare.Simulates.run
