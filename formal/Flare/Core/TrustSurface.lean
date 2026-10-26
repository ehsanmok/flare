import Lean

/-!
# Trust surface of a theorem

A proof is checked, but its statement is only as good as the definitions it
mentions: to believe `T` a reader must read every `Flare.*` definition its
statement reaches. `#trust_surface T` lists them. It starts from the
statement (not the proof), follows definition bodies, structure fields and
constructor types transitively, and stops at Lean's core library, which is
trusted as a whole. Theorems the statement mentions contribute their
statements only.

`scripts/trust_surface.py` runs it over every theorem in the axiom audit.
-/
namespace Flare.TrustSurface
open Lean Elab Command Meta

/-- Every `Flare.*` constant reachable from `root`'s statement. -/
partial def collect (env : Environment) (root : Name) : Array Name := Id.run do
  -- internal names are followed too: a recursive definition's body lives in
  -- an auxiliary such as `f._f` or `f._unary`
  let inFlare (n : Name) := (`Flare).isPrefixOf n
  let mut seen : NameSet := {}
  let mut out : Array Name := #[]
  let mut todo : Array Name :=
    match env.find? root with
    | some ci => ci.type.getUsedConstants
    | none => #[]
  while h : 0 < todo.size do
    let n := todo.back
    todo := todo.pop
    if seen.contains n || !inFlare n then continue
    seen := seen.insert n
    let some ci := env.find? n | continue
    -- generated constants (recursors, constructors, projections,
    -- instances, matchers) are read with the declaration that produced
    -- them: follow them but do not list them
    let last := match n with | .str _ s => s | _ => ""
    let gen := isAuxRecursor env n || isNoConfusion env n || ci matches .ctorInfo _ || ci matches .recInfo _ ||
      (env.getProjectionFnInfo? n).isSome || last.startsWith "inst" ||
      last.startsWith "match_" || last.startsWith "proof_" || last == "ctorIdx" ||
      last.startsWith "_" || n.isInternalDetail
    if !gen then out := out.push n
    let deps := match ci with
      | .defnInfo d => d.type.getUsedConstants ++ d.value.getUsedConstants
      | .thmInfo t => t.type.getUsedConstants
      | .inductInfo i => i.type.getUsedConstants ++ i.ctors.toArray
      | .ctorInfo c => c.type.getUsedConstants
      | .opaqueInfo o => o.type.getUsedConstants ++ o.value.getUsedConstants
      | ci => ci.type.getUsedConstants
    todo := todo ++ deps
  return out.qsort (·.toString < ·.toString)

/-- `#trust_surface T`: print the `Flare.*` definitions `T`'s statement
depends on, one per line after a `trust surface of T (n):` header. -/
elab "#trust_surface " id:ident : command => do
  let n ← liftCoreM <| realizeGlobalConstNoOverloadWithInfo id
  let env ← getEnv
  let ns := collect env n
  let lines := ns.toList.map fun c => s!"  {c}"
  logInfo m!"trust surface of {n} ({ns.size}):\n{String.intercalate "\n" lines}"

end Flare.TrustSurface
