import Flare.L4_App.ConnExt

/-!
# APP-47: an h2c upgrade whose 101 flushes on a writable edge never migrates

flare/http/_unified_reactor_impl.mojo:812-855 @59bda50 routes a writable
edge on a `KIND_H1` connection to `_drive_h1_writable` (:243-258), which
ignores the `h2c_upgrade` cue that `on_writable` reports once the 101 has
flushed (flare/http/_reactor/conn_handle.mojo:1353-1362); only `_drive_h1`
(:174-215) migrates.

Spec clause: RFC 7540 §3.2, after the 101 the server's first bytes are its
HTTP/2 connection preface, and the upgrade request is answered on stream 1.

Counterexample: the 101 is queued behind a full send buffer; every
writable edge after that leaves the connection `KIND_H1`, write-armed and
re-reporting the upgrade, so it spins and never sends SETTINGS.

Repro: formal/repro/APP-47_h2c_upgrade_lost_on_writable_edge.mojo.
-/
namespace Flare.Bugs.APP_47
open Flare.L4.ConnExt.H2c

/-- **Counterexample**: for every backlog and every number of writable
edges, flare is still HTTP/1.1 and still armed for writing. -/
theorem violates_spec :
    (∀ q n, 0 < n → run false n (blocked q) = ⟨.h1, true, 0, true⟩) ∧ ¬ Spec false :=
  ⟨impl_spins, impl_violates⟩

/-- **Fix meets spec**: routing the edge to `_drive_h1` while an upgrade
is pending migrates on the first writable edge. -/
theorem fixed_meets_spec : Spec true := fixed_spec

end Flare.Bugs.APP_47
