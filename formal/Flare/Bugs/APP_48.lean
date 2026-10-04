import Flare.L4_App.ConnExt

/-!
# APP-48: a WebSocket upgrade on a TLS connection is served in cleartext

flare/http/_reactor/conn_handle.mojo:838-875 @59bda50: the
`config.ws.handler` branch of `on_readable` calls `_handle_ws_upgrade`
without checking `self.tls` (the h2c branch at :881 does check it).
`_handle_ws_upgrade` (:1476-1574) detaches the raw fd and writes the 101
and every frame with a plain `TcpStream`.

Spec clause: flare's own contract (server.mojo:813-814,
conn_handle.mojo:1506-1508), "Cleartext only: a wss:// connection is
terminated by the TLS connection handler, which has no upgrade seam"; and
RFC 6455 §4.1 / RFC 8446: a connection opened over TLS stays inside TLS.

Counterexample: TLS connection, WebSocket handler configured, valid
handshake: the response goes out in cleartext.

Repro: formal/repro/APP-48_ws_upgrade_over_tls_sends_cleartext.mojo.
-/
namespace Flare.Bugs.APP_48
open Flare.L4.ConnExt.Ws

theorem violates_spec : wire false true true true = .cleartext ∧ ¬ Spec false := impl_violates

/-- **Fix meets spec**: guarding the branch with `not self.tls` keeps every
TLS connection inside TLS and leaves cleartext connections unchanged. -/
theorem fixed_meets_spec :
    Spec true ∧ ∀ ws isWs, upgradeTaken true ws false isWs = upgradeTaken false ws false isWs :=
  ⟨fixed_spec, fixed_cleartext_same⟩

end Flare.Bugs.APP_48
