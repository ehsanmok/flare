import Flare.L4_App.ConnExt

/-!
# APP-48: a WebSocket upgrade on a TLS connection is served in cleartext

flare/http/_reactor/conn_handle.mojo:838-875 @59bda50 (pre-fix): the
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

Status: resolved. `on_readable` now evaluates `config.ws.handler and not
self.tls` (the version-mismatch 426 included), so a handshake on TLS falls
through to the HTTP handler. Regression test:
tests/http/test_server_ws_upgrade.mojo::test_ws_handshake_on_tls_is_never_upgraded_in_cleartext.
The counterexample below is about the pre-fix `wireOld`.
-/
namespace Flare.Bugs.APP_48
open Flare.L4.ConnExt.Ws

theorem violates_spec : wireOld true true true = .cleartext ∧ ¬ Spec wireOld := old_violates

/-- **Fix meets spec**: the shipped branch (guarded by `not self.tls`) keeps
every TLS connection inside TLS and leaves cleartext connections unchanged
from the pre-fix behaviour. -/
theorem fixed_meets_spec :
    Spec wire ∧ ∀ ws isWs, upgradeTaken ws false isWs = upgradeTakenOld ws false isWs :=
  ⟨spec, cleartext_same⟩

end Flare.Bugs.APP_48
