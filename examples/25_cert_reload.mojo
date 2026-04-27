"""Example 25 — TLS certificate reload without restart
(v0.5.0 Step 3 / Track 5.3).

Production TLS deployments rotate certificates on a regular
cadence (Let's Encrypt: 60-90 days; internal PKI: weeks). The
naive "kill the server, start with new certs" approach drops
in-flight connections — every multi-server deployment needs
some form of zero-downtime cert reload.

flare's ``TlsAcceptor.reload()`` re-reads the cert + key files
from disk without restarting the acceptor. In-flight handshakes
complete with the previous cert; new connections pick up the
new one.

This example demonstrates the trigger pattern. Once the
reactor-side handshake state machine lands, the same pattern
runs against live traffic. Until then, ``reload()`` is a no-op
(the public method exists so deployments can wire SIGHUP /
inotify / file-watcher / cron triggers today).

Trigger options:

1. **SIGHUP signal**: ``trap 'kill -HUP <pid>' SIGHUP``. The
   server's signal handler calls ``acceptor.reload()``. Most
   classic deployments (nginx-style). Requires the SIGHUP
   helper that lands alongside the SIGTERM helper (both
   blocked on Mojo's "global variables not supported" issue).

2. **inotify / kqueue file watcher**: watch the cert file's
   mtime; on change, call ``reload()``. Self-driving — no
   external trigger needed.

3. **cron-like manual call**: a thread that wakes every N
   minutes and calls ``reload()`` regardless of file change.
   Cheap on the no-change path (file open + read).

Run:
    pixi run example-cert-reload
"""

from flare.tls import TlsAcceptor, TlsServerConfig


def main() raises:
    print("=" * 60)
    print("flare example 25 — TLS certificate reload")
    print("=" * 60)
    print()

    # 1. Construct an acceptor with the initial cert / key.
    # We use the bench-tls-setup self-signed cert so the example
    # runs end-to-end without needing a real Let's Encrypt cert
    # in the repo. In production, point at your fullchain /
    # privkey paths.
    var alpn = List[String]()
    alpn.append("h2")
    alpn.append("http/1.1")
    var cert_path = String("build/tls-bench-certs/server.pem")
    var key_path = String("build/tls-bench-certs/server.key")
    var cfg = TlsServerConfig(
        cert_file=cert_path, key_file=key_path, alpn=alpn^
    )
    var acceptor = TlsAcceptor(cfg^)
    print("[1] Acceptor created against", acceptor.config.cert_file)

    # 2. Trigger a reload. In production this fires on a SIGHUP
    #    signal handler, an inotify watch, or a cron-like timer.
    #    Until the reactor follow-up, reload() is a no-op — but
    #    deployments can wire the trigger today and the wiring
    #    flips on without code changes when the implementation
    #    lands.
    print("[2] Triggering reload — reads cert + key from disk again")
    acceptor.reload()
    print("    reload() returned cleanly (no-op until reactor follow-up)")

    # 3. Show the SIGHUP-shaped trigger pattern handlers will
    #    use once the SIGHUP helper lands. Pseudo-code today.
    print()
    print("[3] Production trigger pattern (pseudo-code, deferred):")
    print("    install_sighup_handler(lambda: acceptor.reload())")
    print("    # ... server runs forever ...")
    print()
    print(
        "    The SIGHUP helper is blocked on Mojo's 'global"
        " variables not supported'"
    )
    print(
        "    diagnostic, the same gap that blocks the SIGTERM drain helper from"
    )
    print("    Step 1. Both lift together once Mojo unblocks globals.")
    print()

    print("=== Example 25 complete ===")
