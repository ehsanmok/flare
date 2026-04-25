"""Example 26 — Mutual TLS (mTLS) with client certificate
verification (v0.5.0 Step 3 / Track 5.4).

Mutual TLS pins the client's identity on top of the server's:
the server presents its cert (the standard TLS pattern), AND
the client presents a cert that the server validates against a
trust anchor. Used in service-mesh / zero-trust deployments
where both sides need to prove who they are.

flare's mTLS opt-in is two ``TlsServerConfig`` flags:
``require_client_cert=True`` and ``client_ca_bundle="…"``. The
config validates the combination at construction time —
``require_client_cert=True`` without a ``client_ca_bundle``
raises (mTLS without trust anchors is meaningless; the verify
callback would have nothing to check against).

The handshake selection callback that pulls the verified client
cert subject onto ``Request.tls_info.client_cert_subject``
lands with the reactor follow-up; this example demonstrates the
config shape and the validation behaviour that ships today.

Run:
    pixi run example-mtls
"""

from flare.tls import TlsAcceptor, TlsServerConfig


def main() raises:
    print("=" * 60)
    print("flare example 26 — mutual TLS (mTLS)")
    print("=" * 60)
    print()

    # 1. mTLS-enabled config: require client cert, point to the
    #    trust-anchor bundle. ALPN is independent of mTLS.
    # Uses the bench-tls-setup self-signed cert (which doubles
    # as its own CA) so the example runs end-to-end.
    var alpn = List[String]()
    alpn.append("http/1.1")
    var cert_path = (
        "/Users/ehsan/workspace/flare/build/tls-bench-certs/server.pem"
    )
    var key_path = (
        "/Users/ehsan/workspace/flare/build/tls-bench-certs/server.key"
    )
    var cfg = TlsServerConfig(
        cert_file=cert_path,
        key_file=key_path,
        alpn=alpn^,
        require_client_cert=True,
        client_ca_bundle=cert_path,
    )
    var acceptor = TlsAcceptor(cfg^)
    print("[1] mTLS acceptor configured")
    print("    cert     :", acceptor.config.cert_file)
    print("    key      :", acceptor.config.key_file)
    print("    require  :", acceptor.config.require_client_cert)
    print("    client CA:", acceptor.config.client_ca_bundle)
    print()

    # 2. Misconfiguration: require_client_cert without
    #    client_ca_bundle is rejected at construction time. flare
    #    refuses to silently disable verification.
    print("[2] Demonstrating the rejected misconfiguration:")
    try:
        _ = TlsServerConfig(
            cert_file="/c.pem",
            key_file="/k.pem",
            require_client_cert=True,
            # client_ca_bundle defaults to "".
        )
        print("    ERROR: expected raise, got success!")
    except e:
        print("    rejected as expected:")
        print("    ", String(e))
    print()

    # 3. Per-request access to the client cert subject (deferred
    #    until reactor follow-up):
    print("[3] Per-request access to the client cert subject")
    print("    (lands with the reactor handshake follow-up):")
    print()
    print("    def handler(req: Request) raises -> Response:")
    print("        if req.tls_info:")
    print("            var info = req.tls_info.value()")
    print("            print('client subject:', info.client_cert_subject)")
    print("        return ok('hello')")
    print()

    print("=== Example 26 complete ===")
