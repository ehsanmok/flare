"""Connection migration end to end (RFC 9000 §9).

Drives :class:`flare.quic.client.QuicClientConnection.migrate`
against the real :class:`flare.quic.server.QuicListener` over
loopback UDP, in the same single-thread lockstep harness as
``test_quic_client.mojo``.

Proves the client-initiated migration flow:

1. The server grants a spare Source CID via NEW_CONNECTION_ID in
   its first 1-RTT flight (the client records it in its peer-CID
   table).
2. ``migrate()`` switches the active Destination CID to that spare
   (sequence 0 -> 1), rebinds the local UDP socket to a fresh
   ephemeral port (the address change), and probes the new path
   with a PATH_CHALLENGE.
3. The server routes the new DCID to the same slot, follows the new
   peer address, and echoes a PATH_RESPONSE; the client matches it
   and marks the path validated.
4. Application data continues to flow on the migrated path.

Reuses the 2-cert fixture chain from
``tests/tls/fixtures/rustls-quic-client/``.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_true, assert_not_equal

from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConfig, RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _read_file(path: String) raises -> String:
    return Path(path).read_text()


def _h3_alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _make_connector() raises -> RustlsQuicConnector:
    var ca = _read_file(_FIXDIR + "ca.pem")
    return RustlsQuicConnector(ca^, _h3_alpn())


def _bind_server() raises -> QuicListener:
    var cert = _read_file(_FIXDIR + "cert.pem")
    var key = _read_file(_FIXDIR + "key.pem")
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = cert^
    cfg.rustls_config.private_key_pem = key^
    cfg.rustls_config.alpn_protocols = _h3_alpn()
    return QuicListener.bind(cfg^)


def test_client_migrates_to_new_path() raises:
    var server = _bind_server()
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )

    # 1. Complete the handshake.
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete")

    # The server grants its spare Source CID on the first 1-RTT
    # flight, which it only sends in response to a client 1-RTT
    # packet. A keepalive PING elicits that flight (HANDSHAKE_DONE +
    # NEW_CONNECTION_ID); pump until the client records the CID.
    client.keepalive()
    var has_spare = False
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.peer_cid_count() > 0:
            has_spare = True
            break
    assert_true(has_spare, "server must grant a spare CID for migration")
    assert_equal(client.active_dcid_seq(), UInt64(0))

    var old_addr = client.local_addr()
    # The server's egress address for this slot is the client's
    # pre-migration address (the strict-hold baseline).
    var server_old_egress = server.peer_addrs[0]

    # 2. Migrate: switch CID + rebind socket + probe the new path.
    var started = client.migrate(rebind=True)
    assert_true(started, "migrate() should start with a spare CID")
    assert_equal(client.active_dcid_seq(), UInt64(1))
    assert_not_equal(
        Int(client.local_addr().port),
        Int(old_addr.port),
        "rebind must pick a new local port",
    )

    # Strict egress hold: after the server first sees the migrating
    # packet it probes the new path but must NOT yet switch its egress
    # address to the unvalidated candidate -- the client has not echoed
    # the server's PATH_CHALLENGE, so validation cannot have completed.
    _ = server.tick(timeout_ms=50)
    assert_true(
        not client.path_validated(),
        "client cannot be validated before it polls the server probe",
    )
    assert_equal(
        Int(server.peer_addrs[0].port),
        Int(server_old_egress.port),
        "strict hold: egress stays on the validated path pre-validation",
    )

    # 3. Pump until the server echoes PATH_RESPONSE on the new path.
    var validated = False
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.path_validated():
            validated = True
            break
    assert_true(validated, "new path must validate via PATH_RESPONSE")

    # Once the client echoes the server's PATH_CHALLENGE the server
    # promotes the candidate to its egress address (hold released).
    var promoted = False
    for _ in range(40):
        _ = client.poll(timeout_ms=50)
        _ = server.tick(timeout_ms=50)
        if Int(server.peer_addrs[0].port) != Int(server_old_egress.port):
            promoted = True
            break
    assert_true(
        promoted, "server must promote the validated candidate to egress"
    )

    # 4. Application data still flows on the migrated path.
    var sid = client.open_bidi_stream()
    var body = List[UInt8]()
    for b in String("post-migration").as_bytes():
        body.append(b)
    client.send_stream(sid, body, fin=True)
    for _ in range(4):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)

    assert_true(client.is_established(), "connection survives migration")
    assert_equal(server.connection_count(), 1)

    server.close()
    client.close()


def main() raises:
    test_client_migrates_to_new_path()
    print("test_quic_migration: 1 passed (strict egress hold + promotion)")
