"""Server connection-ID lifecycle (RFC 9000 sec 5.1).

Every CID the server issued must stop routing once its slot is
reclaimed (the sequence-1 CID used to stay mapped to the reused slot),
a RETIRE_CONNECTION_ID unroutes that CID and is answered with a fresh
one, and retiring a CID never issued is a PROTOCOL_VIOLATION.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.quic.client import QuicClientConnection
from flare.quic.frame import (
    RetireConnectionIdFrame,
    encode_retire_connection_id,
)
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _established(
    mut server: QuicListener,
) raises -> QuicClientConnection:
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
        if client.is_established() and server.handshake_done_sent[0]:
            break
    assert_true(client.is_established())
    return client^


def _server() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg^)


def _retire(mut client: QuicClientConnection, seq: UInt64) raises:
    var frame = List[UInt8]()
    encode_retire_connection_id(RetireConnectionIdFrame(seq), frame)
    client._send_padded_1rtt(frame^, ack_eliciting=True)


def test_reclaimed_slot_unroutes_every_issued_cid() raises:
    var server = _server()
    var client = _established(server)
    assert_equal(len(server.connections[0].issued_cids), 2)
    server._reclaim_slot(0)
    assert_equal(len(server.cid_table), 0, "a CID still routes to the slot")
    server.close()
    client.close()


def test_retired_cid_is_unrouted_and_replaced() raises:
    var server = _server()
    var client = _established(server)
    var old_key = server.connections[0].issued_cids[UInt64(1)]
    _retire(client, UInt64(1))
    for _ in range(5):
        _ = server.tick(timeout_ms=20)
    assert_false(UInt64(1) in server.connections[0].issued_cids)
    assert_equal(server.cid_table.lookup(old_key), -1)
    assert_equal(server.next_local_cid_seq[0], UInt64(3), "seq 2 issued")
    assert_true(UInt64(2) in server.connections[0].issued_cids)
    server.close()
    client.close()


def test_retiring_a_cid_never_issued_closes() raises:
    var server = _server()
    var client = _established(server)
    _retire(client, UInt64(9))
    for _ in range(5):
        _ = server.tick(timeout_ms=20)
    assert_false(server.connections[0].alive, "PROTOCOL_VIOLATION closes")
    server.close()
    client.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
