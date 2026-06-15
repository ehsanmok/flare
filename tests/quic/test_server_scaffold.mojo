"""Unit tests for the QUIC server reactor carriers
(``flare.quic.server`` -- Track Q3-W).

The reactor wiring landed in Track Q3-W commit 1/5 (UDP bind +
per-datagram dispatch); this suite covers the carrier shapes
that downstream tracks (H3 dispatch -- Q4-W, ALPN dispatcher
-- Q5-W) build against. The reactor-loop tests live in
``tests/quic/test_quic_reactor.mojo``.

Properties covered:

1. :class:`QuicServerConfig` defaults match the values documented
   in the design notebook (idle timeout, max UDP payload, flow
   control, CC choice).
2. :class:`QuicConnection` constructs cleanly with the existing
   sans-I/O :class:`flare.quic.state.Connection`.
3. :class:`ConnectionIdTable` registers / looks up / retires
   correctly across the small-slot + overflow path.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.quic import (
    ConnectionId,
    ConnectionIdTable,
    QuicAead,
    QuicConnection,
    QuicServerConfig,
)


def _make_cid(b: UInt8) -> ConnectionId:
    var bytes = List[UInt8]()
    bytes.append(b)
    bytes.append(b + UInt8(1))
    bytes.append(b + UInt8(2))
    bytes.append(b + UInt8(3))
    bytes.append(b + UInt8(4))
    bytes.append(b + UInt8(5))
    bytes.append(b + UInt8(6))
    bytes.append(b + UInt8(7))
    return ConnectionId(bytes^)


def test_config_defaults() raises:
    """``QuicServerConfig.__init__`` returns the values documented
    in the design notebook -- 30 s idle timeout, 1452 B MTU,
    1 MiB initial flow control, 100 bidi streams, 3 uni streams,
    AES-128-GCM by default."""
    var cfg = QuicServerConfig()
    assert_equal(cfg.host, String("0.0.0.0"))
    assert_equal(cfg.port, UInt16(0))
    assert_equal(cfg.aead_choice, QuicAead.AES_128_GCM)
    assert_equal(cfg.max_idle_timeout_ms, UInt64(30_000))
    assert_equal(cfg.max_udp_payload_size, UInt64(1452))
    assert_equal(cfg.initial_max_data, UInt64(1 << 20))
    assert_equal(cfg.initial_max_streams_bidi, UInt64(100))
    assert_equal(cfg.initial_max_streams_uni, UInt64(3))


def test_config_carries_overrides() raises:
    """Field-by-field assignment of overrides round-trips."""
    var cfg = QuicServerConfig()
    cfg.host = String("::")
    cfg.port = UInt16(4433)
    cfg.max_idle_timeout_ms = UInt64(5_000)
    assert_equal(cfg.host, String("::"))
    assert_equal(cfg.port, UInt16(4433))
    assert_equal(cfg.max_idle_timeout_ms, UInt64(5_000))


def test_quic_connection_starts_alive_in_handshake() raises:
    """A fresh :class:`QuicConnection` carries the underlying
    state machine in HANDSHAKE and reports ``alive = True``."""
    var local = _make_cid(UInt8(0x10))
    var peer = _make_cid(UInt8(0x20))
    var qc = QuicConnection(local, peer)
    assert_true(qc.alive)
    assert_false(qc.conn.handshake_complete)


def test_quic_connection_records_cids() raises:
    """Both local and peer CIDs round-trip through the carrier
    so the reactor can route inbound datagrams to the right
    connection and emit responses with the right SCID/DCID."""
    var local = _make_cid(UInt8(0x10))
    var peer = _make_cid(UInt8(0x20))
    var qc = QuicConnection(local, peer)
    assert_equal(len(qc.local_cid.bytes), 8)
    assert_equal(len(qc.peer_cid.bytes), 8)
    assert_equal(Int(qc.local_cid.bytes[0]), 0x10)
    assert_equal(Int(qc.peer_cid.bytes[0]), 0x20)


def test_cid_table_register_lookup_retire() raises:
    """Round-trip a CID through register / lookup / retire."""
    var table = ConnectionIdTable()
    table.register(String("aabbccdd"), 7)
    assert_equal(table.lookup(String("aabbccdd")), 7)
    assert_equal(len(table), 1)
    table.retire(String("aabbccdd"))
    assert_equal(table.lookup(String("aabbccdd")), -1)
    assert_equal(len(table), 0)


def test_cid_table_lookup_missing_returns_minus_one() raises:
    """Lookup of an unknown CID returns -1; the reactor uses
    -1 to gate the Initial-packet path (no slot -> potentially
    new connection)."""
    var table = ConnectionIdTable()
    assert_equal(table.lookup(String("ffffffff")), -1)


def test_cid_table_register_overwrites() raises:
    """Re-registering the same CID with a different slot is
    allowed and overwrites; the server may reissue CIDs after
    migration (RFC 9000 §9)."""
    var table = ConnectionIdTable()
    table.register(String("11223344"), 1)
    table.register(String("11223344"), 5)
    assert_equal(table.lookup(String("11223344")), 5)
    assert_equal(len(table), 1)


def main() raises:
    test_config_defaults()
    test_config_carries_overrides()
    test_quic_connection_starts_alive_in_handshake()
    test_quic_connection_records_cids()
    test_cid_table_register_lookup_retire()
    test_cid_table_lookup_missing_returns_minus_one()
    test_cid_table_register_overwrites()
    print("test_quic_server_scaffold: 7 passed")
