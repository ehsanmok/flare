"""The server validates the client's transport parameters (QUIC-11).

RFC 9000 §18.2: a server MUST treat a server-only parameter
(original_destination_connection_id, stateless_reset_token,
preferred_address, retry_source_connection_id) as TRANSPORT_PARAMETER_ERROR.
§7.3: initial_source_connection_id must be present and equal the Source
Connection ID of the client's Initial. §7.4 / §18: duplicates and invalid
values are errors too.

The unit tests drive :func:`check_client_transport_params` with crafted
blobs; the loopback test runs a real rustls client against a real
:class:`QuicListener` and checks that the server drops the connection
for invalid blobs and keeps it for a valid one.
"""

from std.collections import List, Optional
from std.collections.span import Span
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from flare.net.address import IpAddr, SocketAddr
from flare.udp import UdpSocket
from flare.quic.client import QuicClientConnection, _random_cid
from flare.quic.crypto import QuicAead
from flare.quic.packet import ConnectionId
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import new_connection
from flare.quic.transport_params import (
    check_client_transport_params,
    empty_transport_parameters,
    encode_transport_parameters,
    transport_parameter_present,
)
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _cid8(seed: Int) -> List[UInt8]:
    var b = List[UInt8]()
    for i in range(8):
        b.append(UInt8(seed + i))
    return b^


def _base(scid: List[UInt8], with_scid: Bool) raises -> List[UInt8]:
    var tp = empty_transport_parameters()
    if with_scid:
        tp.initial_source_connection_id = scid.copy()
    tp.max_idle_timeout = Optional(UInt64(30_000))
    tp.initial_max_data = Optional(UInt64(1 << 20))
    tp.initial_max_stream_data_bidi_local = Optional(UInt64(1 << 20))
    tp.initial_max_stream_data_bidi_remote = Optional(UInt64(1 << 20))
    tp.initial_max_stream_data_uni = Optional(UInt64(1 << 20))
    tp.initial_max_streams_bidi = Optional(UInt64(16))
    tp.initial_max_streams_uni = Optional(UInt64(16))
    return encode_transport_parameters(tp)


def _append(mut out: List[UInt8], id: UInt8, value: List[UInt8]):
    out.append(id)
    out.append(UInt8(len(value)))
    for i in range(len(value)):
        out.append(value[i])


def _filled(n: Int, v: UInt8) -> List[UInt8]:
    var out = List[UInt8]()
    for _ in range(n):
        out.append(v)
    return out^


def _blob(variant: Int, scid: List[UInt8]) raises -> List[UInt8]:
    """0..5: the invalid blobs of the repro, 6: a valid one, 7: an
    initial_source_connection_id of zero length for a zero-length SCID,
    8: preferred_address, 9: retry_source_connection_id."""
    if variant == 2:
        return _base(scid, False)  # initial_source_connection_id absent
    var out = _base(scid, variant != 3)
    if variant == 0:  # server-only original_destination_connection_id
        _append(out, 0x00, _filled(8, 0x11))
    elif variant == 1:  # server-only stateless_reset_token
        _append(out, 0x02, _filled(16, 0x22))
    elif variant == 3:  # initial_source_connection_id != Initial SCID
        _append(out, 0x0F, _filled(8, 0x33))
    elif variant == 4:  # duplicate id (initial_max_streams_bidi twice)
        _append(out, 0x08, _filled(1, 0x10))
    elif variant == 5:  # max_udp_payload_size = 1000 < 1200
        var v = List[UInt8]()
        v.append(0x43)
        v.append(0xE8)
        _append(out, 0x03, v)
    elif variant == 8:  # server-only preferred_address (any length)
        _append(out, 0x0D, _filled(41, 0x00))
    elif variant == 9:  # server-only retry_source_connection_id
        _append(out, 0x10, _filled(8, 0x44))
    return out^


def _rejects(variant: Int) raises -> Bool:
    var scid = _cid8(0x50)
    var blob = _blob(variant, scid)
    try:
        check_client_transport_params(Span[UInt8, _](blob), scid)
    except e:
        assert_true("TRANSPORT_PARAMETER_ERROR" in String(e))
        return True
    return False


def test_valid_client_params_pass() raises:
    assert_false(_rejects(6), "a valid client blob was rejected")


def test_server_only_parameters_rejected() raises:
    assert_true(_rejects(0), "original_destination_connection_id accepted")
    assert_true(_rejects(1), "stateless_reset_token accepted")
    assert_true(_rejects(8), "preferred_address accepted")
    assert_true(_rejects(9), "retry_source_connection_id accepted")


def test_initial_source_connection_id_enforced() raises:
    assert_true(_rejects(2), "absent initial_source_connection_id accepted")
    assert_true(_rejects(3), "mismatched initial_source_connection_id accepted")


def test_invalid_values_and_duplicates_rejected() raises:
    assert_true(_rejects(4), "duplicate parameter accepted")
    assert_true(_rejects(5), "max_udp_payload_size < 1200 accepted")
    var junk = List[UInt8]()
    junk.append(0x08)  # id, then the length varint is missing
    var raised = False
    try:
        check_client_transport_params(Span[UInt8, _](junk), _cid8(1))
    except:
        raised = True
    assert_true(raised, "truncated blob accepted")


def test_zero_length_scid_needs_a_present_empty_iscid() raises:
    """A zero-length Initial SCID is legal, but initial_source_connection_id
    must still be present (with length 0): absent is not the same as empty."""
    var empty = List[UInt8]()
    var present = _base(empty, True)
    _append(present, 0x0F, empty)
    var raised = False
    try:
        check_client_transport_params(Span[UInt8, _](present), empty)
    except:
        raised = True
    assert_false(raised, "present, empty initial_source_connection_id rejected")
    var absent = _base(empty, False)
    raised = False
    try:
        check_client_transport_params(Span[UInt8, _](absent), empty)
    except:
        raised = True
    assert_true(raised, "absent initial_source_connection_id accepted")


def test_parameter_presence_scan() raises:
    var scid = _cid8(7)
    var blob = _base(scid, True)
    assert_true(transport_parameter_present(Span[UInt8, _](blob), 0x0F))
    assert_false(transport_parameter_present(Span[UInt8, _](blob), 0x00))
    var absent = _base(scid, False)
    assert_false(transport_parameter_present(Span[UInt8, _](absent), 0x0F))
    var trailing = _base(scid, True)
    trailing.append(0x08)
    assert_false(
        transport_parameter_present(Span[UInt8, _](trailing), 0x0F),
        "a malformed list reports nothing present",
    )


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _bind_server() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg^)


def _server_keeps_connection(variant: Int) raises -> Bool:
    var server = _bind_server()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var initial_dcid = _random_cid(8)
    var scid = _random_cid(8)
    var tp = _blob(variant, scid.bytes)
    var session = connector.connect(String("localhost"), tp)
    var sock = UdpSocket.bind(SocketAddr(IpAddr.parse("0.0.0.0"), UInt16(0)))
    var conn = new_connection(UInt64(30_000_000), UInt64(1 << 20))
    var client = QuicClientConnection(
        conn^,
        session^,
        sock^,
        server.local_addr(),
        initial_dcid^,
        scid^,
        QuicAead.AES_128_GCM,
        1452,
    )
    client._send_first_initial()
    for _ in range(40):
        try:
            _ = server.tick(timeout_ms=50)
            _ = client.poll(timeout_ms=50)
        except:
            pass
        if client.is_established():
            break
    var alive = False
    for i in range(len(server.connections)):
        if not server.slot_free[i] and server.connections[i].alive:
            alive = True
    server.close()
    return alive


def test_loopback_server_drops_invalid_client_params() raises:
    assert_true(
        _server_keeps_connection(6),
        "a valid client blob did not keep the connection",
    )
    assert_false(
        _server_keeps_connection(0),
        (
            "server kept a connection whose client sent"
            " original_destination_connection_id"
        ),
    )
    assert_false(
        _server_keeps_connection(2),
        (
            "server kept a connection whose client sent no"
            " initial_source_connection_id"
        ),
    )
    assert_false(
        _server_keeps_connection(3),
        "server kept a connection with a wrong initial_source_connection_id",
    )


def main() raises:
    test_valid_client_params_pass()
    test_server_only_parameters_rejected()
    test_initial_source_connection_id_enforced()
    test_invalid_values_and_duplicates_rejected()
    test_zero_length_scid_needs_a_present_empty_iscid()
    test_parameter_presence_scan()
    test_loopback_server_drops_invalid_client_params()
    print("test_quic_server_peer_params: 7 passed")
