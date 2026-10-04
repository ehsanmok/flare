# PLATFORM: any (loopback UDP; needs the rustls QUIC shim and the
# fixtures in tests/tls/fixtures/rustls-quic-client/)
"""QUIC-11: the server never decodes or validates the client's transport
parameters.

Lean: Flare.Bugs.QUIC_11.impl_accepts (impl),
      Flare.Bugs.QUIC_11.serverCheck_spec (fix).
flare/quic/server.mojo:1199-1368 @59bda50 (`_dispatch_crypto_frames`): the
handshake is driven to 1-RTT keys and the connection becomes usable, but the
client's `quic_transport_parameters` are never read
(`_do_peer_transport_params` is not called anywhere on the server side).

RFC 9000 §18.2: a server MUST treat receipt of a server-only parameter
(original_destination_connection_id, stateless_reset_token,
preferred_address, retry_source_connection_id) as TRANSPORT_PARAMETER_ERROR;
§7.4 / §18: duplicates and invalid values are TRANSPORT_PARAMETER_ERROR;
§7.3: an absent initial_source_connection_id is TRANSPORT_PARAMETER_ERROR
and a value that differs from the Source CID of the client's Initial is
TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION.

Expected: for each of the six client parameter blobs below the server
closes the connection (a seventh, valid blob is the control and must
establish). Actual: every handshake completes and the server
keeps the connection alive.

Minimal fix: once the 1-RTT keys are installed, read the peer parameters,
decode them (duplicates / values), reject server-only ids, and require
initial_source_connection_id to be present and equal to the connection's
peer CID; otherwise close with TRANSPORT_PARAMETER_ERROR (0x08).
"""

from std.collections import List, Optional
from std.collections.span import Span
from std.pathlib import Path

from flare.net.address import IpAddr, SocketAddr
from flare.udp import UdpSocket
from flare.quic.client import QuicClientConnection, _random_cid
from flare.quic.crypto import QuicAead
from flare.quic.packet import ConnectionId
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import new_connection
from flare.quic.transport_params import (
    empty_transport_parameters,
    encode_transport_parameters,
)
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


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


def _base(scid: ConnectionId, with_scid: Bool) raises -> List[UInt8]:
    var tp = empty_transport_parameters()
    if with_scid:
        tp.initial_source_connection_id = scid.bytes.copy()
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


def _blob(variant: Int, scid: ConnectionId) raises -> List[UInt8]:
    if variant == 2:
        return _base(scid, False)  # initial_source_connection_id absent
    var out = _base(scid, variant != 3)
    if variant == 0:  # server-only original_destination_connection_id
        var v = List[UInt8]()
        for _ in range(8):
            v.append(0x11)
        _append(out, 0x00, v)
    elif variant == 1:  # server-only stateless_reset_token
        var v = List[UInt8]()
        for _ in range(16):
            v.append(0x22)
        _append(out, 0x02, v)
    elif variant == 3:  # initial_source_connection_id != Initial SCID
        var v = List[UInt8]()
        for _ in range(8):
            v.append(0x33)
        _append(out, 0x0F, v)
    elif variant == 4:  # duplicate id (initial_max_streams_bidi twice)
        var v = List[UInt8]()
        v.append(0x10)
        _append(out, 0x08, v)
    elif variant == 5:  # max_udp_payload_size = 1000 < 1200
        var v = List[UInt8]()
        v.append(0x43)
        v.append(0xE8)
        _append(out, 0x03, v)
    return out^


def _accepted(variant: Int) raises -> Bool:
    var server = _bind_server()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    # QuicClientConnection.start with a caller-chosen parameter blob.
    var initial_dcid = _random_cid(8)
    var scid = _random_cid(8)
    var tp = _blob(variant, scid)
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
    if not client.is_established():
        server.close()
        return False
    for _ in range(4):
        try:
            client.keepalive()
            _ = server.tick(timeout_ms=50)
            _ = client.poll(timeout_ms=50)
        except:
            pass
    var alive = False
    for i in range(len(server.connections)):
        if not server.slot_free[i] and server.connections[i].alive:
            alive = True
    server.close()
    return alive


def main() raises:
    var names = List[String]()
    names.append("server-only original_destination_connection_id")
    names.append("server-only stateless_reset_token")
    names.append("absent initial_source_connection_id")
    names.append("initial_source_connection_id != Initial SCID")
    names.append("duplicate initial_max_streams_bidi")
    names.append("max_udp_payload_size 1000")
    if not _accepted(6):
        raise Error("harness: a valid client blob did not establish")
    print("valid client parameters -> accepted (control)")
    var bad = 0
    for v in range(len(names)):
        var ok = _accepted(v)
        print(names[v], "->", "accepted" if ok else "rejected")
        if ok:
            bad += 1
    if bad > 0:
        print(
            "BUG REPRODUCED: server completed the handshake and kept the"
            " connection for",
            bad,
            "of",
            len(names),
            "invalid client transport-parameter blobs",
        )
        raise Error("QUIC-11")
    print("OK: every invalid client transport-parameter blob rejected")
