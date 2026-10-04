# PLATFORM: any (needs the rustls QUIC shim and the fixtures in
# tests/tls/fixtures/rustls-quic-client/; UDP on 127.0.0.1 only)
"""QUIC-24: the client keeps sending while draining.

Lean: Flare.Bugs.QUIC_24.impl_sends_draining, Flare.Bugs.QUIC_24.impl_trace
(impl), Flare.Bugs.QUIC_24.fixed_spec (fix). A peer CONNECTION_CLOSE moves
the client to DRAINING (flare/quic/state.mojo:430-445 @59bda50), but no send
path of flare/quic/client.mojo checks the state: poll -> _drain_egress
(1035-1085) and _check_pto (688-706), keepalive (1619-1634), send_stream
(1347-1400) all build 1-RTT packets through _build_1rtt (1231).

RFC 9000 sec 10.2.2: "An endpoint that has received a CONNECTION_CLOSE frame
... An endpoint in the draining state MUST NOT send any packets."

Setup: an in-memory rustls handshake gives the client real 1-RTT keys; its
peer address is a UDP socket this repro owns. The client sends 100 bytes on
stream 0 (unacknowledged), then a CONNECTION_CLOSE (no error) is
dispatched. The client is polled for 3 s (its PTO for the unacknowledged
data fires in that time), then keepalive() is called.
Control: the body chunk itself reaches the peer socket, and the client's
state is DRAINING after the CONNECTION_CLOSE; otherwise inconclusive.

Expected: no datagram after the CONNECTION_CLOSE.
Actual: the PTO retransmission and the keepalive PING are sent.

Minimal fix: _build_1rtt returns no datagram while the connection is
DRAINING.
"""

from std.collections import List, Optional
from std.collections.span import Span
from std.ffi import OwnedDLHandle
from std.pathlib import Path

from flare.net.address import IpAddr, SocketAddr
from flare.udp import UdpSocket
from flare.quic.client import QuicClientConnection
from flare.quic.crypto import QuicAead
from flare.quic.packet import ConnectionId
from flare.quic.state import CONN_STATE_DRAINING, empty_events, new_connection
from flare.quic.transport_params import (
    empty_transport_parameters,
    encode_transport_parameters,
)
from flare.tls import RustlsQuicConnector
from flare.tls.rustls_quic import (
    QuicEncryptionLevel,
    RustlsQuicAcceptor,
    RustlsQuicConfig,
    RustlsQuicSession,
)
from flare.tls._rustls_quic_ffi import _do_accept, _find_rustls_quic_lib


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _cid(b: UInt8) -> List[UInt8]:
    var v = List[UInt8]()
    for _ in range(8):
        v.append(b)
    return v^


def _handshake() raises -> RustlsQuicSession:
    var cfg = RustlsQuicConfig()
    cfg.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.alpn_protocols = _alpn()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var tp = empty_transport_parameters()
    tp.original_destination_connection_id = _cid(0xAA)
    tp.initial_source_connection_id = _cid(0xBB)
    tp.initial_max_data = Optional(UInt64(1 << 20))
    tp.initial_max_stream_data_bidi_remote = Optional(UInt64(1 << 20))
    tp.initial_max_streams_bidi = Optional(UInt64(16))
    var h = _do_accept(
        acceptor._lib, acceptor._opaque_handle, encode_transport_parameters(tp)
    )
    if h == 0:
        raise Error("harness: _do_accept failed")
    var srv = RustlsQuicSession._wrap(
        OwnedDLHandle(_find_rustls_quic_lib()), h, _cid(0xAA)
    )
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var ctp = empty_transport_parameters()
    ctp.initial_source_connection_id = _cid(0xDD)
    var cli = connector.connect(
        String("localhost"), encode_transport_parameters(ctp)
    )
    var levels = List[Int]()
    levels.append(QuicEncryptionLevel.INITIAL)
    levels.append(QuicEncryptionLevel.HANDSHAKE)
    levels.append(QuicEncryptionLevel.APPLICATION)
    for _ in range(10):
        for i in range(len(levels)):
            var d = cli.take_crypto(levels[i])
            if len(d) > 0:
                srv.feed_crypto(levels[i], d)
            var e = srv.take_crypto(levels[i])
            if len(e) > 0:
                cli.feed_crypto(levels[i], e)
        if cli.is_handshake_complete() and srv.is_handshake_complete():
            break
    if not cli.is_handshake_complete():
        raise Error("harness: in-memory handshake did not complete")
    return cli^


def _got_datagram(mut peer: UdpSocket) raises -> Bool:
    var buf = List[UInt8](length=2048, fill=UInt8(0))
    try:
        _ = peer.recv_from(Span[UInt8, _](buf))
    except:
        return False
    return True


def main() raises:
    var session: RustlsQuicSession
    try:
        session = _handshake()
    except e:
        print("inconclusive: harness failed:", e)
        raise Error("QUIC-24 inconclusive")
    var peer = UdpSocket.bind(SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)))
    peer.set_recv_timeout(300)
    var sock = UdpSocket.bind(SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)))
    var client = QuicClientConnection(
        new_connection(UInt64(30_000_000), UInt64(1 << 20)),
        session^,
        sock^,
        peer.local_addr(),
        ConnectionId(bytes=_cid(0xBB)),
        ConnectionId(bytes=_cid(0xDD)),
        QuicAead.AES_128_GCM,
        1452,
    )
    client.have_1rtt_keys = True
    var sid = client.open_bidi_stream()
    var body = List[UInt8](length=100, fill=UInt8(0x41))
    client.send_stream(sid, body, False)
    if not _got_datagram(peer):
        print("inconclusive: the body chunk never reached the peer socket")
        raise Error("QUIC-24 inconclusive")
    # CONNECTION_CLOSE (0x1c): error 0, frame type 0, empty reason.
    var cc: List[UInt8] = [0x1C, 0x00, 0x00, 0x00]
    var ev = empty_events()
    client._dispatch_frames(Span[UInt8, _](cc), ev)
    if client.conn.state != CONN_STATE_DRAINING:
        print("inconclusive: client not DRAINING after CONNECTION_CLOSE; state", client.conn.state)
        raise Error("QUIC-24 inconclusive")
    var after_poll = 0
    for _ in range(30):
        _ = client.poll(timeout_ms=100)
        while _got_datagram(peer):
            after_poll += 1
            peer.set_recv_timeout(10)
        peer.set_recv_timeout(10)
    client.keepalive()
    peer.set_recv_timeout(300)
    var after_ka = 0
    while _got_datagram(peer):
        after_ka += 1
        peer.set_recv_timeout(10)
    print(
        "datagrams sent while DRAINING: by poll (PTO/egress):", after_poll,
        "| by keepalive():", after_ka,
    )
    if after_poll + after_ka > 0:
        print(
            "BUG REPRODUCED: client in DRAINING sent", after_poll + after_ka,
            "datagram(s) (poll:", after_poll, ", keepalive:", after_ka, ")",
        )
        raise Error("QUIC-24")
    print("OK: no datagram sent while draining")
