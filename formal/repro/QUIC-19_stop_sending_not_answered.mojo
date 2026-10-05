# PLATFORM: any (needs the rustls QUIC shim and the fixtures in
# RESOLVED: QUIC-19 fixed on fix/formal-findings
# tests/tls/fixtures/rustls-quic-client/; UDP on 127.0.0.1 only)
"""QUIC-19: STOP_SENDING is never answered with RESET_STREAM.

Lean: Flare.Bugs.QUIC_19.impl_silent (impl), Flare.Bugs.QUIC_19.fixed_spec
(fix). flare/quic/state.mojo:478-486 @59bda50 (apply_stop_sending only sets
RESET_SENT) reached from flare/quic/client.mojo:902-912 (_dispatch_frames,
which sends nothing). The only RESET_STREAM flare encodes is in
cancel_stream (client.mojo:1406-1428).

RFC 9000 sec 3.5: "An endpoint that receives a STOP_SENDING frame MUST send
a RESET_STREAM frame if the stream is in the "Ready" or "Send" state."

Setup: an in-memory rustls handshake gives the client real 1-RTT keys; its
peer address is a UDP socket this repro owns. The client sends part of a
request body on stream 0 without FIN (the stream is in "Send"), then a
STOP_SENDING for stream 0 is dispatched.
Control: the body chunk itself arrives at the peer socket (the harness can
see what the client sends).

Expected: a datagram (the RESET_STREAM) arrives after STOP_SENDING.
Before the fix: nothing is sent.

Minimal fix: in _dispatch_frames, for each STOP_SENDING on a stream not
already RESET_SENT, send RESET_STREAM(stream, code, final size =
send_offsets[stream]).
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
from flare.quic.state import empty_events, new_connection
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
        raise Error("QUIC-19 inconclusive")
    var peer = UdpSocket.bind(SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)))
    peer.set_recv_timeout(500)
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
        raise Error("QUIC-19 inconclusive")
    var stop: List[UInt8] = [0x05, UInt8(Int(sid)), 0x00]
    var ev = empty_events()
    client._dispatch_frames(Span[UInt8, _](stop), ev)
    if not _got_datagram(peer):
        print(
            "BUG REPRODUCED: STOP_SENDING on stream", sid,
            "(in Send state, 100 bytes sent) was not answered: no datagram"
            " within 500 ms",
        )
        raise Error("QUIC-19")
    print("OK: the client answered STOP_SENDING with a packet (RESET_STREAM)")
