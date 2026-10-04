# PLATFORM: any (binds a UDP socket on 127.0.0.1:0; no traffic)
"""QUIC-16: the server does not enforce its unidirectional stream limit.

Lean: Flare.Bugs.QUIC_16.impl_accepts (impl), Flare.Bugs.QUIC_16.fixed_spec
(fix). flare/quic/server.mojo:1407-1430 @59bda50 (_route_http3_stream_chunks)
checks the stream count only for bidirectional streams. The server
advertises initial_max_streams_uni = 3 (flare/quic/_server_types.mojo:162,
701) and never raises it.

RFC 9000 sec 4.6: "An endpoint that receives a frame with a stream ID
exceeding the limit it has sent MUST treat this as a connection error of
type STREAM_LIMIT_ERROR."

Expected: STREAM on client unidirectional stream 14 (the fourth) closes the
connection. Actual: the connection stays alive. Control: stream 10 (the
third) is accepted, and bidirectional stream 400 (the 101st) is rejected.

Minimal fix: in _route_http3_stream_chunks, for a unidirectional stream,
close with STREAM_LIMIT_ERROR when (sid >> 2) + 1 exceeds
config.initial_max_streams_uni.
"""

from std.collections import List

from flare.net import IpAddr, SocketAddr
from flare.quic.frame import StreamFrame
from flare.quic.packet import (
    ConnectionId,
    LongHeader,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
)
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import ConnectionEvents, empty_events
from flare.tls.rustls_quic import RustlsQuicConfig


def _bind() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config = RustlsQuicConfig()
    return QuicListener.bind(cfg^)


def _seed(mut listener: QuicListener) raises -> Int:
    var d = List[UInt8]()
    var s = List[UInt8]()
    for i in range(8):
        d.append(UInt8(0xA0 + i))
        s.append(UInt8(0xB0 + i))
    var lh = LongHeader(
        packet_type=PACKET_TYPE_INITIAL,
        version=QUIC_VERSION_1,
        dcid=ConnectionId(bytes=d^),
        scid=ConnectionId(bytes=s^),
        payload_offset=0,
    )
    return listener._accept_initial(lh, SocketAddr(IpAddr.localhost(), UInt16(54321)))


def _alive_after(sid: UInt64) raises -> Bool:
    var l = _bind()
    var slot = _seed(l)
    if slot < 0 or not l.connections[slot].alive:
        print("inconclusive: could not seed a connection slot")
        raise Error("QUIC-16 inconclusive")
    var ev = empty_events()
    ev.stream_chunks.append(
        StreamFrame(stream_id=sid, offset=UInt64(0), data=List[UInt8](), fin=False)
    )
    l._route_http3_stream_chunks(slot, ev)
    return l.connections[slot].alive


def main() raises:
    if not _alive_after(UInt64(10)):
        print("inconclusive: the third client uni stream was rejected")
        raise Error("QUIC-16 inconclusive")
    if _alive_after(UInt64(400)):
        print("inconclusive: the bidi limit is not enforced either")
        raise Error("QUIC-16 inconclusive")
    if _alive_after(UInt64(14)):
        print(
            "BUG REPRODUCED: STREAM on client uni stream 14 (4th, limit 3)"
            " accepted; connection still alive"
        )
        raise Error("QUIC-16")
    print("OK: client uni stream 14 (4th, limit 3) closed the connection")
