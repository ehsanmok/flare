# PLATFORM: any (binds a UDP socket on 127.0.0.1:0; no traffic, no TLS)
"""QUIC-17: the client checks no stream id on any stream frame.

Lean: Flare.Bugs.QUIC_17.impl_accepts (impl), Flare.Bugs.QUIC_17.fixed_spec
(fix). flare/quic/client.mojo:902-912 @59bda50 (_dispatch_frames, the
client's frame path for every packet level) over
flare/quic/state.mojo:325-365, 454-486.

RFC 9000 sec 19.8 (STREAM on a send-only stream or an unopened locally
initiated one), 19.4 (RESET_STREAM on a send-only stream), 19.5
(STOP_SENDING on a receive-only stream): STREAM_STATE_ERROR; sec 4.6
(above the advertised 16 server bidi streams): STREAM_LIMIT_ERROR.

The client has opened bidi stream 0 and uni streams 2, 6, 10 (as the H3
client does). Cases:
  STREAM 2         its own control stream (send-only)
  STREAM 4         a bidi stream it has not opened
  RESET_STREAM 2   send-only
  STOP_SENDING 3   server uni stream (receive-only for the client)
  STREAM 65        the 17th server bidi stream, 16 allowed
Control: STREAM on 0 and on server uni stream 3 are accepted.

Expected: each case raises. Actual: each is accepted (STREAM 2 / 4 / 65
even create a stream and surface the bytes as stream_chunks).

Minimal fix: in _dispatch_frames, check each stream frame's id against
direction, next_bidi_stream / next_uni_stream and the advertised limits
before handing it to handle_frame_buf.
"""

from std.collections import List
from std.collections.span import Span

from flare.net.address import IpAddr, SocketAddr
from flare.udp import UdpSocket
from flare.quic.client import QuicClientConnection
from flare.quic.crypto import QuicAead
from flare.quic.packet import ConnectionId
from flare.quic.state import empty_events, new_connection, new_stream
from flare.tls.rustls_quic import RustlsQuicSession


def _cid(b: UInt8) -> List[UInt8]:
    var v = List[UInt8]()
    for _ in range(8):
        v.append(b)
    return v^


def _client() raises -> QuicClientConnection:
    var sock = UdpSocket.bind(SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)))
    var c = QuicClientConnection(
        new_connection(UInt64(30_000_000), UInt64(1 << 20)),
        RustlsQuicSession(_cid(0xAA)),
        sock^,
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(9)),
        ConnectionId(bytes=_cid(0xAA)),
        ConnectionId(bytes=_cid(0xDD)),
        QuicAead.AES_128_GCM,
        1452,
    )
    _ = c.open_bidi_stream()
    for _ in range(3):
        _ = c.open_uni_stream()
    var sids: List[UInt64] = [0, 2, 6, 10]
    for i in range(len(sids)):
        c.conn.streams[sids[i]] = new_stream(sids[i], UInt64(1 << 20))
    return c^


def _accepted(var payload: List[UInt8]) raises -> Bool:
    var c = _client()
    var ev = empty_events()
    try:
        c._dispatch_frames(Span[UInt8, _](payload), ev)
    except:
        return False
    return True


def main() raises:
    var ok0: List[UInt8] = [0x0A, 0x00, 0x01, 0x41]
    var ok3: List[UInt8] = [0x0A, 0x03, 0x01, 0x41]
    if not _accepted(ok0^) or not _accepted(ok3^):
        print("inconclusive: control STREAM frames on 0 / 3 rejected")
        raise Error("QUIC-17 inconclusive")
    var names = List[String]()
    var cases = List[List[UInt8]]()
    names.append("STREAM 2")
    cases.append([0x0A, 0x02, 0x01, 0x41])
    names.append("STREAM 4")
    cases.append([0x0A, 0x04, 0x01, 0x41])
    names.append("RESET_STREAM 2")
    cases.append([0x04, 0x02, 0x00, 0x00])
    names.append("STOP_SENDING 3")
    cases.append([0x05, 0x03, 0x00])
    names.append("STREAM 65")
    cases.append([0x0A, 0x40, 0x41, 0x01, 0x41])
    var bad = String("")
    for i in range(len(cases)):
        if _accepted(cases[i].copy()):
            bad += " [" + names[i] + "]"
    if bad.byte_length() > 0:
        print("BUG REPRODUCED: client accepted stream frames RFC 9000 requires it to reject:" + bad)
        raise Error("QUIC-17")
    print("OK: all five wrong-direction / unopened / over-limit stream frames rejected")
