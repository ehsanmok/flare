# PLATFORM: any (binds a UDP socket on 127.0.0.1:0; no traffic, no TLS)
# RESOLVED: QUIC-18 fixed on fix/formal-findings
"""QUIC-18: one state for both stream halves loses a reset.

Lean: Flare.Bugs.QUIC_18.impl_loses (impl), Flare.Bugs.QUIC_18.fixed_spec
(fix). flare/quic/state.mojo:467-486 @59bda50 (apply_reset_stream sets the
single Stream.state to RESET_RECVD, apply_stop_sending to RESET_SENT) and
flare/quic/client.mojo:1406-1428 (cancel_stream writes RESET_SENT),
1455-1460 (stream_reset reads RESET_RECVD), 1357-1362 (send_stream refuses
only in RESET_SENT).

RFC 9000 sec 3: a bidirectional stream has a sending part (3.1) and a
receiving part (3.2). RESET_STREAM moves the receiving part to Reset Recvd;
STOP_SENDING or our own RESET_STREAM moves the sending part to Reset Sent;
sec 3.1: no STREAM frames once in Reset Sent.

Cases on the client's request stream 0:
  A  the server sends RESET_STREAM then STOP_SENDING (one packet):
     stream_reset(0) must be True (the H3 client polls it to fail the
     response, flare/http3/client.mojo:465).
  B  the client cancels the stream (cancel_stream), then the server's
     RESET_STREAM arrives: send_stream(0) must still refuse.
Control: RESET_STREAM alone makes stream_reset(0) True; cancel_stream alone
makes send_stream refuse.

Expected: A True, B refused. Before the fix: A False, B accepted (send_stream goes
on to build a packet).

Minimal fix: keep the two halves apart (a per-stream "peer reset" and
"send reset" flag), set them from the frames and from cancel_stream, and
read them in stream_reset / send_stream.
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
    c.conn.streams[UInt64(0)] = new_stream(UInt64(0), UInt64(1 << 20))
    return c^


def _feed(mut c: QuicClientConnection, var payload: List[UInt8]) raises:
    var ev = empty_events()
    c._dispatch_frames(Span[UInt8, _](payload), ev)


def _send_refused(mut c: QuicClientConnection) raises -> Bool:
    """Whether send_stream(0) stops at the reset check. Past it, the NULL
    session makes packet encryption raise with a different message."""
    c.have_1rtt_keys = True
    var data: List[UInt8] = [0x41]
    try:
        c.send_stream(UInt64(0), data, False)
    except e:
        return "reset stream" in String(e)
    return False


def _cancel(mut c: QuicClientConnection) raises:
    try:
        c.cancel_stream(UInt64(0))  # sets RESET_SENT, then fails to encrypt
    except:
        pass


def main() raises:
    var reset_only: List[UInt8] = [0x04, 0x00, 0x00, 0x00]
    var c0 = _client()
    _feed(c0, reset_only^)
    var c1 = _client()
    _cancel(c1)
    if not c0.stream_reset(UInt64(0)) or not _send_refused(c1):
        print("inconclusive: controls failed (lone RESET_STREAM / lone cancel)")
        raise Error("QUIC-18 inconclusive")

    var a: List[UInt8] = [0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00]
    var ca = _client()
    _feed(ca, a^)
    var seen_a = ca.stream_reset(UInt64(0))

    var cb = _client()
    _cancel(cb)
    var b: List[UInt8] = [0x04, 0x00, 0x00, 0x00]
    _feed(cb, b^)
    var refused_b = _send_refused(cb)

    print("A RESET_STREAM+STOP_SENDING -> stream_reset =", seen_a)
    print("B cancel_stream+RESET_STREAM -> send_stream refused =", refused_b)
    if not seen_a or not refused_b:
        print(
            "BUG REPRODUCED: the single stream state lost a reset"
            " (A stream_reset =", seen_a, ", B send refused =", refused_b, ")"
        )
        raise Error("QUIC-18")
    print("OK: both halves' resets survive the other half's event")
