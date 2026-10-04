# PLATFORM: any
"""QUIC-09: the server accepts a HANDSHAKE_DONE frame from the client.

Lean: Flare.Bugs.QUIC_09.server_accepts (the server-role step on
HANDSHAKE_DONE succeeds) and Flare.Bugs.QUIC_09.fixed_rejects.
flare/quic/state.mojo:765-767 + 487-492 @59bda50 (on_handshake_done has no
role check; the sans-I/O Connection has no role) reached from the server's
per-connection driver flare/quic/_server_types.mojo:565-578
(QuicConnection.dispatch_plaintext; the Initial/Handshake/1-RTT handlers at
485/513/544 are the same).

RFC 9000 sec 19.20: "A server MUST treat receipt of a HANDSHAKE_DONE frame
as a connection error of type PROTOCOL_VIOLATION."

Expected: a 1-RTT payload 1e handed to the server connection raises
PROTOCOL_VIOLATION.
Actual: accepted; the server's connection state flips to ESTABLISHED and
the handshake_done event fires.

Minimal fix: in QuicConnection's frame-dispatch paths, treat
events.handshake_done as PROTOCOL_VIOLATION (connection_close + raise), or
give Connection a role so on_handshake_done can reject it on the server.
"""

from std.collections import List
from std.collections.span import Span

from flare.quic import ConnectionId, QuicConnection


def _cid(seed: Int) -> ConnectionId:
    var b = List[UInt8]()
    for i in range(8):
        b.append(UInt8(seed + i))
    return ConnectionId(bytes=b^)


def main() raises:
    var qc = QuicConnection(_cid(1), _cid(0x40))
    var payload: List[UInt8] = [0x1E]
    var raised = False
    var fired = False
    try:
        var ev = qc.dispatch_plaintext(
            Span[UInt8, _](payload), UInt64(1_000_000), UInt64(0)
        )
        fired = ev.handshake_done
    except:
        raised = True
    if not raised:
        print(
            "BUG REPRODUCED: server accepted HANDSHAKE_DONE from the client"
            " (handshake_done event =",
            fired,
            ", conn.state =",
            qc.conn.state,
            ")",
        )
        raise Error("QUIC-09")
    print("OK: server rejected HANDSHAKE_DONE with PROTOCOL_VIOLATION")
