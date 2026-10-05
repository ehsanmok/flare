# PLATFORM: any
# RESOLVED: QUIC-04 fixed on fix/formal-findings
"""QUIC-04: HANDSHAKE_DONE moves a CLOSING/DRAINING connection back to
ESTABLISHED.

Lean: Flare.Bugs.QUIC_04.reopens (connStep DRAINING handshakeDone =
ESTABLISHED), Flare.L3.Quic.Conn.spec_closing_absorbing, and
Flare.Bugs.QUIC_04.fixed_refines for the fix.
flare/quic/state.mojo:487-492 @59bda50 (apply_handshake_done sets
CONN_STATE_ESTABLISHED unconditionally).

RFC 9000 sec 10.2: the closing and draining states only lead to closed; a
connection that has received CONNECTION_CLOSE never becomes usable again.

Expected: after the payload 1c 00 00 00 1e (CONNECTION_CLOSE then
HANDSHAKE_DONE) the connection stays DRAINING.
Before the fix: conn.state is ESTABLISHED again.

Minimal fix: in apply_handshake_done, only change state when it is
CONN_STATE_HANDSHAKE (as mark_handshake_complete already does).
"""

from std.collections import List

from flare.quic.state import (
    CONN_STATE_DRAINING,
    CONN_STATE_ESTABLISHED,
    dispatch_frames,
    empty_events,
    new_connection,
)
from std.collections.span import Span


def main() raises:
    var conn = new_connection()
    var ev = empty_events()
    var payload: List[UInt8] = [0x1C, 0x00, 0x00, 0x00, 0x1E]
    dispatch_frames(conn, Span[UInt8, _](payload), UInt64(1_000), ev, False)
    if conn.state == CONN_STATE_ESTABLISHED:
        print(
            "BUG REPRODUCED: CONNECTION_CLOSE then HANDSHAKE_DONE leaves the"
            " connection ESTABLISHED (connection_closed event =",
            ev.connection_closed,
            ")",
        )
        raise Error("QUIC-04")
    print("OK: connection stays draining, state =", conn.state)
