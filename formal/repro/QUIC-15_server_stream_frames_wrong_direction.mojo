# PLATFORM: any
"""QUIC-15: the server accepts stream frames that name the wrong direction.

Lean: Flare.Bugs.QUIC_15.impl_accepts (impl), Flare.Bugs.QUIC_15.fixed_spec
(fix). flare/quic/state.mojo:454-486, 712-722 @59bda50 reached from
flare/quic/_server_types.mojo:559-579 (QuicConnection.dispatch_plaintext,
the server's 1-RTT frame path). Only STREAM has a stream-id check
(server.mojo:1407-1430); nothing looks at the other stream frames again.

RFC 9000 sec 19.4 (RESET_STREAM on a send-only stream), 19.5
(STOP_SENDING on a receive-only stream or a locally initiated stream not
yet created), 19.10 (MAX_STREAM_DATA, the same), 19.13
(STREAM_DATA_BLOCKED on a send-only stream): STREAM_STATE_ERROR; sec 4.6:
a stream id above the advertised limit is STREAM_LIMIT_ERROR.

Cases (the server opens no stream of its own; 100 client bidi allowed):
  RESET_STREAM 3, STREAM_DATA_BLOCKED 3   (server uni = send-only)
  STOP_SENDING 2, MAX_STREAM_DATA 2       (client uni = receive-only)
  STOP_SENDING 1                          (server bidi, never opened)
  STOP_SENDING 400                        (101st client bidi)
Control: STOP_SENDING and MAX_STREAM_DATA on client bidi stream 0 are
accepted.

Expected: each case raises. Actual: each is accepted.

Minimal fix: in dispatch_plaintext, check the stream id of every
RESET_STREAM / STOP_SENDING / MAX_STREAM_DATA / STREAM_DATA_BLOCKED
against its direction, the server's (empty) set of opened streams and the
advertised bidi limit before applying it.
"""

from std.collections import List
from std.collections.span import Span

from flare.quic import ConnectionId, QuicConnection


def _cid(seed: Int) -> ConnectionId:
    var b = List[UInt8]()
    for i in range(8):
        b.append(UInt8(seed + i))
    return ConnectionId(bytes=b^)


def _accepted(var payload: List[UInt8]) raises -> Bool:
    var qc = QuicConnection(_cid(1), _cid(0x40))
    try:
        _ = qc.dispatch_plaintext(
            Span[UInt8, _](payload), UInt64(1_000_000), UInt64(0)
        )
    except:
        return False
    return True


def main() raises:
    var ok0: List[UInt8] = [0x05, 0x00, 0x00]
    var ok1: List[UInt8] = [0x11, 0x00, 0x10]
    if not _accepted(ok0^) or not _accepted(ok1^):
        print("inconclusive: control frames on client bidi stream 0 rejected")
        raise Error("QUIC-15 inconclusive")
    var names = List[String]()
    var cases = List[List[UInt8]]()
    names.append("RESET_STREAM sid 3")
    cases.append([0x04, 0x03, 0x00, 0x00])
    names.append("STREAM_DATA_BLOCKED sid 3")
    cases.append([0x15, 0x03, 0x00])
    names.append("STOP_SENDING sid 2")
    cases.append([0x05, 0x02, 0x00])
    names.append("MAX_STREAM_DATA sid 2")
    cases.append([0x11, 0x02, 0x10])
    names.append("STOP_SENDING sid 1")
    cases.append([0x05, 0x01, 0x00])
    names.append("STOP_SENDING sid 400")
    cases.append([0x05, 0x41, 0x90, 0x00])
    var bad = String("")
    for i in range(len(cases)):
        if _accepted(cases[i].copy()):
            bad += " [" + names[i] + "]"
    if bad.byte_length() > 0:
        print("BUG REPRODUCED: server accepted stream frames RFC 9000 requires it to reject:" + bad)
        raise Error("QUIC-15")
    print("OK: all six wrong-direction / unopened / over-limit stream frames rejected")
