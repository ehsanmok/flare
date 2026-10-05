# PLATFORM: any
# RESOLVED: H3-05 fixed on fix/formal-findings
"""H3-05: a second QPACK encoder/decoder stream and a client push stream
are accepted.

Lean: Flare.Bugs.H3_05.implOld_accepts_second_encoder (pre-fix),
      Flare.Bugs.H3_05.classifyFixed_spec (fix).
flare/http3/server.mojo:1046-1068 @59bda50 (`_classify_uni_kind`).

RFC 9204 §4.2: "Receipt of a second instance of either stream type [encoder,
decoder] MUST be treated as a connection error of type
H3_STREAM_CREATION_ERROR." RFC 9114 §6.2.2: a server receiving a
client-initiated push stream MUST treat it as H3_STREAM_CREATION_ERROR.
Expected: feed_uni_stream_chunk raises in all three cases. Before the fix: Actual: the
encoder / decoder stream id is overwritten and the push stream is recorded
and ignored; only a second control stream is rejected.

Minimal fix: in `_classify_uni_kind`, raise if
`peer_qpack_encoder_stream_id >= 0` (resp. decoder) before recording, and
raise for type 0x01 (push).
"""

from std.collections import List

from flare.http3 import Http3Connection


def _try(mut c: Http3Connection, sid: Int, kind: UInt8) -> Bool:
    var b = List[UInt8]()
    b.append(kind)
    try:
        c.feed_uni_stream_chunk(sid, b^)
        return True
    except:
        return False


def main() raises:
    var bad = String("")
    var c1 = Http3Connection()
    _ = _try(c1, 2, 0x02)
    if _try(c1, 6, 0x02):
        bad += "second-encoder-stream "
    var c2 = Http3Connection()
    _ = _try(c2, 2, 0x03)
    if _try(c2, 6, 0x03):
        bad += "second-decoder-stream "
    var c3 = Http3Connection()
    if _try(c3, 2, 0x01):
        bad += "client-push-stream "
    if bad != "":
        print(
            "BUG REPRODUCED: uni streams accepted without"
            " H3_STREAM_CREATION_ERROR:",
            bad,
        )
        raise Error("H3-05")
    print("OK: duplicate QPACK streams and client push streams rejected")
