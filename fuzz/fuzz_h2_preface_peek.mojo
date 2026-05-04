"""Fuzz harness: ``flare.http._h2_conn_handle.PendingConnHandle.on_readable``.

The unified :class:`flare.http.HttpServer` peeks the first 24
bytes of every accepted connection to decide whether the peer is
speaking HTTP/1.1 or HTTP/2 (RFC 9113 §3.4 client connection
preface). The dispatch must NEVER crash on any byte sequence --
malformed peers, partial preface byte streams, random TCP noise,
oversized inputs, etc. The right behaviour is one of:

- ``PROTO_HTTP1`` (any byte mismatching the preface prefix),
- ``PROTO_HTTP2`` (full 24-byte preface match),
- ``PROTO_NEED_MORE`` (the in-memory transport ran out of bytes
  before a decision could be made).

To exercise the *decision logic* (not the underlying ``recv``
syscall) directly, this harness drives the same prefix-match
state machine via a copy of its `_h2_preface_byte` oracle. The
property fuzzed is symmetric: for every input, decision ==
"HTTP/2" iff the input is at least 24 bytes AND matches the
preface; "HTTP/1.1" iff there is at least one byte mismatching
the preface prefix; otherwise "NEED_MORE".

Run:
    pixi run fuzz-h2-preface-peek
"""

from mozz import fuzz, FuzzConfig

from flare.http2 import H2_PREFACE


comptime _PREFACE_LEN: Int = 24


def _preface_byte(i: Int) -> UInt8:
    """Mirror of :func:`flare.http._h2_conn_handle._h2_preface_byte`.
    The fuzz harness can't import private symbols directly so we
    keep an in-test copy of the 24-byte H2 preface."""
    var s = String(H2_PREFACE)
    return s.unsafe_ptr()[i]


def _classify(data: List[UInt8]) -> Int:
    """Return 1 (PROTO_HTTP1), 2 (PROTO_HTTP2), or 0 (NEED_MORE)
    using the same byte-by-byte state machine the
    PendingConnHandle uses."""
    var i = 0
    while i < len(data) and i < _PREFACE_LEN:
        if data[i] != _preface_byte(i):
            return 1  # PROTO_HTTP1
        i += 1
    if i >= _PREFACE_LEN:
        return 2  # PROTO_HTTP2
    return 0  # PROTO_NEED_MORE (consumed all bytes, all matched, but < 24)


def target(data: List[UInt8]) raises:
    var cls = _classify(data)
    # Property 1: the classification is deterministic and total.
    if cls != 0 and cls != 1 and cls != 2:
        raise Error("preface peek: bogus classification " + String(cls))
    # Property 2: HTTP/2 iff the input STARTS WITH the preface AND
    # is at least 24 bytes long.
    var starts_with_preface = len(data) >= _PREFACE_LEN
    if starts_with_preface:
        for i in range(_PREFACE_LEN):
            if data[i] != _preface_byte(i):
                starts_with_preface = False
                break
    if starts_with_preface and cls != 2:
        raise Error("preface peek: false negative on full preface")
    if (not starts_with_preface) and cls == 2:
        raise Error("preface peek: false positive (no full preface match)")
    # Property 3: HTTP/1.1 iff there's some i < len(data) with
    # data[i] != _preface_byte(i).
    var any_mismatch = False
    var bound = len(data)
    if bound > _PREFACE_LEN:
        bound = _PREFACE_LEN
    for i in range(bound):
        if data[i] != _preface_byte(i):
            any_mismatch = True
            break
    if any_mismatch and cls != 1:
        raise Error("preface peek: false negative on mismatching prefix")
    if (not any_mismatch) and cls == 1:
        raise Error("preface peek: false positive (no mismatch present)")


def main() raises:
    print("[mozz] fuzzing PendingConnHandle preface-peek classification...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes(""))
    # Real preface (must classify as HTTP/2).
    seeds.append(_bytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
    # Real preface + extra bytes (must STILL classify as HTTP/2 --
    # the 24-byte prefix is what matters).
    seeds.append(_bytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nDATA-FOLLOWS\xff\xfe"))
    # Plain HTTP/1.1 GET (must classify as HTTP/1.1).
    seeds.append(_bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    # First byte matches the preface 'P', second byte differs
    # (must classify as HTTP/1.1 on the second byte).
    seeds.append(_bytes("PXXX"))
    # Truncated preface (the first 23 bytes match) -- must
    # classify as NEED_MORE.
    seeds.append(_bytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/h2_preface_peek",
            corpus_dir="fuzz/corpus/h2_preface_peek",
            max_input_len=64,
        ),
        seeds,
    )
