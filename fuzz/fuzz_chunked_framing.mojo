"""Fuzz harness: server-side inbound chunked framing scanner.

``scan_chunked_end`` runs on attacker bytes before anything is parsed:
it decides when a chunked request is complete and how far the body
reaches. It is a pure scanner over a caller-owned buffer, so the
property under test is total-function behaviour -- every input must
produce one of the three defined outcomes (an offset,
``CHUNKED_INCOMPLETE``, ``CHUNKED_MALFORMED``) without panicking or
indexing out of bounds.

Two extra invariants are asserted here rather than left implicit:

- A returned offset must lie within the buffer. A scanner that reports
  an end past the end would hand the parser a bad slice.
- ``max_body`` must be respected. The cap is checked during the walk
  precisely so a chunked upload cannot grow the read buffer past the
  configured limit before anyone notices, so a success return whose
  decoded body exceeds it is a bug.

Run:
    pixi run fuzz-chunked-framing
"""

from mozz import fuzz, FuzzConfig

from flare.http.proto.chunked import (
    CHUNKED_INCOMPLETE,
    CHUNKED_MALFORMED,
    decode_chunked_body,
    header_says_chunked,
    request_te_framing,
    scan_chunked_end,
)


comptime _MAX_BODY: Int = 4096


def target(data: List[UInt8]) raises:
    var span = Span[UInt8, _](data)
    var end = scan_chunked_end(span, 0, _MAX_BODY)

    if end == CHUNKED_INCOMPLETE or end == CHUNKED_MALFORMED:
        return

    if end < 0 or end > len(data):
        raise Error(
            "scan_chunked_end returned an out-of-range offset: "
            + String(end)
            + " for a "
            + String(len(data))
            + "-byte buffer"
        )

    # A buffer the scanner accepted must decode without raising, and
    # must respect the cap the scanner enforced.
    var out = List[UInt8]()
    _ = decode_chunked_body(Span[UInt8, _](data)[:end], 0, out)
    if len(out) > _MAX_BODY:
        raise Error(
            "decoded body exceeded max_body after a successful scan: "
            + String(len(out))
        )

    # The header scanner shares the same byte-walking shape; run it on
    # the same input so malformed header blocks are covered too.
    _ = header_says_chunked(span, len(data))
    _ = request_te_framing(span, len(data))


def main() raises:
    print("[mozz] fuzzing scan_chunked_end() + decode_chunked_body()...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes("5\r\nhello\r\n0\r\n\r\n"))
    seeds.append(_bytes("5;ext=1\r\nhello\r\n0\r\nX-T: v\r\n\r\n"))
    seeds.append(_bytes("0\r\n\r\n"))
    seeds.append(_bytes("FFFFFFFF\r\n"))
    seeds.append(_bytes("5\r\nhello"))
    seeds.append(_bytes("zz\r\n"))
    seeds.append(_bytes("Transfer-Encoding: chunked\r\n\r\n"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/chunked_framing",
            corpus_dir="fuzz/corpus/chunked_framing",
            max_input_len=1024,
        ),
        seeds,
    )
