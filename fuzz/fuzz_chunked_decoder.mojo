"""Fuzz harness: HTTP/1.1 chunked transfer-encoding decoder.

Feeds arbitrary bytes to ``_decode_chunked`` (the client-side chunked
body decoder shared by the buffered readers and exercised on the
``get_streaming`` download path). Malformed framing must raise a clean
``Error`` (an expected rejection), never panic / read out of bounds.

Run:
    pixi run fuzz-chunked-decoder
"""

from mozz import fuzz, FuzzConfig

from flare.http._client.parse import _decode_chunked
from flare.http.headers import HeaderMap


def target(data: List[UInt8]) raises:
    """Decode ``data`` as a chunked body from offset 0."""
    var trailers = HeaderMap()
    try:
        _ = _decode_chunked(data, 0, trailers)
    except:
        pass  # malformed chunk framing is an expected rejection


def main() raises:
    print("[mozz] fuzzing _decode_chunked()...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes("5\r\nhello\r\n0\r\n\r\n"))
    seeds.append(_bytes("1\r\nA\r\n1\r\nB\r\n0\r\n\r\n"))
    seeds.append(_bytes("a\r\n0123456789\r\n0\r\n\r\n"))
    seeds.append(_bytes("0\r\n\r\n"))
    seeds.append(_bytes("ff\r\n"))  # truncated
    seeds.append(_bytes("z\r\n\r\n"))  # bad hex
    seeds.append(_bytes("5\r\nhi\r\n"))  # size/len mismatch
    seeds.append(_bytes("3\r\nabc\r\n0\r\nX-Trailer: v\r\n\r\n"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/chunked_decoder",
            corpus_dir="fuzz/corpus/chunked_decoder",
            max_input_len=1024,
        ),
        seeds,
    )
