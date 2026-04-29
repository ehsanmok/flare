"""Fuzz harness: ``multipart/form-data`` parser.

Tests ``parse_multipart_form_data`` for crashes on arbitrary input
under both well-formed and adversarial boundary configurations.
Truncated bodies / missing boundaries raise — that's expected
rejection. Only panic-like errors / OOB reads are bugs.

Run:
    pixi run fuzz-multipart
"""

from mozz import fuzz, FuzzConfig
from flare.http.multipart import parse_multipart_form_data


def target(data: List[UInt8]) raises:
    """Fuzz target: parse arbitrary bytes as multipart with a fixed
    boundary token plus a few input-derived alternates.

    Args:
        data: Arbitrary bytes treated as a multipart body. The
              boundary is read from a small set of fixed values
              and (when the input is long enough) from the first
              byte mod-5 to amplify mutation reach.
    """
    var ct_pool = List[String]()
    ct_pool.append("multipart/form-data; boundary=BND")
    ct_pool.append("multipart/form-data; boundary=---abc")
    ct_pool.append('multipart/form-data; boundary="quoted"')
    ct_pool.append("multipart/form-data; boundary=")  # malformed
    ct_pool.append("application/json")  # missing boundary

    var idx = 0
    if len(data) > 0:
        idx = Int(data[0]) % len(ct_pool)
    var ct = ct_pool[idx]
    try:
        _ = parse_multipart_form_data(data, ct)
    except:
        pass


def main() raises:
    print("[mozz] fuzzing parse_multipart_form_data()...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes(""))
    seeds.append(
        _bytes(
            "--BND\r\n"
            'Content-Disposition: form-data; name="a"\r\n\r\nv\r\n'
            "--BND--\r\n"
        )
    )
    seeds.append(
        _bytes(
            "--BND\r\n"
            'Content-Disposition: form-data; name="f"; filename="x.bin"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
            "DATA\r\n--BND--\r\n"
        )
    )
    seeds.append(
        _bytes(
            "--BND\r\n"
            'Content-Disposition: form-data; name="a"\r\n\r\nv1\r\n'
            "--BND\r\n"
            'Content-Disposition: form-data; name="b"\r\n\r\nv2\r\n'
            "--BND--\r\n"
        )
    )
    # Truncated.
    seeds.append(_bytes("--BND\r\n"))
    seeds.append(_bytes("--BND\r\nContent-Disposition: ...\r\n"))
    # Boundary-shaped chaff.
    seeds.append(_bytes("\r\n--BND--\r\n"))
    seeds.append(_bytes("---BND-----\r\n"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/multipart",
            corpus_dir="fuzz/corpus/multipart",
            max_input_len=2048,
        ),
        seeds,
    )
