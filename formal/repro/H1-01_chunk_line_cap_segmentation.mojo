# PLATFORM: any
"""H1-01: the chunk-line cap gives a different verdict depending on how the
bytes were segmented.

Lean: Flare.Bugs.H1_01.counterexample_size_line,
Flare.Bugs.H1_01.counterexample_trailer (counterexamples) and
Flare.Bugs.H1_01.fixed_segmentation_independent (fix meets spec).
flare/http/proto/chunked.mojo:246-251 and 270-290 @59bda50.

Spec: the reactor polls ``scan_chunked_resume`` after every read
(flare/http/_reactor/conn_handle.mojo:655-678). Its verdict on a byte
stream must not depend on where TCP split the stream: once a prefix gets a
definite verdict, every extension must get the same one, and that verdict
must equal a one-shot scan of all the bytes.

Expected: a chunk-size line of exactly CHUNK_LINE_MAX (4096) content bytes
is accepted (the complete-line test is ``line_end - pos > 4096``), so the
prefix ending in its CR must be INCOMPLETE.
Actual: the incomplete-line test ``n - pos > 4096`` counts the CR, so the
prefix "<4096 bytes>\\r" is MALFORMED (400) while the same bytes delivered
in one read are accepted. Trailer lines have the converse problem: a
complete trailer line has no cap at all, a partial one is capped.

Minimal fix: allow one byte of slack for the pending CR in both
incomplete-line tests (``> CHUNK_LINE_MAX + 1``) and cap complete trailer
lines (``found - t > CHUNK_LINE_MAX`` is MALFORMED).
"""

from flare.http.proto.chunked import (
    scan_chunked_resume,
    scan_chunked_end,
    CHUNKED_MALFORMED,
    CHUNKED_INCOMPLETE,
)


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _poll(full: List[UInt8], split: Int, max_body: Int) -> Int:
    """Reactor-style polling: scan the first ``split`` bytes, then resume
    on the whole buffer if the first verdict was INCOMPLETE."""
    var part = List[UInt8]()
    for i in range(split):
        part.append(full[i])
    var cursor = 0
    var total = 0
    var r = scan_chunked_resume(Span[UInt8, _](part), cursor, total, max_body)
    if r != CHUNKED_INCOMPLETE:
        return r
    return scan_chunked_resume(Span[UInt8, _](full), cursor, total, max_body)


def main() raises:
    var max_body = 1 << 20
    # Chunk-size line "1;" + 4094 extension bytes = 4096 content bytes.
    var line = String("1;")
    for _ in range(4094):
        line += "a"
    var body1 = _bytes(line + "\r\nZ\r\n0\r\n\r\n")
    var one_shot1 = scan_chunked_end(Span[UInt8, _](body1), 0, max_body)
    var split1 = _poll(body1, 4097, max_body)  # cut right after the CR

    # Trailer line of 5000 bytes after the last chunk.
    var tr = String("X: ")
    for _ in range(4997):
        tr += "b"
    var body2 = _bytes("0\r\n" + tr + "\r\n\r\n")
    var one_shot2 = scan_chunked_end(Span[UInt8, _](body2), 0, max_body)
    var split2 = _poll(body2, 3 + 4500, max_body)

    print("size line: one-shot", one_shot1, "split", split1)
    print("trailer:   one-shot", one_shot2, "split", split2)
    if one_shot1 != split1 or one_shot2 != split2:
        print(
            "BUG REPRODUCED: chunked verdict depends on segmentation"
            " (size line one-shot=" + String(one_shot1) + " split="
            + String(split1) + "; trailer one-shot=" + String(one_shot2)
            + " split=" + String(split2) + ")"
        )
        raise Error("H1-01")
    print("OK: chunked verdict is segmentation independent")
