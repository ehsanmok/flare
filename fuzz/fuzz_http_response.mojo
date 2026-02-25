"""Fuzz harness: HTTP/1.1 response parser.

Tests the internal ``_parse_http_response()`` pipeline — the most complex
parser in flare — against arbitrary byte sequences.  Covers:

- Status-line parsing (``_parse_status_line``)
- Header parsing (key/value splitting, ``HeaderMap.append``)
- ``Content-Length`` body extraction (``_parse_int``)
- ``Transfer-Encoding: chunked`` body assembly (``_parse_hex``, ``_decode_chunked``)
- Connection-close body (remainder-of-buffer path)

Valid ``NetworkError`` / ``Error`` rejections are expected and not reported
as bugs.  Only crash-marker messages (``"assertion failed"``, ``"index out
of bounds"``, ``"panic"`` etc.) trigger a saved crash.

Run:
    pixi run fuzz-http-response
"""

from mozz import fuzz, FuzzConfig

# _parse_http_response is a module-level fn — import the whole module and
# call it through the public function alias exposed in the test helpers.
# Since it's not re-exported from __init__, we test it via a thin adapter.
from flare.http.client import _parse_http_response


fn target(data: List[UInt8]) raises:
    """Fuzz target: parse a raw HTTP/1.1 response from arbitrary bytes.

    Args:
        data: Arbitrary bytes presented as a server response.

    Raises:
        Expected: ``NetworkError``, ``Error`` — classified as rejections.
        Bug:      Crash-marker messages — classified as crashes and saved.
    """
    _ = _parse_http_response(data)


fn main() raises:
    print("[mozz] fuzzing _parse_http_response()...")

    fn _b(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    var seeds = List[List[UInt8]]()

    # Minimal valid 200 OK (Content-Length body)
    seeds.append(_b("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))

    # 204 No Content (no body)
    seeds.append(_b("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))

    # Chunked body
    seeds.append(
        _b(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding:"
            " chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        )
    )

    # Multi-chunk
    seeds.append(
        _b(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding:"
            " chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"
        )
    )

    # Multiple headers
    seeds.append(
        _b(
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 2\r\n"
            "X-Custom: value\r\n"
            "\r\n{}"
        )
    )

    # Redirect (no body)
    seeds.append(
        _b(
            "HTTP/1.1 301 Moved Permanently\r\nLocation:"
            " https://example.com/\r\n\r\n"
        )
    )

    # Empty body (connection-close path)
    seeds.append(_b("HTTP/1.1 200 OK\r\n\r\n"))

    # Edge: no reason phrase
    seeds.append(_b("HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n"))

    # Edge: very long header value (but valid — 20 chars)
    seeds.append(
        _b(
            "HTTP/1.1 200 OK\r\nX-Padding:"
            " AAAAAAAAAAAAAAAAAAAA\r\nContent-Length: 0\r\n\r\n"
        )
    )

    # Edge: chunked with chunk extensions (;name=value)
    seeds.append(
        _b(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding:"
            " chunked\r\n\r\n5;ext=val\r\nhello\r\n0\r\n\r\n"
        )
    )

    # Overflow bait: huge Content-Length
    seeds.append(
        _b("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n")
    )

    # Overflow bait: huge chunk size
    seeds.append(
        _b(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding:"
            " chunked\r\n\r\nffffffffffffffff\r\n"
        )
    )

    # Missing header terminator
    seeds.append(_b("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"))

    # Truncated status line
    seeds.append(_b("HTTP/"))

    # Garbage
    seeds.append(_b("\x00\x01\x02\x03\xff\xfe"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=500_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/http_response",
            max_input_len=2048,
        ),
        seeds,
    )
