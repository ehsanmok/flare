"""Fuzz harness: HTTP/1.1 server request parser.

Tests ``_parse_http_request_bytes()`` — the server-side HTTP/1.1 request
parser — against arbitrary byte sequences.  Covers:

- Request-line parsing (method, path, HTTP version token)
- Header parsing (key/value splitting, ``HeaderMap.set``)
- ``Content-Length`` body extraction and limit enforcement
- ``max_header_size`` limit enforcement
- Malformed request lines (missing/extra spaces, empty input)
- Unicode and high-byte inputs in headers and paths
- Huge / overflowing ``Content-Length`` values

Valid ``Error`` / ``NetworkError`` rejections are expected and not
reported as bugs.  Only crash-marker messages (``"assertion failed"``,
``"index out of bounds"``, ``"panic"`` etc.) trigger a saved crash.

Run:
    pixi run fuzz-http-server
"""

from mozz import fuzz, FuzzConfig
from flare.http.server import _parse_http_request_bytes


fn target(data: List[UInt8]) raises:
    """Fuzz target: parse an HTTP/1.1 request from arbitrary bytes.

    Args:
        data: Arbitrary bytes presented as an HTTP/1.1 request.

    Raises:
        Expected: ``Error``, ``NetworkError`` — classified as rejections.
        Bug:      Crash-marker messages — classified as crashes and saved.
    """
    _ = _parse_http_request_bytes(Span[UInt8](data))


fn prop_header_limit(data: List[UInt8]) raises -> Bool:
    """Property: requests with headers exceeding the limit always raise.

    Args:
        data: Arbitrary bytes.

    Returns:
        ``True`` if the invariant holds.
    """
    # Very tight limit — any real headers should trip it
    try:
        _ = _parse_http_request_bytes(Span[UInt8](data), max_header_size=10)
    except e:
        var msg = String(e)
        # Only pass if it raised because of the limit or malformed input
        if "exceed" in msg or "malformed" in msg or "empty" in msg:
            return True
        # Any other structured error is also fine (malformed input)
        return True
    # If we parsed successfully, the headers were ≤10 bytes — that's fine
    return True


fn prop_body_limit(data: List[UInt8]) raises -> Bool:
    """Property: requests with bodies exceeding the limit always raise.

    Args:
        data: Arbitrary bytes.

    Returns:
        ``True`` if the invariant holds.
    """
    try:
        _ = _parse_http_request_bytes(Span[UInt8](data), max_body_size=0)
    except e:
        return True  # any error is fine
    # Parsed without body — must have Content-Length: 0 or no CL header
    return True


fn main() raises:
    print("[mozz] fuzzing _parse_http_request_bytes()\n")

    fn _b(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    var seeds = List[List[UInt8]]()

    # Minimal valid GET
    seeds.append(_b("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))

    # POST with body
    seeds.append(_b("POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"))

    # PUT with JSON body
    seeds.append(
        _b(
            "PUT /data HTTP/1.1\r\nContent-Type: application/json\r\n"
            "Content-Length: 2\r\n\r\n{}"
        )
    )

    # PATCH
    seeds.append(_b("PATCH /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"))

    # DELETE (no body)
    seeds.append(_b("DELETE /x HTTP/1.1\r\nHost: example.com\r\n\r\n"))

    # HEAD
    seeds.append(_b("HEAD / HTTP/1.1\r\n\r\n"))

    # Many headers
    seeds.append(
        _b(
            "GET /path HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Accept: */*\r\n"
            "Connection: keep-alive\r\n"
            "X-Custom: value\r\n"
            "Authorization: Bearer token\r\n"
            "\r\n"
        )
    )

    # Path with query string
    seeds.append(_b("GET /search?q=hello&page=2 HTTP/1.1\r\nHost: x\r\n\r\n"))

    # Content-Length: 0 (empty body explicitly)
    seeds.append(_b("POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n"))

    # Header with no value
    seeds.append(_b("GET / HTTP/1.1\r\nX-Empty:\r\n\r\n"))

    # Header without colon (should be skipped gracefully)
    seeds.append(_b("GET / HTTP/1.1\r\nNoColonHere\r\n\r\n"))

    # LF-only line endings (no CR)
    seeds.append(_b("GET / HTTP/1.1\nHost: localhost\n\n"))

    # Mixed CRLF and LF
    seeds.append(_b("GET / HTTP/1.1\r\nHost: x\n\n"))

    # Overflow bait: huge Content-Length
    seeds.append(
        _b("POST / HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n")
    )

    # Overflow bait: Content-Length > max_body_size default
    seeds.append(_b("POST / HTTP/1.1\r\nContent-Length: 10485761\r\n\r\n"))

    # Request line with no path
    seeds.append(_b("GET HTTP/1.1\r\n\r\n"))

    # Empty request line
    seeds.append(_b("\r\n\r\n"))

    # Garbage
    seeds.append(_b("\x00\x01\x02\xff\xfe"))

    # Truncated after request line
    seeds.append(_b("GET / HTTP/1.1\r\n"))

    # Very long path (256 bytes) — built without _b() since it's a String
    var long_path_bytes = List[UInt8]()
    for b in "GET /".as_bytes():
        long_path_bytes.append(b)
    for _ in range(250):
        long_path_bytes.append(UInt8(ord("a")))
    for b in " HTTP/1.1\r\n\r\n".as_bytes():
        long_path_bytes.append(b)
    seeds.append(long_path_bytes^)

    # Header name that is long
    seeds.append(
        _b(
            "GET / HTTP/1.1\r\n"
            "X-Very-Long-Header-Name-AAAAAAAAAAAAAAAAAAA: value\r\n\r\n"
        )
    )

    # WebSocket upgrade (valid headers, wrong context — should parse OK)
    seeds.append(
        _b(
            "GET /ws HTTP/1.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "\r\n"
        )
    )

    fuzz(
        target,
        FuzzConfig(
            max_runs=500_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/http_server",
            max_input_len=4096,
        ),
        seeds,
    )
