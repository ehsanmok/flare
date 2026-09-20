"""Pull a body with ``get_streaming`` and report what arrived.

The interop smoke test drives this against the ``flare_mc`` server on
each wire it serves. It exists because every in-tree test of the
streaming client runs against a single-process server inside the same
binary; nothing exercised the reader against a separately built,
multi-worker server across a real socket, which is where framing and
flow-control mistakes actually surface.

Prints one machine-readable line on success::

    wire=h2 bytes=1048576 pulls=17

and exits non-zero on any mismatch, so the caller can assert on the
whole line rather than parsing a report.

Environment:
    FLARE_STREAM_URL   : URL to fetch (required).
    FLARE_STREAM_EXPECT: Exact body size to require, in bytes.
    FLARE_STREAM_WIRE  : Wire name to require ("http/1.1", "h2", "h3").
    FLARE_STREAM_H2C   : "1" speaks HTTP/2 prior knowledge on ``http://``.
    FLARE_STREAM_TLS   : "1" skips certificate verification, for the
                         self-signed cert the smoke test generates.
"""

from std.os import getenv

from flare.http import HttpClient
from flare.tls import TlsConfig


comptime _PULL_BYTES: Int = 65536


def main() raises:
    var url = getenv("FLARE_STREAM_URL")
    if url == "":
        raise Error("stream_client: FLARE_STREAM_URL is not set")
    var want_bytes = atol(getenv("FLARE_STREAM_EXPECT", "0"))
    var want_wire = getenv("FLARE_STREAM_WIRE")
    var h2c = getenv("FLARE_STREAM_H2C") == "1"

    var client: HttpClient
    if getenv("FLARE_STREAM_TLS") == "1":
        client = HttpClient(TlsConfig.insecure(), prefer_h2c=h2c)
    else:
        client = HttpClient(prefer_h2c=h2c)

    var r = client.get_streaming(url)
    r.raise_for_status()

    var total = 0
    var pulls = 0
    while True:
        var chunk = r.read_chunk(_PULL_BYTES)
        if len(chunk) == 0:
            break
        total += len(chunk)
        pulls += 1
    r.close()

    print(
        "wire=" + r.protocol(),
        "bytes=" + String(total),
        "pulls=" + String(pulls),
    )

    if want_wire != "" and r.protocol() != want_wire:
        raise Error(
            "stream_client: expected wire "
            + want_wire
            + ", got "
            + r.protocol()
        )
    if want_bytes > 0 and total != want_bytes:
        raise Error(
            "stream_client: expected "
            + String(want_bytes)
            + " bytes, got "
            + String(total)
        )
