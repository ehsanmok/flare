"""Example 21 — Pre-encoded literal responses via ``serve_static``.

``HttpServer.serve_static(resp)`` is the fastest path flare offers:
the reactor parses every request only far enough to find the
``\\r\\n\\r\\n`` terminator and honour Content-Length, then ``memcpy``s
a pre-encoded response buffer into the write queue. No ``Request``
struct, no handler call, no response serialisation per request.

Intended for TFB plaintext and other workloads where the body is
genuinely fixed. This example builds the same wire-form bytes as the
TFB plaintext spec:

    HTTP/1.1 200 OK
    Content-Type: text/plain; charset=utf-8
    Content-Length: 13
    Connection: keep-alive  (or close, chosen by the reactor)

    Hello, World!

The example prints the byte layout and declares the port the server
would bind to; it does **not** actually run the reactor loop (that
would block the test runner). For a live benchmark harness see
``benchmark/baselines/flare/`` and the v0.3.x TFB plaintext shape.

Run:
    pixi run example-static-response
"""

from flare.http import HttpServer, precompute_response
from flare.net import SocketAddr


def main() raises:
    print("=" * 60)
    print("flare example 21 — serve_static (pre-encoded responses)")
    print("=" * 60)

    var hello = precompute_response(
        status=200,
        content_type="text/plain; charset=utf-8",
        body="Hello, World!",
    )

    print("body length         =", hello.body_length)
    print("keep-alive wire size =", len(hello.keepalive_bytes), "bytes")
    print("close wire size      =", len(hello.close_bytes), "bytes")

    # Decode the keep-alive wire form as ASCII so the example output
    # makes the byte layout obvious.
    var preview = String(capacity=len(hello.keepalive_bytes) + 1)
    for b in hello.keepalive_bytes:
        if b == 13:
            preview += "\\r"
        elif b == 10:
            preview += "\\n\n"
        else:
            preview += chr(Int(b))
    print()
    print("keep-alive wire form (escaped):")
    print("---8<---")
    print(preview)
    print("---8<---")

    # Bind the server but do not call serve_static — that loops forever
    # and would block the test runner. Showing the shape is enough for
    # the example.
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    print()
    print("(HttpServer.serve_static(hello) would run the reactor loop here)")
    print("bound to           =", srv.local_addr().port)
    srv.close()

    print()
    print("OK.")
