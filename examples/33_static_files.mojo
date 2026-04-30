"""Example 33: Static file server with HEAD + Range support.

Wires ``FileServer`` to a temporary directory and demonstrates:

- ``GET /index.html`` and ``HEAD /index.html``.
- ``Range: bytes=0-9`` returning 206 + ``Content-Range``.
- Path traversal (``..``) rejection.
- 404 for missing files; 405 for non-GET/HEAD methods.

Pure construction — no live network. Run:
    pixi run example-static-files
"""

from std.os import mkdir, path as os_path

from flare.http import (
    FileServer,
    Method,
    Request,
)


def _ensure(p: String) raises:
    if not os_path.exists(p):
        mkdir(p)


def _write(p: String, body: String) raises:
    var f = open(p, "w")
    f.write(body)
    f.close()


def main() raises:
    print("=== flare Example 33: Static file server ===")
    print()

    var root = String("/tmp/flare_static_demo")
    _ensure(root)
    _write(root + "/index.html", "<!doctype html><h1>flare static</h1>")
    _write(
        root + "/big.txt",
        "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    )

    var fs = FileServer.new(root)

    print("── 1. GET /index.html ──")
    var req = Request(method=Method.GET, url="/index.html")
    var resp = fs.serve(req)
    print("  status      :", resp.status)
    print("  Content-Type:", resp.headers.get("content-type"))
    print("  Accept-Ranges:", resp.headers.get("accept-ranges"))
    print("  body length :", len(resp.body))
    print()

    print("── 2. HEAD /index.html ──")
    var head = Request(method=Method.HEAD, url="/index.html")
    var hresp = fs.serve(head)
    print("  status      :", hresp.status)
    print("  body length :", len(hresp.body), " (HEAD)")
    print(
        "  Content-Length:",
        hresp.headers.get("content-length"),
    )
    print()

    print("── 3. GET /big.txt with Range: bytes=10-19 ──")
    var ranged = Request(method=Method.GET, url="/big.txt")
    ranged.headers.set("Range", "bytes=10-19")
    var rresp = fs.serve(ranged)
    print("  status        :", rresp.status)
    print("  Content-Range :", rresp.headers.get("content-range"))
    print("  body          :", rresp.text())
    print()

    print("── 4. GET /missing.png ──")
    var miss = Request(method=Method.GET, url="/missing.png")
    print("  status :", fs.serve(miss).status)
    print()

    print("── 5. Traversal attempt ──")
    var trv = Request(method=Method.GET, url="/../etc/passwd")
    print("  status :", fs.serve(trv).status)
    print()

    print("── 6. PUT /index.html ──")
    var put = Request(method=Method.PUT, url="/index.html")
    var presp = fs.serve(put)
    print("  status :", presp.status)
    print("  Allow  :", presp.headers.get("allow"))
    print()

    print("=== Example 33 complete ===")
