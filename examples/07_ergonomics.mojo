"""Example 07 — High-level ergonomics API.

Demonstrates the high-level, requests-style interface:

  High-level HTTP
  ───────────────
  - Module-level one-shot helpers: get(), post(), put(), patch(), delete(), head()
  - String body → Content-Type: application/json set automatically
  - mojson.Value body → auto-serialised to JSON
  - HttpClient("https://api.example.com", BearerAuth("tok")) — base URL + auth
  - raise_for_status() to turn non-2xx into HttpError
  - Response.json() returning a mojson.Value
  - iter_bytes() for streaming response bodies

  Authentication
  ──────────────
  - BasicAuth  (RFC 7617 — base64-encoded username:password)
  - BearerAuth (RFC 6750 — Authorization: Bearer <token>)

  Context managers
  ────────────────
  - HttpClient as context manager
  - WsClient   as context manager

  High-level WebSocket
  ────────────────────
  - WsMessage: recv_message() returns a typed message wrapper
  - as_text() / as_bytes() / is_text

  Buffered I/O
  ────────────
  - BufReader[TlsStream] for efficient line-by-line reading

All network-dependent sections skip gracefully when offline.

Run:
    pixi run example-ergonomics
"""

from flare.http import (
    HttpClient,
    BasicAuth,
    BearerAuth,
    HttpError,
    TooManyRedirects,
    Status,
    get,
    post,
    put,
    patch,
    delete,
    head,
)
from flare.ws import WsClient, WsMessage
from flare.io import BufReader
from flare.tls import TlsStream, TlsConfig


# ─────────────────────────────────────────────────────────────────────────────
# Section 1: Module-level one-shot helpers
# ─────────────────────────────────────────────────────────────────────────────


def _demo_oneshot():
    print("── 1. Module-level one-shot helpers ──")
    try:
        var resp = get("http://httpbin.org/get")
        print("  get()    status:", resp.status, "ok:", resp.ok())

        # String body → Content-Type: application/json set automatically
        var resp2 = post("http://httpbin.org/post", '{"library": "flare"}')
        print("  post()   status:", resp2.status)

        var resp3 = put("http://httpbin.org/put", '{"action": "replace"}')
        print("  put()    status:", resp3.status)

        var resp4 = patch("http://httpbin.org/patch", '{"field": "patched"}')
        print("  patch()  status:", resp4.status)

        var resp5 = delete("http://httpbin.org/delete")
        print("  delete() status:", resp5.status)

        var resp6 = head("http://httpbin.org/get")
        print(
            "  head()   status:",
            resp6.status,
            "body:",
            len(resp6.body),
            "bytes",
        )
    except e:
        print("  [SKIP] network unavailable:", String(e))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Section 2: HttpClient with base_url
# ─────────────────────────────────────────────────────────────────────────────


def _demo_base_url():
    print("── 2. HttpClient with base URL (positional first arg) ──")
    try:
        # Positional base_url: HttpClient("url") — most natural syntax
        var client = HttpClient("http://httpbin.org")
        var resp = client.get("/get")  # relative path resolved against base
        print("  GET /get →", resp.status)

        # String body → JSON Content-Type automatic
        var resp2 = client.post("/post", '{"key": "value"}')
        print("  POST /post →", resp2.status)
    except e:
        print("  [SKIP] network unavailable:", String(e))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Section 3: raise_for_status()
# ─────────────────────────────────────────────────────────────────────────────


def _demo_raise_for_status():
    print("── 3. raise_for_status() ──")
    try:
        var resp = get("http://httpbin.org/status/404")
        try:
            resp.raise_for_status()
            print("  ERROR: expected HttpError for 404")
        except:
            print("  ✓ HttpError raised for 404 (expected)")
    except e:
        print("  [SKIP] network unavailable:", String(e))

    try:
        var resp = get("http://httpbin.org/get")
        resp.raise_for_status()  # no-op for 200
        print("  ✓ raise_for_status() no-op on 200")
    except e:
        print("  [SKIP] network unavailable:", String(e))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Section 4: Authentication
# ─────────────────────────────────────────────────────────────────────────────


def _demo_auth():
    print("── 4. Authentication ──")

    # BasicAuth — auth as first positional arg
    try:
        var client = HttpClient(BasicAuth("alice", "s3cr3t"))
        var resp = client.get("http://httpbin.org/basic-auth/alice/s3cr3t")
        print("  BasicAuth →", resp.status, "(expect 200)")
    except e:
        print("  [SKIP] BasicAuth network unavailable:", String(e))

    # BearerAuth — base_url + auth as two positional args
    try:
        var client = HttpClient(
            "http://httpbin.org", BearerAuth("my-token-abc")
        )
        var resp = client.get("/bearer")
        print("  BearerAuth + base_url →", resp.status, "(expect 200)")
    except e:
        print("  [SKIP] BearerAuth network unavailable:", String(e))

    print()


# ─────────────────────────────────────────────────────────────────────────────
# Section 5: iter_bytes() — streaming body
# ─────────────────────────────────────────────────────────────────────────────


def _demo_iter_bytes():
    print("── 5. iter_bytes() streaming ──")
    try:
        var resp = get("http://httpbin.org/bytes/1024")
        var total = 0
        for chunk in resp.iter_bytes(512):
            total += len(chunk)
        print("  streamed", total, "bytes in chunks of 512")
    except e:
        print("  [SKIP] network unavailable:", String(e))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Section 6: HttpClient context manager
# ─────────────────────────────────────────────────────────────────────────────


def _demo_http_context_manager():
    print("── 6. HttpClient context manager ──")
    try:
        with HttpClient() as c:
            var resp = c.get("http://httpbin.org/get")
            print("  context manager GET →", resp.status)
    except e:
        print("  [SKIP] network unavailable:", String(e))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Section 7: WsClient context manager + WsMessage
# ─────────────────────────────────────────────────────────────────────────────


def _demo_ws_high_level():
    print("── 7. WebSocket: context manager + WsMessage ──")
    try:
        with WsClient.connect("ws://echo.websocket.events") as ws:
            ws.send_text("hello from flare!")
            print("  Sent: 'hello from flare!'")

            # recv_message() wraps recv() in a typed WsMessage
            var found = False
            for _ in range(5):
                var msg = ws.recv_message()
                if msg.is_text and "hello from flare!" in msg.as_text():
                    print("  ✓ WsMessage echo:", msg.as_text())
                    found = True
                    break

            if not found:
                print("  echo not received within 5 messages")
    except e:
        print("  [SKIP] echo server unavailable:", String(e))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Section 8: BufReader — buffered line-by-line reading over TLS
# ─────────────────────────────────────────────────────────────────────────────


def _demo_buf_reader():
    print("── 8. BufReader over TLS ──")
    try:
        var stream = TlsStream.connect("example.com", 443, TlsConfig())
        _ = stream.write(
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            .as_bytes()
        )
        # Wrap stream in a 4096-byte buffer for efficient reads
        var reader = BufReader[TlsStream](stream^, capacity=4096)

        # Read the first 4 lines of the HTTP response header
        for _ in range(4):
            var line = reader.readline()
            print(" ", line, end="")
    except e:
        print("  [SKIP] TLS unavailable:", String(e))
    print()


# ─────────────────────────────────────────────────────────────────────────────


def main():
    print("=== flare Example 07: High-Level Ergonomics API ===")
    print()
    _demo_oneshot()
    _demo_base_url()
    _demo_raise_for_status()
    _demo_auth()
    _demo_iter_bytes()
    _demo_http_context_manager()
    _demo_ws_high_level()
    _demo_buf_reader()
    print("=== Example 07 complete ===")
