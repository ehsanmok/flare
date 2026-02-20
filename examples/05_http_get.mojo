"""Example 05 — HTTP GET and POST requests with flare.http.

Demonstrates:
  - Plain HTTP GET (http://)
  - HTTPS GET with JSON response (https://)
  - Response status, headers, and body decoding
  - POST with a JSON body and Content-Type header
  - Graceful skip when the network is unavailable
"""

from flare.http import HttpClient, Status


def main():
    print("=== flare Example 05: HTTP GET / POST ===")
    print()

    var client = HttpClient()

    # ── 1. Plain HTTP GET ─────────────────────────────────────────────────────
    print("── 1. HTTP GET (plain) ──")
    try:
        var resp = client.get("http://httpbin.org/get")
        print("  status :", resp.status, "ok:", resp.ok())
        print("  Content-Type :", resp.headers.get("content-type"))
        print("  body snippet :", resp.text()[:80], "...")
    except e:
        print("  [SKIP] network unavailable:", String(e))

    print()

    # ── 2. HTTPS GET → JSON ───────────────────────────────────────────────────
    print("── 2. HTTPS GET → JSON ──")
    try:
        var resp = client.get("https://httpbin.org/json")
        print("  status :", resp.status, "ok:", resp.ok())
        print("  Content-Type :", resp.headers.get("content-type"))
        print("  body snippet :", resp.text()[:80], "...")
    except e:
        print("  [SKIP] network unavailable:", String(e))

    print()

    # ── 3. 404 response is not ok() ───────────────────────────────────────────
    print("── 3. 404 not found ──")
    try:
        var resp = client.get("http://httpbin.org/status/404")
        print("  status :", resp.status, "ok:", resp.ok())
        print("  ok() is False → expected:", not resp.ok())
    except e:
        print("  [SKIP] network unavailable:", String(e))

    print()

    # ── 4. POST with JSON body ────────────────────────────────────────────────
    # String body → Content-Type: application/json set automatically
    print("── 4. POST with JSON body ──")
    try:
        var resp = client.post(
            "https://httpbin.org/post",
            '{"hello": "flare"}',
        )
        print("  status :", resp.status, "ok:", resp.ok())
        print("  body snippet :", resp.text()[:120], "...")
    except e:
        print("  [SKIP] network unavailable:", String(e))

    print()
    print("=== Example 05 complete ===")
