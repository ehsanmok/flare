"""Example 05 — HTTP client: GET, POST, PUT, PATCH, DELETE with flare.http.

Demonstrates:
  - Plain HTTP GET (http://)
  - HTTPS GET with JSON response (https://)
  - Response status, headers, and body decoding
  - POST, PUT, PATCH with JSON and binary bodies
  - DELETE and HEAD
  - Graceful skip when the network is unavailable

Run:
    pixi run example-http
"""

from flare.http import HttpClient, Status, get, post, put, patch, delete, head


def main():
    print("=== flare Example 05: HTTP Methods ===")
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

    # ── 5. PUT with JSON body ─────────────────────────────────────────────────
    print("── 5. PUT with JSON body ──")
    try:
        var resp = client.put(
            "https://httpbin.org/put",
            '{"action": "update"}',
        )
        print("  status :", resp.status, "ok:", resp.ok())
    except e:
        print("  [SKIP] network unavailable:", String(e))

    print()

    # ── 6. PATCH with JSON body ───────────────────────────────────────────────
    print("── 6. PATCH with JSON body ──")
    try:
        var resp = client.patch(
            "https://httpbin.org/patch",
            '{"field": "patched"}',
        )
        print("  status :", resp.status, "ok:", resp.ok())
        print("  body snippet :", resp.text()[:120], "...")
    except e:
        print("  [SKIP] network unavailable:", String(e))

    print()

    # ── 7. DELETE ─────────────────────────────────────────────────────────────
    print("── 7. DELETE ──")
    try:
        var resp = client.delete("https://httpbin.org/delete")
        print("  status :", resp.status, "ok:", resp.ok())
    except e:
        print("  [SKIP] network unavailable:", String(e))

    print()

    # ── 8. HEAD (no body returned) ────────────────────────────────────────────
    print("── 8. HEAD (no body) ──")
    try:
        var resp = client.head("http://httpbin.org/get")
        print("  status :", resp.status, "body bytes:", len(resp.body))
    except e:
        print("  [SKIP] network unavailable:", String(e))

    print()

    # ── 9. Module-level one-shot patch() ─────────────────────────────────────
    print("── 9. Module-level patch() ──")
    try:
        var resp = patch("https://httpbin.org/patch", '{"one-shot": true}')
        print("  status :", resp.status, "ok:", resp.ok())
    except e:
        print("  [SKIP] network unavailable:", String(e))

    print()
    print("=== Example 05 complete ===")
