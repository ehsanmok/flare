"""Example 27: Request / Response cookies.

Demonstrates the cookie ergonomics on the server side:

- ``Request.cookies()`` — parse all incoming ``Cookie:`` headers into
  a ``CookieJar``.
- ``Request.cookie(name)`` / ``has_cookie(name)`` — convenience
  lookups without an intermediate jar.
- ``Response.set_cookie(c)`` — emit a ``Set-Cookie:`` header per
  cookie (RFC 6265 paragraph 3 forbids comma-folding).
- ``Cookies`` extractor — registerable as a field of an
  ``Extracted[H]`` handler, axum-style.

Pure construction; no live network. Run:
    pixi run example-request-cookies
"""

from flare.http import (
    Cookie,
    Cookies,
    Method,
    Request,
    Response,
    SameSite,
)


def main() raises:
    print("=== flare Example 27: Request / Response cookies ===")
    print()

    # ── 1. Synthesise an incoming request with two cookies ──────────────────
    print("── 1. Read cookies off Request ──")
    var req = Request(method=Method.GET, url="/dashboard")
    req.headers.set("Cookie", "session=abc123; theme=dark")
    var jar = req.cookies()
    print(" jar size :", jar.len())
    print(" session :", jar.get("session"))
    print(" theme :", jar.get("theme"))
    print(" helper :", req.cookie("session"))
    print(" has_user :", req.has_cookie("user"))
    print()

    # ── 2. Set a fresh cookie on the response ───────────────────────────────
    print("── 2. Response.set_cookie(...) ──")
    var resp = Response(status=200)
    resp.set_cookie(
        Cookie(
            name="session",
            value="def456",
            path="/",
            max_age=3600,
            secure=True,
            http_only=True,
            same_site=SameSite.STRICT,
        )
    )
    resp.set_cookie(Cookie(name="theme", value="light", path="/"))
    var lines = resp.headers.get_all("set-cookie")
    print(" emitted :", len(lines), "Set-Cookie line(s)")
    for i in range(len(lines)):
        print(" " + lines[i])
    print()

    # ── 3. Cookies extractor ───────────────────────────────────────────────
    print("── 3. Cookies extractor ──")
    var ck = Cookies.extract(req)
    print(" via extractor.value.get('theme') =", ck.value.get("theme"))
    print()

    print("=== Example 27 complete ===")
