"""Example 13: Cookies with flare.http.Cookie / CookieJar.

Demonstrates:
  - Constructing a ``Cookie`` with ``secure``, ``http_only``, and
    ``same_site`` attributes
  - Adding cookies to a ``CookieJar`` and serialising back to a
    ``Cookie:`` request header
  - Parsing a client-side ``Cookie:`` header sent from a browser
  - Parsing a server-side ``Set-Cookie:`` header (with ``Max-Age``,
    ``Path``, ``Secure``, etc.)

Run:
    pixi run example-cookies
"""

from flare.http import (
    Cookie,
    CookieJar,
    SameSite,
    parse_cookie_header,
    parse_set_cookie_header,
)


def main() raises:
    print("=== flare Example 13: Cookies ===")
    print()

    # ── 1. Build a CookieJar and render a Cookie request header ──────────────
    print("── 1. CookieJar -> Cookie: header ──")
    var jar = CookieJar()
    jar.set(
        Cookie(
            "session",
            "abc123",
            secure=True,
            http_only=True,
            same_site=SameSite.STRICT,
        )
    )
    jar.set(Cookie("lang", "en"))
    print("  Cookie:", jar.to_request_header())
    print()

    # ── 2. Parse an incoming Cookie: header (as a server would) ─────────────
    print("── 2. Parse 'Cookie: id=42; lang=fr' ──")
    var pairs = parse_cookie_header("id=42; lang=fr")
    for i in range(len(pairs)):
        print("  " + pairs[i].name + " = " + pairs[i].value)
    print()

    # ── 3. Parse a Set-Cookie: header (as a client would) ───────────────────
    print("── 3. Parse 'Set-Cookie: id=42; Path=/; Max-Age=3600; Secure' ──")
    var set_cookie = parse_set_cookie_header(
        "id=42; Path=/; Max-Age=3600; Secure"
    )
    print("  name     :", set_cookie.name)
    print("  value    :", set_cookie.value)
    print("  path     :", set_cookie.path)
    print("  max_age  :", set_cookie.max_age)
    print("  secure   :", set_cookie.secure)
    print("  http_only:", set_cookie.http_only)
    print()

    print("=== Example 13 complete ===")
