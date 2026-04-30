"""Example 30: HMAC-signed cookies + typed sessions.

Demonstrates the session surface end-to-end:

- ``hmac_sha256`` derives a stable signing key from a passphrase
  (or use any 32-byte random secret you have).
- ``signed_cookie_encode`` / ``decode`` — the JWS-shape primitive.
- ``CookieSessionStore`` — stateless store; the entire session
  travels in the signed cookie.
- ``InMemorySessionStore`` — server-side table keyed by signed id.

Pure construction; no live network. Run:
    pixi run example-sessions
"""

from flare.crypto import hmac_sha256
from flare.http import (
    CookieSessionStore,
    InMemorySessionStore,
    Method,
    Request,
    Response,
    Cookie,
    SameSite,
    signed_cookie_decode,
    signed_cookie_encode,
)


def main() raises:
    print("=== flare Example 30: Signed cookies + sessions ===")
    print()

    # ── 1. Derive a signing key from a passphrase ──────────────────────────
    print("── 1. Derive signing key ──")
    var key = hmac_sha256(
        List[UInt8]("master-secret".as_bytes()),
        List[UInt8]("flare-session-v1".as_bytes()),
    )
    print(" key length :", len(key), "bytes (HMAC-SHA256 derived)")
    print()

    # ── 2. Stateless cookie session ────────────────────────────────────────
    print("── 2. CookieSessionStore (stateless) ──")
    var store = CookieSessionStore(key=key.copy(), cookie_name="sid")
    var token = store.encode("user=alice;role=admin")
    print(" cookie :", token)

    # Build a fake inbound Request that carries the cookie.
    var req = Request(method=Method.GET, url="/dashboard")
    req.headers.set("Cookie", String("sid=") + token)
    var s = store.load(req)
    print(" loaded :", s.value)
    print(" present :", s.present)
    print()

    # Tampered cookies are silently anonymous (Session.empty()).
    var bad = Request(method=Method.GET, url="/dashboard")
    bad.headers.set("Cookie", "sid=garbage.value")
    var s2 = store.load(bad)
    print(" tampered :", s2.present)
    print()

    # ── 3. Server-side session table ───────────────────────────────────────
    print("── 3. InMemorySessionStore (server-side) ──")
    var srv = InMemorySessionStore(key=key.copy())
    srv.insert("sid-42", "user=alice")
    var enc = srv.encode_id("sid-42")

    var req2 = Request(method=Method.GET, url="/dashboard")
    req2.headers.set("Cookie", String("flare_session=") + enc)
    var s3 = srv.load(req2)
    print(" loaded :", s3.value)

    _ = srv.remove("sid-42")
    var s4 = srv.load(req2)
    print(" after rem :", s4.present)
    print()

    # ── 4. Set the session cookie on a Response ─────────────────────────────
    print("── 4. Response.set_cookie with the signed cookie ──")
    var resp = Response(status=200)
    resp.set_cookie(
        Cookie(
            name="sid",
            value=token,
            path="/",
            secure=True,
            http_only=True,
            same_site=SameSite.LAX,
        )
    )
    print(" Set-Cookie :", resp.headers.get("set-cookie"))
    print()

    # ── 5. Manual decode ───────────────────────────────────────────────────
    print("── 5. Manual signed_cookie_decode ──")
    var decoded = signed_cookie_decode(token, key)
    var as_string = String(capacity=len(decoded) + 1)
    for b in decoded:
        as_string += chr(Int(b))
    print(" payload :", as_string)
    print()

    print("=== Example 30 complete ===")
