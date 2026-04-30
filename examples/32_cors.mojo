"""Example 32: CORS middleware.

Wraps an inner handler with ``Cors`` so cross-origin browsers can
talk to the API per RFC 6454 / Fetch:

- Preflight ``OPTIONS`` short-circuits with the right
  ``Access-Control-Allow-*`` headers and 204.
- Simple cross-origin requests get
  ``Access-Control-Allow-Origin`` attached.
- Disallowed origins fall through without CORS headers; preflight
  from a disallowed origin gets 403.

Pure construction — no live network. Run:
    pixi run example-cors
"""

from flare.http import (
    Cors,
    CorsConfig,
    Handler,
    Method,
    Request,
    Response,
)


@fieldwise_init
struct ApiHandler(Copyable, Defaultable, Handler, Movable):
    """Tiny JSON API; returns a constant payload."""

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8](String('{"users":["alice","bob"]}').as_bytes())
        resp.headers.set("Content-Type", "application/json")
        return resp^


def main() raises:
    print("=== flare Example 32: CORS middleware ===")
    print()

    # ── Permissive (``*``) — fastest setup ─────────────────────────────
    print("── 1. Permissive CORS ──")
    var permissive = Cors(ApiHandler(), CorsConfig.permissive())
    var req = Request(method=Method.GET, url="/api/users")
    req.headers.set("Origin", "https://app.example.com")
    var resp = permissive.serve(req)
    print(
        "  ACAO:",
        resp.headers.get("access-control-allow-origin"),
    )
    print()

    # ── Allowlist + credentials (production shape) ─────────────────────
    print("── 2. Allowlist + credentials ──")
    var cfg = CorsConfig()
    cfg.allowed_origins.append("https://app.example.com")
    cfg.allowed_origins.append("https://admin.example.com")
    cfg.allow_credentials = True
    cfg.allowed_methods.append("GET")
    cfg.allowed_methods.append("POST")
    cfg.allowed_methods.append("DELETE")
    cfg.allowed_headers.append("Content-Type")
    cfg.allowed_headers.append("Authorization")
    cfg.exposed_headers.append("X-Total-Count")
    cfg.max_age_seconds = 600
    var prod = Cors(ApiHandler(), cfg)

    # ── Preflight from an allowed origin ─────────────────────────────
    print("  preflight from app.example.com:")
    var preflight = Request(method=Method.OPTIONS, url="/api/users")
    preflight.headers.set("Origin", "https://app.example.com")
    preflight.headers.set("Access-Control-Request-Method", "DELETE")
    preflight.headers.set("Access-Control-Request-Headers", "Authorization")
    var pre = prod.serve(preflight)
    print("    status :", pre.status)
    print(
        "    ACAO   :",
        pre.headers.get("access-control-allow-origin"),
    )
    print(
        "    ACAM   :",
        pre.headers.get("access-control-allow-methods"),
    )
    print(
        "    ACAH   :",
        pre.headers.get("access-control-allow-headers"),
    )
    print(
        "    Max-Age:",
        pre.headers.get("access-control-max-age"),
    )
    print()

    # ── Disallowed origin ────────────────────────────────────────────
    print("  preflight from evil.example.com:")
    var bad = Request(method=Method.OPTIONS, url="/api/users")
    bad.headers.set("Origin", "https://evil.example.com")
    bad.headers.set("Access-Control-Request-Method", "DELETE")
    var bresp = prod.serve(bad)
    print("    status :", bresp.status)
    print()

    # ── Simple GET from allowed origin ─────────────────────────────────
    print("  simple GET from app.example.com:")
    var sreq = Request(method=Method.GET, url="/api/users")
    sreq.headers.set("Origin", "https://app.example.com")
    var s = prod.serve(sreq)
    print("    status :", s.status)
    print(
        "    ACAO   :",
        s.headers.get("access-control-allow-origin"),
    )
    print(
        "    ACEH   :",
        s.headers.get("access-control-expose-headers"),
    )
    print(
        "    ACAC   :",
        s.headers.get("access-control-allow-credentials"),
    )
    print()

    print("=== Example 32 complete ===")
