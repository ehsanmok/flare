# PLATFORM: any
"""APP-21: CORS allowlist decision depends on list order under credentials.

Lean: Flare.Bugs.APP_21.order_dependent, Flare.Bugs.APP_21.violates_spec
(counterexample) and Flare.Bugs.APP_21.fixed_meets_spec (fix meets spec).
flare/http/cors.mojo:89-98 @59bda50.

Expected: with allow_credentials=True and allowed_origins = ["*",
"https://app.example.com"], a request from https://app.example.com is
allowed (explicitly listed; "*" just cannot authorise credentialed
requests), exactly as with the list in the other order.
Actual: _origin_allowed returns `not allow_credentials` (False) as soon
as it reaches "*", so the listed origin gets no CORS headers; with the
list reversed it is allowed.

Minimal fix: in _origin_allowed, on entry "*" return True only when
credentials are off, otherwise `continue` scanning.
"""

from flare.http import Cors, CorsConfig, Handler, Method, Request, Response


@fieldwise_init
struct _Echo(Copyable, Defaultable, Handler):
    var _p: UInt8

    def __init__(out self):
        self._p = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8]("ok".as_bytes())
        return resp^


def _acao(first: String, second: String) raises -> String:
    var cfg = CorsConfig()
    cfg.allowed_origins.append(first)
    cfg.allowed_origins.append(second)
    cfg.allow_credentials = True
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", "https://app.example.com")
    var resp = mw.serve(req)
    return resp.headers.get("access-control-allow-origin")


def main() raises:
    var star_first = _acao("*", "https://app.example.com")
    var star_last = _acao("https://app.example.com", "*")
    if star_first != "https://app.example.com":
        print(
            "BUG REPRODUCED: with credentials, ['*', origin] gives ACAO '"
            + star_first
            + "' but [origin, '*'] gives '"
            + star_last
            + "'"
        )
        raise Error("APP-21")
    print("OK: listed origin allowed in both orders:", star_first, star_last)
