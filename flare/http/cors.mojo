"""``Cors[Inner]`` middleware (Cross-Origin Resource Sharing).

Implements the algorithmic core of the CORS protocol (Fetch
Living Standard paragraph 3.2 / RFC 6454):

- Inbound ``Origin`` is checked against ``allowed_origins``; mismatches
  produce a plain inner-handler response with no CORS headers.
- ``OPTIONS`` preflight requests with ``Access-Control-Request-Method``
  short-circuit before reaching the inner handler and respond
  with ``Access-Control-Allow-Methods`` /
  ``Access-Control-Allow-Headers`` / ``Access-Control-Max-Age``
  derived from the config.
- Simple (non-preflight) requests reach the inner handler; the
  middleware then attaches ``Access-Control-Allow-Origin`` to the
  outbound response.
- ``allow_credentials=True`` switches the wildcard ``*`` semantics
  off (the spec requires echoing the exact origin when credentials
  are sent).

The middleware is generic over the inner ``Handler`` so the CORS
layer is monomorphised into the handler chain.
"""

from std.collections import Optional

from .handler import Handler
from .request import Request
from .response import Response


struct CorsConfig(Copyable, Defaultable, Movable):
    """Configuration knobs for ``Cors[Inner]``.

    Default policy: deny everything (every list empty,
    ``allow_credentials=False``). Mutate via the named-arg
    constructor or by setting fields after default-construction.
    """

    var allowed_origins: List[String]
    """Origins permitted to send cross-origin requests. ``["*"]``
    is the wildcard. Empty list -> no origin allowed."""

    var allowed_methods: List[String]
    """Methods echoed in ``Access-Control-Allow-Methods`` on
    preflight. Defaults to ``["GET", "HEAD", "POST"]``."""

    var allowed_headers: List[String]
    """Headers echoed in ``Access-Control-Allow-Headers`` on
    preflight. Empty -> echoed from the inbound
    ``Access-Control-Request-Headers``."""

    var exposed_headers: List[String]
    """Headers attached to ``Access-Control-Expose-Headers`` on
    actual responses (so JS can read them)."""

    var max_age_seconds: Int
    """``Access-Control-Max-Age`` (seconds the preflight result is
    cacheable). Default 600."""

    var allow_credentials: Bool
    """When ``True``, ``Access-Control-Allow-Credentials: true`` is
    set; the wildcard origin is *not* used (spec requirement)."""

    def __init__(out self):
        self.allowed_origins = List[String]()
        self.allowed_methods = List[String]()
        self.allowed_methods.append("GET")
        self.allowed_methods.append("HEAD")
        self.allowed_methods.append("POST")
        self.allowed_headers = List[String]()
        self.exposed_headers = List[String]()
        self.max_age_seconds = 600
        self.allow_credentials = False

    @staticmethod
    def permissive() -> CorsConfig:
        """Wildcard-everything config — convenient for local dev /
        public APIs without credentials.
        """
        var c = CorsConfig()
        c.allowed_origins.append("*")
        c.allowed_methods.append("PUT")
        c.allowed_methods.append("DELETE")
        c.allowed_methods.append("PATCH")
        c.allowed_methods.append("OPTIONS")
        return c^


def _origin_allowed(origin: String, config: CorsConfig) -> Bool:
    if origin.byte_length() == 0:
        return False
    for i in range(len(config.allowed_origins)):
        var entry = config.allowed_origins[i]
        if entry == "*":
            return not config.allow_credentials
        if entry == origin:
            return True
    return False


def _join(parts: List[String], sep: String) -> String:
    var out = String("")
    for i in range(len(parts)):
        if i > 0:
            out += sep
        out += parts[i]
    return out^


struct Cors[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """CORS middleware. Wraps ``Inner`` with the spec'd preflight +
    response-header machinery."""

    var inner: Self.Inner
    var config: CorsConfig

    def __init__(out self):
        self.inner = Self.Inner()
        self.config = CorsConfig()

    def __init__(out self, var inner: Self.Inner, config: CorsConfig):
        self.inner = inner^
        self.config = config.copy()

    def _attach_origin(self, mut resp: Response, origin: String) raises:
        """Set ``Access-Control-Allow-Origin`` plus credential / vary
        related headers on ``resp``."""
        var allow_value: String
        if self.config.allow_credentials:
            allow_value = origin
            resp.headers.set("Access-Control-Allow-Credentials", "true")
        else:
            # If exactly one origin is configured (not wildcard), echo it.
            # Otherwise echo the request origin so caches can vary on
            # ``Origin``.
            if (
                len(self.config.allowed_origins) == 1
                and self.config.allowed_origins[0] != "*"
            ):
                allow_value = self.config.allowed_origins[0]
            elif (
                len(self.config.allowed_origins) == 1
                and self.config.allowed_origins[0] == "*"
            ):
                allow_value = "*"
            else:
                allow_value = origin
        resp.headers.set("Access-Control-Allow-Origin", allow_value)
        resp.headers.append("Vary", "Origin")
        if len(self.config.exposed_headers) > 0:
            resp.headers.set(
                "Access-Control-Expose-Headers",
                _join(self.config.exposed_headers, ", "),
            )

    def serve(self, req: Request) raises -> Response:
        var origin = req.headers.get("origin")
        var is_preflight = (
            req.method == "OPTIONS"
            and req.headers.get("access-control-request-method").byte_length()
            > 0
        )

        if origin.byte_length() == 0:
            # Same-origin or non-CORS request; pass through unchanged.
            return self.inner.serve(req)

        if not _origin_allowed(origin, self.config):
            if is_preflight:
                # Spec recommends 403, in practice 204 with no CORS
                # headers is also accepted; we go with 403 so curl
                # users see the rejection.
                var resp = Response(status=403)
                return resp^
            return self.inner.serve(req)

        if is_preflight:
            var resp = Response(status=204)
            self._attach_origin(resp, origin)
            resp.headers.set(
                "Access-Control-Allow-Methods",
                _join(self.config.allowed_methods, ", "),
            )
            var headers_value: String
            if len(self.config.allowed_headers) == 0:
                headers_value = req.headers.get(
                    "access-control-request-headers"
                )
            else:
                headers_value = _join(self.config.allowed_headers, ", ")
            if headers_value.byte_length() > 0:
                resp.headers.set("Access-Control-Allow-Headers", headers_value)
            resp.headers.set(
                "Access-Control-Max-Age", String(self.config.max_age_seconds)
            )
            return resp^

        # Simple / actual request.
        var resp = self.inner.serve(req)
        self._attach_origin(resp, origin)
        return resp^
