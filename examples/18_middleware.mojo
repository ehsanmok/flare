"""Example 18 - Middleware composition.

Middleware in flare is a ``Handler`` that wraps another ``Handler``.
No framework-specific ``Next`` callback, no mutable ``Context``, no
registration step. You nest structs, and the compiler inlines the
whole chain into one direct call sequence per request type.

This example builds a realistic production-shaped pipeline:

    RequestID              # assigns X-Request-ID before anything else runs
      └─ Logger            # every log line carries the trace id
          └─ Timing        # adds X-Response-Time-Us to response
              └─ Recover   # catches raises, returns 500
                  └─ RequireAuth[Bearer token]
                      └─ Router
                          ├─ GET  /              → home
                          ├─ GET  /secret        → secret
                          └─ GET  /boom          → raises on purpose

Read it outside-in: every request enters through RequestID and exits
with a trace id on the response. The order is deliberate; the comments
on ``main()`` walk through why each layer sits where it does.

Each wrapper is a generic ``[Inner: Handler]`` struct, so the compiler
monomorphises the full chain. At runtime there is no virtual dispatch
and no indirect call inside the stack.

Run:
    pixi run example-middleware
"""

from std.time import perf_counter_ns

from flare.http import (
    Router,
    Handler,
    Request,
    Response,
    Method,
    ok,
    bad_request,
    internal_error,
)


# ── Inner handlers ───────────────────────────────────────────────────────────


def home(req: Request) raises -> Response:
    return ok("home")


def secret(req: Request) raises -> Response:
    return ok("the cake is a lie")


def boom(req: Request) raises -> Response:
    """A handler that raises. Proves the Recover middleware works."""
    raise Error("handler blew up on purpose")


# ── Middleware layers ───────────────────────────────────────────────────────


@fieldwise_init
struct Logger[Inner: Handler](Handler):
    """Outermost layer. Always sees the final status, even on 5xx."""

    var inner: Self.Inner

    def serve(self, req: Request) raises -> Response:
        var rid = req.headers.get("X-Request-ID")
        print("  [log]", rid, ">>", req.method, req.url)
        var resp = self.inner.serve(req)
        print("  [log]", rid, "<<", req.method, req.url, "→", resp.status)
        return resp^


@fieldwise_init
struct RequestID[Inner: Handler](Handler):
    """Generate a trace id, inject it on both the request and the response.

    Real systems use something with more entropy; a wall-clock ns counter
    is enough to show the propagation pattern.
    """

    var inner: Self.Inner

    def serve(self, req: Request) raises -> Response:
        var rid = "req-" + String(perf_counter_ns())
        # Rebuild the request with an extra header so inner layers
        # (and the outer Logger) see the same id. ``Request`` is
        # Movable but not Copyable, so passing a mutated version down
        # the chain means constructing a new one; this is the one
        # Mojo-idiosyncratic bit of writing middleware today.
        var tagged = Request(
            method=req.method,
            url=req.url,
            body=req.body.copy(),
            version=req.version,
        )
        tagged.headers = req.headers.copy()
        tagged.headers.set("X-Request-ID", rid)
        var resp = self.inner.serve(tagged^)
        resp.headers.set("X-Request-ID", rid)
        return resp^


@fieldwise_init
struct Timing[Inner: Handler](Handler):
    """Record how long the inner chain took, as a response header."""

    var inner: Self.Inner

    def serve(self, req: Request) raises -> Response:
        var t0 = perf_counter_ns()
        var resp = self.inner.serve(req)
        var elapsed_us = (perf_counter_ns() - t0) // 1000
        resp.headers.set("X-Response-Time-Us", String(elapsed_us))
        return resp^


@fieldwise_init
struct Recover[Inner: Handler](Handler):
    """Turn an unhandled ``raise`` from the inner chain into a 500.

    Without this layer, a panicking handler would unwind all the way
    out of the reactor and end up as a generic 500 synthesised by the
    server. With it, the recovery is local to the handler stack and
    the Logger outer layer still sees the final response.
    """

    var inner: Self.Inner

    def serve(self, req: Request) raises -> Response:
        try:
            return self.inner.serve(req)
        except e:
            var resp = internal_error(String(e))
            resp.status = 500
            resp.reason = "Internal Server Error"
            return resp^


@fieldwise_init
struct RequireAuth[Inner: Handler](Handler):
    """Bearer-token check. Short-circuits to 401 on mismatch.

    Real code should compare tokens in constant time to avoid timing
    attacks. This ``==`` compare is fine for an example.
    """

    var inner: Self.Inner
    var expected_token: String

    def serve(self, req: Request) raises -> Response:
        var expected = String("Bearer ") + self.expected_token
        if req.headers.get("Authorization") == expected:
            return self.inner.serve(req)
        var resp = bad_request("unauthorized")
        resp.status = 401
        resp.reason = "Unauthorized"
        resp.headers.set("WWW-Authenticate", "Bearer")
        return resp^


# ── Main ────────────────────────────────────────────────────────────────────


def _req(method: String, url: String, auth: String = "") raises -> Request:
    var r = Request(method=method, url=url)
    if auth:
        r.headers.set("Authorization", auth)
    return r^


def main() raises:
    print("=" * 60)
    print("flare example 18 - Middleware composition")
    print("=" * 60)

    var router = Router()
    router.get("/", home)
    router.get("/secret", secret)
    router.get("/boom", boom)

    # Build the stack. Read outside-in; each line is one wrapper.
    #
    # Ordering rationale:
    #   1. RequestID outermost so every inner layer (including Logger)
    #      sees the trace id on both request and response. If Logger
    #      were outside RequestID, the request-side log line would
    #      fire before the id existed.
    #   2. Logger second so it still captures the final status of
    #      every request, including ones turned into 5xx by Recover.
    #   3. Timing wraps just the work that matters (auth + routing).
    #      Putting it outside Logger would include the ``print`` cost
    #      in the reported time.
    #   4. Recover below auth so auth failures stay plain 401s instead
    #      of being caught and reported as 500s.
    #   5. RequireAuth before Router so unauthenticated requests never
    #      reach a handler.
    var pipeline = RequestID(
        Logger(Timing(Recover(RequireAuth(router^, expected_token="s3cret"))))
    )

    # 1. Missing token: RequireAuth short-circuits. Logger sees the
    #    401 come back. RequestID and Timing still ran, so the client
    #    gets a trace id and a timing header even for a 401.
    print()
    print("--- missing token ---")
    var r1 = pipeline.serve(_req(Method.GET, "/secret"))
    print("  status     =", r1.status)
    print("  request id =", r1.headers.get("X-Request-ID"))
    print("  elapsed us =", r1.headers.get("X-Response-Time-Us"))
    print("  challenge  =", r1.headers.get("WWW-Authenticate"))

    # 2. Wrong token: same 401 path.
    print()
    print("--- wrong token ---")
    var r2 = pipeline.serve(_req(Method.GET, "/secret", "Bearer nope"))
    print("  status     =", r2.status)
    print("  request id =", r2.headers.get("X-Request-ID"))

    # 3. Correct token on protected path: full pipeline runs top to
    #    bottom, handler produces 200, every header is stamped on the
    #    way back out.
    print()
    print("--- correct token, protected path ---")
    var r3 = pipeline.serve(_req(Method.GET, "/secret", "Bearer s3cret"))
    print("  status     =", r3.status)
    print("  body       =", r3.text())
    print("  request id =", r3.headers.get("X-Request-ID"))
    print("  elapsed us =", r3.headers.get("X-Response-Time-Us"))

    # 4. Panicking handler: Recover catches the raise and turns it
    #    into a 500. Logger still sees the request and reports the
    #    500 status. The outer reactor would never see the raise.
    print()
    print("--- panicking handler (Recover catches the raise) ---")
    var r4 = pipeline.serve(_req(Method.GET, "/boom", "Bearer s3cret"))
    print("  status     =", r4.status)
    print("  body       =", r4.text())
    print("  request id =", r4.headers.get("X-Request-ID"))

    print()
    print("OK.")
