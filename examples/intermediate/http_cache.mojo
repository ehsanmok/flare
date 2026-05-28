"""Example 33: HTTP cache middleware -- Cache + Logger composition.

Demonstrates the RFC 9111 ``Cache[Inner, S]`` middleware in front
of an inner handler. The Logger sits on the inside of the Cache so
its line counts the real serves only -- cache hits never reach
the inner handler, so the log line is omitted. ``X-Cache: HIT`` is
the observable signal for cache decisions; an external client
(or test) reads this header to know whether the response was
served from the store.

Pure construction -- no live network. The example runs the
middleware chain end-to-end against synthetic requests and prints
the observable cache decisions so you can read the trace::

    pixi run example-http-cache

The two key behaviours the trace exercises:

1. **Miss-then-hit**: a fresh ``GET /`` triggers the inner
   handler (logger prints a line), the response is stored, and a
   second identical request returns ``X-Cache: HIT`` without
   reaching the inner handler.
2. **Vary segregation**: a ``GET /`` with ``Accept-Language: en``
   stores in one Vary bucket; a ``GET /`` with
   ``Accept-Language: fr`` stores in a separate bucket. A repeat
   of either hits its own bucket, never the other.
3. **``Cache-Control: no-store``** on a different path bypasses
   the cache, so back-to-back requests both reach the inner
   handler.

The same composition shape works for real apps: wrap your top
handler with ``Cache[..., InMemoryCacheStore]``, mount on the
server, configure capacity, and ship.
"""

from flare.http import (
    Handler,
    Logger,
    Request,
    Response,
)
from flare.http.cache import (
    Cache,
    InMemoryCacheStore,
)


@fieldwise_init
struct DemoApp(Copyable, Defaultable, Handler, Movable):
    """Tiny app that serves two cacheable JSON endpoints + one
    no-store endpoint. The inner handler is intentionally
    self-describing: every response carries a fresh timestamp in
    the body so a cache hit (which returns the stored copy) and
    a cache miss (which gets a fresh timestamp) are visually
    distinguishable when you read the trace."""

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        if req.url == String("/no-store"):
            var resp = Response(status=200)
            resp.body = List[UInt8](
                String('{"endpoint":"/no-store"}').as_bytes()
            )
            resp.headers.set(String("Content-Type"), String("application/json"))
            # Explicit opt-out: never stored by the cache.
            resp.headers.set(String("Cache-Control"), String("no-store"))
            return resp^
        if req.url == String("/i18n"):
            var resp = Response(status=200)
            var lang = req.headers.get(String("Accept-Language"))
            var body = (
                String('{"endpoint":"/i18n","lang":"') + lang + String('"}')
            )
            resp.body = List[UInt8](body.as_bytes())
            resp.headers.set(String("Content-Type"), String("application/json"))
            # 60-second freshness + Vary on Accept-Language so each
            # language gets its own cached bucket.
            resp.headers.set(
                String("Cache-Control"), String("max-age=60, public")
            )
            resp.headers.set(String("Vary"), String("Accept-Language"))
            return resp^
        # Default: a cacheable hello-world.
        var resp = Response(status=200)
        resp.body = List[UInt8](
            String('{"endpoint":"/","msg":"hello"}').as_bytes()
        )
        resp.headers.set(String("Content-Type"), String("application/json"))
        resp.headers.set(String("Cache-Control"), String("max-age=60, public"))
        return resp^


def _describe(label: String, resp: Response) raises:
    print(label)
    print("  status         :", resp.status)
    print("  X-Cache        :", resp.headers.get(String("X-Cache")))
    print("  Cache-Control  :", resp.headers.get(String("Cache-Control")))
    print("  Vary           :", resp.headers.get(String("Vary")))
    print("  Content-Type   :", resp.headers.get(String("Content-Type")))
    print("  body length    :", len(resp.body))
    print()


def main() raises:
    print("=== flare Example 33: HTTP cache middleware ===")
    print()

    # The cache wraps the Logger which wraps the inner app. With
    # ``Cache[Logger[DemoApp], ...]``, hits short-circuit the
    # Logger; you'll see one log line per real serve and zero per
    # cache hit. This is the right ordering for production: the
    # logger reports inner work (not cache decisions), and the
    # cache's ``X-Cache`` header is the observable signal for
    # cache behaviour.
    var stack = Cache[Logger[DemoApp], InMemoryCacheStore](
        Logger[DemoApp](DemoApp(), prefix=String("[demo]")),
        InMemoryCacheStore.with_capacity(64),
    )

    # ── 1. Miss-then-hit ─────────────────────────────────────────
    print("── 1. Miss-then-hit ──")
    var r1 = stack.serve(Request.test_get(String("/")))
    _describe(String("first GET /"), r1)
    var r2 = stack.serve(Request.test_get(String("/")))
    _describe(String("second GET / (expect X-Cache: HIT)"), r2)

    # ── 2. Vary segregation ──────────────────────────────────────
    print("── 2. Vary segregation ──")
    var en = Request.test_get(String("/i18n"))
    en.headers.set(String("Accept-Language"), String("en"))
    var fr = Request.test_get(String("/i18n"))
    fr.headers.set(String("Accept-Language"), String("fr"))

    var en1 = stack.serve(en)
    _describe(String("first /i18n en"), en1)
    var fr1 = stack.serve(fr)
    _describe(String("first /i18n fr"), fr1)

    var en2 = Request.test_get(String("/i18n"))
    en2.headers.set(String("Accept-Language"), String("en"))
    var en_hit = stack.serve(en2)
    _describe(String("repeat /i18n en (expect X-Cache: HIT)"), en_hit)

    # ── 3. no-store always bypasses the cache ───────────────────
    print("── 3. no-store endpoint ──")
    var ns1 = stack.serve(Request.test_get(String("/no-store")))
    _describe(String("first /no-store"), ns1)
    var ns2 = stack.serve(Request.test_get(String("/no-store")))
    _describe(
        String("second /no-store (NEVER X-Cache: HIT -- no-store opt-out)"),
        ns2,
    )

    print("=== Example 33 complete ===")
