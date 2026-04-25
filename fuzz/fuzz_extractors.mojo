"""Fuzz harness: ``flare.http.extract`` extractors + ``Extracted[H]``.

Drives the full reflective extraction pipeline with random bytes used
as both the URL path/query and an arbitrary set of headers. Every call
to ``Extracted[H].serve`` must either return a ``Response`` with a
status in ``{200, 400}`` (extractor failure → 400, success → 200) or
raise a typed error. Any other outcome (segfault, bounds violation,
uncaught non-extractor exception) counts as a bug.

Run:
    pixi run --environment fuzz fuzz-extractors
"""

from mozz import fuzz, FuzzConfig

from flare.http import (
    Request,
    Response,
    Status,
    Method,
    ok,
    ParamInt,
    ParamString,
    Path,
    Query,
    OptionalQuery,
    Header,
    OptionalHeader,
    Handler,
    Extracted,
)


@fieldwise_init
struct _StressHandler(Copyable, Defaultable, Handler, Movable):
    """A handler with one of every extractor kind so a single fuzz run
    exercises path + query + header + optional variants at once.
    """

    var id: Path[ParamInt, "id"]
    var page: OptionalQuery[ParamInt, "page"]
    var name: Query[ParamString, "name"]
    var auth: Header[ParamString, "Authorization"]
    var trace: OptionalHeader[ParamString, "X-Trace"]

    def __init__(out self):
        self.id = Path[ParamInt, "id"]()
        self.page = OptionalQuery[ParamInt, "page"]()
        self.name = Query[ParamString, "name"]()
        self.auth = Header[ParamString, "Authorization"]()
        self.trace = OptionalHeader[ParamString, "X-Trace"]()

    def serve(self, req: Request) raises -> Response:
        return ok("ok")


@always_inline
def _to_ascii(data: List[UInt8], start: Int, end: Int) -> String:
    """Rewrite arbitrary bytes into printable ASCII-only text.

    Non-printables become ``_`` so callers can safely embed the result
    in a URL or header value without tripping the HTTP validator.
    """
    var n = end - start
    if n <= 0:
        return ""
    var out = String(capacity=n)
    for i in range(start, end):
        var b = data[i]
        if b >= 32 and b < 127 and b != Int(ord("?")) and b != Int(ord("#")):
            out += chr(Int(b))
        else:
            out += "_"
    return out^


def target(data: List[UInt8]) raises:
    """Fuzz target: feed `data` into every extractor shape.

    Expected rejections (OK):
        - ``Extracted[...]`` catches extractor failures and returns 400.

    Bugs (crashes):
        - Any status outside ``{200, 400}``.
        - Any raised exception; extractors should convert their own
          errors into 400 responses, never propagate them.
    """
    if len(data) == 0:
        return

    var n = len(data)
    # Slice into regions: path-param / query-value / header-value / id / page.
    var q = n // 4
    var path_piece = _to_ascii(data, 0, q)
    var qvalue = _to_ascii(data, q, 2 * q)
    var hvalue = _to_ascii(data, 2 * q, 3 * q)
    var tail = _to_ascii(data, 3 * q, n)

    # Build a URL with a query string where each key maps to a
    # bytes-derived value. Some permutations of `tail` accidentally
    # resemble valid integers → exercises both happy and error paths.
    var url = "/users/" + path_piece + "?name=" + qvalue + "&page=" + tail
    var req = Request(method=Method.GET, url=url)

    # Inject the :id path capture. Router normally owns this; here we
    # drive the extractor directly so we can feed in garbage.
    req.params_mut()["id"] = path_piece

    # Inject headers. Header extraction fails on injection bytes, so
    # pre-sanitise.
    try:
        req.headers.set("Authorization", hvalue)
    except:
        pass
    try:
        req.headers.set("X-Trace", tail)
    except:
        pass

    var resp = Extracted[_StressHandler]().serve(req)
    if resp.status != Status.OK and resp.status != Status.BAD_REQUEST:
        raise Error(
            "assertion failed: unexpected status "
            + String(resp.status)
            + " for url="
            + url
        )

    # v0.5.0 Step 1 sanitised-error property:
    # When the request did NOT opt into ``expose_errors`` (the
    # production default), a 400 response body must equal the fixed
    # reason ``"Bad Request"`` exactly — no extractor message, no
    # echo of attacker-controlled bytes from the URL or headers.
    # ``Request(expose_errors=False)`` is the constructor default,
    # so ``req`` above carries that policy.
    if resp.status == Status.BAD_REQUEST:
        if resp.text() != "Bad Request":
            raise Error(
                "assertion failed: 400 body is not sanitised; got '"
                + resp.text()
                + "' for url="
                + url
            )


def main() raises:
    print("=" * 60)
    print("fuzz_extractors.mojo — Typed extractors + Extracted[H]")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()

    def _b(s: String) -> List[UInt8]:
        var bs = s.as_bytes()
        var out = List[UInt8](capacity=len(bs))
        for i in range(len(bs)):
            out.append(bs[i])
        return out^

    # Well-formed inputs.
    seeds.append(_b("7abAB1Bearer "))
    seeds.append(_b("42aliceBearer token"))
    seeds.append(_b("0   "))
    # Corner cases.
    seeds.append(_b(""))
    seeds.append(_b("-1"))
    seeds.append(_b("abc999"))
    seeds.append(_b("-"))
    seeds.append(_b("   "))
    seeds.append(_b("9" * 20))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/extractors",
            max_input_len=128,
        ),
        seeds,
    )
