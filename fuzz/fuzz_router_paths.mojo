"""Fuzz harness: ``flare.http.Router`` path matcher.

Drives ``Router.serve`` with random path bytes against a fixed set of
routes covering literal segments, parameters, and the wildcard tail.
Every response must be one of ``{200, 404, 405}``; any other status or
any crash (index out of bounds, assertion failed, uncaught exception)
is a router bug.

The mutator-supplied bytes are converted to an ASCII-printable path
string (non-printables rewritten to ``_``), wrapped in a
``Request(GET path)``, and handed to the router. We try both ``GET``
and the sibling method registered against ``/users`` so the ``405``
branch is exercised too.

Run:
    pixi run --environment fuzz fuzz-router-paths
"""

from mozz import fuzz, FuzzConfig
from flare.http import Router, Request, Method, Status, ok
from flare.http.response import Response


def _ok_home(req: Request) raises -> Response:
    return ok("home")


def _ok_list(req: Request) raises -> Response:
    return ok("list")


def _ok_create(req: Request) raises -> Response:
    return ok("created")


def _ok_user(req: Request) raises -> Response:
    return ok("user:" + req.param("id"))


def _ok_files(req: Request) raises -> Response:
    return ok("files:" + req.param("*"))


def _build_router() raises -> Router:
    var r = Router()
    r.get("/", _ok_home)
    r.get("/users", _ok_list)
    r.post("/users", _ok_create)
    r.get("/users/:id", _ok_user)
    r.get("/files/*", _ok_files)
    return r^


@always_inline
def _bytes_to_path(data: List[UInt8]) -> String:
    """Turn arbitrary bytes into an ASCII path.

    The mutator feeds random bytes; the router only accepts strings, so
    we rewrite non-printables to ``_`` and prepend a ``/`` to form a
    plausible-looking URL. The goal is coverage on the parser's corner
    cases (empty segments, mid-path ``:``, stray ``*``, trailing ``/``),
    not hitting legitimate routes.
    """
    var out = String(capacity=len(data) + 2)
    out += "/"
    for i in range(len(data)):
        var b = data[i]
        if b >= 32 and b < 127:
            out += chr(Int(b))
        else:
            out += "_"
    return out^


def target(data: List[UInt8]) raises:
    """Fuzz target: Router.serve with random paths.

    Expected rejections (treated as OK by mozz):
        - None. The router should return a Response for any input.
          Any raised exception counts as a crash because the router
          is supposed to answer 404 / 405 on malformed paths, not
          propagate errors to the caller.

    Bugs (treated as crashes by mozz):
        - Any response whose status is not in {200, 404, 405}.
        - Any raised exception (bounds violation, OOM, assertion).
    """
    if len(data) == 0:
        return

    var r = _build_router()

    var path = _bytes_to_path(data)

    # Try GET first.
    var req_get = Request(method=Method.GET, url=path)
    var resp_get = r.serve(req_get)
    if (
        resp_get.status != 200
        and resp_get.status != 404
        and resp_get.status != 405
    ):
        raise Error(
            "assertion failed: unexpected status " + String(resp_get.status)
        )

    # Also try POST on the same path — exercises the 405 branch.
    var req_post = Request(method=Method.POST, url=path)
    var resp_post = r.serve(req_post)
    if (
        resp_post.status != 200
        and resp_post.status != 404
        and resp_post.status != 405
    ):
        raise Error(
            "assertion failed: unexpected status " + String(resp_post.status)
        )


def main() raises:
    print("=" * 60)
    print("fuzz_router_paths.mojo — Router path matcher")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()

    def _b(s: String) -> List[UInt8]:
        var bs = s.as_bytes()
        var out = List[UInt8](capacity=len(bs))
        for i in range(len(bs)):
            out.append(bs[i])
        return out^

    # Match-positive seeds.
    seeds.append(_b(""))  # would become "/"
    seeds.append(_b("users"))
    seeds.append(_b("users/42"))
    seeds.append(_b("files/a"))
    seeds.append(_b("files/deep/nested/file.txt"))
    # Corner-case seeds the parser should shrug off.
    seeds.append(_b("users/"))
    seeds.append(_b("//users"))
    seeds.append(_b("users//42"))
    seeds.append(_b("users/:id"))
    seeds.append(_b(":"))
    seeds.append(_b(":::"))
    seeds.append(_b("*"))
    seeds.append(_b("files/*"))
    seeds.append(_b("files/*/extra"))
    seeds.append(_b("?x=1"))
    seeds.append(_b("users?x=1&y=2"))
    seeds.append(_b("users/42?"))
    seeds.append(_b("" + String(chr(0)) + "users"))  # NUL byte
    seeds.append(_b("users/" + String(chr(10)) + "42"))  # LF in path
    seeds.append(_b("a/b/c/d/e/f/g/h/i/j"))  # deep path

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/router_paths",
            max_input_len=128,
        ),
        seeds,
    )
