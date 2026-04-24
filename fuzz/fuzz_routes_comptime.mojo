"""Fuzz harness: ``flare.http.routes.ComptimeRouter`` as an oracle.

Runs random path bytes through a ``ComptimeRouter`` bound to the same
route shape as the runtime ``Router`` used by
[`fuzz_router_paths.mojo`](./fuzz_router_paths.mojo) so the two
routers' responses can be cross-checked. The comptime router must
answer every input with one of ``{200, 404, 405}`` and must agree
with the runtime router on the status code (oracle test).

Run:
    pixi run --environment fuzz fuzz-routes-comptime
"""

from mozz import fuzz, FuzzConfig

from flare.http import (
    ComptimeRoute,
    ComptimeRouter,
    Router,
    Request,
    Method,
    Status,
    ok,
)
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


comptime _ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET, "/"),
    ComptimeRoute(Method.GET, "/users"),
    ComptimeRoute(Method.POST, "/users"),
    ComptimeRoute(Method.GET, "/users/:id"),
    ComptimeRoute(Method.GET, "/files/*"),
]


def _build_comptime_router() raises -> ComptimeRouter[_ROUTES]:
    var r = ComptimeRouter[_ROUTES]()
    r.set_handler(0, _ok_home)
    r.set_handler(1, _ok_list)
    r.set_handler(2, _ok_create)
    r.set_handler(3, _ok_user)
    r.set_handler(4, _ok_files)
    return r^


def _build_runtime_router() raises -> Router:
    var r = Router()
    r.get("/", _ok_home)
    r.get("/users", _ok_list)
    r.post("/users", _ok_create)
    r.get("/users/:id", _ok_user)
    r.get("/files/*", _ok_files)
    return r^


@always_inline
def _bytes_to_path(data: List[UInt8]) -> String:
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
    """Fuzz target: ComptimeRouter.serve with random paths.

    Bugs (treated as crashes by mozz):
        - Any response whose status is not in {200, 404, 405}.
        - Any disagreement with the runtime ``Router`` on status code.
        - Any raised exception.
    """
    if len(data) == 0:
        return

    var path = _bytes_to_path(data)
    var ct = _build_comptime_router()
    var rt = _build_runtime_router()

    # GET.
    var req_g1 = Request(method=Method.GET, url=path)
    var req_g2 = Request(method=Method.GET, url=path)
    var r_ct_g = ct.serve(req_g1)
    var r_rt_g = rt.serve(req_g2)
    if r_ct_g.status != 200 and r_ct_g.status != 404 and r_ct_g.status != 405:
        raise Error("ct: unexpected status " + String(r_ct_g.status))
    if r_ct_g.status != r_rt_g.status:
        raise Error(
            "oracle mismatch (GET): ct="
            + String(r_ct_g.status)
            + " rt="
            + String(r_rt_g.status)
            + " path="
            + path
        )

    # POST.
    var req_p1 = Request(method=Method.POST, url=path)
    var req_p2 = Request(method=Method.POST, url=path)
    var r_ct_p = ct.serve(req_p1)
    var r_rt_p = rt.serve(req_p2)
    if r_ct_p.status != 200 and r_ct_p.status != 404 and r_ct_p.status != 405:
        raise Error("ct: unexpected status " + String(r_ct_p.status))
    if r_ct_p.status != r_rt_p.status:
        raise Error(
            "oracle mismatch (POST): ct="
            + String(r_ct_p.status)
            + " rt="
            + String(r_rt_p.status)
            + " path="
            + path
        )


def main() raises:
    print("=" * 60)
    print("fuzz_routes_comptime.mojo — ComptimeRouter oracle vs Router")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()

    def _b(s: String) -> List[UInt8]:
        var bs = s.as_bytes()
        var out = List[UInt8](capacity=len(bs))
        for i in range(len(bs)):
            out.append(bs[i])
        return out^

    seeds.append(_b(""))
    seeds.append(_b("users"))
    seeds.append(_b("users/42"))
    seeds.append(_b("files/a"))
    seeds.append(_b("files/deep/nested/file.txt"))
    seeds.append(_b("users/"))
    seeds.append(_b("//users"))
    seeds.append(_b("users//42"))
    seeds.append(_b("users/:id"))
    seeds.append(_b("*"))
    seeds.append(_b("files/*"))
    seeds.append(_b("?x=1"))
    seeds.append(_b("users?x=1&y=2"))
    seeds.append(_b("users/42?"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/routes_comptime",
            max_input_len=96,
        ),
        seeds,
    )
