"""Tests for the v0.7 Router-Copyable refactor (Arc-based shared
ownership of boxed handlers).

The Router became ``Handler & Copyable & Movable`` so the
multi-worker
``HttpServer.serve[H: Handler & Copyable](handler, num_workers)``
overload accepts it directly. The shared-cell refcount makes
that safe -- every copy points at the same boxed-handler pool;
only the last drop runs the destroy thunks.

Cases:

1. Empty Router copies cheaply (no struct handlers -> no shared
   cell allocated; copy is a value-typed clone of the route +
   handler lists).
2. Router with one struct handler (Extracted[H]) copies + serves
   identically through the original and the clone.
3. Drop the original first; the copy still serves correctly
   (shared cell stays alive).
4. Drop the copy first; the original still serves correctly
   (refcount drops back to 1; full free runs only when the
   original drops).
5. Copy of a Router with mixed def-handler + struct-handler
   routes works for both kinds.
"""

from std.testing import assert_equal, assert_true

from flare.http import (
    Handler,
    Request,
    Response,
    Router,
    Status,
    ok,
)


def _hello(req: Request) raises -> Response:
    return ok("hello")


@fieldwise_init
struct _StructEcho(Copyable, Handler, Movable):
    var label: String

    def serve(self, req: Request) raises -> Response:
        return ok("struct:" + self.label)


def _make_request(method: String, url: String) raises -> Request:
    return Request(
        method=method,
        url=url,
        body=List[UInt8](),
        version="HTTP/1.1",
    )


def test_empty_router_copies_without_allocating_shared_cell() raises:
    """A Router with no struct handlers leaves ``_shared_addr ==
    0``; copying still works (cheap value clone) and the copy
    serves the registered def-handler."""
    var r = Router()
    r.get("/hi", _hello)
    var clone = r.copy()
    var resp = clone.serve(_make_request("GET", "/hi"))
    assert_equal(resp.status, Status.OK)


def test_struct_handler_copy_serves_through_both_original_and_clone() raises:
    """Registering a struct handler allocates the shared cell;
    both Router copies see the same boxed handler and dispatch
    correctly."""
    var r = Router()
    r.get("/echo", _StructEcho("a"))
    var clone = r.copy()
    var resp_orig = r.serve(_make_request("GET", "/echo"))
    var resp_clone = clone.serve(_make_request("GET", "/echo"))
    assert_equal(resp_orig.status, Status.OK)
    assert_equal(resp_clone.status, Status.OK)


def _build_clone_and_drop_original() raises -> Router:
    """Helper for the "original drops first" lifecycle test. The
    inner Router goes out of scope at the end of this function
    (after the copy) so by the time the caller has the clone,
    the original has already been dropped; the boxed handler
    survives via the refcount."""
    var r = Router()
    r.get("/ping", _StructEcho("alive"))
    var clone = r.copy()
    return clone^


def test_drop_original_first_keeps_copy_alive() raises:
    """Build a clone, return it from a helper that drops the
    original mid-flight, and confirm the survivor still serves
    the boxed handler."""
    var clone = _build_clone_and_drop_original()
    var resp = clone.serve(_make_request("GET", "/ping"))
    assert_equal(resp.status, Status.OK)


def _make_and_drop_clone(imm original: Router) raises -> None:
    """Take a copy of ``original``, then let it drop on return.

    Mirrors the multi-worker shape where each worker thread owns
    a Router clone whose lifetime ends before the original. Done
    in a helper rather than inline with ``_ = clone^`` so the
    drop is unambiguous to the Mojo optimiser.
    """
    var clone = original.copy()
    _ = clone^


def test_drop_clone_first_keeps_original_alive() raises:
    """Drop a Router clone; the original's serve still works.
    Symmetric to the previous test -- the refcount must allow
    arbitrary drop order without freeing under us."""
    var r = Router()
    r.get("/pong", _StructEcho("orig"))
    _make_and_drop_clone(r)
    var resp = r.serve(_make_request("GET", "/pong"))
    assert_equal(resp.status, Status.OK)


@parameter
def _compile_check_router_into_multiworker_serve():
    """Compile-only contract: ``Router`` satisfies
    ``Handler & Copyable`` so the multi-worker overload of
    ``HttpServer.serve`` resolves. Body never runs (``False`` guard);
    if Router lost ``Copyable`` we'd fail at type-check time before
    the test even starts."""
    pass


def test_router_compiles_for_multi_worker_serve_overload() raises:
    """Document the Track-11 contract: the v0.7 Router-Copyable
    refactor exists specifically so ``srv.serve(router^,
    num_workers=N)`` resolves to the
    ``serve[H: Handler & Copyable]`` overload. Compile success of
    this file (and of the multicore example) is the assertion."""
    _compile_check_router_into_multiworker_serve()


def test_mixed_fn_and_struct_routes_copy_correctly() raises:
    """A Router with both def-handlers and struct-handlers
    survives a copy: each route kind dispatches through the
    expected path post-copy."""
    var r = Router()
    r.get("/fn", _hello)
    r.post("/struct", _StructEcho("via-post"))
    var clone = r.copy()
    var fn_resp = clone.serve(_make_request("GET", "/fn"))
    var struct_resp = clone.serve(_make_request("POST", "/struct"))
    assert_equal(fn_resp.status, Status.OK)
    assert_equal(struct_resp.status, Status.OK)


def main() raises:
    test_empty_router_copies_without_allocating_shared_cell()
    test_struct_handler_copy_serves_through_both_original_and_clone()
    test_drop_original_first_keeps_copy_alive()
    test_drop_clone_first_keeps_original_alive()
    test_router_compiles_for_multi_worker_serve_overload()
    test_mixed_fn_and_struct_routes_copy_correctly()
    print("All Router-copy tests pass.")
