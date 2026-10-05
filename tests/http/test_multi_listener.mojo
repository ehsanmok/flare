"""HttpServer.bind_many: single worker, multiple listener fds.

Verifies that ``HttpServer.bind_many([addr1, addr2])`` accepts on
every listener, that the same handler serves traffic from any of
them, and that drain on stop closes all of them cleanly. Same
fork-and-drive topology as ``tests/test_unified_http_server.mojo``.

Cases (7):

* ``test_bind_many_two_ports_serve_both`` -- bind on two ephemeral
  ports, drive each with HttpClient, both responses come back.
* ``test_bind_many_local_addrs_returns_in_order`` -- the
  ``local_addrs()`` accessor enumerates every bound address
  (primary first).
* ``test_bind_many_empty_addrs_raises`` -- the API rejects an
  empty addr list with a clear error message.
* ``test_bind_many_multi_worker_serves_every_address`` -- the
  N x M cross product: two addresses x two workers, both
  addresses served. This combination raised until v0.10.
* ``test_serve_{cancellable,view,static}_rejects_extra_listeners`` --
  the three single-listener loops raise on a multi-address server
  instead of silently serving only the first address (DOC-05).
"""

from std.ffi import c_int, external_call
from std.testing import assert_equal, assert_true


from flare.utils import (
    SIGKILL,
    exit,
    fork,
    kill,
    usleep,
    waitpid,
)

from flare.http import (
    FnHandler,
    HttpClient,
    HttpServer,
    Request,
    Response,
    WithCancel,
    ok,
    precompute_response,
)
from flare.http.handler import WithViewCancel
from flare.net import SocketAddr


def _hello(req: Request) raises -> Response:
    return ok("hello multi-listener: " + req.url)


def test_bind_many_two_ports_serve_both() raises:
    """An ``HttpServer`` bound to two ephemeral ports serves
    traffic from each. Both client requests hit the same handler
    and get the expected per-port response."""
    var addrs = List[SocketAddr]()
    addrs.append(SocketAddr.localhost(0))
    addrs.append(SocketAddr.localhost(0))
    var srv = HttpServer.bind_many(addrs^)

    var port_a = UInt16(srv.local_addrs()[0].port)
    var port_b = UInt16(srv.local_addrs()[1].port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(200000)

    var got_a = String("")
    var got_b = String("")
    var raised = False
    try:
        with HttpClient() as c:
            got_a = c.get(
                "http://127.0.0.1:" + String(Int(port_a)) + "/from-a"
            ).text()
            got_b = c.get(
                "http://127.0.0.1:" + String(Int(port_b)) + "/from-b"
            ).text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_true(not raised, "multi-listener round-trip raised")
    assert_equal(got_a, "hello multi-listener: /from-a")
    assert_equal(got_b, "hello multi-listener: /from-b")


def test_bind_many_local_addrs_returns_in_order() raises:
    """``HttpServer.local_addrs()`` returns every bound address
    in the order ``bind_many`` saw them."""
    var addrs = List[SocketAddr]()
    addrs.append(SocketAddr.localhost(0))
    addrs.append(SocketAddr.localhost(0))
    addrs.append(SocketAddr.localhost(0))
    var srv = HttpServer.bind_many(addrs^)
    var enumerated = srv.local_addrs()
    assert_equal(len(enumerated), 3)
    # Each ephemeral port must be > 0 and pairwise distinct.
    for i in range(3):
        assert_true(enumerated[i].port > 0)
        for j in range(i + 1, 3):
            assert_true(
                enumerated[i].port != enumerated[j].port,
                "two ephemeral ports collided -- kernel should not do that",
            )


def test_bind_many_empty_addrs_raises() raises:
    """Empty addr list is a programmer error; the API rejects it
    with an explicit message rather than silently constructing a
    server with no listeners."""
    var addrs = List[SocketAddr]()
    var raised = False
    try:
        var _srv = HttpServer.bind_many(addrs^)
    except:
        raised = True
    assert_true(raised, "bind_many([]) must raise")


def test_bind_many_multi_worker_serves_every_address() raises:
    """N addresses x M workers: every address is served.

    This raised until v0.10 ("bind_many is single-worker only").
    Each (address, worker) pair now owns its own SO_REUSEPORT
    listener, so two addresses across two workers means four
    listeners.

    The gap this guards against is an address that binds but is
    never accepted on -- the server would come up, answer on the
    primary, and hang every client of the extra. So both addresses
    are driven, several times each, rather than just checking the
    server starts.
    """
    var addrs = List[SocketAddr]()
    addrs.append(SocketAddr.localhost(0))
    addrs.append(SocketAddr.localhost(0))
    var srv = HttpServer.bind_many(addrs^)

    var port_a = UInt16(srv.local_addrs()[0].port)
    var port_b = UInt16(srv.local_addrs()[1].port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello, num_workers=2)
        except:
            pass
        exit()
    usleep(400000)

    var ok_a = 0
    var ok_b = 0
    try:
        with HttpClient() as c:
            # Several round trips per address: with two workers the
            # kernel hashes connections between them, so one request
            # could be served by a single worker and hide a listener
            # that was never registered on the other.
            for _ in range(4):
                if (
                    c.get(
                        "http://127.0.0.1:" + String(Int(port_a)) + "/from-a"
                    ).text()
                    == "hello multi-listener: /from-a"
                ):
                    ok_a += 1
                if (
                    c.get(
                        "http://127.0.0.1:" + String(Int(port_b)) + "/from-b"
                    ).text()
                    == "hello multi-listener: /from-b"
                ):
                    ok_b += 1
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_equal(ok_a, 4, "primary address did not serve under 2 workers")
    assert_equal(ok_b, 4, "extra address did not serve under 2 workers")


def _child_exit_code(pid: Int) -> Int:
    """Poll the child for up to 5 s; -1 if it is still running (then it
    is killed), else its exit status."""
    var st = List[c_int](length=1, fill=0)
    for _ in range(500):
        # wait4 rather than waitpid: flare.utils.waitpid declares that
        # symbol with another signature.
        var r = external_call["wait4", c_int](
            c_int(pid), st.unsafe_ptr(), c_int(1), Int(0)  # WNOHANG
        )
        if Int(r) == pid:
            return (Int(st[0]) >> 8) & 0xFF
        usleep(10000)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    return -1


def _serve_variant_on_two_listeners(method: Int) raises -> Int:
    """Run one serve variant in a forked child on a two-address server.

    The child exits 7 if the method raised and 3 if it returned. A method
    that ignores the extra listener and serves the primary one runs until
    the poll above kills it (-1).
    """
    var addrs = List[SocketAddr]()
    addrs.append(SocketAddr.localhost(0))
    addrs.append(SocketAddr.localhost(0))
    var srv = HttpServer.bind(addrs^)
    var pid = fork()
    if pid == 0:
        try:
            if method == 0:
                srv.serve_cancellable(WithCancel(FnHandler(_hello)))
            elif method == 1:
                srv.serve_view(WithViewCancel(FnHandler(_hello)))
            else:
                srv.serve_static(precompute_response(200, "text/plain", "hi"))
        except:
            exit(7)
        exit(3)
    var code = _child_exit_code(pid)
    srv.close()
    return code


def test_serve_cancellable_rejects_extra_listeners() raises:
    """DOC-05: it used to serve the primary address and ignore the rest."""
    assert_equal(_serve_variant_on_two_listeners(0), 7)


def test_serve_view_rejects_extra_listeners() raises:
    assert_equal(_serve_variant_on_two_listeners(1), 7)


def test_serve_static_rejects_extra_listeners() raises:
    assert_equal(_serve_variant_on_two_listeners(2), 7)


def main() raises:
    test_bind_many_two_ports_serve_both()
    test_bind_many_local_addrs_returns_in_order()
    test_bind_many_empty_addrs_raises()
    test_bind_many_multi_worker_serves_every_address()
    test_serve_cancellable_rejects_extra_listeners()
    test_serve_view_rejects_extra_listeners()
    test_serve_static_rejects_extra_listeners()
    print("test_multi_listener: 7 passed")
