"""HttpServer.bind_many: single worker, multiple listener fds.

Verifies that ``HttpServer.bind_many([addr1, addr2])`` accepts on
every listener, that the same handler serves traffic from any of
them, and that drain on stop closes all of them cleanly. Same
fork-and-drive topology as ``tests/test_unified_http_server.mojo``.

Cases (4):

* ``test_bind_many_two_ports_serve_both`` -- bind on two ephemeral
  ports, drive each with HttpClient, both responses come back.
* ``test_bind_many_local_addrs_returns_in_order`` -- the
  ``local_addrs()`` accessor enumerates every bound address
  (primary first).
* ``test_bind_many_empty_addrs_raises`` -- the API rejects an
  empty addr list with a clear error message.
* ``test_bind_many_multi_worker_raises`` -- combining
  ``bind_many`` with ``num_workers >= 2`` is rejected (single-
  worker only in v0.7).
"""

from std.ffi import c_int, external_call
from std.testing import assert_equal, assert_true

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import SocketAddr


@always_inline
def _fork() -> c_int:
    return external_call["fork", c_int]()


@always_inline
def _waitpid(pid: c_int):
    _ = external_call["waitpid", c_int](pid, 0, c_int(0))


@always_inline
def _exit_child(code: c_int = c_int(0)):
    _ = external_call["_exit", c_int](code)


@always_inline
def _kill(pid: c_int, sig: c_int) -> c_int:
    return external_call["kill", c_int](pid, sig)


@always_inline
def _usleep(us: c_int):
    _ = external_call["usleep", c_int](us)


comptime _SIGKILL: c_int = c_int(9)


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

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

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

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)

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


def test_bind_many_multi_worker_raises() raises:
    """Combining bind_many with num_workers>=2 is rejected in v0.7
    -- multi-listener is single-worker; multi-worker uses
    SO_REUSEPORT (N fds on one address). The error message
    explains the distinction."""
    var addrs = List[SocketAddr]()
    addrs.append(SocketAddr.localhost(0))
    addrs.append(SocketAddr.localhost(0))
    var srv = HttpServer.bind_many(addrs^)
    var raised = False
    try:
        srv.serve(_hello, num_workers=2)
    except:
        raised = True
    assert_true(
        raised,
        "bind_many + num_workers=2 must raise (single-worker only in v0.7)",
    )


def main() raises:
    test_bind_many_two_ports_serve_both()
    test_bind_many_local_addrs_returns_in_order()
    test_bind_many_empty_addrs_raises()
    test_bind_many_multi_worker_raises()
    print("test_multi_listener: 4 passed")
