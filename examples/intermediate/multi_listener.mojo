"""HttpServer.bind_many -- one process, multiple listening addresses (v0.7).

The default :func:`HttpServer.bind` listens on a single
``SocketAddr``. Real deployments often want one process to accept
on **multiple** addresses simultaneously: an internal admin port
alongside the public service port; an IPv4 address paired with an
IPv6 address; the public TCP socket plus a UNIX socket once the
``UdsListener`` track lands.

``HttpServer.bind_many(addrs)`` opens one listener fd per address,
hands all of them to a single-worker reactor, and accepts new
connections on every fd through the same handler. This is
complementary to the multi-worker ``SO_REUSEPORT`` mode -- that
shape is **N fds on the same address** (kernel hashes new
4-tuples across workers); this one is **N fds on N distinct
addresses, one worker**. The cross product (multi-worker x
multi-listener) is on the v0.7.x roadmap; today picking one or
the other is the right design choice.

What this example shows:

1. Bind on three loopback ports at once.
2. Fork a child running the server.
3. From the parent, drive each port via ``HttpClient`` and
   confirm the same handler answered each one.

Run:

    pixi run mojo -I . examples/intermediate/multi_listener.mojo
"""

from std.ffi import c_int, external_call

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import SocketAddr
from flare.testing import fork_server, kill_forked_server


def hello(req: Request) raises -> Response:
    return ok("multi-listener served: " + req.url)


def main() raises:
    print("=== HttpServer.bind_many demo ===\n")

    var addrs = List[SocketAddr]()
    addrs.append(SocketAddr.localhost(0))
    addrs.append(SocketAddr.localhost(0))
    addrs.append(SocketAddr.localhost(0))
    var srv = HttpServer.bind_many(addrs^)

    var bound = srv.local_addrs()
    print("Server is bound on", len(bound), "addresses:")
    for i in range(len(bound)):
        print("  -", bound[i])
    print()

    # Snapshot the ports before fork so we can address them from
    # the parent (the child consumes ``srv``).
    var port_a = UInt16(bound[0].port)
    var port_b = UInt16(bound[1].port)
    var port_c = UInt16(bound[2].port)

    var pid = fork_server(srv^, hello)

    print("Driving each port from the parent process...\n")
    var results = List[String]()
    try:
        with HttpClient() as c:
            results.append(
                c.get(
                    "http://127.0.0.1:" + String(Int(port_a)) + "/svc-a"
                ).text()
            )
            results.append(
                c.get(
                    "http://127.0.0.1:" + String(Int(port_b)) + "/svc-b"
                ).text()
            )
            results.append(
                c.get(
                    "http://127.0.0.1:" + String(Int(port_c)) + "/svc-c"
                ).text()
            )
    except e:
        print("Client error:", e)

    kill_forked_server(pid)

    for i in range(len(results)):
        print("port", i, "->", results[i])
    print("\n=== demo complete ===")
