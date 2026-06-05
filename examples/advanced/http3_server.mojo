"""HTTP/3 server -- one Handler across h1 + h2c + h2 + h3.

Walks the production shape of an HTTP/3 server:

* :meth:`flare.http.HttpServer.bind_with_h3` opens a TCP listener
  for h1 / h2c / h2 AND a QUIC UDP listener for h3 alongside.
* :meth:`flare.http.HttpServer.serve_h3` runs the QUIC reactor
  with H3 Handler dispatch as a single-threaded loop per Phase
  E Track Q12-W: each iteration runs
  :meth:`flare.quic.QuicListener.tick` to drain one inbound UDP
  datagram + drive the QUIC + rustls state machines, then
  :meth:`flare.http.HttpServer.pump_h3_handler_once` to dispatch
  any completed H3 request streams through the handler, then
  :meth:`flare.quic.QuicListener.advance_timers` so PTO + idle
  + ack-delay callbacks fire on time.
* The same :class:`flare.http.Handler` instance serves every
  wire shape -- a single ``serve(req)`` reaches a curl over
  h1, an h2-frame client, and an h3 (QUIC) client.
* :meth:`flare.http.HttpServer.advertised_alpn_protocols` is
  what the TLS handshake advertises (server preference order
  ``h3 > h2 > http/1.1``); the negotiated identifier feeds
  :meth:`flare.http.HttpServer.route_alpn` to pick the matching
  driver per connection.

Live wire status: the QUIC reactor I/O cycle is live, the
rustls FFI wrapper surfaces the per-level ``KeyChange``
Handshake / 1-RTT keys back to
``QuicConnection.install_handshake_keys`` /
``install_1rtt_keys``, and this example's ``serve_h3`` loop
sustains a full request-response round-trip over the wire. The
HTTP/3 bench gate is met: flare h3 leads at 74,653 req/s
(median, +2.9 % over quiche 0.22) on the 1-client x 100-stream
workload -- see ``docs/benchmark.md`` for the full table. The
shared-Handler dispatch is also unit-tested end-to-end via
``tests/h3/test_h3_end_to_end.mojo``.

Run:
    pixi run example-http3-server
"""

from flare.h3 import H3Connection, H3ConnectionConfig
from flare.http import Handler
from flare.http.alpn_dispatch import (
    ALPN_HTTP_1_1,
    ALPN_HTTP_2,
    ALPN_HTTP_3,
    WireProtocol,
    wire_protocol_name,
)
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import HttpServer, ok
from flare.net import IpAddr, SocketAddr
from flare.quic import QuicServerConfig


# ── The shared Handler ────────────────────────────────────────────────


@fieldwise_init
struct SharedHandler(Copyable, Handler, Movable):
    """One handler reachable from every wire (h1 / h2c / h2 / h3).

    The handler doesn't look at the wire shape -- it doesn't
    need to. The reactor + protocol drivers materialize the
    :class:`Request` from the wire, the handler decides what to
    do, and the protocol drivers serialize the :class:`Response`
    back out. That's the point of the trait boundary.
    """

    def serve(self, req: Request) raises -> Response:
        if req.url == "/hello":
            return ok("Hello from flare across every wire!")
        var body = String("you reached ") + req.method + String(" ") + req.url
        return ok(body^)


# ── Walkthrough ───────────────────────────────────────────────────────


def main() raises:
    print("== HTTP/3 server -- one Handler across h1 + h2c + h2 + h3 ==")
    print()

    # Step 1: bind. The TCP listener handles h1 / h2c / h2 via
    # ALPN; the QUIC listener handles h3 via ALPN. Both ports
    # are kernel-chosen (port 0 = ephemeral) so the example is
    # reproducible without claiming well-known ports.
    var tcp_addr = SocketAddr(IpAddr.localhost(), UInt16(0))
    var udp_cfg = QuicServerConfig()
    udp_cfg.host = String("127.0.0.1")
    udp_cfg.port = UInt16(0)
    var srv = HttpServer.bind_with_h3(tcp_addr, udp_cfg^)

    print("[bind] TCP listener:", String(srv.local_addrs()[0]))
    print("[bind] UDP listener:", String(srv.local_h3_addr()))
    print()

    # Step 2: the advertised ALPN list. The TLS handshake on
    # the TCP side advertises ``h2`` + ``http/1.1``; the QUIC
    # handshake on the UDP side advertises ``h3``. Server
    # preference order is highest -> lowest so the negotiator
    # picks h3 over h2 when the client supports both.
    print("[alpn] advertised ALPN protocols (preference order):")
    var alpn = srv.advertised_alpn_protocols()
    for i in range(len(alpn)):
        print("   ", i, ":", alpn[i])
    print()

    # Step 3: ALPN routing decision per peer. The reactor calls
    # route_alpn() on the negotiated identifier from each TLS
    # handshake and gets back a WireProtocol codepoint that
    # picks the driver.
    print("[route] ALPN -> wire-protocol mapping:")
    print(
        "    h3 ->",
        wire_protocol_name(srv.route_alpn(String(ALPN_HTTP_3))),
    )
    print(
        "    h2 ->",
        wire_protocol_name(srv.route_alpn(String(ALPN_HTTP_2))),
    )
    print(
        "    http/1.1 ->",
        wire_protocol_name(srv.route_alpn(String(ALPN_HTTP_1_1))),
    )
    print(
        "    (no ALPN) ->",
        wire_protocol_name(srv.route_alpn(String(""))),
    )
    print()

    # Step 4: prove the shared Handler dispatch surface. The
    # same Handler the QUIC reactor invokes via ``serve_h3``
    # is the one a TCP reactor invokes via ``serve``. Dispatch
    # a synthetic Request through the handler directly so the
    # demo returns deterministically (running the actual
    # serve_h3 loop would block until SIGINT).
    print("[demo] dispatch a synthetic request through the shared Handler:")
    var handler = SharedHandler()
    var req = Request(
        method=String("GET"), url=String("/hello"), body=List[UInt8]()
    )
    var resp = handler.serve(req^)
    print("    response status:", resp.status)
    print(
        "    response body:",
        String(unsafe_from_utf8=Span[UInt8, _](resp.body)),
    )
    print()

    # Step 5: pump_h3_handler_once is the per-tick H3 dispatch
    # surface ``serve_h3`` drives. With no live UDP traffic in
    # this demo the listener has no completed streams to drain,
    # so the count is 0 -- but the call exercises the dispatch
    # path so a reader can see the shape.
    print("[h3] one-shot Handler pump on the live QUIC listener:")
    var dispatched = srv.pump_h3_handler_once[SharedHandler](handler)
    print("    streams dispatched this pass:", dispatched)
    print()

    # Step 6: H3Connection is what the QUIC reactor will hand
    # each accepted QUIC connection to. Build one + verify it
    # emits the server SETTINGS that the listener will write
    # on the new control stream.
    var h3 = H3Connection.with_config(H3ConnectionConfig())
    var initial_settings = h3.emit_initial_settings()
    print("[h3] initial server SETTINGS emit length =", len(initial_settings))
    print()

    # The full live-traffic loop would replace the lines above
    # with::
    #
    #     srv.serve_h3[SharedHandler](handler^)
    #
    # which blocks driving the QUIC reactor + H3 Handler
    # dispatch until ``QuicListener.shutdown`` flips the stop
    # flag. That loop sustains a full request-response
    # round-trip end-to-end over the wire (h3 bench gate met).

    print("== done ==")
