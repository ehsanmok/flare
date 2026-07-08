"""ALPN dispatch -- routing wires to handlers.

When the server is bound on both TCP (TLS-terminated) and UDP
(QUIC), each accepted connection has a negotiated ALPN string
(or no ALPN at all). The reactor needs a pure decision function
that turns that string into a wire-protocol codepoint so it can
route into the matching driver.

This example walks the four wire shapes flare supports:

* HTTP/1.1 (no ALPN advertised, or ALPN ``"http/1.1"``).
* h2c -- HTTP/2 cleartext, triggered by an ``Upgrade: h2c``
  header on the h1 path; not ALPN-routed.
* HTTP/2 over TLS (ALPN ``"h2"``).
* HTTP/3 over QUIC (ALPN ``"h3"``).

It exercises :func:`flare.http.alpn_dispatch.dispatch_alpn`,
:func:`flare.http.alpn_dispatch.dispatch_h2c_upgrade`, and
:func:`flare.http.alpn_dispatch.negotiate_alpn` to show how the
reactor would route an inbound connection to its driver.
"""

from flare.http.alpn_dispatch import (
    ALPN_HTTP_1_1,
    ALPN_HTTP_2,
    ALPN_HTTP_3,
    WireProtocol,
    dispatch_alpn,
    dispatch_h2c_upgrade,
    negotiate_alpn,
    wire_protocol_name,
)
from flare.http.server import HttpServer
from flare.net import IpAddr, SocketAddr
from flare.quic import QuicServerConfig


def _print_dispatch(label: String, protocol: Int):
    print(
        "  ",
        label,
        "->",
        wire_protocol_name(protocol),
        "(",
        protocol,
        ")",
    )


def main() raises:
    print("== ALPN-driven wire dispatch demo ==")
    print()

    # The four canonical input shapes the reactor sees.
    print("Direct ALPN -> wire mapping:")
    _print_dispatch(String(""), dispatch_alpn(String("")))
    _print_dispatch(ALPN_HTTP_1_1, dispatch_alpn(ALPN_HTTP_1_1))
    _print_dispatch(ALPN_HTTP_2, dispatch_alpn(ALPN_HTTP_2))
    _print_dispatch(ALPN_HTTP_3, dispatch_alpn(ALPN_HTTP_3))
    _print_dispatch(
        String("h1.5-experimental"),
        dispatch_alpn(String("h1.5-experimental")),
    )
    print()

    # h2c is the cleartext upgrade path; not ALPN-routed.
    print("h2c upgrade hint -> wire mapping:")
    _print_dispatch(String("Upgrade: h2c present"), dispatch_h2c_upgrade(True))
    _print_dispatch(String("no upgrade hint"), dispatch_h2c_upgrade(False))
    print()

    # Multi-protocol negotiation: a client advertises three protocols,
    # the server lists the three in preference order, and the server's
    # order wins (RFC 7301 paragraph 3.2).
    var client_advertised = List[String]()
    client_advertised.append(ALPN_HTTP_1_1)
    client_advertised.append(ALPN_HTTP_2)
    client_advertised.append(ALPN_HTTP_3)

    var server_supports = List[String]()
    server_supports.append(ALPN_HTTP_3)
    server_supports.append(ALPN_HTTP_2)
    server_supports.append(ALPN_HTTP_1_1)

    var negotiated = negotiate_alpn(client_advertised, server_supports)
    print(
        "Negotiated ALPN (server prefers h3 > h2 > http/1.1):",
        negotiated,
    )
    _print_dispatch(negotiated, dispatch_alpn(negotiated))
    print()

    # No-overlap case: the client advertises an experimental protocol
    # the server doesn't support; negotiation returns empty and the
    # reactor MUST surface a TLS no_application_protocol alert.
    var weird_client = List[String]()
    weird_client.append(String("h1.5-experimental"))
    var pick = negotiate_alpn(weird_client, server_supports)
    if pick == "":
        print("No overlap -> reactor closes connection with TLS alert")
    print()

    # HttpServer.route_alpn cross-checks the negotiated ALPN
    # against which listeners the server has bound. A TCP-only
    # server raises on "h3"; the bind_with_http3 variant accepts it.
    print("== HttpServer.route_alpn cross-checked routing ==")
    var tcp_only = HttpServer.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    print(
        "    tcp-only server advertises:", tcp_only.advertised_alpn_protocols()
    )
    print(
        "    tcp-only route_alpn('h2') ->",
        wire_protocol_name(tcp_only.route_alpn(String(ALPN_HTTP_2))),
    )
    var raised_on_h3 = False
    try:
        var _w = tcp_only.route_alpn(String(ALPN_HTTP_3))
    except _:
        raised_on_h3 = True
    print("    tcp-only route_alpn('h3') raises:", raised_on_h3)

    var udp_cfg = QuicServerConfig()
    udp_cfg.host = String("127.0.0.1")
    udp_cfg.port = UInt16(0)
    var h3_srv = HttpServer.bind_with_http3(
        SocketAddr(IpAddr.localhost(), UInt16(0)), udp_cfg^
    )
    print("    h3 server advertises:", h3_srv.advertised_alpn_protocols())
    print(
        "    h3 server route_alpn('h3') ->",
        wire_protocol_name(h3_srv.route_alpn(String(ALPN_HTTP_3))),
    )
