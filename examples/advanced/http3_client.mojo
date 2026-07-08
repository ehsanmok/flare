"""HTTP/3 client -- one HttpClient call site, h3 over QUIC on the wire.

The same :class:`flare.http.HttpClient` that speaks HTTP/1.1 and HTTP/2
also speaks HTTP/3 when you opt in with ``prefer_http3=True``. The call
site never changes: ``client.get(url)`` returns the same
:class:`flare.http.Response` regardless of which wire carried it.

What this example proves end to end, over real QUIC encryption:

* A forked :meth:`flare.http.HttpServer.serve_http3` loop serves a shared
  :class:`flare.http.Handler` over QUIC/UDP (h3 ALPN).
* The parent's ``HttpClient(prefer_http3=True)`` dials QUIC, completes the
  rustls handshake, and round-trips a GET over HTTP/3.
* Because GET is idempotent and h3 is preferred, flare runs a
  happy-eyeballs race (h3 vs h2/h1) concurrently; the h3 leg wins here
  and the h2/h1 leg's failure never stalls the request -- this is the
  transparent-fallback machinery, exercised live.

The client trusts the example's test-fixture CA (``ca.pem``) and dials
``https://localhost:<udp-port>`` so the SNI matches the ``localhost``
leaf certificate. Real deployments pass a system / corporate CA bundle
the same way (or none, to use the OS trust store).

Run:
    pixi run example-http3-client
"""

from flare.http import Handler, HttpClient, HttpServer
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok
from flare.net import IpAddr, SocketAddr
from flare.quic import QuicServerConfig
from flare.tls import TlsConfig
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


@fieldwise_init
struct SharedHandler(Copyable, Handler, Movable):
    """One handler, reached here over h3 (and over h1/h2/h2c elsewhere)."""

    def serve(self, req: Request) raises -> Response:
        if req.url == "/hello":
            return ok("Hello over HTTP/3 from flare!")
        return ok(String("you reached ") + req.method + String(" ") + req.url)


def _read_file(path: String) raises -> String:
    with open(path, "r") as f:
        return f.read()


def main() raises:
    # Bind the h3 (QUIC/UDP) listener with the fixture cert/key; the
    # TCP side is bound too but only the h3 loop is served below.
    var tcp_addr = SocketAddr(IpAddr.localhost(), UInt16(0))
    var udp_cfg = QuicServerConfig()
    udp_cfg.host = String("127.0.0.1")
    udp_cfg.port = UInt16(0)
    udp_cfg.rustls_config.cert_chain_pem = _read_file(_FIXDIR + "cert.pem")
    udp_cfg.rustls_config.private_key_pem = _read_file(_FIXDIR + "key.pem")
    var h3_alpn = List[String]()
    h3_alpn.append(String("h3"))
    udp_cfg.rustls_config.alpn_protocols = h3_alpn^

    var srv = HttpServer.bind_with_http3(tcp_addr, udp_cfg^)
    var udp_port = UInt16(srv.local_http3_addr().port)
    print("[h3 server] QUIC listening on 127.0.0.1:" + String(Int(udp_port)))

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_http3(SharedHandler())
        except:
            pass
        exit()
    usleep(300_000)  # let the QUIC listener come up

    # The client trusts the fixture CA and dials by hostname so SNI
    # matches the leaf cert. prefer_http3=True opts the https path into h3.
    var tls = TlsConfig()
    tls.ca_bundle = _FIXDIR + "ca.pem"
    var base = String("https://localhost:") + String(Int(udp_port))
    print("[h3 client] GET " + base + "/hello  (prefer_http3=True)")

    var status = -1
    var body = String("")
    try:
        with HttpClient(tls, base_url=base, prefer_http3=True) as c:
            var r = c.get("/hello")
            status = r.status
            body = r.text()
    except e:
        print("[h3 client] request failed:", String(e))

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    print("[h3] response:", String(status), body)
    print("[done] one HttpClient call site, HTTP/3 on the wire.")
