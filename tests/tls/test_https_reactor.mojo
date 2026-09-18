"""HTTPS served by the unified reactor: concurrency, ALPN, workers.

These cover the capability that ``serve_tls``'s sequential accept loop
could not offer. The load-bearing case is
:func:`test_https_concurrent_connections`: it opens several TLS
connections and sends a request on *every* one before reading *any*
response. Against a one-connection-at-a-time server that deadlocks --
connections 2..N never even get a handshake until connection 1 closes.
Against the reactor all of them complete, which is the whole point of
registering ``TlsConnHandle`` as a connection kind.

The rest pin the surrounding contract: ALPN selects h2 over the same
port instead of dropping the connection, multi-worker HTTPS serves,
and a streaming handler still frames chunked ciphertext.
"""

from std.ffi import c_int, c_size_t
from std.memory import stack_allocation
from std.testing import assert_equal, assert_true, TestSuite

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.net import IpAddr, SocketAddr
from flare.net._libc import (
    AF_INET,
    MSG_NOSIGNAL,
    SOCK_STREAM,
    _close,
    _connect,
    _fill_sockaddr_in,
    _send,
    _socket,
    _strerror,
    get_errno,
)
from flare.tls import TlsConfig, TlsStream
from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.response import stream_response
from flare.http.server import ServerConfig


def _connect_loopback(port: UInt16) raises -> c_int:
    """Open a blocking loopback TCP connection and return the fd."""
    var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if c < c_int(0):
        raise Error("socket() failed: " + _strerror(get_errno().value))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa + i).unsafe_write(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip + 0).unsafe_write(UInt8(127))
    (ip + 1).unsafe_write(UInt8(0))
    (ip + 2).unsafe_write(UInt8(0))
    (ip + 3).unsafe_write(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    if _connect(c, sa, c_int(16).cast[DType.uint32]()) < c_int(0):
        var msg = _strerror(get_errno().value)
        _ = _close(c)
        raise Error("connect 127.0.0.1 failed: " + msg)
    return c


comptime _SERVER_CRT: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"
comptime _CA_CRT: String = "tests/certs/ca.crt"

comptime _CONCURRENT_CONNS: Int = 4


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def _hello(req: Request) raises -> Response:
    return ok("hello https")


@fieldwise_init
struct _ThreeChunks(ChunkSource, Copyable):
    var idx: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self.idx == 0:
            self.idx = 1
            return _bytes("alpha ")
        if self.idx == 1:
            self.idx = 2
            return _bytes("beta ")
        if self.idx == 2:
            self.idx = 3
            return _bytes("gamma")
        return None


def _streamer(req: Request) raises -> Response:
    return stream_response(_ThreeChunks(0))


def _alpn_h1() -> List[String]:
    var a = List[String]()
    a.append("http/1.1")
    return a^


def _alpn_h2_first() -> List[String]:
    var a = List[String]()
    a.append("h2")
    a.append("http/1.1")
    return a^


def _read_until_close(mut stream: TlsStream) -> String:
    """Read until the peer closes or the record stream ends."""
    var acc = List[UInt8]()
    var tmp = stack_allocation[4096, UInt8]()
    while True:
        var n: Int
        try:
            n = stream.read(tmp, 4096)
        except:
            break
        if n <= 0:
            break
        for i in range(n):
            acc.append(tmp[i])
    return String(unsafe_from_utf8=Span[UInt8, _](acc))


def test_https_reactor_h1_roundtrip() raises:
    """A TLS connection served by ``serve()`` returns the handler body."""
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h1(),
    )
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(300000)

    var got = String("")
    var raised = False
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var s = TlsStream.connect("localhost", port, cfg)
        s.write_all(
            Span[UInt8, _](
                _bytes(
                    "GET / HTTP/1.1\r\nHost: localhost\r\nConnection:"
                    " close\r\n\r\n"
                )
            )
        )
        got = _read_until_close(s)
        s.close()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "HTTPS round-trip raised")
    assert_true("200" in got, "expected 200, got: " + got)
    assert_true("hello https" in got, "expected body, got: " + got)


def test_https_concurrent_connections() raises:
    """Several TLS connections are in flight at once.

    Every request is written before any response is read, so a
    sequential accept loop cannot pass this: it would still be inside
    connection 1 while connections 2..N sit unhandshaken.
    """
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h1(),
    )
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(300000)

    var ok_count = 0
    var raised = False
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var conns = List[TlsStream]()
        for _ in range(_CONCURRENT_CONNS):
            conns.append(TlsStream.connect("localhost", port, cfg))
        # Phase 1: every connection has an unanswered request on it.
        for i in range(len(conns)):
            conns[i].write_all(
                Span[UInt8, _](
                    _bytes(
                        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection:"
                        " close\r\n\r\n"
                    )
                )
            )
        # Phase 2: only now start draining them.
        for i in range(len(conns)):
            var body = _read_until_close(conns[i])
            if "hello https" in body:
                ok_count += 1
            conns[i].close()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "concurrent HTTPS round-trip raised")
    assert_equal(ok_count, _CONCURRENT_CONNS)


def test_https_reactor_streaming() raises:
    """A streaming handler frames chunked ciphertext over the reactor."""
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h1(),
    )
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_streamer)
        except:
            pass
        exit()
    usleep(300000)

    var got = String("")
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var s = TlsStream.connect("localhost", port, cfg)
        s.write_all(
            Span[UInt8, _](
                _bytes(
                    "GET /s HTTP/1.1\r\nHost: localhost\r\nConnection:"
                    " close\r\n\r\n"
                )
            )
        )
        got = _read_until_close(s)
        s.close()
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(
        "Transfer-Encoding: chunked" in got, "expected chunked, got: " + got
    )
    assert_true("alpha " in got, "missing first chunk: " + got)
    assert_true("gamma" in got, "missing last chunk: " + got)
    assert_true("0\r\n\r\n" in got, "missing chunked terminator")


def test_https_multi_worker() raises:
    """HTTPS serves with ``num_workers > 1``.

    Before the reactor arm existed there was no multi-worker TLS path at
    all -- ``serve_tls`` had no worker parameter.
    """
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h1(),
    )
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello, num_workers=2)
        except:
            pass
        exit()
    usleep(400000)

    var ok_count = 0
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        for _ in range(4):
            var s = TlsStream.connect("localhost", port, cfg)
            s.write_all(
                Span[UInt8, _](
                    _bytes(
                        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection:"
                        " close\r\n\r\n"
                    )
                )
            )
            if "hello https" in _read_until_close(s):
                ok_count += 1
            s.close()
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(ok_count, 4)


def test_https_alpn_negotiates_h2() raises:
    """The server actually selects ``h2`` when the client offers it.

    Split out from the round-trip test below deliberately. Asserting
    only "status 200" cannot tell h2 from an h1 fallback, and an
    earlier version of this file did exactly that -- it passed against
    a server that could not serve h2 at all. This one fails if ALPN
    lands anywhere other than h2.
    """
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h2_first(),
    )
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(300000)

    var negotiated = String("")
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        cfg.alpn = List[String]()
        cfg.alpn.append("h2")
        cfg.alpn.append("http/1.1")
        var s = TlsStream.connect("localhost", port, cfg^)
        negotiated = s.alpn_selected()
        s.close()
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(negotiated, "h2")


def test_https_alpn_h2_is_served() raises:
    """ALPN ``h2`` over TLS reaches the handler.

    The sequential path closed these connections with zero bytes sent;
    the reactor promotes them to an ``Http2ConnHandle`` that has adopted
    the session.
    """
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h2_first(),
    )
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(300000)

    var status = -1
    var body = String("")
    var raised = False
    try:
        var url = String("https://localhost:") + String(Int(port)) + String("/")
        with HttpClient(TlsConfig(ca_bundle=_CA_CRT)) as c:
            var r = c.get(url)
            status = r.status
            body = r.text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "h2-over-TLS round-trip raised")
    assert_equal(status, 200)
    assert_equal(body, "hello https")


def test_stalled_handshake_does_not_block_other_clients() raises:
    """A peer that opens a TLS connection and dribbles a partial
    ClientHello must not stall anyone else.

    On the old sequential driver this wedged the whole server: the
    accept loop sat in that one handshake. On the reactor the stalled
    connection just holds a slot until the idle timer reaps it, while
    other clients are served normally.
    """
    var cfg_srv = ServerConfig(idle_timeout_ms=500)
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h1(),
        config=cfg_srv^,
    )
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(300000)

    var served = False
    try:
        # Raw TCP: one byte of a TLS record header, then silence.
        var stalled = _connect_loopback(port)
        var one = stack_allocation[1, UInt8]()
        one[0] = UInt8(0x16)  # TLS handshake content type
        _ = _send(stalled, one, c_size_t(1), c_int(MSG_NOSIGNAL))

        # A real client on the same server still completes.
        var tcfg = TlsConfig(ca_bundle=_CA_CRT)
        var s = TlsStream.connect("localhost", port, tcfg)
        s.write_all(
            Span[UInt8, _](
                _bytes(
                    "GET / HTTP/1.1\r\nHost: localhost\r\nConnection:"
                    " close\r\n\r\n"
                )
            )
        )
        served = "hello https" in _read_until_close(s)
        s.close()
        _ = _close(stalled)
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(served, "a stalled handshake blocked a healthy client")


def test_bind_tls_constructs() raises:
    """``bind_tls`` loads the cert/key and binds without serving."""
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h1(),
    )
    var addrs = srv.local_addrs()
    assert_true(len(addrs) == 1, "one bound address expected")
    assert_true(addrs[0].port > 0, "ephemeral port must be assigned")


def main() raises:
    print("=" * 60)
    print("test_https_reactor.mojo — HTTPS on the unified reactor")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
