"""The interim ``100 Continue`` is completed when the socket takes it only
in part (APP-49).

A cleartext ``send`` can take part of the 25-byte line (Linux does), and a
TLS ``SSL_write`` can answer WANT_WRITE and keep the record pending. Either
way the connection must finish the interim before the final response: a
half-written status line followed by ``HTTP/1.1 200 OK`` is a corrupt stream,
and after WANT_WRITE a write from another buffer fails with
``SSL_R_BAD_WRITE_RETRY`` and closes the connection.

A kernel send buffer cannot be made to take a short count on every platform,
so these tests put the connection in the state a short send leaves
(``continue_pending``) and check the bytes that follow. The end-to-end
trigger is ``formal/repro/APP-49_continue_partial_send_corrupts_stream.mojo``
(Linux).
"""

from std.memory import Pointer
from std.testing import assert_equal, assert_true, TestSuite

from flare.http import Request, Response, ServerConfig
from flare.http.handler import FnHandler
from flare.http._server_reactor_impl import ConnHandle, STATE_WRITING
from flare.http._reactor.tls_transport import TlsTransport, HS_DONE
from flare.net import SocketAddr
from flare.runtime._thread import ThreadHandle
from flare.tcp import TcpListener, TcpStream
from flare.tls import TlsConfig, TlsStream
from flare.tls._server_ffi import ServerCtx
from flare.utils import usleep

comptime INTERIM = "HTTP/1.1 100 Continue\r\n\r\n"
comptime FINAL = "HTTP/1.1 200 OK"
comptime POST = String(
    "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n"
    "Expect: 100-continue\r\n\r\nhello"
)


def _ok(req: Request) raises -> Response:
    return Response(status=200, reason="OK")


def _text(b: List[UInt8]) -> String:
    return String(unsafe_from_utf8=Span[UInt8, _](b))


def _read_plain(mut c: TcpStream, want: Int) raises -> List[UInt8]:
    """Read until ``want`` bytes arrived (or the receive timeout hits)."""
    var out = List[UInt8]()
    var buf = List[UInt8](length=4096, fill=UInt8(0))
    while len(out) < want:
        var n = c.read(buf.unsafe_ptr(), len(buf))
        if n <= 0:
            break
        for i in range(n):
            out.append(buf[i])
    return out^


def _pump(mut ch: ConnHandle, h: FnHandler, cfg: ServerConfig) raises:
    """Run ``on_readable`` until the response is queued. The request is
    already in the loopback socket, so this converges at once; the bound
    only stops a broken build from spinning."""
    for _ in range(100000):
        _ = ch.on_readable(h, cfg)
        if ch.state == STATE_WRITING:
            return
    raise Error("the request was never answered")


def test_cleartext_unsent_interim_tail_precedes_the_response() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    var ch = ConnHandle(server^)
    var cfg = ServerConfig()
    var h = FnHandler(_ok)

    # The kernel took 24 of the 25 bytes of the interim.
    ch.continue_sent = True
    ch._keep_unsent_interim(24)
    assert_equal(len(ch.continue_pending), 1)

    client.write_all(POST.as_bytes())
    _pump(ch, h, cfg)
    _ = ch.on_writable(cfg)

    client.set_recv_timeout(2000)
    var tail_len = 1
    var got = _read_plain(client, tail_len + FINAL.byte_length())
    assert_true(len(got) >= tail_len + FINAL.byte_length())
    # The last byte of the interim, then the response, with nothing between.
    assert_equal(
        _text(got)[byte = 0 : tail_len + FINAL.byte_length()],
        String("\n") + FINAL,
    )
    assert_equal(len(ch.continue_pending), 0)


def test_interim_taken_whole_leaves_nothing_pending() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    var ch = ConnHandle(server^)
    var cfg = ServerConfig()
    var h = FnHandler(_ok)

    var head = String(
        "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n"
        "Expect: 100-continue\r\n\r\n"
    )
    client.write_all(head.as_bytes())
    for _ in range(100000):
        _ = ch.on_readable(h, cfg)
        if ch.continue_sent:
            break
    assert_true(ch.continue_sent)
    assert_equal(len(ch.continue_pending), 0)
    client.set_recv_timeout(2000)
    var got = _read_plain(client, INTERIM.byte_length())
    assert_equal(_text(got), String(INTERIM))


def test_keep_unsent_interim_ignores_none_and_all() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var server = listener.accept()
    var ch = ConnHandle(server^)
    ch._keep_unsent_interim(0)
    assert_equal(len(ch.continue_pending), 0)
    ch._keep_unsent_interim(String(INTERIM).byte_length())
    assert_equal(len(ch.continue_pending), 0)
    ch._keep_unsent_interim(1)
    assert_equal(len(ch.continue_pending), String(INTERIM).byte_length() - 1)
    client.close()


# ── TLS: the retry goes first, from the connection's own buffer ─────────────


struct _Hs(Movable):
    var tcp: Optional[TcpStream]
    var tls: Optional[TlsStream]

    def __init__(out self, var tcp: TcpStream):
        self.tcp = Optional[TcpStream](tcp^)
        self.tls = Optional[TlsStream]()


def _null() -> Pointer[UInt8, MutUntrackedOrigin]:
    var z = 0
    return Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=z)


def _hs_thread(
    arg: Pointer[UInt8, MutUntrackedOrigin]
) -> Pointer[UInt8, MutUntrackedOrigin]:
    var hs = arg.unsafe_bitcast[_Hs]()
    try:
        var cfg = TlsConfig(ca_bundle="tests/certs/ca.crt")
        hs[].tls = Optional[TlsStream](
            TlsStream.connect_over_tcp(hs[].tcp.take(), "localhost", cfg)
        )
    except:
        pass
    return _null()


def test_tls_pending_interim_is_retried_before_the_response() raises:
    var ctx = ServerCtx.new("tests/certs/server.crt", "tests/certs/server.key")
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    var tr = TlsTransport(ctx, Int(server._socket.fd))
    var hs = _Hs(client^)
    var hs_addr = Int(Pointer[_Hs, _](to=hs))
    var th = ThreadHandle.spawn_os[_hs_thread](
        Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=hs_addr)
    )
    var done = False
    for _ in range(50000):
        var rc = tr.do_handshake()
        if rc == HS_DONE:
            done = True
            break
        if rc < 0:
            break
        usleep(200)
    th.join()
    assert_true(done, "server-side TLS handshake did not complete")
    assert_true(Bool(hs.tls), "client-side TLS handshake did not complete")
    var c = hs.tls.take()

    var ch = ConnHandle(server^)
    ch.attach_tls(tr^)
    var cfg = ServerConfig()
    var h = FnHandler(_ok)

    # OpenSSL answered WANT_WRITE to the interim record: the connection
    # owns it and still owes it to the client.
    ch.continue_sent = True
    var interim = String(INTERIM)
    for b in interim.as_bytes():
        ch.continue_pending.append(b)

    c.write_all(POST.as_bytes())
    _pump(ch, h, cfg)
    var st = ch.on_writable(cfg)
    assert_true(not st.done, "the response write closed the connection")
    assert_equal(len(ch.continue_pending), 0)

    c.set_recv_timeout(2000)
    var want = INTERIM.byte_length() + FINAL.byte_length()
    var out = List[UInt8]()
    var buf = List[UInt8](length=4096, fill=UInt8(0))
    while len(out) < want:
        var n = c.read(buf.unsafe_ptr(), len(buf))
        if n <= 0:
            break
        for i in range(n):
            out.append(buf[i])
    assert_equal(_text(out)[byte=0:want], String(INTERIM) + FINAL)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
