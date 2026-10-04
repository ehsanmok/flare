# PLATFORM: linux
"""APP-49: an interim `100 Continue` that the socket does not take whole is
never completed: on cleartext the client gets a truncated interim line glued
to the final response; on TLS the final response is lost and the connection
is torn down.

Lean: Flare.Bugs.APP_49.violates_spec, Flare.Bugs.APP_49.tls_response_lost
(counterexamples) and Flare.Bugs.APP_49.fixed_meets_spec (fix meets spec).
flare/http/_reactor/conn_handle.mojo:544-576 @59bda50
(``_maybe_send_continue``): the interim line is written with one
non-blocking ``_send`` (cleartext) or ``SSL_write`` (TLS, via
``TlsTransport.send``) whose result is ignored, and ``continue_sent`` is
set either way. The final response is later serialised into a cleared
``write_buf`` (``_finalise_response``, 718-756) and sent from offset 0
(``on_writable`` 1286-1312, ``_flush_write_buf_tls`` 1213-1240).

Spec (RFC 9112 sec 2.1 and 4; RFC 9110 sec 15.2): the bytes a server sends
on a connection are a sequence of complete messages, and an interim 1xx
response is a complete status line and header section. A request that was
read whole is answered.

Precondition: the connection returns to STATE_READING once the previous
response has been handed to the kernel (or to OpenSSL), while the socket
send buffer can still be nearly full. Here a pipelining client with a
small receive window (SO_RCVBUF 4096 set before connecting) sends a GET for
a few KiB and the head of a POST with ``Expect: 100-continue`` in one write
and reads nothing; the accepted socket has SO_SNDBUF 2048. The size of the
first response is varied until the interim does not go out whole:

* cleartext: the kernel takes 1..24 of the 25 bytes (Linux; on macOS a
  non-blocking TCP send this small is all or nothing, so this part never
  meets its precondition there);
* TLS: ``SSL_write`` cannot write the whole 47-byte record and returns
  WANT_WRITE. Flare sets no SSL mode, so ``SSL_write`` never returns a short
  count (no SSL_MODE_ENABLE_PARTIAL_WRITE); the record stays pending inside
  OpenSSL, and the next ``SSL_write`` with a different buffer fails with
  SSL_R_BAD_WRITE_RETRY (no SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER).

On macOS neither precondition was met with these buffer sizes (300
cleartext and 1600 TLS sizes tried), hence `# PLATFORM: linux`.

An attempt counts only if, after the client has read the whole first
response, the interim is short (cleartext) or absent (TLS). If no size
meets a variant's precondition the repro prints ``inconclusive:``; it
prints ``OK:`` only if every variant that can occur on this platform met
its precondition and the stream was well-formed.

Expected: after the first response the client reads the whole interim line
(possibly later) and then the final ``HTTP/1.1 200 OK``.
Actual: cleartext ``HTTP/1.1 100 Continue\\r\\n\\r`` (or a shorter prefix)
directly followed by ``HTTP/1.1 200 OK``; TLS: the server's write of the
final response fails, ``should_close`` is set and the client receives
nothing.

Minimal fix: keep what the socket did not take. Cleartext: keep the unsent
tail of the interim on the connection and put it in front of the final
response in ``write_buf`` (``_transition_to_writing``). TLS: keep the
interim in a buffer owned by the connection, and on WANT_* retry
``SSL_write`` from that same buffer at the start of
``_flush_write_buf_tls`` before any byte of the response.
"""

from std.memory import Pointer
from std.sys.info import CompilationTarget

from flare.net import SocketAddr
from flare.net._libc import _connect
from flare.net.socket import RawSocket, AF_INET, SOCK_STREAM, _build_sockaddr_in
from flare.tcp import TcpStream, TcpListener
from flare.tls import TlsConfig, TlsStream
from flare.tls._server_ffi import ServerCtx
from flare.http._reactor.tls_transport import TlsTransport, HS_DONE
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ServerConfig
from flare.http.handler import FnHandler
from flare.http._server_reactor_impl import ConnHandle, STATE_READING
from flare.runtime._thread import ThreadHandle
from flare.utils import usleep

comptime INTERIM = "HTTP/1.1 100 Continue\r\n\r\n"
comptime FINAL = "HTTP/1.1 200 OK"


def _sized(req: Request) raises -> Response:
    var n = Int(String(req.url[byte=1:]))
    var resp = Response(status=200, reason="OK")
    resp.body = List[UInt8](length=n, fill=UInt8(97))
    return resp^


def _small_window_client(addr: SocketAddr) raises -> TcpStream:
    """`TcpStream.connect` with SO_RCVBUF 4096 set before the handshake,
    so the client advertises a small window from the start."""
    var sock = RawSocket(AF_INET, SOCK_STREAM)
    sock.set_recv_buffer(4096)
    var sa = _build_sockaddr_in(addr)
    var rc = _connect(sock.fd, sa[0], sa[1])
    sa[0].unsafe_free()
    if rc < 0:
        raise Error("setup: connect failed")
    sock.set_tcp_nodelay(True)
    return TcpStream(sock^, addr)


def _requests(body_len: Int) -> String:
    return String(
        "GET /",
        body_len,
        " HTTP/1.1\r\nHost: a\r\n\r\n",
        "POST /2 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n",
        "Expect: 100-continue\r\n\r\n",
    )


def _read_plain(mut c: TcpStream) -> List[UInt8]:
    """Read until 300 ms of silence (the caller set the timeout)."""
    var out = List[UInt8]()
    var buf = List[UInt8](length=65536, fill=UInt8(0))
    while True:
        var n: Int
        try:
            n = c.read(buf.unsafe_ptr(), len(buf))
        except:
            break
        if n <= 0:
            break
        for i in range(n):
            out.append(buf[i])
    return out^


def _read_tls(mut c: TlsStream) -> List[UInt8]:
    var out = List[UInt8]()
    var buf = List[UInt8](length=65536, fill=UInt8(0))
    while True:
        var n: Int
        try:
            n = c.read(buf.unsafe_ptr(), len(buf))
        except:
            break
        if n <= 0:
            break
        for i in range(n):
            out.append(buf[i])
    return out^


def _show(b: List[UInt8], start: Int, count: Int) -> String:
    var end = min(len(b), start + count)
    if start >= end:
        return String("")
    var s = String(unsafe_from_utf8=Span[UInt8, _](b)[start:end])
    return s.replace("\r", "\\r").replace("\n", "\\n")


def _starts_with(b: List[UInt8], s: String) -> Bool:
    var sb = s.as_bytes()
    if len(b) < len(sb):
        return False
    for i in range(len(sb)):
        if b[i] != sb[i]:
            return False
    return True


struct Outcome(Copyable, Movable):
    var met: Bool
    """The precondition held: the interim did not go out whole."""
    var first_len: Int
    var interim_got: Int
    var tail: List[UInt8]
    """Everything the client read after the first response."""
    var closed: Bool
    """The server's step for the final response returned done."""

    def __init__(out self):
        self.met = False
        self.first_len = 0
        self.interim_got = 0
        self.tail = List[UInt8]()
        self.closed = False


def _serve_first(
    mut ch: ConnHandle, h: FnHandler, cfg: ServerConfig
) raises -> Int:
    """Queue and flush the first response, then run the readable pass that
    sends the interim. Returns the first response's length, or 0 if this
    attempt does not reach that state."""
    for _ in range(200):
        usleep(5000)
        _ = ch.on_readable(h, cfg)
        if len(ch.write_buf) > 0:
            break
    var first_len = len(ch.write_buf)
    if first_len == 0:
        return 0
    _ = ch.on_writable(cfg)
    if ch.state != STATE_READING:
        return 0  # the first response did not leave whole
    # The head of request 2 is already buffered: the next readable pass
    # (the reactor runs it straight after the flush) sends the interim.
    for _ in range(200):
        _ = ch.on_readable(h, cfg)
        if ch.continue_sent:
            return first_len
        usleep(5000)
    return 0


def _serve_final(mut ch: ConnHandle, h: FnHandler, cfg: ServerConfig) raises -> Bool:
    """Read the body, flush the final response; True if the step closed."""
    for _ in range(200):
        usleep(5000)
        _ = ch.on_readable(h, cfg)
        if len(ch.write_buf) > 0:
            break
    var closed = False
    for _ in range(20):
        var st = ch.on_writable(cfg)
        if st.done:
            closed = True
            break
        if ch.state == STATE_READING:
            break
        usleep(5000)
    return closed


def _plain_attempt(body_len: Int) raises -> Outcome:
    var out = Outcome()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = _small_window_client(listener.local_addr())
    var server = listener.accept()
    server._socket.set_send_buffer(2048)
    server._socket.set_nonblocking(True)
    var ch = ConnHandle(server^)
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    cfg.write_timeout_ms = 0
    var h = FnHandler(_sized)
    client.write_all(_requests(body_len).as_bytes())
    var first_len = _serve_first(ch, h, cfg)
    if first_len == 0:
        client.close()
        return out^
    client.set_recv_timeout(300)
    var got = _read_plain(client)
    if len(got) < first_len:
        client.close()
        return out^
    out.first_len = first_len
    out.interim_got = len(got) - first_len
    if out.interim_got <= 0 or out.interim_got >= String(INTERIM).byte_length():
        client.close()
        return out^  # the interim went out whole, or not at all
    out.met = True
    client.write_all(String("hello").as_bytes())
    out.closed = _serve_final(ch, h, cfg)
    var rest = _read_plain(client)
    for i in range(first_len, len(got)):
        out.tail.append(got[i])
    for i in range(len(rest)):
        out.tail.append(rest[i])
    client.close()
    return out^


struct Hs(Movable):
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
    var hs = arg.unsafe_bitcast[Hs]()
    try:
        var cfg = TlsConfig(ca_bundle="tests/certs/ca.crt")
        hs[].tls = Optional[TlsStream](
            TlsStream.connect_over_tcp(hs[].tcp.take(), "localhost", cfg)
        )
    except:
        pass
    return _null()


def _tls_attempt(body_len: Int, ctx: ServerCtx) raises -> Outcome:
    var out = Outcome()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = _small_window_client(listener.local_addr())
    var server = listener.accept()
    server._socket.set_send_buffer(2048)
    server._socket.set_nonblocking(True)
    var tr = TlsTransport(ctx, Int(server._socket.fd))
    # The client handshake blocks, so it runs on a thread while this
    # thread steps the server side.
    var hs = Hs(client^)
    var hs_addr = Int(Pointer[Hs, _](to=hs))
    var th = ThreadHandle.spawn_os[_hs_thread](
        Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=hs_addr)
    )
    var done = False
    for _ in range(5000):
        var rc = tr.do_handshake()
        if rc == HS_DONE:
            done = True
            break
        if rc < 0:
            break
        usleep(200)
    th.join()
    if not done or not hs.tls:
        return out^
    var c = hs.tls.take()
    var ch = ConnHandle(server^)
    ch.attach_tls(tr^)
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    cfg.write_timeout_ms = 0
    var h = FnHandler(_sized)
    c.write_all(_requests(body_len).as_bytes())
    var first_len = _serve_first(ch, h, cfg)
    if first_len == 0:
        return out^
    c.set_recv_timeout(300)
    var got = _read_tls(c)
    if len(got) < first_len:
        return out^
    out.first_len = first_len
    out.interim_got = len(got) - first_len
    if out.interim_got != 0:
        return out^  # the interim record went out whole
    out.met = True
    try:
        c.write_all(String("hello").as_bytes())
    except:
        pass
    out.closed = _serve_final(ch, h, cfg)
    out.tail = _read_tls(c)
    return out^


def _well_formed(o: Outcome) -> Bool:
    return not o.closed and _starts_with(o.tail, String(INTERIM + FINAL))


def main() raises:
    var bugs = 0
    var unmet = List[String]()
    var oks = List[String]()

    var plain_met = False
    var tried = 0
    for body_len in range(5900, 6200):
        var o = _plain_attempt(body_len)
        tried += 1
        if not o.met:
            continue
        plain_met = True
        var msg = String(
            "cleartext: send took ",
            o.interim_got,
            " of 25 bytes of the 100 Continue after a ",
            o.first_len,
            " byte response; the client then read ",
            _show(o.tail, 0, 44),
        )
        if _well_formed(o):
            oks.append(msg)
        else:
            print("BUG REPRODUCED:", msg)
            bugs += 1
        break
    if not plain_met:
        unmet.append(
            String(
                "cleartext: no attempt left a partially sent interim line (",
                tried,
                " sizes)",
            )
        )

    var ctx = ServerCtx.new("tests/certs/server.crt", "tests/certs/server.key")
    var tls_met = False
    tried = 0
    for body_len in range(2000, 5200, 2):
        var o = _tls_attempt(body_len, ctx)
        tried += 1
        if not o.met:
            continue
        tls_met = True
        var msg = String(
            "TLS: the interim record did not go out after a ",
            o.first_len,
            " byte response (client read it all, then nothing for 300 ms);",
            " the final response step closed=",
            o.closed,
            " and the client then read ",
            len(o.tail),
            " bytes: ",
            _show(o.tail, 0, 44),
        )
        if _well_formed(o):
            oks.append(msg)
        else:
            print("BUG REPRODUCED:", msg)
            bugs += 1
        break
    if not tls_met:
        unmet.append(
            String(
                "TLS: no attempt left the interim record unsent (",
                tried,
                " sizes)",
            )
        )

    if bugs > 0:
        raise Error("APP-49")
    # A partial cleartext send cannot happen on macOS (send low-water
    # mark), so only the TLS part is required there.
    var need_plain = not CompilationTarget.is_macos()
    if tls_met and (plain_met or not need_plain):
        for m in oks:
            print("OK:", m)
        return
    for m in unmet:
        print("inconclusive:", m)
    raise Error("APP-49 inconclusive")
