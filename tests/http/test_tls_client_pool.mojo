"""Tests for the HTTPS (TLS HTTP/1.1) client connection pool (W5).

Unlike the cleartext pool -- which stores raw fds -- the TLS pool
(:class:`flare.http._client.tls_pool.TlsConnectionPool`) stores whole
established ``TlsStream`` values so the TLS handshake is skipped on
keep-alive reuse. These tests drive the pool directly with *real*
``TlsStream`` connections against the loopback TLS echo server
(``flare_test_server_echo_n`` in ``libflare_tls.so``, the same harness
``test_tls_resume.mojo`` uses), verifying:

* A released stream is reported idle and a re-acquired stream is still a
  live, usable TLS connection (a full echo round trip succeeds *after*
  the acquire / release cycle -- the handshake is not redone).
* ``max_idle_per_host=0`` drops every released stream (idle stays 0).
* A disabled pool never keeps an idle stream.
* The pool is per-origin: distinct keys keep distinct buckets.

The full ``HttpClient`` HTTPS keep-alive round trip (request -> framed
read -> release) reuses the same ``TlsConnectionPool`` plus the shared
generic framed reader exercised end-to-end by the cleartext pool
(``test_h1_client_pool.mojo``); a reactor-driven TLS HTTP server for a
pure-Mojo e2e harness is gated on the same Mojo improvement noted in
``flare/tls/acceptor.mojo``.
"""

from std.ffi import OwnedDLHandle, c_int
from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.net.socket import _find_flare_lib
from flare.tls import TlsConfig, TlsStream
from flare.http._client.tls_pool import TlsConnectionPool
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _CA_CRT: String = "tests/certs/ca.crt"
comptime _SERVER_CRT: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"


@always_inline
def _c_str(s: String) -> Int:
    return Int(s.unsafe_ptr())


struct _TlsEchoServer:
    """RAII wrapper around the ``flare_test_server_*`` echo helper
    (per-message echo over one TLS connection)."""

    var _ptr: Int
    var _lib: OwnedDLHandle

    def __init__(out self) raises:
        self._lib = OwnedDLHandle(_find_flare_lib())
        var fn_new = self._lib.get_function[
            def(Int, Int, Int, c_int) thin abi("C") -> Int
        ]("flare_test_server_new")
        self._ptr = fn_new(
            _c_str(_SERVER_CRT), _c_str(_SERVER_KEY), 0, c_int(0)
        )
        if self._ptr == 0:
            raise Error("flare_test_server_new failed")

    def __del__(deinit self):
        if self._ptr != 0:
            var fn_free = self._lib.get_function[
                def(Int) thin abi("C") -> None
            ]("flare_test_server_free")
            fn_free(self._ptr)

    def port(self) raises -> Int:
        var fn_port = self._lib.get_function[def(Int) thin abi("C") -> c_int](
            "flare_test_server_port"
        )
        return Int(fn_port(self._ptr))

    def echo_n(self, n: Int) raises:
        var fn_n = self._lib.get_function[
            def(Int, c_int) thin abi("C") -> c_int
        ]("flare_test_server_echo_n")
        _ = fn_n(self._ptr, c_int(n))


def _spawn_echo_n(server: _TlsEchoServer, n: Int) -> Int:
    var pid = fork()
    if pid == 0:
        try:
            server.echo_n(n)
        except:
            pass
        exit()
    return pid


def _round_trip(mut stream: TlsStream) raises -> String:
    """Write one byte, read the echo back -- proves the connection is
    live and usable."""
    var msg = String("p")
    stream.write_all(msg.as_bytes())
    var buf = List[UInt8]()
    buf.resize(16, UInt8(0))
    var n = stream.read(buf.unsafe_ptr(), 16)
    if n <= 0:
        return String("")
    return String(unsafe_from_utf8=Span[UInt8, _](buf)[:n])


def test_release_acquire_keeps_live_connection() raises:
    """A released ``TlsStream`` is reported idle; the re-acquired stream
    is still a live TLS connection (echo round trip succeeds after the
    cycle, with no second handshake)."""
    var srv = _TlsEchoServer()
    var port = UInt16(srv.port())
    var pid = _spawn_echo_n(srv, 1)
    usleep(120_000)

    var raised = False
    var idle_after_release = -1
    var idle_after_acquire = -1
    var echo = String("")
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var s = TlsStream.connect("localhost", port, cfg)
        # First round trip on the fresh connection.
        assert_equal(_round_trip(s), "p")

        var pool = TlsConnectionPool.new()
        var key = TlsConnectionPool.build_key("https", "localhost", Int(port))
        assert_equal(pool.idle_count(), 0)
        pool.release(key, s^)
        idle_after_release = pool.idle_count()

        var got = pool.acquire(key)
        assert_true(Bool(got), "expected a pooled stream on acquire")
        var s2 = got.take()
        idle_after_acquire = pool.idle_count()
        # The reused connection still works -- handshake was not redone.
        echo = _round_trip(s2)
        s2.close()
        pool.free()
    except e:
        print("test_release_acquire_keeps_live_connection raised:", e)
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "pool round trip raised")
    assert_equal(idle_after_release, 1)
    assert_equal(idle_after_acquire, 0)
    assert_equal(echo, "p")


def test_max_idle_zero_drops_stream() raises:
    """``max_idle_per_host=0`` closes every released stream; idle stays
    0."""
    var srv = _TlsEchoServer()
    var port = UInt16(srv.port())
    var pid = _spawn_echo_n(srv, 1)
    usleep(120_000)

    var raised = False
    var idle_after = -1
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var s = TlsStream.connect("localhost", port, cfg)
        var pool = TlsConnectionPool.new(max_idle_per_host=0)
        var key = TlsConnectionPool.build_key("https", "localhost", Int(port))
        pool.release(key, s^)
        idle_after = pool.idle_count()
        pool.free()
    except e:
        print("test_max_idle_zero_drops_stream raised:", e)
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "max_idle=0 round trip raised")
    assert_equal(idle_after, 0)


def test_disabled_pool_drops_stream() raises:
    """A disabled pool never keeps an idle stream and reports 0."""
    var srv = _TlsEchoServer()
    var port = UInt16(srv.port())
    var pid = _spawn_echo_n(srv, 1)
    usleep(120_000)

    var raised = False
    var idle_after = -1
    var miss = True
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var s = TlsStream.connect("localhost", port, cfg)
        var pool = TlsConnectionPool.disabled()
        var key = TlsConnectionPool.build_key("https", "localhost", Int(port))
        pool.release(key, s^)
        idle_after = pool.idle_count()
        var got = pool.acquire(key)
        miss = not Bool(got)
        pool.free()
    except e:
        print("test_disabled_pool_drops_stream raised:", e)
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "disabled-pool round trip raised")
    assert_equal(idle_after, 0)
    assert_true(miss, "disabled pool must miss on acquire")


def test_pool_is_per_origin() raises:
    """Distinct keys keep distinct buckets: a stream released under one
    key is invisible to a different key but recoverable under its own.

    Uses a single live connection (the loopback echo server is
    sequential -- it can only service one connection at a time, so
    holding two open simultaneously would deadlock the accept loop)."""
    var srv = _TlsEchoServer()
    var port = UInt16(srv.port())
    var pid = _spawn_echo_n(srv, 1)
    usleep(120_000)

    var raised = False
    var idle_after_release = -1
    var miss_other = True
    var hit_own = False
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var s = TlsStream.connect("localhost", port, cfg)
        var pool = TlsConnectionPool.new()
        var key_a = TlsConnectionPool.build_key("https", "a.local", Int(port))
        var key_b = TlsConnectionPool.build_key("https", "b.local", Int(port))
        pool.release(key_a, s^)
        idle_after_release = pool.idle_count()
        # A different origin must not see a.local's idle stream.
        var other = pool.acquire(key_b)
        miss_other = not Bool(other)
        # The owning origin recovers it.
        var own = pool.acquire(key_a)
        hit_own = Bool(own)
        if own:
            var s2 = own.take()
            s2.close()
        pool.free()
    except e:
        print("test_pool_is_per_origin raised:", e)
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "per-origin round trip raised")
    assert_equal(idle_after_release, 1)
    assert_true(miss_other, "a different origin must miss")
    assert_true(hit_own, "the owning origin must hit")


def main() raises:
    print("=" * 60)
    print("test_tls_client_pool.mojo -- HTTPS keep-alive pool (W5)")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
