"""Tests for ``flare.runtime.Reactor`` (Phase 1.2).

Both the Linux epoll backend and the macOS kqueue backend are exercised via
the same uniform API; the struct itself uses ``@parameter if
CompilationTarget.is_linux()`` internally so callers never see the platform
split.

Tests rely only on loopback socketpairs (built from a TcpListener +
TcpStream pair) and do not require any external network access.
"""

from std.testing import (
    assert_equal,
    assert_not_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)
from std.ffi import c_int, c_size_t

from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener
from flare.runtime import (
    Reactor,
    Event,
    INTEREST_READ,
    INTEREST_WRITE,
    EVENT_READABLE,
    EVENT_WRITABLE,
    EVENT_HUP,
    WAKEUP_TOKEN,
)


# ── Basic lifecycle ───────────────────────────────────────────────────────────


def test_create_and_destroy() raises:
    """A freshly-created reactor has zero user registrations."""
    var r = Reactor()
    assert_equal(r.registered_count(), 0)


def test_many_create_destroy_no_leak() raises:
    """Creating and destroying many reactors in sequence doesn't leak fds.

    Not a perfect leak test — relies on the process not hitting EMFILE.
    Run 100 iterations; any leak of 2-3 fds per reactor would trip this on
    most dev machines by ~300 iterations, so 100 gives ~3x safety margin.
    """
    for _ in range(100):
        var r = Reactor()
        _ = r.registered_count()


# ── register / modify / unregister ────────────────────────────────────────────


def test_register_then_is_registered() raises:
    """After register(), is_registered() returns True."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    r.register(listener._socket.fd, UInt64(1), INTEREST_READ)
    assert_true(r.is_registered(listener._socket.fd))
    assert_equal(r.registered_count(), 1)
    r.unregister(listener._socket.fd)
    assert_false(r.is_registered(listener._socket.fd))
    listener.close()


def test_register_rejects_wakeup_token() raises:
    """Using WAKEUP_TOKEN as a user token is rejected."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    with assert_raises():
        r.register(listener._socket.fd, WAKEUP_TOKEN, INTEREST_READ)
    listener.close()


def test_register_rejects_empty_interest() raises:
    """interest must include at least READ or WRITE."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    with assert_raises():
        r.register(listener._socket.fd, UInt64(1), 0)
    listener.close()


def test_register_same_fd_twice_raises() raises:
    """Registering an fd that is already registered raises."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    r.register(listener._socket.fd, UInt64(1), INTEREST_READ)
    with assert_raises():
        r.register(listener._socket.fd, UInt64(2), INTEREST_READ)
    listener.close()


def test_unregister_unknown_fd_raises() raises:
    """unregister() on a never-registered fd raises."""
    var r = Reactor()
    with assert_raises():
        r.unregister(c_int(999))


def test_modify_unknown_fd_raises() raises:
    """modify() on a never-registered fd raises."""
    var r = Reactor()
    with assert_raises():
        r.modify(c_int(999), INTEREST_READ)


def test_modify_from_read_to_write() raises:
    """modify() changes the interest without changing the token."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    r.register(listener._socket.fd, UInt64(42), INTEREST_READ)
    r.modify(listener._socket.fd, INTEREST_WRITE)
    # Token preserved; fd still registered.
    assert_true(r.is_registered(listener._socket.fd))
    listener.close()


# ── poll timing ───────────────────────────────────────────────────────────────


def test_poll_timeout_zero_returns_empty() raises:
    """Polling an idle reactor with timeout 0 returns no events immediately."""
    var r = Reactor()
    var events = List[Event]()
    var n = r.poll(0, events)
    assert_equal(n, 0)
    assert_equal(len(events), 0)


def test_poll_timeout_short_returns_empty() raises:
    """A short bounded timeout on an idle reactor also returns no events."""
    var r = Reactor()
    var events = List[Event]()
    var n = r.poll(10, events)
    assert_equal(n, 0)


# ── Readability detection ─────────────────────────────────────────────────────


def test_poll_detects_readable_on_writable_peer() raises:
    """A connected peer writing bytes triggers EVENT_READABLE."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    listener.close()

    var token = UInt64(0x1234567890ABCDEF)
    r.register(server._socket.fd, token, INTEREST_READ)
    # Client writes -> server becomes readable
    var msg = List[UInt8]()
    msg.append(UInt8(ord("X")))
    _ = client.write(Span[UInt8](msg))

    var events = List[Event]()
    var n = r.poll(1000, events)
    var found = False
    for i in range(n):
        var ev = events[i]
        if ev.token == token and ev.is_readable():
            found = True
    assert_true(found, "expected a readable event for token")

    r.unregister(server._socket.fd)
    client.close()
    server.close()


def test_poll_detects_writable() raises:
    """A fresh connected socket is typically immediately writable."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    listener.close()

    var token = UInt64(7)
    r.register(client._socket.fd, token, INTEREST_WRITE)
    var events = List[Event]()
    var n = r.poll(1000, events)
    var found = False
    for i in range(n):
        var ev = events[i]
        if ev.token == token and ev.is_writable():
            found = True
    assert_true(found, "expected a writable event on fresh connected socket")

    r.unregister(client._socket.fd)
    client.close()
    server.close()


def test_poll_detects_hup_on_peer_close() raises:
    """When the peer closes, the reactor reports HUP (possibly with READABLE).
    """
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    listener.close()

    var token = UInt64(77)
    r.register(server._socket.fd, token, INTEREST_READ)
    # Client closes -> server fd gets HUP
    client.close()

    var events = List[Event]()
    var n = r.poll(1000, events)
    var saw_hup_or_read = False
    for i in range(n):
        var ev = events[i]
        if ev.token == token and (ev.is_hup() or ev.is_readable()):
            saw_hup_or_read = True
    assert_true(
        saw_hup_or_read,
        "expected HUP or READABLE after peer close",
    )

    r.unregister(server._socket.fd)
    server.close()


# ── Multi-fd handling ─────────────────────────────────────────────────────────


def test_poll_multiple_fds() raises:
    """Multiple registered fds can all fire in a single poll."""
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port

    # 3 pairs is enough to prove the loop without fighting Mojo's Movable-not-
    # Copyable List limitation.
    var c1 = TcpStream.connect(SocketAddr.localhost(port))
    var s1 = listener.accept()
    r.register(s1._socket.fd, UInt64(1001), INTEREST_READ)
    var c2 = TcpStream.connect(SocketAddr.localhost(port))
    var s2 = listener.accept()
    r.register(s2._socket.fd, UInt64(1002), INTEREST_READ)
    var c3 = TcpStream.connect(SocketAddr.localhost(port))
    var s3 = listener.accept()
    r.register(s3._socket.fd, UInt64(1003), INTEREST_READ)
    listener.close()

    # Each client writes a byte.
    var m1 = List[UInt8]()
    m1.append(UInt8(ord("A")))
    _ = c1.write(Span[UInt8](m1))
    var m2 = List[UInt8]()
    m2.append(UInt8(ord("B")))
    _ = c2.write(Span[UInt8](m2))
    var m3 = List[UInt8]()
    m3.append(UInt8(ord("C")))
    _ = c3.write(Span[UInt8](m3))

    # poll may return a subset of ready fds per call on some kernels (the
    # kernel's readiness list can trickle in, especially on macOS kqueue).
    # Accumulate across up to 20 short polls — in practice kqueue usually
    # surfaces all three within 2-3 iterations; the extra budget protects
    # against flaky CI runs under load.
    var events = List[Event]()
    var seen = List[Bool]()
    seen.resize(3, False)
    var total_seen = 0
    var attempts = 0
    while total_seen < 3 and attempts < 20:
        events.clear()
        _ = r.poll(200, events, max_events=16)
        for j in range(len(events)):
            var tok = events[j].token
            if tok == UInt64(1001) and not seen[0]:
                seen[0] = True
                total_seen += 1
            elif tok == UInt64(1002) and not seen[1]:
                seen[1] = True
                total_seen += 1
            elif tok == UInt64(1003) and not seen[2]:
                seen[2] = True
                total_seen += 1
        attempts += 1
    assert_true(
        total_seen == 3,
        "expected all 3 tokens across <=20 polls; got " + String(total_seen),
    )

    r.unregister(s1._socket.fd)
    r.unregister(s2._socket.fd)
    r.unregister(s3._socket.fd)
    c1.close()
    c2.close()
    c3.close()
    s1.close()
    s2.close()
    s3.close()


# ── Wakeup ────────────────────────────────────────────────────────────────────


def test_wakeup_breaks_blocking_poll() raises:
    """``wakeup()`` before poll() causes poll to return a wakeup event.

    Since we're single-threaded, we invoke wakeup() first and then poll()
    with timeout=0 — the event is already queued so poll returns it
    immediately.
    """
    var r = Reactor()
    r.wakeup()
    var events = List[Event]()
    var n = r.poll(100, events)
    assert_true(n >= 1, "expected at least 1 event after wakeup")
    var saw_wakeup = False
    for i in range(n):
        if events[i].is_wakeup():
            saw_wakeup = True
    assert_true(saw_wakeup, "expected a wakeup event flagged is_wakeup=True")


def test_wakeup_does_not_appear_without_call() raises:
    """Without wakeup(), poll(0) on an empty reactor returns 0."""
    var r = Reactor()
    var events = List[Event]()
    var n = r.poll(0, events)
    assert_equal(n, 0)


def test_wakeup_after_drain_can_fire_again() raises:
    """After one wakeup+poll cycle, subsequent wakeup() still works."""
    var r = Reactor()
    r.wakeup()
    var events = List[Event]()
    _ = r.poll(100, events)
    # Drained — now fire another wakeup
    r.wakeup()
    events.clear()
    var n = r.poll(100, events)
    assert_true(n >= 1, "expected second wakeup to fire")


# ── Max-events capping ────────────────────────────────────────────────────────


def test_poll_honors_max_events_cap() raises:
    """When more fds are ready than ``max_events``, only that many are returned.
    """
    var r = Reactor()
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var c1 = TcpStream.connect(SocketAddr.localhost(port))
    var s1 = listener.accept()
    var c2 = TcpStream.connect(SocketAddr.localhost(port))
    var s2 = listener.accept()
    var c3 = TcpStream.connect(SocketAddr.localhost(port))
    var s3 = listener.accept()
    var c4 = TcpStream.connect(SocketAddr.localhost(port))
    var s4 = listener.accept()
    listener.close()
    r.register(s1._socket.fd, UInt64(1), INTEREST_READ)
    r.register(s2._socket.fd, UInt64(2), INTEREST_READ)
    r.register(s3._socket.fd, UInt64(3), INTEREST_READ)
    r.register(s4._socket.fd, UInt64(4), INTEREST_READ)

    # Make all 4 servers readable.
    var m = List[UInt8]()
    m.append(UInt8(ord("X")))
    _ = c1.write(Span[UInt8](m))
    _ = c2.write(Span[UInt8](m))
    _ = c3.write(Span[UInt8](m))
    _ = c4.write(Span[UInt8](m))

    # Ask for at most 2 events.
    var events = List[Event]()
    var n = r.poll(1000, events, max_events=2)
    assert_true(n <= 2, "max_events=2 must cap result; got " + String(n))
    assert_equal(len(events), n)

    r.unregister(s1._socket.fd)
    r.unregister(s2._socket.fd)
    r.unregister(s3._socket.fd)
    r.unregister(s4._socket.fd)
    c1.close()
    c2.close()
    c3.close()
    c4.close()
    s1.close()
    s2.close()
    s3.close()
    s4.close()


# ── Event bit flags ───────────────────────────────────────────────────────────


def test_event_flag_helpers() raises:
    """Event.is_readable/writable/error/hup/wakeup return correct bools."""
    var e = Event(UInt64(1), EVENT_READABLE)
    assert_true(e.is_readable())
    assert_false(e.is_writable())
    assert_false(e.is_hup())
    var e2 = Event(UInt64(2), EVENT_READABLE | EVENT_HUP)
    assert_true(e2.is_readable())
    assert_true(e2.is_hup())
    var wake = Event(WAKEUP_TOKEN, EVENT_READABLE)
    assert_true(wake.is_wakeup())


def main() raises:
    print("=" * 60)
    print("test_reactor.mojo — Phase 1.2 Reactor abstraction")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
