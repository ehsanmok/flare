"""Unit tests for the WS ALPN-driven auto-dispatcher
(``flare.ws.auto_client``).

The decision function :func:`decide_wire` is the pure piece the
dispatcher consults after the TLS handshake completes; this
suite pins every observable outcome at the byte level. The
runtime hand-off is now wired: :meth:`WsAutoClient.connect`
drives a real TLS handshake, the h2 preface + SETTINGS exchange
when ALPN selects ``h2``, the Extended CONNECT bootstrap, and
the per-path carrier storage. The I/O-touching integration
tests over loopback TLS live separately; this file pins the
no-I/O decision matrix + the error surfaces of the runtime call.

The 13 test cases:

1.  `prefer_h2 = True` default, with the runtime hint matrix
    that flows through the pure decision function.
2.  Cleartext ``ws://`` always routes to HTTP/1.1.
3.  TLS ``wss://`` with ``prefer_h2=False`` forces HTTP/1.1.
4.  TLS ``wss://`` + ALPN ``h2`` + ENABLE_CONNECT_PROTOCOL=1
    routes to HTTP/2 (the new path).
5.  TLS ``wss://`` + ALPN ``h2`` + no CONNECT-Protocol bit
    falls back to HTTP/1.1 (RFC 8441 §3 mandates the toggle).
6.  TLS ``wss://`` + ALPN ``http/1.1`` routes to HTTP/1.1.
7.  TLS ``wss://`` + empty ALPN (no extension) -> HTTP/1.1.
8.  Unknown ALPN identifier -> FAILED.
9.  Garbage URL scheme -> FAILED.
10. :meth:`WsAutoClient.url_scheme` parses ``wss://...``.
11. :meth:`WsAutoClient.url_scheme` parses ``ws://...``.
12. :meth:`WsAutoClient.connect` against an unreachable host
    surfaces a clear error + leaves :attr:`chosen_wire` at
    FAILED (the runtime surface).
13. :meth:`take_h1_client` / :meth:`take_h2_carrier` raise
    when the dispatcher hasn't picked the matching path.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.ws import (
    WsAutoClient,
    WsAutoClientConfig,
    WsWireChoice,
    decide_wire,
)


def _config_for(url: String, prefer_h2: Bool = True) -> WsAutoClientConfig:
    var cfg = WsAutoClientConfig()
    cfg.url = url
    cfg.prefer_h2 = prefer_h2
    return cfg^


def test_wire_choice_codepoints() raises:
    """Stable codepoints so the dispatcher can switch on them
    monomorphically + tests can pin specific outcomes."""
    assert_equal(WsWireChoice.UNDETERMINED, 0)
    assert_equal(WsWireChoice.HTTP_1_1, 1)
    assert_equal(WsWireChoice.HTTP_2, 2)
    assert_equal(WsWireChoice.FAILED, 3)


def test_config_defaults() raises:
    """A default config picks WS-over-h2 if possible (the v0.8
    Phase D production posture)."""
    var cfg = WsAutoClientConfig()
    assert_equal(cfg.url, String(""))
    assert_true(cfg.prefer_h2)
    assert_equal(len(cfg.subprotocols), 0)
    assert_equal(len(cfg.extensions), 0)


def test_decide_wire_cleartext_ws_skips_h2() raises:
    """``ws://`` (cleartext) always picks HTTP/1.1, regardless of
    the prefer_h2 toggle.  TLS is the precondition for any h2
    upgrade per RFC 8441 §1."""
    var pick = decide_wire(String("ws"), True, String(""), False)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_wss_prefer_h2_false_forces_h1() raises:
    """``wss://`` with ``prefer_h2=False`` forces HTTP/1.1."""
    var pick = decide_wire(String("wss"), False, String("h2"), True)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_wss_h2_alpn_with_connect_protocol() raises:
    """The happy h2 path: ``wss://`` + prefer_h2 + ALPN ``h2`` +
    ``ENABLE_CONNECT_PROTOCOL=1`` -> WS-over-h2."""
    var pick = decide_wire(String("wss"), True, String("h2"), True)
    assert_equal(pick, WsWireChoice.HTTP_2)


def test_decide_wire_wss_h2_alpn_without_connect_protocol() raises:
    """ALPN h2 but the server didn't advertise the CONNECT-
    Protocol setting -> fall back to HTTP/1.1 (RFC 8441 §3)."""
    var pick = decide_wire(String("wss"), True, String("h2"), False)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_wss_http11_alpn() raises:
    """The server picked http/1.1 in ALPN -> HTTP/1.1 wire."""
    var pick = decide_wire(String("wss"), True, String("http/1.1"), False)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_wss_no_alpn() raises:
    """TLS without ALPN (older TLS or server with no advertise)
    -> HTTP/1.1."""
    var pick = decide_wire(String("wss"), True, String(""), False)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_unknown_alpn_fails() raises:
    """An ALPN identifier the dispatcher doesn't understand
    -> FAILED.  The caller surfaces this as a connect-time
    error rather than silently downgrading to HTTP/1.1."""
    var pick = decide_wire(String("wss"), True, String("h3"), False)
    assert_equal(pick, WsWireChoice.FAILED)


def test_decide_wire_invalid_scheme_fails() raises:
    """A garbage URL scheme means the caller passed a bug; the
    dispatcher returns FAILED to surface it."""
    var pick = decide_wire(String("ftp"), True, String("h2"), True)
    assert_equal(pick, WsWireChoice.FAILED)


def test_url_scheme_parses_wss() raises:
    """The carrier's URL parser recognises ``wss://``."""
    var cfg = _config_for(String("wss://example.com/chat"))
    var auto = WsAutoClient(cfg^)
    assert_equal(auto.url_scheme(), String("wss"))


def test_url_scheme_parses_ws() raises:
    """The carrier's URL parser recognises ``ws://``."""
    var cfg = _config_for(String("ws://example.com/chat"))
    var auto = WsAutoClient(cfg^)
    assert_equal(auto.url_scheme(), String("ws"))


def test_connect_unreachable_host_surfaces_failure() raises:
    """The runtime hand-off lives in :meth:`WsAutoClient.connect`.
    With no listener at the configured host the DNS / TCP / TLS
    layers raise before the dispatcher reaches any wire choice;
    :attr:`chosen_wire` lands on :data:`WsWireChoice.FAILED`
    and :attr:`last_error` carries the failing message."""
    # Use a reserved-for-documentation literal IP that's
    # guaranteed not to host a TLS responder on 443 (RFC 5737
    # 203.0.113.0/24 is the TEST-NET-3 reserved range).
    var cfg = _config_for(String("wss://203.0.113.1/chat"))
    var auto = WsAutoClient(cfg^)
    var raised = False
    try:
        auto.connect()
    except:
        raised = True
    assert_true(raised, "expected WsAutoClient.connect to raise")
    assert_equal(auto.chosen_wire, WsWireChoice.FAILED)
    assert_true(
        auto.last_error.byte_length() > 0,
        "expected last_error to be populated on FAILED",
    )


def test_take_methods_guard_state() raises:
    """``take_h1_client`` and ``take_h2_carrier`` raise when the
    dispatcher hasn't picked the matching path. The carrier
    state machine is one-shot: each take call consumes the
    underlying handle + idempotently transitions to
    consumed-state."""
    var cfg = _config_for(String("wss://example.com/chat"))
    var auto = WsAutoClient(cfg^)
    var raised_h1 = False
    try:
        _ = auto.take_h1_client()
    except:
        raised_h1 = True
    assert_true(
        raised_h1,
        "expected take_h1_client to raise on UNDETERMINED carrier",
    )
    var raised_h2 = False
    try:
        _ = auto.take_h2_carrier()
    except:
        raised_h2 = True
    assert_true(
        raised_h2,
        "expected take_h2_carrier to raise on UNDETERMINED carrier",
    )
    assert_false(auto.is_h1_path())
    assert_false(auto.is_h2_path())


def main() raises:
    test_wire_choice_codepoints()
    test_config_defaults()
    test_decide_wire_cleartext_ws_skips_h2()
    test_decide_wire_wss_prefer_h2_false_forces_h1()
    test_decide_wire_wss_h2_alpn_with_connect_protocol()
    test_decide_wire_wss_h2_alpn_without_connect_protocol()
    test_decide_wire_wss_http11_alpn()
    test_decide_wire_wss_no_alpn()
    test_decide_wire_unknown_alpn_fails()
    test_decide_wire_invalid_scheme_fails()
    test_url_scheme_parses_wss()
    test_url_scheme_parses_ws()
    test_connect_unreachable_host_surfaces_failure()
    test_take_methods_guard_state()
    print("test_ws_autoclient: 14 passed")
