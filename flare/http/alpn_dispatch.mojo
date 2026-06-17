"""``flare.http.alpn_dispatch`` -- ALPN-driven wire dispatcher.

When a TLS-terminated TCP listener completes a handshake with
ALPN negotiation, the server has to pick which protocol driver
handles the resulting stream. flare today supports four wire
shapes:

* **HTTP/1.1** -- the existing h1 parser + reactor.
* **h2c** -- HTTP/2 cleartext, detected via the
  ``Upgrade: h2c`` header on an h1 request (RFC 7540 §3.2).
* **HTTP/2** -- TLS-negotiated h2 via ALPN ``"h2"`` (RFC 9113
  §3.3).
* **HTTP/3** -- TLS-negotiated h3 via ALPN ``"h3"`` (RFC 9114
  §3.1) over QUIC.

The dispatcher in this module is a pure decision function: it
takes the negotiated ALPN string + an optional h2c-upgrade
header hint and returns a :data:`WireProtocol` codepoint. The
reactor uses this codepoint to switch into the matching driver.

The full ``HttpServer.bind`` integration -- mounting one
:trait:`Handler` instance across an h1 + h2c + h2 reactor and an
h3 listener simultaneously, sharing state between TCP and UDP
acceptors -- ships as a focused follow-up. This
module is the small, pure piece that makes the decision: the
expensive wiring (UDP listener allocation, separate epoll
registration, ALPN list assembly per-listener) sits on top of
this dispatcher.

The intent is that test corpora can pin every ALPN -> wire
mapping at the byte level without spinning up a real listener.
The :func:`negotiate_alpn` helper picks the highest-priority
mutually-supported protocol; the :func:`dispatch_alpn` helper
maps the *outcome* string to a wire codepoint.

References:
- RFC 7301 "Transport Layer Security (TLS) Application-Layer
  Protocol Negotiation Extension".
- RFC 9113 §3.3 "Protocol Identification for HTTP/2".
- RFC 9114 §3.1 "HTTP Alternative Services / ALPN for HTTP/3".
"""

from std.collections import List


# ── Wire protocol codepoints ───────────────────────────────────────────


struct WireProtocol:
    """Stable integer codepoints for the wires :class:`HttpServer`
    dispatches between. The reactor switches on these so the
    dispatch table is one indirection per accepted connection.
    """

    comptime UNKNOWN: Int = 0
    """ALPN negotiation produced no match or the input is empty.
    The reactor closes the connection with a TLS no_application_protocol
    alert (RFC 7301 §3.2)."""

    comptime HTTP_1_1: Int = 1
    """HTTP/1.1 -- ALPN ``"http/1.1"`` or no ALPN advertised."""

    comptime H2C: Int = 2
    """HTTP/2 cleartext upgrade via h1's ``Upgrade: h2c`` header.
    Not negotiated through ALPN; the reactor lands here when the
    h1 parser detects the upgrade hint."""

    comptime HTTP_2: Int = 3
    """HTTP/2 over TLS -- ALPN ``"h2"`` (RFC 9113 §3.3)."""

    comptime HTTP_3: Int = 4
    """HTTP/3 over QUIC -- ALPN ``"h3"`` (RFC 9114 §3.1).
    Routed to the :class:`flare.h3.H3Connection` driver on
    the UDP listener side."""


# ── ALPN identifiers ───────────────────────────────────────────────────


comptime ALPN_HTTP_1_1: String = "http/1.1"
"""RFC 7301-registered identifier for HTTP/1.1."""

comptime ALPN_HTTP_2: String = "h2"
"""RFC 7540 §3.3 identifier for HTTP/2 over TLS."""

comptime ALPN_HTTP_3: String = "h3"
"""RFC 9114 §3.1 identifier for HTTP/3 over QUIC."""


# ── Decision functions ─────────────────────────────────────────────────


def dispatch_alpn(alpn: String) -> Int:
    """Map a negotiated ALPN identifier to a :data:`WireProtocol`
    codepoint. Empty string maps to HTTP/1.1 (the assumed-default
    when ALPN was not advertised); unknown identifiers map to
    UNKNOWN.
    """
    if alpn == "":
        return WireProtocol.HTTP_1_1
    if alpn == ALPN_HTTP_1_1:
        return WireProtocol.HTTP_1_1
    if alpn == ALPN_HTTP_2:
        return WireProtocol.HTTP_2
    if alpn == ALPN_HTTP_3:
        return WireProtocol.HTTP_3
    return WireProtocol.UNKNOWN


def dispatch_h2c_upgrade(detected: Bool) -> Int:
    """Map the h1-parser's ``Upgrade: h2c`` detection to a wire
    codepoint. Used by the cleartext path (no TLS, no ALPN).
    """
    if detected:
        return WireProtocol.H2C
    return WireProtocol.HTTP_1_1


def negotiate_alpn(
    client_advertised: List[String], server_supports: List[String]
) -> String:
    """RFC 7301 §3.2 -- pick the highest-priority protocol that
    both sides support.

    The server's preference order wins: walk
    ``server_supports`` in order and pick the first entry that
    appears anywhere in ``client_advertised``. Returns the empty
    string when there's no overlap; the caller MUST then close
    the connection with the ``no_application_protocol`` alert.
    """
    for i in range(len(server_supports)):
        var s = server_supports[i]
        for j in range(len(client_advertised)):
            if client_advertised[j] == s:
                return s
    return String("")


# ── Reverse mapping (for diagnostics) ──────────────────────────────────


def wire_protocol_name(protocol: Int) -> String:
    """Return a human-readable label for a :class:`WireProtocol`
    codepoint. Used for logging + structured metrics.
    """
    if protocol == WireProtocol.HTTP_1_1:
        return String("HTTP/1.1")
    if protocol == WireProtocol.H2C:
        return String("h2c")
    if protocol == WireProtocol.HTTP_2:
        return String("HTTP/2")
    if protocol == WireProtocol.HTTP_3:
        return String("HTTP/3")
    return String("unknown")
