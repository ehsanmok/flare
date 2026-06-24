"""``Alt-Svc`` discovery + the HTTP/3 wire-selection policy (RFC 7838).

When an origin serves over HTTP/1.1 or HTTP/2 it can advertise an
HTTP/3 endpoint via the ``Alt-Svc`` response header (RFC 7838):

```
Alt-Svc: h3=":443"; ma=86400, h2=":443"; ma=3600
```

This module is the client-side discovery + policy layer that lets
:class:`flare.http.HttpClient` upgrade to h3 transparently:

* :func:`parse_alt_svc` -- a lenient RFC 7838 §3 parser: splits the
  header into ``protocol-id="alt-authority"`` advertisements with
  their ``ma`` (max-age) + ``persist`` params, tolerating malformed
  alt-values by skipping them (the header comes from an untrusted
  peer, so a single bad entry must not poison the rest).
* :class:`AltSvcCache` -- a per-origin cache keyed by ``host:port``
  that remembers the freshest advertised h3 endpoint with an
  absolute expiry, so a later request to the same origin can dial
  h3 without re-probing.
* :class:`H3WireChoice` + :func:`decide_h3_wire` -- the pure
  wire-selection decision (mirror of the WS ``decide_wire``): given
  the URL scheme, the ``prefer_h3`` knob, whether a fresh h3 advert
  is cached, and whether the QUIC stack is available, returns the
  carrier the client should attempt. The runtime
  :class:`HttpClient` plumbs the real values in and falls back to
  the existing h2 / h1 path on ``HTTP_2_OR_LOWER`` or on any QUIC
  dial failure.

References:
- RFC 7838 (HTTP Alternative Services).
- RFC 9114 §3.1.1 (Discovering an HTTP/3 endpoint via ``Alt-Svc``).
"""

from std.collections import Dict, List, Optional

from flare.http.proto.ascii import ascii_lower


@fieldwise_init
struct AltSvcEntry(Copyable, Movable):
    """A single parsed ``Alt-Svc`` advertisement.

    ``protocol`` is the ALPN id (``"h3"``, ``"h2"``, ``"h3-29"``,
    ...); ``host`` is the alt-authority host (empty means "same host
    as the origin", RFC 7838 §3); ``port`` is the alt-authority
    port; ``max_age`` is the advertised freshness lifetime in
    seconds (RFC 7838 §3.1, default 86400); ``persist`` is the
    RFC 7838 §3.1 ``persist=1`` hint.
    """

    var protocol: String
    var host: String
    var port: UInt16
    var max_age: UInt64
    var persist: Bool


@fieldwise_init
struct AltSvcParse(Copyable, Movable):
    """The result of parsing one ``Alt-Svc`` header value.

    ``cleared`` is True when the header was the literal ``clear``
    (RFC 7838 §3.1), which invalidates every cached advert for the
    origin; in that case ``entries`` is empty.
    """

    var cleared: Bool
    var entries: List[AltSvcEntry]


def parse_alt_svc(value: String) raises -> AltSvcParse:
    """Parse one ``Alt-Svc`` header value into its advertisements.

    Lenient by design (the input is an untrusted response header):
    a malformed alt-value is skipped rather than failing the whole
    header. The literal token ``clear`` yields ``cleared=True``.
    """
    var trimmed = String(value.strip())
    if ascii_lower(trimmed) == "clear":
        return AltSvcParse(cleared=True, entries=List[AltSvcEntry]())
    var entries = List[AltSvcEntry]()
    var raw_values = trimmed.split(",")
    for i in range(len(raw_values)):
        var alt = String(raw_values[i].strip())
        if len(alt.as_bytes()) == 0:
            continue
        try:
            entries.append(_parse_alt_value(alt))
        except:
            continue  # skip a single malformed alt-value
    return AltSvcParse(cleared=False, entries=entries^)


def _parse_alt_value(alt: String) raises -> AltSvcEntry:
    """Parse one ``protocol-id="authority"; params`` advertisement.
    Raises on a structurally invalid value so the caller skips it.
    """
    var parts = alt.split(";")
    var head = String(parts[0].strip())
    var eq = head.find("=")
    if eq < 0:
        raise Error("alt-svc: missing '=' in alt-value")
    var protocol = String(String(head[byte=:eq]).strip())
    var authority = _unquote(String(String(head[byte = eq + 1 :]).strip()))
    if len(protocol.as_bytes()) == 0:
        raise Error("alt-svc: empty protocol-id")
    # alt-authority is ``[host]:port``; the host half may be empty
    # (same host as the origin). Split on the final colon.
    var colon = authority.rfind(":")
    if colon < 0:
        raise Error("alt-svc: alt-authority without ':'")
    var host = String(String(authority[byte=:colon]).strip())
    var port_s = String(String(authority[byte = colon + 1 :]).strip())
    var port = atol(port_s)
    if port <= 0 or port > 65535:
        raise Error("alt-svc: port out of range")
    var max_age = UInt64(86400)
    var persist = False
    for j in range(1, len(parts)):
        var param = String(parts[j].strip())
        var peq = param.find("=")
        if peq < 0:
            continue
        var name = ascii_lower(String(String(param[byte=:peq]).strip()))
        var pval = String(String(param[byte = peq + 1 :]).strip())
        if name == "ma":
            var ma = atol(pval)
            if ma >= 0:
                max_age = UInt64(ma)
        elif name == "persist":
            persist = pval == "1"
    return AltSvcEntry(
        protocol=protocol,
        host=host,
        port=UInt16(port),
        max_age=max_age,
        persist=persist,
    )


def _unquote(s: String) -> String:
    """Strip one layer of surrounding double quotes if present."""
    var b = s.as_bytes()
    if (
        len(b) >= 2
        and b[0] == UInt8(ord('"'))
        and b[len(b) - 1] == UInt8(ord('"'))
    ):
        return String(s[byte = 1 : len(b) - 1])
    return s


# ── Per-origin cache ────────────────────────────────────────────────────────


@fieldwise_init
struct _CachedH3(Copyable, Movable):
    """A cached h3 endpoint with an absolute expiry timestamp."""

    var host: String
    var port: UInt16
    var expires_at: UInt64


struct AltSvcCache(Copyable, Movable):
    """Per-origin cache of advertised h3 endpoints.

    Keyed by the origin ``host:port`` (the authority the response
    came from). Only h3 adverts are retained -- the client only
    needs to know whether to attempt QUIC. Entries carry an
    absolute expiry derived from ``ma``; :meth:`h3_endpoint` treats
    an expired entry as absent (RFC 7838 §3.1).
    """

    var _by_origin: Dict[String, _CachedH3]

    def __init__(out self):
        self._by_origin = Dict[String, _CachedH3]()

    @staticmethod
    def new() -> Self:
        return Self()

    def record(
        mut self, origin: String, header_value: String, now_s: UInt64
    ) raises:
        """Record the ``Alt-Svc`` header for ``origin`` (the
        ``host:port`` the response arrived from). A ``clear`` token
        evicts any cached entry; otherwise the freshest h3 advert
        wins. Non-h3 adverts are ignored."""
        var parsed = parse_alt_svc(header_value)
        if parsed.cleared:
            _ = self._by_origin.pop(origin, _CachedH3("", UInt16(0), UInt64(0)))
            return
        for i in range(len(parsed.entries)):
            var e = parsed.entries[i].copy()
            if e.protocol != "h3":
                continue
            var host = e.host if len(e.host.as_bytes()) > 0 else _origin_host(
                origin
            )
            self._by_origin[origin] = _CachedH3(
                host=host,
                port=e.port,
                expires_at=now_s + e.max_age,
            )
            return  # first (freshest, leftmost) h3 advert wins

    def h3_endpoint(
        self, origin: String, now_s: UInt64
    ) -> Optional[Tuple[String, UInt16]]:
        """Return the cached ``(host, port)`` h3 endpoint for
        ``origin`` if one is cached and unexpired, else ``None``."""
        try:
            var hit = self._by_origin[origin].copy()
            if hit.expires_at <= now_s:
                return None
            return Optional(Tuple[String, UInt16](hit.host, hit.port))
        except:
            return None

    def has_fresh_h3(self, origin: String, now_s: UInt64) -> Bool:
        """Whether ``origin`` has a cached, unexpired h3 advert."""
        return Bool(self.h3_endpoint(origin, now_s))


def _origin_host(origin: String) -> String:
    """The host half of an ``host:port`` origin key."""
    var colon = origin.rfind(":")
    if colon < 0:
        return origin
    return String(origin[byte=:colon])


# ── Wire-selection policy (mirror of WS decide_wire) ─────────────────────────


struct H3WireChoice:
    """Stable codepoints for the carrier the client attempts after
    consulting the ``Alt-Svc`` cache + ``prefer_h3`` knob."""

    comptime UNDETERMINED: Int = 0
    """The policy has not run yet."""

    comptime HTTP_3: Int = 1
    """Attempt HTTP/3 over QUIC. Chosen when the scheme is
    ``https``, the QUIC stack is available, and either ``prefer_h3``
    is set or the origin has a fresh cached h3 advert."""

    comptime HTTP_2_OR_LOWER: Int = 2
    """Use the existing ALPN ``["h2", "http/1.1"]`` path. Chosen for
    cleartext, when QUIC is unavailable, or when no h3 preference /
    advert applies. The transparent default."""

    comptime FAILED: Int = 3
    """Reserved for an attempted-but-unusable decision (kept for
    symmetry with the WS ``decide_wire`` codepoints)."""


def decide_h3_wire(
    url_scheme: String,
    prefer_h3: Bool,
    h3_cached_available: Bool,
    quic_supported: Bool,
) -> Int:
    """The pure h3-vs-h2 wire decision the client executes before
    dialing.

    Inputs:

    - ``url_scheme`` -- ``"https"`` enables h3; anything else
      (``"http"``) forces the lower path (h3 requires TLS).
    - ``prefer_h3`` -- the explicit opt-in knob.
    - ``h3_cached_available`` -- a fresh ``Alt-Svc`` h3 advert is
      cached for this origin.
    - ``quic_supported`` -- the QUIC/rustls stack is built in.

    Returns an :class:`H3WireChoice` codepoint. The decision is
    pure + testable; the runtime client falls back to
    ``HTTP_2_OR_LOWER`` on any QUIC dial failure regardless of this
    result.
    """
    if not quic_supported:
        return H3WireChoice.HTTP_2_OR_LOWER
    if url_scheme != "https":
        return H3WireChoice.HTTP_2_OR_LOWER
    if prefer_h3 or h3_cached_available:
        return H3WireChoice.HTTP_3
    return H3WireChoice.HTTP_2_OR_LOWER
