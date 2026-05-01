"""PROXY protocol v1 + v2 parser (HAProxy spec).

The PROXY protocol is the de-facto wire shape for forwarding the
*original* client TCP endpoint through a load balancer (HAProxy,
AWS NLB, GCP TCP LB, Cloudflare Spectrum, ...) to the origin
server. Without it the origin only sees the LB's IP — every access
log, every per-IP rate limiter, every geo decision is wrong.

The protocol lives in front of the application data: the LB writes
a small header right after the TCP accept on the origin's listener,
then forwards the raw TLS / HTTP bytes unchanged. The origin sniffs
the first few bytes, parses the header, populates ``Request.peer``
with the original client endpoint, and then proceeds with its
normal handshake / parse on the bytes that follow the header.

flare ships strict, fuzz-clean parsers for both wire shapes:

- **v1 (text)** — ``"PROXY TCP4 src dst sport dport\r\n"`` (or
  ``TCP6`` / ``UNKNOWN``). Variable length, terminated by CRLF,
  spec-mandated maximum 107 bytes.
- **v2 (binary)** — 12-byte signature ``\r\n\r\n\x00\r\nQUIT\n``
  followed by 1-byte version+command, 1-byte family+protocol,
  2-byte big-endian payload length, then a fixed-shape address
  block plus optional TLVs. Total length is always
  ``16 + payload_length`` bytes.

Public surface:

- :class:`ProxyHeader` — the parsed header (source ``SocketAddr`` +
  destination ``SocketAddr`` + ``consumed: Int`` byte count to
  skip before reading application data).
- :func:`parse_proxy_v1` / :func:`parse_proxy_v2` — strict parsers
  that fail closed on any spec violation.
- :func:`parse_proxy_protocol` — version-detecting wrapper. Sniffs
  the first 12 bytes (or fewer) and dispatches to the right
  parser. Returns ``None`` on a buffer that's too short to decide
  yet (keep reading).
- :class:`ProxyParseError` — raised on malformed input. Defensive:
  a hostile peer that thinks it's behind a PROXY-protocol-aware
  LB but actually isn't must not be able to inject log entries or
  spoof source IPs, so the parser refuses any non-conforming
  input rather than guessing.

The reactor integration (``ServerConfig.trust_proxy_protocol``)
opt-in lives in a follow-up commit; this module ships the parsers
+ tests + fuzz harness independently so the wire shapes can be
audited and reused (e.g. by the standalone ``HAProxyClient`` in
``flare/http/client.mojo`` for outbound connections).

References:
- HAProxy 2.8 PROXY protocol spec:
  https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt
- Original RFC-shaped writeup:
  https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt
"""

from std.collections import Optional

from flare.net import IpAddr, SocketAddr


# ── Errors ──────────────────────────────────────────────────────────────────


def _err(msg: String) -> Error:
    """Build a uniformly-prefixed parse error. Centralised so callers
    can ``except: pass`` on prefix-matching ``"ProxyParseError"``
    when integrating into a larger pipeline (the reactor wiring in a
    follow-up commit uses this prefix to fail-closed on bad PROXY
    bytes vs panic on a real I/O error)."""
    return Error("ProxyParseError: " + msg)


# ── ProxyHeader ─────────────────────────────────────────────────────────────


@fieldwise_init
struct ProxyHeader(Copyable, Movable):
    """A parsed PROXY protocol header.

    Fields:
        source: The original client endpoint (the IP + port the LB
            saw on its public-facing socket).
        destination: The endpoint the client *thought* it was
            connecting to (the LB's listener address). Useful for
            origin servers that multiplex on the LB's port.
        consumed: Byte count to skip past in the inbound stream
            before resuming application-protocol read. Always > 0
            when this header was successfully parsed.
        is_local: ``True`` for v2 PROXY-LOCAL frames (LB health
            checks); the ``source`` / ``destination`` fields are
            zero-initialised in this case and the application
            should fall back to ``getpeername(2)`` for the peer
            address. Always ``False`` for v1.
    """

    var source: SocketAddr
    var destination: SocketAddr
    var consumed: Int
    var is_local: Bool


# ── Constants ───────────────────────────────────────────────────────────────


comptime _V1_PREFIX: StaticString = "PROXY "
"""HAProxy v1 (text) wire prefix. ASCII; 6 bytes."""

comptime _V1_MAX_LEN: Int = 107
"""HAProxy spec §2.1: v1 header must be <= 107 bytes including CRLF.
Strict cap defends against an attacker streaming an unbounded "PROXY
" prefix to exhaust the parse buffer."""

comptime _V2_SIGNATURE_LEN: Int = 12
"""HAProxy v2 (binary) wire signature length: ``\\r\\n\\r\\n\\x00
\\r\\nQUIT\\n``."""

comptime _V2_HEADER_LEN: Int = 16
"""HAProxy v2 fixed-prefix length: 12-byte signature + 1-byte
version+command + 1-byte family+protocol + 2-byte length."""


# ── v1 (text) parser ────────────────────────────────────────────────────────


def parse_proxy_v1(buf: Span[UInt8, _]) raises -> Optional[ProxyHeader]:
    """Parse a HAProxy PROXY protocol v1 (text) header from ``buf``.

    Returns ``None`` if the buffer doesn't yet contain the
    terminating CRLF (caller should keep reading and retry).

    Returns the parsed :class:`ProxyHeader` on success.

    Raises :class:`ProxyParseError` on:

    - Missing ``"PROXY "`` prefix (wrong wire shape; v2 sniff
      should have caught this earlier).
    - Header > 107 bytes without CRLF (HAProxy §2.1 cap).
    - Unknown protocol token (must be ``TCP4``, ``TCP6``, or
      ``UNKNOWN``).
    - Malformed IP / port tokens for ``TCP4`` / ``TCP6``.
    - IPv4 address in a ``TCP6`` header (or vice versa).
    - Trailing whitespace or a missing CR before the LF (strict
      spec compliance; the spec uses exactly ``\\r\\n``).
    """
    if len(buf) < 6:
        return None  # not enough yet to even check the prefix

    var prefix = _V1_PREFIX
    var pp = prefix.unsafe_ptr()
    for i in range(6):
        if buf[i] != pp[i]:
            raise _err("v1: missing 'PROXY ' prefix")

    # Find the terminating CRLF, capped at the v1 maximum.
    var scan_end = len(buf)
    if scan_end > _V1_MAX_LEN:
        scan_end = _V1_MAX_LEN
    var crlf = -1
    var i = 6
    while i + 1 < scan_end:
        if buf[i] == 0x0D and buf[i + 1] == 0x0A:
            crlf = i
            break
        # The spec mandates printable ASCII inside the v1 header.
        # Reject NUL / LF-only / CR-only / DEL early so a hostile
        # LB-impersonator can't smuggle bytes through the parser.
        var b = Int(buf[i])
        if b == 0 or b == 0x0A or b == 0x7F:
            raise _err("v1: invalid byte in header")
        i += 1
    if crlf == -1:
        if len(buf) >= _V1_MAX_LEN:
            raise _err("v1: header exceeds 107-byte cap")
        return None  # incomplete; need more bytes

    # Parse the body: "PROTO src dst sport dport"
    # Slice [6, crlf) into a String for tokenisation.
    var body = String(capacity=crlf - 6 + 1)
    for j in range(6, crlf):
        body += chr(Int(buf[j]))

    var consumed = crlf + 2  # past the CRLF

    # Tokenise on single ASCII space; the spec is strict about exactly
    # one space between tokens.
    var tokens = body.split(" ")

    if len(tokens) == 1 and tokens[0] == "UNKNOWN":
        # PROXY UNKNOWN — LB-internal traffic; no peer info available.
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=consumed,
            is_local=True,
        )

    if len(tokens) >= 2 and tokens[0] == "UNKNOWN":
        # The spec also allows arbitrary trailing data after UNKNOWN
        # (LB-discretionary fields); we accept and discard.
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=consumed,
            is_local=True,
        )

    if len(tokens) != 5:
        raise _err("v1: expected 5 tokens, got " + String(len(tokens)))

    # ``StringSlice``s into ``body``; convert to owned ``String`` so
    # they can outlive the slice's origin (the helpers take ``String``
    # because they're also called from manual test fixtures).
    var proto = String(tokens[0])
    var src_ip = String(tokens[1])
    var dst_ip = String(tokens[2])
    var src_port = String(tokens[3])
    var dst_port = String(tokens[4])

    var want_v6: Bool
    if proto == "TCP4":
        want_v6 = False
    elif proto == "TCP6":
        want_v6 = True
    else:
        raise _err("v1: unknown protocol '" + proto + "'")

    var src = _parse_addr_port(src_ip, src_port, want_v6)
    var dst = _parse_addr_port(dst_ip, dst_port, want_v6)

    return ProxyHeader(
        source=src,
        destination=dst,
        consumed=consumed,
        is_local=False,
    )


def _parse_addr_port(
    ip: String, port: String, want_v6: Bool
) raises -> SocketAddr:
    var addr: IpAddr
    try:
        addr = IpAddr.parse(ip)
    except:
        raise _err("v1: invalid IP '" + ip + "'")
    if addr.is_v6() != want_v6:
        raise _err("v1: IP family does not match protocol")
    if port.byte_length() == 0:
        raise _err("v1: empty port")
    var pn: Int = 0
    var pp = port.unsafe_ptr()
    for i in range(port.byte_length()):
        var c = Int(pp[i])
        if c < ord("0") or c > ord("9"):
            raise _err("v1: non-digit byte in port '" + port + "'")
        pn = pn * 10 + (c - ord("0"))
        if pn > 65535:
            raise _err("v1: port > 65535")
    # Reject a leading zero on a multi-digit port (defensive: prevents
    # log-line ambiguity where "08080" could be misread as octal).
    if port.byte_length() > 1 and Int(pp[0]) == ord("0"):
        raise _err("v1: leading zero in port '" + port + "'")
    return SocketAddr(addr, UInt16(pn))


# ── v2 (binary) parser ──────────────────────────────────────────────────────


@always_inline
def _v2_sig_byte(i: Int) -> UInt8:
    """The fixed 12-byte HAProxy v2 signature, accessed by index.

    Literal bytes (verbatim from §2.2): ``0x0D 0x0A 0x0D 0x0A 0x00
    0x0D 0x0A 0x51 0x55 0x49 0x54 0x0A`` — i.e. ``\\r\\n\\r\\n\\x00
    \\r\\nQUIT\\n``. Returned per-index instead of materialising a
    ``List[UInt8]`` because Mojo ``1.0.0b1.dev2026042717`` rejects
    ``comptime`` lists at runtime (the ``List[UInt8]`` is not
    ``ImplicitlyCopyable``); a 12-iteration index loop is the
    cheapest correct shape on this nightly.
    """
    if i == 0:
        return UInt8(0x0D)
    if i == 1:
        return UInt8(0x0A)
    if i == 2:
        return UInt8(0x0D)
    if i == 3:
        return UInt8(0x0A)
    if i == 4:
        return UInt8(0x00)
    if i == 5:
        return UInt8(0x0D)
    if i == 6:
        return UInt8(0x0A)
    if i == 7:
        return UInt8(0x51)  # 'Q'
    if i == 8:
        return UInt8(0x55)  # 'U'
    if i == 9:
        return UInt8(0x49)  # 'I'
    if i == 10:
        return UInt8(0x54)  # 'T'
    return UInt8(0x0A)


def parse_proxy_v2(buf: Span[UInt8, _]) raises -> Optional[ProxyHeader]:
    """Parse a HAProxy PROXY protocol v2 (binary) header from ``buf``.

    Returns ``None`` if the buffer is shorter than ``16 +
    payload_length`` (caller should keep reading). The 16-byte fixed
    prefix is enough to compute the full header length.

    Raises :class:`ProxyParseError` on:

    - Missing 12-byte signature.
    - Version field ``!= 2`` (HAProxy §2.2).
    - Command not in ``{LOCAL=0, PROXY=1}``.
    - Unsupported family (we accept ``UNSPEC=0``, ``INET=1``,
      ``INET6=2``; ``UNIX=3`` is parsed-and-skipped — the LB has
      no client-IP to forward over a UDS).
    - Family + payload-length mismatch
      (``INET`` requires >= 12, ``INET6`` requires >= 36).
    """
    if len(buf) < _V2_HEADER_LEN:
        return None  # not enough yet to compute total length

    for i in range(_V2_SIGNATURE_LEN):
        if buf[i] != _v2_sig_byte(i):
            raise _err("v2: bad 12-byte signature")

    var ver_cmd = Int(buf[12])
    var version = (ver_cmd >> 4) & 0x0F
    var command = ver_cmd & 0x0F
    if version != 2:
        raise _err("v2: version != 2 (got " + String(version) + ")")
    if command != 0 and command != 1:
        raise _err("v2: unknown command " + String(command))

    var fam_proto = Int(buf[13])
    var family = (fam_proto >> 4) & 0x0F
    # Lower nibble is the transport (STREAM=1 / DGRAM=2 / UNSPEC=0);
    # we accept all three for forward-compatibility.

    var length = (Int(buf[14]) << 8) | Int(buf[15])

    var total = _V2_HEADER_LEN + length
    if len(buf) < total:
        return None  # incomplete

    if command == 0:
        # LOCAL — health-check; the address block is meaningless.
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=total,
            is_local=True,
        )

    # command == 1 (PROXY) — parse the address block per family.
    if family == 0:
        # AF_UNSPEC — no usable peer info; the spec says ignore the
        # address block.
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=total,
            is_local=True,
        )

    if family == 1:
        # AF_INET: 4-byte src + 4-byte dst + 2-byte sport + 2-byte dport
        if length < 12:
            raise _err("v2: INET payload < 12 bytes")
        var src_ip = _v4_to_ipaddr(buf, _V2_HEADER_LEN)
        var dst_ip = _v4_to_ipaddr(buf, _V2_HEADER_LEN + 4)
        var sport = (Int(buf[_V2_HEADER_LEN + 8]) << 8) | Int(
            buf[_V2_HEADER_LEN + 9]
        )
        var dport = (Int(buf[_V2_HEADER_LEN + 10]) << 8) | Int(
            buf[_V2_HEADER_LEN + 11]
        )
        return ProxyHeader(
            source=SocketAddr(src_ip, UInt16(sport)),
            destination=SocketAddr(dst_ip, UInt16(dport)),
            consumed=total,
            is_local=False,
        )

    if family == 2:
        # AF_INET6: 16-byte src + 16-byte dst + 2-byte sport + 2-byte dport
        if length < 36:
            raise _err("v2: INET6 payload < 36 bytes")
        var src_ip = _v6_to_ipaddr(buf, _V2_HEADER_LEN)
        var dst_ip = _v6_to_ipaddr(buf, _V2_HEADER_LEN + 16)
        var sport = (Int(buf[_V2_HEADER_LEN + 32]) << 8) | Int(
            buf[_V2_HEADER_LEN + 33]
        )
        var dport = (Int(buf[_V2_HEADER_LEN + 34]) << 8) | Int(
            buf[_V2_HEADER_LEN + 35]
        )
        return ProxyHeader(
            source=SocketAddr(src_ip, UInt16(sport)),
            destination=SocketAddr(dst_ip, UInt16(dport)),
            consumed=total,
            is_local=False,
        )

    if family == 3:
        # AF_UNIX — no useful client-IP. Treat as LOCAL for the
        # caller's purposes so they fall back to getpeername(2).
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=total,
            is_local=True,
        )

    raise _err("v2: unsupported family " + String(family))


def _v4_to_ipaddr(buf: Span[UInt8, _], offset: Int) raises -> IpAddr:
    """Render 4 bytes at ``buf[offset:offset+4]`` as an IPv4
    ``IpAddr`` via dotted-decimal."""
    var s = String(capacity=16)
    s += String(Int(buf[offset]))
    s += "."
    s += String(Int(buf[offset + 1]))
    s += "."
    s += String(Int(buf[offset + 2]))
    s += "."
    s += String(Int(buf[offset + 3]))
    return IpAddr.parse(s)


def _v6_to_ipaddr(buf: Span[UInt8, _], offset: Int) raises -> IpAddr:
    """Render 16 bytes at ``buf[offset:offset+16]`` as an IPv6
    ``IpAddr`` via colon-separated hextets. ``IpAddr.parse``
    canonicalises (collapses zero runs into ``::``) on the way out."""
    var s = String(capacity=40)
    var hex_chars = String("0123456789abcdef")
    var hp = hex_chars.unsafe_ptr()
    for i in range(8):
        if i > 0:
            s += ":"
        var hi = Int(buf[offset + i * 2])
        var lo = Int(buf[offset + i * 2 + 1])
        # Suppress leading zeros within each hextet to make
        # IpAddr.parse's job easier and the canonical form match
        # what inet_ntop emits.
        var word = (hi << 8) | lo
        if word == 0:
            s += "0"
        else:
            var nibble3 = (word >> 12) & 0xF
            var nibble2 = (word >> 8) & 0xF
            var nibble1 = (word >> 4) & 0xF
            var nibble0 = word & 0xF
            var started = False
            if nibble3 != 0:
                s += chr(Int(hp[nibble3]))
                started = True
            if started or nibble2 != 0:
                s += chr(Int(hp[nibble2]))
                started = True
            if started or nibble1 != 0:
                s += chr(Int(hp[nibble1]))
            s += chr(Int(hp[nibble0]))
    return IpAddr.parse(s)


# ── Version-detecting wrapper ───────────────────────────────────────────────


def parse_proxy_protocol(buf: Span[UInt8, _]) raises -> Optional[ProxyHeader]:
    """Sniff the wire shape and dispatch to v1 or v2.

    Returns ``None`` when the buffer is too short to decide — the
    caller should keep reading and retry. Returns the parsed
    :class:`ProxyHeader` on success. Raises :class:`ProxyParseError`
    on a buffer that is long enough to commit to a wire shape but
    fails strict parsing of that shape.

    The dispatch rule (HAProxy §2): if the first 12 bytes match the
    v2 signature, parse as v2; otherwise if the first 6 bytes are
    ``"PROXY "``, parse as v1; otherwise raise.
    """
    if len(buf) < 6:
        return None  # need at least the v1 prefix

    # Try v2 signature first if we have enough bytes.
    if len(buf) >= _V2_SIGNATURE_LEN:
        var matches_v2 = True
        for i in range(_V2_SIGNATURE_LEN):
            if buf[i] != _v2_sig_byte(i):
                matches_v2 = False
                break
        if matches_v2:
            return parse_proxy_v2(buf)

    # Else try v1.
    var prefix = _V1_PREFIX
    var pp = prefix.unsafe_ptr()
    var matches_v1 = True
    for i in range(6):
        if buf[i] != pp[i]:
            matches_v1 = False
            break
    if matches_v1:
        return parse_proxy_v1(buf)

    raise _err(
        "no PROXY protocol signature (neither v1 'PROXY ' nor v2 binary"
        " signature)"
    )
