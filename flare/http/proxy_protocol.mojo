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
- :class:`ProxyParseError` — typed error raised on malformed input.
  Carries ``version`` (1, 2, or 0 for the version-detecting
  wrapper), ``position`` (byte offset where the error was
  detected; -1 if not applicable), and ``what`` (a stable
  human-readable phrase for greppable logs). Defensive: a hostile
  peer that thinks it's behind a PROXY-protocol-aware LB but
  actually isn't must not be able to inject log entries or spoof
  source IPs, so the parser refuses any non-conforming input
  rather than guessing.
- :func:`parse_proxy_v1` / :func:`parse_proxy_v2` — strict parsers
  that fail closed on any spec violation.
- :func:`parse_proxy_protocol` — version-detecting wrapper. Sniffs
  the first 12 bytes (or fewer) and dispatches to the right
  parser. Returns ``None`` on a buffer that's too short to decide
  yet (keep reading).

The reactor integration (``ServerConfig.trust_proxy_protocol``)
opt-in lives in a follow-up commit; this module ships the parsers
+ tests + fuzz harness independently so the wire shapes can be
audited and reused.

References:
- HAProxy 2.8 PROXY protocol spec:
  https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt
"""

from std.collections import Optional
from std.format import Writable, Writer

from flare.net import IpAddr, SocketAddr


# ── ProxyParseError ─────────────────────────────────────────────────────────


@fieldwise_init
struct ProxyParseError(Copyable, Movable, Writable):
    """Typed parse error raised by :func:`parse_proxy_v1` /
    :func:`parse_proxy_v2` / :func:`parse_proxy_protocol`.

    Fields:

    - ``version`` — wire-shape version this error applies to:
      ``1`` (v1 text), ``2`` (v2 binary), or ``0`` (version-
      detecting wrapper rejected the buffer before committing
      to either shape).
    - ``position`` — byte offset in the input buffer where the
      violation was detected, or ``-1`` if not byte-positional
      (e.g. token-level v1 errors).
    - ``what`` — a stable human-readable phrase that callers
      can grep on. Stable across patch versions so log
      regressions are obvious.
    """

    var version: Int
    var position: Int
    var what: String

    def write_to[W: Writer](self, mut writer: W):
        writer.write("ProxyParseError(v", self.version)
        if self.position >= 0:
            writer.write(", pos=", self.position)
        writer.write("): ", self.what)


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


def parse_proxy_v1(
    buf: Span[UInt8, _]
) raises ProxyParseError -> Optional[ProxyHeader]:
    """Parse a HAProxy PROXY protocol v1 (text) header from ``buf``.

    Returns ``None`` if the buffer doesn't yet contain the
    terminating CRLF (caller should keep reading and retry).

    Returns the parsed :class:`ProxyHeader` on success.

    Raises :class:`ProxyParseError` (``version=1``) on:

    - Missing ``"PROXY "`` prefix (wrong wire shape; v2 sniff
      should have caught this earlier).
    - Header > 107 bytes without CRLF (HAProxy §2.1 cap).
    - Unknown protocol token (must be ``TCP4``, ``TCP6``, or
      ``UNKNOWN``).
    - Malformed IP / port tokens for ``TCP4`` / ``TCP6``.
    - IPv4 address in a ``TCP6`` header (or vice versa).
    - Trailing whitespace or a missing CR before the LF.
    """
    if len(buf) < 6:
        return None

    var prefix = _V1_PREFIX
    var pp = prefix.unsafe_ptr()
    for i in range(6):
        if buf[i] != pp[i]:
            raise ProxyParseError(
                version=1, position=i, what=String("missing 'PROXY ' prefix")
            )

    var scan_end = len(buf)
    if scan_end > _V1_MAX_LEN:
        scan_end = _V1_MAX_LEN
    var crlf = -1
    var i = 6
    while i + 1 < scan_end:
        if buf[i] == 0x0D and buf[i + 1] == 0x0A:
            crlf = i
            break
        var b = Int(buf[i])
        if b == 0 or b == 0x0A or b == 0x7F:
            raise ProxyParseError(
                version=1, position=i, what=String("invalid byte in header")
            )
        i += 1
    if crlf == -1:
        if len(buf) >= _V1_MAX_LEN:
            raise ProxyParseError(
                version=1,
                position=_V1_MAX_LEN,
                what=String("header exceeds 107-byte cap"),
            )
        return None

    var body = String(capacity=crlf - 6 + 1)
    for j in range(6, crlf):
        body += chr(Int(buf[j]))

    var consumed = crlf + 2

    var tokens = body.split(" ")

    if len(tokens) == 1 and tokens[0] == "UNKNOWN":
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=consumed,
            is_local=True,
        )

    if len(tokens) >= 2 and tokens[0] == "UNKNOWN":
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=consumed,
            is_local=True,
        )

    if len(tokens) != 5:
        raise ProxyParseError(
            version=1,
            position=-1,
            what=String("expected 5 tokens, got ") + String(len(tokens)),
        )

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
        raise ProxyParseError(
            version=1,
            position=-1,
            what=String("unknown protocol '") + proto + String("'"),
        )

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
) raises ProxyParseError -> SocketAddr:
    """Parse a (ip, port) pair into a :class:`SocketAddr`.

    Wraps :func:`flare.net.IpAddr.parse` (which raises a generic
    ``Error``) and converts the failure into a
    :class:`ProxyParseError` so the caller's typed-raises
    signature stays monomorphic per the Mojo doc § "Don't mix
    error types in a single try block"."""
    var addr: IpAddr
    try:
        addr = IpAddr.parse(ip)
    except _e:
        raise ProxyParseError(
            version=1,
            position=-1,
            what=String("invalid IP '") + ip + String("'"),
        )
    if addr.is_v6() != want_v6:
        raise ProxyParseError(
            version=1,
            position=-1,
            what=String("IP family does not match protocol"),
        )
    if port.byte_length() == 0:
        raise ProxyParseError(version=1, position=-1, what=String("empty port"))
    var pn: Int = 0
    var pp = port.unsafe_ptr()
    for i in range(port.byte_length()):
        var c = Int(pp[i])
        if c < ord("0") or c > ord("9"):
            raise ProxyParseError(
                version=1,
                position=-1,
                what=String("non-digit byte in port '") + port + String("'"),
            )
        pn = pn * 10 + (c - ord("0"))
        if pn > 65535:
            raise ProxyParseError(
                version=1, position=-1, what=String("port > 65535")
            )
    if port.byte_length() > 1 and Int(pp[0]) == ord("0"):
        raise ProxyParseError(
            version=1,
            position=-1,
            what=String("leading zero in port '") + port + String("'"),
        )
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
        return UInt8(0x51)
    if i == 8:
        return UInt8(0x55)
    if i == 9:
        return UInt8(0x49)
    if i == 10:
        return UInt8(0x54)
    return UInt8(0x0A)


def parse_proxy_v2(
    buf: Span[UInt8, _]
) raises ProxyParseError -> Optional[ProxyHeader]:
    """Parse a HAProxy PROXY protocol v2 (binary) header from ``buf``.

    Returns ``None`` if the buffer is shorter than ``16 +
    payload_length`` (caller should keep reading).

    Raises :class:`ProxyParseError` (``version=2``) on:

    - Missing 12-byte signature.
    - Version field ``!= 2`` (HAProxy §2.2).
    - Command not in ``{LOCAL=0, PROXY=1}``.
    - Unsupported family.
    - Family + payload-length mismatch
      (``INET`` requires >= 12, ``INET6`` requires >= 36).
    """
    if len(buf) < _V2_HEADER_LEN:
        return None

    for i in range(_V2_SIGNATURE_LEN):
        if buf[i] != _v2_sig_byte(i):
            raise ProxyParseError(
                version=2,
                position=i,
                what=String("bad 12-byte signature"),
            )

    var ver_cmd = Int(buf[12])
    var version = (ver_cmd >> 4) & 0x0F
    var command = ver_cmd & 0x0F
    if version != 2:
        raise ProxyParseError(
            version=2,
            position=12,
            what=String("version != 2 (got ") + String(version) + String(")"),
        )
    if command != 0 and command != 1:
        raise ProxyParseError(
            version=2,
            position=12,
            what=String("unknown command ") + String(command),
        )

    var fam_proto = Int(buf[13])
    var family = (fam_proto >> 4) & 0x0F

    var length = (Int(buf[14]) << 8) | Int(buf[15])

    var total = _V2_HEADER_LEN + length
    if len(buf) < total:
        return None

    if command == 0:
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=total,
            is_local=True,
        )

    if family == 0:
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=total,
            is_local=True,
        )

    if family == 1:
        if length < 12:
            raise ProxyParseError(
                version=2,
                position=14,
                what=String("INET payload < 12 bytes"),
            )
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
        if length < 36:
            raise ProxyParseError(
                version=2,
                position=14,
                what=String("INET6 payload < 36 bytes"),
            )
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
        return ProxyHeader(
            source=SocketAddr(IpAddr.unspecified(), 0),
            destination=SocketAddr(IpAddr.unspecified(), 0),
            consumed=total,
            is_local=True,
        )

    raise ProxyParseError(
        version=2,
        position=13,
        what=String("unsupported family ") + String(family),
    )


def _v4_to_ipaddr(
    buf: Span[UInt8, _], offset: Int
) raises ProxyParseError -> IpAddr:
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
    try:
        return IpAddr.parse(s)
    except _e:
        raise ProxyParseError(
            version=2,
            position=offset,
            what=String("invalid v4 address bytes"),
        )


def _v6_to_ipaddr(
    buf: Span[UInt8, _], offset: Int
) raises ProxyParseError -> IpAddr:
    """Render 16 bytes at ``buf[offset:offset+16]`` as an IPv6
    ``IpAddr`` via colon-separated hextets."""
    var s = String(capacity=40)
    var hex_chars = String("0123456789abcdef")
    var hp = hex_chars.unsafe_ptr()
    for i in range(8):
        if i > 0:
            s += ":"
        var hi = Int(buf[offset + i * 2])
        var lo = Int(buf[offset + i * 2 + 1])
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
    try:
        return IpAddr.parse(s)
    except _e:
        raise ProxyParseError(
            version=2,
            position=offset,
            what=String("invalid v6 address bytes"),
        )


# ── Version-detecting wrapper ───────────────────────────────────────────────


def parse_proxy_protocol(
    buf: Span[UInt8, _]
) raises ProxyParseError -> Optional[ProxyHeader]:
    """Sniff the wire shape and dispatch to v1 or v2.

    Returns ``None`` when the buffer is too short to decide.
    Raises :class:`ProxyParseError` (``version=0`` for the
    "no signature found" case; otherwise ``version=1`` or
    ``version=2`` from the underlying parser) on a buffer that
    is long enough to commit to a wire shape but fails strict
    parsing of that shape.
    """
    if len(buf) < 6:
        return None

    if len(buf) >= _V2_SIGNATURE_LEN:
        var matches_v2 = True
        for i in range(_V2_SIGNATURE_LEN):
            if buf[i] != _v2_sig_byte(i):
                matches_v2 = False
                break
        if matches_v2:
            return parse_proxy_v2(buf)

    var prefix = _V1_PREFIX
    var pp = prefix.unsafe_ptr()
    var matches_v1 = True
    for i in range(6):
        if buf[i] != pp[i]:
            matches_v1 = False
            break
    if matches_v1:
        return parse_proxy_v1(buf)

    raise ProxyParseError(
        version=0,
        position=0,
        what=String(
            "no PROXY protocol signature (neither v1 'PROXY ' nor v2"
            " binary signature)"
        ),
    )
