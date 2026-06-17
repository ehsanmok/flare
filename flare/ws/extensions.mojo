"""``Sec-WebSocket-Extensions`` header parser + emitter (RFC 6455
§9 + RFC 7692 §7).

The header is a comma-separated list of *extension offers*; each
offer has a token name and an optional ``;``-separated list of
``key`` or ``key=value`` parameters. Whitespace around tokens is
folded; quoted-string parameter values are unquoted on parse and
re-quoted on emit when they contain bytes outside the RFC 6455
``token`` set.

This module deliberately stays narrow: it only emits / accepts
the parameters used by ``permessage-deflate`` (RFC 7692 §7.1.1):

- ``server_no_context_takeover``        (flag)
- ``client_no_context_takeover``        (flag)
- ``server_max_window_bits``            (int 8..15)
- ``client_max_window_bits``            (int 8..15, may also be a
  flag with no value when offered by the client)

Public surface:

- :class:`ExtensionOffer` -- one parsed offer.
- :func:`parse_extensions(header)` -> ``List[ExtensionOffer]``.
- :func:`build_permessage_deflate_offer(cfg)` -> ``String`` (client
  side: emit our offer).
- :func:`negotiate_permessage_deflate(offers, cfg)` -> the
  ``(accepted_header_value, negotiated_cfg)`` pair (server side:
  pick the first acceptable offer; raises if none match).
"""

from .permessage_deflate import PermessageDeflateConfig


struct ExtensionParameter(Copyable, Defaultable, Movable):
    """One ``;``-separated parameter inside an
    :class:`ExtensionOffer`."""

    var name: String
    """Lowercased parameter token (e.g. ``"client_max_window_bits"``)."""
    var value: String
    """Parameter value; empty string when the parameter is a flag.
    Quoted-string values have surrounding quotes stripped."""

    def __init__(out self):
        self.name = ""
        self.value = ""

    def __init__(out self, name: String, value: String):
        self.name = name
        self.value = value


struct ExtensionOffer(Copyable, Defaultable, Movable):
    """One comma-separated extension offer + its parameters."""

    var name: String
    """Lowercased extension token (e.g. ``"permessage-deflate"``)."""
    var params: List[ExtensionParameter]
    """Parsed ``;``-separated parameters in declaration order."""

    def __init__(out self):
        self.name = ""
        self.params = List[ExtensionParameter]()

    def __init__(out self, name: String):
        self.name = name
        self.params = List[ExtensionParameter]()

    def get(read self, name: String) raises -> Optional[String]:
        """Return the value for parameter ``name`` (case-folded)
        if present; ``None`` otherwise. Flag-shaped parameters
        return ``Some("")``."""
        for i in range(len(self.params)):
            if self.params[i].name == name:
                return Optional[String](self.params[i].value.copy())
        return None

    def has(read self, name: String) raises -> Bool:
        """Return ``True`` if parameter ``name`` is present."""
        return Bool(self.get(name))


# ── Parsing ──────────────────────────────────────────────────────


def _ascii_lower(s: String) -> String:
    """ASCII lowercase a token (fast path; non-ASCII is left
    alone -- RFC 6455 tokens are ASCII-only anyway).

    Renamed from the older ``_lc`` for consistency with the
    rest of the codebase (which spells the helper
    ``_ascii_lower``).
    """
    var out = String(capacity=s.byte_length())
    for b in s.as_bytes():
        var c = Int(b)
        if c >= 65 and c <= 90:
            out += chr(c + 32)
        else:
            out += chr(c)
    return out^


def _strip(s: StringSlice[_]) raises -> String:
    """Strip ASCII whitespace from both ends."""
    var bytes = s.as_bytes()
    var n = len(bytes)
    var i = 0
    while i < n and (
        bytes[i] == UInt8(0x20)
        or bytes[i] == UInt8(0x09)
        or bytes[i] == UInt8(0x0A)
        or bytes[i] == UInt8(0x0D)
    ):
        i += 1
    var j = n
    while j > i and (
        bytes[j - 1] == UInt8(0x20)
        or bytes[j - 1] == UInt8(0x09)
        or bytes[j - 1] == UInt8(0x0A)
        or bytes[j - 1] == UInt8(0x0D)
    ):
        j -= 1
    return String(unsafe_from_utf8=bytes[i:j])


def _parse_one_offer(piece: String) raises -> ExtensionOffer:
    """Parse one comma-delimited offer (``name; key=value; flag``)."""
    var parts = piece.split(";")
    if len(parts) == 0:
        raise Error("Sec-WebSocket-Extensions: empty offer")
    var name = _ascii_lower(_strip(parts[0]))
    if name.byte_length() == 0:
        raise Error("Sec-WebSocket-Extensions: missing extension token")
    var offer = ExtensionOffer(name)
    for i in range(1, len(parts)):
        var p = _strip(parts[i])
        if p.byte_length() == 0:
            continue
        var eq = p.find("=")
        var pname: String
        var pvalue: String
        if eq < 0:
            pname = _ascii_lower(_strip(p))
            pvalue = ""
        else:
            pname = _ascii_lower(
                _strip(String(unsafe_from_utf8=p.as_bytes()[:eq]))
            )
            pvalue = _strip(String(unsafe_from_utf8=p.as_bytes()[eq + 1 :]))
            # Strip surrounding quotes if present.
            if pvalue.byte_length() >= 2:
                var first = pvalue.as_bytes()[0]
                var last = pvalue.as_bytes()[pvalue.byte_length() - 1]
                if first == UInt8(0x22) and last == UInt8(0x22):
                    pvalue = String(
                        unsafe_from_utf8=pvalue.as_bytes()[
                            1 : pvalue.byte_length() - 1
                        ]
                    )
        offer.params.append(ExtensionParameter(pname, pvalue))
    return offer^


def parse_extensions(header: String) raises -> List[ExtensionOffer]:
    """Parse one ``Sec-WebSocket-Extensions`` header value into
    its constituent offers.

    Multiple header values are comma-joined per RFC 6455 §9.1.
    The empty header returns an empty list (no offers).

    Args:
        header: The raw ``Sec-WebSocket-Extensions`` value.
    """
    var trimmed = _strip(header)
    if trimmed.byte_length() == 0:
        return List[ExtensionOffer]()
    var pieces = trimmed.split(",")
    var out = List[ExtensionOffer]()
    for i in range(len(pieces)):
        var p = _strip(pieces[i])
        if p.byte_length() == 0:
            continue
        out.append(_parse_one_offer(p))
    return out^


# ── Emit / negotiate ─────────────────────────────────────────────


def build_permessage_deflate_offer(cfg: PermessageDeflateConfig) -> String:
    """Build the client-side ``Sec-WebSocket-Extensions`` value for
    a ``permessage-deflate`` offer.

    Always emits ``permessage-deflate`` plus any parameters that
    differ from the RFC default. The offer always carries
    ``client_no_context_takeover`` and
    ``server_no_context_takeover`` so the negotiated mode is
    deterministic.

    Args:
        cfg: The :class:`PermessageDeflateConfig` to translate.

    Returns:
        The header value (e.g.
        ``"permessage-deflate; client_no_context_takeover; server_no_context_takeover"``).
    """
    if not cfg.enabled:
        return ""
    var out = String("permessage-deflate")
    if cfg.client_no_context_takeover:
        out += "; client_no_context_takeover"
    if cfg.server_no_context_takeover:
        out += "; server_no_context_takeover"
    if cfg.client_max_window_bits != 15:
        out += "; client_max_window_bits=" + String(cfg.client_max_window_bits)
    if cfg.server_max_window_bits != 15:
        out += "; server_max_window_bits=" + String(cfg.server_max_window_bits)
    return out^


def negotiate_permessage_deflate(
    offers: List[ExtensionOffer], cfg: PermessageDeflateConfig
) raises -> Optional[Tuple[String, PermessageDeflateConfig]]:
    """Server-side negotiation: pick the first acceptable
    ``permessage-deflate`` offer.

    Returns ``None`` if the client offered nothing acceptable or
    the server has the extension disabled. Otherwise returns the
    ``(Sec-WebSocket-Extensions response value, negotiated_cfg)``
    pair the caller writes into the 101 response. The negotiator
    always enforces ``no_context_takeover`` on both sides so the
    response value is fully deterministic regardless of the
    client's offer.

    Args:
        offers: Parsed offers from the client's
            ``Sec-WebSocket-Extensions`` header.
        cfg: The server's :class:`PermessageDeflateConfig`. Must
            have ``enabled=True``; otherwise this returns
            ``None``.
    """
    if not cfg.enabled:
        return None
    for i in range(len(offers)):
        if offers[i].name != "permessage-deflate":
            continue
        var negotiated = cfg.copy()
        # Honour the client-bit-set parameters so the response
        # value reflects what was offered (handshake honesty), but
        # always force both no_context_takeover bits so the
        # no-context-takeover codec model is in effect.
        negotiated.client_no_context_takeover = True
        negotiated.server_no_context_takeover = True
        # Cap window bits at the RFC default (we don't do < 15).
        var cmw = offers[i].get("client_max_window_bits")
        if cmw and cmw.value().byte_length() > 0:
            try:
                var bits = Int(cmw.value())
                if bits >= 8 and bits <= 15:
                    negotiated.client_max_window_bits = 15
            except:
                pass
        var smw = offers[i].get("server_max_window_bits")
        if smw and smw.value().byte_length() > 0:
            try:
                var bits = Int(smw.value())
                if bits >= 8 and bits <= 15:
                    negotiated.server_max_window_bits = 15
            except:
                pass
        return Optional[Tuple[String, PermessageDeflateConfig]](
            (
                build_permessage_deflate_offer(negotiated),
                negotiated^,
            )
        )
    return None
