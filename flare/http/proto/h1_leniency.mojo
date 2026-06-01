"""Named opt-in flags for HTTP/1.1 parser leniency.

RFC 9112 (HTTP/1.1) defines a strict wire grammar. Real-world
clients ship bugs around the edges of that grammar, and most
deployed servers historically silently accepted a handful of
relaxations. This module surfaces those relaxations as **named,
strict-by-default opt-in flags**: a deployment chooses which
relaxations its parser performs, and the choice is visible at
the configuration call site rather than buried in parser
internals.

## Design

- **Strict by default.** ``H1LeniencyConfig()`` returns the
  strictest configuration: every flag off. A server that trusts
  only well-behaved peers can ship this config and reject
  anything that bends the spec.
- **One flag, one relaxation.** No "loose" / "strict" master
  preset: each relaxation is justified individually.
- **No silent relaxations.** Each flag's docstring cites the
  RFC section it relaxes; deployments that depended on prior
  silent acceptance opt into the corresponding flag.

## Plumbing status

Flags are consumed by the H1 request parser
(:func:`flare.http.server._parse_http_request_bytes`) when wired
through :attr:`flare.http.server.ServerConfig.h1_leniency`. The
ten request-message flags (every flag except the two chunked-
extension flags below) flip parser behaviour today; the
conformance corpus under ``conformance/h1/`` carries one accept
+ one reject fixture per flag.

The two chunked-extension flags --
``accept_empty_chunk_extensions`` and
``accept_invalid_chunk_extension_chars`` -- govern server-side
``Transfer-Encoding: chunked`` request-body decoding, which the
v0.8 server rejects up-front (no chunked request decoder is
mounted yet). The flags are present so deployment configuration
that anticipates chunked support compiles today; they become
load-bearing alongside the chunked-decoder audit pass.

## Flags

```mojo
from flare.http.proto import H1LeniencyConfig

# Strict (default): reject every relaxation.
var strict = H1LeniencyConfig()

# Compatible with chatty legacy clients.
var compat = H1LeniencyConfig(
    allow_lf_only_line_endings=True,
    allow_mixed_case_method=True,
)
```

The legacy name ``_ExperimentalH1LeniencyConfig`` is preserved
as an alias (a structurally-identical rebind) so existing
configuration code keeps compiling; the canonical name moving
forward is :class:`H1LeniencyConfig`.
"""


struct H1LeniencyConfig(Copyable, Movable):
    """HTTP/1.1 parser leniency configuration.

    Strict by default. Each field maps to one RFC 9112
    relaxation; the docstring on each field cites the section
    it relaxes.

    Wired into :func:`flare.http.server._parse_http_request_bytes`
    via :attr:`flare.http.server.ServerConfig.h1_leniency`. The
    parser checks each flag at the matching grammar branch and
    relaxes the strict default only when the flag is set. The
    two chunked-extension flags govern a chunked-decoder audit
    pass that lands alongside server-side chunked-body support;
    they currently have no parser-side effect.
    """

    var allow_lf_only_line_endings: Bool
    """Accept bare ``LF`` (``\\n``) as a line terminator in
    place of ``CRLF`` (``\\r\\n``). RFC 9112 §2.2 requires
    ``CRLF``; many older clients emit bare ``LF`` between the
    request line, headers, and the trailing blank line. The
    parser's tokeniser still rejects mixed terminators (``CR``
    not followed by ``LF``)."""

    var allow_mixed_case_method: Bool
    """Accept method tokens with mixed case (e.g. ``Get`` /
    ``get``). RFC 9110 §9.1 defines methods as case-sensitive
    tokens; this flag normalises common variants to upper-case
    before dispatch. Defaults off because case-folding
    pre-dispatch can mask request-smuggling attempts."""

    var allow_ows_around_colon: Bool
    """Accept optional whitespace (``SP`` / ``HTAB``) between
    the header field name and the ``:`` separator. RFC 9112
    §5.1 explicitly forbids whitespace before the ``:``; this
    is the classic request-smuggling vector
    (CVE-2022-24999-class). Defaults off; flip only if a
    trusted upstream emits ``Header :value``."""

    var allow_obs_fold: Bool
    """Accept line-folded header values (``LWS`` continuation
    line where the next line starts with whitespace). RFC 9112
    §5.2 calls this "obs-fold" and recommends rejection (it's
    a request-smuggling primitive). Defaults off; flip only
    when an upstream protocol cannot avoid emitting folded
    values."""

    var allow_oversized_request_uri: Bool
    """Accept request URIs beyond ``ServerConfig.max_uri_length``
    instead of emitting ``414 URI Too Long``. RFC 9110 §15.5.15
    permits the server to choose its own cap; this flag elides
    the cap entirely. Defaults off so DoS surfaces stay
    bounded."""

    var allow_oversized_header_list: Bool
    """Accept the request header block beyond
    ``ServerConfig.max_header_size`` instead of emitting
    ``431 Request Header Fields Too Large``. RFC 6585 §5
    motivates the 431. Defaults off."""

    var accept_empty_chunk_extensions: Bool
    """Accept ``5;\\r\\nhello\\r\\n`` chunked-body bodies that
    declare a chunk extension (the ``;`` after the size) and
    then provide no extension value or name. RFC 9112 §7.1.1
    defines the chunk extension grammar; some clients emit a
    bare ``;`` with no name=value pair. Defaults off.

    .. note::

       Reserved for the chunked-body decoder audit pass. The
       server today rejects ``Transfer-Encoding: chunked``
       request bodies up-front; this flag has no current
       parser-side effect.
    """

    var allow_multiple_content_length: Bool
    """Accept duplicate ``Content-Length`` headers that agree
    on the value (one value, repeated). RFC 9112 §6.3.5 says
    duplicate ``Content-Length`` MUST be rejected unless all
    values are identical; the spec wording covers both "same
    value, same header line, comma-separated" and "same value,
    repeated header line". Defaults off; the canonical
    treatment is 400 Bad Request."""

    var allow_te_chunked_when_cl_present: Bool
    """When the request carries both ``Content-Length`` and
    ``Transfer-Encoding: chunked``, prefer the chunked framing
    and ignore the ``Content-Length``. RFC 9112 §6.3 requires
    this (the chunked encoding wins) but recommends rejecting
    the request as ambiguous in proxy contexts. Flare's
    default is to reject (400); flip this flag to honour the
    RFC's chunked-wins rule. The "reject" default is the
    request-smuggling-safe choice for an origin server."""

    var accept_obs_text_in_field_value: Bool
    """Accept high-bit bytes (``0x80``..``0xFF``) in header
    field values. RFC 9112 §5.5 defines obs-text and notes
    that recipients SHOULD treat the bytes as opaque but MAY
    reject them. Defaults off because legitimate clients
    rarely emit obs-text and the bytes are a common
    fuzzing-discovered crash vector."""

    var accept_invalid_chunk_extension_chars: Bool
    """Accept characters that violate the chunk-extension
    ``token`` / ``quoted-string`` grammar inside the
    ``;ext=value`` portion of a chunk-size line. RFC 9112
    §7.1.1 defines the grammar strictly. Defaults off; flip
    only if you trust the upstream's chunk-extension
    formatting.

    .. note::

       Reserved for the chunked-body decoder audit pass; see
       :attr:`accept_empty_chunk_extensions`.
    """

    var allow_leading_whitespace_before_request_line: Bool
    """Accept leading ``CR`` / ``LF`` / ``SP`` / ``HTAB`` bytes
    before the request line. RFC 9112 §2.2 says servers
    SHOULD ignore leading empty lines (older RFCs allowed
    leading CRLFs as a workaround for clients that emitted a
    trailing CRLF after a previous request). Defaults off
    because the modern preface-peek dispatcher (HTTP/2
    preface detection) needs the first bytes to be
    meaningful."""

    def __init__(
        out self,
        *,
        allow_lf_only_line_endings: Bool = False,
        allow_mixed_case_method: Bool = False,
        allow_ows_around_colon: Bool = False,
        allow_obs_fold: Bool = False,
        allow_oversized_request_uri: Bool = False,
        allow_oversized_header_list: Bool = False,
        accept_empty_chunk_extensions: Bool = False,
        allow_multiple_content_length: Bool = False,
        allow_te_chunked_when_cl_present: Bool = False,
        accept_obs_text_in_field_value: Bool = False,
        accept_invalid_chunk_extension_chars: Bool = False,
        allow_leading_whitespace_before_request_line: Bool = False,
    ):
        """Build a config with each flag independently set.

        Every argument defaults to ``False`` (strict). Use
        keyword arguments so the call site shows which
        relaxations are enabled.
        """
        self.allow_lf_only_line_endings = allow_lf_only_line_endings
        self.allow_mixed_case_method = allow_mixed_case_method
        self.allow_ows_around_colon = allow_ows_around_colon
        self.allow_obs_fold = allow_obs_fold
        self.allow_oversized_request_uri = allow_oversized_request_uri
        self.allow_oversized_header_list = allow_oversized_header_list
        self.accept_empty_chunk_extensions = accept_empty_chunk_extensions
        self.allow_multiple_content_length = allow_multiple_content_length
        self.allow_te_chunked_when_cl_present = allow_te_chunked_when_cl_present
        self.accept_obs_text_in_field_value = accept_obs_text_in_field_value
        self.accept_invalid_chunk_extension_chars = (
            accept_invalid_chunk_extension_chars
        )
        self.allow_leading_whitespace_before_request_line = (
            allow_leading_whitespace_before_request_line
        )

    @staticmethod
    def strict() -> Self:
        """The strict configuration: every flag off.

        Synonym for the no-argument constructor. Provided so the
        intent is unambiguous at the call site.
        """
        return Self()

    def any_enabled(self) -> Bool:
        """Returns ``True`` if at least one relaxation is on.

        Useful for logging / metrics: a server can record
        whether it's running with leniency enabled and which
        flags are tripped.
        """
        return (
            self.allow_lf_only_line_endings
            or self.allow_mixed_case_method
            or self.allow_ows_around_colon
            or self.allow_obs_fold
            or self.allow_oversized_request_uri
            or self.allow_oversized_header_list
            or self.accept_empty_chunk_extensions
            or self.allow_multiple_content_length
            or self.allow_te_chunked_when_cl_present
            or self.accept_obs_text_in_field_value
            or self.accept_invalid_chunk_extension_chars
            or self.allow_leading_whitespace_before_request_line
        )


# Legacy alias preserved for back-compat with v0.7 configuration
# code. New code should reach for ``H1LeniencyConfig`` directly;
# the underscore-prefixed alias is documented as a thin rebind in
# the module docstring and will be removed in a future cycle.
comptime _ExperimentalH1LeniencyConfig = H1LeniencyConfig
