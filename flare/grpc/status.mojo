"""``gRPC`` status codes and trailer carrier.

A gRPC call ends with a *trailer* header set containing at least
``grpc-status`` (a decimal integer 0..16). Successful calls
return ``grpc-status: 0`` (OK); failed calls return a non-zero
code plus an optional ``grpc-message`` (a Percent-Encoded UTF-8
human description, capped at a few KiB by most clients).

This module defines the 16 standard status code constants and a
small :class:`GrpcStatus` carrier callers can pass through their
handler chain. The actual trailer-emitting code lives in the
HTTP/2 server adapter (a later commit); this module is purely
the data model.

References:
- https://github.com/grpc/grpc/blob/master/doc/statuscodes.md
- https://grpc.github.io/grpc/core/md_doc_statuscodes.html
"""

from std.collections import List, Optional
from std.collections.span import Span

from flare.crypto.base64 import base64_encode
from flare.http.proto.utf8 import utf8_lossy_string


# Canonical status code constants. The numeric values are stable
# across all gRPC implementations and clients depend on the
# specific integers; do not renumber.


@fieldwise_init
struct GrpcStatus(Copyable):
    """An RPC outcome: numeric code + optional human message + optional binary detail.

    Status codes are stable across implementations -- a Mojo
    handler returning ``GRPC_STATUS_NOT_FOUND`` will surface as
    the same code in a Go / Python / C++ client. The optional
    ``message`` carries free-text context for diagnostics; it
    must not be used for branching by the client.

    ``details`` carries the optional ``grpc-status-details-bin``
    payload (RFC 4648 §4 base64 on the wire; opaque bytes here so
    the application can attach a serialised
    ``google.rpc.Status`` proto, a typed error envelope, or any
    other binary frame the client knows how to parse).
    """

    # ── Canonical status codes (grpc-status wire values) ───────────────
    #
    # Namespaced onto the struct in v0.11 so they read as
    # ``GrpcStatus.NOT_FOUND`` rather than as seventeen bare
    # module-level names -- matching Status, Method, WsOpcode and
    # WireProtocol, which already do this. The module-level
    # ``GRPC_STATUS_*`` spellings remain as aliases below and are used
    # at roughly 155 call sites; they are not going away this release.

    comptime OK: Int = 0
    comptime CANCELLED: Int = 1
    comptime UNKNOWN: Int = 2
    comptime INVALID_ARGUMENT: Int = 3
    comptime DEADLINE_EXCEEDED: Int = 4
    comptime NOT_FOUND: Int = 5
    comptime ALREADY_EXISTS: Int = 6
    comptime PERMISSION_DENIED: Int = 7
    comptime RESOURCE_EXHAUSTED: Int = 8
    comptime FAILED_PRECONDITION: Int = 9
    comptime ABORTED: Int = 10
    comptime OUT_OF_RANGE: Int = 11
    comptime UNIMPLEMENTED: Int = 12
    comptime INTERNAL: Int = 13
    comptime UNAVAILABLE: Int = 14
    comptime DATA_LOSS: Int = 15
    comptime UNAUTHENTICATED: Int = 16

    var code: Int
    var message: String
    var details: Optional[List[UInt8]]

    @staticmethod
    def ok() -> Self:
        return Self(code=GRPC_STATUS_OK, message=String(""), details=None)

    @staticmethod
    def err(code: Int, message: String) -> Self:
        return Self(code=code, message=message, details=None)

    def with_details(self, var details: List[UInt8]) -> Self:
        """Return a copy of this status with the ``grpc-status-
        details-bin`` payload attached. The caller owns the bytes;
        the trailer emitter base64-encodes them when serialising
        the trailing HEADERS field set.
        """
        return Self(
            code=self.code,
            message=self.message,
            details=Optional[List[UInt8]](details^),
        )

    def is_ok(self) -> Bool:
        return self.code == GRPC_STATUS_OK

    def name(self) -> String:
        """Return the canonical short name for the status code.
        Unknown numeric codes (outside 0..16) return
        ``"UNKNOWN_CODE_<n>"`` so logs always have something to
        grep for."""
        if self.code == GRPC_STATUS_OK:
            return String("OK")
        if self.code == GRPC_STATUS_CANCELLED:
            return String("CANCELLED")
        if self.code == GRPC_STATUS_UNKNOWN:
            return String("UNKNOWN")
        if self.code == GRPC_STATUS_INVALID_ARGUMENT:
            return String("INVALID_ARGUMENT")
        if self.code == GRPC_STATUS_DEADLINE_EXCEEDED:
            return String("DEADLINE_EXCEEDED")
        if self.code == GRPC_STATUS_NOT_FOUND:
            return String("NOT_FOUND")
        if self.code == GRPC_STATUS_ALREADY_EXISTS:
            return String("ALREADY_EXISTS")
        if self.code == GRPC_STATUS_PERMISSION_DENIED:
            return String("PERMISSION_DENIED")
        if self.code == GRPC_STATUS_RESOURCE_EXHAUSTED:
            return String("RESOURCE_EXHAUSTED")
        if self.code == GRPC_STATUS_FAILED_PRECONDITION:
            return String("FAILED_PRECONDITION")
        if self.code == GRPC_STATUS_ABORTED:
            return String("ABORTED")
        if self.code == GRPC_STATUS_OUT_OF_RANGE:
            return String("OUT_OF_RANGE")
        if self.code == GRPC_STATUS_UNIMPLEMENTED:
            return String("UNIMPLEMENTED")
        if self.code == GRPC_STATUS_INTERNAL:
            return String("INTERNAL")
        if self.code == GRPC_STATUS_UNAVAILABLE:
            return String("UNAVAILABLE")
        if self.code == GRPC_STATUS_DATA_LOSS:
            return String("DATA_LOSS")
        if self.code == GRPC_STATUS_UNAUTHENTICATED:
            return String("UNAUTHENTICATED")
        return String("UNKNOWN_CODE_") + String(self.code)


# ── Module-level aliases (pre-0.11 spelling) ──────────────────────────

comptime GRPC_STATUS_OK: Int = GrpcStatus.OK
comptime GRPC_STATUS_CANCELLED: Int = GrpcStatus.CANCELLED
comptime GRPC_STATUS_UNKNOWN: Int = GrpcStatus.UNKNOWN
comptime GRPC_STATUS_INVALID_ARGUMENT: Int = GrpcStatus.INVALID_ARGUMENT
comptime GRPC_STATUS_DEADLINE_EXCEEDED: Int = GrpcStatus.DEADLINE_EXCEEDED
comptime GRPC_STATUS_NOT_FOUND: Int = GrpcStatus.NOT_FOUND
comptime GRPC_STATUS_ALREADY_EXISTS: Int = GrpcStatus.ALREADY_EXISTS
comptime GRPC_STATUS_PERMISSION_DENIED: Int = GrpcStatus.PERMISSION_DENIED
comptime GRPC_STATUS_RESOURCE_EXHAUSTED: Int = GrpcStatus.RESOURCE_EXHAUSTED
comptime GRPC_STATUS_FAILED_PRECONDITION: Int = GrpcStatus.FAILED_PRECONDITION
comptime GRPC_STATUS_ABORTED: Int = GrpcStatus.ABORTED
comptime GRPC_STATUS_OUT_OF_RANGE: Int = GrpcStatus.OUT_OF_RANGE
comptime GRPC_STATUS_UNIMPLEMENTED: Int = GrpcStatus.UNIMPLEMENTED
comptime GRPC_STATUS_INTERNAL: Int = GrpcStatus.INTERNAL
comptime GRPC_STATUS_UNAVAILABLE: Int = GrpcStatus.UNAVAILABLE
comptime GRPC_STATUS_DATA_LOSS: Int = GrpcStatus.DATA_LOSS
comptime GRPC_STATUS_UNAUTHENTICATED: Int = GrpcStatus.UNAUTHENTICATED


# ── grpc-message percent-encoding (PROTOCOL-HTTP2) ────────────────────


comptime _HEX: String = "0123456789ABCDEF"


def grpc_message_encode(message: String) -> String:
    """Percent-encode ``message`` for the ``grpc-message`` field.

    gRPC's PROTOCOL-HTTP2 carries the message as percent-encoded UTF-8:
    every byte outside ``0x20..0x7E``, and ``%`` itself, becomes
    ``%XX``. Sent raw, a non-ASCII message reached clients as mojibake
    and a CR or LF in it was a field-injection vector on any transport
    that did not reject it.
    """
    var out = List[UInt8](capacity=message.byte_length())
    for b in message.as_bytes():
        if b < 0x20 or b > 0x7E or b == UInt8(ord("%")):
            out.append(UInt8(ord("%")))
            out.append(_HEX.as_bytes()[Int(b >> 4)])
            out.append(_HEX.as_bytes()[Int(b & 0x0F)])
        else:
            out.append(b)
    return String(unsafe_from_utf8=Span[UInt8, _](out))


def _hex_val(b: UInt8) -> Int:
    if b >= UInt8(ord("0")) and b <= UInt8(ord("9")):
        return Int(b) - ord("0")
    if b >= UInt8(ord("a")) and b <= UInt8(ord("f")):
        return Int(b) - ord("a") + 10
    if b >= UInt8(ord("A")) and b <= UInt8(ord("F")):
        return Int(b) - ord("A") + 10
    return -1


def grpc_message_decode(value: String) -> String:
    """Undo :func:`grpc_message_encode` on a received ``grpc-message``.

    The spec asks a receiver not to fail on a malformed value, so a
    ``%`` not followed by two hex digits is kept as it is, and bytes
    that do not decode to valid UTF-8 are replaced, not raised on.
    """
    var src = value.as_bytes()
    var out = List[UInt8](capacity=len(src))
    var i = 0
    while i < len(src):
        if src[i] == UInt8(ord("%")) and i + 2 < len(src):
            var hi = _hex_val(src[i + 1])
            var lo = _hex_val(src[i + 2])
            if hi >= 0 and lo >= 0:
                out.append(UInt8(hi * 16 + lo))
                i += 3
                continue
        out.append(src[i])
        i += 1
    return utf8_lossy_string(Span[UInt8, _](out))
