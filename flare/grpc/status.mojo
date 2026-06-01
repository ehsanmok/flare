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
from std.memory import Span

from flare.crypto.base64 import base64_encode


# Canonical status code constants. The numeric values are stable
# across all gRPC implementations and clients depend on the
# specific integers; do not renumber.
comptime GRPC_STATUS_OK: Int = 0
comptime GRPC_STATUS_CANCELLED: Int = 1
comptime GRPC_STATUS_UNKNOWN: Int = 2
comptime GRPC_STATUS_INVALID_ARGUMENT: Int = 3
comptime GRPC_STATUS_DEADLINE_EXCEEDED: Int = 4
comptime GRPC_STATUS_NOT_FOUND: Int = 5
comptime GRPC_STATUS_ALREADY_EXISTS: Int = 6
comptime GRPC_STATUS_PERMISSION_DENIED: Int = 7
comptime GRPC_STATUS_RESOURCE_EXHAUSTED: Int = 8
comptime GRPC_STATUS_FAILED_PRECONDITION: Int = 9
comptime GRPC_STATUS_ABORTED: Int = 10
comptime GRPC_STATUS_OUT_OF_RANGE: Int = 11
comptime GRPC_STATUS_UNIMPLEMENTED: Int = 12
comptime GRPC_STATUS_INTERNAL: Int = 13
comptime GRPC_STATUS_UNAVAILABLE: Int = 14
comptime GRPC_STATUS_DATA_LOSS: Int = 15
comptime GRPC_STATUS_UNAUTHENTICATED: Int = 16


@fieldwise_init
struct GrpcStatus(Copyable, Movable):
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
