"""``gRPC`` metadata carrier (initial + trailing).

gRPC metadata is a name-value map carried in HTTP/2 HEADERS
frames at the start (initial metadata) and after the body
(trailing metadata) of every call. The keys are ASCII-only
(lowercased on the wire), and values come in two flavours:

- **Text keys** (most): name ends in any suffix except ``-bin``;
  value must be printable ASCII (subset of HTTP field-content
  per the gRPC spec).
- **Binary keys**: name ends in ``-bin`` (e.g. ``trace-bin``);
  value is arbitrary bytes encoded as base64 on the HTTP/2 wire.
  At the application layer the caller works with the raw bytes
  and the framing layer base64-encodes on egress, decodes on
  ingress.

Reserved keys begin with ``grpc-`` and are managed by the
framework (e.g. ``grpc-status``, ``grpc-message``,
``grpc-encoding``, ``grpc-timeout``). The carrier rejects writes
to reserved keys to keep handler code from accidentally clobbering
framework-controlled trailers.

References:
- gRPC PROTOCOL-HTTP2 spec (Metadata section).
- https://grpc.github.io/grpc/core/md_doc_PROTOCOL-HTTP2.html
"""

from std.collections import List
from std.collections import Optional

from ..http.proto.ascii import ascii_unchecked_string


@fieldwise_init
struct GrpcMetadataEntry(Copyable):
    """Single metadata key-value pair. ``is_binary`` is derived
    from the key suffix (``-bin``) but cached for fast access."""

    var key: String
    var value: List[UInt8]
    var is_binary: Bool


def _ends_with_bin(key: String) -> Bool:
    """Return True if ``key`` ends in ``-bin`` (gRPC binary
    metadata suffix). Case-insensitive per the gRPC spec, but the
    wire form is always lowercase so we compare lowercase here."""
    var n = key.byte_length()
    if n < 4:
        return False
    var p = key.unsafe_ptr()
    if p[unsafe_offset=n - 4] != UInt8(ord("-")):
        return False
    if p[unsafe_offset=n - 3] != UInt8(ord("b")) and p[
        unsafe_offset=n - 3
    ] != UInt8(ord("B")):
        return False
    if p[unsafe_offset=n - 2] != UInt8(ord("i")) and p[
        unsafe_offset=n - 2
    ] != UInt8(ord("I")):
        return False
    if p[unsafe_offset=n - 1] != UInt8(ord("n")) and p[
        unsafe_offset=n - 1
    ] != UInt8(ord("N")):
        return False
    return True


def _is_reserved(key: String) -> Bool:
    """Reserved gRPC framework keys start with ``grpc-``. The
    carrier rejects application writes to these keys."""
    if key.byte_length() < 5:
        return False
    var p = key.unsafe_ptr()
    return (
        p[unsafe_offset=0] == UInt8(ord("g"))
        and p[unsafe_offset=1] == UInt8(ord("r"))
        and p[unsafe_offset=2] == UInt8(ord("p"))
        and p[unsafe_offset=3] == UInt8(ord("c"))
        and p[unsafe_offset=4] == UInt8(ord("-"))
    )


struct GrpcMetadata(Copyable, Defaultable):
    """Ordered list of metadata entries.

    The list preserves insertion order so trailers like
    ``set-cookie`` (rare in gRPC but legal) round-trip with their
    original sequence. Lookup is O(N) because metadata sets are
    typically tiny (under 10 entries); a hash-backed variant can
    be added later if profilers complain.
    """

    var _entries: List[GrpcMetadataEntry]

    def __init__(out self):
        self._entries = List[GrpcMetadataEntry]()

    def __init__(out self, *, copy: Self):
        self._entries = copy._entries.copy()

    def copy(self) -> Self:
        var out = Self()
        out._entries = self._entries.copy()
        return out^

    def len(self) -> Int:
        return len(self._entries)

    def append(mut self, key: String, var value: List[UInt8]) raises:
        """Append a metadata entry. The key must not be reserved
        (``grpc-`` prefix); reserved keys are framework-managed
        and are emitted by the gRPC adapter directly."""
        if _is_reserved(key):
            raise Error(
                "grpc metadata: reserved key '" + key + "' is framework-managed"
            )
        var bin = _ends_with_bin(key)
        self._entries.append(
            GrpcMetadataEntry(key=key, value=value^, is_binary=bin)
        )

    def append_text(mut self, key: String, value: String) raises:
        """Convenience: append a text-valued metadata entry. The
        key must NOT end in ``-bin``; text values that look like
        binary are a frequent footgun, so the carrier rejects
        them rather than silently mis-encoding."""
        if _ends_with_bin(key):
            raise Error(
                "grpc metadata: text value passed to binary key '"
                + key
                + "' (the -bin suffix selects binary semantics)"
            )
        if _is_reserved(key):
            raise Error(
                "grpc metadata: reserved key '" + key + "' is framework-managed"
            )
        var bytes = List[UInt8]()
        var p = value.unsafe_ptr()
        for i in range(value.byte_length()):
            bytes.append(p[unsafe_offset=i])
        self._entries.append(
            GrpcMetadataEntry(key=key, value=bytes^, is_binary=False)
        )

    def get_text(self, key: String) raises -> Optional[String]:
        """Return the first text-valued entry under ``key``, or
        ``None`` if absent. Raises if the entry is binary (the
        caller should use ``get_binary`` instead)."""
        for i in range(len(self._entries)):
            if self._entries[i].key == key:
                if self._entries[i].is_binary:
                    raise Error("grpc metadata: key '" + key + "' is binary")
                var s = ascii_unchecked_string(
                    Span[UInt8, _](self._entries[i].value)
                )
                return Optional[String](s)
        return Optional[String]()

    def get_binary(self, key: String) raises -> Optional[List[UInt8]]:
        """Return the first binary-valued entry under ``key``."""
        for i in range(len(self._entries)):
            if self._entries[i].key == key:
                if not self._entries[i].is_binary:
                    raise Error(
                        "grpc metadata: key '" + key + "' is not binary"
                    )
                return Optional[List[UInt8]](self._entries[i].value.copy())
        return Optional[List[UInt8]]()

    def entries(self) -> List[GrpcMetadataEntry]:
        """Return a copy of the entry list (insertion order
        preserved). Useful for serialising the metadata into
        HTTP/2 HEADERS frames."""
        return self._entries.copy()
