"""``flare.grpc.reflection`` -- gRPC server reflection (v1alpha).

Server reflection lets a client (``grpcurl``, ``grpc_cli``, Postman)
discover what a server exposes without a local ``.proto``. The service
is ``grpc.reflection.v1alpha.ServerReflection`` with one bidi-streaming
method ``ServerReflectionInfo`` -- each request message asks one of:

* ``list_services`` (field 7): "what services do you serve?"
* ``file_by_filename`` (field 3) / ``file_containing_symbol``
  (field 4): "give me the descriptor for X".

This module ships the wire codec for the request / response messages
and a :class:`ReflectionService` that answers ``list_services`` from a
registered service-name list. Descriptor lookups return the reflection
``ErrorResponse`` with ``UNIMPLEMENTED``.

ponytail: only ``list_services`` is answered with data;
``file_by_filename`` / ``file_containing_symbol`` return UNIMPLEMENTED.
Ceiling: ``grpcurl list`` works, but ``grpcurl describe`` /
``<call without -proto>`` does not -- those need serialized
``FileDescriptorProto`` bytes. Upgrade path: have ``tools/proto_gen.py``
also emit a ``FileDescriptorProto`` blob per file and serve it here.

ponytail: this is the sans-I/O codec + a per-request answerer.
``ServerReflectionInfo`` is bidi-streaming; wiring it onto a live
server needs a bidi server adapter (the unary / server-streaming
adapters in this package handle one request message). Ceiling: not
auto-mountable yet. Upgrade path: a ``GrpcBidi`` server adapter that
feeds each inbound request message through :meth:`ReflectionService.
answer` and frames each response as its own LPM frame.

References:
- https://github.com/grpc/grpc/blob/master/src/proto/grpc/reflection/v1alpha/reflection.proto
"""

from std.collections import List
from std.memory import Span

from .proto import ProtoReader, ProtoWriter, WIRE_LEN
from .status import GRPC_STATUS_UNIMPLEMENTED


# Reflection request oneof field numbers (message_request).
comptime REFLECT_FILE_BY_FILENAME: Int = 3
comptime REFLECT_FILE_CONTAINING_SYMBOL: Int = 4
comptime REFLECT_LIST_SERVICES: Int = 7

# Reflection response oneof field numbers (message_response).
comptime REFLECT_LIST_SERVICES_RESPONSE: Int = 6
comptime REFLECT_ERROR_RESPONSE: Int = 7


@fieldwise_init
struct ReflectionRequest(Copyable, Movable):
    """Decoded ``ServerReflectionRequest`` -- which oneof arm is set
    plus its string argument.

    ``kind`` is the oneof field number (one of the ``REFLECT_*``
    constants) or ``0`` when none of the recognised arms were present.
    ``arg`` carries the string payload for the string-valued arms
    (``list_services`` / ``file_by_filename`` /
    ``file_containing_symbol``).
    """

    var kind: Int
    var arg: String

    @staticmethod
    def decode(data: Span[UInt8, _]) raises -> Self:
        var kind = 0
        var arg = String("")
        var r = ProtoReader(data)
        while r.has_more():
            var tw = r.read_tag()
            var field = tw[0]
            var wire = tw[1]
            if (
                field == REFLECT_LIST_SERVICES
                or field == REFLECT_FILE_BY_FILENAME
                or field == REFLECT_FILE_CONTAINING_SYMBOL
            ) and wire == WIRE_LEN:
                kind = field
                arg = r.read_string()
            else:
                r.skip(wire)
        return Self(kind=kind, arg=arg^)


struct ReflectionService(Copyable, Movable):
    """Answers ``ServerReflectionInfo`` requests from a registered set
    of service names.

    Register every gRPC service path (``package.Service``) the server
    mounts; :meth:`answer` then satisfies ``list_services`` and returns
    ``UNIMPLEMENTED`` for descriptor lookups (see module ceiling).
    """

    var services: List[String]

    def __init__(out self):
        self.services = List[String]()

    def __init__(out self, *, copy: Self):
        self.services = copy.services.copy()

    def copy(self) -> Self:
        return Self(copy=self)

    def register(mut self, name: String):
        """Add a fully-qualified service name (``package.Service``)."""
        self.services.append(name)

    def answer(self, request_bytes: Span[UInt8, _]) raises -> List[UInt8]:
        """Decode one ``ServerReflectionRequest`` and encode the
        matching ``ServerReflectionResponse`` bytes.

        ``list_services`` returns a ``ListServiceResponse`` naming every
        registered service. Every other arm returns an ``ErrorResponse``
        carrying ``UNIMPLEMENTED`` -- the descriptor path is the
        documented ceiling.
        """
        var req = ReflectionRequest.decode(request_bytes)
        var w = ProtoWriter()
        # Echo the original request (response field 2) so the client can
        # correlate -- it carries the raw request bytes verbatim.
        w.write_message(2, request_bytes)
        if req.kind == REFLECT_LIST_SERVICES:
            w.write_message(
                REFLECT_LIST_SERVICES_RESPONSE,
                Span[UInt8, _](self._list_services_response()),
            )
        else:
            w.write_message(
                REFLECT_ERROR_RESPONSE,
                Span[UInt8, _](
                    _error_response(
                        GRPC_STATUS_UNIMPLEMENTED,
                        String(
                            "reflection: descriptor responses not supported"
                            " (list_services only)"
                        ),
                    )
                ),
            )
        return w.take()

    def _list_services_response(self) raises -> List[UInt8]:
        # ListServiceResponse { repeated ServiceResponse service = 1; }
        # ServiceResponse     { string name = 1; }
        var lw = ProtoWriter()
        for i in range(len(self.services)):
            var sw = ProtoWriter()
            sw.write_string(1, self.services[i])
            lw.write_message(1, Span[UInt8, _](sw.take()))
        return lw.take()


def _error_response(code: Int, message: String) raises -> List[UInt8]:
    # ErrorResponse { int32 error_code = 1; string error_message = 2; }
    var ew = ProtoWriter()
    ew.write_int64(1, Int64(code))
    ew.write_string(2, message)
    return ew.take()
