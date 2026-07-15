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
registered service-name list and ``file_by_filename`` /
``file_containing_symbol`` from a registered ``FileDescriptorProto``
registry (the blobs ``tools/proto_gen.py`` emits per ``.proto`` file).
Lookups that miss return ``NOT_FOUND``. As a result ``grpcurl list``,
``grpcurl describe``, and reflection-driven calls all work once the
generated descriptors are registered.

``ServerReflectionInfo`` is bidi-streaming;
:class:`ReflectionBidiHandler` adapts :meth:`ReflectionService.answer`
onto the :trait:`flare.grpc.GrpcBidiStreaming` server trait, so it is
mountable via ``GrpcBidiService(ReflectionBidiHandler(svc))``.

References:
- https://github.com/grpc/grpc/blob/master/src/proto/grpc/reflection/v1alpha/reflection.proto
"""

from std.collections import Dict, List
from std.memory import Span

from .client_stream import GrpcBidiStreaming
from .proto import ProtoReader, ProtoWriter, WIRE_LEN
from .server import GrpcCallContext
from .server_stream import GrpcServerStreamReply
from .status import GRPC_STATUS_NOT_FOUND, GRPC_STATUS_UNIMPLEMENTED


# Reflection request oneof field numbers (message_request).
comptime REFLECT_FILE_BY_FILENAME: Int = 3
comptime REFLECT_FILE_CONTAINING_SYMBOL: Int = 4
comptime REFLECT_LIST_SERVICES: Int = 7

# Reflection response oneof field numbers (message_response).
comptime REFLECT_FILE_DESCRIPTOR_RESPONSE: Int = 4
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
    """Answers ``ServerReflectionInfo`` requests.

    Register every gRPC service path (``package.Service``) for
    ``list_services``; register a serialized ``FileDescriptorProto`` per
    ``.proto`` file (from :func:`tools.proto_gen` output) with its symbol
    names for ``file_by_filename`` / ``file_containing_symbol``. Lookups
    that miss return ``NOT_FOUND``.
    """

    var services: List[String]
    var descriptors: Dict[String, List[UInt8]]
    """filename -> serialized FileDescriptorProto bytes."""
    var symbol_index: Dict[String, String]
    """fully-qualified symbol (``pkg.Service`` / ``pkg.Message``) ->
    the filename whose descriptor defines it."""

    def __init__(out self):
        self.services = List[String]()
        self.descriptors = Dict[String, List[UInt8]]()
        self.symbol_index = Dict[String, String]()

    def __init__(out self, *, copy: Self):
        self.services = copy.services.copy()
        self.descriptors = copy.descriptors.copy()
        self.symbol_index = copy.symbol_index.copy()

    def copy(self) -> Self:
        return Self(copy=self)

    def register(mut self, name: String):
        """Add a fully-qualified service name (``package.Service``)."""
        self.services.append(name)

    def register_descriptor(
        mut self,
        filename: String,
        var descriptor: List[UInt8],
        symbols: List[String],
    ):
        """Register a serialized ``FileDescriptorProto`` under
        ``filename`` and index every ``symbols`` entry (service / message
        fully-qualified names) to it for ``file_containing_symbol``."""
        for i in range(len(symbols)):
            self.symbol_index[symbols[i]] = filename
        self.descriptors[filename] = descriptor^

    def answer(self, request_bytes: Span[UInt8, _]) raises -> List[UInt8]:
        """Decode one ``ServerReflectionRequest`` and encode the
        matching ``ServerReflectionResponse`` bytes.

        ``list_services`` names every registered service.
        ``file_by_filename`` / ``file_containing_symbol`` return the
        registered ``FileDescriptorProto`` (``NOT_FOUND`` on a miss). An
        unrecognised arm returns ``UNIMPLEMENTED``.
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
        elif req.kind == REFLECT_FILE_BY_FILENAME:
            self._write_descriptor(w, req.arg, req.arg in self.descriptors)
        elif req.kind == REFLECT_FILE_CONTAINING_SYMBOL:
            var fname = String("")
            var found = req.arg in self.symbol_index
            if found:
                fname = self.symbol_index[req.arg]
            self._write_descriptor(w, fname, found)
        else:
            w.write_message(
                REFLECT_ERROR_RESPONSE,
                Span[UInt8, _](
                    _error_response(
                        GRPC_STATUS_UNIMPLEMENTED,
                        String("reflection: unrecognised request"),
                    )
                ),
            )
        return w.take()

    def _write_descriptor(
        self, mut w: ProtoWriter, filename: String, found: Bool
    ) raises:
        """Append a FileDescriptorResponse (field 4) for ``filename`` or a
        NOT_FOUND error when the descriptor is not registered."""
        if not found or filename not in self.descriptors:
            w.write_message(
                REFLECT_ERROR_RESPONSE,
                Span[UInt8, _](
                    _error_response(
                        GRPC_STATUS_NOT_FOUND,
                        String("reflection: descriptor not found"),
                    )
                ),
            )
            return
        # FileDescriptorResponse { repeated bytes file_descriptor_proto = 1; }
        var fw = ProtoWriter()
        fw.write_bytes(1, Span[UInt8, _](self.descriptors[filename]))
        w.write_message(
            REFLECT_FILE_DESCRIPTOR_RESPONSE, Span[UInt8, _](fw.take())
        )

    def _list_services_response(self) raises -> List[UInt8]:
        # ListServiceResponse { repeated ServiceResponse service = 1; }
        # ServiceResponse     { string name = 1; }
        var lw = ProtoWriter()
        for i in range(len(self.services)):
            var sw = ProtoWriter()
            sw.write_string(1, self.services[i])
            lw.write_message(1, Span[UInt8, _](sw.take()))
        return lw.take()


@fieldwise_init
struct ReflectionBidiHandler(Copyable, GrpcBidiStreaming, Movable):
    """Bidi adapter that runs every inbound ``ServerReflectionRequest``
    through :meth:`ReflectionService.answer`, framing each response as
    its own LPM frame. Mount via
    ``GrpcBidiService(ReflectionBidiHandler(svc))`` on
    ``/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo``.
    """

    var service: ReflectionService

    def serve_bidi(
        mut self,
        ctx: GrpcCallContext,
        messages: List[List[UInt8]],
    ) raises -> GrpcServerStreamReply:
        var outs = List[List[UInt8]]()
        for i in range(len(messages)):
            outs.append(self.service.answer(Span[UInt8, _](messages[i])))
        return GrpcServerStreamReply.ok(outs^)


def _error_response(code: Int, message: String) raises -> List[UInt8]:
    # ErrorResponse { int32 error_code = 1; string error_message = 2; }
    var ew = ProtoWriter()
    ew.write_int64(1, Int64(code))
    ew.write_string(2, message)
    return ew.take()
