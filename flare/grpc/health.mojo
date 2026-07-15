"""``flare.grpc.health`` -- the standard ``grpc.health.v1.Health``
service (Check), implemented as a :trait:`GrpcUnary` handler.

Wire schema (grpc/health/v1/health.proto):

    message HealthCheckRequest  { string service = 1; }
    message HealthCheckResponse { ServingStatus status = 1; }
    enum ServingStatus {
        UNKNOWN = 0; SERVING = 1; NOT_SERVING = 2; SERVICE_UNKNOWN = 3;
    }

``Check`` returns the registered status for the requested service name
(the empty name ``""`` is the conventional "overall server" key). An
unregistered name yields ``SERVICE_UNKNOWN`` per the spec.

Mount it like any unary service (typically behind a router that
dispatches ``/grpc.health.v1.Health/Check`` to this handler)::

    var health = HealthService()
    health.set_status("", HEALTH_SERVING)
    var svc = GrpcService(health)

The streaming ``Watch`` method (:class:`HealthWatchHandler`) is a
server-streaming RPC that replays the current status plus each recorded
status change; mount it via ``GrpcStreamingService(HealthWatchHandler(
health))``.
"""

from std.collections import Dict
from std.memory import Span

from .proto import ProtoReader, ProtoWriter, WIRE_LEN
from .server import GrpcCallContext, GrpcUnary, GrpcUnaryReply
from .server_stream import GrpcServerStreaming, GrpcServerStreamReply


comptime HEALTH_UNKNOWN: Int = 0
comptime HEALTH_SERVING: Int = 1
comptime HEALTH_NOT_SERVING: Int = 2
comptime HEALTH_SERVICE_UNKNOWN: Int = 3
"""``grpc.health.v1.HealthCheckResponse.ServingStatus`` codepoints."""


def decode_health_request(payload: Span[UInt8, _]) raises -> String:
    """Decode a ``HealthCheckRequest`` -> the requested service name
    (field 1, string). Missing field 1 decodes to the empty name."""
    var r = ProtoReader(payload)
    var service = String("")
    while r.has_more():
        var t = r.read_tag()
        if t[0] == 1 and t[1] == WIRE_LEN:
            service = r.read_string()
        else:
            r.skip(t[1])
    return service^


def encode_health_response(status: Int) -> List[UInt8]:
    """Encode a ``HealthCheckResponse`` carrying ``status`` (field 1,
    enum). proto3 omits the field when the value is the default ``0``
    (UNKNOWN)."""
    var w = ProtoWriter()
    if status != HEALTH_UNKNOWN:
        w.write_enum(1, status)
    return w.take()


struct HealthService(Copyable, GrpcUnary, Movable):
    """In-memory ``grpc.health.v1.Health`` Check handler.

    Holds a per-service status map; ``set_status`` registers / updates a
    service's serving status. An unregistered service name returns
    ``SERVICE_UNKNOWN``.
    """

    var statuses: Dict[String, Int]
    var history: Dict[String, List[Int]]
    """Per-service ordered status-transition log. Every ``set_status``
    appends here so :class:`HealthWatchHandler` can replay the current
    status plus each subsequent change as a Watch stream."""

    def __init__(out self):
        self.statuses = Dict[String, Int]()
        self.history = Dict[String, List[Int]]()

    def set_status(mut self, service: String, status: Int) raises:
        """Register / update ``service``'s serving status. Use the
        empty name ``""`` for overall server health. Each call records a
        transition in :attr:`history` for Watch."""
        self.statuses[service] = status
        if service in self.history:
            self.history[service].append(status)
        else:
            var seq = List[Int]()
            seq.append(status)
            self.history[service] = seq^

    def status_of(self, service: String) raises -> Int:
        """Current serving status for ``service`` (SERVICE_UNKNOWN if
        never registered)."""
        if service in self.statuses:
            return self.statuses[service]
        return HEALTH_SERVICE_UNKNOWN

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        var service = decode_health_request(request_bytes)
        return GrpcUnaryReply.ok(
            encode_health_response(self.status_of(service))
        )


struct HealthWatchHandler(Copyable, GrpcServerStreaming, Movable):
    """The streaming ``grpc.health.v1.Health/Watch`` RPC.

    Watch is a server-streaming RPC: the client sends one
    ``HealthCheckRequest`` and receives a ``HealthCheckResponse`` for the
    current status plus one for every subsequent status change. This
    handler replays the recorded transition log (:attr:`HealthService.
    history`) as the response stream, framing each transition as its own
    DATA frame over the incremental H2 path.

    ponytail: the stream terminates after replaying the recorded
    transitions rather than staying open forever pushing live changes --
    an unbounded live Watch needs a shared cross-connection notify
    channel + an async chunk source. Replaying the transition log gives
    real status-change delivery within one buffered snapshot; the
    upgrade path is a poll/notify AsyncChunkSource.
    """

    var health: HealthService

    def __init__(out self, var health: HealthService):
        self.health = health^

    def __init__(out self, *, copy: Self):
        self.health = copy.health.copy()

    def copy(self) -> Self:
        return Self(copy=self)

    def serve_server_streaming(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcServerStreamReply:
        var service = decode_health_request(request_bytes)
        var msgs = List[List[UInt8]]()
        if service in self.health.history:
            var seq = self.health.history[service].copy()
            for i in range(len(seq)):
                msgs.append(encode_health_response(seq[i]))
        else:
            msgs.append(encode_health_response(HEALTH_SERVICE_UNKNOWN))
        return GrpcServerStreamReply.ok(msgs^)
