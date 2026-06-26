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

The streaming ``Watch`` method is a separate server-streaming RPC and
is tracked with the rest of the streaming surface.
"""

from std.collections import Dict
from std.memory import Span

from .proto import ProtoReader, ProtoWriter, WIRE_LEN
from .server import GrpcCallContext, GrpcUnary, GrpcUnaryReply


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

    def __init__(out self):
        self.statuses = Dict[String, Int]()

    def set_status(mut self, service: String, status: Int):
        """Register / update ``service``'s serving status. Use the
        empty name ``""`` for overall server health."""
        self.statuses[service] = status

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        var service = decode_health_request(request_bytes)
        var status = HEALTH_SERVICE_UNKNOWN
        if service in self.statuses:
            status = self.statuses[service]
        return GrpcUnaryReply.ok(encode_health_response(status))
