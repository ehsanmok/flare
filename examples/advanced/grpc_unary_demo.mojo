"""GRPC unary server demo -- bytes-in / bytes-out over the H2 wire.

This example walks the gRPC unary server adapter end-to-end
without binding a port. It exercises:

* :mod:`flare.grpc.framing` -- the length-prefix-message (LPM)
  codec.
* :mod:`flare.grpc.metadata` -- the initial-metadata carrier.
* :mod:`flare.grpc.status` -- canonical RPC status codes.
* :mod:`flare.grpc.server` -- ``GrpcUnary`` handler trait +
  ``run_unary_call`` orchestrator that validates HTTP/2
  pseudo-headers, stitches LPM frames out of the request DATA
  payload, invokes the handler, and emits the response DATA +
  trailers shape an :class:`H2Connection` would put on the
  wire.

The demo runs two calls against a tiny "echo" handler:

* a healthy call (``application/grpc+proto``, ``te: trailers``,
  one 5-byte payload) and prints the resulting LPM-wrapped
  response bytes + the final ``GrpcStatus``.
* an error call: the handler returns ``RESOURCE_EXHAUSTED``;
  the adapter emits an empty response body and the trailers
  carry the status.

Sans-I/O contract: no socket, no H2Connection, no allocator
beyond the codec's own. The adapter is the same one the
HTTP/2 reactor wraps once the bytes reach the per-stream
handler.
"""

from std.collections import List
from std.memory import Span

from flare.grpc import (
    GRPC_STATUS_OK,
    GRPC_STATUS_RESOURCE_EXHAUSTED,
    GrpcCallContext,
    GrpcCallOutcome,
    GrpcMessage,
    GrpcMetadata,
    GrpcRequestHeaders,
    GrpcStatus,
    GrpcUnary,
    GrpcUnaryReply,
    decode_grpc_message,
    run_unary_call,
)


@fieldwise_init
struct EchoHandler(Copyable, GrpcUnary, Movable):
    """Tiny handler that echoes the request bytes back, or fails
    with the configured error status when ``fail`` is set.
    """

    var fail: Bool

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        if self.fail:
            return GrpcUnaryReply.err(
                GrpcStatus.err(
                    GRPC_STATUS_RESOURCE_EXHAUSTED, String("quota exhausted")
                )
            )
        var echoed = List[UInt8](capacity=len(request_bytes))
        for i in range(len(request_bytes)):
            echoed.append(request_bytes[i])
        return GrpcUnaryReply.ok(echoed^)


def _hex(bytes: List[UInt8]) -> String:
    var s = String(capacity=len(bytes) * 3)
    for i in range(len(bytes)):
        var b = Int(bytes[i])
        var hi = b // 16
        var lo = b % 16
        s += chr(48 + hi) if hi < 10 else chr(87 + hi)
        s += chr(48 + lo) if lo < 10 else chr(87 + lo)
        s += " "
    return s^


def _build_request_data() -> List[UInt8]:
    """Synthesize an LPM-framed request body: one uncompressed
    5-byte message ("hello") behind the standard gRPC length
    prefix (compression flag + 4-byte big-endian length).
    """
    var data = List[UInt8]()
    data.append(UInt8(0))  # compression flag = 0 (uncompressed)
    data.append(UInt8(0))  # length high byte 0
    data.append(UInt8(0))
    data.append(UInt8(0))
    data.append(UInt8(5))  # length = 5
    for b in String("hello").as_bytes():
        data.append(b)
    return data^


def _print_outcome(label: String, outcome: GrpcCallOutcome) raises:
    print("--", label)
    print(
        "  status code:",
        String(Int(outcome.status.code)),
        "(ok=" + String(outcome.status.is_ok()) + ")",
    )
    if not outcome.status.is_ok():
        print("  status msg :", outcome.status.message)
    print(
        "  response   :",
        String(len(outcome.response_data)) + " bytes",
        "[" + _hex(outcome.response_data) + "]",
    )
    if len(outcome.response_data) > 0:
        var decoded = decode_grpc_message(Span[UInt8, _](outcome.response_data))
        print(
            "  LPM decode :",
            "flag=" + String(Int(decoded.message.flag.raw)),
            "payload_len=" + String(len(decoded.message.payload)),
            "consumed=" + String(decoded.consumed),
        )


def main() raises:
    print("== gRPC unary server demo (sans-I/O round-trip) ==")
    print("")
    var request_data = _build_request_data()
    var initial_meta = GrpcMetadata()

    var ok_handler = EchoHandler(fail=False)
    var ok_outcome = run_unary_call[EchoHandler](
        ok_handler,
        GrpcRequestHeaders(
            method=String("POST"),
            path=String("/echo.EchoService/Echo"),
            content_type=String("application/grpc+proto"),
            te=String("trailers"),
            timeout=None,
            accept_encoding=None,
            encoding=None,
            initial_metadata=initial_meta.copy(),
        ),
        Span[UInt8, _](request_data),
    )
    _print_outcome(String("OK call"), ok_outcome)

    print("")
    var err_handler = EchoHandler(fail=True)
    var err_outcome = run_unary_call[EchoHandler](
        err_handler,
        GrpcRequestHeaders(
            method=String("POST"),
            path=String("/echo.EchoService/Echo"),
            content_type=String("application/grpc+proto"),
            te=String("trailers"),
            timeout=String("1S"),
            accept_encoding=None,
            encoding=None,
            initial_metadata=initial_meta^,
        ),
        Span[UInt8, _](request_data),
    )
    _print_outcome(String("ERROR call (RESOURCE_EXHAUSTED)"), err_outcome)
    print("")
    print("Both calls processed without binding a socket.")
