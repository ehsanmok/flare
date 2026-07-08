"""HTTP/3 codec demo -- byte-level request/response round-trip.

This example walks the HTTP/3 codec layer end-to-end without
opening a QUIC stream. It exercises:

* :mod:`flare.qpack` -- the RFC 9204 static-only field-section
  encoder + decoder.
* :mod:`flare.http3.frame` -- the RFC 9114 §7 frame codec
  (``encode_http3_frame`` + the ``H3_FRAME_TYPE_*`` tags).
* :mod:`flare.http3.request_reader` -- the sans-I/O state machine
  that turns request-stream bytes back into typed callback
  dispatches on a caller-supplied
  :trait:`Http3RequestEventHandler` (``on_headers`` /
  ``on_data`` / ``on_trailers``).
* :mod:`flare.http3.response_writer` -- the symmetric writer that
  serialises a status + headers + body + trailers into the
  wire bytes a QUIC stream send would carry.

The walk is::

    +----------+ encode_field_section / encode_http3_frame
    |  client  |--------------------------------------+
    +----------+                                      |
                                                      v
    +----------+ <-- feed_into() <-- Http3RequestReader -+ wire bytes
    | reader   |                                         + handler
    +----------+

then::

    +----------+ encode_response_{headers,data,trailers}
    |  server  |--------------------------------------+
    +----------+                                      |
                                                      v
    +----------+ <--- decode_http3_frame ----------------+ wire bytes
    | decoder  | -> decode_field_section
    +----------+

Sans-I/O contract: no QUIC, no UDP, no rustls, no socket calls.
Everything below the AEAD-sealed packet payload is fair game from
this entry point.
"""

from std.collections import List
from std.memory import Span

from flare.http3 import (
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    Http3RequestEventHandler,
    Http3RequestReader,
    decode_http3_frame,
    encode_http3_frame,
    encode_response_data,
    encode_response_headers,
    encode_response_trailers,
    feed_into,
)
from flare.quic import decode_varint
from flare.qpack import (
    QpackHeader,
    decode_field_section,
    encode_field_section,
)


# Demo-only handler that prints each dispatched callback. A
# production handler would forward fields into an application
# request type and stream body bytes into the handler pipeline.
@fieldwise_init
struct _DemoHandler(Http3RequestEventHandler, Movable):
    def on_headers(mut self, headers: List[QpackHeader]) raises:
        print(
            "   HEADERS",
            "fields=" + String(len(headers)),
        )
        for i in range(len(headers)):
            print(
                "      ",
                String(headers[i].name),
                "=",
                String(headers[i].value),
            )

    def on_data(mut self, data: List[UInt8]) raises:
        print(
            "   DATA",
            "bytes=" + String(len(data)),
        )

    def on_trailers(mut self, trailers: List[QpackHeader]) raises:
        print(
            "   TRAILERS",
            "fields=" + String(len(trailers)),
        )
        for i in range(len(trailers)):
            print(
                "      ",
                String(trailers[i].name),
                "=",
                String(trailers[i].value),
            )

    def on_unknown_frame(mut self, type_id: UInt64) raises:
        print("   UNKNOWN_FRAME type=" + String(Int(type_id)))

    def on_protocol_error(mut self, message: String) raises:
        print("   PROTOCOL_ERROR", message)


def _build_request_bytes() raises -> List[UInt8]:
    """Build the wire bytes a client would send for
    ``GET /index.html`` with a 5-byte body and one trailer.
    """
    var req_headers = List[QpackHeader]()
    req_headers.append(QpackHeader(":method", "GET"))
    req_headers.append(QpackHeader(":scheme", "https"))
    req_headers.append(QpackHeader(":authority", "example.test"))
    req_headers.append(QpackHeader(":path", "/index.html"))
    req_headers.append(QpackHeader("user-agent", "flare-h3-demo/0"))

    var headers_payload = List[UInt8]()
    encode_field_section(req_headers, headers_payload)
    var wire = List[UInt8]()
    encode_http3_frame(
        H3_FRAME_TYPE_HEADERS, Span[UInt8, _](headers_payload), wire
    )

    var body = List[UInt8]()
    for b in String("hello").as_bytes():
        body.append(b)
    encode_http3_frame(H3_FRAME_TYPE_DATA, Span[UInt8, _](body), wire)

    var trailers = List[QpackHeader]()
    trailers.append(QpackHeader("x-trailer", "ok"))
    var trailer_payload = List[UInt8]()
    encode_field_section(trailers, trailer_payload)
    encode_http3_frame(
        H3_FRAME_TYPE_HEADERS, Span[UInt8, _](trailer_payload), wire
    )
    return wire^


def _drain_reader(wire: List[UInt8]) raises:
    """Feed the wire buffer into the reader until the stream is
    fully consumed; the demo handler prints each callback as it
    fires.
    """
    var reader = Http3RequestReader.new()
    var handler = _DemoHandler()
    var offset = 0
    var loops = 0
    while offset < len(wire) and loops < 16:
        loops += 1
        var rest = Span[UInt8, _](wire)[offset:]
        var consumed = feed_into(reader, rest, handler)
        # consumed == 0 means NEEDS_MORE / DONE: bail out so the
        # demo doesn't spin forever on a malformed slice.
        if consumed == 0:
            print("   NEEDS_MORE (or DONE)")
            break
        offset += consumed


def _build_response_bytes() raises -> List[UInt8]:
    """Build the wire bytes a server would emit for the response
    to the above request: status 200, JSON body, and one
    trailer.
    """
    var headers = List[QpackHeader]()
    headers.append(QpackHeader("content-type", "application/json"))
    headers.append(QpackHeader("cache-control", "no-store"))

    var wire = List[UInt8]()
    encode_response_headers(200, headers, wire)

    var body = List[UInt8]()
    for b in String('{"ok": true}').as_bytes():
        body.append(b)
    encode_response_data(Span[UInt8, _](body), wire)

    var trailers = List[QpackHeader]()
    trailers.append(QpackHeader("x-runtime-ms", "3"))
    encode_response_trailers(trailers, wire)
    return wire^


def _decode_response_bytes(wire: List[UInt8]) raises:
    """Walk the response wire bytes by hand: decode each H3 frame,
    QPACK-decode any HEADERS field sections, and print the
    pieces. The H3 server reactor would do this on the response
    receiver side.
    """
    var offset = 0
    var loops = 0
    while offset < len(wire) and loops < 16:
        loops += 1
        var rest = Span[UInt8, _](wire)[offset:]
        var frame = decode_http3_frame(rest)
        # decode_http3_frame does not advance the cursor on its own;
        # re-walk the (type, length) varints to compute consumed.
        var type_var = decode_varint(rest)
        var len_var = decode_varint(rest[type_var.consumed :])
        var consumed = type_var.consumed + len_var.consumed + Int(len_var.value)
        offset += consumed
        if frame.frame_type.raw == H3_FRAME_TYPE_HEADERS:
            var decoded = decode_field_section(Span[UInt8, _](frame.payload))
            print(
                "   HEADERS",
                "frame_len=" + String(len(frame.payload)),
                "fields=" + String(len(decoded)),
            )
            for i in range(len(decoded)):
                print(
                    "      ",
                    String(decoded[i].name),
                    "=",
                    String(decoded[i].value),
                )
        elif frame.frame_type.raw == H3_FRAME_TYPE_DATA:
            print(
                "   DATA",
                "frame_len=" + String(len(frame.payload)),
            )
        else:
            print(
                "   OTHER(type=" + String(Int(frame.frame_type.raw)) + ")",
                "frame_len=" + String(len(frame.payload)),
            )


def main() raises:
    print("== HTTP/3 codec demo (sans-I/O round-trip) ==")
    print("")
    print("Request side (client encodes, server reader decodes):")
    var req_wire = _build_request_bytes()
    print(
        "  encoded request stream:",
        String(len(req_wire)) + " bytes",
    )
    _drain_reader(req_wire)

    print("")
    print("Response side (server writer encodes, client decodes):")
    var resp_wire = _build_response_bytes()
    print(
        "  encoded response stream:",
        String(len(resp_wire)) + " bytes",
    )
    _decode_response_bytes(resp_wire)

    print("")
    print("All frames byte-clean; no socket touched.")
