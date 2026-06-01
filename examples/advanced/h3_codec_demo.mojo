"""HTTP/3 codec demo -- byte-level request/response round-trip.

This example walks the HTTP/3 codec layer end-to-end without
opening a QUIC stream. It exercises:

* :mod:`flare.qpack` -- the RFC 9204 static-only field-section
  encoder + decoder.
* :mod:`flare.h3.frame` -- the RFC 9114 §7 frame codec
  (``encode_h3_frame`` + the ``H3_FRAME_TYPE_*`` tags).
* :mod:`flare.h3.request_reader` -- the sans-I/O state machine
  that turns request-stream bytes back into typed events
  (HEADERS / DATA / TRAILERS).
* :mod:`flare.h3.response_writer` -- the symmetric writer that
  serialises a status + headers + body + trailers into the
  wire bytes a QUIC stream send would carry.

The walk is::

    +----------+ encode_field_section / encode_h3_frame
    |  client  |--------------------------------------+
    +----------+                                      |
                                                      v
    +----------+ <--- feed() <--- H3RequestReader <-+ wire bytes
    | reader   |
    +----------+

then::

    +----------+ encode_response_{headers,data,trailers}
    |  server  |--------------------------------------+
    +----------+                                      |
                                                      v
    +----------+ <--- decode_h3_frame ----------------+ wire bytes
    | decoder  | -> decode_field_section
    +----------+

Sans-I/O contract: no QUIC, no UDP, no rustls, no socket calls.
Everything below the AEAD-sealed packet payload is fair game from
this entry point.
"""

from std.collections import List
from std.memory import Span

from flare.h3 import (
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    H3_REQUEST_EVENT_DATA,
    H3_REQUEST_EVENT_HEADERS,
    H3_REQUEST_EVENT_NEEDS_MORE,
    H3_REQUEST_EVENT_TRAILERS,
    H3RequestReader,
    decode_h3_frame,
    encode_h3_frame,
    encode_response_data,
    encode_response_headers,
    encode_response_trailers,
    feed,
)
from flare.quic import decode_varint
from flare.qpack import (
    QpackHeader,
    decode_field_section,
    encode_field_section,
)


def _event_name(kind: Int) -> String:
    if kind == H3_REQUEST_EVENT_HEADERS:
        return String("HEADERS")
    if kind == H3_REQUEST_EVENT_DATA:
        return String("DATA")
    if kind == H3_REQUEST_EVENT_TRAILERS:
        return String("TRAILERS")
    if kind == H3_REQUEST_EVENT_NEEDS_MORE:
        return String("NEEDS_MORE")
    return String("OTHER(" + String(kind) + ")")


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

    var headers_payload = encode_field_section(req_headers)
    var wire = encode_h3_frame(
        H3_FRAME_TYPE_HEADERS, Span[UInt8, _](headers_payload)
    )

    var body = List[UInt8]()
    for b in String("hello").as_bytes():
        body.append(b)
    var data_bytes = encode_h3_frame(H3_FRAME_TYPE_DATA, Span[UInt8, _](body))
    for b in data_bytes:
        wire.append(b)

    var trailers = List[QpackHeader]()
    trailers.append(QpackHeader("x-trailer", "ok"))
    var trailer_payload = encode_field_section(trailers)
    var trailer_bytes = encode_h3_frame(
        H3_FRAME_TYPE_HEADERS, Span[UInt8, _](trailer_payload)
    )
    for b in trailer_bytes:
        wire.append(b)
    return wire^


def _drain_reader(wire: List[UInt8]) raises:
    """Feed the wire buffer into the reader until the stream is
    fully consumed, printing each emitted event.
    """
    var reader = H3RequestReader.new()
    var offset = 0
    var loops = 0
    while offset < len(wire) and loops < 16:
        loops += 1
        var rest = Span[UInt8, _](wire)[offset:]
        var event = feed(reader, rest)
        if event.kind == H3_REQUEST_EVENT_HEADERS or (
            event.kind == H3_REQUEST_EVENT_TRAILERS
        ):
            print(
                "  ",
                _event_name(event.kind),
                "consumed=" + String(event.consumed),
                "fields=" + String(len(event.headers)),
            )
            for i in range(len(event.headers)):
                print(
                    "      ",
                    String(event.headers[i].name),
                    "=",
                    String(event.headers[i].value),
                )
        elif event.kind == H3_REQUEST_EVENT_DATA:
            print(
                "  ",
                _event_name(event.kind),
                "consumed=" + String(event.consumed),
                "bytes=" + String(len(event.data)),
            )
        else:
            print(
                "  ",
                _event_name(event.kind),
                "consumed=" + String(event.consumed),
            )
            if event.consumed == 0:
                break
        offset += event.consumed


def _build_response_bytes() raises -> List[UInt8]:
    """Build the wire bytes a server would emit for the response
    to the above request: status 200, JSON body, and one
    trailer.
    """
    var headers = List[QpackHeader]()
    headers.append(QpackHeader("content-type", "application/json"))
    headers.append(QpackHeader("cache-control", "no-store"))

    var wire = encode_response_headers(200, headers)

    var body = List[UInt8]()
    for b in String('{"ok": true}').as_bytes():
        body.append(b)
    var data_bytes = encode_response_data(Span[UInt8, _](body))
    for b in data_bytes:
        wire.append(b)

    var trailers = List[QpackHeader]()
    trailers.append(QpackHeader("x-runtime-ms", "3"))
    var trailer_bytes = encode_response_trailers(trailers)
    for b in trailer_bytes:
        wire.append(b)
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
        var frame = decode_h3_frame(rest)
        # decode_h3_frame does not advance the cursor on its own;
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
