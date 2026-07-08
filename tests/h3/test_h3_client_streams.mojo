"""HTTP/3 client request writer + response reader codecs.

Two wire-compatibility round-trips that pin the client codecs
against the already-shipped server codecs (no QUIC, pure bytes):

1. client ``encode_request_*`` -> server ``H3RequestReader`` /
   ``feed_into``: the bytes the client emits for a request decode
   exactly into the pseudo-headers + body + trailers the server
   parses.
2. server ``encode_response_*`` -> client ``H3ResponseReader``:
   the bytes the server emits for a response assemble into the
   status + headers + body the client reader yields.

Also covers the control / QPACK uni-stream preambles
(``encode_client_control_stream`` decodes as a SETTINGS-first
control stream) and the response reader's protocol-error paths.
"""

from std.collections import List
from std.memory import Span
from std.testing import assert_equal, assert_false, assert_true

from flare.h3 import (
    H3RequestEventHandler,
    H3RequestReader,
    H3ResponseReader,
    H3_FRAME_TYPE_SETTINGS,
    H3_UNI_STREAM_CONTROL,
    decode_h3_frame,
    decode_h3_settings,
    encode_client_control_stream,
    encode_qpack_decoder_stream,
    encode_qpack_encoder_stream,
    encode_request_data,
    encode_request_headers,
    encode_request_trailers,
    encode_response_data,
    encode_response_headers,
    feed_into,
)
from flare.qpack import QpackHeader
from flare.quic.varint import decode_varint


# ── A collector implementing the server's request-event handler ────────


struct _Collector(H3RequestEventHandler):
    var method: String
    var scheme: String
    var authority: String
    var path: String
    var app_headers: List[QpackHeader]
    var body: List[UInt8]
    var trailers: List[QpackHeader]
    var error: String
    var n_headers: Int

    def __init__(out self):
        self.method = String("")
        self.scheme = String("")
        self.authority = String("")
        self.path = String("")
        self.app_headers = List[QpackHeader]()
        self.body = List[UInt8]()
        self.trailers = List[QpackHeader]()
        self.error = String("")
        self.n_headers = 0

    def on_headers(mut self, headers: List[QpackHeader]) raises:
        self.n_headers += 1
        for i in range(len(headers)):
            var n = headers[i].name
            if n == ":method":
                self.method = String(headers[i].value)
            elif n == ":scheme":
                self.scheme = String(headers[i].value)
            elif n == ":authority":
                self.authority = String(headers[i].value)
            elif n == ":path":
                self.path = String(headers[i].value)
            else:
                self.app_headers.append(headers[i].copy())

    def on_data(mut self, data: List[UInt8]) raises:
        for i in range(len(data)):
            self.body.append(data[i])

    def on_trailers(mut self, trailers: List[QpackHeader]) raises:
        for i in range(len(trailers)):
            self.trailers.append(trailers[i].copy())

    def on_unknown_frame(mut self, type_id: UInt64) raises:
        pass

    def on_protocol_error(mut self, message: String) raises:
        self.error = message


def _drain_request(buf: List[UInt8], mut col: _Collector) raises:
    var reader = H3RequestReader.new()
    var cursor = 0
    while cursor < len(buf):
        var view = Span[UInt8, _](buf)[cursor:]
        var consumed = feed_into(reader, view, col)
        if consumed == 0:
            break
        cursor += consumed


def test_request_roundtrip_into_server_reader() raises:
    """Client request bytes decode into the server's request
    reader: pseudo-headers, one app header, body, trailers."""
    var hdrs = List[QpackHeader]()
    hdrs.append(QpackHeader("user-agent", "flare-h3"))
    var wire = List[UInt8]()
    encode_request_headers(
        String("POST"),
        String("https"),
        String("example.com"),
        String("/submit"),
        hdrs,
        wire,
    )
    var body = List[UInt8]()
    for b in String("payload-bytes").as_bytes():
        body.append(b)
    encode_request_data(Span[UInt8, _](body), wire)
    var trl = List[QpackHeader]()
    trl.append(QpackHeader("x-checksum", "abc123"))
    encode_request_trailers(trl, wire)

    var col = _Collector()
    _drain_request(wire, col)

    assert_equal(col.error, String(""))
    assert_equal(col.method, String("POST"))
    assert_equal(col.scheme, String("https"))
    assert_equal(col.authority, String("example.com"))
    assert_equal(col.path, String("/submit"))
    assert_equal(len(col.app_headers), 1)
    assert_equal(col.app_headers[0].name, String("user-agent"))
    assert_equal(col.app_headers[0].value, String("flare-h3"))
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](col.body)),
        String("payload-bytes"),
    )
    assert_equal(len(col.trailers), 1)
    assert_equal(col.trailers[0].name, String("x-checksum"))


def test_get_request_no_body() raises:
    """A GET with no authority-less host still round-trips."""
    var hdrs = List[QpackHeader]()
    var wire = List[UInt8]()
    encode_request_headers(
        String("GET"),
        String("https"),
        String("localhost"),
        String("/"),
        hdrs,
        wire,
    )
    var col = _Collector()
    _drain_request(wire, col)
    assert_equal(col.error, String(""))
    assert_equal(col.method, String("GET"))
    assert_equal(col.path, String("/"))
    assert_equal(len(col.body), 0)
    assert_equal(col.n_headers, 1)


def test_response_roundtrip_into_client_reader() raises:
    """Server response bytes assemble in the client reader:
    status, header, body across two DATA chunks."""
    var hdrs = List[QpackHeader]()
    hdrs.append(QpackHeader("content-type", "text/plain"))
    var wire = List[UInt8]()
    encode_response_headers(200, hdrs, wire)
    var b1 = List[UInt8]()
    for b in String("hello ").as_bytes():
        b1.append(b)
    encode_response_data(Span[UInt8, _](b1), wire)
    var b2 = List[UInt8]()
    for b in String("world").as_bytes():
        b2.append(b)
    encode_response_data(Span[UInt8, _](b2), wire)

    # Feed the wire in two arbitrary splits to exercise the inbox
    # buffering across a frame boundary.
    var reader = H3ResponseReader.new()
    var split = len(wire) // 3
    reader.feed(Span[UInt8, _](wire)[:split])
    reader.feed(Span[UInt8, _](wire)[split:])
    reader.signal_fin()

    assert_true(reader.is_complete(), "response should be complete after fin")
    assert_false(reader.has_error())
    var resp = reader.take_response()
    assert_equal(resp.status, 200)
    assert_equal(len(resp.headers), 1)
    assert_equal(resp.headers[0].name, String("content-type"))
    assert_equal(resp.headers[0].value, String("text/plain"))
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](resp.body)),
        String("hello world"),
    )


def test_response_reader_rejects_control_frame() raises:
    """A SETTINGS frame on the response (request) stream is a hard
    protocol error per RFC 9114 §6.2."""
    var wire = List[UInt8]()
    var empty = List[UInt8]()
    from flare.h3 import encode_h3_frame

    encode_h3_frame(H3_FRAME_TYPE_SETTINGS, Span[UInt8, _](empty), wire)
    var reader = H3ResponseReader.new()
    reader.feed(Span[UInt8, _](wire))
    assert_true(reader.has_error(), "SETTINGS on request stream must error")


def test_control_stream_preamble_is_settings_first() raises:
    """The control preamble emits the 0x00 type byte then a
    SETTINGS frame as the mandatory first control-stream frame."""
    var wire = List[UInt8]()
    encode_client_control_stream(UInt64(1 << 16), wire)
    var tvar = decode_varint(Span[UInt8, _](wire))
    assert_equal(tvar.value, H3_UNI_STREAM_CONTROL)
    var frame = decode_h3_frame(Span[UInt8, _](wire)[tvar.consumed :])
    assert_equal(frame.frame_type.raw, H3_FRAME_TYPE_SETTINGS)
    var settings = decode_h3_settings(Span[UInt8, _](frame.payload))
    assert_true(len(settings) >= 1, "control SETTINGS must carry params")


def test_qpack_stream_preambles() raises:
    """The QPACK encoder/decoder uni-streams carry just their type
    byte (0x02 / 0x03) in static-only mode."""
    var enc = List[UInt8]()
    encode_qpack_encoder_stream(enc)
    assert_equal(len(enc), 1)
    assert_equal(Int(enc[0]), 0x02)
    var dec = List[UInt8]()
    encode_qpack_decoder_stream(dec)
    assert_equal(len(dec), 1)
    assert_equal(Int(dec[0]), 0x03)


def main() raises:
    test_request_roundtrip_into_server_reader()
    test_get_request_no_body()
    test_response_roundtrip_into_client_reader()
    test_response_reader_rejects_control_frame()
    test_control_stream_preamble_is_settings_first()
    test_qpack_stream_preambles()
    print("test_h3_client_streams: 6 passed")
