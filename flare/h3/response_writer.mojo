"""HTTP/3 response-stream writer -- sans-I/O byte emitter.

Symmetric to :mod:`flare.h3.request_reader`. Builds the bytes
the H3 server reactor hands to the QUIC stream abstraction for a
response on a request stream.

A complete H3 response is at most three concatenated wire
fragments:

  HEADERS frame (status pseudo-header + application headers,
                 QPACK-encoded)
  DATA frame    (zero or more, body bytes)
  HEADERS frame (optional trailers, QPACK-encoded)

The writer doesn't own the bytes -- it returns owned ``List[
UInt8]`` outputs that the caller stitches into one or more QUIC
stream sends. The reactor wrapper drives flow control, MTU
splits, and FIN; this module is purely the codec.

Public surface:

* :func:`encode_response_headers` -- build the HEADERS frame
  bytes for the initial response. Always emits ``:status`` first
  per RFC 9114 §4.3, then the supplied application headers
  verbatim. Lowercases header names on the way through to keep
  the output H3-conformant.
* :func:`encode_response_data` -- wrap a payload chunk in a
  DATA frame. The reactor calls this once per body chunk to
  preserve back-pressure.
* :func:`encode_response_trailers` -- build the trailing
  HEADERS frame.

Sans-I/O contract: the writer holds zero state; every entry
point is a pure function over its inputs. The reactor wrapper
keeps the per-stream cursor + FIN bit.

References:
- RFC 9114 §4 (HTTP Message Exchanges) + §7 (Frames).
- RFC 9204 (QPACK).
"""

from std.collections import List
from std.memory import Span

from flare.http.proto.ascii import ascii_lower
from flare.qpack import QpackHeader, encode_field_section

from .frame import H3_FRAME_TYPE_DATA, H3_FRAME_TYPE_HEADERS, encode_h3_frame


def encode_response_headers(
    status: Int,
    headers: List[QpackHeader],
    mut out: List[UInt8],
) raises:
    """Append the HEADERS-frame bytes for an HTTP/3 response to ``out``.

    Emits ``:status`` as the first field per RFC 9114 §4.3.2,
    then the supplied application headers (all names lowercased).
    The caller MUST NOT include ``:status`` in ``headers`` --
    the reader rejects field sections that emit pseudo-headers
    after a regular header (RFC 9114 §4.3 invariant), and this
    writer skips application-pseudoheader emission entirely.

    The caller owns the buffer and may reuse the same
    ``List[UInt8]`` across HEADERS + DATA + trailers so the
    underlying allocation amortises across the response. The
    encoder appends only; it never reads from or truncates the
    existing contents.
    """
    if status < 100 or status > 599:
        raise Error("h3 writer: invalid HTTP status " + String(status))
    var emit = List[QpackHeader]()
    emit.append(QpackHeader(":status", String(status)))
    for i in range(len(headers)):
        var name = ascii_lower(headers[i].name)
        if name == ":status" or (
            len(name.as_bytes()) > 0 and name.as_bytes()[0] == UInt8(ord(":"))
        ):
            raise Error(
                "h3 writer: pseudo-header '"
                + name
                + "' not allowed in application headers"
            )
        emit.append(QpackHeader(name^, String(headers[i].value)))
    var qpack_payload = List[UInt8]()
    encode_field_section(emit, qpack_payload)
    encode_h3_frame(H3_FRAME_TYPE_HEADERS, Span[UInt8, _](qpack_payload), out)


def encode_response_data(
    payload: Span[UInt8, _],
    mut out: List[UInt8],
) raises:
    """Append an HTTP/3 DATA frame wrapping ``payload`` to ``out``.

    The H3 server reactor calls this once per body chunk so
    flow-control back-pressure on the QUIC stream applies per
    chunk; emitting the entire body in one DATA frame is legal
    but loses the granularity. Empty payloads are legal and
    encode as a 2-byte frame (type=0x00 + length=0x00).

    The caller owns the buffer and may reuse the same
    ``List[UInt8]`` across HEADERS + DATA + trailers so the
    underlying allocation amortises across the response.
    """
    encode_h3_frame(H3_FRAME_TYPE_DATA, payload, out)


def encode_response_trailers(
    trailers: List[QpackHeader],
    mut out: List[UInt8],
) raises:
    """Append the trailing HEADERS-frame bytes to ``out``.

    Trailers MUST NOT include pseudo-headers; the writer rejects
    any field whose name starts with ``:``. The reactor sends
    this frame followed by FIN to close the response side of the
    request stream.

    The caller owns the buffer and may reuse the same
    ``List[UInt8]`` across HEADERS + DATA + trailers so the
    underlying allocation amortises across the response.
    """
    var emit = List[QpackHeader]()
    for i in range(len(trailers)):
        var name = ascii_lower(trailers[i].name)
        if len(name.as_bytes()) > 0 and name.as_bytes()[0] == UInt8(ord(":")):
            raise Error(
                "h3 writer: pseudo-header '"
                + name
                + "' not allowed in trailers"
            )
        emit.append(QpackHeader(name^, String(trailers[i].value)))
    var qpack_payload = List[UInt8]()
    encode_field_section(emit, qpack_payload)
    encode_h3_frame(H3_FRAME_TYPE_HEADERS, Span[UInt8, _](qpack_payload), out)
