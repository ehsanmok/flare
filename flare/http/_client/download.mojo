"""Streaming client download reader (headers-then-body-reader).

The buffered client readers (:func:`_read_http_response_tcp` /
``_framed``) materialize the whole response body into
``Response.body`` before returning. :class:`HttpDownload` instead parses
only the status line + headers up front and then hands the body back one
chunk at a time via :meth:`read_chunk`, so a multi-gigabyte download is
consumed in bounded memory.

Framing is decoded incrementally on the read side:

- ``Content-Length``: exactly N body bytes.
- ``Transfer-Encoding: chunked``: RFC 9112 sec 7.1 chunks decoded on the
  fly (size line -> data -> CRLF, terminated by the ``0`` chunk).
- neither (``Connection: close`` / HTTP/1.0): read until EOF.

Generic over any :trait:`flare.io.buf_reader.Readable` transport so the
cleartext (``TcpStream``) path shares the reader; the owning
:class:`HttpDownload` closes the transport on drop.
"""

from ..headers import HeaderMap
from ...io.buf_reader import Readable
from ...net import NetworkError

from .parse import (
    _READ_BUF_SIZE,
    _bytes_to_str,
    _find_crlf2,
    _parse_status_line,
    _split_lines,
)


comptime _DL_MODE_CONTENT_LENGTH: Int = 0
comptime _DL_MODE_CHUNKED: Int = 1
comptime _DL_MODE_CLOSE: Int = 2


struct HttpDownload[R: Readable](Movable):
    """Incremental HTTP/1.1 response body reader over a ``Readable``.

    Construct by moving a transport that has already had the request
    written to it; the constructor reads + parses the response head and
    leaves the reader positioned at the first body byte. Pull the body
    with :meth:`read_chunk` (empty list = end of stream).
    """

    var _stream: Self.R
    var status: Int
    var reason: String
    var headers: HeaderMap
    var trailers: HeaderMap
    var _buf: List[UInt8]
    var _pos: Int
    var _mode: Int
    var _cl_remaining: Int
    var _chunk_remaining: Int
    var _done: Bool
    var _need_chunk_crlf: Bool
    var _max_header_bytes: Int

    def __init__(
        out self,
        var stream: Self.R,
        method: String = "GET",
        max_header_bytes: Int = 65536,
        var initial: List[UInt8] = List[UInt8](),
    ) raises:
        """Read + parse the response head from ``stream`` (request already
        written) and set up incremental body framing."""
        self._stream = stream^
        self.status = 0
        self.reason = ""
        self.headers = HeaderMap()
        self.trailers = HeaderMap()
        self._buf = initial^
        self._pos = 0
        self._mode = _DL_MODE_CLOSE
        self._cl_remaining = -1
        self._chunk_remaining = -1
        self._done = False
        self._need_chunk_crlf = False
        self._max_header_bytes = max_header_bytes
        if max_header_bytes <= 0:
            raise Error("HTTP download: header limit must be positive")

        # Keep read-ahead in the same bounded buffer, including between 1xx
        # heads. Do not mistake an informational response for the final head.
        var total_head_bytes = 0
        while True:
            var hdr_end = _find_crlf2(self._buf)
            while hdr_end < 0:
                if len(self._buf) >= max_header_bytes:
                    raise NetworkError("HTTP download: response head too large")
                if not self._fill():
                    raise NetworkError(
                        "HTTP download: EOF before response head"
                    )
                hdr_end = _find_crlf2(self._buf)
            total_head_bytes += hdr_end + 4
            if total_head_bytes > max_header_bytes:
                raise NetworkError("HTTP download: response head too large")
            var head = List[UInt8]()
            for i in range(hdr_end):
                head.append(self._buf[i])
            self._pos = hdr_end + 4
            self._compact()
            self._parse_head(head)
            if self.status == 101:
                raise NetworkError(
                    "HTTP download: protocol upgrades are not supported"
                )
            if self.status >= 200:
                break
            self.headers = HeaderMap()

        # RFC 9110 sec 9.3.6: a 2xx to CONNECT has no body either -- the
        # connection becomes a tunnel. Without this arm such a response
        # carries neither Content-Length nor Transfer-Encoding, falls
        # through to _DL_MODE_CLOSE below, and the reader starts handing
        # back tunnel bytes as though they were a response body.
        var verb = method.upper()
        if (
            verb == "HEAD"
            or self.status == 204
            or self.status == 304
            or (verb == "CONNECT" and self.status >= 200 and self.status < 300)
        ):
            self._done = True
            self._buf = List[UInt8]()
            return

        var content_length = -1
        var lengths = self.headers.get_all("content-length")
        # Any repeat is refused, even when the values agree. RFC 9112
        # sec 6.3 allows a single value; the server side of this tree
        # refuses duplicates by default
        # (allow_multiple_content_length in flare.http.proto.h1_leniency,
        # whose docstring records that the canonical answer is 400 even
        # when the values match). One answer per repo: a client that
        # agrees with the origin about framing is worth more than one
        # extra accepted response.
        if len(lengths) > 1:
            raise NetworkError("HTTP download: duplicate Content-Length")
        for i in range(len(lengths)):
            content_length = _parse_decimal(lengths[i])
        var encodings = self.headers.get_all("transfer-encoding")
        if len(encodings) > 0:
            if len(encodings) != 1 or encodings[0].lower() != "chunked":
                raise NetworkError(
                    "HTTP download: unsupported Transfer-Encoding"
                )
            if content_length >= 0:
                raise NetworkError("HTTP download: ambiguous response framing")
            self._mode = _DL_MODE_CHUNKED
        elif content_length >= 0:
            self._mode = _DL_MODE_CONTENT_LENGTH
            self._cl_remaining = content_length
            self._done = content_length == 0
        else:
            self._mode = _DL_MODE_CLOSE

    def _parse_head(mut self, head: List[UInt8]) raises:
        var lines = _split_lines(_bytes_to_str(head))
        if len(lines) == 0:
            raise NetworkError("HTTP download: empty response")
        var sl = _parse_status_line(lines[0])
        self.status = sl.code
        self.reason = sl.reason
        if self.status < 100 or self.status > 599:
            raise NetworkError("HTTP download: invalid status code")

        for li in range(1, len(lines)):
            var ln = lines[li]
            var raw = ln.as_bytes()
            # RFC 9112 sec 5.2: a line starting with SP or HTAB is an
            # obs-fold continuation of the previous field. It is not a
            # field line, and it must not become one -- a folded
            # "X-Foo: bar\r\n evil: value" would otherwise appear
            # downstream as a genuine "evil" header, indistinguishable
            # from one the origin sent. The server side refuses obs-fold
            # by default (allow_obs_fold in flare.http.proto.h1_leniency)
            # and so does this reader.
            if len(raw) > 0 and (raw[0] == 32 or raw[0] == 9):
                raise NetworkError(
                    "HTTP download: obs-fold continuation line rejected"
                )
            var colon = ln.find(":")
            if colon <= 0:
                raise NetworkError("HTTP download: malformed response header")
            # RFC 9112 sec 5.1: no whitespace is allowed between the
            # field name and the colon. "Content-Length : 5" stripped to
            # "content-length" is the classic smuggling vector, named as
            # such by allow_whitespace_before_colon on the server side.
            if raw[colon - 1] == 32 or raw[colon - 1] == 9:
                raise NetworkError(
                    "HTTP download: whitespace before header colon"
                )
            var k = String(
                String(unsafe_from_utf8=ln.as_bytes()[:colon])
            ).lower()
            var v = String(
                String(unsafe_from_utf8=ln.as_bytes()[colon + 1 :])
            ).strip()
            self.headers.append(String(k), String(v))

    def _compact(mut self):
        """Drop consumed prefix so the buffer stays bounded."""
        if self._pos == 0:
            return
        var nb = List[UInt8](capacity=len(self._buf) - self._pos)
        for i in range(self._pos, len(self._buf)):
            nb.append(self._buf[i])
        self._buf = nb^
        self._pos = 0

    def _fill(mut self) raises -> Bool:
        """Read one socket chunk into the buffer. Returns False on EOF."""
        self._compact()
        var tmp = List[UInt8](capacity=_READ_BUF_SIZE)
        tmp.resize(_READ_BUF_SIZE, 0)
        var n = self._stream.read(tmp.unsafe_ptr(), _READ_BUF_SIZE)
        if n == 0:
            return False
        for i in range(n):
            self._buf.append(tmp[i])
        return True

    def _find_crlf_from(self, start: Int) -> Int:
        """Index of the CRLF at/after ``start`` in the buffer, or -1."""
        var i = start
        while i + 1 < len(self._buf):
            if self._buf[i] == 13 and self._buf[i + 1] == 10:
                return i
            i += 1
        return -1

    def _take(mut self, max_bytes: Int) -> List[UInt8]:
        """Move up to ``max_bytes`` buffered bytes out from the cursor."""
        var avail = len(self._buf) - self._pos
        var take = max_bytes if max_bytes < avail else avail
        var out = List[UInt8](capacity=take)
        for i in range(take):
            out.append(self._buf[self._pos + i])
        self._pos += take
        return out^

    def read_chunk(mut self, max_bytes: Int = 65536) raises -> List[UInt8]:
        """Return the next body bytes (<= ``max_bytes``); empty at EOS."""
        if max_bytes <= 0:
            raise Error("HTTP download: max_bytes must be positive")
        if self._done:
            return List[UInt8]()
        if self._mode == _DL_MODE_CONTENT_LENGTH:
            return self._read_content_length(max_bytes)
        if self._mode == _DL_MODE_CHUNKED:
            return self._read_chunked(max_bytes)
        return self._read_close(max_bytes)

    def _read_content_length(mut self, max_bytes: Int) raises -> List[UInt8]:
        if self._cl_remaining == 0:
            self._done = True
            return List[UInt8]()
        if self._pos >= len(self._buf):
            if not self._fill():
                raise NetworkError("HTTP download: EOF before Content-Length")
        var cap = (
            max_bytes if max_bytes < self._cl_remaining else self._cl_remaining
        )
        var out = self._take(cap)
        self._cl_remaining -= len(out)
        if self._cl_remaining == 0:
            self._done = True
        return out^

    def _read_close(mut self, max_bytes: Int) raises -> List[UInt8]:
        if self._pos >= len(self._buf):
            if not self._fill():
                self._done = True
                return List[UInt8]()
        return self._take(max_bytes)

    def _read_chunked(mut self, max_bytes: Int) raises -> List[UInt8]:
        # Validate a preceding chunk terminator on the NEXT pull, so a
        # server withholding framing cannot delay delivery of available data.
        if self._need_chunk_crlf:
            while len(self._buf) - self._pos < 2:
                if not self._fill():
                    raise NetworkError("HTTP download: EOF in chunk terminator")
            if self._buf[self._pos] != 13 or self._buf[self._pos + 1] != 10:
                raise NetworkError("HTTP download: invalid chunk terminator")
            self._pos += 2
            self._need_chunk_crlf = False
        if self._chunk_remaining < 0:
            # Need a chunk-size line: ensure a CRLF is buffered.
            var crlf = self._find_crlf_from(self._pos)
            while crlf < 0:
                if len(self._buf) - self._pos >= self._max_header_bytes:
                    raise NetworkError(
                        "HTTP download: chunk size line too large"
                    )
                if not self._fill():
                    raise NetworkError("HTTP download: EOF in chunk size line")
                crlf = self._find_crlf_from(self._pos)
            if crlf - self._pos > self._max_header_bytes:
                raise NetworkError("HTTP download: chunk size line too large")
            var line = String(
                unsafe_from_utf8=Span[UInt8, origin_of(self._buf)](self._buf)[
                    self._pos : crlf
                ]
            )
            self._pos = crlf + 2
            # Chunk extensions (";..."): size is the hex prefix.
            var semi = line.find(";")
            var size_str = line if semi < 0 else String(
                unsafe_from_utf8=line.as_bytes()[:semi]
            )
            # No strip(). Leading or trailing whitespace in a chunk-size
            # line is a request-smuggling primitive: " 3" and "3 " must
            # not both mean 3. _parse_hex rejects any byte outside
            # [0-9a-fA-F], which matches scan_chunked_end in
            # flare.http.proto.chunked -- the repo's other chunked
            # decoder -- and matches the strict chunk terminator this
            # layer enforces just above.
            var size = _parse_hex(String(size_str))
            if size == 0:
                self._read_trailers()
                self._done = True
                return List[UInt8]()
            self._chunk_remaining = size
        # Emit from the current chunk's data.
        if self._pos >= len(self._buf):
            if not self._fill():
                raise NetworkError("HTTP download: EOF in chunk data")
        var cap = (
            max_bytes if max_bytes
            < self._chunk_remaining else self._chunk_remaining
        )
        var out = self._take(cap)
        self._chunk_remaining -= len(out)
        if self._chunk_remaining == 0:
            self._need_chunk_crlf = True
            self._chunk_remaining = -1
        return out^

    def _read_trailers(mut self) raises:
        var size = 0
        while True:
            var crlf = self._find_crlf_from(self._pos)
            while crlf < 0:
                if size + len(self._buf) - self._pos >= self._max_header_bytes:
                    raise NetworkError("HTTP download: trailers too large")
                if not self._fill():
                    raise NetworkError("HTTP download: EOF in trailers")
                crlf = self._find_crlf_from(self._pos)
            size += crlf - self._pos + 2
            if size > self._max_header_bytes:
                raise NetworkError("HTTP download: trailers too large")
            var line = _bytes_to_str(
                List[UInt8](Span(self._buf)[self._pos : crlf])
            )
            self._pos = crlf + 2
            if line.byte_length() == 0:
                return
            var colon = line.find(":")
            if colon <= 0:
                raise NetworkError("HTTP download: malformed trailer")
            var key = String(unsafe_from_utf8=line.as_bytes()[:colon]).lower()
            if (
                key == "content-length"
                or key == "transfer-encoding"
                or key == "host"
            ):
                raise NetworkError("HTTP download: forbidden trailer")
            var value = String(
                String(unsafe_from_utf8=line.as_bytes()[colon + 1 :]).strip()
            )
            self.trailers.append(key, value)

    def read_all(mut self, max_bytes: Int = 65536) raises -> List[UInt8]:
        """Drain the whole body into one buffer (convenience for tests /
        small streams -- defeats the memory bound)."""
        var out = List[UInt8]()
        while True:
            var c = self.read_chunk(max_bytes)
            if len(c) == 0:
                break
            for i in range(len(c)):
                out.append(c[i])
        return out^

    def header(self, name: String) -> String:
        return self.headers.get(name.lower())


def _parse_hex(s: String) raises -> Int:
    """Parse a lowercase/uppercase hex string to an Int."""
    var acc = 0
    if s.byte_length() == 0:
        raise NetworkError("HTTP download: empty chunk size")
    for i in range(s.byte_length()):
        var c = Int(s.unsafe_ptr()[unsafe_offset=i])
        var d: Int
        if c >= 48 and c <= 57:
            d = c - 48
        elif c >= 97 and c <= 102:
            d = c - 97 + 10
        elif c >= 65 and c <= 70:
            d = c - 65 + 10
        else:
            raise NetworkError("HTTP download: bad hex in chunk size")
        if acc > (Int.MAX - d) // 16:
            raise NetworkError("HTTP download: chunk size overflow")
        acc = acc * 16 + d
    return acc


def _parse_decimal(s: String) raises -> Int:
    var acc = 0
    if s.byte_length() == 0:
        raise NetworkError("HTTP download: empty Content-Length")
    for byte in s.as_bytes():
        var digit = Int(byte) - 48
        if digit < 0 or digit > 9 or acc > (Int.MAX - digit) // 10:
            raise NetworkError("HTTP download: invalid Content-Length")
        acc = acc * 10 + digit
    return acc
