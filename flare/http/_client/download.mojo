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


struct HttpDownload[R: Readable & Movable](Movable):
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
    var _buf: List[UInt8]
    var _pos: Int
    var _mode: Int
    var _cl_remaining: Int
    var _chunk_remaining: Int
    var _done: Bool

    def __init__(out self, var stream: Self.R) raises:
        """Read + parse the response head from ``stream`` (request already
        written) and set up incremental body framing."""
        self._stream = stream^
        self.status = 0
        self.reason = ""
        self.headers = HeaderMap()
        self._buf = List[UInt8]()
        self._pos = 0
        self._mode = _DL_MODE_CLOSE
        self._cl_remaining = -1
        self._chunk_remaining = -1
        self._done = False

        var scratch = List[UInt8](capacity=_READ_BUF_SIZE)
        scratch.resize(_READ_BUF_SIZE, 0)
        var raw = List[UInt8](capacity=4096)
        var hdr_end = -1
        while hdr_end < 0:
            var n = self._stream.read(scratch.unsafe_ptr(), len(scratch))
            if n == 0:
                if len(raw) == 0:
                    raise NetworkError(
                        "HTTP download: peer closed before reply"
                    )
                raise NetworkError("HTTP download: missing header terminator")
            for i in range(n):
                raw.append(scratch[i])
            hdr_end = _find_crlf2(raw)

        var header_bytes = List[UInt8](capacity=hdr_end)
        for i in range(hdr_end):
            header_bytes.append(raw[i])
        var lines = _split_lines(_bytes_to_str(header_bytes))
        if len(lines) == 0:
            raise NetworkError("HTTP download: empty response")
        var sl = _parse_status_line(lines[0])
        self.status = sl.code
        self.reason = sl.reason

        var content_length = -1
        var is_chunked = False
        for li in range(1, len(lines)):
            var ln = lines[li]
            var colon = ln.find(":")
            if colon < 0:
                continue
            var k = (
                String(String(unsafe_from_utf8=ln.as_bytes()[:colon]))
                .strip()
                .lower()
            )
            var v = String(
                String(unsafe_from_utf8=ln.as_bytes()[colon + 1 :])
            ).strip()
            self.headers.set(String(k), String(v))
            if k == "content-length":
                try:
                    content_length = Int(atol(v))
                except:
                    raise NetworkError("HTTP download: invalid Content-Length")
            elif k == "transfer-encoding":
                if v.lower() == "chunked":
                    is_chunked = True

        # Stash any body bytes already read past the header terminator.
        var body_start = hdr_end + 4
        for i in range(body_start, len(raw)):
            self._buf.append(raw[i])

        if is_chunked:
            self._mode = _DL_MODE_CHUNKED
            self._chunk_remaining = -1
        elif content_length >= 0:
            self._mode = _DL_MODE_CONTENT_LENGTH
            self._cl_remaining = content_length
            if content_length == 0:
                self._done = True
        else:
            self._mode = _DL_MODE_CLOSE

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
        if self._done or max_bytes <= 0:
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
        if self._chunk_remaining < 0:
            # Need a chunk-size line: ensure a CRLF is buffered.
            var crlf = self._find_crlf_from(self._pos)
            while crlf < 0:
                if not self._fill():
                    raise NetworkError("HTTP download: EOF in chunk size line")
                crlf = self._find_crlf_from(self._pos)
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
            var size = _parse_hex(String(String(size_str).strip()))
            if size == 0:
                # Final chunk: consume trailing CRLF(s) / trailers to EOS.
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
            # Consume the CRLF that terminates the chunk data.
            while len(self._buf) - self._pos < 2:
                if not self._fill():
                    break
            if len(self._buf) - self._pos >= 2:
                self._pos += 2
            self._chunk_remaining = -1
        return out^

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
    for i in range(s.byte_length()):
        var c = Int(s.unsafe_ptr()[i])
        var d: Int
        if c >= 48 and c <= 57:
            d = c - 48
        elif c >= 97 and c <= 102:
            d = c - 97 + 10
        elif c >= 65 and c <= 70:
            d = c - 65 + 10
        else:
            raise NetworkError("HTTP download: bad hex in chunk size")
        acc = acc * 16 + d
    return acc
