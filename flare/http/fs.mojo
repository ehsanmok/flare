"""``FileServer`` — serve files from a directory with HEAD + Range support.

Reads files synchronously via libc ``open(2)`` / ``read(2)``;
suitable for sub-100 MB static directories. For larger trees (or
concurrent reactor pressure) the reactor's ``Pool[T]`` blocking
escape hatch is the follow-up.

Features:

- ``GET`` and ``HEAD``.
- Single-range ``Range: bytes=<start>-<end>`` support, RFC 9110
  paragraph 14.2 / 14.4. Multi-range responses are out of scope —
  servers may reject them per spec.
- Path safety: rejects any URL whose normalised path escapes the
  base directory (``..`` components, absolute paths, NUL bytes).
- ``Content-Type`` from a small built-in extension table (covers
  the common web shapes: HTML/CSS/JS/JSON/PNG/JPG/SVG/WOFF/TXT).
- Sets ``Last-Modified`` from the file's mtime so caches /
  conditional GET (``If-Modified-Since``) work correctly.

The handler is a plain ``Handler`` so it composes with the rest of
flare's middleware. Configure via ``FileServer.new(root)``.
"""

from std.collections import Optional
from std.ffi import OwnedDLHandle, c_int
from std.os import getenv

from .handler import Handler
from .request import Request
from .response import Response
from ..utils.dylib import find_flare_lib, dl_sym


# ── libflare_fs.so bindings ────────────────────────────────────────────
# Mojo's stdlib already registers external_call signatures for libc
# ``open`` / ``close`` / ``read`` / ``lseek`` for its own I/O. Calling
# them again from user code with a slightly different signature causes
# LLVM lowering errors. We therefore route through a tiny C wrapper
# (``flare/http/ffi/fs_wrapper.c``) compiled to ``libflare_fs.so``.


def _find_flare_fs_lib() -> String:
    """Return the path to ``libflare_fs.so``.

    Thin wrapper over :func:`flare.utils.dylib.find_flare_lib`
    pinned to the ``"fs"`` shim name (the canonical resolver is
    :mod:`flare.utils.dylib`).
    """
    return find_flare_lib("fs")


def _cstr(path: String) -> List[UInt8]:
    """Build an explicitly NUL-terminated byte buffer for libc paths.

    Mojo ``String`` is *not* guaranteed NUL-terminated past
    ``byte_length()``, so passing ``unsafe_ptr()`` straight into
    libc routines that expect a C string can spill into adjacent
    heap memory.
    """
    var bytes = path.as_bytes()
    var n = len(bytes)
    var buf = List[UInt8](length=n + 1, fill=UInt8(0))
    for i in range(n):
        buf[i] = bytes[i]
    buf[n] = UInt8(0)
    return buf^


def _fs_close(lib: OwnedDLHandle, fd: Int) raises:
    var fn_close = dl_sym[def(c_int) thin abi("C") -> c_int](
        lib, "flare_fs_close"
    )
    _ = fn_close(c_int(fd))


def _fs_pread(
    lib: OwnedDLHandle, fd: Int, buf_addr: Int, n: Int, offset: Int
) raises -> Int:
    var fn_read = dl_sym[def(c_int, Int, Int, Int64) thin abi("C") -> Int64](
        lib, "flare_fs_pread"
    )
    return Int(fn_read(c_int(fd), buf_addr, n, Int64(offset)))


def _fs_open_regular(
    lib: OwnedDLHandle, path: String, root: String
) raises -> Tuple[Int, Int, Int]:
    """``(fd, size, mtime)`` for a regular file under ``root``; fd -1
    otherwise (missing, a directory, or a symlink that leaves root)."""
    var fn_open = dl_sym[def(Int, Int, Int, Int) thin abi("C") -> c_int](
        lib, "flare_fs_open_regular"
    )
    var cp = _cstr(path)
    var cr = _cstr(root)
    var out = List[Int64](length=2, fill=Int64(0))
    var fd = Int(
        fn_open(
            Int(cp.unsafe_ptr()),
            Int(cr.unsafe_ptr()),
            Int(out.unsafe_ptr()),
            Int(out.unsafe_ptr()) + 8,
        )
    )
    _ = cp^
    _ = cr^
    return (fd, Int(out[0]), Int(out[1]))


def _http_date(unix_secs: Int) -> String:
    from flare.runtime.date_cache import _format_imf_fixdate

    var buf = List[UInt8](length=29, fill=UInt8(0))
    _format_imf_fixdate(unix_secs, buf.unsafe_ptr())
    return String(unsafe_from_utf8=Span[UInt8, _](buf))


# ── Path safety + MIME ──────────────────────────────────────────────────


def _safe_join(root: String, url_path: String) -> String:
    """Combine ``root`` with the request URL path, rejecting traversal.

    Returns ``""`` when the request path is unsafe. Acceptable inputs:

    - URL paths starting with ``/``.
    - Components free of ``..`` and NUL bytes.

    The returned path is ``root`` + the (possibly empty) URL path
    with a leading ``/`` ensured.
    """
    if url_path.byte_length() == 0:
        return ""
    var src = url_path.unsafe_ptr()
    if src[unsafe_offset=0] != 47:  # '/'
        return ""
    # Reject NULs.
    for i in range(url_path.byte_length()):
        if src[unsafe_offset=i] == 0:
            return ""
    # Reject ``..`` components.
    var n = url_path.byte_length()
    var i = 0
    while i < n:
        var end = n
        for j in range(i, n):
            if src[unsafe_offset=j] == 47:
                end = j
                break
        if (
            end - i == 2
            and src[unsafe_offset=i] == 46
            and src[unsafe_offset=i + 1] == 46
        ):
            return ""
        i = end + 1
    var out = String("")
    out += root
    out += url_path
    return out^


def _ext(path: String) -> String:
    """Return the lowercase extension (without the dot), or ``""``."""
    var n = path.byte_length()
    var src = path.unsafe_ptr()
    var i = n - 1
    while i >= 0:
        var c = src[unsafe_offset=i]
        if c == 47:  # '/'
            return ""
        if c == 46:  # '.'
            var out = String(capacity_bytes=n - i)
            for j in range(i + 1, n):
                var ec = src[unsafe_offset=j]
                if ec >= 65 and ec <= 90:
                    out += chr(Int(ec) + 32)
                else:
                    out += chr(Int(ec))
            return out^
        i -= 1
    return ""


def _content_type_from_ext(ext: String) -> String:
    """Return the ``Content-Type`` for ``ext`` (lowercase, no dot)."""
    if ext == "html" or ext == "htm":
        return "text/html; charset=utf-8"
    if ext == "css":
        return "text/css; charset=utf-8"
    if ext == "js" or ext == "mjs":
        return "application/javascript"
    if ext == "json":
        return "application/json"
    if ext == "txt" or ext == "md":
        return "text/plain; charset=utf-8"
    if ext == "png":
        return "image/png"
    if ext == "jpg" or ext == "jpeg":
        return "image/jpeg"
    if ext == "gif":
        return "image/gif"
    if ext == "svg":
        return "image/svg+xml"
    if ext == "ico":
        return "image/x-icon"
    if ext == "woff":
        return "font/woff"
    if ext == "woff2":
        return "font/woff2"
    if ext == "wasm":
        return "application/wasm"
    if ext == "pdf":
        return "application/pdf"
    return "application/octet-stream"


# ── Range parsing ──────────────────────────────────────────────────────


struct ByteRange(Copyable, Defaultable):
    """One ``Range: bytes=start-end`` request.

    Fields are 0-indexed inclusive, matching RFC 9110 paragraph
    14.1.2's wire format. Negative ``start`` (suffix range) is
    resolved into an absolute ``[start, end]`` against the file
    size by ``parse_range``.
    """

    var start: Int
    var end: Int

    def __init__(out self):
        self.start = 0
        self.end = 0


def parse_range(value: String, file_size: Int) raises -> Optional[ByteRange]:
    """Parse a single-range ``Range`` header value.

    Returns ``None`` if the header is missing/blank. Returns
    ``Some(ByteRange{start, end})`` on success. Raises ``Error`` on:

    - Multi-range requests (``,``-separated).
    - Out-of-range / negative-end / inverted ranges.
    - Non-``bytes=`` units.
    """
    if value.byte_length() == 0:
        return Optional[ByteRange]()
    var src = value.unsafe_ptr()
    var n = value.byte_length()
    var prefix = "bytes="
    if n < 6:
        raise Error("parse_range: invalid header")
    for i in range(6):
        if src[unsafe_offset=i] != prefix.unsafe_ptr()[unsafe_offset=i]:
            raise Error("parse_range: not bytes-unit")
    var rest = String(unsafe_from_utf8=value.as_bytes()[6:])
    for i in range(rest.byte_length()):
        if rest.unsafe_ptr()[unsafe_offset=i] == 44:
            raise Error("parse_range: multi-range unsupported")
    var dash = -1
    for i in range(rest.byte_length()):
        if rest.unsafe_ptr()[unsafe_offset=i] == 45:  # '-'
            dash = i
            break
    if dash < 0:
        raise Error("parse_range: missing '-'")
    var start_s = String(unsafe_from_utf8=rest.as_bytes()[:dash])
    var end_s = String(unsafe_from_utf8=rest.as_bytes()[dash + 1 :])
    var start: Int
    var end: Int
    if start_s.byte_length() == 0:
        # Suffix range: -N -> last N bytes.
        var n_suffix = atol(end_s)
        if n_suffix <= 0:
            raise Error("parse_range: invalid suffix length")
        if n_suffix > file_size:
            n_suffix = file_size
        start = file_size - n_suffix
        end = file_size - 1
    else:
        start = atol(start_s)
        if end_s.byte_length() == 0:
            end = file_size - 1
        else:
            end = atol(end_s)
    if start < 0 or end < start or end >= file_size:
        raise Error("parse_range: out of bounds")
    var br = ByteRange()
    br.start = start
    br.end = end
    return Optional[ByteRange](br^)


# ── FileServer handler ─────────────────────────────────────────────────


struct FileServer(Copyable, Defaultable, Handler):
    """Serve files from ``root`` under the request URL path.

    Construction:
        ```mojo
        var fs = FileServer.new("./public")
        var srv = HttpServer.bind(addr)
        srv.serve(fs^, num_workers=4)
        ```

    Returns 404 for any path that escapes ``root``, doesn't exist,
    or is not a regular file. ``HEAD`` returns the response with an
    empty body. ``Range: bytes=...`` returns 206 with the requested
    slice; other methods return 405.
    """

    var root: String
    var index_file: String

    def __init__(out self):
        self.root = "."
        self.index_file = "index.html"

    @staticmethod
    def new(root: String, index_file: String = "index.html") -> FileServer:
        var fs = FileServer()
        fs.root = root
        fs.index_file = index_file
        return fs^

    def _resolve(self, url: String) -> String:
        """Resolve the URL path under ``root``, applying ``index_file``.

        The query and fragment are not part of the path: ``/app.js?v=3``
        used to look for a file literally named ``app.js?v=3``. An empty
        ``root`` would make every URL an absolute path, so it serves
        nothing.
        """
        if self.root.byte_length() == 0:
            return ""
        var cut = url.byte_length()
        var up = url.unsafe_ptr()
        for i in range(url.byte_length()):
            if up[unsafe_offset=i] == 63 or up[unsafe_offset=i] == 35:
                cut = i
                break
        var path = _safe_join(
            self.root, String(unsafe_from_utf8=url.as_bytes()[:cut])
        )
        if path.byte_length() == 0:
            return ""
        # Trailing slash -> append index file.
        if path.unsafe_ptr()[unsafe_offset=path.byte_length() - 1] == 47:
            return path + self.index_file
        return path^

    def serve(self, req: Request) raises -> Response:
        if req.method != "GET" and req.method != "HEAD":
            var resp = Response(status=405)
            resp.headers.set("Allow", "GET, HEAD")
            return resp^

        var path = self._resolve(req.url)
        if path.byte_length() == 0:
            return Response(status=404)

        var lib = OwnedDLHandle(_find_flare_fs_lib())
        # One open that also checks the file is regular and, after
        # resolving every symlink, still under root.
        var opened = _fs_open_regular(lib, path, self.root)
        var fd = opened[0]
        if fd < 0:
            return Response(status=404)
        var size = opened[1]
        var mtime = opened[2]

        # Range handling.
        var range_value = req.headers.get("range")
        var maybe_range: Optional[ByteRange]
        try:
            maybe_range = parse_range(range_value, size)
        except:
            _fs_close(lib, fd)
            var resp = Response(status=416)
            resp.headers.set("Content-Range", String("bytes */") + String(size))
            return resp^

        var start: Int = 0
        var end: Int = size - 1
        var status: Int = 200
        var partial = False
        if maybe_range:
            var br = maybe_range.value().copy()
            start = br.start
            end = br.end
            status = 206
            partial = True

        var slice_len = end - start + 1
        # HEAD needs the length, not the bytes: allocating (and zeroing)
        # the whole slice first made ``HEAD /big.iso`` cost its size in
        # memory.
        var body = List[UInt8]()
        var body_len = slice_len
        if req.method == "GET" and slice_len > 0:
            body = List[UInt8](length=slice_len, fill=UInt8(0))
            var got = _fs_pread(
                lib, fd, Int(body.unsafe_ptr()), slice_len, start
            )
            if got < 0:
                _fs_close(lib, fd)
                return Response(status=500)
            if got < slice_len:
                body.resize(got, 0)
            body_len = len(body)
        _fs_close(lib, fd)

        var resp = Response(status=status)
        var ext = _ext(path)
        resp.headers.set("Content-Type", _content_type_from_ext(ext))
        resp.headers.set("Accept-Ranges", "bytes")
        resp.headers.set("Content-Length", String(body_len))
        resp.headers.set("Last-Modified", _http_date(mtime))
        if partial:
            var hdr = String("bytes ")
            hdr += String(start)
            hdr += "-"
            hdr += String(end)
            hdr += "/"
            hdr += String(size)
            resp.headers.set("Content-Range", hdr)
        resp.body = body^
        return resp^
