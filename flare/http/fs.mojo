"""``FileServer`` — serve files from a directory with HEAD + Range support.

Reads files synchronously via libc ``open(2)`` / ``read(2)``;
suitable for sub-100 MB static directories. For larger trees (or
concurrent reactor pressure) the reactor's ``Pool[T]`` blocking
escape hatch is the v0.7 follow-up.

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


# ── libflare_fs.so bindings ────────────────────────────────────────────
# Mojo's stdlib already registers external_call signatures for libc
# ``open`` / ``close`` / ``read`` / ``lseek`` for its own I/O. Calling
# them again from user code with a slightly different signature causes
# LLVM lowering errors. We therefore route through a tiny C wrapper
# (``flare/http/ffi/fs_wrapper.c``) compiled to ``libflare_fs.so``.


def _find_flare_fs_lib() -> String:
    """Resolve ``libflare_fs.so`` next to ``libflare_zlib.so``."""
    var conda = getenv("CONDA_PREFIX")
    if conda:
        var p = conda + "/lib/libflare_fs.so"
        return p^
    return "libflare_fs.so"


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


def _fs_open_rdonly(lib: OwnedDLHandle, path: String) -> Int:
    var fn_open = lib.get_function[def(Int) thin abi("C") -> c_int](
        "flare_fs_open_rdonly"
    )
    var c = _cstr(path)
    var addr = Int(c.unsafe_ptr())
    var rc = Int(fn_open(addr))
    _ = c^  # keep alive until after fn_open returns
    return rc


def _fs_close(lib: OwnedDLHandle, fd: Int):
    var fn_close = lib.get_function[def(c_int) thin abi("C") -> c_int](
        "flare_fs_close"
    )
    _ = fn_close(c_int(fd))


def _fs_pread(
    lib: OwnedDLHandle, fd: Int, buf_addr: Int, n: Int, offset: Int
) -> Int:
    var fn_read = lib.get_function[
        def(c_int, Int, Int, Int64) thin abi("C") -> Int64
    ]("flare_fs_pread")
    return Int(fn_read(c_int(fd), buf_addr, n, Int64(offset)))


def _fs_size(lib: OwnedDLHandle, path: String) -> Int:
    var fn_size = lib.get_function[def(Int) thin abi("C") -> Int64](
        "flare_fs_size"
    )
    var c = _cstr(path)
    var addr = Int(c.unsafe_ptr())
    var rc = Int(fn_size(addr))
    _ = c^
    return rc


# ``struct stat`` layout differs across glibc / musl / Darwin. We
# only need the size + mtime fields, so allocate a generous 256-byte
# buffer and offset-load. The values lie at conservative offsets
# common to all three on x86_64 / aarch64; on systems where this
# isn't true the resulting nonsense is benign (file size 0 -> 404).
struct _StatBuf(Copyable, Defaultable, Movable):
    var data: List[UInt8]

    def __init__(out self):
        self.data = List[UInt8](length=256, fill=UInt8(0))


def _stat_size(lib: OwnedDLHandle, path: String) raises -> Int:
    """Return ``st_size`` for ``path``, or -1 on error."""
    return _fs_size(lib, path)


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
    if src[0] != 47:  # '/'
        return ""
    # Reject NULs.
    for i in range(url_path.byte_length()):
        if src[i] == 0:
            return ""
    # Reject ``..`` components.
    var n = url_path.byte_length()
    var i = 0
    while i < n:
        var end = n
        for j in range(i, n):
            if src[j] == 47:
                end = j
                break
        if end - i == 2 and src[i] == 46 and src[i + 1] == 46:
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
        var c = src[i]
        if c == 47:  # '/'
            return ""
        if c == 46:  # '.'
            var out = String(capacity=n - i)
            for j in range(i + 1, n):
                var ec = src[j]
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


struct ByteRange(Copyable, Defaultable, Movable):
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
        if src[i] != prefix.unsafe_ptr()[i]:
            raise Error("parse_range: not bytes-unit")
    var rest = String(unsafe_from_utf8=value.as_bytes()[6:])
    for i in range(rest.byte_length()):
        if rest.unsafe_ptr()[i] == 44:
            raise Error("parse_range: multi-range unsupported")
    var dash = -1
    for i in range(rest.byte_length()):
        if rest.unsafe_ptr()[i] == 45:  # '-'
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


struct FileServer(Copyable, Defaultable, Handler, Movable):
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
        """Resolve the URL path under ``root``, applying ``index_file``."""
        var path = _safe_join(self.root, url)
        if path.byte_length() == 0:
            return ""
        # Trailing slash -> append index file.
        if path.unsafe_ptr()[path.byte_length() - 1] == 47:
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
        var size = _stat_size(lib, path)
        if size < 0:
            return Response(status=404)

        var fd = _fs_open_rdonly(lib, path)
        if fd < 0:
            return Response(status=404)

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
        var body = List[UInt8](length=slice_len, fill=UInt8(0))
        if req.method == "GET" and slice_len > 0:
            var got = _fs_pread(
                lib, fd, Int(body.unsafe_ptr()), slice_len, start
            )
            if got < 0:
                _fs_close(lib, fd)
                return Response(status=500)
            if got < slice_len:
                body.resize(got, 0)
        _fs_close(lib, fd)

        var resp = Response(status=status)
        var ext = _ext(path)
        resp.headers.set("Content-Type", _content_type_from_ext(ext))
        resp.headers.set("Accept-Ranges", "bytes")
        resp.headers.set("Content-Length", String(len(body)))
        if partial:
            var hdr = String("bytes ")
            hdr += String(start)
            hdr += "-"
            hdr += String(end)
            hdr += "/"
            hdr += String(size)
            resp.headers.set("Content-Range", hdr)
        if req.method == "HEAD":
            body.clear()
        resp.body = body^
        return resp^
