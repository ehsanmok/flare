"""Generic middleware library for .

The ``Handler`` trait is already a perfectly good middleware
abstraction: a middleware is a handler that wraps another handler.
This module bundles the middlewares every flare app eventually
needs:

- ``Logger[Inner]`` — log method / url / status / latency.
- ``RequestId[Inner]`` — attach an opaque request id (read on
  inbound, echo on outbound).
- ``Compress[Inner]`` — content-encoding negotiation
  (``Accept-Encoding`` q-values per RFC 9110 paragraph 12.5.3),
  encoding the response body in gzip or brotli.
- ``CatchPanic[Inner]`` — turn any ``raise`` from the inner
  handler into a sanitised 500 response so the connection is not
  torn down (the ``HttpServer`` already does this; ``CatchPanic``
  is for inner-only middleware stacks where the server isn't
  reached).

Each middleware is generic over its inner ``Handler`` so the chain
stays monomorphised — no virtual dispatch, no allocation per
request.
"""

from std.ffi import OwnedDLHandle, c_int
from std.os import getenv
from std.time import perf_counter_ns

from .encoding import (
    Encoding,
    compress_brotli,
    compress_gzip,
)
from .handler import Handler
from .request import Request
from .response import Response


# ── Logger ─────────────────────────────────────────────────────────────────


struct Logger[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Log method, url, status, and latency around the inner handler.

    Output goes to stdout via ``print``. The format is intentionally
    machine-grep-friendly so you can pipe it through ``jq`` /
    ``awk`` without a structured-logging dep.
    """

    var inner: Self.Inner
    """The wrapped handler."""

    var prefix: String
    """Prefix prepended to every log line; defaults to ``"[flare]"``."""

    def __init__(out self):
        self.inner = Self.Inner()
        self.prefix = "[flare]"

    def __init__(out self, var inner: Self.Inner, prefix: String = "[flare]"):
        self.inner = inner^
        self.prefix = prefix

    def serve(self, req: Request) raises -> Response:
        var start = perf_counter_ns()
        var resp: Response
        try:
            resp = self.inner.serve(req)
        except e:
            var latency_ms = (perf_counter_ns() - start) // 1_000_000
            var msg = String(e)
            print(
                self.prefix,
                req.method,
                req.url,
                "raised",
                msg,
                String(latency_ms) + "ms",
            )
            raise Error(msg)
        var latency_ms = (perf_counter_ns() - start) // 1_000_000
        print(
            self.prefix,
            req.method,
            req.url,
            String(resp.status),
            String(latency_ms) + "ms",
        )
        return resp^


# ── RequestId ──────────────────────────────────────────────────────────────


struct RequestId[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Echo the inbound ``X-Request-Id`` header back on the response.

    If absent on the inbound side, a deterministic id derived from
    ``perf_counter_ns`` is generated. Useful for request tracing
    when paired with the upstream gateway / load balancer.
    """

    var inner: Self.Inner

    def __init__(out self):
        self.inner = Self.Inner()

    def __init__(out self, var inner: Self.Inner):
        self.inner = inner^

    def serve(self, req: Request) raises -> Response:
        var id = req.headers.get("x-request-id")
        if id.byte_length() == 0:
            id = String("req-") + String(perf_counter_ns())
        var resp = self.inner.serve(req)
        resp.headers.set("X-Request-Id", id)
        return resp^


# ── Compress ───────────────────────────────────────────────────────────────


struct _AcceptEncodingPick(Copyable, Defaultable, Movable):
    """Result of parsing an ``Accept-Encoding`` header."""

    var encoding: String
    """Selected encoding token: ``"gzip"``, ``"br"``, or ``"identity"``."""

    var quality: Int
    """Quality value of the chosen entry (out of 1000)."""

    def __init__(out self):
        self.encoding = "identity"
        self.quality = 1000


def _parse_q(value: String) -> Int:
    """Parse a ``q=`` value into a 0-1000 integer (3-decimal scaled).

    Accepts ``q=0``, ``q=0.5``, ``q=0.999``, ``q=1.0``. Out-of-range
    or malformed values fall back to 1000 (max).
    """
    var n = value.byte_length()
    if n == 0:
        return 1000
    var src = value.unsafe_ptr()
    var i = 0
    while i < n and (src[i] == 32 or src[i] == 9):
        i += 1
    if i >= n:
        return 1000
    if src[i] == 49:  # '1'
        return 1000
    if src[i] != 48:  # '0'
        return 1000
    i += 1
    if i >= n or src[i] != 46:  # '.'
        return 0
    i += 1
    var places = 0
    var q = 0
    while i < n and places < 3:
        var c = src[i]
        if c < 48 or c > 57:
            break
        q = q * 10 + (Int(c) - 48)
        places += 1
        i += 1
    while places < 3:
        q *= 10
        places += 1
    return q


def negotiate_encoding(accept: String, brotli_ok: Bool) -> _AcceptEncodingPick:
    """Pick the best ``Content-Encoding`` for an ``Accept-Encoding``.

    Walks every comma-separated entry, parses ``;q=<weight>`` per
    RFC 9110 paragraph 12.5.3, and returns the highest-q entry from
    {``br``, ``gzip``, ``identity``} that the client accepts. Ties
    break on brotli > gzip > identity (matches nginx default).

    Args:
        accept: Raw ``Accept-Encoding`` header value.
        brotli_ok: Whether brotli is linkable on this build.

    Returns:
        ``_AcceptEncodingPick`` with the chosen encoding (defaults
        to ``identity`` / q=1000 when the header is absent).
    """
    var pick = _AcceptEncodingPick()
    if accept.byte_length() == 0:
        return pick^
    var n = accept.byte_length()
    var src = accept.unsafe_ptr()
    var pos = 0
    var best_q = 0
    var best_enc = "identity"
    while pos < n:
        var end = n
        for i in range(pos, n):
            if src[i] == 44:  # ','
                end = i
                break
        var entry = String(unsafe_from_utf8=accept.as_bytes()[pos:end]).strip()
        pos = end + 1
        if entry.byte_length() == 0:
            continue
        # Split entry into name + params.
        var sc = entry.byte_length()
        var sp = entry.unsafe_ptr()
        var semi = sc
        for i in range(sc):
            if sp[i] == 59:  # ';'
                semi = i
                break
        var name = String(unsafe_from_utf8=entry.as_bytes()[:semi]).strip()
        var lower = String(capacity=name.byte_length() + 1)
        for i in range(name.byte_length()):
            var c = name.unsafe_ptr()[i]
            if c >= 65 and c <= 90:
                lower += chr(Int(c) + 32)
            else:
                lower += chr(Int(c))
        var q = 1000
        if semi < sc:
            var rest = String(unsafe_from_utf8=entry.as_bytes()[semi + 1 :])
            var pos_q = -1
            for i in range(rest.byte_length()):
                var c = rest.unsafe_ptr()[i]
                if c == 113 or c == 81:  # 'q' or 'Q'
                    if (
                        i + 1 < rest.byte_length()
                        and rest.unsafe_ptr()[i + 1] == 61
                    ):
                        pos_q = i + 2
                        break
            if pos_q >= 0:
                q = _parse_q(String(unsafe_from_utf8=rest.as_bytes()[pos_q:]))
        # Wildcard accepts anything; treat as "identity" if no specific match
        # has been found yet (we still prefer concrete entries).
        if lower == "*":
            if best_q == 0:
                best_q = q
                best_enc = "identity"
            continue
        if lower == "br" and brotli_ok:
            if q > best_q or (q == best_q and best_enc != "br"):
                best_q = q
                best_enc = "br"
        elif lower == "gzip":
            if q > best_q or (q == best_q and best_enc == "identity"):
                best_q = q
                best_enc = "gzip"
        elif lower == "identity":
            if q > best_q:
                best_q = q
                best_enc = "identity"
    if best_q == 0:
        # No acceptable encoding found.
        pick.encoding = "identity"
        pick.quality = 0
        return pick^
    pick.encoding = best_enc
    pick.quality = best_q
    return pick^


def _brotli_available() -> Bool:
    """Best-effort check that ``libflare_brotli.so`` is loadable.

    Probes the canonical install path under ``$CONDA_PREFIX/lib``
    and falls back to the bare-checkout ``build/`` directory.
    Pure-syscall (``access(2)``) — no Mojo OwnedDLHandle hot path,
    so it's safe to call once per request.
    """
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix == "":
        return _file_exists("build/libflare_brotli.so")
    var p1 = String("")
    p1 += prefix
    p1 += "/lib/libflare_brotli.so"
    return _file_exists(p1)


def _flare_fs_access(read lib: OwnedDLHandle, addr: Int) -> c_int:
    """Invoke ``flare_fs_access`` while ``lib`` is borrowed by the caller.

    Taking ``lib`` as ``read`` ties the dylib's lifetime to the caller's
    frame, so Mojo's ASAP destructor cannot drop the handle (and thus
    ``dlclose`` it) before the resolved function pointer is invoked.
    Without this, ``_file_exists`` segfaults inside the runtime call
    helper on macOS arm64 / Mojo nightly 1.0.0b1.dev2026042717: the
    function-local ``OwnedDLHandle`` is reclaimed after ``get_function``
    and the cached pointer dangles into unmapped memory by the time we
    call it.
    """
    var fn_access = lib.get_function[def(Int) thin abi("C") -> c_int](
        "flare_fs_access"
    )
    return fn_access(addr)


def _file_exists(path: String) -> Bool:
    """Return whether ``path`` exists.

    Routes through ``libflare_fs.so`` (``flare_fs_access``) so the
    middleware does not register conflicting ``access(2)`` external_call
    signatures with the stdlib.
    """
    try:
        var conda = getenv("CONDA_PREFIX")
        var lib_path = String("libflare_fs.so")
        if conda:
            lib_path = conda + "/lib/libflare_fs.so"
        var lib = OwnedDLHandle(lib_path)
        var n = path.byte_length()
        var c = List[UInt8](length=n + 1, fill=UInt8(0))
        var src = path.unsafe_ptr()
        for i in range(n):
            c[i] = src[i]
        var addr = Int(c.unsafe_ptr())
        var rc = Int(_flare_fs_access(lib, addr))
        _ = c^
        return rc == 0
    except:
        return False


struct Compress[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Negotiate ``Content-Encoding`` per RFC 9110 paragraph 12.5.3.

    Inspects the inbound ``Accept-Encoding`` header, picks the
    highest-q entry from {``br``, ``gzip``, ``identity``}, and
    encodes the inner response body accordingly. Sets
    ``Content-Encoding`` and ``Vary: Accept-Encoding`` on the
    response.

    Bodies smaller than ``min_size_bytes`` (default 1024) are passed
    through untouched — the per-request encoder overhead beats the
    transfer-time savings on small bodies.
    """

    var inner: Self.Inner
    var min_size_bytes: Int
    var brotli_quality: Int
    var gzip_level: Int

    def __init__(out self):
        self.inner = Self.Inner()
        self.min_size_bytes = 1024
        self.brotli_quality = 5
        self.gzip_level = 6

    def __init__(
        out self,
        var inner: Self.Inner,
        min_size_bytes: Int = 1024,
        brotli_quality: Int = 5,
        gzip_level: Int = 6,
    ):
        self.inner = inner^
        self.min_size_bytes = min_size_bytes
        self.brotli_quality = brotli_quality
        self.gzip_level = gzip_level

    def serve(self, req: Request) raises -> Response:
        var accept = req.headers.get("accept-encoding")
        var brotli_ok = _brotli_available()
        var pick = negotiate_encoding(accept, brotli_ok)
        var resp = self.inner.serve(req)
        if pick.quality == 0:
            return resp^
        if len(resp.body) < self.min_size_bytes:
            return resp^
        if resp.headers.contains("content-encoding"):
            # Already encoded upstream; don't double-compress.
            return resp^
        if pick.encoding == "br" and brotli_ok:
            var encoded = compress_brotli(
                Span[UInt8, _](resp.body), self.brotli_quality
            )
            resp.body = encoded^
            resp.headers.set("Content-Encoding", "br")
        elif pick.encoding == "gzip":
            var encoded = compress_gzip(
                Span[UInt8, _](resp.body), self.gzip_level
            )
            resp.body = encoded^
            resp.headers.set("Content-Encoding", "gzip")
        else:
            return resp^
        resp.headers.set("Content-Length", String(len(resp.body)))
        resp.headers.append("Vary", "Accept-Encoding")
        return resp^


# ── CatchPanic ─────────────────────────────────────────────────────────────


struct CatchPanic[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Convert any ``raise`` from the inner handler into a 500.

    Useful when stacking middleware below the server's own
    error-sanitisation layer (e.g. inside a router branch). The
    server's ``HttpServer.serve`` path already wraps the top-level
    handler this way; this is for inner stacks.
    """

    var inner: Self.Inner
    var body: String

    def __init__(out self):
        self.inner = Self.Inner()
        self.body = "Internal Server Error"

    def __init__(
        out self, var inner: Self.Inner, body: String = "Internal Server Error"
    ):
        self.inner = inner^
        self.body = body

    def serve(self, req: Request) raises -> Response:
        try:
            return self.inner.serve(req)
        except:
            var resp = Response(status=500)
            resp.body = List[UInt8](self.body.as_bytes())
            resp.headers.set("Content-Type", "text/plain; charset=utf-8")
            return resp^
