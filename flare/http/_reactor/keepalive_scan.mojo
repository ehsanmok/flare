"""Sans-I/O byte-fast-path + keep-alive helpers for the reactor.

This module holds the pieces of the per-connection state machine
that do not touch the socket: the ``STATE_*`` integer constants,
the ``StepResult`` return shape, the monotonic-clock reader,
the case-insensitive byte-level matchers used by the response
serializer, and the ``Connection``-header / HTTP/1.0 close-policy
decisions consumed by the H1 hot path.

Splitting these helpers out of :mod:`flare.http._reactor.conn_handle`
keeps that module focused on the ``ConnHandle`` state machine
itself; the helpers here are pure functions over byte buffers and
parsed ``HeaderMap`` instances and can be tested independently of
``ConnHandle``.

References:
- RFC 9110 §6.6.1 (Date field), RFC 9112 §9 (persistent
  connections + ``Connection`` header).
- RFC 7540 §3.2 (h2c upgrade detection -- the helper here is a
  thin wrapper around :mod:`flare.http.proto.h2c_upgrade`).
"""

from std.collections import List
from std.ffi import c_int, external_call
from std.memory import memcpy, stack_allocation
from std.sys.info import CompilationTarget

from flare.http.headers import HeaderMap

# CLOCK_MONOTONIC clock id: 1 on Linux, 6 on Darwin/macOS (id 1 is
# undefined there, so clock_gettime would fail and the clock read 0).
comptime _CLOCK_MONOTONIC: c_int = c_int(
    6
) if CompilationTarget.is_macos() else c_int(1)
from flare.http.proto.h2c_upgrade import (
    detect_h2c_upgrade as _proto_detect_h2c_upgrade,
)


# ── State constants ───────────────────────────────────────────────────────────

comptime STATE_READING: Int = 0
"""Reading headers and body from the socket (non-blocking)."""

comptime STATE_WRITING: Int = 1
"""Writing the response back to the socket (non-blocking)."""

comptime STATE_CLOSING: Int = 2
"""Connection is shutting down; next event should finalize close."""


# ── h2c upgrade detection ─────────────────────────────────────────────


@always_inline
def _detect_h2c_upgrade_inline(headers: HeaderMap) -> Bool:
    """Thin wrapper around :func:`flare.http.proto.h2c_upgrade.detect_h2c_upgrade`.

    The neutral sans-I/O detector lives in
    :mod:`flare.http.proto.h2c_upgrade`; the canonical helper in
    :mod:`flare.http2.server` also delegates there. This wrapper
    keeps the local call site short (the `_inline` name signals
    "predicate over a parsed HeaderMap" at the per-conn dispatch
    point) and avoids pulling :mod:`flare.http2.server` into the
    reactor's import graph.
    """
    return _proto_detect_h2c_upgrade(headers)


# ── Step result ───────────────────────────────────────────────────────────────


struct StepResult(Copyable, ImplicitlyCopyable, Movable):
    """Outcome of one state-machine step.

    The reactor wrapper uses these fields to update its registration for
    the connection's fd (interest bits), decide whether the connection is
    finished, and arm / clear the idle timer.

    Fields:
        want_read: True if the fd should be watched for readability.
        want_write: True if the fd should be watched for writability.
        done: True if the connection is finished; caller should unregister
              the fd and close it.
        idle_timeout_ms: -1 = no change; 0 = clear any pending idle timer;
                        > 0 = arm a fresh idle timer for this many
                        milliseconds.
        h2c_upgrade: True when the connection has just finished writing
                     a ``101 Switching Protocols`` response and the unified
                     reactor must migrate this fd's conn-dict entry from
                     ``KIND_H1`` to ``KIND_H2`` (RFC 7540 §3.2). The
                     migration helper extracts the saved Request +
                     decoded ``HTTP2-Settings`` payload from the h1
                     ``ConnHandle`` and constructs an
                     :class:`H2ConnHandle` pre-seeded with the original
                     request as stream id 1.
    """

    var want_read: Bool
    var want_write: Bool
    var done: Bool
    var idle_timeout_ms: Int
    var h2c_upgrade: Bool

    def __init__(
        out self,
        want_read: Bool = False,
        want_write: Bool = False,
        done: Bool = False,
        idle_timeout_ms: Int = -1,
        h2c_upgrade: Bool = False,
    ):
        """Construct a StepResult.

        Args:
            want_read: Whether the caller should keep read interest on the fd.
            want_write: Whether the caller should add write interest.
            done: Whether the caller should unregister and close the fd.
            idle_timeout_ms: Idle-timer rearm instruction (-1 = unchanged,
                0 = clear, >0 = arm for this many ms).
            h2c_upgrade: True when the unified reactor should migrate
                this fd from ``KIND_H1`` to ``KIND_H2`` after the 101
                Switching Protocols response has been flushed.
        """
        self.want_read = want_read
        self.want_write = want_write
        self.done = done
        self.idle_timeout_ms = idle_timeout_ms
        self.h2c_upgrade = h2c_upgrade


# ── Monotonic clock + small ASCII helpers ─────────────────────────────────────


def _monotonic_ms() -> Int:
    """Return the monotonic clock in milliseconds.

    Uses ``clock_gettime(CLOCK_MONOTONIC, ...)`` with the per-OS clock
    id (1 on Linux, 6 on macOS; see ``_CLOCK_MONOTONIC``).
    """
    var buf = stack_allocation[16, UInt8]()
    for i in range(16):
        (buf + i).init_pointee_copy(UInt8(0))
    _ = external_call["clock_gettime", c_int](
        _CLOCK_MONOTONIC, buf.bitcast[NoneType]()
    )
    var sec: Int64 = 0
    var nsec: Int64 = 0
    for i in range(8):
        sec |= Int64(Int((buf + i).load())) << Int64(8 * i)
    for i in range(8):
        nsec |= Int64(Int((buf + 8 + i).load())) << Int64(8 * i)
    return Int(sec) * 1000 + Int(nsec) // 1_000_000


@always_inline
def _is_content_length(k: String) -> Bool:
    """Return True if ``k`` is ``Content-Length`` (ASCII case-insensitive).

    Hot path: called for every response header to decide whether
    ``_serialize_response`` should emit or skip. Avoids the lowercase
    allocation that ``_ascii_lower`` + string-compare would cost.
    """
    if k.byte_length() != 14:
        return False
    var p = k.unsafe_ptr()
    var target = "content-length"
    var t = target.unsafe_ptr()
    for i in range(14):
        var c = p[i]
        if c >= 65 and c <= 90:
            c = c + 32
        if c != t[i]:
            return False
    return True


@always_inline
def _is_date(k: String) -> Bool:
    """Return True if ``k`` is ``Date`` (ASCII case-insensitive).

    Hot path: called for every response header during serialise so
    that any caller-supplied ``Date`` is dropped in favour of the
    canonical IMF-fixdate emitted from the per-connection
    :class:`DateCache`. RFC 9110 §6.6.1 mandates a single ``Date``
    field-line; the cached form is always correct, the
    caller-supplied one might drift.
    """
    if k.byte_length() != 4:
        return False
    var p = k.unsafe_ptr()
    var target = "date"
    var t = target.unsafe_ptr()
    for i in range(4):
        var c = p[i]
        if c >= 65 and c <= 90:
            c = c + 32
        if c != t[i]:
            return False
    return True


@always_inline
def _connection_is_keepalive(s: String) -> Bool:
    """Hot-path byte fast-check for ``Connection: keep-alive``.

    Designed to short-circuit the per-request ``_ascii_lower`` +
    string-compare in the keep-alive policy decision. Matches the
    exact lowercase 10-byte sequence used by the overwhelming
    majority of HTTP/1.1 clients in 10 byte loads + 10 compares
    without any allocation.

    For non-matching values (uppercase, mixed-case, ``Keep-Alive``
    with capital K, header missing, etc.) callers fall back to
    the slow path (``_ascii_lower(s) == "keep-alive"``).

    Returns False on length mismatch or any byte mismatch.
    """
    if s.byte_length() != 10:
        return False
    var p = s.unsafe_ptr()
    return (
        p[0] == UInt8(ord("k"))
        and p[1] == UInt8(ord("e"))
        and p[2] == UInt8(ord("e"))
        and p[3] == UInt8(ord("p"))
        and p[4] == UInt8(ord("-"))
        and p[5] == UInt8(ord("a"))
        and p[6] == UInt8(ord("l"))
        and p[7] == UInt8(ord("i"))
        and p[8] == UInt8(ord("v"))
        and p[9] == UInt8(ord("e"))
    )


@always_inline
def _connection_is_close(s: String) -> Bool:
    """Hot-path byte fast-check for ``Connection: close``.

    Companion to :func:`_connection_is_keepalive`. Matches the exact
    lowercase bytes ``close`` in 5 byte loads, and as a small
    extension also matches the common mixed-case ``Close`` (capital
    C only). Anything else falls through to the slow ``_ascii_lower``
    path. Returns False on length mismatch.
    """
    if s.byte_length() != 5:
        return False
    var p = s.unsafe_ptr()
    var c0 = p[0]
    if c0 != UInt8(ord("c")) and c0 != UInt8(ord("C")):
        return False
    return (
        p[1] == UInt8(ord("l"))
        and p[2] == UInt8(ord("o"))
        and p[3] == UInt8(ord("s"))
        and p[4] == UInt8(ord("e"))
    )


@always_inline
def _is_connection(k: String) -> Bool:
    """Return True if ``k`` is ``Connection`` (ASCII case-insensitive)."""
    if k.byte_length() != 10:
        return False
    var p = k.unsafe_ptr()
    var target = "connection"
    var t = target.unsafe_ptr()
    for i in range(10):
        var c = p[i]
        if c >= 65 and c <= 90:
            c = c + 32
        if c != t[i]:
            return False
    return True


# ── Read buffer compaction ────────────────────────────────────────────────────


@always_inline
def _compact_read_buf_drop_prefix(
    mut read_buf: List[UInt8], drop_n: Int
) -> None:
    """Drop the first ``drop_n`` bytes of ``read_buf``, keeping the
    trailing bytes (typically: pipelined-next-request bytes that
    arrived in the same recv as the just-handled request).

    Hot path: called once per processed request from every reader
    entry point AND from the static fast path. Uses a single
    ``memcpy`` from the old buffer into a freshly-sized
    replacement, preserving the prior allocation pattern (still
    one List[UInt8] alloc per request) while collapsing the
    per-byte append loop the earlier implementation used.

    Pre-conditions enforced by the callers:
    * ``drop_n > 0`` -- if no bytes to drop, callers skip this
      helper.
    * ``drop_n <= len(read_buf)`` -- otherwise the math below
      under-flows.
    """
    var n = len(read_buf)
    if drop_n >= n:
        # Either exactly consumed (drop_n == n) or over-consumed
        # (defensive). Either way the buffer is empty after this.
        read_buf.clear()
        return
    var keep = n - drop_n
    # Non-overlapping memcpy from old buffer into a fresh
    # capacity-sized List. The old buffer's drop is implicit when
    # we move the new one into ``read_buf`` (the caller's previous
    # storage drops at scope-end). This matches the prior shape
    # (one List alloc per request, prior bytes freed after) but
    # replaces the O(N) per-byte append loop with a single memcpy.
    var leftover = List[UInt8](capacity=keep)
    leftover.resize(keep, UInt8(0))
    memcpy(
        dest=leftover.unsafe_ptr(),
        src=read_buf.unsafe_ptr() + drop_n,
        count=keep,
    )
    read_buf = leftover^


# ── HTTP/1.1 keep-alive policy ────────────────────────────────────────────────


@always_inline
def _compute_close_after(req_headers: HeaderMap, req_version: String) -> Bool:
    """Decide whether to close the connection after this request,
    based on RFC 9112 keep-alive policy.

    Hot path: called once per request from the read-side state-
    machine entry points. The byte-fast-paths for
    ``Connection: keep-alive`` and ``Connection: close`` short-
    circuit the per-request ``_ascii_lower`` allocation when the
    header value matches the lowercase wire form most HTTP/1.1
    clients send. Mixed-case + uncommon values fall through to
    the slow allocation path.

    Caller still needs to combine this with config.max_keepalive_-
    requests + config.keep_alive (those are per-server policy, not
    per-request).
    """
    # Imported lazily to keep this module's top-level import block
    # free of ``flare.http.server`` -- the helper only fires on the
    # mixed-case slow path so the deferred import never bites the
    # hot-path lowercase branch.
    from flare.http.server import _ascii_lower

    var conn_hdr = req_headers.get("connection")
    var is_http10 = req_version == "HTTP/1.0"
    if _connection_is_close(conn_hdr):
        return True
    if _connection_is_keepalive(conn_hdr):
        return False
    if conn_hdr.byte_length() == 0:
        # No Connection header. RFC 9112: HTTP/1.1 is keep-alive
        # by default; HTTP/1.0 is close by default.
        return is_http10
    # Slow path: lowercase + compare. Reachable on mixed-case
    # ``Keep-Alive`` etc.
    var lo = _ascii_lower(conn_hdr)
    if lo == "close":
        return True
    if is_http10 and lo != "keep-alive":
        return True
    return False


def _wants_close(data: List[UInt8], header_end: Int) -> Bool:
    """Scan the raw header block for HTTP/1.0 + ``Connection:`` signals
    that mean this connection should close after the response.

    Returns True when the request line declares HTTP/1.0 without a
    ``Connection: keep-alive`` override, or when any ``Connection:``
    header value equals ``close`` (case-insensitive).

    Operates directly on bytes so the static fast path doesn't need to
    construct a ``Request`` / ``HeaderMap``.
    """
    var n = header_end
    var version_is_10 = False
    # 1. Request line up to the first CRLF.
    var first_eol = -1
    for i in range(n):
        if data[i] == 10:  # LF
            first_eol = i
            break
    if first_eol < 0:
        first_eol = n
    # Look for "HTTP/1.0" on the request line.
    var http_needle = "HTTP/1.0"
    var hp = http_needle.unsafe_ptr()
    var hn = http_needle.byte_length()
    for i in range(first_eol - hn + 1):
        if i < 0:
            break
        var is_match = True
        for j in range(hn):
            if data[i + j] != hp[j]:
                is_match = False
                break
        if is_match:
            version_is_10 = True
            break
    # 2. Connection header. Case-insensitive name match, value compared
    # against "close" and "keep-alive" (lowercase).
    var needle = "connection:"
    var np = needle.unsafe_ptr()
    var nn = needle.byte_length()
    var conn_close = False
    var conn_keepalive = False
    var i = first_eol + 1
    while i < n - nn:
        var found = True
        for j in range(nn):
            var c = data[i + j]
            if c >= 65 and c <= 90:
                c = c + 32
            if c != np[j]:
                found = False
                break
        if found:
            var pos = i + nn
            while pos < n and (data[pos] == 32 or data[pos] == 9):
                pos += 1
            # Compare value until CR, LF, or end-of-header-block.
            var v_end = pos
            while v_end < n and data[v_end] != 13 and data[v_end] != 10:
                v_end += 1
            # Lowercase slice compare against "close" and "keep-alive".
            var val_len = v_end - pos
            if val_len == 5:
                var ck = True
                for j in range(5):
                    var c = data[pos + j]
                    if c >= 65 and c <= 90:
                        c = c + 32
                    if c != UInt8(ord("close"[j])):
                        ck = False
                        break
                if ck:
                    conn_close = True
            if val_len == 10:
                var ck2 = True
                for j in range(10):
                    var c = data[pos + j]
                    if c >= 65 and c <= 90:
                        c = c + 32
                    if c != UInt8(ord("keep-alive"[j])):
                        ck2 = False
                        break
                if ck2:
                    conn_keepalive = True
            break
        i += 1
    if conn_close:
        return True
    if version_is_10 and not conn_keepalive:
        return True
    return False
