"""``writev(2)`` vectored-I/O primitive (Track B4).

Provides ``IoVecBuf`` — a typed wrapper around a heap-allocated
``struct iovec[]`` array — and the high-level ``writev_buf_all``
helper that loops over partial writes until every byte across
every vector has been sent.

Why this is a Track B subtrack
-------------------------------

flare's HTTP/1.1 response serializer today copies the status
line + every header + the body into a single contiguous
``List[UInt8]`` and calls ``send(2)`` once. The ``memcpy`` of
the body into that intermediate buffer is the dominant
allocation + copy cost on every response — for a 1 KiB body
that's a 1 KiB ``memcpy`` per request that doesn't actually
need to move bytes (the body is already in some other
``List[UInt8]`` owned by the handler).

``writev(2)`` lets the kernel scatter-gather a list of
``iovec`` cells (each a ``{ ptr, len }`` pair) into one TCP
segment without touching the body bytes from userspace. For
the same 1 KiB body case, the response serializer can pass:

* iovec[0] = status line bytes (≤ ~30 B)
* iovec[1] = header block bytes (~100-500 B)
* iovec[2] = body bytes (untouched, borrowed)

…and skip the ``memcpy``. On a workload where the body is
already a long-lived ``List[UInt8]`` (any handler that returns
a precomputed payload), this is a strict win.

This is the same approach hyper / actix-web / axum take at the
H1 layer: hyper's ``h1::role::Server::encode`` builds an
``EncodedBuf`` of multiple slices and passes them to
``Tokio``'s ``write_vectored`` (which is ``writev`` on
epoll/kqueue, ``WSASend`` on IOCP).

What this commit ships (only the primitive)
--------------------------------------------

* ``IoVecBuf(n)`` — allocates a heap region of
  ``n * sizeof(struct iovec)`` bytes (16 B per cell on every
  64-bit Linux / macOS target). Callers populate cells via
  ``set(i, ptr, len)``.
* ``IoVecBuf.size_for(n) -> Int`` — exposes the byte-count
  computation for callers that want to ``stack_allocation`` an
  iovec array themselves.
* ``writev_buf(fd, iov_base, iovcnt) -> Int`` — single
  ``writev(2)`` call with EINTR retry. Returns bytes written
  on success; raises on EAGAIN / EPIPE / etc. (matches
  ``TcpStream.write`` semantics).
* ``writev_buf_all(fd, iov_base, iovcnt, total_bytes)`` —
  loops over partial writes by advancing through the iovec
  list until every byte across every cell is written. Updates
  the iovec cells in-place (advances ``iov_base[i].iov_base``
  / shrinks ``iov_base[i].iov_len`` for cells that were
  partially written).

Wiring into the HTTP/1.1 response serializer is a follow-up
commit that bolts onto this primitive without changing the
response struct's hot-path layout. The primitive exists today
so the wiring change is mechanical.

iovec layout
------------

On every supported target (64-bit Linux + macOS), the C
``struct iovec`` is 16 bytes::

    struct iovec {
        void  *iov_base;  // 8 bytes
        size_t iov_len;   // 8 bytes
    };

This module models the array as a flat ``UnsafePointer[UInt8]``
buffer of ``n * 16`` bytes, with ``set(i, ptr, len)`` writing
the two 8-byte words at the right offset. Reading the buffer
back via ``writev(2)`` gets the layout the kernel expects.
"""

from std.ffi import c_int, c_size_t, get_errno, ErrNo
from std.memory import UnsafePointer, alloc

from ..net._libc import _writev, _strerror
from ..net.error import NetworkError, BrokenPipe, Timeout, ConnectionReset


comptime _IOVEC_BYTES: Int = 16
"""Size of a single C ``struct iovec`` cell on every 64-bit
target this commit supports (Linux + macOS / x86_64 + aarch64).
8 bytes for ``iov_base`` (a pointer) + 8 bytes for ``iov_len``
(a ``size_t``).
"""


# ── IoVecBuf ─────────────────────────────────────────────────────────────────


struct IoVecBuf(Movable):
    """A heap-allocated ``struct iovec[n]`` array.

    Owns the underlying buffer; frees on drop. Callers populate
    cells via ``set(i, ptr, len)``; the buffer's base pointer is
    exposed via ``base()`` for the ``writev(2)`` call.

    Fields:
        _buf: The owning heap pointer to the raw byte buffer
              that backs the iovec array.
        _n: Number of iovec cells the buffer holds. Bounded
            on construction; cells are NOT bounds-checked at
            ``set`` time for performance.

    Example:
        ```mojo
        var iov = IoVecBuf(3)
        iov.set(0, status_line_ptr, status_line_len)
        iov.set(1, headers_ptr, headers_len)
        iov.set(2, body_ptr, body_len)
        var n = writev_buf(fd, iov.base(), 3)
        ```
    """

    var _buf: UnsafePointer[UInt8, MutExternalOrigin]
    var _n: Int

    def __init__(out self, n: Int):
        """Construct a buffer holding ``n`` iovec cells.

        Args:
            n: Number of cells. Must be > 0.
        """
        debug_assert[assert_mode="safe"](
            n > 0, "IoVecBuf: n must be positive; got ", n
        )
        var bytes = n * _IOVEC_BYTES
        var raw = alloc[UInt8](bytes)
        # Zero-init so an unset cell behaves as { NULL, 0 } —
        # writev(2) treats { ptr, 0 } as "skip this cell".
        for i in range(bytes):
            (raw + i).init_pointee_copy(UInt8(0))
        self._buf = UnsafePointer[UInt8, MutExternalOrigin](
            unsafe_from_address=Int(raw)
        )
        self._n = n

    def __del__(deinit self):
        """Free the underlying buffer."""
        if Int(self._buf) != 0:
            self._buf.free()

    @staticmethod
    @always_inline
    def size_for(n: Int) -> Int:
        """Return the byte size of an iovec array of ``n`` cells.

        Useful for ``stack_allocation`` callers that want to
        avoid a heap allocation entirely::

            var raw = stack_allocation[IoVecBuf.size_for(3), UInt8]()
        """
        return n * _IOVEC_BYTES

    def base(self) -> UnsafePointer[UInt8, MutExternalOrigin]:
        """Return the buffer's base pointer (suitable as the
        ``iov`` arg to ``writev_buf``).
        """
        return self._buf

    def count(self) -> Int:
        """Return the number of cells in the buffer."""
        return self._n

    def set(mut self, i: Int, ptr: Int, n: Int):
        """Write the i'th iovec cell.

        Args:
            i: Cell index. Bounds-checked under ``-D ASSERT=safe``
               (the default). The check uses ``debug_assert`` rather
               than ``std.collections.check_bounds`` because
               ``check_bounds`` requires the call site to be
               ``@always_inline`` (it relies on
               ``call_location[inline_count=2]()``); the per-call
               cost of inlining ``set`` here would bloat every
               keep-alive serialiser site without a measurable win.
               See ``.cursor/rules/sanitizers-and-bounds-checking.mdc``
               §3 / §4 for the rationale.
            ptr: ``iov_base`` value (typically
                 ``Int(some_buffer.unsafe_ptr())``).
            n: ``iov_len`` value (number of bytes at ``ptr``).
        """
        debug_assert[assert_mode="safe"](
            i >= 0 and i < self._n,
            "IoVecBuf.set: index out of range; got ",
            i,
        )
        debug_assert[assert_mode="safe"](
            n >= 0, "IoVecBuf.set: iov_len must be non-negative; got ", n
        )
        debug_assert[assert_mode="safe"](
            n == 0 or ptr != 0,
            "IoVecBuf.set: iov_base must be non-NULL when iov_len > 0",
        )
        var off = i * _IOVEC_BYTES
        # Write the 8-byte iov_base pointer as a little-endian
        # Int. Mojo's UnsafePointer assignment + init_pointee_copy
        # writes one byte at a time, so we manually pack.
        var p = self._buf + off
        var ptr_u64 = UInt64(ptr)
        for k in range(8):
            (p + k).init_pointee_copy(
                UInt8(Int((ptr_u64 >> UInt64(k * 8)) & UInt64(0xFF)))
            )
        var len_u64 = UInt64(n)
        var q = self._buf + off + 8
        for k in range(8):
            (q + k).init_pointee_copy(
                UInt8(Int((len_u64 >> UInt64(k * 8)) & UInt64(0xFF)))
            )

    def cell_ptr(self, i: Int) -> Int:
        """Read back the i'th cell's ``iov_base``.

        Useful for tests + the ``writev_buf_all`` partial-write
        loop that needs to advance the ptr after a short write.
        Bounds-checked under ``-D ASSERT=safe``.
        """
        debug_assert[assert_mode="safe"](
            i >= 0 and i < self._n,
            "IoVecBuf.cell_ptr: index out of range; got ",
            i,
        )
        var off = i * _IOVEC_BYTES
        var p = self._buf + off
        var v = UInt64(0)
        for k in range(8):
            v = v | (UInt64(Int(p[k])) << UInt64(k * 8))
        return Int(v)

    def cell_len(self, i: Int) -> Int:
        """Read back the i'th cell's ``iov_len``.

        Bounds-checked under ``-D ASSERT=safe``.
        """
        debug_assert[assert_mode="safe"](
            i >= 0 and i < self._n,
            "IoVecBuf.cell_len: index out of range; got ",
            i,
        )
        var off = i * _IOVEC_BYTES
        var q = self._buf + off + 8
        var v = UInt64(0)
        for k in range(8):
            v = v | (UInt64(Int(q[k])) << UInt64(k * 8))
        return Int(v)


# ── writev wrappers ──────────────────────────────────────────────────────────


def writev_buf(
    fd: Int, iov_base: UnsafePointer[UInt8, _], iovcnt: Int
) raises -> Int:
    """Single ``writev(2)`` call with EINTR retry.

    Returns the number of bytes the kernel accepted across all
    iovec cells (may be less than the total — the caller is
    responsible for any partial-write loop; use
    ``writev_buf_all`` for the looped variant).

    Args:
        fd: Open socket / file descriptor.
        iov_base: Pointer to the iovec array (typically
                  ``IoVecBuf.base()``).
        iovcnt: Number of cells in the array.

    Returns:
        Bytes written on success.

    Raises:
        BrokenPipe: ``EPIPE`` from the kernel.
        ConnectionReset: ``ECONNRESET`` from the kernel.
        Timeout: ``EAGAIN`` / ``EWOULDBLOCK`` (matches
                 ``TcpStream.write`` semantics on a non-blocking
                 socket with a send timeout).
        NetworkError: For any other libc errno.
    """
    debug_assert[assert_mode="safe"](
        fd >= 0, "writev_buf: fd must be non-negative; got ", fd
    )
    debug_assert[assert_mode="safe"](
        iovcnt >= 0, "writev_buf: iovcnt must be non-negative; got ", iovcnt
    )
    debug_assert[assert_mode="safe"](
        iovcnt == 0 or Int(iov_base) != 0,
        "writev_buf: iov_base must be non-NULL when iovcnt > 0",
    )
    while True:
        var n = _writev(c_int(fd), iov_base, c_int(iovcnt))
        if n >= 0:
            return Int(n)
        var e = get_errno()
        if e == ErrNo.EINTR:
            continue
        if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
            raise Timeout("writev")
        if e == ErrNo.EPIPE:
            raise BrokenPipe(String("writev"), Int(e.value))
        if e == ErrNo.ECONNRESET:
            raise ConnectionReset(String("writev"), Int(e.value))
        raise NetworkError(_strerror(e.value) + " (writev)", Int(e.value))


def writev_buf_all(mut iov: IoVecBuf, fd: Int, total_bytes: Int) raises:
    """Write every byte across every cell, advancing through the
    iovec array on partial writes.

    Updates the cells in ``iov`` in place: a cell that was
    partially written has its ``iov_base`` advanced and its
    ``iov_len`` shrunk; a fully-written cell is zeroed
    (``{ NULL, 0 }``). The kernel ignores zero-length cells, so
    leaving them in the array is harmless.

    Args:
        iov: The iovec buffer; cells are mutated in place.
        fd: Open socket / file descriptor.
        total_bytes: Sum of ``iov_len`` across every cell at
                     entry. Used to terminate the loop without
                     re-summing the cells on every iteration.

    Raises:
        BrokenPipe / ConnectionReset / Timeout / NetworkError:
            Per ``writev_buf`` semantics.
    """
    var remaining = total_bytes
    var n = iov.count()
    var first = 0
    while remaining > 0:
        var sent = writev_buf(fd, iov.base() + first * _IOVEC_BYTES, n - first)
        if sent <= 0:
            return
        remaining -= sent
        # Advance through the iovec list, consuming `sent` bytes.
        var consumed = sent
        var i = first
        while consumed > 0 and i < n:
            var cell_len = iov.cell_len(i)
            if cell_len <= consumed:
                consumed -= cell_len
                # Zero the cell so a future iteration sees
                # { NULL, 0 } and the kernel treats it as a
                # no-op.
                iov.set(i, 0, 0)
                first = i + 1
                i += 1
            else:
                # Partial write within cell i: advance ptr,
                # shrink len.
                var cell_ptr = iov.cell_ptr(i)
                iov.set(i, cell_ptr + consumed, cell_len - consumed)
                consumed = 0
