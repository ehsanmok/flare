"""Streaming-response plumbing for the normal Handler path (K1).

The reactor serves a buffered ``Response`` by serialising its whole
``body`` up front. To stream an open-ended body (SSE, a log tail, a
large download, incremental gRPC) through the *same*
``Handler.serve -> Response`` contract, a ``Response`` can carry a
type-erased chunk source that the reactor pulls on each writable edge
and frames as ``Transfer-Encoding: chunked``.

This module is the source-side foundation, deliberately free of any
reactor coupling so it can land and be tested on its own:

- ``ChunkSourceBox``: a move-only, type-erased box over any
  :trait:`flare.http.body.ChunkSource`. It heap-allocates the concrete
  source via ``Pool[S]`` and captures monomorphised ``next`` / destroy
  thunks, so ``Response`` (and later the reactor's ``ConnHandle``) can
  hold and drive a source without being generic over its type.
- Chunked-framing helpers (``frame_chunk_into`` / ``frame_terminator_into``)
  that emit RFC 9112 sec 7.1 chunk framing into a reused buffer.

The reactor adoption (a ``ChunkSourceBox`` field on ``Response`` +
``ConnHandle``, and the per-writable-edge pull loop) lands as the
follow-up; the box + framing here are what it builds on.
"""

from std.collections import Optional

from ..runtime import Pool
from .body import ChunkSource
from .cancel import Cancel


# ── Type-erased chunk-source box ─────────────────────────────────────────────


def _chunk_next_thunk[
    S: ChunkSource
](addr: Int, cancel: Cancel) raises -> Optional[List[UInt8]]:
    """Monomorphised ``next``: reconstruct ``S*`` from ``addr`` and pull
    one chunk. Captured per concrete source at box-creation time."""
    return Pool[S].get_ptr(addr)[].next(cancel)


def _chunk_destroy_thunk[S: ChunkSource](addr: Int) -> None:
    """Monomorphised destroy: run ``S``'s destructor + free the cell."""
    Pool[S].free(addr)


struct ChunkSourceBox(Movable):
    """Move-only, type-erased owner of a heap-boxed ``ChunkSource``.

    Built via :meth:`create`; drives the source via :meth:`next`; frees
    the box exactly once on drop (or when moved-from, ownership
    transfers so the destructor runs only on the final owner). The
    reactor takes the box out of a ``Response`` onto its per-connection
    state and pulls ``next(cancel)`` per writable edge until it returns
    ``None`` (end-of-stream).
    """

    var addr: Int
    """Heap address of the boxed concrete source (0 = empty / moved-from)."""
    var _next: def(Int, Cancel) raises thin -> Optional[List[UInt8]]
    var _destroy: def(Int) thin -> None

    def __init__(
        out self,
        addr: Int,
        next_fn: def(Int, Cancel) raises thin -> Optional[List[UInt8]],
        destroy_fn: def(Int) thin -> None,
    ):
        self.addr = addr
        self._next = next_fn
        self._destroy = destroy_fn

    # Move is memberwise (Mojo-synthesised): the boxed-source address +
    # thunks transfer to the new owner and ``existing`` is moved-from, so
    # its ``__del__`` does not run -- the box is freed exactly once by the
    # final owner. An explicit ``__moveinit__`` here tripped ``mojo doc``
    # ('None has no attributes'); the synthesised move is identical.

    def __del__(deinit self):
        if self.addr != 0:
            self._destroy(self.addr)

    @staticmethod
    def create[S: ChunkSource](var source: S) raises -> ChunkSourceBox:
        """Heap-box ``source`` and capture its monomorphised thunks."""
        return ChunkSourceBox(
            Pool[S].alloc_move(source^),
            _chunk_next_thunk[S],
            _chunk_destroy_thunk[S],
        )

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        """Pull the next chunk, or ``None`` at end-of-stream."""
        return self._next(self.addr, cancel)


# ── Chunked (RFC 9112 sec 7.1) framing helpers ───────────────────────────────


@always_inline
def _hex_len_into(mut buf: List[UInt8], n: Int):
    """Append the lowercase-hex chunk size of ``n`` (no leading zeros)."""
    if n <= 0:
        buf.append(48)  # '0'
        return
    var digits = List[UInt8](capacity=16)
    var x = n
    while x > 0:
        var d = x & 0xF
        if d < 10:
            digits.append(UInt8(48 + d))  # '0'..'9'
        else:
            digits.append(UInt8(97 + d - 10))  # 'a'..'f'
        x >>= 4
    for i in range(len(digits) - 1, -1, -1):
        buf.append(digits[i])


def frame_chunk_into(mut buf: List[UInt8], chunk: List[UInt8]):
    """Append one framed chunk ``{hexlen}\\r\\n{bytes}\\r\\n`` to ``buf``.

    ``chunk`` MUST be non-empty: a zero-length chunk is the terminator
    (see :func:`frame_terminator_into`), so callers skip empty chunks
    rather than framing them here.
    """
    _hex_len_into(buf, len(chunk))
    buf.append(13)  # \r
    buf.append(10)  # \n
    for i in range(len(chunk)):
        buf.append(chunk[i])
    buf.append(13)
    buf.append(10)


def frame_terminator_into(mut buf: List[UInt8]):
    """Append the last-chunk terminator ``0\\r\\n\\r\\n`` (no trailers)."""
    buf.append(48)  # '0'
    buf.append(13)
    buf.append(10)
    buf.append(13)
    buf.append(10)
