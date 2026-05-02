"""Per-worker ``Response`` pool (Track B6).

Holds a small stack of pre-allocated, reset-in-place ``Response``
objects so the keep-alive hot path can reuse the same struct
(plus its ``HeaderMap`` + ``body`` ``List[UInt8]`` backings)
across consecutive requests on the same connection.

Why this is a Track B subtrack
-------------------------------

Each ``Response.__init__`` allocates:

1. A fresh ``HeaderMap`` (two empty ``List[String]`` instances).
2. The body ``List[UInt8]`` (default-constructed; capacity 0).
3. A fresh ``reason`` String + ``version`` String.

Even with the v0.6 ownership refactor (``var body``, no copy),
this is one struct + two lists per response. On a long-running
keep-alive connection at 220K req/s, that's ~2.2M list
allocations / s — measurable. ``ResponsePool.acquire()`` returns
a ``Response`` whose backings still carry the previous request's
capacity but are emptied via ``Response.reset(...)``, so the
next ``headers.append`` / ``body.append`` reuses the same
malloc'd backing as long as it fits.

Per-worker, not shared
-----------------------

This pool, like ``DateCache`` (B7) and ``Pool[BufferHandle]`` (B5),
is **per-worker**. There's no atomic, no mutex, no cross-thread
coordination. Each reactor worker constructs its own
``ResponsePool`` and calls ``acquire`` / ``release`` on its local
instance. Two workers handing the same FD's response cell across
a thread boundary is not a supported pattern.

Storage strategy
----------------

``Response`` is ``Movable`` but not ``Copyable``, so we can't
hold a ``List[Response]`` directly (Mojo's ``List`` requires
``Copyable``). Instead we store ``List[Int]`` where each entry
is a heap-allocated ``Response`` cell address, managed via the
existing ``flare.runtime.Pool[Response]`` typed allocator.
``acquire`` pops an address, copies the Response value out via
``Pool.get_ptr().take_pointee()``, and frees the cell.
``release`` moves the supplied Response into a fresh cell and
pushes the address. Net allocation cost: ``alloc/free`` per
acquire/release pair, but the underlying body + header List
buffers are **preserved across the move**, which is the actual
B6 win.

Wiring into the reactor's per-connection state machine
(``flare.http._server_reactor_impl.ConnHandle``) is a follow-up
commit that bolts onto this primitive without changing the
serializer's hot-path layout. The primitive exists today so
the wiring change is a mechanical swap of
``Response(status=200, ...)`` for
``response_pool.acquire(status=200, ...)``.
"""

from .response import Response
from ..runtime.pool import Pool


struct ResponsePool(Movable):
    """Stack of recycled ``Response`` objects for keep-alive reuse.

    The pool holds at most ``capacity`` items. Acquiring from an
    empty pool constructs a fresh ``Response``; releasing into a
    full pool drops the response on the floor (Mojo destructor
    runs).

    Fields:
        _slots: Top-of-stack-grows-up storage of heap-allocated
                ``Response`` cell addresses (returned by
                ``Pool[Response].alloc_move``). Each cell holds
                a Response whose backing buffers (header lists,
                body bytes) have been ``reset()`` empty but
                retain their allocated capacity.
        _capacity: Maximum number of items the pool will hold.
                Releases past this cap drop the released
                response.
    """

    var _slots: List[Int]
    var _capacity: Int

    def __init__(out self):
        """Construct an empty pool with the default capacity (8)."""
        self._slots = List[Int]()
        self._capacity = 8

    def __del__(deinit self):
        """Free every retained cell when the pool is dropped.

        Without this, dropping a non-empty pool would leak every
        cell + its body / header backings.
        """
        for i in range(len(self._slots)):
            Pool[Response].free(self._slots[i])

    @staticmethod
    def with_capacity(capacity: Int) -> ResponsePool:
        """Construct an empty pool with a custom maximum capacity.

        Args:
            capacity: Maximum number of pooled ``Response``
                      objects. Must be > 0.

        Returns:
            A fresh ``ResponsePool`` with the supplied cap.
        """
        var p = ResponsePool()
        p._capacity = 1 if capacity < 1 else capacity
        return p^

    def acquire(
        mut self, status: Int = 200, var reason: String = ""
    ) raises -> Response:
        """Return a reusable ``Response`` from the top of the pool,
        or construct a fresh one if the pool is empty.

        On a hit, the returned ``Response`` has empty headers + body
        but retains its prior backing capacity, so the next
        ``headers.append`` / ``body.append`` call reuses the same
        malloc'd backing as long as the new payload fits.

        Args:
            status: Status code for the returned response (default
                    200).
            reason: Reason phrase (default empty — the serializer
                    will fill from the status code at write time).

        Returns:
            A ``Response`` with the requested status / reason and
            empty headers / body.
        """
        if len(self._slots) > 0:
            var addr = self._slots.pop()
            var ptr = Pool[Response].get_ptr(addr)
            var resp = ptr.take_pointee()
            ptr.free()
            resp.reset(status=status, reason=reason^)
            return resp^
        return Response(status=status, reason=reason^)

    def release(mut self, var response: Response) raises:
        """Return ``response`` to the pool for future ``acquire``
        calls.

        If the pool is at capacity the response is destroyed
        (Mojo's ``var`` destructor runs at the end of this
        function); the pool itself never grows past
        ``_capacity``.

        Args:
            response: Owned ``Response`` to recycle.
        """
        if len(self._slots) < self._capacity:
            var addr = Pool[Response].alloc_move(response^)
            self._slots.append(addr)
        # else: response goes out of scope → destroyed.

    def size(self) -> Int:
        """Return the number of recycled responses currently
        sitting in the pool.

        Useful for tests + telemetry.
        """
        return len(self._slots)

    def capacity(self) -> Int:
        """Return the maximum number of items the pool will hold."""
        return self._capacity
