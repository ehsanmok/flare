"""Typed heap-allocator wrapper (v0.5.0 Step 2 / Track 1.2).

``Pool[T]`` confines ``UnsafePointer.alloc`` / ``free`` /
``init_pointee_move`` / ``destroy_pointee`` plumbing to one place
so the rest of ``flare/http`` and ``flare/runtime`` can stay
pointer-free at the source level. Closes the criticism §2.9
"raw pointers in the hot path" item by giving callers a typed
API that owns the pointer arithmetic.

Today's callers go through ``UnsafePointer[T].alloc(1)`` directly:

    var p = alloc[ConnHandle](1)
    if Int(p) == 0:
        raise Error("alloc failed")
    p.init_pointee_move(ConnHandle(stream^))
    var addr = Int(p)
    ...
    var ptr = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=addr
    ).bitcast[ConnHandle]()
    ptr.destroy_pointee()
    ptr.free()

After this commit, the same flow reads:

    var addr = Pool[ConnHandle].alloc_move(ConnHandle(stream^))
    ...
    Pool[ConnHandle].free(addr)

Same machine code (``Pool`` is a zero-size dispatcher with
``@staticmethod`` methods); narrower public surface; one place to
audit if ownership semantics ever change.

The "Pool" name leaves room for a future implementation that
batches allocations or hands out from a per-connection slab; the
current implementation is one heap allocation per call. The
public API doesn't need to change for that upgrade.

Why is this in ``flare/runtime/`` rather than each call site?

- Per the criticism: "no ``UnsafePointer`` reaches outside
  ``flare/runtime/``." Concentrating the unsafe primitives here
  means the rest of the library can stay safe code.
- ``Pool[T]`` is generic enough to serve other modules
  (``Request._params``, future ``StreamingBody`` chunk pools).
"""

from std.memory import UnsafePointer, alloc
from std.sys.info import size_of


struct Pool[T: ImplicitlyDestructible & Movable]:
    """Typed heap allocator over ``UnsafePointer[T].alloc(1)``.

    Stateless — every method is ``@staticmethod``. The struct
    exists only to pin the type parameter; instantiating it is
    not required.

    ``alloc_move(value)`` returns the heap address as an ``Int``
    so callers can store it in a Mojo-managed structure
    (``Dict[Int, Int]``, ``List[Int]``, struct field) without a
    typed pointer escaping into user code. ``free(addr)`` runs
    ``T``'s destructor and releases the memory.

    ZST handling: when ``size_of[T]() == 0``, ``alloc[T](1)`` is
    rejected by Mojo's stdlib ("size must be greater than zero").
    Pool transparently allocates a single placeholder byte via
    ``alloc[UInt8](1)`` and bitcasts to ``UnsafePointer[T]`` for
    the move-in / dereference pattern (which is a no-op for a
    zero-byte type). Callers see the same API regardless of
    whether ``T`` is ZST.

    Threading: each ``Pool[T]`` operation is independent (no
    shared state between calls). Multiple threads can call
    ``alloc_move`` and ``free`` concurrently as long as each
    address is owned by exactly one thread at a time.
    """

    @staticmethod
    @always_inline
    def alloc_move(var value: Self.T) raises -> Int:
        """Heap-allocate one ``T``, move ``value`` into it, return
        the address.

        Args:
            value: Owned ``T`` to move into the heap cell.

        Returns:
            The cell's address as an ``Int``. Zero is never
            returned — alloc failure raises.

        Raises:
            Error: When the underlying allocation returns null.
        """

        comptime if size_of[Self.T]() > 0:
            var p = alloc[Self.T](1)
            p.init_pointee_move(value^)
            return Int(p)
        else:
            # ZST path: alloc a single placeholder byte and
            # bitcast. ``init_pointee_move`` writes 0 bytes
            # through the bitcast pointer; reads / dereferences
            # also touch 0 bytes.
            var raw = alloc[UInt8](1)
            raw.bitcast[Self.T]().init_pointee_move(value^)
            return Int(raw)

    @staticmethod
    @always_inline
    def free(addr: Int) -> None:
        """Run ``T``'s destructor at ``addr`` and release the
        memory.

        Idempotent on ``addr == 0`` (no-op). Calling ``free``
        twice on the same non-zero ``addr`` is undefined
        behaviour — the caller must own the address exactly
        once, just as with raw ``UnsafePointer``.

        Args:
            addr: Address returned by ``Pool[T].alloc_move``, or
                0 (no-op).
        """
        if addr == 0:
            return

        comptime if size_of[Self.T]() > 0:
            var ptr = UnsafePointer[UInt8, MutExternalOrigin](
                unsafe_from_address=addr
            ).bitcast[Self.T]()
            ptr.destroy_pointee()
            ptr.free()
        else:
            # ZST path: free as UInt8 since that's what was
            # allocated. Still run T's destructor for symmetry —
            # it touches 0 bytes for a zero-sized type but keeps
            # the contract identical to the non-ZST case.
            var raw = UnsafePointer[UInt8, MutExternalOrigin](
                unsafe_from_address=addr
            )
            raw.bitcast[Self.T]().destroy_pointee()
            raw.free()

    @staticmethod
    @always_inline
    def get_ptr(addr: Int) -> UnsafePointer[Self.T, MutExternalOrigin]:
        """Re-materialise a typed pointer from an address.

        For callers that need to dereference the cell (e.g. read /
        write a field) without allocating their own
        ``UnsafePointer`` arithmetic. Returned pointer carries
        ``MutExternalOrigin`` so the Mojo optimiser cannot hoist
        loads through it.

        Caller is responsible for ensuring ``addr`` is a valid
        live pool allocation.
        """
        return UnsafePointer[UInt8, MutExternalOrigin](
            unsafe_from_address=addr
        ).bitcast[Self.T]()
