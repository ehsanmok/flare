"""Off-reactor DNS resolution + happy-eyeballs ordering (W6).

``getaddrinfo(3)`` is a blocking syscall with no async variant on the
platforms flare targets. :func:`resolve_async` offloads it to a fresh
pool thread (via the same pthread mechanism :func:`block_in_pool` uses)
so the call runs off the reactor's stack and is bounded by a
:class:`Cancel` token at the call boundary, rather than running inline.
The synchronous :func:`flare.dns.resolve` is untouched; callers that do
not need the off-thread variant pay nothing.

:func:`order_happy_eyeballs` reorders a resolved address list into the
RFC 8305 connection-attempt order (interleave IPv6 / IPv4) so a dialer
can race families without one stalling the other.

ponytail: the worker thread is joined (the public API is synchronous --
the submitter waits for the result anyway), so a flipped ``cancel`` is
honored at the pre-flight and post-flight boundaries, the same contract
as ``block_in_pool``. A truly fire-and-forget resolve that returns the
reactor to its loop while the lookup runs needs reactor-side completion
wiring (eventfd/pipe wakeup); that is the documented upgrade path.
"""

from std.memory import UnsafePointer, alloc

from ..http.cancel import Cancel
from ..net import IpAddr
from ..net.error import AddressParseError, DnsError
from ..runtime._thread import ThreadHandle, _OpaquePtr
from ..runtime.pool import Pool
from .resolver import resolve


@fieldwise_init
struct _ResolveCtx(Movable):
    """Cross-thread handoff cell for one :func:`resolve_async` call.

    The submitter fills ``host_addr`` (a heap ``String`` cell) and zeroes
    the rest; the worker writes ``result_addr`` (a heap ``List[IpAddr]``
    cell) on success or ``err_addr`` (a heap ``String`` cell) on failure,
    then sets ``ok``. ``pthread_join`` provides the happens-before edge,
    so plain fields (no atomics) are safe to read after the join."""

    var host_addr: Int
    var result_addr: Int
    var err_addr: Int
    var ok: Int


def _resolve_start(arg: _OpaquePtr) -> _OpaquePtr:
    """pthread start routine: resolve the host named by ``arg`` (a
    ``_ResolveCtx*``) and record the outcome in the cell. Must not raise
    (pthread has no exception channel), so all fallible work is wrapped."""
    var ctx = arg.bitcast[_ResolveCtx]()
    var host = Pool[String].get_ptr(ctx[].host_addr)[].copy()
    var res_addr = 0
    var err_addr = 0
    var success = False
    try:
        var addrs = resolve(host)
        res_addr = Pool[List[IpAddr]].alloc_move(addrs^)
        success = True
    except e:
        try:
            err_addr = Pool[String].alloc_move(String(e))
        except:
            err_addr = 0
    ctx[].result_addr = res_addr
    ctx[].err_addr = err_addr
    ctx[].ok = 1 if success else 0
    return arg


def resolve_async(host: String, cancel: Cancel) raises -> List[IpAddr]:
    """Resolve ``host`` on a pool thread, off the reactor stack.

    Same result as :func:`flare.dns.resolve` but the ``getaddrinfo``
    call runs on a fresh kernel thread; a flipped ``cancel`` aborts the
    call at the pre-flight / post-flight boundary.

    Args:
        host: Hostname or numeric IP string.
        cancel: Per-request cancel token (use ``Cancel.never()`` for an
            uncancellable call).

    Returns:
        A non-empty ``List[IpAddr]`` (OS-preference order; pass through
        :func:`order_happy_eyeballs` for connection-attempt order).

    Raises:
        AddressParseError: empty ``host``.
        DnsError / Error: resolver failure (propagated from the worker),
            or cancellation.
    """
    if cancel.cancelled():
        raise Error("resolve_async: cancelled")
    if host.byte_length() == 0:
        raise AddressParseError("empty hostname")

    var host_addr = Pool[String].alloc_move(host)
    var ctx_ptr = alloc[_ResolveCtx](1)
    ctx_ptr.init_pointee_move(_ResolveCtx(host_addr, 0, 0, 0))
    var ctx_opaque = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx_ptr)
    )

    var handle = ThreadHandle.spawn[_resolve_start](ctx_opaque)
    handle.join()

    var ok = ctx_ptr[].ok == 1
    var res_addr = ctx_ptr[].result_addr
    var err_addr = ctx_ptr[].err_addr
    Pool[String].free(host_addr)
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()

    if ok:
        var out = Pool[List[IpAddr]].get_ptr(res_addr)[].copy()
        Pool[List[IpAddr]].free(res_addr)
        if cancel.cancelled():
            raise Error("resolve_async: cancelled mid-flight")
        return out^

    var msg = String("resolve_async: resolution failed")
    if err_addr != 0:
        msg = Pool[String].get_ptr(err_addr)[].copy()
        Pool[String].free(err_addr)
    raise Error(msg)


def order_happy_eyeballs(addrs: List[IpAddr]) -> List[IpAddr]:
    """Reorder ``addrs`` into RFC 8305 connection-attempt order.

    Interleaves the IPv6 and IPv4 results (``v6[0], v4[0], v6[1],
    v4[1], ...``) preserving each family's relative order, so a dialer
    can race the two families without one family's slow first address
    starving the other. Returns a new list; the input is unchanged.
    """
    var v6 = List[IpAddr]()
    var v4 = List[IpAddr]()
    for i in range(len(addrs)):
        if addrs[i].is_v6():
            v6.append(addrs[i].copy())
        else:
            v4.append(addrs[i].copy())
    var out = List[IpAddr](capacity=len(addrs))
    var i = 0
    while i < len(v6) or i < len(v4):
        if i < len(v6):
            out.append(v6[i].copy())
        if i < len(v4):
            out.append(v4[i].copy())
        i += 1
    return out^
