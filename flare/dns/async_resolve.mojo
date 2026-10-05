"""DNS resolution on a separate thread + happy-eyeballs ordering.

``getaddrinfo(3)`` is a blocking syscall with no async variant on the
platforms flare targets. :func:`resolve_async` runs it on a fresh pool
thread (the pthread mechanism :func:`block_in_pool` uses) **and waits
for that thread**: the caller is blocked for the whole lookup, exactly
as with :func:`flare.dns.resolve`. What it adds is a separate stack and
a :class:`Cancel` check before the lookup starts and after it returns.
It does not free a reactor thread to serve other connections while the
lookup runs, and a cancel that arrives mid-lookup takes effect only
when ``getaddrinfo`` returns. Errors come back with the resolver's
message (``DnsError(host): reason``) as a plain ``Error``, which is
what a raised ``DnsError`` is by the time any caller sees it.

:func:`order_happy_eyeballs` reorders a resolved address list into the
RFC 8305 connection-attempt order (interleave IPv6 / IPv4, starting with
the family of the first address) so a dialer can race families without one
stalling the other.

The worker thread is joined (the public API is synchronous --
the submitter waits for the result anyway), so a flipped ``cancel`` is
honored at the pre-flight and post-flight boundaries, the same contract
as ``block_in_pool``. A truly fire-and-forget resolve that returns the
reactor to its loop while the lookup runs would need reactor-side
completion wiring (eventfd/pipe wakeup) instead.
"""

from std.memory import Pointer
from std.memory.alloc import unsafe_alloc

from ..http.cancel import Cancel
from ..net import IpAddr
from ..net.error import AddressParseError, DnsError
from ..runtime._thread import ThreadHandle, _OpaquePtr
from ..runtime.blocking import _pool_try_acquire, _pool_release, MAX_POOL_SIZE
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
    var ctx = arg.unsafe_bitcast[_ResolveCtx]()
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
    """Resolve ``host`` on a pool thread and wait for it.

    Same result as :func:`flare.dns.resolve`, and it blocks the caller
    just as long: the ``getaddrinfo`` call runs on a fresh kernel thread
    that this function joins. A flipped ``cancel`` is honoured before
    the thread starts and after it finishes, not during the lookup.

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

    # Admission: share the process-wide pool-thread cap with
    # ``block_in_pool`` so a fan-out of resolves cannot thread-bomb.
    if not _pool_try_acquire():
        raise Error(
            "resolve_async: pool saturated (MAX_POOL_SIZE="
            + String(MAX_POOL_SIZE)
            + " concurrent pool threads)"
        )

    var host_addr = Pool[String].alloc_move(host)
    var ctx_ptr = unsafe_alloc[_ResolveCtx](1)
    ctx_ptr.unsafe_write(_ResolveCtx(host_addr, 0, 0, 0))
    var ctx_opaque = Pointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=Int(ctx_ptr)
    )

    try:
        var handle = ThreadHandle.spawn[_resolve_start](ctx_opaque)
        handle.join()
    except e:
        Pool[String].free(host_addr)
        ctx_ptr.unsafe_deinit_pointee()
        ctx_ptr.unsafe_free()
        _pool_release()
        raise e^
    _pool_release()

    var ok = ctx_ptr[].ok == 1
    var res_addr = ctx_ptr[].result_addr
    var err_addr = ctx_ptr[].err_addr
    Pool[String].free(host_addr)
    ctx_ptr.unsafe_deinit_pointee()
    ctx_ptr.unsafe_free()

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

    Interleaves the two address families, **starting with the family of
    ``addrs[0]``** (the resolver's most-preferred address, RFC 8305 §4:
    "whichever address family is first in the list should be followed by an
    address of the other address family"), preserving each family's relative
    order: ``[v6, v4, v6, v4, ...]`` for an IPv6-first input and
    ``[v4, v6, v4, v6, ...]`` for an IPv4-first one. A dialer can then race
    the two families without one family's slow first address starving the
    other, and the first attempt still goes to the address the OS ranked
    highest. Returns a new list; the input is unchanged.
    """
    var v6 = List[IpAddr]()
    var v4 = List[IpAddr]()
    for i in range(len(addrs)):
        if addrs[i].is_v6():
            v6.append(addrs[i].copy())
        else:
            v4.append(addrs[i].copy())
    var first_v6 = len(addrs) == 0 or addrs[0].is_v6()
    ref first = v6 if first_v6 else v4
    ref second = v4 if first_v6 else v6
    var out = List[IpAddr](capacity=len(addrs))
    var i = 0
    while i < len(first) or i < len(second):
        if i < len(first):
            out.append(first[i].copy())
        if i < len(second):
            out.append(second[i].copy())
        i += 1
    return out^
