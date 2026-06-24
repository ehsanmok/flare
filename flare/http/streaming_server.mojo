"""Typed streaming-handler surface (v0.9 gap family A).

A custom multiplexing / streaming front -- the shape an LLM-inference
proxy needs -- used to drop to the raw reactor and smuggle every live
object (the reactor, the streams, the buffers) as an ``Int`` address,
rebuilding it with ``UnsafePointer(unsafe_from_address=...)``, plus
hand-rolled ``alloc`` per-slot tables and a free list. This module
removes that: the framework owns the connection lifecycle and the
reactor; the handler is a typed struct whose fields are its shared
state and which receives a framework-owned ``StreamConn`` per event.

Pieces:

- ``StreamHandler`` -- the lifecycle trait (``on_open`` / ``on_upstream``
  / ``on_writable`` / ``on_close``). Every method takes ``mut self``
  (the typed shared state, one instance shared across all connections)
  and a ``mut`` ref to the framework-owned ``StreamConn``. No raw
  token, no address-as-``Int``.
- ``StreamConn`` -- the framework-owned per-connection handle. Owns the
  client ``TcpStream``, a per-connection ``Cancel`` cell, a stable
  per-connection id, and the close flag.
- ``run_stream_connection`` -- a blocking single-connection driver that
  walks one connection through the lifecycle. The reactor-integrated
  multi-connection entry point (``HttpServer.serve_streaming``) builds
  on the same trait and lands next (A2); this driver is the testable
  core of the contract and is itself useful for one-connection UDS
  sidecars.

Typed-state model
-----------------

Mojo (1.0.0b2) has neither parameterized traits nor associated types,
so a single ``StreamHandler`` cannot carry a per-handler "state type
S" or "per-connection type U" in its method signatures and still let
the method *body* read those typed fields. The model that is both
typed and usable:

- **Shared state** is the handler struct's own fields. The framework
  holds one handler instance and calls it (via ``mut self``) for every
  connection and every event, so the fields are shared, mutable, and
  fully typed -- this is the ``ServeState`` (e.g. a persistent
  ``FrameMux``) the design's "after" sketch wanted, reached as a typed
  ref rather than an ``Int`` address.
- **Per-connection state** is keyed by ``conn.id()`` in a typed
  container the handler declares once (e.g. ``Dict[Int, MyConnState]``).
  The framework assigns the id and signals ``on_open`` / ``on_close``
  so the handler inserts / removes its entry -- no ``alloc``, no manual
  free list, lifecycle framework-owned.

Together this deletes the design-0.9 A1/A2 gaps: the 18-field ``Ctx``
of ``Int`` addresses and the ``alloc[...](max_slots)`` slot tables +
free stack.
"""

from std.ffi import c_int

from .cancel import Cancel, CancelCell, CancelReason
from flare.tcp import TcpStream


# ── StreamConn ─────────────────────────────────────────────────────────────


struct StreamConn(Movable):
    """Framework-owned per-connection handle.

    Owns the accepted client stream and a per-connection cancel cell,
    carries a stable per-connection id (for the handler to key its own
    typed per-connection state), and the close flag the handler trips
    when it is done with the connection. The ``client`` stream is owned
    here (sole owner) and closed when the handle is dropped -- the same
    ownership rule the reactor's ``ConnHandle`` follows.
    """

    var client: TcpStream
    """The accepted client connection. Sole owner; closed on drop."""
    var _id: Int
    """Stable per-connection id assigned by the framework. The handler
    keys its typed per-connection state on this value."""
    var _cancel_cell: CancelCell
    """Per-connection cancel cell. ``cancel()`` hands out a ``Cancel``
    bound to it; the driver / reactor flips it on peer FIN / deadline /
    drain."""
    var _close_requested: Bool
    """Set by the front via ``request_close()`` once it has finished
    with the connection; the driver / reactor tears the connection down
    after the current step returns."""

    def __init__(out self, var client: TcpStream, id: Int = 0) raises:
        """Adopt ``client`` into a fresh per-connection handle."""
        self.client = client^
        self._id = id
        self._cancel_cell = CancelCell()
        self._close_requested = False

    @always_inline
    def id(self) -> Int:
        """Stable per-connection id (key for handler-owned per-conn
        state)."""
        return self._id

    @always_inline
    def fd(self) -> c_int:
        """Underlying client fd. Fast accessor; does not check state."""
        return self.client._socket.fd

    @always_inline
    def cancel(mut self) -> Cancel:
        """Return a ``Cancel`` handle bound to this connection's cell."""
        return self._cancel_cell.handle()

    @always_inline
    def flip_cancel(mut self, reason: Int):
        """Flip the connection's cancel cell (framework-internal)."""
        self._cancel_cell.flip(reason)

    @always_inline
    def request_close(mut self):
        """Ask the framework to close this connection after the current
        lifecycle step returns."""
        self._close_requested = True

    @always_inline
    def is_closing(self) -> Bool:
        """True once ``request_close`` has been called."""
        return self._close_requested

    def send(mut self, data: Span[UInt8, _]) raises:
        """Write ``data`` to the client, looping until fully sent.

        Blocking on this single-connection driver. The reactor-backed
        ``serve_streaming`` (A2) replaces this with a buffered,
        backpressure-aware EPOLLOUT write path; the front's call site
        is unchanged.
        """
        self.client.write_all(data)

    def recv(mut self, mut buf: List[UInt8], max_bytes: Int) raises -> Int:
        """Append up to ``max_bytes`` bytes read from the client onto
        ``buf``. Returns the count read (0 on peer EOF)."""
        var old = len(buf)
        buf.resize(old + max_bytes, UInt8(0))
        var n = self.client.read(buf.unsafe_ptr() + old, max_bytes)
        buf.resize(old + n, UInt8(0))
        return n


# ── StreamHandler ──────────────────────────────────────────────────────────


trait StreamHandler(ImplicitlyDestructible, Movable):
    """Lifecycle callbacks for one logical stream.

    The framework owns the reactor and the connection; the handler is a
    typed struct whose fields are its shared state. Every callback takes
    ``mut self`` (that typed shared state) and a ``mut`` ref to the
    framework-owned ``StreamConn``. There is no raw token and no
    address-as-``Int`` anywhere in the front.
    """

    def on_open(mut self, mut conn: StreamConn) raises:
        """Called once when the connection is accepted. Parse the
        request, attach an upstream, begin the response."""
        ...

    def on_upstream(mut self, mut conn: StreamConn) raises:
        """Called when attached upstream data is ready to be pumped to
        the client. (Wired to a real upstream fd in A4 / B1.)"""
        ...

    def on_writable(mut self, mut conn: StreamConn) raises:
        """Called on a writable edge. Emit the next chunk of the
        response; call ``conn.request_close()`` when the stream is
        complete."""
        ...

    def on_close(mut self, mut conn: StreamConn) raises:
        """Called once as the connection is torn down (front FIN,
        deadline, or ``request_close``). Release per-connection
        resources."""
        ...


# ── Single-connection blocking driver ──────────────────────────────────────


def run_stream_connection[
    H: StreamHandler
](mut handler: H, var client: TcpStream, id: Int = 0) raises:
    """Drive one accepted ``client`` connection through the handler
    lifecycle, blocking.

    Calls ``on_open`` once, then ``on_writable`` repeatedly until the
    front requests close (so a streaming front emits chunk-by-chunk),
    then ``on_close`` exactly once. ``on_upstream`` is driven by the
    reactor path (A4 / B1); this blocking driver is the single-
    connection core used by tests and one-shot sidecars.

    The connection is closed when ``conn`` drops at function exit.
    """
    var conn = StreamConn(client^, id)
    handler.on_open(conn)
    while not conn.is_closing():
        handler.on_writable(conn)
    handler.on_close(conn)
