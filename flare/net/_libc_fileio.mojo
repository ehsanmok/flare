"""Raw read/write for non-socket fds (pipe, eventfd) - split out of ``_libc``.

``_recv`` / ``_send`` in ``flare.net._libc`` only work on sockets. Eventfd and
pipe require plain ``read(2)`` / ``write(2)``. We route through ``flare_read`` /
``flare_write`` exposed by ``libflare_tls.so`` because Mojo's stdlib also
declares ``external_call["read" / "write", ...]`` for ``FileDescriptor`` with a
different signature, and the two collide at the MLIR lowering stage. The C
wrappers compile to a single tail-call; no measurable cost.

Both platforms load the library on demand via ``OwnedDLHandle``:

- macOS: SIP blocks ``DYLD_INSERT_LIBRARIES`` for non-signed binaries, so a
  preload-style injection is impossible.
- Linux: Mojo's JIT symbol resolver does **not** look at ``LD_PRELOAD``ed
  globals - it only searches the small set of shared objects it opened
  itself. So even on Linux we must ``dlopen`` via ``OwnedDLHandle`` to get a
  callable pointer.

Two call shapes are provided:

* ``FlareRawIO`` - a cached handle + function-pointer struct. Owners (like
  ``Reactor``) construct one at init time and call ``io.read() / io.write()``
  on the hot path. No dlopen/dlsym per call. Pattern lifted straight from
  ``ehsanmok/json``'s ``SimdjsonFFI``.
* ``_read_fd`` / ``_write_fd`` - thin module-level helpers that open the
  library per call. Convenient for one-off use from tests and non-hot-path
  call sites; do **not** use in anything that runs per-request or per-wakeup.

These names are re-exported from ``flare.net._libc`` so existing
``from flare.net._libc import FlareRawIO`` call sites keep working unchanged.
"""

from std.ffi import (
    c_int,
    c_size_t,
    c_ssize_t,
    OwnedDLHandle,
)
from std.memory import UnsafePointer

from ..utils.dylib import find_flare_lib


def _find_flare_lib_for_io() -> String:
    """Locate ``libflare_tls.so`` at runtime.

    Thin wrapper over :func:`flare.utils.dylib.find_flare_lib`
    pinned to the ``"tls"`` shim name. Kept under the
    ``flare.net._libc`` namespace because the file's own
    ``FlareRawIO`` constructor uses it; everything else routes
    through :func:`flare.net.socket._find_flare_lib` which uses
    the same canonical helper.
    """
    return find_flare_lib("tls")


# FlareRawIO: cached handle for the reactor's hot-path.
#
# The reactor calls ``_read_fd`` / ``_write_fd`` on every wakeup to drain
# the eventfd / self-pipe. Doing ``dlopen + dlsym + dlclose`` per wakeup
# is measurable under churn (Stage 2+ multi-threaded wakeup, the
# ``fuzz_reactor_churn`` workload). ``FlareRawIO`` opens the library and
# resolves ``flare_read`` / ``flare_write`` exactly once - subsequent
# I/O is a plain indirect call through the cached function pointer.
#
# Ownership invariant: the ``OwnedDLHandle`` field keeps the library
# mapped for the lifetime of the struct, so the cached function
# pointers stay valid. Moving the struct moves the handle + pointers
# together. ``Copyable`` would be wrong because duplicating an
# ``OwnedDLHandle`` would double-free on destruction.


struct FlareRawIO(Movable):
    """Cached dlopen handle + function pointers for ``flare_read`` /
    ``flare_write`` in ``libflare_tls.so``.

    Construct once per owner (typically a ``Reactor``), then call
    ``read()`` / ``write()`` on the hot path without paying a dlopen
    cost per syscall. See the module comment above for the full
    rationale and the ``ehsanmok/json`` ``SimdjsonFFI`` pattern we
    inherit from.
    """

    var _lib: OwnedDLHandle
    """Owned dlopen handle. Keeps the library mapped for the lifetime of
    the struct so the cached function pointers stay valid."""

    var _read: def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
    """Cached pointer to ``flare_read`` in ``libflare_tls.so``."""

    var _write: def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
    """Cached pointer to ``flare_write`` in ``libflare_tls.so``."""

    def __init__(out self) raises:
        """Open ``libflare_tls.so`` and resolve the raw I/O entry points.

        Raises:
            Error: If the library can't be located (via
                ``_find_flare_lib_for_io``) or any symbol is missing.
        """
        self._lib = OwnedDLHandle(_find_flare_lib_for_io())
        self._read = self._lib.get_function[
            def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
        ]("flare_read")
        self._write = self._lib.get_function[
            def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
        ]("flare_write")

    @always_inline
    def read(
        self, fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t
    ) -> c_ssize_t:
        """Read up to ``n`` bytes from ``fd`` into ``buf`` via the cached
        ``flare_read`` pointer.

        Mirrors ``read(2)`` semantics: returns the byte count on success
        (0 on EOF), or -1 on error with ``errno`` set.
        """
        return self._read(fd, Int(buf), n)

    @always_inline
    def write(
        self, fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t
    ) -> c_ssize_t:
        """Write up to ``n`` bytes from ``buf`` to ``fd`` via the cached
        ``flare_write`` pointer.

        Mirrors ``write(2)`` semantics: returns the byte count actually
        written, or -1 on error with ``errno`` set.
        """
        return self._write(fd, Int(buf), n)


# Per-call wrappers (convenience; prefer FlareRawIO on hot paths).
#
# Implementation note - ``read lib`` borrow trick:
#
# Mojo's ASAP (As Soon As Possible) destruction policy destroys an
# ``OwnedDLHandle`` immediately after its *last Mojo-visible use*, which
# in a naive ``var lib = OwnedDLHandle(...); var fn = lib.get_function(...);
# return fn(...)`` pattern is the ``get_function`` call, not the actual
# ``fn(...)`` invocation. ASAP then ``dlclose``s the library and unmaps
# it *before* the function pointer is called, crashing the JIT on both
# macOS ARM64 and Linux. (This was hidden earlier on Linux by the pixi
# activation script ``LD_PRELOAD``ing ``libflare_tls.so``, which kept
# the library mapped regardless of ``dlclose``.)
#
# The fix, lifted from ``flare/http/encoding.mojo``: each public entry
# point opens ``lib`` itself, then delegates to a private helper that
# accepts ``lib`` as a ``read`` (borrowed) parameter. A borrow cannot
# be ASAP-destroyed - it stays alive for the helper's entire
# execution, including every C call inside it.


def _do_read_fd(
    read lib: OwnedDLHandle,
    fd: c_int,
    buf: UnsafePointer[UInt8, _],
    n: c_size_t,
) raises -> c_ssize_t:
    """Inner helper: resolve ``flare_read`` on the borrowed ``lib`` and
    call it. The ``read`` parameter keeps ``lib`` alive across the
    ``fn_r(...)`` call so ASAP doesn't ``dlclose`` it mid-helper.
    """
    var fn_r = lib.get_function[
        def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
    ]("flare_read")
    return fn_r(fd, Int(buf), n)


def _do_write_fd(
    read lib: OwnedDLHandle,
    fd: c_int,
    buf: UnsafePointer[UInt8, _],
    n: c_size_t,
) raises -> c_ssize_t:
    """Inner helper: resolve ``flare_write`` on the borrowed ``lib``
    and call it. See ``_do_read_fd`` for the borrow rationale.
    """
    var fn_w = lib.get_function[
        def(c_int, Int, c_size_t) thin abi("C") -> c_ssize_t
    ]("flare_write")
    return fn_w(fd, Int(buf), n)


@always_inline
def _read_fd(
    fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t
) raises -> c_ssize_t:
    """Read from any fd (socket, pipe, eventfd) via ``libflare_tls.so``.

    Opens the library once per call through ``OwnedDLHandle``. Fine for
    one-off test/tool use; for anything that runs per-wakeup or per-
    request, use ``FlareRawIO`` instead to avoid a dlopen on every call.

    Raises if the library can't be located or opened.
    """
    var lib = OwnedDLHandle(_find_flare_lib_for_io())
    return _do_read_fd(lib, fd, buf, n)


@always_inline
def _write_fd(
    fd: c_int, buf: UnsafePointer[UInt8, _], n: c_size_t
) raises -> c_ssize_t:
    """Write to any fd (socket, pipe, eventfd) via ``libflare_tls.so``.

    Opens the library once per call through ``OwnedDLHandle``. Fine for
    one-off test/tool use; for anything that runs per-wakeup or per-
    request, use ``FlareRawIO`` instead to avoid a dlopen on every call.

    Raises if the library can't be located or opened.
    """
    var lib = OwnedDLHandle(_find_flare_lib_for_io())
    return _do_write_fd(lib, fd, buf, n)
