"""Canonical FFI dylib path resolver shared across :mod:`flare`.

Consolidates the per-package FFI-lib finders: every package that
owned a C-side helper carried its own ``_find_flare_*_lib``
helper -- 7 callers, 4 lookalike implementations of the same
``CONDA_PREFIX`` / bare-checkout fallback search. Different
return values for
"library not present" (``"build/libflare_X.so"`` vs
``"libflare_X.so"``); identical search order otherwise.

This module is the single canonical home. Each call site that
opens a flare-bundled shared object goes through
:func:`find_flare_lib`; the bundled shim's name (the ``X`` in
``libflare_X.so``) is the only argument.

Library naming convention
-------------------------

flare bundles four FFI shims under ``$CONDA_PREFIX/lib/``:

* ``libflare_tls.so`` -- OpenSSL hooks (TLS handshake, AEAD,
  hkdf, hmac, sha1) plus the ``flare_read`` / ``flare_write``
  thin wrappers used by the io_uring reactor's hot path.
* ``libflare_zlib.so`` -- zlib + gzip + raw-deflate thin
  wrappers consumed by :mod:`flare.http.encoding` (HTTP
  ``Content-Encoding``) and :mod:`flare.ws.permessage_deflate`
  (WebSocket ``permessage-deflate``).
* ``libflare_brotli.so`` -- libbrotlienc + libbrotlidec
  consumed by :mod:`flare.http.encoding` for ``Content-Encoding:
  br``.
* ``libflare_fs.so`` -- ``access(2)`` + ``open(2)`` +
  ``read(2)`` + ``close(2)`` thin wrappers consumed by
  :mod:`flare.http.fs` (``FileServer`` static-file path) and
  :mod:`flare.http.middleware._file_exists`.

Search order (used by every call site):
1. ``$FLARE_LIB_DIR/libflare_<name>.so`` -- when ``FLARE_LIB_DIR`` is
   an absolute path; for running outside pixi.
2. ``$CONDA_PREFIX/lib/libflare_<name>.so`` -- the canonical
   install location, populated by ``flare/<sub>/ffi/build.sh``
   on pixi activation.
3. The bare ``libflare_<name>.so``, which ``dlopen`` resolves on the
   system library path. Never the working directory.
The path is built via ``String("") += prefix += literal``
rather than the ``prefix + literal`` concat operator. See the
:mod:`flare.tls.config` module docstring for the full rationale
(Mojo's concat can return a String whose buffer aliases another
``getenv`` + literal result, so two sequential
``CONDA_PREFIX + ...`` calls can clobber each other's bytes).

Public API
----------

``find_flare_lib(name: String) -> String``
    Resolves ``libflare_<name>.so`` in the order above. ``name`` is
    the bare suffix (``"tls"``, ``"zlib"``, ``"brotli"``, ``"fs"``).

``dl_sym[FT](lib: OwnedDLHandle, name: String) raises -> FT``
    Resolve a C-ABI function symbol. ``OwnedDLHandle.get_function``
    returns an origin-bound ``_DLCallable`` that cannot be called
    or stored the way plain function pointers used to be;
    ``get_symbol`` + address reinterpret is the replacement every
    FFI call site across :mod:`flare` now shares.
"""

from std.os import getenv
from std.ffi import OwnedDLHandle
from std.memory import Pointer


def dl_sym[
    FT: TrivialRegisterPassable
](lib: OwnedDLHandle, name: String) raises -> FT:
    """Look up a C-ABI function symbol as a plain callable value.

    Replaces the ``lib.get_function[FT](name)`` idiom, whose return
    type (an origin-bound ``_DLCallable``) can no longer be invoked
    directly or stored across scopes.
    """
    var opt = lib.get_symbol[FT](name)
    if not opt:
        raise Error("flare: FFI symbol not found: " + name)
    var addr: Int = Int(opt.value())
    return Pointer(to=addr).unsafe_bitcast[FT]()[]


def _lib_in(dir: String, name: String) -> String:
    var out = String("")
    out += dir
    out += "/libflare_"
    out += name
    out += ".so"
    return out^


def find_flare_lib(name: String) -> String:
    """Return the path to ``libflare_<name>.so``.

    Search order:

    1. ``$FLARE_LIB_DIR/libflare_<name>.so``, when ``FLARE_LIB_DIR``
       is an absolute path. For running outside pixi, e.g. a bare
       checkout with ``FLARE_LIB_DIR=$PWD/build``.
    2. ``$CONDA_PREFIX/lib/libflare_<name>.so``, when ``CONDA_PREFIX``
       is absolute: the install that ``flare/<sub>/ffi/build.sh``
       populates on pixi activation.
    3. The bare file name, which ``dlopen`` looks up on the system
       library path (``LD_LIBRARY_PATH`` / ``DYLD_LIBRARY_PATH``,
       rpath, the system directories). It never looks in the working
       directory.

    The last step used to be ``build/libflare_<name>.so``, relative to
    the working directory. A flare program started with no
    ``CONDA_PREFIX`` from a directory someone else could write to (a
    shared ``/tmp``, a checked-out repository) loaded whatever
    ``build/libflare_tls.so`` it found there, and ran that code with the
    program's privileges.

    Args:
        name: The bare suffix, e.g. ``"tls"`` for
              ``libflare_tls.so``.

    Returns:
        Path string suitable for passing to ``OwnedDLHandle(path)``.
    """
    var dir = getenv("FLARE_LIB_DIR", "")
    if dir.startswith("/"):
        return _lib_in(dir, name)
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix.startswith("/"):
        var lib_dir = String("")
        lib_dir += prefix
        lib_dir += "/lib"
        return _lib_in(lib_dir, name)
    var bare = String("")
    bare += "libflare_"
    bare += name
    bare += ".so"
    return bare^
