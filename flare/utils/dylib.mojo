"""Canonical FFI dylib path resolver shared across :mod:`flare`.

Closes critique register §C3 (every package that owned a C-side
helper carried its own ``_find_flare_*_lib`` helper -- 7 callers,
4 lookalike implementations of the same ``CONDA_PREFIX`` /
bare-checkout fallback search). Different return values for
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

1. ``$CONDA_PREFIX/lib/libflare_<name>.so`` -- the canonical
   install location, populated by ``flare/<sub>/ffi/build.sh``
   on pixi activation.
2. ``build/libflare_<name>.so`` -- bare-checkout fallback when
   running outside a conda/pixi environment.

The path is built via ``String("") += prefix += literal``
rather than the ``prefix + literal`` concat operator. See the
:mod:`flare.tls.config` module docstring for the full rationale
(Mojo's concat can return a String whose buffer aliases another
``getenv`` + literal result, so two sequential
``CONDA_PREFIX + ...`` calls can clobber each other's bytes).

Public API
----------

``find_flare_lib(name: String) -> String``
    Returns ``$CONDA_PREFIX/lib/libflare_<name>.so`` when
    ``CONDA_PREFIX`` is set, ``build/libflare_<name>.so``
    otherwise. ``name`` is the bare suffix (``"tls"``,
    ``"zlib"``, ``"brotli"``, ``"fs"``).
"""

from std.os import getenv


def find_flare_lib(name: String) -> String:
    """Return the path to ``libflare_<name>.so``.

    Search order:
    1. ``$CONDA_PREFIX/lib/libflare_<name>.so`` -- canonical
       install populated by ``flare/<sub>/ffi/build.sh`` on pixi
       activation.
    2. ``build/libflare_<name>.so`` -- bare-checkout fallback
       when running outside a conda/pixi environment.

    Args:
        name: The bare suffix, e.g. ``"tls"`` for
              ``libflare_tls.so``.

    Returns:
        Path string suitable for passing to
        ``OwnedDLHandle(path)``. The bare-checkout fallback is
        a relative path; the conda path is absolute.
    """
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix == "":
        var local = String("")
        local += "build/libflare_"
        local += name
        local += ".so"
        return local^
    var out = String("")
    out += prefix
    out += "/lib/libflare_"
    out += name
    out += ".so"
    return out^
