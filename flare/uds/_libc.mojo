"""``flare.uds._libc`` — internal AF_UNIX FFI helpers.

The publicly-exposed ``flare.net._libc`` module wraps every libc
syscall flare needs for AF_INET / AF_INET6. AF_UNIX uses the same
``bind(2)`` / ``listen(2)`` / ``accept(2)`` / ``connect(2)`` /
``send(2)`` / ``recv(2)`` calls but with a different address-family
constant + a different ``sockaddr`` byte layout:

- Linux: ``struct sockaddr_un { sa_family_t sun_family; char
  sun_path[108]; }`` — total 110 bytes (sa_family_t is 2 bytes).
- macOS / BSD: ``struct sockaddr_un { uint8_t sun_len; sa_family_t
  sun_family; char sun_path[104]; }`` — total 106 bytes
  (sa_family_t is 1 byte).

This module exposes:

- :data:`AF_UNIX` — address-family constant (POSIX-defined as 1
  on Linux + macOS; double-checked at runtime in our tests).
- :data:`SOCKADDR_UN_SIZE` — total struct size; 110 on Linux,
  106 on macOS.
- :data:`SUN_PATH_MAX` — path-byte capacity; 108 on Linux, 104
  on macOS. The upper bound on what
  :func:`fill_sockaddr_un` will accept.
- :func:`fill_sockaddr_un` — populate a caller-allocated
  :data:`SOCKADDR_UN_SIZE`-byte buffer for a given path (a
  filesystem pathname, or ``@name`` for the Linux abstract
  namespace).
- :func:`unlink_path` — wrapper around ``unlink(2)``.

These names are package-internal (single-leading-underscore module
name); the public surface lives in :class:`UnixListener` /
:class:`UnixStream`.
"""

from std.ffi import c_char, c_int, c_uint, external_call, get_errno, ErrNo
from std.memory import UnsafePointer
from std.sys.info import CompilationTarget


comptime AF_UNIX: c_int = 1
"""POSIX-defined constant for the AF_UNIX / AF_LOCAL address family.
Identical on Linux + macOS. Checked at runtime by
``test_uds_listener.test_af_unix_constant``."""

comptime SOCKADDR_UN_SIZE: c_uint = c_uint(
    110
) if not CompilationTarget.is_macos() else c_uint(106)
"""Total ``struct sockaddr_un`` size (in bytes)."""

comptime SUN_PATH_MAX: Int = 108 if not CompilationTarget.is_macos() else 104
"""Maximum path length flare's :class:`UnixListener.bind` accepts.
Includes the NUL terminator: a 108-byte (Linux) / 104-byte (macOS)
buffer must hold ``len(path) + 1`` bytes. Paths longer than this
are rejected before any libc call."""


def fill_sockaddr_un(
    buf: UnsafePointer[UInt8, _],
    path: String,
) raises -> c_uint where type_of(buf).mut:
    """Populate a :data:`SOCKADDR_UN_SIZE`-byte buffer with a
    ``sockaddr_un`` for ``path`` and return the *used* length.

    The returned length is the libc-ABI ``addrlen`` value to pass
    to ``bind(2)`` / ``connect(2)``. It is the byte offset of the
    NUL terminator past the family-prefix bytes, **not** the total
    buffer size — this matters on Linux where ``addrlen <
    SOCKADDR_UN_SIZE`` is the conventional shape (BSD compatibility,
    abstract-namespace forward compat).

    Abstract namespace — the ``@name`` convention (Linux only):

    When ``path`` starts with ASCII ``@`` (0x40), the buffer is
    encoded as a Linux *abstract namespace* address instead of a
    filesystem pathname: the family bytes are written as usual,
    then ``sun_path[0]`` is set to the NUL marker (0x00) that
    tells the kernel "abstract, not pathname", and the name octets
    (every byte after the ``@``) follow immediately. **No trailing
    NUL is written** for abstract names: the Linux kernel treats
    ``sun_path[0] == 0`` as the abstract flag and takes the name
    length from ``addrlen`` alone, so ``addrlen`` must cover
    exactly the name::

        abstract:   addrlen = 2 (family bytes) + 1 (0x00 marker) + len(name)
        pathname:   addrlen = 2 (family bytes) + len(path) + 1 (NUL)

    e.g. ``@hyrxmq`` (6 name bytes) → ``addrlen = 9``; the same
    string without the ``@`` would give ``addrlen = 9`` too, but
    with a trailing NUL and no marker byte. No socket file is
    created (or unlinked) for an abstract name — the kernel keeps
    it only while a listening socket holds it.

    A NUL byte inside an abstract name is rejected by the same
    embedded-NUL check as for pathname sockets. A name that does
    not fit ``sun_path`` minus the 1-byte marker raises
    ``Error("sockaddr_un: abstract name too long (...)")``.

    Portability rows:

    - Linux: ``SOCKADDR_UN_SIZE`` = 110, ``SUN_PATH_MAX`` = 108;
      ``@name`` binds in the abstract namespace (kernel rule
      ``sun_path[0] == 0``).
    - macOS / BSD: ``SOCKADDR_UN_SIZE`` = 106, ``SUN_PATH_MAX`` =
      104; abstract sockets do not exist there (``sun_path[0]``
      is ``sun_len``, and the kernel has no abstract rule), so an
      ``@name`` path raises :class:`Error` before any buffer
      write.

    Raises :class:`Error` (with ``"sockaddr_un: path too long"``) if
    the encoded path doesn't fit the platform's ``sun_path`` field,
    (with ``"sockaddr_un: abstract name too long"``) if an abstract
    name doesn't fit ``sun_path`` minus the 1-byte marker, and (on
    non-Linux targets) for any ``@name`` path.
    """
    var path_bytes = path.byte_length()
    var pp = path.unsafe_ptr()
    var is_abstract = path_bytes > 0 and pp[0] == 0x40  # '@'
    # The name octets are everything after the '@' marker byte.
    var name_bytes = path_bytes - (1 if is_abstract else 0)

    comptime if CompilationTarget.is_macos():
        if is_abstract:
            raise Error(
                "sockaddr_un: abstract namespace (@name) requires"
                + " Linux; macOS/BSD sockaddr_un has no abstract sockets"
            )
    if is_abstract:
        # Marker (sun_path[0] = 0x00) + name must fit sun_path:
        # name_bytes + 1 <= SUN_PATH_MAX, i.e. the same
        # SUN_PATH_MAX - 1 usable-byte budget as the NUL-terminated
        # pathname branch.
        if name_bytes >= SUN_PATH_MAX:
            raise Error(
                "sockaddr_un: abstract name too long ("
                + String(name_bytes)
                + " bytes, limit "
                + String(SUN_PATH_MAX - 1)
                + ")"
            )
    else:
        if path_bytes >= SUN_PATH_MAX:
            raise Error(
                "sockaddr_un: path too long ("
                + String(path_bytes)
                + " bytes, limit "
                + String(SUN_PATH_MAX - 1)
                + ")"
            )
    # Reject embedded NUL (would terminate the C string early and
    # bind to a shorter prefix path silently; for abstract names it
    # would make the kernel-visible name ambiguous for the
    # String-based API). Covers the abstract name octets too.
    for i in range(path_bytes):
        if pp[i] == 0:
            raise Error("sockaddr_un: embedded NUL in path")

    var path_offset: Int
    comptime if CompilationTarget.is_macos():
        # BSD: [0]=sun_len, [1]=sun_family, [2..]=sun_path
        (buf + 0).unsafe_write(UInt8(Int(SOCKADDR_UN_SIZE)))  # sun_len
        (buf + 1).unsafe_write(UInt8(Int(AF_UNIX)))  # sun_family
        path_offset = 2
    else:
        # Linux: sa_family_t is uint16 little-endian (AF_UNIX=1)
        (buf + 0).unsafe_write(UInt8(1))
        (buf + 1).unsafe_write(UInt8(0))
        path_offset = 2

    if is_abstract:
        # Linux abstract: sun_path[0] = 0x00 marker, then the name
        # octets, NO trailing NUL (addrlen carries the length).
        (buf + path_offset).unsafe_write(UInt8(0))
        for i in range(name_bytes):
            (buf + path_offset + 1 + i).unsafe_write(pp[1 + i])
        return c_uint(path_offset + 1 + name_bytes)

    for i in range(path_bytes):
        (buf + path_offset + i).unsafe_write(pp[i])
    # NUL terminator
    (buf + path_offset + path_bytes).unsafe_write(UInt8(0))

    return c_uint(path_offset + path_bytes + 1)


def read_path_from_sockaddr_un(
    buf: UnsafePointer[UInt8, _],
    used_len: c_uint,
) raises -> String:
    """Decode a ``sockaddr_un`` buffer back into a Python-style
    path string. Used by :meth:`UnixListener.local_path`
    after ``getsockname(2)``.

    The path is read from offset 2 (past the family-prefix bytes
    on both Linux + macOS) up to the first NUL byte or
    ``used_len - 2``, whichever comes first.
    """
    var path_offset: Int = 2
    var max_len = Int(used_len) - path_offset
    if max_len < 0:
        return String("")
    if max_len > SUN_PATH_MAX:
        max_len = SUN_PATH_MAX
    var out = String(capacity=max_len + 1)
    for i in range(max_len):
        var b = (buf + path_offset + i).load()
        if b == 0:
            break
        out += chr(Int(b))
    return out^


def unlink_path(var path: String) -> c_int:
    """Wrapper around ``unlink(2)``. Returns 0 on success, -1 on
    failure (errno set; check ``get_errno()``).

    ``as_c_string_slice`` is mutating, so we ask for an owning
    ``var`` to avoid silently mutating the caller's string."""
    return external_call["unlink", c_int](path.as_c_string_slice())
