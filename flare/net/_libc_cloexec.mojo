"""Close-on-exec for flare's fds, split out of ``_libc``.

Re-exported from :mod:`flare.net._libc`, whose ``_socket`` and
``_accept`` use these so every socket is close-on-exec.
"""

from std.ffi import c_int, c_ulong, external_call
from std.sys.info import CompilationTarget


comptime F_GETFD: c_int = 1
comptime F_SETFD: c_int = 2
comptime FD_CLOEXEC: c_int = 1
comptime _SOCK_CLOEXEC_LINUX: c_int = 0o2000000
"""``SOCK_CLOEXEC`` on Linux: or-ed into the socket type, and the flag
``accept4`` takes. macOS has neither and sets ``FD_CLOEXEC`` after."""
comptime _FIOCLEX_MACOS: c_ulong = 0x20006601
"""``FIOCLEX`` on macOS: ``_IO('f', 1)``."""


def _set_cloexec(fd: c_int) -> None:
    """Set ``FD_CLOEXEC`` on ``fd``; a no-op for an invalid fd.

    macOS uses ``ioctl(fd, FIOCLEX)`` rather than ``fcntl(F_SETFD)``:
    ``fcntl`` is variadic, and ``external_call`` corrupts the third
    argument of a variadic call on macOS/arm64 (the reason
    ``RawSocket.set_nonblocking`` goes through the C wrapper there).
    ``FIOCLEX`` takes no third argument.
    """
    if fd < c_int(0):
        return
    comptime if CompilationTarget.is_linux():
        _ = external_call["fcntl", c_int](fd, F_SETFD, FD_CLOEXEC)
    else:
        _ = external_call["ioctl", c_int](fd, _FIOCLEX_MACOS)
