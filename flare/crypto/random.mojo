"""``flare.crypto.random`` -- bytes from the operating system's CSPRNG.

Every unpredictable byte flare needs comes from here: WebSocket
masking keys and handshake nonces, QUIC connection IDs, stateless
reset and Retry keys, session identifiers. Before this module each
of those read ``/dev/urandom`` itself, and three of them fell back to
a clock-derived or constant value when the open failed. Opening a
file fails under fd exhaustion, which a remote peer can cause, so
the fallback was reachable on demand.

This module calls ``getentropy(3)`` instead. It is in macOS libc and
in glibc since 2.25, needs no file descriptor, and blocks only until
the kernel pool is first seeded at boot. There is no fallback: if
the kernel cannot supply entropy the call raises, and the caller
fails closed.

## Public API

```mojo
from flare.crypto.random import random_bytes, fill_random
```

* :func:`random_bytes(n) raises -> List[UInt8]` -- ``n`` fresh bytes.
* :func:`fill_random(mut buf) raises` -- overwrite every byte of an
  existing buffer.
"""

from std.ffi import external_call, c_int, c_size_t, get_errno
from std.memory import Pointer


# getentropy(2) refuses requests larger than this (EIO on Linux,
# EINVAL on macOS), so longer fills are issued in chunks.
comptime _GETENTROPY_MAX: Int = 256


def fill_random(mut buf: List[UInt8]) raises:
    """Overwrite every byte of ``buf`` with CSPRNG output.

    Args:
        buf: Buffer to fill. Its length is unchanged.

    Raises:
        Error: If the kernel cannot supply entropy. There is no
            fallback source.
    """
    var n = len(buf)
    var off = 0
    var p = buf.unsafe_ptr()
    while off < n:
        var take = n - off
        if take > _GETENTROPY_MAX:
            take = _GETENTROPY_MAX
        var rc = external_call["getentropy", c_int](
            p.unsafe_offset(off), c_size_t(take)
        )
        if rc != 0:
            raise Error(
                "fill_random: getentropy failed (errno "
                + String(get_errno().value)
                + ")"
            )
        off += take


def random_bytes(n: Int) raises -> List[UInt8]:
    """Return ``n`` bytes of CSPRNG output.

    Args:
        n: Number of bytes. Zero returns an empty list.

    Returns:
        A list of exactly ``n`` unpredictable bytes.

    Raises:
        Error: If ``n`` is negative, or the kernel cannot supply
            entropy.
    """
    if n < 0:
        raise Error("random_bytes: negative length " + String(n))
    var out = List[UInt8](length=n, fill=0)
    fill_random(out)
    return out^
