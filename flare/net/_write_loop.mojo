"""The ``write_all`` loop shared by ``TcpStream`` and ``UnixStream``.

Both streams implement ``write_all`` as "call ``send(2)`` until every byte is
out". The loop lives here, generic over a one-shot writer, so that it can be
unit-tested against a writer that returns results ``send(2)`` never returns
for a blocking stream socket on Linux or macOS (notably ``0`` for a non-empty
buffer, which POSIX permits). See ``formal/Flare/Bugs/NET_02.lean``.
"""

from .error import NetworkError


trait _ChunkWriter:
    """A one-shot writer: ``_write_chunk`` sends *some* prefix of ``data``
    and returns how many bytes it took (``write(2)`` / ``send(2)`` semantics).
    """

    def _write_chunk(self, data: Span[UInt8, _]) raises -> Int:
        ...


def write_all_chunks[W: _ChunkWriter](writer: W, data: Span[UInt8, _]) raises:
    """Write all of ``data`` through ``writer``, one chunk at a time.

    Args:
        writer: The one-shot writer (a ``TcpStream`` or ``UnixStream``).
        data: The bytes to send completely.

    Raises:
        NetworkError: If a chunk write reports that no byte was written
            while bytes remain (a ``send`` return of ``0``). Anything the
            writer itself raises is propagated unchanged.
    """
    var total = len(data)
    var ptr = data.unsafe_ptr()
    var sent = 0
    while sent < total:
        var chunk = Span[UInt8, _](
            unsafe_ptr=ptr.unsafe_offset(sent), length=total - sent
        )
        var n = writer._write_chunk(chunk)
        if n <= 0:
            # POSIX lets send(2) return 0 for a non-empty buffer. Adding 0
            # to ``sent`` would call send again with the same arguments,
            # forever; no progress means the stream cannot be written.
            raise NetworkError(
                "write_all: send returned "
                + String(n)
                + " after "
                + String(sent)
                + "/"
                + String(total)
                + " bytes"
            )
        sent += n
