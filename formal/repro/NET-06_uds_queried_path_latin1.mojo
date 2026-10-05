# PLATFORM: any
# RESOLVED: NET-06 fixed on fix/formal-findings
"""NET-06: UnixListener.queried_local_path() garbles non-ASCII paths.

Lean: Flare.Bugs.NET_06.decode_encode_not_id (counterexample) and
Flare.Bugs.NET_06.decodeFixed_encode (fix meets spec).
flare/uds/_libc.mojo:55-134 @59bda50.

Expected: queried_local_path() == the path passed to bind().
Before the fix: fill_sockaddr_un copies the path's UTF-8 bytes, but
read_path_from_sockaddr_un turns every byte b into chr(b), i.e. decodes
Latin-1 and re-encodes each byte >= 0x80 as two UTF-8 bytes. A path
containing "é" (C3 A9) comes back as "Ã©".

Minimal fix: collect the bytes up to the NUL into a List[UInt8] and
build the String from them as UTF-8 (String(unsafe_from_utf8=...)),
mirroring fill_sockaddr_un.
"""

from flare.uds import UnixListener
from flare.uds._libc import unlink_path


def main() raises:
    var p = String("/tmp/flare_net06_é.sock")
    _ = unlink_path(p)
    var l = UnixListener.bind(p)
    var q = l.queried_local_path()
    if q != p:
        print(
            "BUG REPRODUCED: bound",
            p,
            "(",
            p.byte_length(),
            "bytes) but queried_local_path() returned",
            q,
            "(",
            q.byte_length(),
            "bytes)",
        )
        raise Error("NET-06")
    print("OK: queried_local_path() round-trips", q)
