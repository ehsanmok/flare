# PLATFORM: macos
# RESOLVED: NET-07 fixed on fix/formal-findings
"""NET-07: UnixListener.bind unlinks a live socket whose probe fails with EACCES.

Lean: Flare.Bugs.NET_07.takeover_unlinks_live (counterexample) and
Flare.Bugs.NET_07.prep_safe (fix meets spec).
flare/uds/listener.mojo:163-184 @59bda50.

Expected (docstring 146-153): a stale socket is "one no process is
listening on"; "a live socket raises AddressInUse". Here listener A is
alive and listening at the path, so a second bind must fail.
Before the fix: the liveness probe UnixStream.connect fails with EACCES (the
socket file is not writable by the caller: mode 0 here, or another user's
0600 socket in a shared directory), the bare `except: pass` treats every
failure as "stale", the path is unlinked and the second bind succeeds.
Listener A keeps running but can never be reached again.

Linux: the same happens for a non-root caller; root bypasses the
permission check, so this repro is marked macos (the Linux runner is
root).

Minimal fix: treat only ConnectionRefused (ECONNREFUSED / ENOENT) as
stale; re-raise (or raise AddressInUse) on any other probe error.
"""

from std.ffi import c_int, external_call
from flare.uds import UnixListener
from flare.uds._libc import unlink_path


def _chmod(var path: String, mode: Int) -> c_int:
    return external_call["chmod", c_int](path.as_c_string_span(), c_int(mode))


def main() raises:
    var p = String("/tmp/flare_net07.sock")
    _ = unlink_path(p)
    var a = UnixListener.bind(p)
    if _chmod(p, 0) != 0:
        raise Error("test setup: chmod failed")
    var took_over = False
    var why = String("")
    try:
        var b = UnixListener.bind(p)
        took_over = True
        _ = b.local_path()
    except e:
        why = String(e)
    _ = a.local_path()
    _ = unlink_path(p)
    if took_over:
        print(
            "BUG REPRODUCED: second bind() unlinked the live listener's socket"
            " file (its probe failed with EACCES) and bound the path itself"
        )
        raise Error("NET-07")
    print("OK: second bind() refused while the first listener is live:", why)
