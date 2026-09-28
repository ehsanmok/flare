"""Fork-and-serve helpers for cookbook examples and integration tests.

Most flare examples want to demo a real end-to-end flow: bind a
port, accept connections, drive them with the real client.
``HttpServer.serve(handler)`` blocks the calling thread, so a
single-process example can't both serve and connect to itself.

The standard Unix workaround is ``fork(2)``: the parent reads the
bound port, forks, the child calls ``serve()`` (blocks forever),
the parent uses the port for client work, then the parent
SIGKILLs the child on cleanup. The mechanics aren't interesting
-- five FFI thunks plus a brief startup sleep -- but they're 50
LoC of noise at the top of every multi-process example.

Usage:

```mojo
from flare.testing import fork_server, kill_forked_server


def my_handler(req: Request) raises -> Response:
    return ok("hi")


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port  # parent reads before fork

    var pid = fork_server(srv^, my_handler)  # forks, parent waits 150 ms
    # ... parent uses ``port`` to drive HttpClient, etc. ...
    kill_forked_server(pid)                  # SIGKILL + waitpid
```

The bare-function and ``Handler``-struct overloads both forward
to ``HttpServer.serve``, so anything that ``HttpServer.serve``
accepts is acceptable here. The startup sleep
(``startup_us=150_000`` by default) covers the kernel-side
``listen``/``accept`` ramp on the slowest CI runners; tune it
down for tighter integration tests.
"""

from flare.http import Handler, HttpServer, Request, Response
from flare.utils import (
    SIGKILL,
    exit,
    fork,
    kill,
    usleep,
    waitpid,
)


def fork_server(
    var srv: HttpServer,
    handler: def(Request) raises thin -> Response,
    startup_us: Int = 150_000,
) raises -> Int:
    """Fork a child, run ``srv.serve(handler)`` in it, return the
    child PID to the parent after a brief startup wait.

    The bare-function overload. For ``Handler``-struct shapes use
    the parametric overload below.

    Args:
        srv: A bound ``HttpServer`` (the parent reads
            ``srv.local_addr()`` *before* the call so it knows
            the port). Moved into the child via the standard
            ``fork(2)`` semantics; the parent's reference is
            consumed.
        handler: The same ``def(Request) raises -> Response`` shape
            ``HttpServer.serve`` accepts.
        startup_us: Microseconds the parent sleeps after the fork
            so the child has time to enter ``serve()``. Default
            150 ms covers the slowest CI runners.

    Returns:
        Child PID (positive int). Pass to :func:`kill_forked_server`
        on teardown.

    Raises:
        Error: If ``fork(2)`` fails. Failures inside the child's
            ``serve()`` are swallowed (the child ``_exit``s); the
            parent only ever sees the PID.
    """
    var pid = fork()
    if pid < 0:
        # It returned -1 to the caller, whose kill_forked_server(-1) then
        # sent SIGKILL to every process the user could signal.
        raise Error("fork_server: fork() failed")
    if pid == 0:
        try:
            srv.serve(handler)
        except:
            pass
        exit()
    usleep(startup_us)
    return pid


def fork_server[
    H: Handler
](
    var srv: HttpServer,
    var handler: H,
    startup_us: Int = 150_000,
) raises -> Int:
    """Fork-and-serve overload for ``Handler``-struct shapes.

    Identical semantics to the bare-function overload; this one
    exists so ``Router``, middleware wrappers, and
    user-defined ``Handler`` structs can flow through the helper
    without an ``FnHandler`` shim. ``Copyable`` is *not* required
    -- the child process runs the single-worker ``HttpServer.serve``
    path, which only needs ``Handler``.

    Args:
        srv: A bound ``HttpServer``. Moved into the child.
        handler: Any ``Handler`` struct.
        startup_us: Parent-side startup sleep (microseconds).

    Returns:
        Child PID.

    Raises:
        Error: If ``fork(2)`` fails.
    """
    var pid = fork()
    if pid < 0:
        # It returned -1 to the caller, whose kill_forked_server(-1) then
        # sent SIGKILL to every process the user could signal.
        raise Error("fork_server: fork() failed")
    if pid == 0:
        try:
            srv.serve(handler^)
        except:
            pass
        exit()
    usleep(startup_us)
    return pid


def kill_forked_server(pid: Int):
    """SIGKILL a forked-server child and ``waitpid`` for it.

    Args:
        pid: The PID returned by :func:`fork_server`.
    """
    if pid <= 0:
        return
    _ = kill(pid, SIGKILL)
    waitpid(pid)
