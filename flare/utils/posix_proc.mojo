"""POSIX process-control helpers thin-wrapped over ``external_call``.

A handful of POSIX primitives -- ``fork(2)``, ``waitpid(2)``,
``kill(2)``, ``usleep(3)``, ``_exit(2)``, ``getpid(2)`` -- show up
repeatedly across flare tests, examples, and a few internal
modules (``flare.testing.fork_server``,
``flare.runtime._libc_time``). The Mojo stdlib doesn't expose them
yet, so every site re-declares the same five-line ``external_call``
thunks. This module centralises them so the next contributor
adding a fork-and-serve test reaches for one import instead of
copy-pasting the FFI stanza.

Threading + safety:

* These are direct passthroughs to the libc symbols. No
  ``OwnedDLHandle`` plumbing -- libc is process-wide, always
  resolvable, and never unloaded out from under us.
* Signatures use ``c_int`` from ``std.ffi`` for the kernel-shaped
  arguments; the public surface accepts and returns ``Int`` for
  ergonomics so call sites don't need to litter ``c_int(...)``
  conversions.
* :func:`exit` calls ``_exit(2)`` (the underscore version) to
  skip ``atexit`` handlers and stdio flush -- the right shape
  inside a forked child whose only job is to call ``serve()``
  and then disappear.

Example:

```mojo
from flare.utils import fork, kill, usleep, waitpid, exit, SIGKILL

var pid = fork()
if pid == 0:
    # ... child work ...
    exit()
usleep(150_000)        # let child enter serve()
# ... parent work ...
_ = kill(pid, SIGKILL)
waitpid(pid)
```
"""

from std.ffi import c_int, external_call


# ── Signal numbers ──────────────────────────────────────────────────────────

comptime SIGKILL: Int = 9
"""POSIX ``SIGKILL`` signal number. Forces immediate, uncatchable
termination of the target process. Pass to :func:`kill`."""

comptime SIGTERM: Int = 15
"""POSIX ``SIGTERM`` signal number. The polite "please shut down"
signal; can be caught and handled. Use this when the child has a
graceful shutdown path; reach for :data:`SIGKILL` when it doesn't
or you don't want to wait."""

comptime SIGINT: Int = 2
"""POSIX ``SIGINT`` signal number. Same shape as ``Ctrl-C`` from a
terminal; can be caught."""


# ── Process control ────────────────────────────────────────────────────────


@always_inline
def fork() -> Int:
    """Thin wrapper around POSIX ``fork(2)``.

    Returns:
        ``0`` in the child process, the child's PID (a positive
        ``Int``) in the parent. Negative values indicate failure;
        check ``errno`` via the standard ``external_call`` shape
        if you need to differentiate.
    """
    return Int(external_call["fork", c_int]())


@always_inline
def waitpid(pid: Int):
    """Thin wrapper around POSIX ``waitpid(2)`` with ``status=NULL``
    and ``options=0``.

    Blocks until ``pid`` exits and reaps its zombie. The exit
    status is intentionally ignored -- callers reaching for this
    function are typically tearing down a forked test child where
    "did the child exit cleanly?" isn't the assertion.

    Args:
        pid: The child PID returned by :func:`fork`.
    """
    _ = external_call["waitpid", c_int](c_int(pid), 0, c_int(0))


@always_inline
def kill(pid: Int, sig: Int) -> Int:
    """Thin wrapper around POSIX ``kill(2)``.

    Args:
        pid: Target PID.
        sig: Signal number; pass :data:`SIGKILL` / :data:`SIGTERM`
             / :data:`SIGINT`.

    Only a single process is signalled. ``pid <= 0`` returns ``-1``
    without calling ``kill(2)``: there ``0`` means the caller's process
    group and ``-1`` every process the user may signal, and the usual
    way to reach them is a failed ``fork()``'s ``-1`` passed straight
    through.

    Returns:
        ``0`` on success, ``-1`` on failure.
    """
    if pid <= 0:
        return -1
    return Int(external_call["kill", c_int](c_int(pid), c_int(sig)))


@always_inline
def exit(code: Int = 0):
    """Thin wrapper around POSIX ``_exit(2)``.

    Skips ``atexit`` handlers and stdio buffer flush -- the right
    primitive for a forked child whose work has finished and
    needs to disappear without clobbering the parent's open file
    descriptors via shared stdio buffers.

    Args:
        code: Process exit status (usually ``0``).
    """
    _ = external_call["_exit", c_int](c_int(code))


@always_inline
def usleep(microseconds: Int):
    """Thin wrapper around POSIX ``usleep(3)``.

    Suspends the calling thread for at least ``microseconds``;
    the kernel may overshoot under load. Used in fork-and-serve
    tests as the "let the child enter ``serve()`` before driving
    a client" pause.

    Args:
        microseconds: Sleep duration; ``150_000`` (150 ms) is the
            standard CI-runner-safe value.
    """
    _ = external_call["usleep", c_int](c_int(microseconds))


@always_inline
def getpid() -> Int:
    """Thin wrapper around POSIX ``getpid(2)``.

    Returns:
        The calling process's PID.
    """
    return Int(external_call["getpid", c_int]())
