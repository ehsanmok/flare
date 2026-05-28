"""Cross-cutting utility helpers that don't fit any other layer.

The first inhabitant is :mod:`flare.utils.posix_proc` -- thin
wrappers over POSIX ``fork`` / ``waitpid`` / ``kill`` / ``usleep``
/ ``_exit`` / ``getpid`` that the Mojo stdlib doesn't expose yet.
A handful of flare tests, examples, and internal modules
(``flare.testing.fork_server``, ``flare.runtime._libc_time``) all
need the same five-line ``external_call`` thunks; this module is
the one canonical home for them.

Future inhabitants belong here when they're (a) low-level enough
that they don't fit a protocol-shaped subpackage like
``flare.http`` / ``flare.tls`` and (b) cross-cutting enough that
they're consumed by more than one such subpackage. Anything more
specific should land in the most-specific subpackage that uses it.
"""

from .posix_proc import (
    SIGINT,
    SIGKILL,
    SIGTERM,
    exit,
    fork,
    getpid,
    kill,
    usleep,
    waitpid,
)
from .dylib import find_flare_lib
