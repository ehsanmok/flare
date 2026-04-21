"""flare.runtime — event-loop primitives for the Stage 1 reactor.

Public exports:
    Reactor, Event, INTEREST_READ, INTEREST_WRITE,
    EVENT_READABLE, EVENT_WRITABLE, EVENT_ERROR, EVENT_HUP,
    WAKEUP_TOKEN, num_cpus, default_worker_count

``Reactor`` wraps ``epoll`` (Linux) and ``kqueue`` (macOS) behind a uniform
API. Use it to build single-threaded servers that handle many concurrent
connections from one OS thread. See the module docstring on ``Reactor`` for
an end-to-end example.

For multicore servers, use ``HttpServer.serve_multicore(handler, num_workers=N)``
and size ``N`` with ``num_cpus()`` (total logical CPUs) or
``default_worker_count()`` (sensible default for IO-bound handlers).
"""

from .event import (
    Event,
    INTEREST_READ,
    INTEREST_WRITE,
    EVENT_READABLE,
    EVENT_WRITABLE,
    EVENT_ERROR,
    EVENT_HUP,
    WAKEUP_TOKEN,
)
from .reactor import Reactor
from .timer_wheel import TimerWheel
from ._thread import num_cpus
from .scheduler import default_worker_count
