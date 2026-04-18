"""flare.runtime — event-loop primitives for the Stage 1 reactor.

Public exports:
    Reactor, Event, INTEREST_READ, INTEREST_WRITE,
    EVENT_READABLE, EVENT_WRITABLE, EVENT_ERROR, EVENT_HUP,
    WAKEUP_TOKEN

``Reactor`` wraps ``epoll`` (Linux) and ``kqueue`` (macOS) behind a uniform
API. Use it to build single-threaded servers that handle many concurrent
connections from one OS thread. See the module docstring on ``Reactor`` for
an end-to-end example.
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
