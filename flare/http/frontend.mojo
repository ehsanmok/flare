"""HTTP frontends for the multicore :class:`flare.runtime.Scheduler`.

A :trait:`flare.runtime.Frontend` impl is the *only* coupling
point between the runtime's multicore lifecycle and a serving
protocol's accept-and-serve loop. This module ships every HTTP-
flavoured frontend flare needs:

- :class:`HttpFrontend[H]` — the dynamic-handler frontend. Wraps
  a user :trait:`Handler` plus a :class:`ServerConfig` and an
  optional :class:`flare.http2.Http2Config`. Selects between the
  HTTP/1.1-only loop, the unified HTTP/1.1 + HTTP/2 preface-peek
  loop, and the io_uring buffer-ring loop based on its config
  flags + the runtime backend probe.
- :class:`StaticHttpFrontend` — the pre-encoded
  :class:`StaticResponse` frontend. Dedicated fast path for
  workloads whose every response is identical (the TFB plaintext
  gate; production health-check / fixed-response endpoints).
  Replaces the prior ``StaticScheduler`` type which baked the
  same dispatch into the runtime layer.

The runtime no longer imports anything from :mod:`flare.http`;
both frontends here import the reactor entry points and serve as
the inversion boundary. See :mod:`flare.runtime.frontend` for the
trait contract.
"""

from std.os import getenv
from std.sys.info import CompilationTarget

from flare.http.handler import Handler
from flare.http.server import ServerConfig
from flare.http._server_reactor_impl import (
    run_reactor_loop_shared,
    run_reactor_loop_static_shared,
    run_uring_bufring_reactor_loop_shared,
)
from flare.http._unified_reactor_impl import run_unified_reactor_loop_shared
from flare.http.static_response import StaticResponse
from flare.http2.server import Http2Config
from flare.runtime.frontend import Frontend
from flare.runtime.uring_reactor import use_uring_backend


struct HttpFrontend[H: Handler & Copyable](Copyable, Frontend, Movable):
    """Dynamic-handler HTTP frontend for the multicore scheduler.

    Carries the per-worker HTTP state (handler, request config,
    HTTP/2 settings, auto-protocol toggle) and dispatches into
    one of three reactor entry points per accepted connection:

    1. **io_uring buffer-ring path** (Linux + ``use_bufring``):
       :func:`run_uring_bufring_reactor_loop_shared`. Signalled
       to the scheduler via :meth:`requires_per_worker_listener`
       so each worker gets its own SO_REUSEPORT listener.
    2. **Unified HTTP/1.1 + HTTP/2** (``auto_protocol``):
       :func:`run_unified_reactor_loop_shared`. Per-connection
       preface peek selects the protocol.
    3. **HTTP/1.1 only** (default):
       :func:`run_reactor_loop_shared`.

    The frontend is :class:`Copyable` so the scheduler can clone
    it once per worker before pthread spawn; expensive shared
    state inside the user handler should be wrapped behind an
    :class:`UnsafePointer` so per-worker copies stay cheap.
    """

    var handler: Self.H
    var config: ServerConfig
    var h2_config: Http2Config
    var auto_protocol: Bool

    def __init__(
        out self,
        var handler: Self.H,
        var config: ServerConfig,
        var h2_config: Http2Config = Http2Config(),
        auto_protocol: Bool = False,
    ):
        """Build a frontend with the given handler + config combo.

        Args:
            handler: User request handler; cloned per worker.
            config: Server configuration; cloned per worker.
            h2_config: HTTP/2 SETTINGS used by the unified path.
                Ignored when ``auto_protocol`` is ``False``.
            auto_protocol: When ``True``, every accepted
                connection auto-dispatches to the right per-conn
                state machine via the RFC 9113 §3.4 preface peek.
                When ``False`` (default), the worker speaks
                HTTP/1.1 exclusively.
        """
        self.handler = handler^
        self.config = config^
        self.h2_config = h2_config^
        self.auto_protocol = auto_protocol

    def requires_per_worker_listener(self) -> Bool:
        """The io_uring buffer-ring path needs per-worker listeners.

        See the trait docstring for the full rationale: the
        kernel-side accept fan-out happens at multishot accept
        arming time, and a shared listener with EPOLLEXCLUSIVE
        would funnel every accept event through one entry. For
        every other backend the scheduler is free to pick its
        listener strategy from the ``FLARE_REUSEPORT_WORKERS``
        env knob (which still applies to the epoll handler /
        unified paths).
        """
        comptime if CompilationTarget.is_linux():
            if use_uring_backend() and self.config.use_bufring:
                return True
        return False

    def run_worker(
        mut self, listener_fd: Int, mut stopping: Bool, stats_addr: Int
    ):
        """Pick the reactor entry point and run it until ``stopping`` flips."""
        try:
            comptime if CompilationTarget.is_linux():
                if use_uring_backend() and self.config.use_bufring:
                    run_uring_bufring_reactor_loop_shared[Self.H](
                        listener_fd,
                        self.config,
                        self.handler,
                        stopping,
                        stats_addr,
                    )
                    return
            if self.auto_protocol:
                run_unified_reactor_loop_shared[Self.H](
                    listener_fd,
                    self.config,
                    self.h2_config.copy(),
                    self.handler,
                    stopping,
                    stats_addr,
                )
            else:
                run_reactor_loop_shared[Self.H](
                    listener_fd,
                    self.config,
                    self.handler,
                    stopping,
                    stats_addr,
                )
        except:
            pass


struct StaticHttpFrontend(Copyable, Frontend, Movable):
    """Pre-encoded :class:`StaticResponse` frontend.

    Replaces the prior runtime-side ``StaticScheduler`` type. The
    serving loop is the static fast-path
    :func:`run_reactor_loop_static_shared`; every accepted
    connection emits the same canned bytes, sized once at startup.

    Used by :meth:`HttpServer.serve_static` for the TFB plaintext
    gate and any production endpoint that returns a fixed body.
    """

    var config: ServerConfig
    var resp: StaticResponse

    def __init__(
        out self,
        var config: ServerConfig,
        var resp: StaticResponse,
    ):
        """Build a static-response frontend.

        Args:
            config: Server configuration; cloned per worker.
            resp: Pre-encoded response bytes; cloned per worker.
        """
        self.config = config^
        self.resp = resp^

    def requires_per_worker_listener(self) -> Bool:
        """The static path is fine with either listener strategy.

        It honours the ``FLARE_REUSEPORT_WORKERS`` env knob
        directly (per-worker SO_REUSEPORT by default; shared
        EPOLLEXCLUSIVE listener when the knob is ``0``).
        """
        return False

    def run_worker(
        mut self, listener_fd: Int, mut stopping: Bool, stats_addr: Int
    ):
        """Drive the static-response fast path."""
        try:
            run_reactor_loop_static_shared(
                listener_fd,
                self.config,
                self.resp,
                stopping,
                stats_addr,
            )
        except:
            pass
