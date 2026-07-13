"""Worker-target trait for the multicore :class:`Scheduler`.

The trait defines the *only* coupling point between
:mod:`flare.runtime` (the multicore lifecycle: pthread spawn /
join, listener bind, shared-stop flag, drain accounting) and the
HTTP / HTTP/2 / future-protocol layers above it. Every protocol
that wants to ride the multicore scheduler implements
:trait:`Frontend` once (HTTP/1.1, the unified HTTP/1.1+HTTP/2
preface-peek path, the io_uring buffer-ring path, the static-
response fast path); the scheduler stays oblivious to which one
runs.

Before this inversion :mod:`flare.runtime.scheduler` imported
directly from :mod:`flare.http._server_reactor_impl`,
:mod:`flare.http._unified_reactor_impl`,
:mod:`flare.http.handler`, :mod:`flare.http.server`,
:mod:`flare.http.static_response`, and
:mod:`flare.http2.server`. That's a layering violation -- the
runtime package should *not* depend on protocol packages -- and
the cycle blocked any work where the H1/H2/H3 surfaces wanted to
call back into runtime primitives without circling. Pushing the
dispatch into a protocol-side :class:`Frontend` impl breaks the
cycle: the runtime depends on the trait only, the trait lives in
:mod:`flare.runtime`, and concrete impls live where the protocol
itself does.

## Contract

Each worker thread calls :meth:`Frontend.run_worker` exactly once
with:

- ``listener_fd``: the socket fd this worker should accept on.
  Whether that fd is a per-worker ``SO_REUSEPORT`` listener or a
  shared listener the kernel routes via ``EPOLLEXCLUSIVE`` is the
  scheduler's binding decision (driven by the ``FLARE_REUSEPORT_WORKERS``
  env knob and :meth:`Frontend.requires_per_worker_listener`).
  The frontend never closes ``listener_fd`` -- the scheduler owns
  the lifetime.
- ``stopping``: a heap-allocated ``Bool`` shared across every
  worker. The frontend's poll loop must observe this flag every
  iteration; when it becomes ``True`` the loop exits and the
  worker thread returns.

The frontend is :class:`Movable` + :class:`Copyable` so the
scheduler can ``H.copy()`` it once per worker before spawning;
each worker then owns its own copy. Frontend implementations that
want to share expensive state across workers should put that
state behind an :class:`UnsafePointer` or a similar shared-
reference holder so the per-worker copy stays cheap.
"""


trait Frontend(Copyable, ImplicitlyDestructible, Movable):
    """Multicore-scheduler worker-target trait.

    Implementations bridge the scheduler's lifecycle (pthread
    spawn, listener bind, stop flag, drain) with a protocol-
    specific accept-and-serve loop. The scheduler does not know
    which protocol is running; the frontend's
    :meth:`run_worker` body is what actually serves traffic on
    each accepted connection.

    Frontends are copied per worker via the trait's
    :class:`Copyable` super-trait; implementations should keep
    expensive shared state behind an :class:`UnsafePointer` or a
    similar shared-reference holder so the per-worker copy is
    cheap.
    """

    def run_worker(
        mut self, listener_fd: Int, mut stopping: Bool, stats_addr: Int
    ):
        """Run this worker's accept-and-serve loop until ``stopping`` flips.

        Args:
            listener_fd: The socket fd this worker accepts on.
                The scheduler owns the fd; the frontend never
                closes it.
            stopping: Heap-shared stop flag; observed every loop
                iteration. Frontend exits cleanly when ``True``.
            stats_addr: Heap address of this worker's two-slot
                ``Int64`` stats cell (live-connection snapshot +
                exit status), or 0 to disable. The frontend forwards
                it into the reactor loop so the Scheduler can read a
                real drain report and detect worker crashes.
        """
        ...

    def requires_per_worker_listener(self) -> Bool:
        """Return ``True`` if this frontend cannot share a single listener fd.

        Some serving paths (notably the io_uring buffer-ring
        path) need each worker to have its own ``SO_REUSEPORT``
        listener -- the kernel-side fan-out happens at accept
        time and a shared listener with ``EPOLLEXCLUSIVE`` would
        funnel every accept event through one entry. The
        scheduler honours this signal: when it returns ``True``
        the scheduler always binds per-worker SO_REUSEPORT
        listeners, ignoring the ``FLARE_REUSEPORT_WORKERS=0``
        env knob.

        Default false: the frontend is fine with whichever
        listener strategy the scheduler picks.
        """
        ...
