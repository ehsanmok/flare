"""``flare.testing`` — handler + middleware testing helpers.

This package ships the in-process testing surface that lets
handlers and middleware be exercised without a real reactor:

- :class:`TestClient[H]` — FastAPI-style client that
  synthesises a :class:`flare.http.Request`, runs it through a
  handler ``H``, and returns the captured
  :class:`flare.http.Response`. No socket, no reactor, no
  thread.

Existing test infrastructure (``flare.testing.fork_server`` for
integration tests that need a real socket) continues to live in
its own module; ``TestClient`` complements it for the much
larger universe of pure handler-level tests.
"""

from .client import H2cTestClient, TestClient
from .fork_server import fork_server, kill_forked_server
