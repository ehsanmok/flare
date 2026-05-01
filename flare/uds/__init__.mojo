"""``flare.uds`` — Unix domain socket primitives.

UDS gives a flare-process two doors that TCP doesn't:

1. **Sidecar IPC.** A process pinned to a single host can talk to a
   local sibling (logging agent, metrics scraper, in-rack mesh
   sidecar) without going through the network stack — no ARP, no
   IP routing, no TCP retransmit timer, no TLS. ~3-5x lower latency
   than ``127.0.0.1`` TCP for short request/response pairs.
2. **Filesystem-permission AAA.** ``chmod`` / ``chown`` on the
   socket path are the entire access-control story; no per-message
   token, no TLS client cert. The kernel enforces it before
   ``accept(2)`` ever fires.

The wire shape is a stream-oriented byte pipe identical to
``flare.tcp``: same ``read`` / ``write`` / ``write_all`` /
``shutdown`` semantics. The differences are address-family-only:

- The "address" is a filesystem path (Linux: 108 bytes; macOS BSD:
  104 bytes — flare uses 108 in the public surface but enforces
  the BSD-shorter limit on macOS).
- ``SO_REUSEADDR`` doesn't apply (UDS doesn't have a port to
  contend on); rebinding to the same path requires the previous
  socket to be ``unlink(2)``'d. ``UnixListener.bind`` does this
  cleanup automatically when ``unlink_existing=True`` (default).
- ``TCP_NODELAY`` doesn't apply (no Nagle on UDS).
- ``SO_REUSEPORT`` works on Linux >= 4.5 for UDS too — the
  multi-worker shared-listener scheduler in
  :mod:`flare.runtime.scheduler` can balance UDS connections
  across worker pthreads exactly the way it does for TCP.

Public surface:

- :class:`UnixListener` — bound + listening AF_UNIX socket.
- :class:`UnixStream` — connected AF_UNIX byte stream.
- :func:`accept_uds_fd` — accept on a borrowed listener fd
  (multi-worker scheduler hand-off path; mirrors
  :func:`flare.tcp.accept_fd`).

Example:

```mojo
from flare.uds import UnixListener

var l = UnixListener.bind("/tmp/flare-sidecar.sock")
while True:
    var s = l.accept()
    s.write_all("hello".as_bytes())
    s.close()
```

Out of scope for the v0.7 ship:

- Abstract namespace addresses (Linux-only ``\0``-prefixed path);
  follow-up if a downstream sidecar request comes in.
- ``SCM_RIGHTS`` fd passing; same — interesting for hot
  binary upgrades, ship when there's a caller.
- macOS Mach-port shim; the macOS UDS path goes through the
  POSIX shim layer, no Mach involvement.
"""

from .listener import UnixListener, accept_uds_fd
from .stream import UnixStream
