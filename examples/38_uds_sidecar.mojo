"""Example 38 — UDS sidecar pipe.

Demonstrates :class:`flare.uds.UnixListener` + :class:`UnixStream`
as a sidecar IPC channel. The "server" (e.g. an in-rack metrics
sidecar) binds an AF_UNIX socket at ``/tmp/flare_sidecar.sock``;
a "client" (e.g. an application worker pinned to the same host)
connects, ships one short message, and reads a response.

Run:
    pixi run example-uds-sidecar

Why a sidecar over UDS instead of ``127.0.0.1`` TCP?

- ~3-5x lower latency for short request/response pairs (no IP /
  TCP machinery).
- Filesystem-permission AAA: ``chmod 0600`` on the socket path
  is the entire access-control story; no token, no TLS client
  cert needed.
- No port allocation, no ephemeral-port-exhaustion under churn.

The example uses a single-pthread back-and-forth so it stays
self-contained (no scheduler involvement). For the multi-worker
shared-listener shape, hand :meth:`UnixListener.as_raw_fd` to each
worker and call :func:`flare.uds.accept_uds_fd` from the worker
loop — same shape as :func:`flare.tcp.accept_fd`.
"""

from flare.uds import UnixListener, UnixStream


def main() raises:
    var path = String("/tmp/flare_sidecar.sock")
    print("[example 38] binding UDS at", path)
    var listener = UnixListener.bind(path)
    print("  local_path =", listener.local_path())
    print("  fd         =", Int(listener.as_raw_fd()))

    print("[example 38] connecting client...")
    var client = UnixStream.connect(path)

    print("[example 38] accepting on listener...")
    var server = listener.accept()

    var ping = String("ping").as_bytes()
    print("[example 38] client → server:", String("ping"))
    client.write_all(ping)

    var rbuf = List[UInt8](capacity=16)
    rbuf.resize(16, 0)
    var n = server.read(rbuf.unsafe_ptr(), 16)
    var got = String(capacity=n + 1)
    for i in range(n):
        got += chr(Int(rbuf[i]))
    print("[example 38] server received:", got)

    var pong = String("pong").as_bytes()
    print("[example 38] server → client:", String("pong"))
    server.write_all(pong)

    var rbuf2 = List[UInt8](capacity=16)
    rbuf2.resize(16, 0)
    var n2 = client.read(rbuf2.unsafe_ptr(), 16)
    var got2 = String(capacity=n2 + 1)
    for i in range(n2):
        got2 += chr(Int(rbuf2[i]))
    print("[example 38] client received:", got2)

    client.close()
    server.close()
    listener.close()
    print("[example 38] done; socket file unlinked on listener __del__.")
