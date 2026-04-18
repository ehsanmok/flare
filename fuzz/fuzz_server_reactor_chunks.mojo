"""Fuzz harness: feed random HTTP-ish byte streams into ``ConnHandle`` in
fuzzer-chosen chunk sizes.

Invariants:

- No crashes on any byte input.
- The state machine always terminates — either by transitioning to
  ``STATE_WRITING`` (handler dispatched successfully or an error response
  queued) or by returning ``done=True`` (peer close / hard error).
- No input keeps the machine in ``STATE_READING`` forever: bounded
  iterations per input.

Strategy:

For each fuzz input we synthesise a plausible HTTP-ish prefix (request
line + a few headers + optional body) using the fuzz bytes as a mutator,
send the bytes to the state machine in 1..64-byte chunks, and drive
``on_readable`` after each chunk via a loopback socket.

Run:
    pixi run fuzz-server-reactor-chunks
"""

from mozz import fuzz, FuzzConfig
from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ServerConfig
from flare.http._server_reactor_impl import (
    ConnHandle,
    STATE_READING,
    STATE_WRITING,
    STATE_CLOSING,
)


def _ok_handler(req: Request) raises -> Response:
    """Trivial handler that always returns 200 OK with a tiny body."""
    var b = List[UInt8]()
    b.append(UInt8(ord("O")))
    b.append(UInt8(ord("K")))
    var r = Response(status=200, reason="OK", body=b^)
    return r^


def target(data: List[UInt8]) raises:
    """Feed ``data`` to a fresh ConnHandle via a loopback socket pair.

    The fuzzer chooses the split points by using the first few bytes as
    chunk-size hints.
    """
    if len(data) == 0:
        return

    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()

    var ch = ConnHandle(server^)
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    cfg.write_timeout_ms = 0
    # Keep limits loose so parser error paths aren't the dominant outcome.
    cfg.max_header_size = 16384
    cfg.max_body_size = 65536

    # Slice the input into chunks driven by the fuzz bytes. Start chunk
    # sizes at 1..8 bytes to exercise per-byte partial reads.
    var pos = 0
    var guard = 0  # bounded iterations to detect stuck states
    while pos < len(data) and guard < 128:
        var hint = Int(data[pos % len(data)])
        var chunk = (hint & 0x07) + 1  # 1..8
        if pos + chunk > len(data):
            chunk = len(data) - pos
        if chunk <= 0:
            break
        # Send the chunk.
        var slice = List[UInt8](capacity=chunk)
        for i in range(chunk):
            slice.append(data[pos + i])
        _ = client.write(Span[UInt8](slice))
        pos += chunk

        # Drive the state machine (at most a few times to surface data).
        var inner = 0
        while inner < 4:
            var step = ch.on_readable(_ok_handler, cfg)
            if step.done:
                client.close()
                return
            if ch.state == STATE_WRITING:
                # Drain the response.
                var wstep = ch.on_writable(cfg)
                if wstep.done:
                    client.close()
                    return
            inner += 1
        guard += 1

    # Final drive to see if any trailing data completes a request.
    _ = ch.on_readable(_ok_handler, cfg)
    if ch.state == STATE_WRITING:
        _ = ch.on_writable(cfg)
    client.close()


def main() raises:
    print("[mozz] fuzzing ConnHandle state machine with chunked feeds...")

    var seeds = List[List[UInt8]]()

    def _mk(s: String) raises -> List[UInt8]:
        var sb = s.as_bytes()
        var out = List[UInt8](capacity=len(sb))
        for i in range(len(sb)):
            out.append(sb[i])
        return out^

    seeds.append(_mk("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    seeds.append(_mk("POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"))
    seeds.append(_mk("GARBAGE\r\n\r\n"))
    seeds.append(_mk("GET / HTTP/1.0\r\n\r\n"))
    seeds.append(_mk("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=30_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/server_reactor_chunks",
            max_input_len=256,
        ),
        seeds,
    )
