"""Benchmark: TCP throughput.

Measures raw bytes-per-second over a local loopback connection.

Usage:
    pixi run mojo run benchmark/bench_tcp.mojo
"""

from benchmark import run, keep
from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener


fn main() raises:
    # TODO: spin up a loopback listener in a thread, then benchmark
    # TcpStream.write() throughput across a range of buffer sizes.
    print("TCP benchmark: not yet implemented (requires socket FFI)")
