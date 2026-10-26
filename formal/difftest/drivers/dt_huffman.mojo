"""Difftest driver: flare.http.hpack_huffman.

Targets (input layout as in formal/Oracle/Registry.lean):
  huffman.decode       huffman_decode on the buffer
  huffman.decode_simd  huffman_decode_simd on the buffer (what HPACK and
                       QPACK call)
  huffman.encode       huffman_encode on the buffer
  huffman.length       huffman_encoded_length on the buffer

Run: pixi run mojo -I . formal/difftest/drivers/dt_huffman.mojo IN OUT
"""

from std.sys import argv

from flare.http.hpack_huffman import (
    huffman_decode,
    huffman_encode,
    huffman_encoded_length,
)
from flare.http.hpack_huffman_simd import huffman_decode_simd

from _dtio import ok_hex, read_cases, write_lines


def _decode[simd: Bool](data: List[UInt8]) -> String:
    var out = List[UInt8]()
    try:
        comptime if simd:
            huffman_decode_simd(Span[UInt8, _](data), out)
        else:
            huffman_decode(Span[UInt8, _](data), out)
        return ok_hex(Span[UInt8, _](out))
    except:
        return "ERR"


def main() raises:
    var args = argv()
    var lines = List[String]()
    for c in read_cases(String(args[1])):
        if c.target == "huffman.decode":
            lines.append(_decode[False](c.data))
        elif c.target == "huffman.decode_simd":
            lines.append(_decode[True](c.data))
        elif c.target == "huffman.encode":
            var out = List[UInt8]()
            huffman_encode(Span[UInt8, _](c.data), out)
            lines.append(ok_hex(Span[UInt8, _](out)))
        elif c.target == "huffman.length":
            var n = huffman_encoded_length(Span[UInt8, _](c.data))
            lines.append("OK:" + String(n))
        else:
            lines.append("BAD:unknown target " + c.target)
    write_lines(String(args[2]), lines)
