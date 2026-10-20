"""The OpenSSL shim must carry no TLS segment.

``libflare_tls.so`` is loaded with dlopen after startup. A PT_TLS segment
in it bumps glibc's TLS generation, and every other library's dynamic TLS
access, the allocator's on every malloc and free included, then stays on
``__tls_get_addr``'s slow path.
"""

from std.testing import TestSuite, assert_equal, assert_true

from flare.utils import find_flare_lib

comptime _PT_TLS = 7


def _u16(b: List[UInt8], at: Int) -> Int:
    return Int(b[at]) | (Int(b[at + 1]) << 8)


def _u64(b: List[UInt8], at: Int) -> Int:
    var v = 0
    for i in range(8):
        v |= Int(b[at + i]) << (8 * i)
    return v


def _program_header_types(path: String) raises -> List[Int]:
    var f = open(path, "r")
    var b = f.read_bytes()
    f.close()
    assert_true(len(b) > 64 and b[0] == 0x7F and b[4] == 2, "not ELF64")
    var phoff = _u64(b, 0x20)
    var phentsize = _u16(b, 0x36)
    var phnum = _u16(b, 0x38)
    var out = List[Int]()
    for i in range(phnum):
        var at = phoff + i * phentsize
        out.append(
            Int(b[at])
            | (Int(b[at + 1]) << 8)
            | (Int(b[at + 2]) << 16)
            | (Int(b[at + 3]) << 24)
        )
    return out^


def test_openssl_shim_has_no_tls_segment() raises:
    var types = _program_header_types(find_flare_lib("tls"))
    assert_true(len(types) > 0)
    var tls = 0
    for t in types:
        if t == _PT_TLS:
            tls += 1
    assert_equal(tls, 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
