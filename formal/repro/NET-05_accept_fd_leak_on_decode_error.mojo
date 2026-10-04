# PLATFORM: any
"""NET-05: TcpListener.accept / accept_fd leak the accepted fd if the peer
address fails to decode.

Lean: Flare.Bugs.NET_05.accept_leaks_on_decode_error (counterexample) and
Flare.Bugs.NET_05.acceptFixed_spec (fix meets spec).
flare/tcp/listener.mojo:183-201 and 265-282 @59bda50.

Expected: after accept(2) returns a client fd, either a TcpStream owns it
or it is closed before the error propagates.
Actual: _sockaddr_to_socket_addr(peer_buf) runs before client_fd is
wrapped in a RawSocket; when it raises, nothing owns the fd and it is
never closed. The decode raises only if inet_ntop fails, which it never
does for AF_INET/AF_INET6 with flare's 64-byte buffer, so the repro
injects the failure: it compiles a small fault-injection library
(interposing `inet_ntop` through DYLD_INSERT_LIBRARIES on macOS,
LD_PRELOAD on Linux), `mojo build`s itself and re-runs the binary with
the library loaded. The fault is armed only around the accept() call.
The repro learns the lowest free fd k before accept (accept(2) must
return it) and, after accept raises, checks with fcntl/getpeername that
k is still an open socket connected to the client. (In testing, the `mojo`
JIT did not route these libc calls through the interposer on either
platform, hence the build step.)

Minimal fix: wrap client_fd in a RawSocket before decoding the peer
address, so a raise runs the destructor and closes the fd.
"""

from std.ffi import external_call
from std.memory import Layout, alloc
from std.os import getenv, setenv, unsetenv
from std.sys.info import CompilationTarget
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream

comptime ID = "NET-05"
comptime SELF = "formal/repro/NET-05_accept_fd_leak_on_decode_error.mojo"

comptime FAULT_C = """
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
static long hits;
typedef const char *(*ntop_t)(int, const void *, char *, socklen_t);
static const char *fault_ntop(int af, const void *src, char *dst,
                              socklen_t size, ntop_t real) {
  if (getenv("FLARE_FAULT_NTOP")) {
    char s[32];
    hits++;
    snprintf(s, sizeof s, "%ld", hits);
    setenv("FLARE_FAULT_HITS", s, 1);
    errno = ENOSPC;
    return NULL;
  }
  return real(af, src, dst, size);
}
#ifdef __APPLE__
static const char *i_ntop(int af, const void *src, char *dst, socklen_t size) {
  return fault_ntop(af, src, dst, size, inet_ntop);
}
__attribute__((used, section("__DATA,__interpose"))) static struct {
  const void *r, *o;
} ip[] = {{(const void *)i_ntop, (const void *)inet_ntop}};
#else
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
  static ntop_t real;
  if (!real) real = (ntop_t)dlsym(RTLD_NEXT, "inet_ntop");
  return fault_ntop(af, src, dst, size, real);
}
#endif
"""


def _sh(cmd: String) -> Int:
    var c = cmd.copy()
    var st = Int(external_call["system", Int32](c.as_c_string_span().ptr()))
    if st < 0:
        return 255
    return (st >> 8) & 0xFF


def _parent() raises:
    var dir = "/tmp/flare-repro-" + ID + "-" + String(
        Int(external_call["getpid", Int32]())
    )
    if _sh("mkdir -p " + dir) != 0:
        print("inconclusive: cannot create", dir)
        raise Error(ID + " inconclusive")
    with open(dir + "/fault.c", "w") as f:
        f.write(FAULT_C)
    var lib: String
    var cc: String
    var env: String
    comptime if CompilationTarget.is_macos():
        lib = dir + "/fault.dylib"
        cc = "cc -dynamiclib -o " + lib + " " + dir + "/fault.c"
        env = "DYLD_INSERT_LIBRARIES=" + lib
    else:
        lib = dir + "/fault.so"
        cc = "cc -shared -fPIC -o " + lib + " " + dir + "/fault.c -ldl"
        env = "LD_PRELOAD=" + lib
    if _sh(cc + " >" + dir + "/cc.log 2>&1") != 0:
        print("inconclusive: no C compiler to build the fault injector (" + cc + ")")
        raise Error(ID + " inconclusive")
    # The conda linker's glibc stubs predate the versions Mojo's runtime
    # libraries reference; the real glibc resolves them at run time.
    var flags = String("")
    comptime if CompilationTarget.is_linux():
        flags = " -Xlinker --allow-shlib-undefined"
    var exe = dir + "/repro"
    if _sh("mojo build -I ." + flags + " " + SELF + " -o " + exe + " >" + dir + "/build.log 2>&1") != 0:
        print("inconclusive: mojo build of", SELF, "failed; see", dir + "/build.log")
        raise Error(ID + " inconclusive")
    var rc = _sh(
        "FLARE_FAULT_CHILD=1 " + env + " " + exe + " >" + dir + "/out.log 2>&1"
    )
    var out: String
    with open(dir + "/out.log", "r") as f:
        out = f.read()
    _ = _sh("rm -rf " + dir)
    print(out, end="")
    if rc == 0 and out.startswith("OK:"):
        return
    if out.startswith("BUG REPRODUCED:"):
        raise Error(ID)
    print("inconclusive: child exited", rc, "without a verdict")
    raise Error(ID + " inconclusive")


def _hits() -> Int:
    try:
        return Int(getenv("FLARE_FAULT_HITS", "0"))
    except:
        return -1


def _peer_port(fd: Int) -> Int:
    """Port of the peer connected to fd, or -1."""
    var buf = alloc(Layout[UInt8](count=128)).unsafe_leak()
    var ln = alloc(Layout[UInt32](count=1)).unsafe_leak()
    ln.unsafe_write(UInt32(128))
    var r = external_call["getpeername", Int32](Int32(fd), buf, ln)
    if r != 0:
        return -1
    return (Int(buf.unsafe_offset(2)[]) << 8) | Int(buf.unsafe_offset(3)[])


def _child() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    var cport = Int(c.local_addr().port)
    var k = Int(external_call["dup", Int32](Int32(2)))
    if k < 0:
        print("inconclusive: dup(2) failed")
        raise Error(ID + " inconclusive")
    _ = external_call["close", Int32](Int32(k))
    var err = String("")
    var raised = False
    _ = setenv("FLARE_FAULT_NTOP", "1")
    try:
        var s = l.accept()
        _ = s.peer_addr()
    except e:
        raised = True
        err = String(e)
    _ = unsetenv("FLARE_FAULT_NTOP")
    _ = l.local_addr()
    var hits = _hits()
    if hits <= 0 or not raised:
        print(
            "inconclusive: accept did not hit the inet_ntop fault (hits =",
            hits, ", raised =", raised, ")",
        )
        raise Error(ID + " inconclusive")
    var open_ = Int(external_call["fcntl", Int32](Int32(k), Int32(1))) >= 0
    var pp = _peer_port(k)
    _ = c.local_addr()
    if open_ and pp == cport:
        print(
            "BUG REPRODUCED: accept raised (", err, ") but the accepted fd",
            k, "is still open and connected to the client (peer port",
            pp, "); nothing owns it, so it leaks",
        )
        raise Error(ID)
    if open_:
        print("inconclusive: fd", k, "is open but not the accepted socket (peer port", pp, "vs", cport, ")")
        raise Error(ID + " inconclusive")
    print("OK: accept raised (", err, ") and the accepted fd", k, "was closed")


def main() raises:
    if getenv("FLARE_FAULT_CHILD") == "1":
        _child()
    else:
        _parent()
