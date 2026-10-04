# PLATFORM: any
"""RT-02: writev_buf_all returns normally after a short write.

Lean: Flare.Bugs.RT_02.writev_silent_short_write (counterexample) and
Flare.Bugs.RT_02.writevAllFixed_spec (fix meets spec).
flare/runtime/iovec.mojo:312-361 (the branch at 340-341) @59bda50.

Expected: writev_buf_all returns normally only after every byte was
written; otherwise it raises.
Actual: writev_buf already raises on -1, so `if sent <= 0: return`
handles writev returning 0 with bytes still queued, and the caller is
told everything was written. No supported kernel returns 0 from writev
with a non-empty iovec on a socket, so the repro injects it: it compiles
a small fault-injection library (interposing `writev` through
DYLD_INSERT_LIBRARIES on macOS, LD_PRELOAD on Linux), `mojo build`s
itself and re-runs the binary with the library loaded. (In testing, the `mojo`
JIT did not route these libc calls through the interposer on either
platform, hence the build step.)

Minimal fix: raise (e.g. NetworkError("writev returned 0")) instead of
returning when sent == 0.
"""

from std.ffi import external_call
from std.os import getenv, setenv, unsetenv
from std.sys.info import CompilationTarget
from flare.net import SocketAddr
from flare.runtime.iovec import IoVecBuf, writev_buf_all
from flare.tcp import TcpListener, TcpStream

comptime ID = "RT-02"
comptime SELF = "formal/repro/RT-02_writev_all_silent_short_write.mojo"

comptime FAULT_C = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
static long hits;
static ssize_t fault_writev(int fd, const struct iovec *v, int n,
                            ssize_t (*real)(int, const struct iovec *, int)) {
  if (getenv("FLARE_FAULT_WRITEV_ZERO")) {
    char s[32];
    hits++;
    snprintf(s, sizeof s, "%ld", hits);
    setenv("FLARE_FAULT_HITS", s, 1);
    return 0;
  }
  return real(fd, v, n);
}
#ifdef __APPLE__
static ssize_t i_writev(int fd, const struct iovec *v, int n) {
  return fault_writev(fd, v, n, writev);
}
__attribute__((used, section("__DATA,__interpose"))) static struct {
  const void *r, *o;
} ip[] = {{(const void *)i_writev, (const void *)writev}};
#else
ssize_t writev(int fd, const struct iovec *v, int n) {
  static ssize_t (*real)(int, const struct iovec *, int);
  if (!real) real = dlsym(RTLD_NEXT, "writev");
  return fault_writev(fd, v, n, real);
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


def _child() raises:
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var c = TcpStream.connect(l.local_addr())
    var s = l.accept()
    var data = List[UInt8](length=100, fill=UInt8(0x41))
    var iov = IoVecBuf(1)
    iov.set(0, Int(data.unsafe_ptr()), len(data))
    var err = String("")
    var raised = False
    _ = setenv("FLARE_FAULT_WRITEV_ZERO", "1")
    try:
        writev_buf_all(iov, Int(c._socket.fd), len(data))
    except e:
        raised = True
        err = String(e)
    _ = unsetenv("FLARE_FAULT_WRITEV_ZERO")
    _ = data[0]
    _ = s.peer_addr()
    var hits = _hits()
    if hits <= 0:
        print("inconclusive: the writev fault injector was not reached (hits =", hits, ")")
        raise Error(ID + " inconclusive")
    if not raised:
        print(
            "BUG REPRODUCED: writev_buf_all(total_bytes=100) returned normally"
            " after writev returned 0; 0 of 100 bytes were written and iovec 0"
            " still holds",
            iov.cell_len(0),
            "bytes",
        )
        raise Error(ID)
    print("OK: writev_buf_all raised after writev returned 0:", err)


def main() raises:
    if getenv("FLARE_FAULT_CHILD") == "1":
        _child()
    else:
        _parent()
