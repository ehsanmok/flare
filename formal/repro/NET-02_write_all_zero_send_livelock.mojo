# PLATFORM: any
# RESOLVED: NET-02 fixed on fix/formal-findings
"""NET-02: TcpStream.write_all / UnixStream.write_all livelock if send(2)
returns 0.

Lean: Flare.Bugs.NET_02.writeAll_livelock (counterexample) and
Flare.Bugs.NET_02.writeAllFixed_terminates (fix meets spec).
flare/tcp/stream.mojo:497-519 and flare/uds/stream.mojo:156-163 @59bda50.

Expected: write_all either writes every byte or raises.
Before the fix: write() returns 0 when send returns 0, and write_all adds 0 to
its progress and calls send again, forever. No supported kernel returns
0 from send with len > 0 on a TCP socket, so the repro injects it: it
compiles a small fault-injection library (interposing `send` through
DYLD_INSERT_LIBRARIES on macOS, LD_PRELOAD on Linux), `mojo build`s
itself and re-runs the binary with the library loaded. The injected send
returns 0 for its first 1000 calls and then fails with EIO, which is the
only thing that ends the loop. (In testing, the `mojo`
JIT did not route these libc calls through the interposer on either
platform, hence the build step.)

Minimal fix: in write_all, raise (e.g. NetworkError("send returned 0"))
when write() returns 0 with bytes remaining.
"""

from std.ffi import external_call
from std.os import getenv, setenv, unsetenv
from std.sys.info import CompilationTarget
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream

comptime ID = "NET-02"
comptime SELF = "formal/repro/NET-02_write_all_zero_send_livelock.mojo"
comptime ZERO_CALLS = 1000

comptime FAULT_C = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
static long hits;
static ssize_t fault_send(int fd, const void *b, size_t n, int fl,
                          ssize_t (*real)(int, const void *, size_t, int)) {
  const char *z = getenv("FLARE_FAULT_SEND_ZERO");
  if (z && n > 0) {
    char s[32];
    hits++;
    snprintf(s, sizeof s, "%ld", hits);
    setenv("FLARE_FAULT_HITS", s, 1);
    if (hits <= atol(z)) return 0;
    errno = EIO;
    return -1;
  }
  return real(fd, b, n, fl);
}
#ifdef __APPLE__
static ssize_t i_send(int fd, const void *b, size_t n, int fl) {
  return fault_send(fd, b, n, fl, send);
}
__attribute__((used, section("__DATA,__interpose"))) static struct {
  const void *r, *o;
} ip[] = {{(const void *)i_send, (const void *)send}};
#else
ssize_t send(int fd, const void *b, size_t n, int fl) {
  static ssize_t (*real)(int, const void *, size_t, int);
  if (!real) real = dlsym(RTLD_NEXT, "send");
  return fault_send(fd, b, n, fl, real);
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
    var dir = (
        "/tmp/flare-repro-"
        + ID
        + "-"
        + String(Int(external_call["getpid", Int32]()))
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
        print(
            "inconclusive: no C compiler to build the fault injector ("
            + cc
            + ")"
        )
        raise Error(ID + " inconclusive")
    # The conda linker's glibc stubs predate the versions Mojo's runtime
    # libraries reference; the real glibc resolves them at run time.
    var flags = String("")
    comptime if CompilationTarget.is_linux():
        flags = " -Xlinker --allow-shlib-undefined"
    var exe = dir + "/repro"
    if (
        _sh(
            "mojo build -I ."
            + flags
            + " "
            + SELF
            + " -o "
            + exe
            + " >"
            + dir
            + "/build.log 2>&1"
        )
        != 0
    ):
        print(
            "inconclusive: mojo build of",
            SELF,
            "failed; see",
            dir + "/build.log",
        )
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
    var err = String("")
    var raised = False
    _ = setenv("FLARE_FAULT_SEND_ZERO", String(ZERO_CALLS))
    try:
        c.write_all(data)
    except e:
        raised = True
        err = String(e)
    _ = unsetenv("FLARE_FAULT_SEND_ZERO")
    _ = s.peer_addr()
    var hits = _hits()
    if hits <= 0:
        print(
            "inconclusive: the send fault injector was not reached (hits =",
            hits,
            ")",
        )
        raise Error(ID + " inconclusive")
    if hits > ZERO_CALLS:
        print(
            "BUG REPRODUCED: write_all of 100 bytes called send",
            hits - 1,
            (
                "times while send returned 0 (no progress) and only stopped"
                " when the injected send failed with EIO:"
            ),
            err,
        )
        raise Error(ID)
    if not raised:
        print(
            "BUG REPRODUCED: write_all returned normally after send returned 0",
            hits,
            "times (0 of 100 bytes written)",
        )
        raise Error(ID)
    print(
        "OK: write_all raised after send returned 0 (send called",
        hits,
        "time(s)):",
        err,
    )


def main() raises:
    if getenv("FLARE_FAULT_CHILD") == "1":
        _child()
    else:
        _parent()
