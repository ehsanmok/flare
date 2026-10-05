# PLATFORM: any
# RESOLVED: NET-08 fixed on fix/formal-findings
"""NET-08: resolve() rejects a valid 254-byte absolute hostname.

Lean: Flare.Bugs.NET_08.valid_but_rejected (counterexample) and
Flare.Bugs.NET_08.validateFixed_spec (fix meets spec).
flare/dns/resolver.mojo:78-87 @59bda50.

Expected: RFC 1035 section 2.3.4 (cited in the code) bounds a name at 255
wire octets, i.e. 253 text bytes plus an optional trailing root dot. A
253-byte name written absolute (254 bytes ending in ".") is valid and goes
to getaddrinfo (here it ends in the reserved .invalid TLD, so the lookup
fails with a DnsError, not a validation error).
Before the fix: AddressParseError "hostname too long (max 253 chars)".

Minimal fix: compare the length without one trailing "." against 253.
"""

from flare.dns import resolve


def main() raises:
    var host = String("")
    for _ in range(63):
        host += "a"
    host += "."
    for _ in range(63):
        host += "b"
    host += "."
    for _ in range(63):
        host += "c"
    host += "."
    for _ in range(53):
        host += "d"
    host += ".invalid."
    if host.byte_length() != 254:
        raise Error("test setup: length " + String(host.byte_length()))
    var msg: String
    try:
        _ = resolve(host)
        msg = "resolved"
    except e:
        msg = String(e)
    if "too long" in msg:
        print(
            "BUG REPRODUCED: 254-byte absolute name (253 + root dot) rejected:",
            msg[byte=0:60],
        )
        raise Error("NET-08")
    print("OK: name passed validation; resolver said:", msg[byte=0:80])
