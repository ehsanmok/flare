# PLATFORM: any
# RESOLVED: ENC-01 fixed on fix/formal-findings
"""ENC-01: IpAddr.is_multicast() reports non-multicast IPv6 addresses as multicast.

Lean: Flare.Bugs.ENC_01.counterexample (00ff::1 renders as "ff::1" and is
classified multicast) and Flare.Bugs.ENC_01.isMulticast6Fixed_correct (the
fix equals the RFC 4291 predicate for every first group).
flare/net/address.mojo:232-240 @59bda50.

Expected: is_multicast() is True exactly for ff00::/8 (RFC 4291 section 2.7:
first byte 0xff).
Before the fix: the IPv6 branch tests `self._addr.startswith("ff")` on the
inet_ntop text. RFC 5952 drops leading zeros in a group, so first groups
0x00ff and 0x0ff0..0x0fff also print starting with "ff": 00ff::1 is stored
as "ff::1" and fff:: as "fff::", and both are reported as multicast.

Minimal fix: require the first group to have four hex digits:
    return self._addr.startswith("ff") and _find_char(self._addr, UInt8(ord(":"))) == 4
"""

from flare.net.address import IpAddr


def main() raises:
    var real = IpAddr.parse("ff02::1")
    if not real.is_multicast():
        raise Error("sanity: ff02::1 must be multicast")
    var bad = List[String]()
    for s in ["00ff::1", "fff::", "ff0:1::"]:
        var a = IpAddr.parse(s)
        if a.is_multicast():
            bad.append(s + " (stored as " + String(a) + ")")
    if len(bad) > 0:
        var msg = String("")
        for i in range(len(bad)):
            msg += bad[i] + "; "
        print(
            (
                "BUG REPRODUCED: is_multicast() is True for non-ff00::/8"
                " addresses:"
            ),
            msg,
        )
        raise Error("ENC-01")
    print(
        "OK: is_multicast() is False for 00ff::1, fff::, ff0:1:: and True for"
        " ff02::1"
    )
