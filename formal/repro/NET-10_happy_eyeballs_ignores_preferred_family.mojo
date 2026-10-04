# PLATFORM: any
"""NET-10: order_happy_eyeballs always puts IPv6 first.

Lean: Flare.Bugs.NET_10.order_breaks_spec (counterexample) and
Flare.Bugs.NET_10.orderFixed_spec (fix meets spec).
flare/dns/async_resolve.mojo:154-177 @59bda50.

Expected (RFC 8305 section 4): the first address of the sorted input stays
first ("whichever address family is first in the list should be followed
by an address of the other address family"). For [192.0.2.1, 2001:db8::1,
192.0.2.2] the attempt order is 192.0.2.1, 2001:db8::1, 192.0.2.2.
Actual: 2001:db8::1, 192.0.2.1, 192.0.2.2; the resolver's IPv4 preference
is overridden.

Minimal fix: start the interleaving with the family of addrs[0] (swap the
roles of v6 and v4 when addrs[0] is IPv4).
"""

from flare.dns import order_happy_eyeballs
from flare.net import IpAddr


def main() raises:
    var addrs = List[IpAddr]()
    addrs.append(IpAddr.parse("192.0.2.1"))
    addrs.append(IpAddr.parse("2001:db8::1"))
    addrs.append(IpAddr.parse("192.0.2.2"))
    var out = order_happy_eyeballs(addrs)
    var got = String("")
    for i in range(len(out)):
        got += String(out[i]) + " "
    if out[0] != addrs[0]:
        print(
            "BUG REPRODUCED: input starts with",
            String(addrs[0]),
            "but order_happy_eyeballs returned",
            got,
        )
        raise Error("NET-10")
    print("OK: preferred first address kept first:", got)
