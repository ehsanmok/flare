import Flare.L2_Machine.HappyEyeballs

/-!
# NET-10: `order_happy_eyeballs` always tries IPv6 first

Status: resolved. `order_happy_eyeballs` now starts with the family of
`addrs[0]`; `Flare.L2.HappyEyeballs.order` mirrors the shipped code and the
counterexample below is about the pre-fix `orderOld`.

Pre-fix code: flare/dns/async_resolve.mojo:154-177 @59bda50 (used by
`DnsCache.resolve_ordered`, flare/dns/cache.mojo:176-180).

Spec (RFC 8305 §4, which the docstring cites): the input is the resolver's
RFC 6724-sorted list; interleaving must keep its first address first —
"Whichever address family is first in the list should be followed by an
address of the other address family". So `head? (order l) = head? l`.

What goes wrong: flare splits the list by family and always emits the IPv6
sublist first. When `getaddrinfo` puts IPv4 first (e.g. on a host with no
usable IPv6 route, RFC 6724 rules 1-2), the dialer's first attempt goes to
an IPv6 address the OS ranked lower. Order within each family and the
permutation property were fine (`order_perm`, `order_filter_v6`,
`order_filter_v4`).

Repro: formal/repro/NET-10_happy_eyeballs_ignores_preferred_family.mojo.
-/
namespace Flare.Bugs.NET_10
open Flare.L2.HappyEyeballs

/-- the RFC 8305 §4 clause flare violates -/
def Spec {α : Type} (l out : List α) : Prop := out.head? = l.head?

/-- addresses as booleans: `true` = IPv6 -/
def input : List Bool := [false, true, false]

/-- **Counterexample** (pre-fix `orderOld`): input `[v4, v6, v4]` (IPv4
preferred) comes out as `[v6, v4, v4]`. -/
theorem order_breaks_spec :
    orderOld id input = [true, false, false] ∧ ¬ Spec input (orderOld id input) := by
  unfold Spec; native_decide

/-- **Fix meets spec**: the shipped `order` keeps the first address first. -/
theorem order_spec {α : Type} (isV6 : α → Bool) (l : List α) :
    Spec l (order isV6 l) := order_head isV6 l

/-- and the shipped `order` is still a permutation of the input -/
theorem order_perm' {α : Type} (isV6 : α → Bool) (l : List α) :
    (order isV6 l).Perm l := order_perm isV6 l

/-- on the counterexample input the shipped order is `[v4, v6, v4]` -/
theorem order_fixes_input : order id input = [false, true, false] := by native_decide

end Flare.Bugs.NET_10
