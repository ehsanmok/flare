import Flare.L2_Machine.DnsCache

/-!
# NET-03: `DnsCache` with a very large `ttl_ms` never serves a hit

flare/dns/cache.mojo:96-142 @59bda50.

Spec (`DnsCache` docstring): an entry is served from memory until
`ttl_ms` has elapsed since it was stored, and the cache holds at most
`max_entries` hosts.

What goes wrong: `_store` sets `expires_at_ms = now + ttl_ms` in wrapping
`Int` arithmetic. With `ttl_ms = Int.MAX` ("cache forever") and any
monotonic clock reading `now ≥ 1`, the sum wraps negative, every entry is
born expired, and every `resolve` calls `getaddrinfo`.

A second, latent defect sits in the eviction scan: it starts from
`oldest_at = Int.MAX` with a strict `<`, so an entry expiring exactly at
`Int.MAX` is never chosen for eviction and the cache grows past
`max_entries`. flare reaches this only when `now + ttl_ms = Int.MAX` (e.g.
`now = 0`); saturating the expiry alone would make it the common case for
large TTLs, so the fix changes both.

Repro: formal/repro/NET-03_dns_cache_ttl_overflow.mojo.
-/
namespace Flare.Bugs.NET_03
open Flare.L2.DnsCache

/-- **Counterexample (general)**: with `ttl = Int.MAX`, after a store at any
`now ≥ 1`, a lookup at any `now' ≥ 0` misses. -/
theorem huge_ttl_never_hits (c : Cache) (k : Nat) (now now' : Int64)
    (hn : 1 ≤ now.toInt) (hn' : 0 ≤ now'.toInt) (httl : c.ttl = Int64.maxValue) :
    (resolve (store c k now) k now').2 = false :=
  resolve_store_miss c k now now' hn hn' httl

/-- The repro's trace: two lookups of one host at t = 1000 and 1001 ms
resolve twice and hit never. -/
theorem huge_ttl_trace :
    let c0 := Cache.new Int64.maxValue 1024
    let r1 := resolve c0 0 1000
    let r2 := resolve r1.1 0 1001
    r2.2 = false ∧ r2.1.resolves = 2 ∧ r2.1.hits = 0 := by
  native_decide

/-- Latent defect, reachable in flare at `now = 0`: two hosts stored with
`ttl = Int.MAX` into a 1-entry cache both stay. -/
theorem store_exceeds_max_at_INT_MAX :
    let c0 := Cache.new Int64.maxValue 1
    ((store (store c0 0 0) 1 0).byHost.length = 2) := by
  native_decide

/-- Saturating the expiry without changing the scan's `<` breaks the bound
for every clock reading. -/
def storeSatOnly (c : Cache) (k : Nat) (now : Int64) : Cache :=
  { c with byHost := setKey (evict false c k now) k (satAdd now c.ttl) }

theorem saturation_alone_exceeds_max :
    let c0 := Cache.new Int64.maxValue 1
    ((storeSatOnly (storeSatOnly c0 0 1000) 1 1001).byHost.length = 2) := by
  native_decide

/-- **Fix meets spec (TTL)**: after the fixed store at `now ≥ 0`, a lookup
strictly inside the TTL window is a hit (for every `ttl`, including
`Int.MAX`). -/
theorem storeFixed_hits_within_ttl (c : Cache) (k : Nat) (now now' : Int64)
    (hn : 0 ≤ now.toInt) (h1 : now.toInt ≤ now'.toInt)
    (h2 : now'.toInt < now.toInt + c.ttl.toInt) (h3 : now'.toInt < Int64.maxValue.toInt) :
    (resolveFixed (storeFixed c k now) k now').2 = true :=
  Flare.L2.DnsCache.storeFixed_hits_within_ttl c k now now' hn h1 h2 h3

/-- **Fix meets spec (size)**: the fixed store keeps `size() ≤ max_entries`. -/
theorem storeFixed_size_bound (c : Cache) (k : Nat) (now : Int64) (hmax : 1 ≤ c.maxEntries)
    (h : c.byHost.length ≤ c.maxEntries) : (storeFixed c k now).byHost.length ≤ c.maxEntries :=
  Flare.L2.DnsCache.storeFixed_size_bound c k now hmax h

end Flare.Bugs.NET_03
