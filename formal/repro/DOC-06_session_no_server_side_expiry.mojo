# PLATFORM: any (pure in-process)
"""DOC-06: sessions carry no server-side expiry by default, so a stolen
session cookie replays for as long as the signing key lives.

Lean: Flare.Bugs.DOC_06.counterexample (counterexample) and
Flare.Bugs.DOC_06.fixed (fix meets spec).
flare/http/session.mojo @59bda50:
- CookieSessionStore (315-384): `encode` signs the raw value
  (`signed_cookie_encode(value, key)`, 380-384); `load` (359-378) takes no
  clock and accepts any cookie whose HMAC verifies. Nothing in the cookie
  or the store records when it was issued or when it expires.
- InMemorySessionStore (390-468): fields `_ids` / `_values` only; `load`
  takes no clock, so an inserted id is valid until `remove`.
- BackedSessionStore (574-650): `ttl_s: Int = 0` (598), which
  `MemorySessionBackend.set` maps to "never expires" (535).

Doc claim: docs/threat-model.md:73 (replay of a stolen session cookie)
"Session contents include a server-side expiry".

Checks:
A. CookieSessionStore: a cookie signed with the store key whose payload is
   just the value (exactly what `encode` emits) is accepted by `load`. The
   store has no clock input, so it accepts that cookie at any later time.
B. BackedSessionStore with its default TTL: `save` at now_s = 0, then
   `load` at now_s = 10 years still returns the session.
Preconditions: `encode`/`load` and `save`/`load` at the same instant
round-trip the value.

Expected: A rejects a cookie that carries no expiry, and B's session is
gone ten years later. Actual: both accept.

Minimal fix: CookieSessionStore embeds an absolute expiry in the signed
payload ("<exp_unix>|<value>", default lifetime one day) and `load`
rejects a payload with no expiry or one already past the wall clock;
BackedSessionStore defaults `ttl_s` to 86400. (InMemorySessionStore needs
an expiry column the same way; it has no clock input to test here.)
"""

from flare.http import (
    BackedSessionStore,
    CookieSessionStore,
    MemorySessionBackend,
    Method,
    Request,
    signed_cookie_encode,
)


def _req(cookie: String) raises -> Request:
    var r = Request(method=Method.GET, url="/")
    r.headers.set("Cookie", "flare_session=" + cookie)
    return r^


def main() raises:
    var key = List[UInt8](length=32, fill=0x5A)
    var value = String("user=alice")

    var cs = CookieSessionStore(key)
    var fresh = cs.load(_req(cs.encode(value)))
    if not fresh.present or fresh.value != value:
        print("inconclusive: CookieSessionStore encode/load does not round-trip")
        raise Error("setup")
    var bare = signed_cookie_encode(List[UInt8](value.as_bytes()), key)
    var a = cs.load(_req(bare))
    var a_accepts = a.present and a.value == value

    var bs = BackedSessionStore(MemorySessionBackend(), key)
    var c = bs.save(value, 0)
    var now = bs.load(_req(c), 0)
    if not now.present or now.value != value:
        print("inconclusive: BackedSessionStore save/load does not round-trip")
        raise Error("setup")
    var later = bs.load(_req(c), 10 * 365 * 86400)
    var b_accepts = later.present

    if not a_accepts and not b_accepts:
        print("OK: sessions expire server-side by default")
        return
    print(
        "BUG REPRODUCED: CookieSessionStore accepted a signed cookie with no",
        "expiry (no clock input exists):",
        a_accepts,
        "; BackedSessionStore with default ttl returned the session 10 years",
        "after save:",
        b_accepts,
    )
    raise Error("DOC-06")
