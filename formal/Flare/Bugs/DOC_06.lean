/-!
# DOC-06: sessions have no server-side expiry by default

Status: resolved. `CookieSessionStore` signs `"<expiry>|<value>"` and refuses
an expired cookie or one without an expiry, `InMemorySessionStore` stamps its
entries, and all three stores default `ttl_s` to `DEFAULT_SESSION_TTL_S`
(86400; `0` opts out); `flare/http/session.mojo`. Regression tests
`tests/http/test_session.mojo` (`test_cookie_store_cookie_expires_server_side`,
`test_cookie_store_refuses_a_signed_value_without_expiry`,
`test_in_memory_store_entry_expires_server_side`,
`test_backed_store_default_ttl_expires_the_session`, ...). The unprimed
definitions below (`csEncode`, `csLoad`, `backedDefaultTtl`, `lifetime`) are the
shipped model; the `Old` ones are the pre-fix behaviour.

* flare file (pre-fix): `flare/http/session.mojo` @59bda50.
  `CookieSessionStore.encode` (380-384) signs the raw value and `load`
  (359-378) takes no clock: a cookie whose HMAC verifies is accepted forever.
  `InMemorySessionStore` (390-468) keeps only ids and values and its `load`
  has no clock either. `BackedSessionStore` (574-650) defaults `ttl_s` to 0
  (598), which `MemorySessionBackend.set` (534-543) stores as "never expires".
* Doc clause: `docs/threat-model.md:73` (replay of a stolen session cookie)
  "Session contents include a server-side expiry".
* What goes wrong: a stolen session cookie replays for as long as the signing
  key is in use; with the backed store's default TTL, ten years later.
* Fix: `CookieSessionStore` signs an absolute expiry with the value and
  `load` refuses a payload with no expiry or a past one (`csEncode`,
  `csLoad`); `BackedSessionStore` defaults `ttl_s` to a positive value
  (`backedDefaultTtl`). `InMemorySessionStore` needs the same expiry
  column; it has no clock input, so it is not modelled here.

Time is whole seconds; the stores' payloads are modelled after HMAC
verification (a forged payload never reaches `load`, which holds; see the
signed-cookie rows of `formal/report/Docs.md`).
-/
namespace Flare.Bugs.DOC_06

/-- A verified signed-cookie payload: the session value and, in the fixed
format, the absolute expiry it was signed with. -/
structure Payload where
  exp : Option Nat
  value : String
  deriving DecidableEq, Repr

/-- Pre-fix.
mirrors flare/http/session.mojo:380-384 @59bda50 -/
def csEncodeOld (_now : Nat) (v : String) : Payload := ⟨none, v⟩

/-- Pre-fix: `load` had no clock parameter; `_now` is the moment it runs.
mirrors flare/http/session.mojo:359-378 @59bda50 -/
def csLoadOld (_now : Nat) (p : Payload) : Option String := some p.value

/-- `MemorySessionBackend.set`: `ttl_s <= 0` means no expiry (stored as 0).
mirrors flare/http/session.mojo:534-535 @59bda50 -/
def expiry (now ttl : Nat) : Nat := if ttl = 0 then 0 else now + ttl

/-- `MemorySessionBackend.get`: live unless an expiry is set and reached.
mirrors flare/http/session.mojo:523-532 @59bda50 -/
def live (exp now : Nat) : Bool := exp == 0 || decide (now < exp)

/-- Pre-fix: `BackedSessionStore.__init__` defaulted `ttl_s` to 0.
mirrors flare/http/session.mojo:598 @59bda50 -/
def backedDefaultTtlOld : Nat := 0

/-- `BackedSessionStore.save` at `i`, then `load` at `t`. -/
def bsAccepts (ttl i t : Nat) : Bool := live (expiry i ttl) t

/-- Server-side expiry: a session issued at `i` is refused from `i + L` on,
for some lifetime `L`. `accepts i t`: issued at `i`, presented at `t`. -/
def Expires (accepts : Nat → Nat → Bool) : Prop := ∃ L, ∀ i t, i + L ≤ t → accepts i t = false

def csAcceptsOld (v : String) (i t : Nat) : Bool := (csLoadOld t (csEncodeOld i v)).isSome

/-- `DEFAULT_SESSION_TTL_S`. -/
def lifetime : Nat := 86400

/-- `CookieSessionStore.encode_at`: sign `"<now + ttl_s>|<value>"`.
mirrors flare/http/session.mojo:372-455 (fixed, DOC-06) -/
def csEncode (now : Nat) (v : String) : Payload := ⟨some (now + lifetime), v⟩

/-- `CookieSessionStore.load_at`: refuse a payload with no expiry or a past one.
mirrors flare/http/session.mojo:372-455 (fixed, DOC-06) -/
def csLoad (now : Nat) (p : Payload) : Option String :=
  match p.exp with
  | some e => if now < e then some p.value else none
  | none => none

def csAccepts (v : String) (i t : Nat) : Bool := (csLoad t (csEncode i v)).isSome

/-- `BackedSessionStore.__init__`: `ttl_s` defaults to `DEFAULT_SESSION_TTL_S`.
mirrors flare/http/session.mojo:700-720 (fixed, DOC-06) -/
def backedDefaultTtl : Nat := lifetime

/-- The repro's checks: a bare signed value is accepted, and the backed
store's default keeps a session ten years. -/
theorem bug : csLoadOld (10 * 365 * 86400) ⟨none, "user=alice"⟩ = some "user=alice" ∧
    bsAccepts backedDefaultTtlOld 0 (10 * 365 * 86400) = true := by
  decide

theorem counterexample (v : String) :
    ¬ Expires (csAcceptsOld v) ∧ ¬ Expires (bsAccepts backedDefaultTtlOld) := by
  refine ⟨fun ⟨L, h⟩ => ?_, fun ⟨L, h⟩ => ?_⟩
  · have := h 0 L (by omega)
    simp [csAcceptsOld, csLoadOld] at this
  · have := h 0 L (by omega)
    simp [bsAccepts, live, expiry, backedDefaultTtlOld] at this

theorem fixed (v : String) :
    Expires (csAccepts v) ∧ Expires (bsAccepts backedDefaultTtl) := by
  refine ⟨⟨lifetime, fun i t h => ?_⟩, ⟨lifetime, fun i t h => ?_⟩⟩
  · have : ¬ t < i + lifetime := by omega
    simp [csAccepts, csLoad, csEncode, this]
  · have : ¬ t < i + lifetime := by omega
    simp [bsAccepts, live, expiry, backedDefaultTtl, lifetime] at this ⊢
    omega

/-- The fixed cookie store refuses a payload signed without an expiry (the
repro's check A) and still accepts a fresh session. -/
theorem fixed_rejects_bare (t : Nat) (v : String) : csLoad t ⟨none, v⟩ = none := rfl

theorem fixed_fresh (i : Nat) (v : String) : csLoad i (csEncode i v) = some v := by
  simp [csLoad, csEncode, lifetime]

end Flare.Bugs.DOC_06
