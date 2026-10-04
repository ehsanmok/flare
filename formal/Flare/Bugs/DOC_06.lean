/-!
# DOC-06: sessions have no server-side expiry by default

* flare file: `flare/http/session.mojo` @59bda50.
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
  `load` refuses a payload with no expiry or a past one (`csEncodeFixed`,
  `csLoadFixed`); `BackedSessionStore` defaults `ttl_s` to a positive value
  (`backedDefaultTtlFixed`). `InMemorySessionStore` needs the same expiry
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

/-- mirrors flare/http/session.mojo:380-384 @59bda50 -/
def csEncode (_now : Nat) (v : String) : Payload := ⟨none, v⟩

/-- `load` has no clock parameter in flare; `_now` is the moment it runs.
mirrors flare/http/session.mojo:359-378 @59bda50 -/
def csLoad (_now : Nat) (p : Payload) : Option String := some p.value

/-- `MemorySessionBackend.set`: `ttl_s <= 0` means no expiry (stored as 0).
mirrors flare/http/session.mojo:534-535 @59bda50 -/
def expiry (now ttl : Nat) : Nat := if ttl = 0 then 0 else now + ttl

/-- `MemorySessionBackend.get`: live unless an expiry is set and reached.
mirrors flare/http/session.mojo:523-532 @59bda50 -/
def live (exp now : Nat) : Bool := exp == 0 || decide (now < exp)

/-- mirrors flare/http/session.mojo:598 @59bda50 -/
def backedDefaultTtl : Nat := 0

/-- `BackedSessionStore.save` at `i`, then `load` at `t`. -/
def bsAccepts (ttl i t : Nat) : Bool := live (expiry i ttl) t

/-- Server-side expiry: a session issued at `i` is refused from `i + L` on,
for some lifetime `L`. `accepts i t`: issued at `i`, presented at `t`. -/
def Expires (accepts : Nat → Nat → Bool) : Prop := ∃ L, ∀ i t, i + L ≤ t → accepts i t = false

def csAccepts (v : String) (i t : Nat) : Bool := (csLoad t (csEncode i v)).isSome

def lifetime : Nat := 86400

def csEncodeFixed (now : Nat) (v : String) : Payload := ⟨some (now + lifetime), v⟩

def csLoadFixed (now : Nat) (p : Payload) : Option String :=
  match p.exp with
  | some e => if now < e then some p.value else none
  | none => none

def csAcceptsFixed (v : String) (i t : Nat) : Bool := (csLoadFixed t (csEncodeFixed i v)).isSome

def backedDefaultTtlFixed : Nat := lifetime

/-- The repro's checks: a bare signed value is accepted, and the backed
store's default keeps a session ten years. -/
theorem bug : csLoad (10 * 365 * 86400) ⟨none, "user=alice"⟩ = some "user=alice" ∧
    bsAccepts backedDefaultTtl 0 (10 * 365 * 86400) = true := by
  decide

theorem counterexample (v : String) :
    ¬ Expires (csAccepts v) ∧ ¬ Expires (bsAccepts backedDefaultTtl) := by
  refine ⟨fun ⟨L, h⟩ => ?_, fun ⟨L, h⟩ => ?_⟩
  · have := h 0 L (by omega)
    simp [csAccepts, csLoad] at this
  · have := h 0 L (by omega)
    simp [bsAccepts, live, expiry, backedDefaultTtl] at this

theorem fixed (v : String) :
    Expires (csAcceptsFixed v) ∧ Expires (bsAccepts backedDefaultTtlFixed) := by
  refine ⟨⟨lifetime, fun i t h => ?_⟩, ⟨lifetime, fun i t h => ?_⟩⟩
  · have : ¬ t < i + lifetime := by omega
    simp [csAcceptsFixed, csLoadFixed, csEncodeFixed, this]
  · have : ¬ t < i + lifetime := by omega
    simp [bsAccepts, live, expiry, backedDefaultTtlFixed, lifetime] at this ⊢
    omega

/-- The fixed cookie store refuses a payload signed without an expiry (the
repro's check A) and still accepts a fresh session. -/
theorem fixed_rejects_bare (t : Nat) (v : String) : csLoadFixed t ⟨none, v⟩ = none := rfl

theorem fixed_fresh (i : Nat) (v : String) : csLoadFixed i (csEncodeFixed i v) = some v := by
  simp [csLoadFixed, csEncodeFixed, lifetime]

end Flare.Bugs.DOC_06
