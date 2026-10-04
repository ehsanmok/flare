import Flare.L4_App.Url

/-!
# APP-25: userinfo split at the first `@` leaves `@` in the host

flare/http/url.mojo:143-148 @59bda50 strips userinfo through the **first**
`@`. For `http://a@evil.com@good.com/` the host becomes
`evil.com@good.com`, which no RFC 3986 host form allows (§3.2.2: IP-literal,
IPv4address and reg-name exclude `@`). WHATWG and curl split at the last
`@` (host `good.com`). The input is not a valid RFC 3986 URI; flare should
either reject it or pick the same host as everyone else.
-/
namespace Flare.Bugs.APP_25
open Flare Flare.L4.Url

def raw : Bytes := Bytes.ofString "http://a@evil.com@good.com/"

theorem parse_raw :
    parse raw = .ok ⟨httpB, Bytes.ofString "evil.com@good.com", 80, [cSlash], [], []⟩ := by
  native_decide

/-- Counterexample: the parsed host contains `@`. -/
theorem host_has_at : ∃ u, parse raw = .ok u ∧ ¬ HostNoAt u := by
  refine ⟨_, parse_raw, fun h => h ?_⟩
  native_decide

/-- Minimal fix: strip userinfo through the last `@`. -/
def implFixed : Bytes → Except String Url :=
  parseWith splitFragment splitAuthority stripUserinfoFixed

theorem implFixed_meets_spec (r : Bytes) (u : Url) (e : implFixed r = .ok u) : HostNoAt u :=
  parseWith_fixedStrip_noAt _ _ r u e

theorem implFixed_raw :
    implFixed raw = .ok ⟨httpB, Bytes.ofString "good.com", 80, [cSlash], [], []⟩ := by
  native_decide

end Flare.Bugs.APP_25
