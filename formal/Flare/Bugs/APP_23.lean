import Flare.L4_App.Url

/-!
# APP-23: `Url.parse` does not end the authority at `?` (host confusion)

flare/http/url.mojo:101-123 @59bda50 takes the fragment after the **last**
`#` and ends the authority at the first `/` only. RFC 3986 §3.2 ends the
authority at the first `/`, `?` or `#`. On the valid URI
`http://evil.com?@good.com/` (authority `evil.com`, query `@good.com/`)
flare's authority is `evil.com?@good.com`; the userinfo strip then removes
`evil.com?@` and the host becomes `good.com`. RFC 3986 parsers, WHATWG
browsers and curl connect to `evil.com`. Related wrong hosts on valid URIs:
`http://good.com?x=/y` gives host `good.com?x=`; and (invalid URI, `#` twice)
`http://evil.com#@good.com#x` gives host `good.com`.
-/
namespace Flare.Bugs.APP_23
open Flare Flare.L4.Url

def raw : Bytes := Bytes.ofString "http://evil.com?@good.com/"
def rest : Bytes := Bytes.ofString "evil.com?@good.com/"

theorem raw_split : raw = httpB ++ sepB ++ rest := by native_decide

theorem spec_authority : specAuthority rest = Bytes.ofString "evil.com" := by native_decide

/-- What flare returns: host `good.com`, path `/`, empty query. -/
theorem parse_raw :
    parse raw = .ok ⟨httpB, Bytes.ofString "good.com", 80, [cSlash], [], []⟩ := by
  native_decide

/-- Counterexample: the host is not part of the RFC 3986 authority. -/
theorem host_confusion : ∃ u, parse raw = .ok u ∧ ¬ HostInAuthority raw u := by
  refine ⟨_, parse_raw, fun h => ?_⟩
  have hi := h rest raw_split
  rw [spec_authority] at hi
  have hg : (103 : UInt8) ∈ Bytes.ofString "good.com" := by native_decide
  have hn : (103 : UInt8) ∉ Bytes.ofString "evil.com" := by native_decide
  exact hn (hi.subset hg)

/-- Second witness on a valid URI with no `@`: `http://good.com?x=/y`. -/
theorem parse_query_slash :
    (parse (Bytes.ofString "http://good.com?x=/y")).map (·.host) =
      .ok (Bytes.ofString "good.com?x=") := by native_decide

/-- `#` variant (invalid URI): the last `#` is used. -/
theorem parse_double_hash :
    (parse (Bytes.ofString "http://evil.com#@good.com#x")).map (·.host) =
      .ok (Bytes.ofString "good.com") := by native_decide

/-- Minimal fix: fragment at the first `#`, authority ends at `/` or `?`
(userinfo strip unchanged). -/
def implFixed : Bytes → Except String Url :=
  parseWith splitFragmentFixed splitAuthorityFixed stripUserinfo

/-- The fix meets the spec on every input. -/
theorem implFixed_meets_spec (r : Bytes) (u : Url) (e : implFixed r = .ok u) :
    HostInAuthority r u :=
  parseWith_fixedSplit_hostInAuthority _ stripUserinfo_infix r u e

theorem implFixed_raw :
    implFixed raw = .ok ⟨httpB, Bytes.ofString "evil.com", 80, [cSlash],
      Bytes.ofString "@good.com/", []⟩ := by native_decide

end Flare.Bugs.APP_23
