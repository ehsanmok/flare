import Flare.L4_App.Middleware

/-!
# APP-27: Compress omits `Vary: Accept-Encoding` on identity responses

flare/http/middleware.mojo:345-376 @59bda50. For a body of at least
`min_size_bytes` that is not already encoded, Compress chooses gzip, br or
identity from Accept-Encoding, so the representation depends on that
field. `Vary: Accept-Encoding` is appended only in the encoding branch; the
identity response (no Accept-Encoding, `identity` preferred, or every
coding refused) has none. RFC 9110 §12.5.5: an origin server SHOULD send
Vary when the selection depends on request fields other than the method
and target URI; without it a shared cache can store the identity response
as the only variant.

Repro: formal/repro/APP-27_compress_missing_vary_on_identity.mojo.

Status: resolved. `Compress.serve` appends `Vary: Accept-Encoding` to every
response past the size, already-encoded and partial-content checks, whether
it encodes or leaves the body as identity. The model `compress` is the shipped
code; `compressNoVary` is the pre-fix one (APP-26 already applied).
Regression tests: `tests/http/test_middleware.mojo::test_compress_identity_variant_has_vary`,
`::test_compress_vary_on_every_negotiated_outcome` and
`::test_compress_no_vary_when_passed_through`.
-/
namespace Flare.Bugs.APP_27

open Flare.L4.Middleware

def x200 : Resp := ⟨200, [], List.replicate 2048 65⟩

def gzipStub : Enc → List UInt8 → List UInt8 := fun _ b => b.take 35

/-- No Accept-Encoding: `negotiate_encoding("")` returns identity, q 1000. -/
def cfgNone : CCfg := ⟨⟨.identity, 1000⟩, true, gzipStub, 1024⟩

/-- `Accept-Encoding: gzip`. -/
def cfgGzip : CCfg := ⟨⟨.gzip, 1000⟩, true, gzipStub, 1024⟩

theorem x200_negotiated (c : CCfg) (hc : c.minSize = 1024) : negotiated c x200 := by
  refine ⟨?_, rfl, rfl⟩
  simp only [hc, x200, List.length_replicate]; omega

/-- Counterexample (pre-fix): the gzip variant carries Vary, the identity variant of
the same response does not. -/
theorem identity_without_vary :
    ("Vary", "Accept-Encoding") ∈ (compressNoVary cfgGzip x200).hdrs ∧
    ("Vary", "Accept-Encoding") ∉ (compressNoVary cfgNone x200).hdrs := by
  native_decide

theorem violates_spec : ¬ VarySpec compressNoVary := by
  intro h
  exact identity_without_vary.2 (h cfgNone x200 (x200_negotiated cfgNone rfl))

/-- The shipped `compress` appends `Vary: Accept-Encoding` on every negotiated
response; it meets the spec for every configuration and response. -/
theorem fixed_meets_spec : VarySpec compress := compress_vary

theorem fixed_on_example : ("Vary", "Accept-Encoding") ∈ (compress cfgNone x200).hdrs :=
  compress_vary cfgNone x200 (x200_negotiated cfgNone rfl)

end Flare.Bugs.APP_27
