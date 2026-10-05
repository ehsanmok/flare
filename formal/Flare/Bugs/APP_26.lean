import Flare.L4_App.Middleware

/-!
# APP-26: Compress re-encodes 206 Partial Content

flare/http/middleware.mojo:345-376 @59bda50 (pre-fix). Compress checked the pick, the
body size and an existing Content-Encoding, but not the status or
Content-Range. A 206 whose body is the identity bytes `0-2047` of a file is
gzipped and its Content-Length rewritten, while Content-Range still claims
`bytes 0-2047/10000`. RFC 9110 §14.4 / §8.4: the range offsets refer to the
selected representation (content coding included), so the header no longer
describes the body. FileServer (fs.mojo:381-430) produces exactly such
responses for `Range:` requests and advertises `Accept-Ranges: bytes`.

Repro: formal/repro/APP-26_compress_encodes_partial_content.mojo.

Status: resolved. `Compress.serve` now returns a 206, or any response with
`Content-Range`, unchanged. The model `compress` is the shipped code and
`compressOld` the pre-fix one. Regression tests:
`tests/http/test_middleware.mojo::test_compress_partial_content_passthrough`
and `::test_compress_content_range_header_passthrough`.
-/
namespace Flare.Bugs.APP_26

open Flare.L4.Middleware

def x206 : Resp :=
  ⟨206, [("Content-Range", "bytes 0-2047/10000"), ("Content-Length", "2048")],
    List.replicate 2048 65⟩

/-- Any encoder that changes the body; the stub stands for gzip, which
shrank the 2048 bytes to 35 in the repro. -/
def gzipStub : Enc → List UInt8 → List UInt8 := fun _ b => b.take 35

def cfgGzip : CCfg := ⟨⟨.gzip, 1000⟩, true, gzipStub, 1024⟩

theorem x206_partial : isPartial x206 = true := by native_decide

/-- Counterexample (pre-fix): the 206 is rewritten (35-byte body, status 206). -/
theorem partial_reencoded :
    (compressOld cfgGzip x206).status = 206 ∧ (compressOld cfgGzip x206).body.length = 35 := by
  native_decide

theorem violates_spec : ¬ PartialSpec (compressOld cfgGzip) := by
  intro h
  have := congrArg (fun r => r.body.length) (h x206 x206_partial)
  rw [partial_reencoded.2] at this
  have h2 : x206.body.length = 2048 := by simp only [x206, List.length_replicate]
  omega

/-- In general (pre-fix): any 206 without Content-Encoding, at or above the size
threshold, with gzip negotiated, got the encoder's output as its body. -/
theorem partial_body_replaced (c : CCfg) (x : Resp) (hq : c.pick.q ≠ 0) (he : c.pick.enc = .gzip)
    (hm : c.minSize ≤ x.body.length) (hce : hasH x.hdrs "content-encoding" = false) :
    (compressOld c x).body = c.encode .gzip x.body := by
  have hlt : ¬ x.body.length < c.minSize := by omega
  simp [compressOld, hq, hlt, hce, he, encodeAs]

/-- The shipped `compress` (partial responses pass through) meets the spec
for every configuration. -/
theorem fixed_meets_spec (c : CCfg) : PartialSpec (compress c) := compress_partial c

theorem fixed_on_example : compress cfgGzip x206 = x206 :=
  compress_partial cfgGzip x206 x206_partial

end Flare.Bugs.APP_26
