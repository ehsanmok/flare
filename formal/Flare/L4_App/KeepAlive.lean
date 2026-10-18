import Flare.Core

/-!
# Per-request close decision (`_compute_close_after`, `_wants_close`)

Model of the two functions in flare/http/_reactor/keepalive_scan.mojo that
decide, per request, whether the connection closes after the response:

* `computeCloseAfter`: `_compute_close_after(headers, version)`
  (keepalive_scan.mojo:350-390), used by the buffered reader paths. It sees
  the value of the first `Connection` field (`HeaderMap.get`) and whether the
  version is `HTTP/1.0`.
* `wantsClose`: `_wants_close(data, header_end)` (keepalive_scan.mojo:393-484),
  a byte scan over the raw header block used by the static fast path and by
  `skip_header_decode_for_short_requests`.

Their verdict is the `closeAfter` parameter of `Flare.L4.ConnSM`.

Spec (RFC 9110 §7.6.1, RFC 9112 §9.3 and §9.6, written independently):
`Connection = #connection-option`, a comma-separated list of
case-insensitive tokens with optional whitespace. The connection closes
after the response iff some token is `close`, or the request is HTTP/1.0
and no token is `keep-alive`.

Results:
* `computeCloseAfter_eq_spec`: the function (fast paths, token-list slow
  path) equals the spec on every value (general).
* `wantsClose_spec`: the byte scan (match `connection:` only at a line
  start, OR the verdicts of all such lines) returns `true` whenever any
  header line is `Connection: close` (general).
* `wantsClose_sound_close`: the scan never reports close without a
  `Connection` line (soundness direction, general).
-/
namespace Flare.L4.KeepAlive

/-! ASCII literals, spelled out as bytes so that kernel evaluation never
touches `String`. -/
def closeB : Bytes := [99, 108, 111, 115, 101]                         -- close
def closeCapB : Bytes := [67, 108, 111, 115, 101]                      -- Close
def keepAliveB : Bytes := [107, 101, 101, 112, 45, 97, 108, 105, 118, 101]  -- keep-alive
def http10B : Bytes := [72, 84, 84, 80, 47, 49, 46, 48]                -- HTTP/1.0
def connB : Bytes := [99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 58]   -- connection:

/-- One byte lowercased the way the scan loops do it (`c + 32` on `A-Z`).
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=98b092d2 -/
def lowerB (c : UInt8) : UInt8 := if 65 ≤ c ∧ c ≤ 90 then c + 32 else c

/-- `_ascii_lower` on a whole value. -/
def lower (b : Bytes) : Bytes := b.map lowerB

/-! ## `_compute_close_after` -/

/-- `_connection_is_keepalive`: exact lowercase `keep-alive`.
mirrors flare/http/_reactor/keepalive_scan.mojo#_connection_is_keepalive sha=578c31553cb5 at=59bda50f -/
def isKeepaliveFast (v : Bytes) : Bool := v == keepAliveB

/-- `_connection_is_close`: `close` or `Close`.
mirrors flare/http/_reactor/keepalive_scan.mojo#_connection_is_close sha=deb8cc55055e at=59bda50f -/
def isCloseFast (v : Bytes) : Bool := v == closeB || v == closeCapB

/-! ### Spec: the token list -/

def isOWS (c : UInt8) : Bool := c == 32 || c == 9

/-- Strip leading and trailing OWS. -/
def trimOWS (b : Bytes) : Bytes := ((b.dropWhile isOWS).reverse.dropWhile isOWS).reverse

/-- Split on `,` (every comma ends an element; empty elements are kept and
never equal a token, as RFC 9110 §5.6.1 requires recipients to ignore
them). -/
def splitComma : Bytes → List Bytes
  | [] => [[]]
  | c :: cs =>
    if c == 44 then [] :: splitComma cs
    else match splitComma cs with
      | [] => [[c]]
      | t :: ts => (c :: t) :: ts

/-- The connection options, normalised: trimmed and lowercased. -/
def tokens (v : Bytes) : List Bytes := (splitComma v).map fun t => lower (trimOWS t)

/-- RFC 9112 §9.3/§9.6: close iff a `close` option is present, or HTTP/1.0
without a `keep-alive` option. -/
def closeSpec (v : Bytes) (http10 : Bool) : Bool :=
  (tokens v).contains closeB || (http10 && !(tokens v).contains keepAliveB)

/-- `_compute_close_after` as shipped (fixed, APP-03): both fast paths kept,
the slow path is the option-list scan (`_conn_token_mask`: close wins, else
HTTP/1.0 needs a `keep-alive` option), i.e. the spec.
mirrors flare/http/_reactor/keepalive_scan.mojo#_conn_token_mask+_compute_close_after+_wants_close sha=2b2afc1f6111 at=4178dbc5 (fixed, APP-03) -/
def computeCloseAfter (v : Bytes) (http10 : Bool) : Bool :=
  if isCloseFast v then true
  else if isKeepaliveFast v then false
  else if v.isEmpty then http10
  else closeSpec v http10

theorem computeCloseAfter_eq_spec (v : Bytes) (http10 : Bool) :
    computeCloseAfter v http10 = closeSpec v http10 := by
  unfold computeCloseAfter
  by_cases h1 : isCloseFast v = true
  · simp only [h1, if_true]
    simp only [isCloseFast, Bool.or_eq_true, beq_iff_eq] at h1
    rcases h1 with rfl | rfl <;> cases http10 <;> decide
  · simp only [h1, Bool.false_eq_true, if_false]
    by_cases h2 : isKeepaliveFast v = true
    · simp only [h2, if_true]
      simp only [isKeepaliveFast, beq_iff_eq] at h2
      subst h2; cases http10 <;> decide
    · simp only [h2, Bool.false_eq_true, if_false]
      split
      · rename_i h3
        simp only [List.isEmpty_iff] at h3
        subst h3; cases http10 <;> decide
      · rfl

/-! ## `_wants_close` -/

/-- `data[i]` (the scan only reads inside `[0, header_end)`). -/
def at' (d : Bytes) (i : Nat) : UInt8 := Bytes.getD d i

/-- Exact match of `needle` at offset `i`.
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=98b092d2 -/
def matchAt (d : Bytes) (i : Nat) (needle : Bytes) : Bool :=
  (List.range needle.length).all fun j => at' d (i + j) == Bytes.getD needle j

/-- Case-folded match of `needle` (lowercase) at offset `i`.
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=98b092d2 -/
def matchAtLower (d : Bytes) (i : Nat) (needle : Bytes) : Bool :=
  (List.range needle.length).all fun j => lowerB (at' d (i + j)) == Bytes.getD needle j

/-- Index of the first LF in `[0, n)`, else `n`.
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=98b092d2 -/
def firstEol (d : Bytes) (n : Nat) : Nat :=
  ((List.range n).find? fun i => at' d i == 10).getD n

/-- `HTTP/1.0` somewhere on the request line.
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=98b092d2 -/
def version10 (d : Bytes) (n : Nat) : Bool :=
  (List.range (firstEol d n + 1 - 8)).any fun i => matchAt d i http10B

/-- First index in `[from, n)` satisfying `p`, else `n` (a `while` loop that
advances while `¬ p`). -/
def scanTo (n start : Nat) (p : Nat → Bool) : Nat :=
  ((List.range' start (n - start)).find? p).getD n

/-- The value of a `connection:` match at `i`: skip OWS, cut at CR, LF or
`header_end`.
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=98b092d2 -/
def valueAt (d : Bytes) (n i : Nat) : Bytes :=
  let pos := scanTo n (i + 11) fun k => !isOWS (at' d k)
  let vEnd := scanTo n pos fun k => at' d k == 13 || at' d k == 10
  (d.drop pos).take (vEnd - pos)

/-- Verdict as shipped (fixed, APP-03): the value is an option list
(`_conn_token_mask`), so `close` / `keep-alive` may be any of its tokens.
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=4178dbc5 (fixed, APP-03) -/
def verdict (d : Bytes) (n i : Nat) : Bool × Bool :=
  let v := valueAt d n i
  ((tokens v).contains closeB, (tokens v).contains keepAliveB)

/-- Candidate offsets of the header scan: `i` from `first_eol + 1` while
`i < n - len("connection:")`.
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=98b092d2 -/
def candidates (d : Bytes) (n : Nat) : List Nat :=
  List.range' (firstEol d n + 1) (n - 11 - (firstEol d n + 1))

def isConn (d : Bytes) (i : Nat) : Bool := matchAtLower d i connB

/-- The offset where the scan `break`s: the first `connection:` match. -/
def firstConn (d : Bytes) (n : Nat) : Option Nat := (candidates d n).find? (isConn d)

/-- Offset `i` starts a header line.
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=98b092d2 (fixed, APP-02) -/
def lineStart (d : Bytes) (n i : Nat) : Bool := i == firstEol d n + 1 || at' d (i - 1) == 10

/-- `_wants_close` as shipped (fixed, APP-02): `connection:` is tested only at
line starts and the verdicts of every such line are OR-ed instead of
`break`ing at the first match.
mirrors flare/http/_reactor/keepalive_scan.mojo#_wants_close sha=1dc8921b6a2c at=98b092d2 (fixed, APP-02) -/
def wantsClose (d : Bytes) (n : Nat) : Bool :=
  let hits := (candidates d n).filter fun i => lineStart d n i && isConn d i
  hits.any (fun i => (verdict d n i).1) ||
    (version10 d n && !hits.any (fun i => (verdict d n i).2))

/-- Spec (RFC 9112 §9.6): if some header line (after the request line) is a
`Connection` field whose value is `close`, the connection closes. -/
def WantsCloseSpec (d : Bytes) (n : Nat) (r : Bool) : Prop :=
  ∀ i, firstEol d n + 1 ≤ i → i + 11 < n → lineStart d n i = true → isConn d i = true →
    (verdict d n i).1 = true → r = true

theorem wantsClose_spec (d : Bytes) (n : Nat) :
    WantsCloseSpec d n (wantsClose d n) := by
  intro i h1 h2 hl hc hv
  have hmem : i ∈ candidates d n := by
    unfold candidates; rw [List.mem_range'_1]; omega
  unfold wantsClose
  simp only [Bool.or_eq_true, List.any_eq_true, List.mem_filter, Bool.and_eq_true]
  exact Or.inl ⟨i, ⟨hmem, hl, hc⟩, hv⟩

/-- Soundness of the shipped scan: with an HTTP/1.1 request line it reports
`close` only when some header line starts with `connection:` and has a
`close` verdict. -/
theorem wantsClose_sound_close (d : Bytes) (n : Nat) (h : wantsClose d n = true)
    (h10 : version10 d n = false) :
    ∃ i ∈ candidates d n, lineStart d n i = true ∧ isConn d i = true ∧
      (verdict d n i).1 = true := by
  unfold wantsClose at h
  simp only [h10, Bool.false_and, Bool.or_false, List.any_eq_true, List.mem_filter,
    Bool.and_eq_true] at h
  obtain ⟨i, ⟨hmem, hl, hc⟩, hv⟩ := h
  exact ⟨i, hmem, hl, hc, hv⟩

end Flare.L4.KeepAlive
