import Flare.L3_Protocol.H1.ClientChunked

/-!
# The client's HTTP/1.1 response reader

`flare/http/_client/parse.mojo` @59bda50 and `flare/http/_client/download.mojo`:

* `respFraming` mirrors `_response_framing` (RFC 9112 §6.3), shared by the
  buffered, framed and streaming readers; the `*_iff` theorems prove it
  implements §6.3 (with flare's stricter choices: TE + CL and a repeated
  CL are refused).
* `parseStatusOld` mirrors `_parse_status_line` before the H1-08 fix;
  `parseStatus` is the shipped parser (finding H1-08).
* `canReuseOld` mirrors the keep-alive decision of the framed reader before
  the H1-09 fix; `canReuse` is the shipped decision (HTTP/1.1 only).
* `splitGo`/`headOld` mirror `_find_crlf2_from`, `_split_lines` and the
  line loop of `_parse_response_head` before the H1-07 fix; `headImpl` is the
  shipped head parser (bare LF and empty lines refused); `lfHead` is an RFC 9112 §2.2
  recipient that recognises a bare LF as a line terminator (finding H1-07).
* `dlCloseOld` mirrors `HttpDownload._read_close` over the pre-fix transport,
  `dlClose` the shipped transport read with the close_notify guard
  (finding H1-11).
-/
namespace Flare.L3.H1.ClientResponse
open Flare Flare.L3.H1.Text Flare.L3.H1.ClientChunked

/-! ## Body framing (RFC 9112 §6.3) -/

inductive RFraming where
  | none
  | length (n : Nat)
  | chunked
  | close
  | reject
  deriving DecidableEq, Repr

/-- HEAD, 1xx, 204, 304 and a 2xx to CONNECT have no body. -/
def bodyless (isHead isConnect : Bool) (status : Nat) : Bool :=
  isHead || decide (status < 200) || status == 204 || status == 304 || (isConnect && decide (status < 300))

def CHUNKED : Bytes := Bytes.ofString "chunked"

/-- `cls`/`tes` are the (stripped) Content-Length and Transfer-Encoding
field values in order.
mirrors flare/http/_client/parse.mojo:128-170 @59bda50 -/
def respFraming (isHead isConnect : Bool) (status : Nat) (cls tes : List Bytes) : RFraming :=
  if bodyless isHead isConnect status then .none
  else if cls.length > 1 then .reject
  else
    let cl : Int := match cls with | [v] => parseCL v | _ => -1
    if cls.length = 1 ∧ cl < 0 then .reject
    else if tes ≠ [] then
      if tes.map lowerB ≠ [CHUNKED] then .reject
      else if 0 ≤ cl then .reject else .chunked
    else if 0 ≤ cl then .length cl.toNat else .close

theorem framing_bodyless {isHead isConnect : Bool} {status : Nat} {cls tes : List Bytes}
    (h : bodyless isHead isConnect status = true) : respFraming isHead isConnect status cls tes = .none := by
  simp [respFraming, h]

/-- RFC 9112 §6.3 item 3: Transfer-Encoding together with Content-Length is
refused (the RFC allows treating it as an error; flare always does). -/
theorem framing_te_cl_reject {isHead isConnect : Bool} {status : Nat} {cls tes : List Bytes}
    (hb : bodyless isHead isConnect status = false) (ht : tes ≠ []) (hc : cls ≠ []) :
    respFraming isHead isConnect status cls tes = .reject := by
  rcases cls with _ | ⟨v, _ | ⟨w, cs⟩⟩
  · exact absurd rfl hc
  · by_cases hcl : 0 ≤ parseCL v
    · simp [respFraming, hb, ht, hcl, Int.not_lt.mpr hcl]
    · simp [respFraming, hb, Int.lt_of_not_ge hcl]
  · simp [respFraming, hb]

/-- RFC 9112 §6.3 item 5: more than one Content-Length is refused. -/
theorem framing_dup_cl {isHead isConnect : Bool} {status : Nat} {cls tes : List Bytes}
    (hb : bodyless isHead isConnect status = false) (h : cls.length > 1) :
    respFraming isHead isConnect status cls tes = .reject := by
  simp [respFraming, hb, h]

theorem cl_cases (x : Int) : (0 ≤ x ∧ ¬ x < 0) ∨ (¬ 0 ≤ x ∧ x < 0) := by omega

theorem framing_chunked_iff (isHead isConnect : Bool) (status : Nat) (cls tes : List Bytes) :
    respFraming isHead isConnect status cls tes = .chunked ↔
      bodyless isHead isConnect status = false ∧ cls = [] ∧ ∃ v, tes = [v] ∧ lowerB v = CHUNKED := by
  cases hb : bodyless isHead isConnect status
  · rcases cls with _ | ⟨v, _ | ⟨w, cs⟩⟩
    · rcases tes with _ | ⟨t, _ | ⟨t2, ts⟩⟩
      · simp [respFraming, hb]
      · by_cases ht : lowerB t = CHUNKED <;> simp [respFraming, hb, ht]
      · simp [respFraming, hb]
    · rcases cl_cases (parseCL v) with ⟨h1, h2⟩ | ⟨h1, h2⟩ <;>
        rcases tes with _ | ⟨t, _ | ⟨t2, ts⟩⟩ <;> simp [respFraming, hb, h1, h2] <;> omega
    · simp [respFraming, hb]
  · simp [respFraming, hb]

theorem framing_length_iff (isHead isConnect : Bool) (status n : Nat) (cls tes : List Bytes) :
    respFraming isHead isConnect status cls tes = .length n ↔
      bodyless isHead isConnect status = false ∧ tes = [] ∧ ∃ v, cls = [v] ∧ parseCL v = n := by
  cases hb : bodyless isHead isConnect status
  · rcases cls with _ | ⟨v, _ | ⟨w, cs⟩⟩
    · rcases tes with _ | ⟨t, _ | ⟨t2, ts⟩⟩
      · simp [respFraming, hb]
      · by_cases ht : lowerB t = CHUNKED <;> simp [respFraming, hb, ht]
      · simp [respFraming, hb]
    · rcases cl_cases (parseCL v) with ⟨h1, h2⟩ | ⟨h1, h2⟩ <;>
        rcases tes with _ | ⟨t, _ | ⟨t2, ts⟩⟩ <;> simp [respFraming, hb, h1, h2] <;> omega
    · simp [respFraming, hb]
  · simp [respFraming, hb]

theorem framing_close_iff (isHead isConnect : Bool) (status : Nat) (cls tes : List Bytes) :
    respFraming isHead isConnect status cls tes = .close ↔
      bodyless isHead isConnect status = false ∧ cls = [] ∧ tes = [] := by
  cases hb : bodyless isHead isConnect status
  · rcases cls with _ | ⟨v, _ | ⟨w, cs⟩⟩
    · rcases tes with _ | ⟨t, _ | ⟨t2, ts⟩⟩
      · simp [respFraming, hb]
      · by_cases ht : lowerB t = CHUNKED <;> simp [respFraming, hb, ht]
      · simp [respFraming, hb]
    · rcases cl_cases (parseCL v) with ⟨h1, h2⟩ | ⟨h1, h2⟩ <;>
        rcases tes with _ | ⟨t, _ | ⟨t2, ts⟩⟩ <;> simp [respFraming, hb, h1, h2] <;> omega
    · simp [respFraming, hb]
  · simp [respFraming, hb]

/-! ## Status line (RFC 9112 §4) -/

def isDig (c : UInt8) : Bool := 48 ≤ c && c ≤ 57
def HTTP_ : Bytes := Bytes.ofString "HTTP/"

/-- `_parse_status_line`: `HTTP/` prefix, first SP, `lstrip`, three digits;
the reason is whatever follows byte 4. This is the parser before the H1-08
fix; kept for the counterexample.
mirrors flare/http/_client/parse.mojo:318-352 @59bda50 -/
def parseStatusOld (line : Bytes) : Option Nat :=
  if line.take 5 ≠ HTTP_ then none else
  match findB 32 line with
  | none => none
  | some sp =>
    match (line.drop (sp + 1)).dropWhile isSWS with
    | a :: b :: c :: _ =>
      if isDig a && isDig b && isDig c then
        some ((a.toNat - 48) * 100 + (b.toNat - 48) * 10 + (c.toNat - 48))
      else none
    | _ => none

/-- The shipped `_parse_status_line` (H1-08 fix): the code must be followed by
SP or the end of line.
mirrors flare/http/_client/parse.mojo:362-403 (fixed, H1-08) -/
def parseStatus (line : Bytes) : Option Nat :=
  if line.take 5 ≠ HTTP_ then none else
  match findB 32 line with
  | none => none
  | some sp =>
    match (line.drop (sp + 1)).dropWhile isSWS with
    | a :: b :: c :: r =>
      if isDig a && isDig b && isDig c && (r.head? = none || r.head? = some 32) then
        some ((a.toNat - 48) * 100 + (b.toNat - 48) * 10 + (c.toNat - 48))
      else none
    | _ => none

/-- RFC 9112 §4: `status-code = 3DIGIT`, delimited by SP on both sides
(the reason phrase may be empty; flare also tolerates its missing SP). -/
def CodeDelimited (line : Bytes) (code : Nat) : Prop :=
  ∃ pre ws a b c r, line = pre ++ [32] ++ ws ++ [a, b, c] ++ r ∧
    isDig a = true ∧ isDig b = true ∧ isDig c = true ∧ (r = [] ∨ r.head? = some 32) ∧
    code = (a.toNat - 48) * 100 + (b.toNat - 48) * 10 + (c.toNat - 48)

theorem split_at_findB {line : Bytes} {sp : Nat} (h : findB 32 line = some sp) :
    line = line.take sp ++ [32] ++ line.drop (sp + 1) := by
  obtain ⟨hlt, hget, -⟩ := findB_spec h
  have e : line.drop sp = 32 :: line.drop (sp + 1) := by
    rw [List.drop_eq_getElem_cons hlt]
    simp [Bytes.getD, List.getElem?_eq_getElem hlt] at hget
    rw [hget]
  conv => lhs; rw [← List.take_append_drop sp line, e]
  simp

theorem takeWhile_dropWhile (p : UInt8 → Bool) (l : Bytes) : l = l.takeWhile p ++ l.dropWhile p :=
  (List.takeWhile_append_dropWhile).symm

theorem parseStatus_delimited (line : Bytes) (code : Nat) (h : parseStatus line = some code) :
    CodeDelimited line code := by
  unfold parseStatus at h
  split at h; · cases h
  split at h; · cases h
  rename_i sp hsp
  split at h
  · rename_i a b c r hr
    split at h
    · rename_i hd
      cases h
      simp only [Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq] at hd
      obtain ⟨⟨⟨ha, hb⟩, hc⟩, hrr⟩ := hd
      refine ⟨line.take sp, (line.drop (sp + 1)).takeWhile isSWS, a, b, c, r, ?_, ha, hb, hc, ?_, rfl⟩
      · have e1 := split_at_findB hsp
        have e2 := takeWhile_dropWhile isSWS (line.drop (sp + 1))
        rw [hr] at e2
        conv => lhs; rw [e1, e2]
        simp
      · rcases hrr with h1 | h1
        · left; cases r <;> simp_all
        · right; simpa using h1
    · cases h
  · cases h

/-! ## Connection reuse (RFC 9112 §9.3) -/

def CLOSE : Bytes := Bytes.ofString "close"
def KEEPALIVE : Bytes := Bytes.ofString "keep-alive"
def HTTP11 : Bytes := Bytes.ofString "HTTP/1.1"
def HTTP10 : Bytes := Bytes.ofString "HTTP/1.0"

/-- A `Connection` token present in any of the field values. -/
def hasTok (tok : Bytes) (vals : List Bytes) : Bool :=
  vals.any fun v => (splitComma v).any fun t => lowerB (pyStrip t) == tok

/-- The framed reader's verdict before the H1-09 fix: `clean` (no bytes past the message),
no `close` token, and not close-delimited. The response's HTTP version is
never consulted.
mirrors flare/http/_client/parse.mojo:836-884 @59bda50 -/
def canReuseOld (_version : Bytes) (clean : Bool) (conn : List Bytes) (fr : RFraming) : Bool :=
  clean && !(hasTok CLOSE conn) && fr != .close

/-- The shipped decision (finding H1-09): only an HTTP/1.1 response leaves the
connection open. An HTTP/1.0 response with `keep-alive` is not pooled either,
which is stricter than RFC 9112 §9.3 allows and still meets `PersistOK`.
mirrors flare/http/_client/parse.mojo `can_reuse = clean and not conn_close and http11` -/
def canReuse (version : Bytes) (clean : Bool) (conn : List Bytes) (fr : RFraming) : Bool :=
  canReuseOld version clean conn fr && version == HTTP11

/-- RFC 9112 §9.3: the connection persists after a response only if it is
HTTP/1.1 without `close`, or HTTP/1.0 with `keep-alive`. -/
def PersistOK (reuse : Bytes → Bool → List Bytes → RFraming → Bool) : Prop :=
  ∀ v clean conn fr, reuse v clean conn fr = true →
    ¬ hasTok CLOSE conn = true ∧ (v = HTTP11 ∨ (v = HTTP10 ∧ hasTok KEEPALIVE conn = true))

theorem canReuse_ok : PersistOK canReuse := by
  intro v clean conn fr h
  simp only [canReuse, canReuseOld, Bool.and_eq_true, Bool.not_eq_true', beq_iff_eq,
    bne_iff_ne, ne_eq] at h
  exact ⟨by simp [h.1.1.2], Or.inl h.2⟩

/-! ## Response head lines (RFC 9112 §2.1, §2.2) -/

/-- `_bytes_to_str`: NUL and bytes ≥ 0x80 become `?`.
mirrors flare/http/_client/parse.mojo:262-280 @59bda50 -/
def san (c : UInt8) : UInt8 := if c = 0 ∨ 128 ≤ c then 63 else c

/-- First `CR LF CR LF`.
mirrors flare/http/_client/parse.mojo:233-245 @59bda50 -/
def findCRLF2 : Bytes → Option Nat
  | a :: b :: c :: d :: t =>
    if a = 13 ∧ b = 10 ∧ c = 13 ∧ d = 10 then some 0 else (findCRLF2 (b :: c :: d :: t)).map (· + 1)
  | _ => none

/-- `_split_lines`: CRLF or a bare LF ends a line; a non-empty last segment
is kept. `acc` is the current segment, reversed.
mirrors flare/http/_client/parse.mojo:283-306 @59bda50 -/
def splitGo (acc : Bytes) : Bytes → List Bytes
  | [] => if acc = [] then [] else [acc.reverse]
  | c :: t =>
    if c = 10 then acc.reverse :: splitGo [] t
    else if c = 13 ∧ t.head? = some 10 then acc.reverse :: splitGo [] t.tail
    else splitGo (c :: acc) t
termination_by l => l.length
decreasing_by all_goals simp only [List.length_cons, List.length_tail]; omega

def splitLines (h : Bytes) : List Bytes := splitGo [] h

theorem splitGo_cons (acc : Bytes) (c : UInt8) (t : Bytes) : splitGo acc (c :: t) =
    if c = 10 then acc.reverse :: splitGo [] t
    else if c = 13 ∧ t.head? = some 10 then acc.reverse :: splitGo [] t.tail
    else splitGo (c :: acc) t := by
  rw [splitGo.eq_2]

/-- Mojo sanitises the head before splitting; `san` fixes CR and LF and
maps every other byte to a non-CR/LF byte, so splitting first is the same
(`splitLines_san`). The head parser skips empty lines.
This is the head parser before the H1-07 fix; kept for the counterexample.
mirrors flare/http/_client/parse.mojo:89-125, 195-204 @59bda50 -/
def headOld (m : Bytes) : Option (List Bytes × Bytes) :=
  match findCRLF2 m with
  | none => none
  | some p =>
    match splitLines (m.take p) with
    | [] => none
    | s :: fs => if s = [] then none else some ((s :: fs.filter (· ≠ [])).map (·.map san), m.drop (p + 4))

/-- A LF not preceded by CR. -/
def hasBareLF : Bytes → Bool
  | [] => false
  | c :: t =>
    if c = 10 then true
    else if c = 13 ∧ t.head? = some 10 then hasBareLF t.tail
    else hasBareLF t
termination_by l => l.length
decreasing_by all_goals simp only [List.length_cons, List.length_tail]; omega

theorem hasBareLF_cons (c : UInt8) (t : Bytes) : hasBareLF (c :: t) =
    if c = 10 then true
    else if c = 13 ∧ t.head? = some 10 then hasBareLF t.tail
    else hasBareLF t := by
  rw [hasBareLF.eq_2]

/-- The shipped head parser (H1-07 fix): a head holding a bare LF, or an empty
line before its end, is refused.
mirrors flare/http/_client/parse.mojo:98-148 (fixed, H1-07) -/
def headImpl (m : Bytes) : Option (List Bytes × Bytes) :=
  match findCRLF2 m with
  | none => none
  | some p =>
    if hasBareLF (m.take p) then none else
    let ls := splitLines (m.take p)
    if ls = [] ∨ [] ∈ ls then none else some (ls.map (·.map san), m.drop (p + 4))

/-- An RFC 9112 §2.2 recipient that recognises a bare LF as a line
terminator (ignoring one preceding CR): the head ends at the first empty
line. Returns the lines before it and the body. -/
def lfGo (acc : Bytes) : Bytes → Option (List Bytes × Bytes)
  | [] => none
  | c :: t =>
    if c = 10 then
      let line := (if acc.head? = some 13 then acc.tail else acc).reverse
      if line = [] then some ([], t) else (lfGo [] t).map fun r => (line :: r.1, r.2)
    else lfGo (c :: acc) t

def lfHead (m : Bytes) : Option (List Bytes × Bytes) := lfGo [] m

/-- flare's header lines and body start are the LF-recognising recipient's
(up to `_bytes_to_str`). -/
def HeadAgrees (f : Bytes → Option (List Bytes × Bytes)) : Prop :=
  ∀ m ls b, f m = some (ls, b) → ∃ ls0, lfHead m = some (ls0, b) ∧ ls = ls0.map (·.map san)

theorem san_crlf {c d : UInt8} (hd : d = 10 ∨ d = 13) : san c = d ↔ c = d := by
  unfold san
  have hc := c.toNat_lt
  constructor
  · intro h
    split at h
    · rcases hd with rfl | rfl <;> simp at h
    · exact h
  · rintro rfl
    rw [if_neg]
    rcases hd with rfl | rfl <;> simp [UInt8.le_iff_toNat_le]

theorem splitGo_san (acc : Bytes) (h : Bytes) :
    splitGo (acc.map san) (h.map san) = (splitGo acc h).map (·.map san) := by
  fun_induction splitGo acc h with
  | case1 => simp [splitGo]
  | case2 acc ha => simp [splitGo, ha, List.map_reverse]
  | case3 acc t ih =>
    rw [List.map_cons, splitGo_cons, if_pos ((san_crlf (Or.inl rfl)).mpr rfl)]
    simp only [List.map_nil] at ih
    simp [ih, List.map_reverse]
  | case4 acc c t hc h13 ih =>
    obtain ⟨rfl, ht⟩ := h13
    obtain ⟨x, xs, rfl⟩ : ∃ x xs, t = x :: xs := by
      cases t with
      | nil => simp at ht
      | cons x xs => exact ⟨x, xs, rfl⟩
    simp at ht; subst ht
    simp only [List.map_nil, List.tail_cons] at ih
    have h13' : san 13 = 13 ∧ (List.map san (10 :: xs)).head? = some 10 := by simp [san]
    rw [List.map_cons, splitGo_cons, if_neg (by simp [san]), if_pos h13']
    simp [ih, List.map_reverse]
  | case5 acc c t hc h13 ih =>
    rw [List.map_cons, splitGo_cons, if_neg (fun x => hc ((san_crlf (Or.inl rfl)).mp x))]
    have : ¬ (san c = 13 ∧ (t.map san).head? = some 10) := by
      rintro ⟨x, y⟩
      apply h13
      refine ⟨(san_crlf (Or.inr rfl)).mp x, ?_⟩
      cases t with
      | nil => simp at y
      | cons z zs => simp at y ⊢; exact (san_crlf (Or.inl rfl)).mp y
    rw [if_neg this, ← List.map_cons, ih]

theorem splitLines_san (h : Bytes) : splitLines (h.map san) = (splitLines h).map (·.map san) :=
  splitGo_san [] h

/-! ### Proof that the fixed head parser agrees with the LF recipient -/

def CRLF : Bytes := [13, 10]

/-- `CRLF`-joined lines. -/
def joinL : List Bytes → Bytes
  | [] => []
  | [s] => s
  | s :: ss => s ++ CRLF ++ joinL ss

theorem findCRLF2_spec : ∀ {m : Bytes} {p : Nat}, findCRLF2 m = some p →
    m.drop p = 13 :: 10 :: 13 :: 10 :: m.drop (p + 4) ∧
    ∀ q, q < p → ¬ ∃ r, m.drop q = 13 :: 10 :: 13 :: 10 :: r
  | a :: b :: c :: d :: t, p, h => by
    simp only [findCRLF2] at h
    split at h
    · rename_i habcd
      simp at h; subst h
      obtain ⟨rfl, rfl, rfl, rfl⟩ := habcd
      exact ⟨rfl, fun q hq => absurd hq (by omega)⟩
    · rename_i habcd
      cases h' : findCRLF2 (b :: c :: d :: t) with
      | none => simp [h'] at h
      | some j =>
        simp [h'] at h; subst h
        obtain ⟨h1, h2⟩ := findCRLF2_spec h'
        refine ⟨by simpa using h1, ?_⟩
        intro q hq ⟨r, hr⟩
        cases q with
        | zero => simp at hr; exact habcd ⟨hr.1, hr.2.1, hr.2.2.1, hr.2.2.2.1⟩
        | succ q => exact h2 q (by omega) ⟨r, by simpa using hr⟩
  | [], _, h | [_], _, h | [_, _], _, h | [_, _, _], _, h => by simp [findCRLF2] at h

theorem take_not_endsCRLF {m : Bytes} {p : Nat} (h : findCRLF2 m = some p) :
    ¬ ∃ x, m.take p = x ++ CRLF := by
  rintro ⟨x, hx⟩
  obtain ⟨h1, h2⟩ := findCRLF2_spec h
  have hl : x.length + 2 = p := by
    have := congrArg List.length hx
    have hp : p ≤ m.length := by
      rcases Nat.lt_or_ge m.length p with hc | hc
      · rw [List.drop_eq_nil_of_le (by omega)] at h1; cases h1
      · exact hc
    simp [CRLF, List.length_take] at this; omega
  apply h2 x.length (by omega)
  refine ⟨13 :: 10 :: m.drop (p + 4), ?_⟩
  have e : m.drop x.length = CRLF ++ m.drop p := by
    conv => lhs; rw [← List.take_append_drop p m, hx]
    simp
  rw [e, h1]; rfl

theorem splitGo_ne_nil : ∀ (acc h : Bytes), (acc ≠ [] ∨ h ≠ []) → splitGo acc h ≠ [] := by
  intro acc h
  fun_induction splitGo acc h with
  | case1 => intro hh; simp at hh
  | case2 acc ha => intro _; simp [splitGo, ha]
  | case3 acc t ih => intro _; simp
  | case4 acc c t hc h13 ih => intro _; simp
  | case5 acc c t hc h13 ih => intro _; exact ih (Or.inl (by simp))

theorem joinL_cons (s : Bytes) (ss : List Bytes) (h : ss ≠ []) : joinL (s :: ss) = s ++ CRLF ++ joinL ss := by
  match ss, h with
  | _ :: _, _ => rfl

/-- Without a bare LF and not ending in CRLF, a head is the CRLF-join of its
lines, and no line holds an LF. -/
theorem splitGo_join : ∀ (acc h : Bytes), hasBareLF h = false → (¬ ∃ x, h = x ++ CRLF) → 10 ∉ acc →
    joinL (splitGo acc h) = acc.reverse ++ h ∧ ∀ s ∈ splitGo acc h, 10 ∉ s := by
  intro acc h
  fun_induction splitGo acc h with
  | case1 => intro _ _ _; simp [splitGo, joinL]
  | case2 acc h0 => intro _ _ ha; simp [splitGo, h0, joinL, ha]
  | case3 acc t ih => intro hb; rw [hasBareLF_cons, if_pos rfl] at hb; cases hb
  | case4 acc c t hc h13 ih =>
    intro hb he ha
    obtain ⟨rfl, ht⟩ := h13
    rw [hasBareLF_cons, if_neg hc, if_pos ⟨rfl, ht⟩] at hb
    obtain ⟨y, ys, rfl⟩ : ∃ y ys, t = y :: ys := by
      cases t with
      | nil => simp at ht
      | cons y ys => exact ⟨y, ys, rfl⟩
    simp at ht; subst ht
    simp only [List.tail_cons] at hb ih ⊢
    have hys : ys ≠ [] := by rintro rfl; exact he ⟨[], rfl⟩
    have hne : ¬ ∃ x, ys = x ++ CRLF := by
      rintro ⟨x, rfl⟩; exact he ⟨13 :: 10 :: x, rfl⟩
    obtain ⟨j1, j2⟩ := ih hb hne (by simp)
    refine ⟨?_, ?_⟩
    · rw [joinL_cons _ _ (splitGo_ne_nil [] ys (Or.inr hys)), j1]; simp [CRLF]
    · intro s hs
      rcases List.mem_cons.mp hs with rfl | hs
      · simpa using ha
      · exact j2 s hs
  | case5 acc c t hc h13 ih =>
    intro hb he ha
    have hb' : hasBareLF t = false := by rw [hasBareLF_cons, if_neg hc, if_neg h13] at hb; exact hb
    have hne : ¬ ∃ x, t = x ++ CRLF := by
      rintro ⟨x, rfl⟩; exact he ⟨c :: x, rfl⟩
    obtain ⟨j1, j2⟩ := ih hb' hne (by simp [ha]; exact fun e => hc e.symm)
    exact ⟨by rw [j1]; simp, j2⟩

theorem lfGo_append (acc s rest : Bytes) (hs : 10 ∉ s) : lfGo acc (s ++ rest) = lfGo (s.reverse ++ acc) rest := by
  induction s generalizing acc with
  | nil => rfl
  | cons x xs ih =>
    have hx : x ≠ 10 := fun e => hs (by simp [e])
    rw [List.cons_append, lfGo, if_neg hx, ih _ (fun e => hs (by simp [e]))]
    simp

theorem lfGo_join : ∀ (ss : List Bytes) (b : Bytes), ss ≠ [] → (∀ s ∈ ss, s ≠ [] ∧ 10 ∉ s) →
    lfGo [] (joinL ss ++ [13, 10, 13, 10] ++ b) = some (ss, b)
  | [], _, h, _ => absurd rfl h
  | [s], b, _, hs => by
    obtain ⟨h1, h2⟩ := hs s (by simp)
    simp only [joinL, List.append_assoc]
    rw [lfGo_append _ _ _ h2]
    simp only [List.cons_append, List.nil_append]
    rw [lfGo, if_neg (by decide), lfGo, if_pos rfl]
    simp only [List.head?_cons, if_true, List.tail_cons, List.append_nil, List.reverse_reverse]
    rw [if_neg h1, lfGo, if_neg (by decide), lfGo, if_pos rfl]
    simp
  | s :: s2 :: ss, b, _, hs => by
    obtain ⟨h1, h2⟩ := hs s (by simp)
    have ih := lfGo_join (s2 :: ss) b (by simp) (fun x hx => hs x (by simp [hx]))
    rw [joinL_cons _ _ (by simp)]
    simp only [CRLF, List.append_assoc]
    rw [lfGo_append _ _ _ h2]
    simp only [List.cons_append, List.nil_append]
    rw [lfGo, if_neg (by decide), lfGo, if_pos rfl]
    simp only [List.head?_cons, if_true, List.tail_cons, List.append_nil, List.reverse_reverse]
    rw [if_neg h1]
    simp only [List.append_assoc, List.cons_append, List.nil_append] at ih
    rw [ih]; rfl

/-- **H1-07 fix meets spec**: when the fixed head parser accepts, its lines
and body start are exactly those of an LF-recognising recipient. -/
theorem headImpl_agrees : HeadAgrees headImpl := by
  intro m ls b h
  unfold headImpl at h
  split at h; · cases h
  rename_i p hp
  split at h; · cases h
  rename_i hb
  simp only at h
  split at h; · cases h
  rename_i hne
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  refine ⟨splitLines (m.take p), ?_, rfl⟩
  have hb' : hasBareLF (m.take p) = false := by simpa using hb
  obtain ⟨j1, j2⟩ := splitGo_join [] (m.take p) hb' (take_not_endsCRLF hp) (by simp)
  have hm : m = joinL (splitLines (m.take p)) ++ [13, 10, 13, 10] ++ m.drop (p + 4) := by
    rw [splitLines, j1, List.reverse_nil, List.nil_append]
    conv => lhs; rw [← List.take_append_drop p m, (findCRLF2_spec hp).1]
    simp
  have hne' : splitLines (m.take p) ≠ [] ∧ [] ∉ splitLines (m.take p) := by
    simpa [not_or] using hne
  rw [lfHead]
  conv => lhs; rw [hm]
  exact lfGo_join _ _ hne'.1 (fun s hs => ⟨fun e => hne'.2 (e ▸ hs), j2 s hs⟩)

/-! ## TLS end of stream (finding H1-11) -/

/-- `HttpDownload._read_close` over the pre-fix transport: a close-delimited
body ends at the first `read` returning 0, clean or not. Kept for the
H1-11 counterexample.
mirrors flare/http/_client/download.mojo:215-220 @59bda50 -/
def dlCloseOld (reads : List Bytes) (_unclean : Bool) : Except String Bytes := .ok reads.flatten

/-- The buffered readers' guard: a close-delimited body that ended without
close_notify raises.
mirrors flare/http/_client/parse.mojo:665-683 @59bda50 -/
def bufferedClose (reads : List Bytes) (unclean : Bool) : Except String Bytes :=
  if unclean then .error "TLS connection closed without close_notify" else .ok reads.flatten

/-- The shipped streaming reader: `_H2Transport.read` raises when a TLS read
returns 0 without close_notify, so `_read_close` never sees that end.
mirrors flare/http/_client/h2_transport.mojo:69-96 (fixed, H1-11) -/
abbrev dlClose := bufferedClose

/-- A close-delimited TLS body is complete only if the stream ended with
close_notify (RFC 8446 §6.1, RFC 9112 §8). -/
def TruncSafe (f : List Bytes → Bool → Except String Bytes) : Prop :=
  ∀ reads out, f reads true ≠ .ok out

theorem bufferedClose_safe : TruncSafe bufferedClose := by
  intro reads out h; simp [bufferedClose] at h

end Flare.L3.H1.ClientResponse
