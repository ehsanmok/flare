import Flare.L3_Protocol.H1.FieldValue

/-!
# obs-fold in the server's header-field loop

`_parse_http_request_bytes` (`flare/http/_server/parse.mojo:203-320`
@59bda50) reads field lines one at a time and commits a field only when the
next line shows it is not continued. With `allow_obs_fold`, a line starting
with SP/HTAB is a continuation: its stripped bytes are appended to the
previous value after one SP.

* `fields` is the loop (a continuation passes the same `valueOk` check as a
  first line). `fields_valid`: every stored value passes `valueOk`.

Lines are as `_read_line_buf_lenient` returns them (terminator and one CR
removed); an empty line, or the end of the data, ends the block. Name
whitespace leniency (`allow_ows_around_colon`) and the Content-Length /
Transfer-Encoding bookkeeping are not modelled (they do not touch values).
-/
namespace Flare.L3.H1.ObsFold
open Flare Flare.L3.H1.Text Flare.L3.H1.FieldValue

def isSPHT (c : UInt8) : Bool := c == 32 || c == 9

/-- mirrors flare/http/_server/parse_util.mojo#_ascii_strip_slice sha=bac9f9c64e73 at=59bda50f -/
def aStrip (l : Bytes) : Bytes := ((l.dropWhile isSPHT).reverse.dropWhile isSPHT).reverse

/-- First `:`. -/
def colonAt (l : Bytes) : Option Nat := l.findIdx? (· == 58)

abbrev Field := Bytes × Bytes

/-- The shipped loop (H1-10 fix): the continuation passes the same value check.
`_check_field_value` also refuses obs-text that is not UTF-8 (H1-05,
`FieldValue.valueAccepted`); `valueOk` leaves that out, so this loop accepts
a superset of what the code accepts.
mirrors flare/http/_server/parse.mojo#_check_field_value+_parse_http_request_bytes sha=e947e2428622 at=e767e34c (fixed, H1-10) -/
def fields (obsFold obsText : Bool) : Option Field → List Bytes → Except String (List Field)
  | prev, [] => .ok prev.toList
  | prev, l :: ls =>
    if l = [] then .ok prev.toList
    else if isSPHT (l.headD 0) then
      match obsFold, prev with
      | true, some (k, v) =>
        if !valueOk obsText (aStrip l) then .error "invalid header value"
        else fields obsFold obsText (some (k, v ++ [32] ++ aStrip l)) ls
      | _, _ => .error "obs-fold rejected"
    else
      match colonAt l with
      | none => .error "header line without a colon"
      | some c =>
        if c = 0 then .error "empty header field name"
        else if !((l.take c).all isTchar) then .error "invalid character in header name"
        else
          let v := aStrip (l.drop (c + 1))
          if !valueOk obsText v then .error "invalid header value"
          else (fields obsFold obsText (some (aStrip (l.take c), v)) ls).map (prev.toList ++ ·)

/-- A continuation line: non-empty, starting with SP or HTAB. -/
def IsCont (l : Bytes) : Prop := l ≠ [] ∧ isSPHT (l.headD 0) = true

/-- RFC 9112 §5.2: each obs-fold is replaced by one SP. -/
def unfoldOnto (v : Bytes) (cs : List Bytes) : Bytes := v ++ (cs.map fun c => [32] ++ aStrip c).flatten

/-- Every stored value passes the byte check. -/
def AllValid (obsText : Bool) (hs : List Field) : Prop := ∀ kv ∈ hs, valueOk obsText kv.2 = true

theorem byteOk_sp (obsText : Bool) : byteOk obsText 32 = true := by
  cases obsText <;> decide

theorem valueOk_join {obsText : Bool} {v s : Bytes} (hv : valueOk obsText v = true)
    (hs : valueOk obsText s = true) : valueOk obsText (v ++ [32] ++ s) = true := by
  simp only [valueOk, List.all_append, Bool.and_eq_true] at hv hs ⊢
  exact ⟨⟨hv, by simp [byteOk_sp]⟩, hs⟩

theorem prev_valid {obsText : Bool} {prev : Option Field}
    (hp : ∀ kv, prev = some kv → valueOk obsText kv.2 = true) : AllValid obsText prev.toList := by
  intro kv hkv
  cases prev with
  | none => simp at hkv
  | some x => simp at hkv; subst hkv; exact hp _ rfl

/-- **H1-10 fix meets spec**: with or without folding, every stored value
passes `valueOk`. -/
theorem fields_valid (obsFold obsText : Bool) : ∀ (ls : List Bytes) (prev : Option Field) (hs : List Field),
    (∀ kv, prev = some kv → valueOk obsText kv.2 = true) →
    fields obsFold obsText prev ls = .ok hs → AllValid obsText hs
  | [], prev, hs, hp, h => by simp [fields] at h; subst h; exact prev_valid hp
  | l :: ls, prev, hs, hp, h => by
    unfold fields at h
    split at h
    · simp at h; subst h; exact prev_valid hp
    split at h
    · match obsFold, prev, hp, h with
      | true, some (k, v), hp, h =>
        dsimp only at h
        by_cases hs' : valueOk obsText (aStrip l) = true
        · rw [if_neg (by simp [hs'])] at h
          exact fields_valid true obsText ls _ hs (fun kv hkv => by
            simp at hkv; subst hkv
            simpa using valueOk_join (hp _ rfl) hs') h
        · rw [if_pos (by simpa using hs')] at h; cases h
      | false, none, _, h => simp at h
      | false, some _, _, h => simp at h
      | true, none, _, h => simp at h
    split at h
    · cases h
    split at h
    · cases h
    split at h
    · cases h
    dsimp only at h
    split at h
    · cases h
    rename_i hv
    cases hr : fields obsFold obsText _ ls with
    | error e => rw [hr] at h; cases h
    | ok r =>
      rw [hr] at h; simp [Except.map] at h; subst h
      have ih := fields_valid obsFold obsText ls _ r (fun kv hkv => by
        simp at hkv; subst hkv; simpa using hv) hr
      intro kv hkv
      rcases List.mem_append.mp hkv with h1 | h1
      · exact prev_valid hp kv h1
      · exact ih kv h1

/-- The fix changes nothing for valid continuations: a run of continuations
that are each `valueOk` unfolds exactly as RFC 9112 §5.2 says. -/
theorem fold_unfold (obsText : Bool) (k : Bytes) :
    ∀ (cs : List Bytes) (v : Bytes) (rest : List Bytes), (∀ c ∈ cs, IsCont c ∧ valueOk obsText (aStrip c) = true) →
      fields true obsText (some (k, v)) (cs ++ rest) = fields true obsText (some (k, unfoldOnto v cs)) rest
  | [], v, rest, _ => by simp [unfoldOnto]
  | c :: cs, v, rest, h => by
    obtain ⟨⟨h1, h2⟩, h3⟩ := h c (by simp)
    rw [List.cons_append, fields, if_neg h1, if_pos h2]
    simp only [h3, Bool.not_true, Bool.false_eq_true, if_false]
    rw [fold_unfold obsText k cs _ rest (fun x hx => h x (by simp [hx]))]
    simp [unfoldOnto, List.append_assoc]

/-- Strict mode: a continuation line is an error. -/
theorem strict_no_fold (obsText : Bool) (prev : Option Field) (c : Bytes) (ls : List Bytes)
    (h : IsCont c) : ∃ e, fields false obsText prev (c :: ls) = .error e := by
  refine ⟨"obs-fold rejected", ?_⟩
  unfold fields
  rw [if_neg h.1, if_pos h.2]

end Flare.L3.H1.ObsFold
