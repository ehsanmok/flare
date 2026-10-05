import Flare.L3_Protocol.H1.FieldValue

/-!
# obs-fold in the server's header-field loop

`_parse_http_request_bytes` (`flare/http/_server/parse.mojo:203-320`
@59bda50) reads field lines one at a time and commits a field only when the
next line shows it is not continued. With `allow_obs_fold`, a line starting
with SP/HTAB is a continuation: its stripped bytes are appended to the
previous value after one SP.

* `fieldsOld` is the loop before the H1-10 fix: the continuation bytes were
  not checked. `fieldsOld_fold_unfold`, `fieldsOld_strict_no_fold` and
  `fieldsOld_ok_strict` are facts about it.
* `fields` is the shipped loop (the continuation passes the same `valueOk`
  check as a first line). `fold_unfold`: a run of valid continuation lines is
  unfolded exactly as RFC 9112 §5.2 says (each obs-fold becomes one SP);
  `strict_no_fold`: without the flag a continuation line is an error;
  `fields_valid`: every stored value passes `valueOk`.

Lines are as `_read_line_buf_lenient` returns them (terminator and one CR
removed); an empty line, or the end of the data, ends the block. Name
whitespace leniency (`allow_ows_around_colon`) and the Content-Length /
Transfer-Encoding bookkeeping are not modelled (they do not touch values).
-/
namespace Flare.L3.H1.ObsFold
open Flare Flare.L3.H1.Text Flare.L3.H1.FieldValue

def isSPHT (c : UInt8) : Bool := c == 32 || c == 9

/-- mirrors flare/http/_server/parse_util.mojo:65-90 @59bda50 -/
def aStrip (l : Bytes) : Bytes := ((l.dropWhile isSPHT).reverse.dropWhile isSPHT).reverse

/-- First `:`. -/
def colonAt (l : Bytes) : Option Nat := l.findIdx? (· == 58)

abbrev Field := Bytes × Bytes

/-- The field loop before the H1-10 fix. `prev` is the uncommitted field.
mirrors flare/http/_server/parse.mojo:203-320 @59bda50 -/
def fieldsOld (obsFold obsText : Bool) : Option Field → List Bytes → Except String (List Field)
  | prev, [] => .ok prev.toList
  | prev, l :: ls =>
    if l = [] then .ok prev.toList
    else if isSPHT (l.headD 0) then
      match obsFold, prev with
      | true, some (k, v) => fieldsOld obsFold obsText (some (k, v ++ [32] ++ aStrip l)) ls
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
          else (fieldsOld obsFold obsText (some (aStrip (l.take c), v)) ls).map (prev.toList ++ ·)

/-- The shipped loop (H1-10 fix): the continuation passes the same value check. -/
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

/-- **The unfolding is RFC 9112 §5.2's**: after a field `k: v`, a run of
continuation lines leaves `k` with `v` and each continuation (trimmed)
joined by one SP. -/
theorem fieldsOld_fold_unfold (obsText : Bool) (k : Bytes) :
    ∀ (cs : List Bytes) (v : Bytes) (rest : List Bytes), (∀ c ∈ cs, IsCont c) →
      fieldsOld true obsText (some (k, v)) (cs ++ rest) = fieldsOld true obsText (some (k, unfoldOnto v cs)) rest
  | [], v, rest, _ => by simp [unfoldOnto]
  | c :: cs, v, rest, h => by
    obtain ⟨h1, h2⟩ := h c (by simp)
    rw [List.cons_append, fieldsOld, if_neg h1, if_pos h2]
    rw [fieldsOld_fold_unfold obsText k cs _ rest (fun x hx => h x (by simp [hx]))]
    simp [unfoldOnto, List.append_assoc]

/-- Strict mode: a continuation line is an error. -/
theorem fieldsOld_strict_no_fold (obsText : Bool) (prev : Option Field) (c : Bytes) (ls : List Bytes)
    (h : IsCont c) : ∃ e, fieldsOld false obsText prev (c :: ls) = .error e := by
  refine ⟨"obs-fold rejected", ?_⟩
  unfold fieldsOld
  rw [if_neg h.1, if_pos h.2]

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

/-- In strict mode (no folding) every stored value passes `valueOk`. -/
theorem fieldsOld_ok_strict (obsText : Bool) : ∀ (ls : List Bytes) (prev : Option Field) (hs : List Field),
    (∀ kv, prev = some kv → valueOk obsText kv.2 = true) →
    fieldsOld false obsText prev ls = .ok hs → AllValid obsText hs
  | [], prev, hs, hp, h => by simp [fieldsOld] at h; subst h; exact prev_valid hp
  | l :: ls, prev, hs, hp, h => by
    unfold fieldsOld at h
    split at h
    · simp at h; subst h; exact prev_valid hp
    split at h
    · cases prev <;> simp at h
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
    cases hr : fieldsOld false obsText _ ls with
    | error e => rw [hr] at h; cases h
    | ok r =>
      rw [hr] at h; simp [Except.map] at h; subst h
      have ih := fieldsOld_ok_strict obsText ls _ r (fun kv hkv => by
        simp at hkv; subst hkv; simpa using hv) hr
      intro kv hkv
      rcases List.mem_append.mp hkv with h1 | h1
      · exact prev_valid hp kv h1
      · exact ih kv h1

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
