import Flare.L3_Protocol.H2.Names
import Flare.L3_Protocol.H2.HpackTable

/-!
# Request header validation (RFC 9113 §8.2, §8.3; RFC 8441 §4)

`validate` transliterates `validate_request_fields`
(`flare/http2/state.mojo:1697-1801`), with `_is_valid_field_value`
(69-84), `_is_connection_specific` (718-728) and `_is_request_pseudo`
(730-738). `path_empty` and `is_connect` are set together with
`path_value` / `method_value` at their only assignments (1745-1752), so
they are computed from those fields here.

`SpecRequest` / `SpecTrailers` are written from the RFC text.

* `loop_iff`, `fold_facts`: the loop accepts exactly when every field
  passes its per-field check, and leaves in each accumulator the count /
  last value of the corresponding field.
* `SpecName` is the §8.2.1 field-name rule (visible ASCII, no uppercase,
  and no colon except as the leading pseudo-header marker).
  `fixedNameOK_iff`: the fixed per-name check is exactly `SpecName`.
  `implNameOK_spec`: flare's check implies `SpecName` *provided* the
  name is ASCII and has no colon after the first byte. Both provisos are
  necessary: `Flare.Bugs.H2_10` exhibits accepted names that break each.
-/
namespace Flare.L3.H2.Validate
open Flare.L3.H2.Names
open Flare.L3.H2.Hpack (Entry)

abbrev Header := Entry

/-! ## Implementation -/

/-- mirrors flare/http2/state.mojo:69-84 @59bda50 -/
def validValue (v : Bytes) : Bool :=
  match v.head?, v.getLast? with
  | some f, some l =>
    !(f == 32 || f == 9 || l == 32 || l == 9) && v.all (fun c => !(c == 0 || c == 10 || c == 13))
  | _, _ => true

/-- The per-byte name check (`state.mojo:1727-1733`). -/
def implNameOK (n : Bytes) : Bool :=
  n.all fun c => !(65 ≤ c && c ≤ 90) && !(c ≤ 32 || c == 127)

/-- mirrors flare/http2/state.mojo:718-728 @59bda50 -/
def isConnSpecific (n : Bytes) : Bool :=
  n == kConnection || n == kKeepAlive || n == kProxyConnection || n == kTransferEncoding ||
  n == kUpgrade

/-- mirrors flare/http2/state.mojo:730-738 @59bda50 -/
def isRequestPseudo (n : Bytes) : Bool :=
  n == kMethod || n == kScheme || n == kPath || n == kAuthority || n == kProtocol

def isPseudo (h : Header) : Bool := h.name.head? == some 58

/-- Loop state (`state.mojo:1706-1717`). -/
structure Acc where
  seenRegular : Bool := false
  nMethod : Nat := 0
  nScheme : Nat := 0
  nPath : Nat := 0
  nAuthority : Nat := 0
  pathValue : Bytes := []
  methodValue : Bytes := []
  authority : Bytes := []
  host : Bytes := []
  hasProtocol : Bool := false

/-- The early-return checks of one loop iteration (`state.mojo:1719-1766`). -/
def fieldOK (isTr : Bool) (a : Acc) (h : Header) : Bool :=
  h.name != [] && implNameOK h.name && validValue h.value &&
  (if isPseudo h then !(isTr || a.seenRegular) && isRequestPseudo h.name
   else !isConnSpecific h.name && !(h.name == kTe && h.value != kTrailers))

/-- The state updates of one loop iteration. -/
def upd (a : Acc) (h : Header) : Acc :=
  if isPseudo h then
    if h.name = kMethod then { a with nMethod := a.nMethod + 1, methodValue := h.value }
    else if h.name = kScheme then { a with nScheme := a.nScheme + 1 }
    else if h.name = kPath then { a with nPath := a.nPath + 1, pathValue := h.value }
    else if h.name = kAuthority then { a with nAuthority := a.nAuthority + 1, authority := h.value }
    else if h.name = kProtocol then { a with hasProtocol := true }
    else a
  else { a with seenRegular := true, host := if h.name = kHost then h.value else a.host }

/-- mirrors flare/http2/state.mojo:1718-1766 @59bda50 -/
def loop (isTr : Bool) : List Header → Acc → Option Acc
  | [], a => some a
  | h :: t, a => if fieldOK isTr a h then loop isTr t (upd a h) else none

/-- mirrors flare/http2/state.mojo:1767-1801 @59bda50 -/
def final (isTr allowExt : Bool) (a : Acc) : Bool :=
  if isTr then true
  else if a.nMethod ≠ 1 then false
  else if a.hasProtocol && (!(a.methodValue == kConnect) || !allowExt) then false
  else if a.authority ≠ [] && a.host ≠ [] && a.host ≠ a.authority then false
  else if a.nScheme > 1 || a.nPath > 1 || a.nAuthority > 1 then false
  else if (a.methodValue == kConnect) && !a.hasProtocol then
    a.nScheme == 0 && a.nPath == 0 && a.nAuthority == 1
  else if a.nScheme ≠ 1 || a.nPath ≠ 1 then false
  else if a.pathValue = [] then false
  else if !(a.pathValue.head? == some 47) && !(a.pathValue == [42] && a.methodValue == kOptions)
    then false
  else true

/-- mirrors flare/http2/state.mojo:1697-1801 @59bda50 -/
def validate (hs : List Header) (isTr allowExt : Bool) : Bool :=
  match loop isTr hs {} with
  | none => false
  | some a => final isTr allowExt a

/-! ## Spec (RFC 9113 §8.2.1, §8.2.2, §8.3, §8.3.1, §8.5; RFC 8441 §4) -/

def cnt (k : Bytes) (hs : List Header) : Nat := hs.countP (fun h => h.name == k)
def vals (k : Bytes) (hs : List Header) : List Bytes := (hs.filter (fun h => h.name == k)).map (·.value)

/-- §8.2.1 field value rules. -/
def SpecValue (v : Bytes) : Prop :=
  (∀ c ∈ v, c ≠ 0 ∧ c ≠ 10 ∧ c ≠ 13) ∧ v.head? ≠ some 32 ∧ v.head? ≠ some 9 ∧
  v.getLast? ≠ some 32 ∧ v.getLast? ≠ some 9

/-- §8.2.1 field rules plus §8.2.2 (connection-specific fields, TE). -/
def SpecField (h : Header) : Prop :=
  h.name ≠ [] ∧
  (∀ c ∈ h.name, 0x20 < c ∧ ¬ (0x41 ≤ c ∧ c ≤ 0x5a) ∧ c < 0x7f) ∧
  (∀ c ∈ h.name.tail, c ≠ 0x3a) ∧
  SpecValue h.value ∧
  (isPseudo h = false → isConnSpecific h.name = false ∧ (h.name = kTe → h.value = kTrailers))

/-- §8.3: pseudo-header fields precede regular ones. -/
def Ordered (hs : List Header) : Prop :=
  ∃ ps rs, hs = ps ++ rs ∧ (∀ p ∈ ps, isPseudo p = true) ∧ (∀ r ∈ rs, isPseudo r = false)

def SpecRequest (allowExt : Bool) (hs : List Header) : Prop :=
  (∀ h ∈ hs, SpecField h) ∧ Ordered hs ∧
  (∀ h ∈ hs, isPseudo h = true → isRequestPseudo h.name = true) ∧
  cnt kMethod hs = 1 ∧ cnt kScheme hs ≤ 1 ∧ cnt kPath hs ≤ 1 ∧ cnt kAuthority hs ≤ 1 ∧
  cnt kProtocol hs ≤ 1 ∧
  (cnt kProtocol hs = 1 → vals kMethod hs = [kConnect] ∧ allowExt = true) ∧
  (∀ a ∈ vals kAuthority hs, ∀ v ∈ vals kHost hs, a ≠ [] → v ≠ [] → v = a) ∧
  (vals kMethod hs = [kConnect] ∧ cnt kProtocol hs = 0 →
    cnt kScheme hs = 0 ∧ cnt kPath hs = 0 ∧ cnt kAuthority hs = 1) ∧
  (¬ (vals kMethod hs = [kConnect] ∧ cnt kProtocol hs = 0) →
    cnt kScheme hs = 1 ∧ cnt kPath hs = 1 ∧
    ∀ p ∈ vals kPath hs, p ≠ [] ∧ (p.head? = some 47 ∨ (p = [42] ∧ vals kMethod hs = [kOptions])))

/-- §8.1: a trailer section carries no pseudo-header fields. -/
def SpecTrailers (hs : List Header) : Prop :=
  ∀ h ∈ hs, SpecField h ∧ isPseudo h = false

/-- The provisos under which flare's check implies the RFC's. -/
def Provisos (hs : List Header) : Prop :=
  (∀ h ∈ hs, ∀ c ∈ h.name, c < 0x80) ∧ (∀ h ∈ hs, ∀ c ∈ h.name.tail, c ≠ 0x3a)

/-! ## Loop characterisation -/

def AllOK (isTr : Bool) : Acc → List Header → Prop
  | _, [] => True
  | a, h :: t => fieldOK isTr a h = true ∧ AllOK isTr (upd a h) t

theorem loop_iff (isTr : Bool) (hs : List Header) (a a' : Acc) :
    loop isTr hs a = some a' ↔ AllOK isTr a hs ∧ a' = hs.foldl upd a := by
  induction hs generalizing a with
  | nil => simp [loop, AllOK, eq_comm]
  | cons h t ih =>
    simp only [loop, AllOK, List.foldl]
    split
    · rename_i hok; rw [ih]; simp [hok]
    · rename_i hok; simp [hok]

/-- The "last value" a field name leaves in a loop variable. -/
def lastVal (k : Bytes) (hs : List Header) (d : Bytes) : Bytes :=
  hs.foldl (fun acc h => if h.name = k then h.value else acc) d

theorem lastVal_vals (k : Bytes) (hs : List Header) (d : Bytes) :
    lastVal k hs d = (vals k hs).getLastD d := by
  induction hs generalizing d with
  | nil => simp [lastVal, vals]
  | cons h t ih =>
    simp only [lastVal, List.foldl] at ih ⊢
    rw [ih]
    by_cases hk : h.name = k
    · have e : vals k (h :: t) = h.value :: vals k t := by simp [vals, List.filter_cons, hk]
      rw [if_pos hk, e, List.getLastD_cons]
    · have e : vals k (h :: t) = vals k t := by simp [vals, List.filter_cons, hk]
      rw [if_neg hk, e]

theorem vals_length (k : Bytes) (hs : List Header) : (vals k hs).length = cnt k hs := by
  simp [vals, cnt, List.countP_eq_length_filter]

theorem pseudo_of_name (h : Header) (k : Bytes) (hk : k.head? = some 58) (hn : h.name = k) :
    isPseudo h = true := by simp [isPseudo, hn, hk]

theorem kHost_not_pseudo (h : Header) (hn : h.name = kHost) : isPseudo h = false := by
  simp [isPseudo, hn, kHost]

/-- One loop iteration's effect on each accumulator field. -/
theorem upd_facts (a : Acc) (h : Header) :
    (upd a h).nMethod = a.nMethod + (if h.name = kMethod then 1 else 0) ∧
    (upd a h).nScheme = a.nScheme + (if h.name = kScheme then 1 else 0) ∧
    (upd a h).nPath = a.nPath + (if h.name = kPath then 1 else 0) ∧
    (upd a h).nAuthority = a.nAuthority + (if h.name = kAuthority then 1 else 0) ∧
    (upd a h).methodValue = (if h.name = kMethod then h.value else a.methodValue) ∧
    (upd a h).pathValue = (if h.name = kPath then h.value else a.pathValue) ∧
    (upd a h).authority = (if h.name = kAuthority then h.value else a.authority) ∧
    (upd a h).host = (if h.name = kHost then h.value else a.host) ∧
    (upd a h).hasProtocol = (a.hasProtocol || decide (h.name = kProtocol)) ∧
    (upd a h).seenRegular = (a.seenRegular || !isPseudo h) := by
  unfold upd
  by_cases e1 : h.name = kMethod
  · simp [isPseudo, e1, kMethod, kScheme, kPath, kAuthority, kProtocol, kHost]
  by_cases e2 : h.name = kScheme
  · simp [isPseudo, e2, kMethod, kScheme, kPath, kAuthority, kProtocol, kHost]
  by_cases e3 : h.name = kPath
  · simp [isPseudo, e3, kMethod, kScheme, kPath, kAuthority, kProtocol, kHost]
  by_cases e4 : h.name = kAuthority
  · simp [isPseudo, e4, kMethod, kScheme, kPath, kAuthority, kProtocol, kHost]
  by_cases e5 : h.name = kProtocol
  · simp [isPseudo, e5, kMethod, kScheme, kPath, kAuthority, kProtocol, kHost]
  by_cases e6 : h.name = kHost
  · simp [isPseudo, e6, kMethod, kScheme, kPath, kAuthority, kProtocol, kHost]
  by_cases hp : isPseudo h = true
  · simp [hp, e1, e2, e3, e4, e5, e6]
  · simp [hp, e1, e2, e3, e4, e5, e6]

/-- What the loop accumulates. -/
theorem fold_facts (hs : List Header) (a : Acc) :
    let a' := hs.foldl upd a
    a'.nMethod = a.nMethod + cnt kMethod hs ∧ a'.nScheme = a.nScheme + cnt kScheme hs ∧
    a'.nPath = a.nPath + cnt kPath hs ∧ a'.nAuthority = a.nAuthority + cnt kAuthority hs ∧
    a'.methodValue = lastVal kMethod hs a.methodValue ∧
    a'.pathValue = lastVal kPath hs a.pathValue ∧
    a'.authority = lastVal kAuthority hs a.authority ∧
    a'.host = lastVal kHost hs a.host ∧
    a'.hasProtocol = (a.hasProtocol || decide (0 < cnt kProtocol hs)) ∧
    a'.seenRegular = (a.seenRegular || hs.any (fun h => !isPseudo h)) := by
  induction hs generalizing a with
  | nil => simp [cnt, lastVal]
  | cons h t ih =>
    obtain ⟨i1, i2, i3, i4, i5, i6, i7, i8, i9, i10⟩ := ih (upd a h)
    obtain ⟨u1, u2, u3, u4, u5, u6, u7, u8, u9, u10⟩ := upd_facts a h
    simp only [List.foldl, cnt, lastVal, List.countP_cons, List.any_cons] at *
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [i1, u1]; split <;> simp_all <;> omega
    · rw [i2, u2]; split <;> simp_all <;> omega
    · rw [i3, u3]; split <;> simp_all <;> omega
    · rw [i4, u4]; split <;> simp_all <;> omega
    · rw [i5, u5]
    · rw [i6, u6]
    · rw [i7, u7]
    · rw [i8, u8]
    · rw [i9, u9]; by_cases hk : h.name = kProtocol <;> simp [hk]
    · rw [i10, u10]; simp [Bool.or_assoc]

/-! ## Field names (§8.2.1, H2-10) -/

/-- §8.2.1: a field name is non-empty visible ASCII without uppercase
letters; a colon may appear only as the first byte (pseudo-header). -/
def SpecName (n : Bytes) : Prop :=
  n ≠ [] ∧ (∀ c ∈ n, 0x20 < c ∧ ¬ (0x41 ≤ c ∧ c ≤ 0x5a) ∧ c < 0x7f) ∧ (∀ c ∈ n.tail, c ≠ 0x3a)

/-- The H2-10 fix: also reject bytes ≥ 0x7f and a colon after the first byte. -/
def fixedNameOK (n : Bytes) : Bool :=
  n != [] && n.all (fun c => decide (0x20 < c ∧ ¬ (0x41 ≤ c ∧ c ≤ 0x5a) ∧ c < 0x7f)) &&
    n.tail.all (fun c => decide (c ≠ 0x3a))

theorem fixedNameOK_iff (n : Bytes) : fixedNameOK n = true ↔ SpecName n := by
  simp only [fixedNameOK, SpecName, List.all_eq_true, decide_eq_true_eq, Bool.and_eq_true,
    bne_iff_ne, ne_eq, and_assoc]

theorem implByte_spec (c : UInt8) (h1 : (!(65 ≤ c && c ≤ 90) && !(c ≤ 32 || c == 127)) = true)
    (h2 : c < 0x80) : 0x20 < c ∧ ¬ (0x41 ≤ c ∧ c ≤ 0x5a) ∧ c < 0x7f := by
  have e : (c == 127) = decide (c.toNat = 127) := by
    by_cases h : c.toNat = 127
    · have : c = 127 := UInt8.toNat_inj.mp (by simpa using h)
      simp [this]
    · have : c ≠ 127 := fun e => h (by subst e; rfl)
      simp [this, h]
  rw [e] at h1
  simp only [UInt8.le_iff_toNat_le, UInt8.lt_iff_toNat_lt, UInt8.toNat_ofNat] at *
  simp only [Bool.and_eq_true, Bool.not_eq_true', Bool.and_eq_false_iff, Bool.or_eq_false_iff,
    decide_eq_false_iff_not] at h1
  omega

theorem implNameOK_spec (n : Bytes) (hne : n ≠ []) (hi : implNameOK n = true)
    (ha : ∀ c ∈ n, c < 0x80) (hc : ∀ c ∈ n.tail, c ≠ 0x3a) : SpecName n := by
  refine ⟨hne, fun c hm => ?_, hc⟩
  simp only [implNameOK, List.all_eq_true] at hi
  exact implByte_spec c (hi c hm) (ha c hm)

end Flare.L3.H2.Validate
