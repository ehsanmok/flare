import Flare.L3_Protocol.H2.HpackSync

/-!
# HPACK header-block decoder and encoder (RFC 7541 §6)

`decodeLoop` transliterates `HpackDecoder.decode` (`hpack.mojo:356-441`)
and `encode` transliterates `HpackEncoder.encode` with
`allow_huffman = False` (`hpack.mojo:480-512`, the default).

The prefix-integer codec (§5.1) and the Huffman codec (§5.2) belong to the
L1 layer, so here they are parameters (`Codec`), and the properties used
are explicit hypotheses (`Codec.Correct`), never axioms.

Results:
* `decode_encode`: for any header list whose octets survive
  `_octets_to_string` unchanged (all ASCII, `octetsToString_ascii`) and
  whose strings are shorter than `2^31`, decoding flare's own encoding
  returns the same list and leaves the dynamic table untouched.
* `decode_budget_impl`: the exact bound the shipped budget check gives:
  the sizes of all fields *but the last* are within the budget.
  `Flare.Bugs.HPACK_02` shows the last field is never counted.
* `decode_budget_fixed`: with the check moved after each field, the whole
  decoded list is within the budget.
* `decode_table_inv`: decoding preserves the table invariant.
-/
namespace Flare.L3.H2.Hpack

/-- RFC 7541 Appendix A, as flare spells it (`hpack.mojo:179-243`). -/
def staticPairs : List (String × String) :=
  [(":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
   (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"), (":status", "200"),
   (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
   (":status", "404"), (":status", "500"), ("accept-charset", ""),
   ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""),
   ("accept", ""), ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
   ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
   ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
   ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
   ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
   ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""),
   ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""), ("location", ""),
   ("max-forwards", ""), ("proxy-authenticate", ""), ("proxy-authorization", ""),
   ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
   ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
   ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", "")]

def staticTable : List Entry :=
  staticPairs.map fun (n, v) => ⟨Bytes.ofString n, Bytes.ofString v⟩

/-- Static entry `i` (1-based). -/
def staticEntry (i : Nat) : Entry := staticTable.getD (i - 1) ⟨[], []⟩

/-- Prefix-integer and Huffman codecs (owned by L1). -/
structure Codec where
  /-- `encode_integer(out, value, prefix_bits, prefix_byte)`. -/
  encInt : Nat → Nat → UInt8 → Bytes
  /-- `decode_integer(buf, 0, prefix_bits)`: value and the rest. -/
  decInt : Bytes → Nat → Option (Nat × Bytes)
  /-- `huffman_decode_simd`. -/
  huff : Bytes → Option Bytes

/-- What the HPACK layer needs from the L1 codecs (RFC 7541 §5.1). -/
structure Codec.Correct (C : Codec) : Prop where
  /-- decoding consumes at least one byte -/
  progress : ∀ l p v r, C.decInt l p = some (v, r) → r.length < l.length
  /-- round trip, and the bits above the prefix are those of `prefix_byte` -/
  roundtrip : ∀ p v (hi : UInt8) rest, 4 ≤ p → p ≤ 7 → v < 2 ^ 31 →
    ∃ b0 bs, C.encInt p v hi = b0 :: bs ∧ b0.toNat / 2 ^ p = hi.toNat / 2 ^ p ∧
      C.decInt (C.encInt p v hi ++ rest) p = some (v, rest)

inductive DErr where
  | trunc | budget | zeroIdx | range | huffDisabled | huffBad | capExceeded | afterField | fuel
  deriving Repr, DecidableEq

/-- `_decode_string` (`hpack.mojo:330-354`). -/
def decodeString (C : Codec) (allowHuff : Bool) (l : Bytes) : Except DErr (Bytes × Bytes) :=
  match l with
  | [] => .error .trunc
  | b0 :: _ =>
    match C.decInt l 7 with
    | none => .error .trunc
    | some (slen, rest) =>
      if rest.length < slen then .error .trunc
      else if b0 ≥ 0x80 then
        if !allowHuff then .error .huffDisabled
        else match C.huff (rest.take slen) with
          | some d => .ok (octetsToString d, rest.drop slen)
          | none => .error .huffBad
      else .ok (octetsToString (rest.take slen), rest.drop slen)

/-- `_lookup` to an entry (`hpack.mojo:318-328`). -/
def lookupEntry (t : Table) (idx : Nat) : Except DErr Entry :=
  match lookup t idx with
  | .static i => .ok (staticEntry i)
  | .dyn e => .ok e
  | .errZero => .error .zeroIdx
  | .errRange => .error .range

/-- Name for a literal: index `0` means a literal name follows. -/
def literalName (C : Codec) (ah : Bool) (t : Table) (idx : Nat) (rest : Bytes) :
    Except DErr (Bytes × Bytes) :=
  if idx = 0 then decodeString C ah rest
  else do let e ← lookupEntry t idx; pure (e.name, rest)

/-- One field representation (`hpack.mojo:386-440`). Returns the new table,
the decoded field (if any) and the rest. -/
def decodeOne (C : Codec) (ah : Bool) (t : Table) (nFields : Nat) (l : Bytes) :
    Except DErr (Table × Option Entry × Bytes) :=
  match l with
  | [] => .error .trunc
  | b0 :: _ =>
    if b0 &&& 0x80 ≠ 0 then
      match C.decInt l 7 with
      | none => .error .trunc
      | some (i, rest) => do let e ← lookupEntry t i; pure (t, some e, rest)
    else if b0 &&& 0x40 ≠ 0 then
      match C.decInt l 6 with
      | none => .error .trunc
      | some (i, rest) => do
        let (name, rest) ← literalName C ah t i rest
        let (value, rest) ← decodeString C ah rest
        let h : Entry := ⟨name, value⟩
        pure (insert t h, some h, rest)
    else if b0 &&& 0x20 ≠ 0 then
      match C.decInt l 5 with
      | none => .error .trunc
      | some (n, rest) =>
        match sizeUpdate t n nFields with
        | .ok t' => .ok (t', none, rest)
        | .exceedsCap => .error .capExceeded
        | .afterField => .error .afterField
    else
      match C.decInt l 4 with
      | none => .error .trunc
      | some (i, rest) => do
        let (name, rest) ← literalName C ah t i rest
        let (value, rest) ← decodeString C ah rest
        pure (t, some ⟨name, value⟩, rest)

def lastSize (hs : List Entry) : Nat :=
  match hs.getLast? with
  | some h => entrySize h
  | none => 0

/-- `decoded` after the check at the top of an iteration (`hpack.mojo:378-383`). -/
def acct (budget : Nat) (hs : List Entry) (decoded : Nat) : Nat :=
  if budget > 0 ∧ hs ≠ [] then decoded + lastSize hs else decoded

/-- The raise condition (`hpack.mojo:378,384`). -/
def overBudget (budget : Nat) (hs : List Entry) (d : Nat) : Bool :=
  decide (budget > 0 ∧ hs ≠ [] ∧ d > budget)

/-- The decode loop. The budget check runs *before* each field and
accounts the previously decoded one.
mirrors flare/http2/hpack.mojo:356-441 @59bda50 -/
def decodeLoop (C : Codec) (ah : Bool) (budget : Nat) :
    Nat → Table → List Entry → Nat → Bytes → Except DErr (Table × List Entry)
  | _, t, hs, _, [] => .ok (t, hs)
  | 0, _, _, _, _ :: _ => .error .fuel
  | fuel + 1, t, hs, decoded, l@(_ :: _) =>
    if overBudget budget hs (acct budget hs decoded) then .error .budget
    else match decodeOne C ah t hs.length l with
      | .error e => .error e
      | .ok (t', oh, rest) =>
        decodeLoop C ah budget fuel t' (hs ++ oh.toList) (acct budget hs decoded) rest

def decode (C : Codec) (ah : Bool) (t : Table) (buf : Bytes) (budget : Nat) :
    Except DErr (Table × List Entry) :=
  decodeLoop C ah budget buf.length t [] 0 buf

/-- The minimal fix for HPACK-02: account each field right after it is
decoded. -/
def decodeLoopFixed (C : Codec) (ah : Bool) (budget : Nat) :
    Nat → Table → List Entry → Nat → Bytes → Except DErr (Table × List Entry)
  | _, t, hs, _, [] => .ok (t, hs)
  | 0, _, _, _, _ :: _ => .error .fuel
  | fuel + 1, t, hs, decoded, l@(_ :: _) =>
    match decodeOne C ah t hs.length l with
    | .error e => .error e
    | .ok (t', oh, rest) =>
      let decoded' := decoded + tsize oh.toList
      if budget > 0 ∧ decoded' > budget then .error .budget
      else decodeLoopFixed C ah budget fuel t' (hs ++ oh.toList) decoded' rest

def decodeFixed (C : Codec) (ah : Bool) (t : Table) (buf : Bytes) (budget : Nat) :
    Except DErr (Table × List Entry) :=
  decodeLoopFixed C ah budget buf.length t [] 0 buf

/-! ## Budget theorems -/

theorem tsize_dropLast_add (hs : List Entry) : tsize hs = tsize hs.dropLast + lastSize hs := by
  induction hs with
  | nil => simp [tsize, lastSize]
  | cons x xs ih =>
    cases xs with
    | nil => simp [tsize, lastSize]
    | cons y ys =>
      simp only [List.dropLast_cons₂, tsize, lastSize, List.getLast?_cons_cons] at *
      omega

/-- Only a size update yields no field, and it is only legal before any
field. -/
theorem decodeOne_none (C : Codec) (ah : Bool) (t : Table) (n : Nat) (l : Bytes)
    (t' : Table) (r : Bytes) (h : decodeOne C ah t n l = .ok (t', none, r)) : n = 0 := by
  unfold decodeOne at h
  split at h; · cases h
  split at h
  · split at h; · cases h
    simp only [bind, Except.bind] at h; split at h <;> cases h
  split at h
  · split at h; · cases h
    simp only [bind, Except.bind] at h
    split at h; · cases h
    split at h; · cases h
    cases h
  split at h
  · split at h; · cases h
    split at h
    · exact (sizeUpdate_guard _ _ _ _ ‹_›).1
    · cases h
    · cases h
  · split at h; · cases h
    simp only [bind, Except.bind] at h
    split at h; · cases h
    split at h; · cases h
    cases h

/-- Exact guarantee of the shipped check: with a positive budget, every
field but the last is accounted for and within budget. -/
theorem decode_budget_impl (C : Codec) (ah : Bool) (budget : Nat) (hb : 0 < budget) :
    ∀ fuel t hs decoded l t' hs',
    decoded = tsize hs.dropLast → decoded ≤ budget →
    decodeLoop C ah budget fuel t hs decoded l = .ok (t', hs') →
    tsize hs'.dropLast ≤ budget := by
  intro fuel
  induction fuel with
  | zero =>
    intro t hs decoded l t' hs' hd hle h
    cases l with
    | nil => simp [decodeLoop] at h; obtain ⟨_, rfl⟩ := h; omega
    | cons _ _ => simp [decodeLoop] at h
  | succ fuel ih =>
    intro t hs decoded l t' hs' hd hle h
    cases l with
    | nil => simp [decodeLoop] at h; obtain ⟨_, rfl⟩ := h; omega
    | cons b bs =>
      simp only [decodeLoop] at h
      split at h
      · cases h
      rename_i hnb
      split at h
      · cases h
      rename_i t1 oh rest hd1
      -- the accounted value is the size of everything decoded so far
      have hacc : acct budget hs decoded = tsize hs := by
        unfold acct
        by_cases hne : hs = []
        · subst hne; simp [tsize] at hd ⊢; exact hd
        · rw [if_pos ⟨hb, hne⟩, tsize_dropLast_add hs, hd]
      have hle' : acct budget hs decoded ≤ budget := by
        unfold overBudget at hnb
        by_cases hne : hs = []
        · subst hne; rw [hacc]; simp [tsize]
        · simp only [decide_eq_true_eq, not_and] at hnb; have := hnb hb hne; omega
      refine ih _ _ _ _ _ _ ?_ hle' h
      cases oh with
      | none =>
        have := decodeOne_none C ah t _ _ _ _ hd1
        have hnil : hs = [] := List.length_eq_zero_iff.mp this
        subst hnil; simp [tsize] at hd; simp [acct, tsize, hd]
      | some e => simp [hacc]

/-- With the fix, every decoded field is within budget. -/
theorem decode_budget_fixed (C : Codec) (ah : Bool) (budget : Nat) (hb : 0 < budget) :
    ∀ fuel t hs decoded l t' hs',
    decoded = tsize hs → decoded ≤ budget →
    decodeLoopFixed C ah budget fuel t hs decoded l = .ok (t', hs') →
    tsize hs' ≤ budget := by
  intro fuel
  induction fuel with
  | zero =>
    intro t hs decoded l t' hs' hd hle h
    cases l with
    | nil => simp [decodeLoopFixed] at h; obtain ⟨_, rfl⟩ := h; omega
    | cons _ _ => simp [decodeLoopFixed] at h
  | succ fuel ih =>
    intro t hs decoded l t' hs' hd hle h
    cases l with
    | nil => simp [decodeLoopFixed] at h; obtain ⟨_, rfl⟩ := h; omega
    | cons b bs =>
      simp only [decodeLoopFixed] at h
      split at h
      · cases h
      · rename_i t1 oh rest _
        split at h
        · cases h
        · rename_i hn
          exact ih _ _ _ _ _ _ (by rw [tsize_append]; omega) (by omega) h

/-! ## Table invariant across a block -/

theorem decodeOne_inv (C : Codec) (ah : Bool) (t : Table) (n : Nat) (l : Bytes)
    (t' : Table) (o : Option Entry) (r : Bytes) (hi : Inv t)
    (h : decodeOne C ah t n l = .ok (t', o, r)) : Inv t' := by
  unfold decodeOne at h
  split at h; · cases h
  split at h
  · split at h; · cases h
    simp only [bind, Except.bind] at h; split at h <;> cases h; exact hi
  split at h
  · split at h; · cases h
    simp only [bind, Except.bind] at h
    split at h; · cases h
    split at h; · cases h
    cases h; exact inv_insert _ _ hi
  split at h
  · split at h; · cases h
    split at h
    · cases h; exact (inv_sizeUpdate _ _ _ _ hi ‹_›).1
    · cases h
    · cases h
  · split at h; · cases h
    simp only [bind, Except.bind] at h
    split at h; · cases h
    split at h; · cases h
    cases h; exact hi

theorem decode_table_inv (C : Codec) (ah : Bool) (budget : Nat) :
    ∀ fuel t hs d l t' hs', Inv t → decodeLoop C ah budget fuel t hs d l = .ok (t', hs') →
    Inv t' := by
  intro fuel
  induction fuel with
  | zero => intro t hs d l t' hs' hi h; cases l <;> simp [decodeLoop] at h; obtain ⟨rfl, _⟩ := h; exact hi
  | succ fuel ih =>
    intro t hs d l t' hs' hi h
    cases l with
    | nil => simp [decodeLoop] at h; obtain ⟨rfl, _⟩ := h; exact hi
    | cons b bs =>
      simp only [decodeLoop] at h
      split at h; · cases h
      split at h; · cases h
      rename_i hd1
      exact ih _ _ _ _ _ _ (decodeOne_inv C ah _ _ _ _ _ _ hi hd1) h

/-! ## Encoder and round trip -/

/-- First static index whose name matches, or `0` (`hpack.mojo:502-506`). -/
def findStatic (name : Bytes) : Nat :=
  match staticTable.findIdx? (fun e => e.name == name) with
  | some i => i + 1
  | none => 0

/-- `_encode_string` with `allow_huffman = False` (`hpack.mojo:480-492`). -/
def encodeString (C : Codec) (s : Bytes) : Bytes := C.encInt 7 s.length 0 ++ s

/-- mirrors flare/http2/hpack.mojo:494-512 @59bda50 -/
def encodeField (C : Codec) (h : Entry) : Bytes :=
  let j := findStatic h.name
  C.encInt 4 j 0 ++ (if j = 0 then encodeString C h.name else []) ++ encodeString C h.value

def encode (C : Codec) : List Entry → Bytes
  | [] => []
  | h :: hs => encodeField C h ++ encode C hs

theorem findStatic_spec (name : Bytes) (h : findStatic name ≠ 0) :
    (staticEntry (findStatic name)).name = name ∧ findStatic name ≤ 61 := by
  unfold findStatic at *
  split
  · rename_i i hi
    obtain ⟨hlt, hp, _⟩ := List.findIdx?_eq_some_iff_getElem.mp hi
    have hl : staticTable.length = 61 := by decide
    refine ⟨?_, by omega⟩
    simp only [staticEntry, Nat.add_sub_cancel, List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem hlt, Option.getD_some]
    simpa using hp
  · rename_i hn; rw [hn] at h; simp at h

/-- Octets `_octets_to_string` leaves unchanged. -/
def Stable (b : Bytes) : Prop := octetsToString b = b ∧ b.length < 2 ^ 31

theorem decodeString_encode (C : Codec) (hC : C.Correct) (ah : Bool) (s rest : Bytes)
    (hs : Stable s) : decodeString C ah (encodeString C s ++ rest) = .ok (s, rest) := by
  obtain ⟨b0, bs, he, hhi, hd⟩ := hC.roundtrip 7 s.length 0 (s ++ rest) (by omega) (by omega) hs.2
  unfold encodeString
  rw [List.append_assoc, he]
  simp only [List.cons_append, decodeString]
  rw [← List.cons_append, ← he, hd]
  have hb0 : ¬ b0 ≥ 0x80 := by
    have := b0.toNat_lt; simp at hhi
    intro hge; have : (0x80 : UInt8).toNat ≤ b0.toNat := hge; simp at this; omega
  simp [hb0, List.take_left' rfl, List.drop_left' rfl, hs.1]

theorem low_bits (b : UInt8) (h : b < 16) :
    b &&& 0x80 = 0 ∧ b &&& 0x40 = 0 ∧ b &&& 0x20 = 0 := by
  have hb : b.toNat < 16 := h
  have key : ∀ n, n < 16 → n &&& 128 = 0 ∧ n &&& 64 = 0 ∧ n &&& 32 = 0 := by decide
  obtain ⟨k1, k2, k3⟩ := key b.toNat hb
  refine ⟨?_, ?_, ?_⟩ <;> apply UInt8.toNat_inj.mp <;> simp [UInt8.toNat_and, k1, k2, k3]

theorem findStatic_lt (name : Bytes) : findStatic name < 62 := by
  unfold findStatic; split
  · rename_i i hi
    obtain ⟨hlt, _⟩ := List.findIdx?_eq_some_iff_getElem.mp hi
    have : staticTable.length = 61 := by decide
    omega
  · omega

/-- The name part of a literal decodes to the original name. -/
theorem literalName_encode (C : Codec) (hC : C.Correct) (ah : Bool) (t : Table) (h : Entry)
    (rest : Bytes) (hn : Stable h.name) :
    literalName C ah t (findStatic h.name)
      ((if findStatic h.name = 0 then encodeString C h.name else []) ++ rest)
      = .ok (h.name, rest) := by
  unfold literalName
  by_cases hz : findStatic h.name = 0
  · simp only [hz, if_true]; exact decodeString_encode C hC ah _ _ hn
  · simp only [hz, if_false, List.nil_append]
    have ⟨hname, hle⟩ := findStatic_spec h.name hz
    have hl : lookupEntry t (findStatic h.name) = .ok (staticEntry (findStatic h.name)) := by
      unfold lookupEntry lookup STATIC_TABLE_LEN
      simp [hz, hle]
    rw [hl]; simp [bind, Except.bind, pure, Except.pure, hname]

/-- **Round trip.** Decoding flare's encoding of a stable header list
returns it unchanged and does not touch the dynamic table (the encoder
never indexes), whatever the table contents. -/
theorem decode_encode (C : Codec) (hC : C.Correct) (ah : Bool) (t : Table) :
    ∀ (hs acc : List Entry) (fuel : Nat), (∀ h ∈ hs, Stable h.name ∧ Stable h.value) →
    (encode C hs).length ≤ fuel →
    decodeLoop C ah 0 fuel t acc 0 (encode C hs) = .ok (t, acc ++ hs) := by
  intro hs
  induction hs with
  | nil => intro acc fuel _ _; cases fuel <;> simp [encode, decodeLoop]
  | cons h hs ih =>
    intro acc fuel hst hf
    have ⟨hn, hv⟩ := hst h (List.mem_cons_self ..)
    have hj : findStatic h.name < 2 ^ 31 := by have := findStatic_lt h.name; omega
    generalize hX : (if findStatic h.name = 0 then encodeString C h.name else []) = X
    obtain ⟨b0, bs, he, hhi, hd⟩ :=
      hC.roundtrip 4 (findStatic h.name) 0 (X ++ encodeString C h.value ++ encode C hs)
        (by omega) (by omega) hj
    have hb0 : b0 < 16 := by
      have := b0.toNat_lt; simp at hhi
      exact UInt8.lt_iff_toNat_lt.mpr (by simp; omega)
    have ⟨n80, n40, n20⟩ := low_bits b0 hb0
    have hE : encode C (h :: hs) = b0 :: (bs ++ (X ++ encodeString C h.value ++ encode C hs)) := by
      simp only [encode, encodeField, hX, he, List.cons_append, List.append_assoc]
    have hlen : (encode C (h :: hs)).length = bs.length + 1 +
        (X ++ encodeString C h.value ++ encode C hs).length := by rw [hE]; simp; omega
    cases fuel with
    | zero => rw [hE] at hf; simp at hf
    | succ fuel =>
      rw [hE, decodeLoop]
      simp only [overBudget, acct, Nat.lt_irrefl, false_and, decide_false, Bool.false_eq_true,
        if_false, decodeOne, n80, n40, n20, ne_eq, not_true_eq_false]
      rw [← List.cons_append, ← he, hd]
      have hL := literalName_encode C hC ah t h (encodeString C h.value ++ encode C hs) hn
      rw [hX] at hL
      simp only [List.append_assoc] at hL ⊢
      simp only [bind, Except.bind, hL, decodeString_encode C hC ah _ _ hv, pure, Except.pure]
      have := ih (acc ++ [h]) fuel (fun h' hm => hst h' (List.mem_cons_of_mem _ hm))
        (by have := hlen; simp [encodeString] at this hf ⊢; omega)
      simpa using this
