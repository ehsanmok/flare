import Flare.L3_Protocol.H2.Hpack

/-!
# The peer's HPACK encoder against flare's decoder (RFC 7541 §6)

A peer encoder emits a field block as a list of representations
(`Rep`): indexed field (§6.1), literal with incremental indexing (§6.2.1),
literal without indexing / never indexed (§6.2.2-3), dynamic table size
update (§6.3); each literal string raw or Huffman-coded (§5.2). `pstep`
is the peer's own view (RFC 7541 table over the raw octets), `encRep` its
bytes.

flare's decoder (`Hpack.decodeOne` / `decode`) presents every octet string
either verbatim (static-table and copied names) or through
`_octets_to_string` (`ConvB`). `PInv` relates the two tables: flare's
dynamic table is, entry by entry, such a view of a prefix of the peer's.

* `decodeOne_rep`: one representation either fails to decode or yields
  the peer's field (up to `ConvB`) and keeps `PInv`.
* `decode_block`: a whole block decodes to the peer's field list, or fails.

So a desynchronised table can only make decoding fail
(COMPRESSION_ERROR); it never yields a header the peer did not send.
-/
namespace Flare.L3.H2.Hpack

/-! ## The view relation -/

/-- flare shows the peer's octets `a` as `b`: verbatim or converted. -/
def ConvB (a b : Bytes) : Prop := b = a ∨ b = octetsToString a

def Conv (e d : Entry) : Prop := ConvB e.name d.name ∧ ConvB e.value d.value

theorem convB_len {a b : Bytes} (h : ConvB a b) : a.length ≤ b.length := by
  rcases h with h | h
  · rw [h]; exact Nat.le_refl _
  · rw [h]; exact octetsToString_length_ge a

theorem conv_refl (e : Entry) : Conv e e := ⟨Or.inl rfl, Or.inl rfl⟩

theorem conv_size {e d : Entry} (h : Conv e d) : entrySize e ≤ entrySize d := by
  have := convB_len h.1; have := convB_len h.2
  unfold entrySize; omega

/-- Pointwise `Conv`. -/
def Pw : List Entry → List Entry → Prop
  | [], [] => True
  | a :: as, b :: bs => Conv a b ∧ Pw as bs
  | _, _ => False

theorem pw_length : ∀ {A B : List Entry}, Pw A B → A.length = B.length
  | [], [], _ => rfl
  | _ :: _, _ :: _, h => by simp [pw_length h.2]
  | [], _ :: _, h => h.elim
  | _ :: _, [], h => h.elim

theorem pw_take : ∀ {A B : List Entry} (j : Nat), Pw A B → Pw (A.take j) (B.take j)
  | [], [], _, _ => by simp [Pw]
  | _ :: _, _ :: _, 0, _ => by simp [Pw]
  | _ :: _, _ :: _, j + 1, h => by simp only [List.take_succ_cons, Pw]; exact ⟨h.1, pw_take j h.2⟩
  | [], _ :: _, _, h => h.elim
  | _ :: _, [], _, h => h.elim

theorem pw_tsize : ∀ {A B : List Entry}, Pw A B → tsize A ≤ tsize B
  | [], [], _ => Nat.le_refl _
  | _ :: _, _ :: _, h => by have := conv_size h.1; have := pw_tsize h.2; simp [tsize]; omega
  | [], _ :: _, h => h.elim
  | _ :: _, [], h => h.elim

theorem pw_get : ∀ {A B : List Entry} (i : Nat) (d : Entry), Pw A B → B[i]? = some d →
    ∃ e, A[i]? = some e ∧ Conv e d
  | [], [], _, _, _, h => by simp at h
  | a :: _, _ :: _, 0, _, hp, h => by simp at h; subst h; exact ⟨a, rfl, hp.1⟩
  | _ :: _, _ :: _, i + 1, d, hp, h => by simp at h ⊢; exact pw_get i d hp.2 h
  | [], _ :: _, _, _, h, _ => h.elim
  | _ :: _, [], _, _, h, _ => h.elim

theorem pw_append : ∀ {A B C D : List Entry}, Pw A B → Pw C D → Pw (A ++ C) (B ++ D)
  | [], [], _, _, _, h => h
  | _ :: _, _ :: _, _, _, h1, h2 => ⟨h1.1, pw_append h1.2 h2⟩
  | [], _ :: _, _, _, h, _ => h.elim
  | _ :: _, [], _, _, h, _ => h.elim

/-- flare's table is a pointwise view of a prefix of the peer's. -/
def CorrR (P D : List Entry) : Prop := ∃ k, Pw (P.take k) D

theorem evictR (P D : List Entry) (k rP rD m : Nat) (hp : Pw (P.take k) D) (hr : rP ≤ rD)
    (hm : rD ≤ m) : ∃ j, Pw ((specEvict P rP m).take j) (specEvict D rD m) := by
  have hDlen : D.length = min k P.length := by rw [← pw_length hp]; simp
  have hjD := fitLen_le D rD m D.length
  have hfitD := fitLen_fits D rD m D.length hm
  unfold specEvict
  generalize hj : fitLen D rD m D.length = j at hjD hfitD ⊢
  have h1 : (P.take k).take j = P.take j := by
    rw [List.take_take, show min j k = j by omega]
  have hpj := pw_take j hp
  rw [h1] at hpj
  have hfitP : tsize (P.take j) + rP ≤ m := by have := pw_tsize hpj; omega
  have hji := fitLen_max P rP m P.length j (by omega) hfitP
  refine ⟨j, ?_⟩
  rw [List.take_take, show min j (fitLen P rP m P.length) = j by omega]
  exact hpj

theorem corrR_insert (P : List Entry) (t : Table) (e d : Entry) (hi : Inv t) (hc : CorrR P t.dyn)
    (hcv : Conv e d) : CorrR (specInsert P t.maxSize e) (insert t d).dyn := by
  rw [(insert_spec t _ hi.size_eq).1]
  obtain ⟨k, hk⟩ := hc
  unfold specInsert
  have hs := conv_size hcv
  by_cases h1 : entrySize d > t.maxSize
  · rw [if_pos h1]; exact ⟨0, by simp [Pw]⟩
  · rw [if_neg h1, if_neg (by omega)]
    obtain ⟨j, hj⟩ := evictR P t.dyn k (entrySize e) (entrySize d) t.maxSize hk hs (by omega)
    exact ⟨j + 1, by simp only [List.take_succ_cons, Pw]; exact ⟨hcv, hj⟩⟩

theorem corrR_sizeUpdate (P : List Entry) (t t' : Table) (n : Nat) (hi : Inv t)
    (hc : CorrR P t.dyn) (hu : sizeUpdate t n 0 = .ok t') : CorrR (specEvict P 0 n) t'.dyn := by
  unfold sizeUpdate at hu
  split at hu; · cases hu
  simp at hu; subst hu
  have h' : ({ t with maxSize := n } : Table).size = tsize ({ t with maxSize := n } : Table).dyn :=
    hi.size_eq
  rw [evict_spec _ _ h']
  obtain ⟨k, hk⟩ := hc
  exact evictR P t.dyn k 0 0 n hk (Nat.le_refl _) (Nat.zero_le _)

/-! ## The peer -/

/-- The peer encoder's state: its RFC 7541 table and maximum size. -/
structure Peer where
  tbl : List Entry
  max : Nat

def Peer.init : Peer := { tbl := [], max := 4096 }

/-- Peer and decoder agree. -/
def PInv (p : Peer) (t : Table) : Prop := Inv t ∧ t.maxSize = p.max ∧ CorrR p.tbl t.dyn

theorem pinv_init : PInv Peer.init Table.init := ⟨inv_init, rfl, ⟨0, by simp [Pw, Table.init]⟩⟩

/-- A field representation (RFC 7541 §6). Literal strings carry their
Huffman flag. -/
inductive Rep where
  | idx (i : Nat)
  | inc (ni : Nat) (name value : Bytes) (hn hv : Bool)
  | lit (ni : Nat) (name value : Bytes) (hn hv : Bool)
  | upd (n : Nat)

/-- The peer's entry at index `i` (§2.3.3). -/
def pentry (P : List Entry) (i : Nat) : Option Entry :=
  if i = 0 then none else if i ≤ 61 then some (staticEntry i) else P[i - 62]?

def pname (P : List Entry) (ni : Nat) (name : Bytes) : Option Bytes :=
  if ni = 0 then some name else (pentry P ni).map (·.name)

/-- The peer's step: the field it means, and its new table. `none`: the
representation is invalid for the peer (it never sends it). -/
def pstep (p : Peer) : Rep → Option (Peer × Option Entry)
  | .idx i => (pentry p.tbl i).map fun e => (p, some e)
  | .inc ni n v _ _ =>
    (pname p.tbl ni n).map fun nm => ({ p with tbl := specInsert p.tbl p.max ⟨nm, v⟩ }, some ⟨nm, v⟩)
  | .lit ni n v _ _ => (pname p.tbl ni n).map fun nm => (p, some ⟨nm, v⟩)
  | .upd n => some ({ tbl := specEvict p.tbl 0 n, max := n }, none)

/-- A whole block on the peer side: final state and the field list. -/
def pblock (p : Peer) : List Rep → Option (Peer × List Entry)
  | [] => some (p, [])
  | r :: rs => match pstep p r with
    | none => none
    | some (p1, o) => (pblock p1 rs).map fun (p2, fs) => (p2, o.toList ++ fs)

/-! ## The peer's bytes -/

def huffString (C : Codec) (henc : Bytes → Bytes) (s : Bytes) : Bytes :=
  C.encInt 7 (henc s).length 0x80 ++ henc s

def estr (C : Codec) (henc : Bytes → Bytes) (h : Bool) (s : Bytes) : Bytes :=
  if h then huffString C henc s else encodeString C s

def encRep (C : Codec) (henc : Bytes → Bytes) : Rep → Bytes
  | .idx i => C.encInt 7 i 0x80
  | .inc ni n v hn hv => C.encInt 6 ni 0x40 ++ (if ni = 0 then estr C henc hn n else []) ++ estr C henc hv v
  | .lit ni n v hn hv => C.encInt 4 ni 0 ++ (if ni = 0 then estr C henc hn n else []) ++ estr C henc hv v
  | .upd n => C.encInt 5 n 0x20

def encBlock (C : Codec) (henc : Bytes → Bytes) : List Rep → Bytes
  | [] => []
  | r :: rs => encRep C henc r ++ encBlock C henc rs

/-- Encodable: integers and string lengths below 2^31 (flare's integer
limit). -/
def SOK (henc : Bytes → Bytes) (h : Bool) (s : Bytes) : Prop :=
  if h then (henc s).length < 2 ^ 31 else s.length < 2 ^ 31

def RepOK (henc : Bytes → Bytes) : Rep → Prop
  | .idx i => i < 2 ^ 31
  | .inc ni n v hn hv => ni < 2 ^ 31 ∧ (ni = 0 → SOK henc hn n) ∧ SOK henc hv v
  | .lit ni n v hn hv => ni < 2 ^ 31 ∧ (ni = 0 → SOK henc hn n) ∧ SOK henc hv v
  | .upd n => n < 2 ^ 31

/-! ## Strings -/

theorem decInt_enc (C : Codec) (hC : C.Correct) (p v : Nat) (hi : UInt8) (rest : Bytes)
    (h4 : 4 ≤ p) (h7 : p ≤ 7) (hv : v < 2 ^ 31) :
    ∃ b0 bs, C.encInt p v hi = b0 :: bs ∧ b0.toNat / 2 ^ p = hi.toNat / 2 ^ p ∧
      C.decInt (b0 :: (bs ++ rest)) p = some (v, rest) := by
  obtain ⟨b0, bs, he, hhi, hd⟩ := hC.roundtrip p v hi rest h4 h7 hv
  refine ⟨b0, bs, he, hhi, ?_⟩
  rw [he] at hd; simpa using hd

theorem decodeString_raw (C : Codec) (hC : C.Correct) (ah : Bool) (s rest : Bytes)
    (hl : s.length < 2 ^ 31) : decodeString C ah (encodeString C s ++ rest) = .ok (octetsToString s, rest) := by
  obtain ⟨b0, bs, he, hhi, hd⟩ := decInt_enc C hC 7 s.length 0 (s ++ rest) (by omega) (by omega) hl
  unfold encodeString
  rw [List.append_assoc, he]
  simp only [List.cons_append, decodeString]
  rw [hd]
  have hb0 : ¬ b0 ≥ 0x80 := by
    have := b0.toNat_lt; simp at hhi
    intro hge; have : (0x80 : UInt8).toNat ≤ b0.toNat := hge; simp at this; omega
  simp [hb0, List.take_left' rfl, List.drop_left' rfl]

theorem decodeString_huff (C : Codec) (hC : C.Correct) (henc : Bytes → Bytes)
    (hH : ∀ s, C.huff (henc s) = some s) (s rest : Bytes) (hl : (henc s).length < 2 ^ 31) :
    decodeString C true (huffString C henc s ++ rest) = .ok (octetsToString s, rest) := by
  obtain ⟨b0, bs, he, hhi, hd⟩ := decInt_enc C hC 7 (henc s).length 0x80 (henc s ++ rest)
    (by omega) (by omega) hl
  unfold huffString
  rw [List.append_assoc, he]
  simp only [List.cons_append, decodeString]
  rw [hd]
  have hb0 : b0 ≥ 0x80 := by
    have := b0.toNat_lt; simp at hhi
    show (0x80 : UInt8).toNat ≤ b0.toNat
    simp; omega
  simp [hb0, List.take_left' rfl, List.drop_left' rfl, hH]

theorem decodeString_estr (C : Codec) (hC : C.Correct) (henc : Bytes → Bytes)
    (hH : ∀ s, C.huff (henc s) = some s) (h : Bool) (s rest : Bytes) (hs : SOK henc h s) :
    decodeString C true (estr C henc h s ++ rest) = .ok (octetsToString s, rest) := by
  unfold estr; unfold SOK at hs
  cases h
  · simp only [Bool.false_eq_true, if_false] at hs ⊢; exact decodeString_raw C hC true s rest hs
  · simp only [if_true] at hs ⊢; exact decodeString_huff C hC henc hH s rest hs

/-! ## First-byte patterns -/

set_option maxRecDepth 8000 in
theorem flag80 (b : UInt8) (h : b.toNat / 2 ^ 7 = (0x80 : UInt8).toNat / 2 ^ 7) : b &&& 0x80 ≠ 0 := by
  have hb := b.toNat_lt
  have key : ∀ n, n < 256 → n / 128 = 1 → n &&& 128 ≠ 0 := by decide
  intro h0
  have := congrArg UInt8.toNat h0
  simp [UInt8.toNat_and] at this h
  exact key _ hb h this

set_option maxRecDepth 8000 in
theorem flag40 (b : UInt8) (h : b.toNat / 2 ^ 6 = (0x40 : UInt8).toNat / 2 ^ 6) :
    b &&& 0x80 = 0 ∧ b &&& 0x40 ≠ 0 := by
  have hb := b.toNat_lt
  have key : ∀ n, n < 256 → n / 64 = 1 → n &&& 128 = 0 ∧ n &&& 64 ≠ 0 := by decide
  simp at h
  obtain ⟨k1, k2⟩ := key _ hb h
  refine ⟨?_, ?_⟩
  · apply UInt8.toNat_inj.mp; simp [UInt8.toNat_and, k1]
  · intro h0; have := congrArg UInt8.toNat h0; simp [UInt8.toNat_and] at this; exact k2 this

set_option maxRecDepth 8000 in
theorem flag20 (b : UInt8) (h : b.toNat / 2 ^ 5 = (0x20 : UInt8).toNat / 2 ^ 5) :
    b &&& 0x80 = 0 ∧ b &&& 0x40 = 0 ∧ b &&& 0x20 ≠ 0 := by
  have hb := b.toNat_lt
  have key : ∀ n, n < 256 → n / 32 = 1 → n &&& 128 = 0 ∧ n &&& 64 = 0 ∧ n &&& 32 ≠ 0 := by decide
  simp at h
  obtain ⟨k1, k2, k3⟩ := key _ hb h
  refine ⟨?_, ?_, ?_⟩
  · apply UInt8.toNat_inj.mp; simp [UInt8.toNat_and, k1]
  · apply UInt8.toNat_inj.mp; simp [UInt8.toNat_and, k2]
  · intro h0; have := congrArg UInt8.toNat h0; simp [UInt8.toNat_and] at this; exact k3 this

theorem flag00 (b : UInt8) (h : b.toNat / 2 ^ 4 = (0 : UInt8).toNat / 2 ^ 4) :
    b &&& 0x80 = 0 ∧ b &&& 0x40 = 0 ∧ b &&& 0x20 = 0 := by
  have hb := b.toNat_lt
  simp at h
  exact low_bits b (UInt8.lt_iff_toNat_lt.mpr (by simp; omega))

/-! ## One representation -/

/-- flare's lookup agrees with the peer's entry, up to the view. -/
theorem lookupEntry_conv (P : List Entry) (t : Table) (hc : CorrR P t.dyn) (i : Nat) (d : Entry)
    (h : lookupEntry t i = .ok d) : ∃ e, pentry P i = some e ∧ Conv e d := by
  unfold lookupEntry at h
  cases hlk : lookup t i with
  | static j =>
    rw [hlk] at h; cases h
    have : j = i ∧ i ≠ 0 ∧ i ≤ 61 := by
      unfold lookup STATIC_TABLE_LEN at hlk
      split at hlk; · cases hlk
      split at hlk
      · cases hlk; exact ⟨rfl, ‹_›, ‹_›⟩
      · split at hlk <;> cases hlk
    obtain ⟨rfl, h0, hle⟩ := this
    exact ⟨staticEntry j, by simp [pentry, h0, hle], conv_refl _⟩
  | dyn e =>
    rw [hlk] at h; cases h
    rw [lookup_spec] at hlk
    unfold specLookup at hlk
    split at hlk; · cases hlk
    split at hlk; · cases hlk
    rename_i h0 h61
    split at hlk
    · rename_i hlt
      simp only [Look.dyn.injEq] at hlk
      obtain ⟨k, hk⟩ := hc
      obtain ⟨e0, h1, h2⟩ := pw_get (i - 62) d hk (by rw [← hlk]; exact List.getElem?_eq_getElem hlt)
      refine ⟨e0, ?_, h2⟩
      simp only [pentry, h0, h61, if_false]
      rw [List.getElem?_take] at h1
      split at h1
      · exact h1
      · cases h1
    · cases hlk
  | errZero => rw [hlk] at h; cases h
  | errRange => rw [hlk] at h; cases h

/-- The name part of a literal: flare's name is a view of the peer's. -/
theorem literalName_rep (C : Codec) (hC : C.Correct) (henc : Bytes → Bytes)
    (hH : ∀ s, C.huff (henc s) = some s) (P : List Entry) (t : Table) (hc : CorrR P t.dyn)
    (ni : Nat) (n : Bytes) (hn : Bool) (rest : Bytes) (hs : ni = 0 → SOK henc hn n)
    (nm : Bytes) (r : Bytes)
    (h : literalName C true t ni ((if ni = 0 then estr C henc hn n else []) ++ rest) = .ok (nm, r)) :
    r = rest ∧ ∃ pn, pname P ni n = some pn ∧ ConvB pn nm := by
  unfold literalName at h
  by_cases h0 : ni = 0
  · simp only [h0, if_true] at h
    rw [decodeString_estr C hC henc hH hn n rest (hs h0)] at h
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, n, by simp [pname, h0], Or.inr rfl⟩
  · simp only [h0, if_false, List.nil_append] at h
    cases hl : lookupEntry t ni with
    | error e => simp [hl, bind, Except.bind] at h
    | ok d =>
      simp only [hl, bind, Except.bind, pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨e, he, hcv⟩ := lookupEntry_conv P t hc ni d hl
      exact ⟨rfl, e.name, by simp [pname, h0, he], hcv.1⟩

/-- `od` is a view of the peer's optional field `o`. -/
def OConv : Option Entry → Option Entry → Prop
  | none, none => True
  | some e, some d => Conv e d
  | _, _ => False

theorem pw_oconv {o od : Option Entry} (h : OConv o od) : Pw o.toList od.toList := by
  cases o <;> cases od <;> simp_all [OConv, Pw]

/-- **One representation.** Decoding the peer's bytes for `r` either
fails, or consumes exactly them, yields (a view of) the field the peer
meant, and keeps the tables in correspondence. -/
theorem decodeOne_rep (C : Codec) (hC : C.Correct) (henc : Bytes → Bytes)
    (hH : ∀ s, C.huff (henc s) = some s) (p p' : Peer) (o : Option Entry) (t : Table)
    (nF : Nat) (r : Rep) (rest : Bytes) (hv : RepOK henc r) (hp : PInv p t)
    (hs : pstep p r = some (p', o)) (t' : Table) (od : Option Entry) (rest' : Bytes)
    (h : decodeOne C true t nF (encRep C henc r ++ rest) = .ok (t', od, rest')) :
    rest' = rest ∧ PInv p' t' ∧ OConv o od := by
  obtain ⟨hi, hm, hc⟩ := hp
  cases r with
  | idx i =>
    obtain ⟨b0, bs, he, hhi, hd⟩ := decInt_enc C hC 7 i 0x80 rest (by omega) (by omega) hv
    have f80 := flag80 b0 hhi
    simp only [encRep, he, List.cons_append] at h
    simp only [decodeOne, ne_eq, f80, not_false_eq_true, if_true, hd] at h
    cases hl : lookupEntry t i with
    | error e => simp [hl, bind, Except.bind] at h
    | ok d =>
      simp only [hl, bind, Except.bind, pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      obtain ⟨e, hpe, hcv⟩ := lookupEntry_conv p.tbl t hc i d hl
      simp only [pstep, hpe, Option.map_some, Option.some.injEq, Prod.mk.injEq] at hs
      obtain ⟨rfl, rfl⟩ := hs
      exact ⟨rfl, ⟨hi, hm, hc⟩, hcv⟩
  | inc ni n v hn hv' =>
    obtain ⟨hni, hsn, hsv⟩ := hv
    obtain ⟨b0, bs, he, hhi, hd⟩ := decInt_enc C hC 6 ni 0x40
      ((if ni = 0 then estr C henc hn n else []) ++ (estr C henc hv' v ++ rest)) (by omega) (by omega) hni
    obtain ⟨f80, f40⟩ := flag40 b0 hhi
    simp only [encRep, he, List.cons_append, List.append_assoc] at h
    simp only [decodeOne, ne_eq, f80, not_true_eq_false, if_false, f40, not_false_eq_true, if_true,
      hd] at h
    cases hL : literalName C true t ni ((if ni = 0 then estr C henc hn n else []) ++
        (estr C henc hv' v ++ rest)) with
    | error e => simp [hL, bind, Except.bind] at h
    | ok pr =>
      obtain ⟨nm, r1⟩ := pr
      obtain ⟨rfl, pn, hpn, hcn⟩ := literalName_rep C hC henc hH p.tbl t hc ni n hn _ hsn nm r1 hL
      simp only [hL, bind, Except.bind] at h
      rw [decodeString_estr C hC henc hH hv' v rest hsv] at h
      simp only [pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      simp only [pstep, hpn, Option.map_some, Option.some.injEq, Prod.mk.injEq] at hs
      obtain ⟨rfl, rfl⟩ := hs
      have hcv : Conv ⟨pn, v⟩ ⟨nm, octetsToString v⟩ := ⟨hcn, Or.inr rfl⟩
      refine ⟨rfl, ⟨inv_insert _ _ hi, ?_, ?_⟩, hcv⟩
      · rw [(insert_spec t _ hi.size_eq).2.2.1]; exact hm
      · rw [← hm]; exact corrR_insert _ t _ _ hi hc hcv
  | lit ni n v hn hv' =>
    obtain ⟨hni, hsn, hsv⟩ := hv
    obtain ⟨b0, bs, he, hhi, hd⟩ := decInt_enc C hC 4 ni 0
      ((if ni = 0 then estr C henc hn n else []) ++ (estr C henc hv' v ++ rest)) (by omega) (by omega) hni
    obtain ⟨f80, f40, f20⟩ := flag00 b0 hhi
    simp only [encRep, he, List.cons_append, List.append_assoc] at h
    simp only [decodeOne, ne_eq, f80, f40, f20, not_true_eq_false, if_false, hd] at h
    cases hL : literalName C true t ni ((if ni = 0 then estr C henc hn n else []) ++
        (estr C henc hv' v ++ rest)) with
    | error e => simp [hL, bind, Except.bind] at h
    | ok pr =>
      obtain ⟨nm, r1⟩ := pr
      obtain ⟨rfl, pn, hpn, hcn⟩ := literalName_rep C hC henc hH p.tbl t hc ni n hn _ hsn nm r1 hL
      simp only [hL, bind, Except.bind] at h
      rw [decodeString_estr C hC henc hH hv' v rest hsv] at h
      simp only [pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      simp only [pstep, hpn, Option.map_some, Option.some.injEq, Prod.mk.injEq] at hs
      obtain ⟨rfl, rfl⟩ := hs
      exact ⟨rfl, ⟨hi, hm, hc⟩, hcn, Or.inr rfl⟩
  | upd n =>
    obtain ⟨b0, bs, he, hhi, hd⟩ := decInt_enc C hC 5 n 0x20 rest (by omega) (by omega) hv
    obtain ⟨f80, f40, f20⟩ := flag20 b0 hhi
    simp only [encRep, he, List.cons_append] at h
    simp only [decodeOne, ne_eq, f80, f40, not_true_eq_false, if_false, f20, not_false_eq_true,
      if_true, hd] at h
    split at h
    · rename_i t1 hu
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      simp only [pstep, Option.some.injEq, Prod.mk.injEq] at hs
      obtain ⟨rfl, rfl⟩ := hs
      have ⟨hi', hm', _, hk⟩ := inv_sizeUpdate _ _ _ _ hi hu
      subst hk
      exact ⟨rfl, ⟨hi', hm', corrR_sizeUpdate _ t _ n hi hc hu⟩, trivial⟩
    · cases h
    · cases h

theorem encRep_ne (C : Codec) (hC : C.Correct) (henc : Bytes → Bytes) (r : Rep) (hv : RepOK henc r) :
    ∃ b bs, encRep C henc r = b :: bs := by
  cases r with
  | idx i =>
    obtain ⟨b0, bs, he, -⟩ := hC.roundtrip 7 i 0x80 [] (by omega) (by omega) hv
    exact ⟨b0, bs, he⟩
  | inc ni n v hn hv' =>
    obtain ⟨b0, bs, he, -⟩ := hC.roundtrip 6 ni 0x40 [] (by omega) (by omega) hv.1
    exact ⟨b0, bs ++ ((if ni = 0 then estr C henc hn n else []) ++ estr C henc hv' v),
      by simp [encRep, he]⟩
  | lit ni n v hn hv' =>
    obtain ⟨b0, bs, he, -⟩ := hC.roundtrip 4 ni 0 [] (by omega) (by omega) hv.1
    exact ⟨b0, bs ++ ((if ni = 0 then estr C henc hn n else []) ++ estr C henc hv' v),
      by simp [encRep, he]⟩
  | upd n =>
    obtain ⟨b0, bs, he, -⟩ := hC.roundtrip 5 n 0x20 [] (by omega) (by omega) hv
    exact ⟨b0, bs, he⟩

/-! ## A block -/

theorem decodeLoop_block (C : Codec) (hC : C.Correct) (henc : Bytes → Bytes)
    (hH : ∀ s, C.huff (henc s) = some s) (budget : Nat) :
    ∀ (rs : List Rep) (p p' : Peer) (fs : List Entry) (t t' : Table) (hs hs' : List Entry)
      (d fuel : Nat), (∀ r ∈ rs, RepOK henc r) → PInv p t → pblock p rs = some (p', fs) →
      (encBlock C henc rs).length ≤ fuel →
      decodeLoop C true budget fuel t hs d (encBlock C henc rs) = .ok (t', hs') →
      ∃ ds, hs' = hs ++ ds ∧ Pw fs ds ∧ PInv p' t' := by
  intro rs
  induction rs with
  | nil =>
    intro p p' fs t t' hs hs' d fuel _ hp hb _ h
    simp only [pblock, Option.some.injEq, Prod.mk.injEq] at hb
    obtain ⟨rfl, rfl⟩ := hb
    cases fuel <;> simp only [encBlock, decodeLoop, Except.ok.injEq, Prod.mk.injEq] at h <;>
      (obtain ⟨rfl, rfl⟩ := h; exact ⟨[], by simp, trivial, hp⟩)
  | cons r rs ih =>
    intro p p' fs t t' hs hs' d fuel hv hp hb hf h
    simp only [pblock] at hb
    split at hb
    · cases hb
    · rename_i p1 o hps
      cases hb2 : pblock p1 rs with
      | none => rw [hb2] at hb; cases hb
      | some q =>
        obtain ⟨p2, fs2⟩ := q
        rw [hb2] at hb
        simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hb
        obtain ⟨rfl, rfl⟩ := hb
        have hvr := hv r (List.mem_cons_self ..)
        obtain ⟨b, bs, hbe⟩ := encRep_ne C hC henc r hvr
        have hE : encBlock C henc (r :: rs) = b :: (bs ++ encBlock C henc rs) := by
          simp [encBlock, hbe]
        have hlen : (encBlock C henc (r :: rs)).length = bs.length + 1 + (encBlock C henc rs).length := by
          rw [hE]; simp; omega
        cases fuel with
        | zero => rw [hE] at hf; simp at hf
        | succ fuel =>
          rw [hE] at h
          simp only [decodeLoop] at h
          split at h
          · cases h
          · rename_i t1 od rest1 hd1
            split at h
            · cases h
            · rw [← List.cons_append, ← hbe] at hd1
              obtain ⟨rfl, hp1, hoc⟩ :=
                decodeOne_rep C hC henc hH p p1 o t hs.length r _ hvr hp hps t1 od rest1 hd1
              obtain ⟨ds, rfl, hpw, hp2⟩ := ih p1 p2 fs2 t1 t' _ hs' _ fuel
                (fun r' hr' => hv r' (List.mem_cons_of_mem _ hr')) hp1 hb2 (by omega) h
              exact ⟨od.toList ++ ds, by simp, pw_append (pw_oconv hoc) hpw, hp2⟩

/-- **A block.** flare's decode of the peer's block either fails or
returns, field for field, (a view of) what the peer sent, and leaves the
tables in correspondence. -/
theorem decode_block (C : Codec) (hC : C.Correct) (henc : Bytes → Bytes)
    (hH : ∀ s, C.huff (henc s) = some s) (budget : Nat) (rs : List Rep) (p p' : Peer)
    (fs : List Entry) (t t' : Table) (hs : List Entry) (hv : ∀ r ∈ rs, RepOK henc r)
    (hp : PInv p t) (hb : pblock p rs = some (p', fs))
    (h : decode C true t (encBlock C henc rs) budget = .ok (t', hs)) : Pw fs hs ∧ PInv p' t' := by
  obtain ⟨ds, h1, h2, h3⟩ :=
    decodeLoop_block C hC henc hH budget rs p p' fs t t' [] hs 0 _ hv hp hb (Nat.le_refl _) h
  simp at h1; subst h1; exact ⟨h2, h3⟩

end Flare.L3.H2.Hpack
