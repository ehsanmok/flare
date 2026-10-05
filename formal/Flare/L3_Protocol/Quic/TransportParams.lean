import Flare.L3_Protocol.H3.Frame

/-!
# QUIC transport parameters (RFC 9000 §7.3, §7.4, §18)

Model of flare/quic/transport_params.mojo @59bda50:

* `decodeLoop` / `decode` — `decode_transport_parameters` (410-525): the
  `varint(id) || varint(len) || value` loop with the "missing length
  varint" and "value truncated" checks, the `seen` duplicate list, and the
  per-id branches (`apply`, with `readVar` = `_read_param_varint`, 401-407).

The varint codec is `Flare.L3.H3.decVarint` (= flare/quic/varint.mojo).
CIDs and the reset token are `Bytes`, empty meaning absent, as in flare.

Spec (`specDecode`): the buffer is a sequence of TLVs (`tlvs`); the ids are
pairwise distinct (§18: duplicates are TRANSPORT_PARAMETER_ERROR); every
parameter has a valid value (`valid`, §7.4 and the per-parameter rules of
§18.2: varint parameters are exactly one varint, max_udp_payload_size ≥ 1200,
initial_max_streams_* ≤ 2^60, ack_delay_exponent ≤ 20, max_ack_delay < 2^14,
active_connection_id_limit ≥ 2, stateless_reset_token is 16 bytes,
disable_active_migration is empty, preferred_address has its fixed layout
with a 1..20-byte CID); the result is the fold of the parameters.

`Fixes.none` is flare as first audited; `Fixes.shipped` has the QUIC-10 and QUIC-13 checks
(it equals `Fixes.all`); `Fixes.all` adds the QUIC-10 check
(initial_max_streams_* ≤ 2^60) and the QUIC-13 check (preferred_address
layout).

Results:
* `decodeFixed_eq_spec`: with both fixes the decoder succeeds exactly when
  the spec does and returns the same parameters, on every input. Hence
  flare's duplicate, truncation, trailing-byte and value checks are right
  (they are the parts both versions share).
* flare as written differs from the fixed decoder only in the 0x08 / 0x09
  value bound and the 0x0d layout check (`implVarOk`, `apply`); the
  counterexamples are `Flare.Bugs.QUIC_10` and `QUIC_13`.

The encoder (`encode`, mirroring `encode_transport_parameters`, 237-395) is
stated for any varint encoder with `VarintCodec` (as in `Flare.L3.H3`):
* `tlvs_wire`: the wire form of a parameter list parses back into it;
* `encode_roundtrip`: for every `Sendable` parameter set the encoder does
  not raise, and `specDecode` (hence the fixed decoder) accepts the blob and
  returns the same parameters. `Sendable` adds to the encoder's own checks
  the two §18.2 bounds it leaves to configuration (max_udp_payload_size ≥
  1200, initial_max_streams_* ≤ 2^60).
-/
namespace Flare.L3.Quic.TransportParams
open Flare Flare.L3.H3

inductive TPErr | truncated | trailing | duplicate | invalid
  deriving DecidableEq, Repr

/-- Which minimal fixes are applied. -/
structure Fixes where
  streams : Bool -- QUIC-10
  pa : Bool      -- QUIC-13
  deriving DecidableEq, Repr

def Fixes.none : Fixes := ⟨false, false⟩
def Fixes.all : Fixes := ⟨true, true⟩
/-- The fixes present in `flare/quic/transport_params.mojo` now. -/
def Fixes.shipped : Fixes := ⟨true, true⟩

/-- mirrors flare/quic/transport_params.mojo:70-87 @59bda50 -/
inductive PK
  | odcid | idle | token | maxUdp | maxData | sdBidiLocal | sdBidiRemote | sdUni
  | streamsBidi | streamsUni | ackExp | maxAckDelay | disableMig | prefAddr | cidLimit
  | iscid | rscid | datagram | unknown
  deriving DecidableEq, Repr

/-- mirrors flare/quic/transport_params.mojo:70-87 @59bda50 -/
def kindTable : List (Nat × PK) :=
  [(0x00, .odcid), (0x01, .idle), (0x02, .token), (0x03, .maxUdp), (0x04, .maxData),
   (0x05, .sdBidiLocal), (0x06, .sdBidiRemote), (0x07, .sdUni), (0x08, .streamsBidi),
   (0x09, .streamsUni), (0x0a, .ackExp), (0x0b, .maxAckDelay), (0x0c, .disableMig),
   (0x0d, .prefAddr), (0x0e, .cidLimit), (0x0f, .iscid), (0x10, .rscid), (0x20, .datagram)]

def kind (id : Nat) : PK := ((kindTable.find? (·.1 = id)).map (·.2)).getD .unknown

theorem kind_mem {id : Nat} {k : PK} (h : kind id = k) (hk : k ≠ .unknown) : (id, k) ∈ kindTable := by
  unfold kind at h
  cases hf : kindTable.find? (·.1 = id) with
  | none => rw [hf] at h; exact absurd h.symm hk
  | some p =>
    rw [hf] at h
    have h1 := List.find?_some hf
    have h2 := List.mem_of_find?_eq_some hf
    simp only [decide_eq_true_eq] at h1
    simp only [Option.map_some, Option.getD_some] at h
    obtain ⟨a, b⟩ := p
    simp only at h1 h
    subst h1 h
    exact h2

/-- mirrors flare/quic/transport_params.mojo:104-138 @59bda50 -/
structure TP where
  odcid : Bytes := []
  idle : Option Nat := none
  token : Bytes := []
  maxUdp : Option Nat := none
  maxData : Option Nat := none
  sdBidiLocal : Option Nat := none
  sdBidiRemote : Option Nat := none
  sdUni : Option Nat := none
  streamsBidi : Option Nat := none
  streamsUni : Option Nat := none
  ackExp : Option Nat := none
  maxAckDelay : Option Nat := none
  disableMig : Bool := false
  cidLimit : Option Nat := none
  iscid : Bytes := []
  rscid : Bytes := []
  datagram : Option Nat := none
  deriving DecidableEq, Repr

/-- mirrors flare/quic/transport_params.mojo:401-407 @59bda50 -/
def readVar (v : Bytes) : Except TPErr Nat :=
  match decVarint v with
  | none => .error .truncated
  | some (x, k) => if k = v.length then .ok x else .error .trailing

/-- RFC 9000 §18.2 value rule of each varint parameter. -/
def varOk : PK → Nat → Bool
  | .maxUdp, x => decide (1200 ≤ x)
  | .streamsBidi, x => decide (x ≤ 2 ^ 60)
  | .streamsUni, x => decide (x ≤ 2 ^ 60)
  | .ackExp, x => decide (x ≤ 20)
  | .maxAckDelay, x => decide (x < 2 ^ 14)
  | .cidLimit, x => decide (2 ≤ x)
  | _, _ => true

/-- The checks flare applies to each varint parameter (QUIC-10: none on
the stream limits unless `fx.streams`).
mirrors flare/quic/transport_params.mojo:450-523 @59bda50 -/
def implVarOk (fx : Fixes) (k : PK) (x : Nat) : Bool :=
  match k with
  | .streamsBidi | .streamsUni => !fx.streams || varOk k x
  | _ => varOk k x

def setVar (k : PK) (x : Nat) (tp : TP) : TP :=
  match k with
  | .idle => { tp with idle := some x }
  | .maxUdp => { tp with maxUdp := some x }
  | .maxData => { tp with maxData := some x }
  | .sdBidiLocal => { tp with sdBidiLocal := some x }
  | .sdBidiRemote => { tp with sdBidiRemote := some x }
  | .sdUni => { tp with sdUni := some x }
  | .streamsBidi => { tp with streamsBidi := some x }
  | .streamsUni => { tp with streamsUni := some x }
  | .ackExp => { tp with ackExp := some x }
  | .maxAckDelay => { tp with maxAckDelay := some x }
  | .cidLimit => { tp with cidLimit := some x }
  | .datagram => { tp with datagram := some x }
  | _ => tp

/-- RFC 9000 §18.2 preferred_address layout: 4 + 2 + 16 + 2 bytes of
addresses, a CID length byte in 1..20, the CID, a 16-byte token. -/
def paValid (v : Bytes) : Bool :=
  decide (25 ≤ v.length) && decide (1 ≤ (Bytes.getD v 24).toNat) &&
    decide ((Bytes.getD v 24).toNat ≤ 20) && decide (v.length = 41 + (Bytes.getD v 24).toNat)

/-- A varint parameter. mirrors flare/quic/transport_params.mojo:450-523 @59bda50 -/
def applyVar (fx : Fixes) (k : PK) (v : Bytes) (tp : TP) : Except TPErr TP :=
  match readVar v with
  | .error e => .error e
  | .ok x => if implVarOk fx k x then .ok (setVar k x tp) else .error .invalid

/-- One parameter. mirrors flare/quic/transport_params.mojo:447-524 @59bda50
(0x0d has no branch there; `fx.pa` adds the QUIC-13 layout check). -/
def apply (fx : Fixes) (id : Nat) (v : Bytes) (tp : TP) : Except TPErr TP :=
  match kind id with
  | .odcid => .ok { tp with odcid := v }
  | .token => if v.length = 16 then .ok { tp with token := v } else .error .invalid
  | .iscid => .ok { tp with iscid := v }
  | .rscid => .ok { tp with rscid := v }
  | .disableMig => if v.length = 0 then .ok { tp with disableMig := true } else .error .invalid
  | .prefAddr => if fx.pa && !paValid v then .error .invalid else .ok tp
  | .unknown => .ok tp
  | k => applyVar fx k v tp

/-- mirrors flare/quic/transport_params.mojo:420-525 @59bda50 (`b` is
`buf[pos:]`; `seen` is the duplicate list, newest first) -/
def decodeLoop (fx : Fixes) (seen : List Nat) (tp : TP) (b : Bytes) : Except TPErr TP :=
  if b.length = 0 then .ok tp else
  match h1 : decVarint b with
  | none => .error .truncated
  | some (id, k1) =>
    if k1 ≥ b.length then .error .truncated else
    match decVarint (b.drop k1) with
    | none => .error .truncated
    | some (l, k2) =>
      if k1 + k2 + l > b.length then .error .truncated
      else if id ∈ seen then .error .duplicate
      else match apply fx id ((b.drop (k1 + k2)).take l) tp with
        | .error e => .error e
        | .ok tp' => decodeLoop fx (id :: seen) tp' (b.drop (k1 + k2 + l))
termination_by b.length
decreasing_by have := decVarint_some h1; simp; omega

def decode (fx : Fixes) (b : Bytes) : Except TPErr TP := decodeLoop fx [] {} b

/-! ## Spec -/

/-- RFC 9000 §18 framing: a sequence of `varint(id) varint(len) value`. -/
def tlvs (b : Bytes) : Option (List (Nat × Bytes)) :=
  if b.length = 0 then some [] else
  match h1 : decVarint b with
  | none => none
  | some (id, k1) =>
    if k1 ≥ b.length then none else
    match decVarint (b.drop k1) with
    | none => none
    | some (l, k2) =>
      if k1 + k2 + l > b.length then none
      else (tlvs (b.drop (k1 + k2 + l))).map (((id, (b.drop (k1 + k2)).take l)) :: ·)
termination_by b.length
decreasing_by have := decVarint_some h1; simp; omega

def validVar (k : PK) (v : Bytes) : Bool :=
  match decVarint v with
  | some (x, n) => decide (n = v.length) && varOk k x
  | none => false

def setVarB (k : PK) (v : Bytes) (tp : TP) : TP := setVar k (((decVarint v).map (·.1)).getD 0) tp

/-- RFC 9000 §7.4, §18.2: the value rules (receiving side, role-agnostic). -/
def valid (id : Nat) (v : Bytes) : Bool :=
  match kind id with
  | .odcid | .iscid | .rscid | .unknown => true
  | .token => decide (v.length = 16)
  | .disableMig => decide (v.length = 0)
  | .prefAddr => paValid v
  | k => validVar k v

def set (id : Nat) (v : Bytes) (tp : TP) : TP :=
  match kind id with
  | .odcid => { tp with odcid := v }
  | .token => { tp with token := v }
  | .iscid => { tp with iscid := v }
  | .rscid => { tp with rscid := v }
  | .disableMig => { tp with disableMig := true }
  | .prefAddr | .unknown => tp
  | k => setVarB k v tp

def ids (ps : List (Nat × Bytes)) : List Nat := ps.map (·.1)

def fold (tp : TP) (ps : List (Nat × Bytes)) : TP := ps.foldl (fun t p => set p.1 p.2 t) tp

def specDecode (b : Bytes) : Option TP :=
  match tlvs b with
  | none => none
  | some ps => if (ids ps).Nodup ∧ ps.all (fun p => valid p.1 p.2) then some (fold {} ps) else none

/-! ## The fixed decoder equals the spec -/

theorem implVarOk_all (k : PK) (x : Nat) : implVarOk Fixes.all k x = varOk k x := by
  cases k <;> simp [implVarOk, Fixes.all]

theorem applyVar_fixed (k : PK) (v : Bytes) (tp : TP) :
    (applyVar Fixes.all k v tp).toOption = if validVar k v then some (setVarB k v tp) else none := by
  unfold applyVar validVar setVarB readVar
  cases decVarint v with
  | none => simp [Except.toOption]
  | some r =>
    obtain ⟨x, n⟩ := r
    by_cases hn : n = v.length
    · simp only [hn, ↓reduceIte, implVarOk_all, decide_true, Bool.true_and, Option.map_some,
        Option.getD_some]
      cases varOk k x <;> simp [Except.toOption]
    · simp [hn, Except.toOption]

theorem apply_fixed (id : Nat) (v : Bytes) (tp : TP) :
    (apply Fixes.all id v tp).toOption = if valid id v then some (set id v tp) else none := by
  unfold apply valid set
  generalize kind id = k
  cases k
  all_goals first
    | exact applyVar_fixed _ v tp
    | (simp only [Fixes.all, Bool.true_and]; split <;> simp_all [Except.toOption]; done)
    | (simp [Except.toOption]; done)

/-- The spec, processed one parameter at a time. -/
def specFrom (seen : List Nat) (tp : TP) : List (Nat × Bytes) → Option TP
  | [] => some tp
  | (id, v) :: ps =>
    if id ∈ seen then none else if valid id v then specFrom (id :: seen) (set id v tp) ps else none

theorem decodeLoop_fixed (n : Nat) :
    ∀ b : Bytes, b.length ≤ n → ∀ seen tp,
      (decodeLoop Fixes.all seen tp b).toOption =
        match tlvs b with
        | none => none
        | some ps => specFrom seen tp ps := by
  induction n with
  | zero =>
    intro b hb seen tp
    have : b = [] := List.eq_nil_of_length_eq_zero (by omega)
    subst this
    rw [decodeLoop, tlvs]; simp [specFrom, Except.toOption]
  | succ n ih =>
    intro b hb seen tp
    rw [decodeLoop, tlvs]
    by_cases h0 : b.length = 0
    · simp [h0, specFrom, Except.toOption]
    · simp only [h0, ↓reduceIte]
      split
      · rfl
      · rename_i id k1 h1
        have hk1 := decVarint_some h1
        split
        · rfl
        · split
          · rfl
          · rename_i l k2 h2
            split
            · rfl
            · rename_i hle
              have ihb := ih (b.drop (k1 + k2 + l)) (by simp; omega)
              cases ht : tlvs (b.drop (k1 + k2 + l)) with
              | none =>
                simp only [Option.map_none]
                split
                · rfl
                · have ha := apply_fixed id ((b.drop (k1 + k2)).take l) tp
                  revert ha
                  cases apply Fixes.all id ((b.drop (k1 + k2)).take l) tp with
                  | error e => intro _; rfl
                  | ok tp' =>
                    intro ha
                    have := ihb (id :: seen) tp'
                    rw [ht] at this
                    exact this
              | some ps =>
                simp only [Option.map_some, specFrom]
                split
                · rfl
                · rename_i hs
                  try simp only [hs, ↓reduceIte]
                  have ha := apply_fixed id ((b.drop (k1 + k2)).take l) tp
                  revert ha
                  cases apply Fixes.all id ((b.drop (k1 + k2)).take l) tp with
                  | error e =>
                    intro ha
                    simp only [Except.toOption] at ha
                    split at ha
                    · cases ha
                    · rename_i hv; simp [hv, Except.toOption]
                  | ok tp' =>
                    intro ha
                    simp only [Except.toOption] at ha
                    split at ha
                    · rename_i hv
                      cases ha
                      simp only [hv, ↓reduceIte]
                      have := ihb (id :: seen) (set id ((b.drop (k1 + k2)).take l) tp)
                      rw [ht] at this
                      exact this
                    · cases ha

theorem ids_cons (id : Nat) (v : Bytes) (ps : List (Nat × Bytes)) :
    ids ((id, v) :: ps) = id :: ids ps := rfl

theorem specFrom_eq (ps : List (Nat × Bytes)) :
    ∀ seen tp, specFrom seen tp ps =
      if (∀ x ∈ ids ps, x ∉ seen) ∧ (ids ps).Nodup ∧ ps.all (fun p => valid p.1 p.2)
      then some (fold tp ps) else none := by
  induction ps with
  | nil => intro seen tp; simp [specFrom, ids, fold]
  | cons p ps ih =>
    obtain ⟨id, v⟩ := p
    intro seen tp
    simp only [specFrom]
    have hf : fold tp ((id, v) :: ps) = fold (set id v tp) ps := rfl
    rw [hf, ids_cons]
    by_cases hs : id ∈ seen
    · rw [if_pos hs, if_neg]
      intro h; exact h.1 id (List.mem_cons_self) hs
    · rw [if_neg hs]
      by_cases hv : valid id v = true
      · rw [if_pos hv, ih]
        by_cases hc : (∀ x ∈ ids ps, x ∉ id :: seen) ∧ (ids ps).Nodup ∧
            ps.all (fun p => valid p.1 p.2)
        · rw [if_pos hc, if_pos]
          refine ⟨fun x hx => ?_, List.nodup_cons.mpr ⟨fun hm => hc.1 id hm List.mem_cons_self, hc.2.1⟩,
            by simp only [List.all_cons, hv, Bool.true_and]; exact hc.2.2⟩
          rcases List.mem_cons.mp hx with rfl | hx
          · exact hs
          · exact fun h => hc.1 x hx (List.mem_cons_of_mem _ h)
        · rw [if_neg hc, if_neg]
          intro ⟨h1, h2, h3⟩
          apply hc
          refine ⟨fun x hx hx' => ?_, (List.nodup_cons.mp h2).2, ?_⟩
          · rcases List.mem_cons.mp hx' with rfl | hx'
            · exact (List.nodup_cons.mp h2).1 hx
            · exact h1 x (List.mem_cons_of_mem _ hx) hx'
          · simp only [List.all_cons, Bool.and_eq_true] at h3; exact h3.2
      · rw [if_neg hv, if_neg]
        intro ⟨_, _, h3⟩
        simp only [List.all_cons, Bool.and_eq_true] at h3
        exact hv h3.1

/-- **The fixed decoder meets the spec** on every input. -/
theorem decodeFixed_eq_spec (b : Bytes) : (decode Fixes.all b).toOption = specDecode b := by
  unfold decode specDecode
  rw [decodeLoop_fixed b.length b (Nat.le_refl _)]
  cases tlvs b with
  | none => rfl
  | some ps =>
    simp only
    rw [specFrom_eq]
    simp only [List.not_mem_nil, not_false_eq_true, implies_true, true_and]

/-! ## The encoder

`encode_transport_parameters` emits each populated field as one TLV, in the
fixed order below; varint parameters through `_emit_varint_param`, byte
strings through `_emit_bytes_param`, the flag as `varint(0x0c) 00`. It raises
on a reset token that is not 16 bytes, ack_delay_exponent > 20,
max_ack_delay ≥ 2^14 and active_connection_id_limit < 2, and
`encode_varint` raises on a value ≥ 2^62. Stated for any varint encoder
`enc` with `VarintCodec enc` (flare's is proved in L1). -/

/-- mirrors flare/quic/transport_params.mojo:237-250 @59bda50 (the value) -/
def optP (enc : Nat → Bytes) (id : Nat) : Option Nat → List (Nat × Bytes)
  | some x => [(id, enc x)]
  | none => []

/-- mirrors flare/quic/transport_params.mojo:253-263 @59bda50 (emitted only
when non-empty) -/
def bytP (id : Nat) (b : Bytes) : List (Nat × Bytes) := if b = [] then [] else [(id, b)]

/-- mirrors flare/quic/transport_params.mojo:266-272 @59bda50 -/
def flagP (id : Nat) (f : Bool) : List (Nat × Bytes) := if f then [(id, [])] else []

/-- The parameters emitted, in order.
mirrors flare/quic/transport_params.mojo:290-394 @59bda50 -/
def params (enc : Nat → Bytes) (tp : TP) : List (Nat × Bytes) :=
  bytP 0x00 tp.odcid ++ optP enc 0x01 tp.idle ++ bytP 0x02 tp.token ++ optP enc 0x03 tp.maxUdp ++
  optP enc 0x04 tp.maxData ++ optP enc 0x05 tp.sdBidiLocal ++ optP enc 0x06 tp.sdBidiRemote ++
  optP enc 0x07 tp.sdUni ++ optP enc 0x08 tp.streamsBidi ++ optP enc 0x09 tp.streamsUni ++
  optP enc 0x0a tp.ackExp ++ optP enc 0x0b tp.maxAckDelay ++ flagP 0x0c tp.disableMig ++
  optP enc 0x0e tp.cidLimit ++ bytP 0x0f tp.iscid ++ bytP 0x10 tp.rscid ++ optP enc 0x20 tp.datagram

/-- The length field: `encode_varint(len)`, a literal `00` for the flag.
mirrors flare/quic/transport_params.mojo:244, 257, 272 @59bda50 -/
def lenBytes (enc : Nat → Bytes) (v : Bytes) : Bytes := if v = [] then [0] else enc v.length

def wire (enc : Nat → Bytes) : List (Nat × Bytes) → Bytes
  | [] => []
  | (id, v) :: ps => enc id ++ (lenBytes enc v ++ (v ++ wire enc ps))

def varFields (tp : TP) : List (Option Nat) :=
  [tp.idle, tp.maxUdp, tp.maxData, tp.sdBidiLocal, tp.sdBidiRemote, tp.sdUni, tp.streamsBidi,
   tp.streamsUni, tp.ackExp, tp.maxAckDelay, tp.cidLimit, tp.datagram]

/-- The encoder's raises. mirrors flare/quic/transport_params.mojo:301-305,
351-376 @59bda50 and flare/quic/varint.mojo (values ≥ 2^62) -/
def encodeOk (tp : TP) : Bool :=
  (tp.token = [] || tp.token.length = 16) && tp.ackExp.all (· ≤ 20) &&
    tp.maxAckDelay.all (· < 2 ^ 14) && tp.cidLimit.all (2 ≤ ·) &&
    (varFields tp).all (fun o => o.all (· < 2 ^ 62)) &&
    [tp.odcid, tp.token, tp.iscid, tp.rscid].all (fun b => decide (b.length < 2 ^ 62))

/-- mirrors flare/quic/transport_params.mojo:277-395 @59bda50 -/
def encode (enc : Nat → Bytes) (tp : TP) : Except TPErr Bytes :=
  if encodeOk tp then .ok (wire enc (params enc tp)) else .error .invalid

theorem lenBytes_dec (enc : Nat → Bytes) (henc : VarintCodec enc) (v rest : Bytes)
    (hv : v.length < 2 ^ 62) :
    decVarint (lenBytes enc v ++ rest) = some (v.length, (lenBytes enc v).length) := by
  unfold lenBytes
  by_cases h : v = []
  · subst h; simp [decVarint, varLen, vval, Bytes.beNat]
  · simp only [h, if_false]; exact henc _ _ hv

theorem lenBytes_pos (enc : Nat → Bytes) (henc : VarintCodec enc) (v : Bytes)
    (hv : v.length < 2 ^ 62) : 1 ≤ (lenBytes enc v).length := by
  have := decVarint_some (lenBytes_dec enc henc v [] hv)
  omega

/-- **Framing round trip**: the wire form of any parameter list parses back
into that list. -/
theorem tlvs_wire (enc : Nat → Bytes) (henc : VarintCodec enc) :
    ∀ ps : List (Nat × Bytes), (∀ p ∈ ps, p.1 < 2 ^ 62 ∧ p.2.length < 2 ^ 62) →
      tlvs (wire enc ps) = some ps := by
  intro ps
  induction ps with
  | nil => intro _; simp [wire, tlvs]
  | cons p ps ih =>
    obtain ⟨id, v⟩ := p
    intro hall
    have hp := hall (id, v) List.mem_cons_self
    have hrest : ∀ q ∈ ps, q.1 < 2 ^ 62 ∧ q.2.length < 2 ^ 62 :=
      fun q hq => hall q (List.mem_cons_of_mem _ hq)
    simp only at hp
    have h1 := henc id (lenBytes enc v ++ (v ++ wire enc ps)) hp.1
    have h2 := lenBytes_dec enc henc v (v ++ wire enc ps) hp.2
    have hl2 := lenBytes_pos enc henc v hp.2
    have hl1 := (decVarint_some h1).1
    simp only [wire]
    rw [tlvs]
    have hne : (enc id ++ (lenBytes enc v ++ (v ++ wire enc ps))).length ≠ 0 := by
      simp only [List.length_append]; omega
    rw [if_neg hne]
    split
    · rename_i h; rw [h1] at h; cases h
    · rename_i id' k1 h
      rw [h1] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      have hlt : ¬ (enc id).length ≥ (enc id ++ (lenBytes enc v ++ (v ++ wire enc ps))).length := by
        simp only [List.length_append]; omega
      rw [if_neg hlt, List.drop_left, h2]
      simp only
      have hle : ¬ (enc id).length + (lenBytes enc v).length + v.length >
          (enc id ++ (lenBytes enc v ++ (v ++ wire enc ps))).length := by
        simp only [List.length_append]; omega
      rw [if_neg hle]
      have e1 : (enc id ++ (lenBytes enc v ++ (v ++ wire enc ps))).drop
          ((enc id).length + (lenBytes enc v).length) = v ++ wire enc ps := by
        rw [← List.append_assoc, ← List.length_append, List.drop_left]
      have e2 : (enc id ++ (lenBytes enc v ++ (v ++ wire enc ps))).drop
          ((enc id).length + (lenBytes enc v).length + v.length) = wire enc ps := by
        rw [← List.append_assoc, ← List.append_assoc, ← List.length_append, ← List.length_append,
          List.drop_left]
      rw [e1, e2, List.take_left, ih hrest]
      rfl

theorem decVarint_enc (enc : Nat → Bytes) (henc : VarintCodec enc) (x : Nat) (hx : x < 2 ^ 62) :
    decVarint (enc x) = some (x, (enc x).length) := by
  have := henc x [] hx; simpa using this

theorem setVarB_enc (enc : Nat → Bytes) (henc : VarintCodec enc) (k : PK) (x : Nat) (tp : TP)
    (hx : x < 2 ^ 62) : setVarB k (enc x) tp = setVar k x tp := by
  unfold setVarB; rw [decVarint_enc enc henc x hx]; rfl

theorem validVar_enc (enc : Nat → Bytes) (henc : VarintCodec enc) (k : PK) (x : Nat)
    (hx : x < 2 ^ 62) : validVar k (enc x) = varOk k x := by
  unfold validVar; rw [decVarint_enc enc henc x hx]; simp

/-- Every parameter the encoder emits names a distinct id. -/
theorem ids_params_sublist (enc : Nat → Bytes) (tp : TP) :
    (ids (params enc tp)).Sublist [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0a, 0x0b, 0x0c, 0x0e, 0x0f, 0x10, 0x20] := by
  have ho : ∀ id o, (ids (optP enc id o)).Sublist [id] := by
    intro id o; cases o <;> simp [optP, ids]
  have hb : ∀ id (b : Bytes), (ids (bytP id b)).Sublist [id] := by
    intro id b; unfold bytP; split <;> simp [ids]
  have hf : ∀ id f, (ids (flagP id f)).Sublist [id] := by
    intro id f; unfold flagP; split <;> simp [ids]
  have hm : ∀ a b : List (Nat × Bytes), ids (a ++ b) = ids a ++ ids b := fun a b => List.map_append
  unfold params
  simp only [hm]
  refine List.Sublist.append (List.Sublist.append (List.Sublist.append (List.Sublist.append
    (List.Sublist.append (List.Sublist.append (List.Sublist.append (List.Sublist.append
    (List.Sublist.append (List.Sublist.append (List.Sublist.append (List.Sublist.append
    (List.Sublist.append (List.Sublist.append (List.Sublist.append (List.Sublist.append
    (hb _ _) (ho _ _)) (hb _ _)) (ho _ _)) (ho _ _)) (ho _ _)) (ho _ _)) (ho _ _)) (ho _ _))
    (ho _ _)) (ho _ _)) (ho _ _)) (hf _ _)) (ho _ _)) (hb _ _)) (hb _ _)) (ho _ _)

/-- What the RFC lets an endpoint send: each varint value inside its
§18.2 range, and a 16-byte reset token if any. `encode` does not check
max_udp_payload_size ≥ 1200 or initial_max_streams_* ≤ 2^60 (they come
from configuration); the spec decoder rejects such a blob. -/
def Sendable (tp : TP) : Prop :=
  encodeOk tp = true ∧ tp.maxUdp.all (1200 ≤ ·) = true ∧ tp.streamsBidi.all (· ≤ 2 ^ 60) = true ∧
    tp.streamsUni.all (· ≤ 2 ^ 60) = true

abbrev step : TP → Nat × Bytes → TP := fun t p => set p.1 p.2 t

theorem fold_eq (tp : TP) (ps : List (Nat × Bytes)) : fold tp ps = ps.foldl step tp := rfl

theorem seg_var (enc : Nat → Bytes) (henc : VarintCodec enc) (id : Nat) (k : PK)
    (hset : ∀ v t, set id v t = setVarB k v t) (o : Option Nat) (ho : o.all (· < 2 ^ 62) = true)
    (t : TP) : (optP enc id o).foldl step t = match o with | none => t | some x => setVar k x t := by
  cases o with
  | none => rfl
  | some x =>
    simp only [Option.all_some, decide_eq_true_eq] at ho
    show set id (enc x) t = setVar k x t
    rw [hset, setVarB_enc enc henc k x t ho]

theorem valid_var (enc : Nat → Bytes) (henc : VarintCodec enc) (id : Nat) (k : PK)
    (hv : ∀ v, valid id v = validVar k v) (o : Option Nat) (ho : o.all (· < 2 ^ 62) = true)
    (hr : o.all (varOk k) = true) : (optP enc id o).all (fun p => valid p.1 p.2) = true := by
  cases o with
  | none => rfl
  | some x =>
    simp only [Option.all_some, decide_eq_true_eq] at ho hr
    simp only [optP, List.all_cons, List.all_nil, Bool.and_true]
    rw [hv, validVar_enc enc henc k x ho]; exact hr

theorem valid_bytes (id : Nat) (b : Bytes) (h : b ≠ [] → valid id b = true) :
    (bytP id b).all (fun p => valid p.1 p.2) = true := by
  unfold bytP; split
  · rfl
  · rename_i hb; simp only [List.all_cons, List.all_nil, Bool.and_true]; exact h hb

theorem varOk_true (k : PK) (o : Option Nat) (hk : ∀ x, varOk k x = true) : o.all (varOk k) = true := by
  cases o <;> simp [hk]

theorem ite_nil_self (b : Bytes) : (if b = [] then ([] : Bytes) else b) = b := by
  split <;> simp_all

theorem mem_wire_bounds (enc : Nat → Bytes) (henc : VarintCodec enc) (tp : TP) (h : encodeOk tp = true) :
    ∀ p ∈ params enc tp, p.1 < 2 ^ 62 ∧ p.2.length < 2 ^ 62 := by
  have hO : ∀ id o, id < 2 ^ 62 → o.all (· < 2 ^ 62) = true →
      ∀ p ∈ optP enc id o, p.1 < 2 ^ 62 ∧ p.2.length < 2 ^ 62 := by
    intro id o hid ho p hp
    cases o with
    | none => cases hp
    | some x =>
      simp only [optP, List.mem_cons, List.not_mem_nil, or_false] at hp
      subst hp
      simp only [Option.all_some, decide_eq_true_eq] at ho
      have := decVarint_some (decVarint_enc enc henc x ho)
      exact ⟨hid, by simp only; omega⟩
  have hB : ∀ id (b : Bytes), id < 2 ^ 62 → b.length < 2 ^ 62 →
      ∀ p ∈ bytP id b, p.1 < 2 ^ 62 ∧ p.2.length < 2 ^ 62 := by
    intro id b hid hb p hp
    unfold bytP at hp; split at hp
    · cases hp
    · simp only [List.mem_cons, List.not_mem_nil, or_false] at hp; subst hp; exact ⟨hid, hb⟩
  have hF : ∀ id f, id < 2 ^ 62 → ∀ p ∈ flagP id f, p.1 < 2 ^ 62 ∧ p.2.length < 2 ^ 62 := by
    intro id f hid p hp
    unfold flagP at hp; split at hp
    · simp only [List.mem_cons, List.not_mem_nil, or_false] at hp; subst hp; exact ⟨hid, by simp⟩
    · cases hp
  unfold encodeOk at h
  simp only [Bool.and_eq_true] at h
  obtain ⟨⟨⟨⟨⟨_, _⟩, _⟩, _⟩, hvars⟩, hbytes⟩ := h
  rw [List.all_eq_true] at hvars hbytes
  have hv : ∀ o, o ∈ varFields tp → o.all (· < 2 ^ 62) = true := hvars
  have hb : ∀ b, b ∈ [tp.odcid, tp.token, tp.iscid, tp.rscid] → b.length < 2 ^ 62 :=
    fun b hm => of_decide_eq_true (hbytes b hm)
  unfold params
  simp only [List.forall_mem_append]
  refine ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩
  · exact hB _ _ (by decide) (hb _ (by simp))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hB _ _ (by decide) (hb _ (by simp))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hF _ _ (by decide)
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))
  · exact hB _ _ (by decide) (hb _ (by simp))
  · exact hB _ _ (by decide) (hb _ (by simp))
  · exact hO _ _ (by decide) (hv _ (by simp [varFields]))

theorem encFacts (tp : TP) (hok : encodeOk tp = true) :
    (tp.token = [] ∨ tp.token.length = 16) ∧ tp.ackExp.all (· ≤ 20) = true ∧
    tp.maxAckDelay.all (· < 2 ^ 14) = true ∧ tp.cidLimit.all (2 ≤ ·) = true ∧
    ∀ o, o ∈ varFields tp → o.all (· < 2 ^ 62) = true := by
  have h := hok
  unfold encodeOk at h
  simp only [Bool.and_eq_true] at h
  obtain ⟨⟨⟨⟨⟨htok, hae⟩, hmad⟩, hcid⟩, hvars⟩, _⟩ := h
  rw [List.all_eq_true] at hvars
  refine ⟨?_, hae, hmad, hcid, hvars⟩
  simp only [Bool.or_eq_true, decide_eq_true_eq] at htok
  exact htok

theorem valid_params (enc : Nat → Bytes) (henc : VarintCodec enc) (tp : TP) (hs : Sendable tp) :
    (params enc tp).all (fun p => valid p.1 p.2) = true := by
  obtain ⟨hok, hmu, hsb, hsu⟩ := hs
  obtain ⟨htok, hae, hmad, hcid, hv⟩ := encFacts tp hok
  simp only [params, List.all_append, Bool.and_eq_true]
  refine ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩
  · exact valid_bytes _ _ (fun _ => rfl)
  · exact valid_var enc henc 0x01 .idle (fun _ => rfl) _ (hv _ (by simp [varFields])) (varOk_true _ _ (fun _ => rfl))
  · refine valid_bytes _ _ (fun hne => ?_)
    have h16 : tp.token.length = 16 := htok.resolve_left hne
    show decide (tp.token.length = 16) = true
    simp [h16]
  · exact valid_var enc henc 0x03 .maxUdp (fun _ => rfl) _ (hv _ (by simp [varFields])) hmu
  · exact valid_var enc henc 0x04 .maxData (fun _ => rfl) _ (hv _ (by simp [varFields])) (varOk_true _ _ (fun _ => rfl))
  · exact valid_var enc henc 0x05 .sdBidiLocal (fun _ => rfl) _ (hv _ (by simp [varFields])) (varOk_true _ _ (fun _ => rfl))
  · exact valid_var enc henc 0x06 .sdBidiRemote (fun _ => rfl) _ (hv _ (by simp [varFields])) (varOk_true _ _ (fun _ => rfl))
  · exact valid_var enc henc 0x07 .sdUni (fun _ => rfl) _ (hv _ (by simp [varFields])) (varOk_true _ _ (fun _ => rfl))
  · exact valid_var enc henc 0x08 .streamsBidi (fun _ => rfl) _ (hv _ (by simp [varFields])) hsb
  · exact valid_var enc henc 0x09 .streamsUni (fun _ => rfl) _ (hv _ (by simp [varFields])) hsu
  · exact valid_var enc henc 0x0a .ackExp (fun _ => rfl) _ (hv _ (by simp [varFields])) hae
  · exact valid_var enc henc 0x0b .maxAckDelay (fun _ => rfl) _ (hv _ (by simp [varFields])) hmad
  · unfold flagP; split <;> rfl
  · exact valid_var enc henc 0x0e .cidLimit (fun _ => rfl) _ (hv _ (by simp [varFields])) hcid
  · exact valid_bytes _ _ (fun _ => rfl)
  · exact valid_bytes _ _ (fun _ => rfl)
  · exact valid_var enc henc 0x20 .datagram (fun _ => rfl) _ (hv _ (by simp [varFields])) (varOk_true _ _ (fun _ => rfl))

theorem seg_idle (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x01 o).foldl step t = { t with idle := o.or t.idle } := by
  rw [seg_var enc henc 0x01 .idle (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_maxUdp (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x03 o).foldl step t = { t with maxUdp := o.or t.maxUdp } := by
  rw [seg_var enc henc 0x03 .maxUdp (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_maxData (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x04 o).foldl step t = { t with maxData := o.or t.maxData } := by
  rw [seg_var enc henc 0x04 .maxData (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_sdBidiLocal (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x05 o).foldl step t = { t with sdBidiLocal := o.or t.sdBidiLocal } := by
  rw [seg_var enc henc 0x05 .sdBidiLocal (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_sdBidiRemote (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x06 o).foldl step t = { t with sdBidiRemote := o.or t.sdBidiRemote } := by
  rw [seg_var enc henc 0x06 .sdBidiRemote (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_sdUni (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x07 o).foldl step t = { t with sdUni := o.or t.sdUni } := by
  rw [seg_var enc henc 0x07 .sdUni (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_streamsBidi (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x08 o).foldl step t = { t with streamsBidi := o.or t.streamsBidi } := by
  rw [seg_var enc henc 0x08 .streamsBidi (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_streamsUni (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x09 o).foldl step t = { t with streamsUni := o.or t.streamsUni } := by
  rw [seg_var enc henc 0x09 .streamsUni (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_ackExp (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x0a o).foldl step t = { t with ackExp := o.or t.ackExp } := by
  rw [seg_var enc henc 0x0a .ackExp (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_maxAckDelay (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x0b o).foldl step t = { t with maxAckDelay := o.or t.maxAckDelay } := by
  rw [seg_var enc henc 0x0b .maxAckDelay (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_cidLimit (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x0e o).foldl step t = { t with cidLimit := o.or t.cidLimit } := by
  rw [seg_var enc henc 0x0e .cidLimit (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_datagram (enc : Nat → Bytes) (henc : VarintCodec enc) (o : Option Nat)
    (ho : o.all (· < 2 ^ 62) = true) (t : TP) :
    (optP enc 0x20 o).foldl step t = { t with datagram := o.or t.datagram } := by
  rw [seg_var enc henc 0x20 .datagram (fun _ _ => rfl) o ho]
  cases o <;> rfl

theorem seg_odcid (b : Bytes) (t : TP) :
    (bytP 0x00 b).foldl step t = { t with odcid := if b = [] then t.odcid else b } := by
  unfold bytP; split <;> rfl

theorem seg_token (b : Bytes) (t : TP) :
    (bytP 0x02 b).foldl step t = { t with token := if b = [] then t.token else b } := by
  unfold bytP; split <;> rfl

theorem seg_iscid (b : Bytes) (t : TP) :
    (bytP 0x0f b).foldl step t = { t with iscid := if b = [] then t.iscid else b } := by
  unfold bytP; split <;> rfl

theorem seg_rscid (b : Bytes) (t : TP) :
    (bytP 0x10 b).foldl step t = { t with rscid := if b = [] then t.rscid else b } := by
  unfold bytP; split <;> rfl

theorem seg_disableMig (f : Bool) (t : TP) :
    (flagP 0x0c f).foldl step t = { t with disableMig := f || t.disableMig } := by
  unfold flagP; cases f <;> rfl

theorem fold_params (enc : Nat → Bytes) (henc : VarintCodec enc) (tp : TP) (hok : encodeOk tp = true) :
    (params enc tp).foldl step {} = tp := by
  obtain ⟨_, _, _, _, hv⟩ := encFacts tp hok
  simp only [params, List.foldl_append, seg_odcid, seg_token, seg_iscid, seg_rscid, seg_disableMig,
    seg_idle enc henc tp.idle (hv _ (by simp [varFields])), seg_maxUdp enc henc tp.maxUdp (hv _ (by simp [varFields])), seg_maxData enc henc tp.maxData (hv _ (by simp [varFields])), seg_sdBidiLocal enc henc tp.sdBidiLocal (hv _ (by simp [varFields])), seg_sdBidiRemote enc henc tp.sdBidiRemote (hv _ (by simp [varFields])), seg_sdUni enc henc tp.sdUni (hv _ (by simp [varFields])), seg_streamsBidi enc henc tp.streamsBidi (hv _ (by simp [varFields])), seg_streamsUni enc henc tp.streamsUni (hv _ (by simp [varFields])), seg_ackExp enc henc tp.ackExp (hv _ (by simp [varFields])), seg_maxAckDelay enc henc tp.maxAckDelay (hv _ (by simp [varFields])), seg_cidLimit enc henc tp.cidLimit (hv _ (by simp [varFields])), seg_datagram enc henc tp.datagram (hv _ (by simp [varFields]))]
  obtain ⟨odcid, idle, token, maxUdp, maxData, sdBidiLocal, sdBidiRemote, sdUni, streamsBidi,
    streamsUni, ackExp, maxAckDelay, disableMig, cidLimit, iscid, rscid, datagram⟩ := tp
  simp [ite_nil_self]

/-- **Encoder round trip**: every parameter set the RFC lets flare send is
encoded without raising, and the spec decoder (hence the fixed decoder)
accepts the blob and returns the same parameters. -/
theorem encode_roundtrip (enc : Nat → Bytes) (henc : VarintCodec enc) (tp : TP) (hs : Sendable tp) :
    ∃ b, encode enc tp = .ok b ∧ specDecode b = some tp := by
  refine ⟨wire enc (params enc tp), by simp [encode, hs.1], ?_⟩
  unfold specDecode
  rw [tlvs_wire enc henc _ (mem_wire_bounds enc henc tp hs.1)]
  have hnd : (ids (params enc tp)).Nodup := (ids_params_sublist enc tp).nodup (by decide)
  simp only
  rw [if_pos ⟨hnd, valid_params enc henc tp hs⟩, fold_eq, fold_params enc henc tp hs.1]

end Flare.L3.Quic.TransportParams
