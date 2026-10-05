import Flare.L3_Protocol.Quic.Frame
/-!
# Postconditions of the QUIC frame parser

`ack_range_cap`, `newcid_checks` (the shipped parser), `parseFrame_not_unknown`
(QUIC-01 is fixed in flare) and `parseFrameFixed_ok` (the parser with all three
fixes, QUIC-01/02/03, meets `RfcFrameOk`).

Each proof is a case split over `Kind`: the branches that can produce the
frame of interest get a dedicated lemma, every other branch is discharged by
`body_sat` (it only returns frames of its own kind).
-/
namespace Flare.L3.Quic.Frame
open Flare.L3.Quic.Wire

/-! ## The fix meets `RfcFrameOk` -/

theorem ackFinish_fixed_ok (t : Nat) (largest delay first : UInt64)
    (ranges : List (UInt64 × UInt64)) :
    Sat RfcFrameOk (ackFinish Fixes.all t largest delay first ranges) :=
  sat_ite_dep (fun _ => sat_fail _) fun h => sat_pure <| by
    show ackOk largest first ranges = true
    cases hk : ackOk largest first ranges
    · exact absurd ⟨rfl, hk⟩ h
    · rfl

theorem ackBody_fixed_ok (b : Bytes) (t : Nat) : Sat RfcFrameOk (ackBody b Fixes.all t) :=
  sat_bind fun _ => sat_bind fun _ => sat_bind fun _ => sat_ite (sat_fail _) <|
    sat_bind fun _ => sat_bind fun _ => sat_bind fun _ => ackFinish_fixed_ok _ _ _ _ _

theorem maxStreamsBody_fixed_ok (b : Bytes) (t : Nat) :
    Sat RfcFrameOk (maxStreamsBody b Fixes.all t) :=
  sat_bind fun v => sat_ite_dep (fun _ => sat_fail _) fun h =>
    sat_pure (show v.toNat ≤ 2 ^ 60 from Nat.le_of_not_gt fun h' => h ⟨rfl, h'⟩)

theorem streamsBlockedBody_fixed_ok (b : Bytes) (t : Nat) :
    Sat RfcFrameOk (streamsBlockedBody b Fixes.all t) :=
  sat_bind fun v => sat_ite_dep (fun _ => sat_fail _) fun h =>
    sat_pure (show v.toNat ≤ 2 ^ 60 from Nat.le_of_not_gt fun h' => h ⟨rfl, h'⟩)

theorem unknownBody_fixed_ok (raw : UInt64) : Sat RfcFrameOk (unknownBody Fixes.all raw) :=
  sat_ite_dep (fun _ => sat_fail _) fun h => absurd rfl h

theorem rfcOk_hf (f : Frame) {k : Kind} (hf : f.kind = k)
    (hk : k ≠ .ack ∧ k ≠ .maxStreams ∧ k ≠ .streamsBlocked ∧ k ≠ .unknown) : RfcFrameOk f := by
  subst hf; exact rfcFrameOk_of_kind f hk.1 hk.2.1 hk.2.2.1 hk.2.2.2

theorem body_fixed_ok (b : Bytes) (raw : UInt64) (k : Kind) :
    Sat RfcFrameOk (body b Fixes.all raw k) := by
  cases k
  case ack => exact ackBody_fixed_ok b _
  case maxStreams => exact maxStreamsBody_fixed_ok b _
  case streamsBlocked => exact streamsBlockedBody_fixed_ok b _
  case unknown => exact unknownBody_fixed_ok raw
  all_goals exact body_sat b Fixes.all raw _ fun f hf => rfcOk_hf f hf (by decide)

theorem frameBody_fixed_ok (b : Bytes) (raw : UInt64) :
    Sat RfcFrameOk (frameBody b Fixes.all raw) :=
  body_fixed_ok b raw (kindOf raw.toNat)

/-- **Minimal fix meets the spec**: every frame `parseFrameFixed` accepts
satisfies `RfcFrameOk`. -/
theorem parseFrameFixed_ok (b : Bytes) (f : Frame) (n : Nat)
    (h : parseFrameFixed b = .ok (f, n)) : RfcFrameOk f := by
  unfold parseFrameFixed parseFrameWith at h
  split at h
  · cases h
  · simp only [parseFrameAux, bind, StateT.bind] at h
    cases hv : varint b 0 with
    | error e => rw [hv] at h; cases h
    | ok r => rw [hv] at h; exact frameBody_fixed_ok b r.1 r.2 f n h

/-- Every frame the drain loop returns came out of `pf`. -/
theorem parsePayloadWith_sat {P : Frame → Prop} (pf : Bytes → Except Err (Frame × Nat))
    (hpf : ∀ b f n, pf b = .ok (f, n) → P f) :
    ∀ fuel p fs, parsePayloadWith pf fuel p = .ok fs → ∀ f ∈ fs, P f := by
  intro fuel
  induction fuel with
  | zero => intro p fs h; simp only [parsePayloadWith, Except.ok.injEq] at h; subst h; simp
  | succ fuel ih =>
    intro p fs h
    simp only [parsePayloadWith] at h
    split at h
    · simp only [Except.ok.injEq] at h; subst h; simp
    · split at h
      · cases h
      · rename_i f n hp
        split at h
        · simp only [Except.ok.injEq] at h; subst h
          intro g hg; simp only [List.mem_singleton] at hg; subst hg; exact hpf p _ _ hp
        · split at h
          · cases h
          · rename_i fs' hrest
            simp only [Except.ok.injEq] at h; subst h
            intro g hg
            simp only [List.mem_cons] at hg
            rcases hg with rfl | hg
            · exact hpf p _ _ hp
            · exact ih _ _ hrest g hg

/-- **Payload-level fix.** Every frame of a packet payload accepted by the
fixed drain loop satisfies `RfcFrameOk`; in particular no unknown frame type
is skipped and no unknown frame's body is reinterpreted as frames. -/
theorem parsePayloadFixed_ok (p : Bytes) (fs : List Frame) (h : parsePayloadFixed p = .ok fs) :
    ∀ f ∈ fs, RfcFrameOk f :=
  parsePayloadWith_sat parseFrameFixed (fun b f n h => parseFrameFixed_ok b f n h) _ _ _ h

/-! ## Properties of flare as written -/

def AckCapOk : Frame → Prop
  | .ack _ _ _ ranges _ => ranges.length ≤ 0x4000
  | _ => True

def NewCidOk : Frame → Prop
  | .newConnectionId seq retire cid tok =>
      1 ≤ cid.length ∧ cid.length ≤ 20 ∧ tok.length = 16 ∧ retire ≤ seq
  | _ => True

theorem ackCapOk_of_kind (f : Frame) (h : f.kind ≠ .ack) : AckCapOk f := by
  cases f <;> first | exact True.intro | exact absurd rfl h

theorem newCidOk_of_kind (f : Frame) (h : f.kind ≠ .newConnectionId) : NewCidOk f := by
  cases f <;> first | exact True.intro | exact absurd rfl h

theorem sat_bytes_len (b : Bytes) (n : Nat) : Sat (fun l => l.length = n) (bytes b n) := by
  intro pos a p e
  simp only [bytes] at e
  split at e; · cases e
  have : ∀ k i xs, bytes.go b k i = .ok xs → xs.length = k := by
    intro k
    induction k with
    | zero => intro i xs h; simp [bytes.go] at h; simp [← h]
    | succ k ih =>
      intro i xs h
      simp only [bytes.go] at h
      cases h1 : rd b i with
      | error _ => rw [h1] at h; cases h
      | ok x =>
        rw [h1] at h
        simp only [bind, Except.bind] at h
        cases h2 : bytes.go b k (i + 1) with
        | error _ => rw [h2] at h; cases h
        | ok ys =>
          rw [h2] at h
          simp [pure, Except.pure] at h
          rw [← h]; simp [ih _ _ h2]
  split at e
  · rename_i xs hg; simp at e; rw [← e.1]; exact this _ _ _ hg
  · cases e

theorem ackBody_cap (b : Bytes) (fx : Fixes) (t : Nat) : Sat AckCapOk (ackBody b fx t) :=
  sat_bind fun _ => sat_bind fun _ => sat_bind fun rc => sat_ite_dep (fun _ => sat_fail _) fun hrc =>
    sat_bind fun _ => sat_bind_dep (sat_ackRanges_len b rc.toNat) fun ranges hl =>
      sat_bind fun _ => sat_ite (sat_fail _) <| sat_pure <| by
        show ranges.length ≤ 0x4000
        rw [hl]
        have : ¬ rc.toNat > 0x4000 := by
          intro h; exact hrc (UInt64.lt_iff_toNat_lt.mpr h)
        omega

theorem body_ackcap (b : Bytes) (fx : Fixes) (raw : UInt64) (k : Kind) :
    Sat AckCapOk (body b fx raw k) := by
  cases k
  case ack => exact ackBody_cap b fx _
  all_goals exact body_sat b fx raw _ fun f hf => ackCapOk_of_kind f (by rw [hf]; decide)

theorem newCidBody_ok (b : Bytes) : Sat NewCidOk (newCidBody b) :=
  sat_bind fun _ => sat_bind fun _ => sat_bind fun cl => sat_ite_dep (fun _ => sat_fail _) fun hcl =>
    sat_bind_dep (sat_bytes_len b cl.toNat) fun cid hc =>
    sat_bind_dep (sat_bytes_len b 16) fun tok ht =>
      sat_ite_dep (fun _ => sat_fail _) fun hr => sat_pure <| by
        refine ⟨?_, ?_, ht, ?_⟩
        · rw [hc]; omega
        · rw [hc]; omega
        · exact UInt64.not_lt.mp hr

theorem body_newcid (b : Bytes) (fx : Fixes) (raw : UInt64) (k : Kind) :
    Sat NewCidOk (body b fx raw k) := by
  cases k
  case newConnectionId => exact newCidBody_ok b
  all_goals exact body_sat b fx raw _ fun f hf => newCidOk_of_kind f (by rw [hf]; decide)

theorem parseFrame_sat {P : Frame → Prop} {b : Bytes}
    (hb : ∀ raw, Sat P (frameBody b Fixes.shipped raw)) (f : Frame) (n : Nat)
    (h : parseFrame b = .ok (f, n)) : P f := by
  unfold parseFrame parseFrameWith at h
  split at h
  · cases h
  · simp only [parseFrameAux, bind, StateT.bind] at h
    cases hv : varint b 0 with
    | error e => rw [hv] at h; cases h
    | ok r => rw [hv] at h; exact hb r.1 r.2 f n h

/-- **ACK range cap.** An ACK frame flare accepts carries at most 0x4000
additional ranges (frame.mojo:769-770), bounding the loop at 773. -/
theorem ack_range_cap (b : Bytes) (largest delay first : UInt64)
    (ranges : List (UInt64 × UInt64)) (ecn : Bool) (n : Nat)
    (h : parseFrame b = .ok (.ack largest delay first ranges ecn, n)) :
    ranges.length ≤ 0x4000 :=
  parseFrame_sat (P := AckCapOk) (fun raw => body_ackcap b Fixes.shipped raw _) _ _ h

/-- **NEW_CONNECTION_ID checks** (frame.mojo:885-899, RFC 9000 §19.15). -/
theorem newcid_checks (b : Bytes) (seq retire : UInt64) (cid tok : Bytes) (n : Nat)
    (h : parseFrame b = .ok (.newConnectionId seq retire cid tok, n)) :
    1 ≤ cid.length ∧ cid.length ≤ 20 ∧ tok.length = 16 ∧ retire ≤ seq :=
  parseFrame_sat (P := NewCidOk) (fun raw => body_newcid b Fixes.shipped raw _) _ _ h

/-! ## QUIC-01: the shipped parser never returns an unknown frame -/

theorem body_not_unknown (b : Bytes) (fx : Fixes) (raw : UInt64) (hfx : fx.unk = true) (k : Kind) :
    Sat (fun f => f.kind ≠ .unknown) (body b fx raw k) := by
  cases k
  case unknown =>
    show Sat _ (unknownBody fx raw)
    unfold unknownBody
    rw [if_pos hfx]
    exact sat_fail _
  all_goals exact body_sat b fx raw _ fun f hf => by rw [hf]; decide

/-- **QUIC-01 (fixed).** Every frame `parse_frame_into` accepts is of a type in
the v1 table (RFC 9000 §12.4): an unknown type is a `FRAME_ENCODING_ERROR`. -/
theorem parseFrame_not_unknown (b : Bytes) (f : Frame) (n : Nat)
    (h : parseFrame b = .ok (f, n)) : f.kind ≠ .unknown :=
  parseFrame_sat (P := fun f => f.kind ≠ .unknown)
    (fun raw => body_not_unknown b Fixes.shipped raw rfl _) f n h

/-- Payload level: no unknown frame, so no unknown frame's body is read as frames. -/
theorem parsePayload_not_unknown (p : Bytes) (fs : List Frame) (h : parsePayload p = .ok fs) :
    ∀ f ∈ fs, f.kind ≠ .unknown :=
  parsePayloadWith_sat parseFrame (fun b f n h => parseFrame_not_unknown b f n h) _ _ _ h

end Flare.L3.Quic.Frame
