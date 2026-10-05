import Flare.L3_Protocol.H3.RequestReader

/-!
# HTTP/3 server: unidirectional streams and the peer control stream

Model of the parts of `Http3Connection` (flare/http3/server.mojo) that
handle the client's unidirectional streams:

* `classify` — `_classify_uni_kind` (stream-type varint → kind, recording the
  control / QPACK encoder / QPACK decoder stream ids),
* `dispatchControl` — `_dispatch_control_frame` (SETTINGS first, no second
  SETTINGS, GOAWAY ids non-increasing) with `applySettings` =
  `_apply_peer_settings`,
* `feedControl` — the frame loop of `_feed_peer_control_stream` (16 KiB cap
  from the header, partial frames carried to the next chunk),
* `feedUni` — `feed_uni_stream_chunk` (per-stream buffering of the type
  varint, routing by kind).

Each function takes a `Fixes` switch: `Fixes.none` is flare as it was at
59bda50 (the pre-fix behaviour the Bugs counterexamples are about),
`Fixes.shipped` is flare as shipped on this branch (the fixes landed so
far), `Fixes.all` adds the minimal fixes of H3-03 (forbidden control-stream frame
types), H3-04 (HTTP/2-reserved setting identifiers), H3-05 (second QPACK
streams, client push stream) and H3-06 (bytes after the GOAWAY id). The QPACK encoder-stream payload is modelled
in `Flare.L3.Qpack`; here those bytes are consumed without effect, like the
decoder / push / unknown streams flare drops.

Spec (RFC 9114 §6.2, §7.2, §11.2; RFC 9204 §4.2), server receiving:
* `specClassify`: a second control, QPACK encoder or QPACK decoder stream is
  H3_STREAM_CREATION_ERROR (RFC 9114 §6.2.1, RFC 9204 §4.2); a push stream
  from a client is H3_STREAM_CREATION_ERROR (§6.2.2); unknown types are
  ignored (§6.2.3).
* `specControl`: the first frame is SETTINGS (else H3_MISSING_SETTINGS); a
  second SETTINGS, DATA, HEADERS, PUSH_PROMISE and the HTTP/2-reserved
  types 0x02/0x06/0x08/0x09 are H3_FRAME_UNEXPECTED (§7.2.1, §7.2.2,
  §7.2.4, §7.2.5, §7.2.8); a GOAWAY id larger than a previous one is an
  error (§5.2); a GOAWAY payload that is not exactly one varint is
  H3_FRAME_ERROR (`specGoaway`, §7.1, §7.2.6); CANCEL_PUSH, MAX_PUSH_ID and unknown types are accepted.
* `specApplySettings`: identifiers 0x02-0x05 are H3_SETTINGS_ERROR
  (§7.2.4.1, §11.2.2); others update the peer view or are ignored.

Results: `dispatchControlFixed_eq_spec`, `goawayFixed_eq_spec`, `applySettingsFixed_eq_spec`,
`classifyFixed_eq_spec` (the fixes equal the spec on every input),
`runClassifyFixed_unique` (with the fix at most one stream of each critical
type is ever accepted and no push stream), `feedControl_le` (the carry is a
suffix of the input).
-/
namespace Flare.L3.H3.Control
open Flare.L3.H3

inductive H3Err
  | streamCreation | missingSettings | frameUnexpected | settingsError | frameError
  | excessiveLoad | idError
  deriving DecidableEq, Repr

/-- Which minimal fixes are applied. -/
structure Fixes where
  frames : Bool    -- H3-03
  settings : Bool  -- H3-04
  streams : Bool   -- H3-05
  goawayLen : Bool -- H3-06
  deriving DecidableEq, Repr

def Fixes.none : Fixes := ⟨false, false, false, false⟩
def Fixes.all : Fixes := ⟨true, true, true, true⟩
/-- flare as shipped: one field flips to `true` with each of H3-03 (frames),
H3-04 (settings), H3-05 (streams) and H3-06 (goawayLen). -/
def Fixes.shipped : Fixes := ⟨true, false, false, false⟩

/-! ## SETTINGS -/

/-- mirrors flare/http3/server.mojo:1213-1228 @59bda50 (the fields of
`Http3Connection` it writes) -/
structure PeerSettings where
  maxFieldSection : Option Nat := none
  qpackCap : Option Nat := none
  qpackBlocked : Option Nat := none
  connect : Option Bool := none
  deriving DecidableEq, Repr

/-- mirrors flare/http3/server.mojo:1219-1228 @59bda50 -/
def applySetting (ps : PeerSettings) (p : Nat × Nat) : PeerSettings :=
  if p.1 = 0x06 then { ps with maxFieldSection := some p.2 }
  else if p.1 = 0x01 then { ps with qpackCap := some p.2 }
  else if p.1 = 0x07 then { ps with qpackBlocked := some p.2 }
  else if p.1 = 0x08 then { ps with connect := some (p.2 ≠ 0) }
  else ps

/-- HTTP/2 setting identifiers reserved by RFC 9114 §7.2.4.1 / §11.2.2. -/
def isH2Setting (id : Nat) : Bool := 2 ≤ id && id ≤ 5

/-- mirrors flare/http3/server.mojo:1213-1228 @59bda50 (never raises);
`fx.settings` adds the H3-04 check. -/
def applySettings (fx : Fixes) (ps : PeerSettings) (ss : List (Nat × Nat)) :
    Except H3Err PeerSettings :=
  if fx.settings ∧ ss.any (fun p => isH2Setting p.1) then .error .settingsError
  else .ok (ss.foldl applySetting ps)

/-- RFC 9114 §7.2.4.1: reserved identifiers are an error, every other
identifier is applied (known) or ignored (unknown). -/
def specApplySettings (ps : PeerSettings) : List (Nat × Nat) → Except H3Err PeerSettings
  | [] => .ok ps
  | (id, v) :: ss =>
    if 2 ≤ id ∧ id ≤ 5 then .error .settingsError
    else specApplySettings (applySetting ps (id, v)) ss

theorem applySettingsFixed_eq_spec (ps : PeerSettings) (ss : List (Nat × Nat)) :
    applySettings Fixes.all ps ss = specApplySettings ps ss := by
  induction ss generalizing ps with
  | nil => rfl
  | cons p ss ih =>
    obtain ⟨id, v⟩ := p
    have e := ih (applySetting ps (id, v))
    simp only [applySettings, Fixes.all, true_and, List.any_cons, Bool.or_eq_true,
      List.foldl_cons, specApplySettings] at e ⊢
    by_cases h : 2 ≤ id ∧ id ≤ 5
    · have : isH2Setting id = true := by simp [isH2Setting]; omega
      simp [this, h]
    · have : isH2Setting id = false := by simp [isH2Setting]; omega
      simp only [this, Bool.false_eq_true, false_or, h, ↓reduceIte] at e ⊢
      exact e

/-! ## Control-stream frames -/

/-- mirrors flare/http3/server.mojo:591-598 (initial values),
1170-1211 (fields read and written) @59bda50 -/
structure CtlState where
  settingsReceived : Bool := false
  goawayMax : Option Nat := none
  peer : PeerSettings := {}
  deriving DecidableEq, Repr

/-- Types RFC 9114 forbids on a control stream: DATA, HEADERS, PUSH_PROMISE
and the HTTP/2-reserved types. -/
def isForbiddenOnControl (t : Nat) : Bool := t = 0x00 || t = 0x01 || t = 0x05 || isH2Reserved t

/-- Record a GOAWAY id, rejecting an increase (RFC 9114 §5.2). -/
def goawayId (s : CtlState) (id : Nat) : Except H3Err CtlState :=
  match s.goawayMax with
  | some m => if id > m then .error .idError else .ok { s with goawayMax := some id }
  | none => .ok { s with goawayMax := some id }

/-- RFC 9114 §7.2.6 / §7.1: the GOAWAY payload is exactly one varint; a
truncated varint or bytes after it are H3_FRAME_ERROR. -/
def specGoaway (s : CtlState) (p : Bytes) : Except H3Err CtlState :=
  match decVarint p with
  | none => .error .frameError
  | some (id, k) => if k = p.length then goawayId s id else .error .frameError

/-- mirrors flare/http3/server.mojo:1197-1211 @59bda50: one varint is
decoded and `goaway_id.consumed` is never compared with `len(payload)`;
`fx.goawayLen` adds that comparison (H3-06). -/
def goaway (fx : Fixes) (s : CtlState) (p : Bytes) : Except H3Err CtlState :=
  if p.length = 0 then .error .frameError
  else match decVarint p with
    | none => .error .frameError
    | some (id, k) =>
      if fx.goawayLen ∧ k ≠ p.length then .error .frameError else goawayId s id

theorem goawayFixed_eq_spec (s : CtlState) (p : Bytes) :
    goaway Fixes.all s p = specGoaway s p := by
  unfold goaway specGoaway
  cases p with
  | nil => simp [decVarint]
  | cons b tl =>
    simp only [List.length_cons, Nat.add_one_ne_zero, ↓reduceIte, Fixes.all, true_and]
    cases decVarint (b :: tl) with
    | none => rfl
    | some r =>
      obtain ⟨id, k⟩ := r
      simp only
      by_cases hk : k = tl.length + 1 <;> simp [hk]

/-- mirrors flare/http3/server.mojo:1272-1337 (fixed, H3-03); `fx.frames` is the
H3-03 check after the SETTINGS-first check (absent at 59bda50). -/
def dispatchControl (fx : Fixes) (s : CtlState) (t : Nat) (p : Bytes) : Except H3Err CtlState :=
  if t = 0x04 then
    if s.settingsReceived then .error .frameUnexpected
    else match decodeSettings p with
      | none => .error .frameError
      | some ss => match applySettings fx s.peer ss with
        | .error e => .error e
        | .ok ps => .ok { s with peer := ps, settingsReceived := true }
  else if s.settingsReceived = false then .error .missingSettings
  else if t = 0x07 then goaway fx s p
  else if fx.frames ∧ isForbiddenOnControl t then .error .frameUnexpected
  else .ok s

inductive CtlClass | settings | goaway | forbidden | other
  deriving DecidableEq

def ctlClass (t : Nat) : CtlClass :=
  if t = 0x04 then .settings
  else if t = 0x07 then .goaway
  else if t = 0x00 ∨ t = 0x01 ∨ t = 0x05 ∨ t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09 then .forbidden
  else .other

/-- RFC 9114 §5.2, §6.2.1, §7.2 control-stream rules (server receiving). -/
def specControl (s : CtlState) (t : Nat) (p : Bytes) : Except H3Err CtlState :=
  match ctlClass t with
  | .settings =>
    if s.settingsReceived then .error .frameUnexpected
    else match decodeSettings p with
      | none => .error .frameError
      | some ss => match specApplySettings s.peer ss with
        | .error e => .error e
        | .ok ps => .ok { s with peer := ps, settingsReceived := true }
  | k =>
    if ¬ s.settingsReceived then .error .missingSettings
    else match k with
      | .goaway => specGoaway s p
      | .forbidden => .error .frameUnexpected
      | _ => .ok s

theorem dispatchControlFixed_eq_spec (s : CtlState) (t : Nat) (p : Bytes) :
    dispatchControl Fixes.all s t p = specControl s t p := by
  unfold dispatchControl specControl ctlClass
  by_cases h4 : t = 0x04
  · simp only [h4, ↓reduceIte, applySettingsFixed_eq_spec]
  · by_cases h7 : t = 0x07
    · simp only [h7, ↓reduceIte, Nat.reduceEqDiff, goawayFixed_eq_spec]
      cases s.settingsReceived <;> simp
    · have hf : isForbiddenOnControl t =
          decide (t = 0x00 ∨ t = 0x01 ∨ t = 0x05 ∨ t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09) := by
        unfold isForbiddenOnControl isH2Reserved
        by_cases hc : t = 0x00 ∨ t = 0x01 ∨ t = 0x05 ∨ t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09
        · simp only [hc, decide_true]; rcases hc with h | h | h | h | h | h | h <;> subst h <;> rfl
        · simp only [hc, decide_false]; simp only [not_or] at hc
          simp [hc.1, hc.2.1, hc.2.2.1, hc.2.2.2.1, hc.2.2.2.2.1, hc.2.2.2.2.2.1, hc.2.2.2.2.2.2]
      simp only [h4, h7, ↓reduceIte, Fixes.all, true_and, hf]
      by_cases hc : t = 0x00 ∨ t = 0x01 ∨ t = 0x05 ∨ t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09
      · simp only [hc, ↓reduceIte, decide_true]; cases s.settingsReceived <;> simp
      · simp only [hc, ↓reduceIte, decide_false]; cases s.settingsReceived <;> simp

/-- The frame loop of the control stream: returns the new state and the
carry (an incomplete trailing frame).
mirrors flare/http3/server.mojo:1071-1120 @59bda50 -/
def feedControlLoop (fx : Fixes) : Nat → CtlState → Bytes → Except H3Err (CtlState × Bytes)
  | 0, s, b => .ok (s, b)
  | fuel + 1, s, b =>
    if b.length = 0 then .ok (s, [])
    else match parseHeader b with
      | none => .ok (s, b)
      | some (t, l, hs) =>
        if l > 16384 then .error .excessiveLoad
        else if hs + l > b.length then .ok (s, b)
        else match dispatchControl fx s t ((b.drop hs).take l) with
          | .error e => .error e
          | .ok s' => feedControlLoop fx fuel s' (b.drop (hs + l))

/-- Fuel = buffer length suffices: every frame consumes `hs ≥ 2` bytes. -/
def feedControl (fx : Fixes) (s : CtlState) (b : Bytes) : Except H3Err (CtlState × Bytes) :=
  feedControlLoop fx b.length s b

/-- The carry is a suffix of the input (so its length never exceeds it). -/
theorem feedControlLoop_suffix (fx : Fixes) (fuel : Nat) :
    ∀ s b s' c, feedControlLoop fx fuel s b = .ok (s', c) → ∃ k, c = b.drop k := by
  induction fuel with
  | zero => intro s b s' c h; simp only [feedControlLoop, Except.ok.injEq, Prod.mk.injEq] at h;
              exact ⟨0, by simp [h.2]⟩
  | succ fuel ih =>
    intro s b s' c h
    simp only [feedControlLoop] at h
    split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h; exact ⟨b.length, by simp [← h.2]⟩
    · split at h
      · simp only [Except.ok.injEq, Prod.mk.injEq] at h; exact ⟨0, by simp [h.2]⟩
      · split at h
        · cases h
        · split at h
          · simp only [Except.ok.injEq, Prod.mk.injEq] at h; exact ⟨0, by simp [h.2]⟩
          · split at h
            · cases h
            · rename_i hs _ _ _ _ _ _
              obtain ⟨k, hk⟩ := ih _ _ s' c h
              exact ⟨_ + k, by rw [hk, List.drop_drop]⟩

theorem feedControl_le (fx : Fixes) (s : CtlState) (b : Bytes) (s' : CtlState) (c : Bytes)
    (h : feedControl fx s b = .ok (s', c)) : c.length ≤ b.length := by
  obtain ⟨k, hk⟩ := feedControlLoop_suffix fx _ s b s' c h
  rw [hk]; simp

/-! ## Unidirectional stream types -/

/-- mirrors flare/http3/server.mojo:103-125 @59bda50 -/
inductive UKind | control | push | qpackEnc | qpackDec | unknown
  deriving DecidableEq, Repr

/-- mirrors flare/http3/server.mojo:591-593 @59bda50 -/
structure UniState where
  ctrl : Option Nat := none
  enc : Option Nat := none
  dec : Option Nat := none
  deriving DecidableEq, Repr

/-- mirrors flare/http3/server.mojo:1045-1068 @59bda50; `fx.streams` adds the
H3-05 checks. -/
def classify (fx : Fixes) (u : UniState) (code sid : Nat) : Except H3Err (UniState × UKind) :=
  if code = 0x00 then
    if u.ctrl.isSome then .error .streamCreation
    else .ok ({ u with ctrl := some sid }, .control)
  else if code = 0x01 then
    if fx.streams then .error .streamCreation else .ok (u, .push)
  else if code = 0x02 then
    if fx.streams ∧ u.enc.isSome then .error .streamCreation
    else .ok ({ u with enc := some sid }, .qpackEnc)
  else if code = 0x03 then
    if fx.streams ∧ u.dec.isSome then .error .streamCreation
    else .ok ({ u with dec := some sid }, .qpackDec)
  else .ok (u, .unknown)

/-- RFC 9114 §6.2, RFC 9204 §4.2 (server receiving a client stream). -/
def specClassify (u : UniState) (code sid : Nat) : Except H3Err (UniState × UKind) :=
  match code with
  | 0x00 => match u.ctrl with
    | some _ => .error .streamCreation
    | none => .ok ({ u with ctrl := some sid }, .control)
  | 0x01 => .error .streamCreation
  | 0x02 => match u.enc with
    | some _ => .error .streamCreation
    | none => .ok ({ u with enc := some sid }, .qpackEnc)
  | 0x03 => match u.dec with
    | some _ => .error .streamCreation
    | none => .ok ({ u with dec := some sid }, .qpackDec)
  | _ => .ok (u, .unknown)

theorem classifyFixed_eq_spec (u : UniState) (code sid : Nat) :
    classify Fixes.all u code sid = specClassify u code sid := by
  unfold classify specClassify Fixes.all
  rcases u with ⟨c, e, d⟩
  match code with
  | 0 => cases c <;> rfl
  | 1 => rfl
  | 2 => cases e <;> rfl
  | 3 => cases d <;> rfl
  | n + 4 => simp

/-- Successive new uni streams `(sid, type code)`. -/
def runClassify (fx : Fixes) : UniState → List (Nat × Nat) → Except H3Err (List UKind)
  | _, [] => .ok []
  | u, (sid, code) :: xs => match classify fx u code sid with
    | .error e => .error e
    | .ok (u', k) => match runClassify fx u' xs with
      | .error e => .error e
      | .ok ks => .ok (k :: ks)

def slot : Option Nat → Nat
  | some _ => 0
  | none => 1

/-- **Uniqueness with the fix.** However many uni streams a client opens,
the accepted kinds contain at most one control, one QPACK encoder and one
QPACK decoder stream (counting those already open in `u`) and no push
stream. -/
theorem runClassifyFixed_unique (xs : List (Nat × Nat)) :
    ∀ u ks, runClassify Fixes.all u xs = .ok ks →
      ks.count .control ≤ slot u.ctrl ∧ ks.count .qpackEnc ≤ slot u.enc ∧
      ks.count .qpackDec ≤ slot u.dec ∧ ks.count .push = 0 := by
  induction xs with
  | nil => intro u ks h; simp only [runClassify, Except.ok.injEq] at h; subst h; simp
  | cons x xs ih =>
    intro u ks h
    obtain ⟨sid, code⟩ := x
    simp only [runClassify] at h
    split at h
    · cases h
    · rename_i u' k hc
      split at h
      · cases h
      · rename_i ks' hr
        simp only [Except.ok.injEq] at h; subst h
        have ih' := ih u' ks' hr
        rw [classifyFixed_eq_spec] at hc
        rcases u with ⟨c, e, d⟩
        unfold specClassify at hc
        match code, c, e, d with
        | 0, none, _, _ | 2, _, none, _ | 3, _, _, none =>
          simp only [Except.ok.injEq, Prod.mk.injEq] at hc; obtain ⟨rfl, rfl⟩ := hc
          simp [slot] at ih' ⊢; omega
        | 0, some _, _, _ | 2, _, some _, _ | 3, _, _, some _ | 1, _, _, _ => cases hc
        | n + 4, _, _, _ =>
          simp only [Except.ok.injEq, Prod.mk.injEq] at hc; obtain ⟨rfl, rfl⟩ := hc
          simpa [slot] using ih'

/-! ## `feed_uni_stream_chunk` -/

def lookup {α : Type} (l : List (Nat × α)) (k : Nat) : Option α := (l.find? (·.1 = k)).map (·.2)
def erase {α : Type} (l : List (Nat × α)) (k : Nat) : List (Nat × α) := l.filter (·.1 ≠ k)
def set {α : Type} (l : List (Nat × α)) (k : Nat) (v : α) : List (Nat × α) := (k, v) :: erase l k

/-- mirrors flare/http3/server.mojo (fields `peer_uni_kinds`,
`peer_uni_buffers`, the uni-stream ids and the control-stream state) @59bda50 -/
structure Conn where
  uni : UniState := {}
  kinds : List (Nat × UKind) := []
  bufs : List (Nat × Bytes) := []
  ctl : CtlState := {}

/-- Route a resolved stream's bytes by kind.
mirrors flare/http3/server.mojo:1034-1043 @59bda50 -/
def route (fx : Fixes) (c : Conn) (k : UKind) (buf : Bytes) : Except H3Err Conn :=
  match k with
  | .control => match feedControl fx c.ctl buf with
    | .error e => .error e
    | .ok (ctl', carry) =>
      .ok { c with ctl := ctl',
                   bufs := if carry = [] then c.bufs else set c.bufs (c.uni.ctrl.getD 0) carry }
  | _ => .ok c

/-- mirrors flare/http3/server.mojo:975-1043 @59bda50 -/
def feedUni (fx : Fixes) (c : Conn) (sid : Nat) (chunk : Bytes) : Except H3Err Conn :=
  let buf := (lookup c.bufs sid).getD [] ++ chunk
  let c := { c with bufs := erase c.bufs sid }
  match lookup c.kinds sid with
  | some k => route fx c k buf
  | none => match decVarint buf with
    | none => .ok { c with bufs := set c.bufs sid buf }
    | some (code, n) => match classify fx c.uni code sid with
      | .error e => .error e
      | .ok (u', k) => route fx { c with uni := u', kinds := set c.kinds sid k } k (buf.drop n)

/-- The raised error, if any (`Except` has no decidable equality). -/
def errOf {α : Type} : Except H3Err α → Option H3Err
  | .error e => some e
  | .ok _ => none

/-- A sequence of `feed_uni_stream_chunk(sid, chunk)` calls. -/
def feedUnis (fx : Fixes) : Conn → List (Nat × Bytes) → Except H3Err Conn
  | c, [] => .ok c
  | c, (sid, ch) :: xs => match feedUni fx c sid ch with
    | .error e => .error e
    | .ok c' => feedUnis fx c' xs

end Flare.L3.H3.Control
