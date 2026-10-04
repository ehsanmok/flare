import Flare.L2_Machine.TimerWheel

/-!
# TimerWheel: the order `_jump` fires timers, and `UInt64` time

Two refinements of `Flare.L2.TimerWheel` (flare/runtime/timer_wheel.mojo).

## Firing order of the jump path

flare documents it (timer_wheel.mojo:190-191): "Timers due within one
rotation are reported in fire order; overflow timers due in the same jump
come after them." `jump_fire_order` proves exactly that: the fired list
is `W ++ O` where `W` is a sublist of the wheel ids in slot order, sorted by
fire time, and `O` is a sublist of the overflow list in list order.

The tick-by-tick path reports in a different order: an overflow timer can
be due *before* a wheel timer (between rotation boundaries an overflow
entry may be as close as `512 - slot` ticks, a wheel entry as far as 511),
and `jump_not_sorted` exhibits a reachable-shaped state where the jump
reports a later timer first. Both paths fire the same set
(`jump_equiv_ticks`). Callers: the HTTP reactors
(`_server_reactor_epoll.mojo:174,396,615,761`,
`_unified_reactor_impl.mojo:764`) treat each fired token as an independent
connection close, so order is irrelevant there. QUIC
(`quic/server.mojo:2923-2939`) dispatches idle/ack-delay/PTO per slot; when
an idle timer and a PTO of the same connection fire in one jump in the
"wrong" order, the PTO handler runs on a connection whose idle timer has
also expired, i.e. at most one extra probe is sent before the idle close
reclaims the slot. No caller relies on fire-time order.

## `UInt64` time

The Mojo fields are `UInt64`; the base model uses `Nat`. The `…64`
definitions below redo every time computation with `UInt64` arithmetic
(`u n = UInt64.ofNat n`, wrapping `+` and `-`, `UInt64` comparisons) on the
same state shape. Under the Prop hypothesis `ClockBound` (every `now` fed to
`advance` is below `2^63` ms and every `after_ms` is a Mojo `Int`, i.e. below
`2^63`) the two machines agree on every trace (`run64_eq`). `2^63` ms is
about 292 million years of monotonic uptime. Without a bound the models
differ: `nextFire64_wraps` shows the "no timer" hint `now + 0xFFFFFFFF`
wrapping below `now` near `2^64`.
-/
namespace Flare.L2.TimerWheel

/-! ## Jump order -/

/-- `x` fires no later than `y` (both looked up in `E`) -/
def FireLe (E : Nat → Option Entry) (x y : Nat) : Prop :=
  ∀ ex ey, E x = some ex → E y = some ey → ex.fireAt ≤ ey.fireAt

/-- the wheel part of `jumpIds`, slots `slot+1 .. slot+512` -/
def wheelIds (s : TW) : List Nat :=
  (List.range 512).flatMap (fun d => s.wheel ((s.slot + (d + 1)) % 512))

theorem jumpIds_eq (s : TW) : jumpIds s = wheelIds s ++ s.overflow := rfl

theorem triage_fired_step {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (st : TState σ) (a : Nat) :
    (triage T put st a).fired = st.fired ∨ (triage T put st a).fired = st.fired ++ [a] := by
  unfold triage
  cases st.entries a with
  | none => exact Or.inl rfl
  | some e =>
    dsimp only
    split
    · exact Or.inl rfl
    · split
      · exact Or.inr rfl
      · exact Or.inl rfl

theorem fold_fired_sublist {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (L : List Nat) :
    ∀ st : TState σ, ∃ G, (L.foldl (triage T put) st).fired = st.fired ++ G ∧ G.Sublist L := by
  induction L with
  | nil => intro st; exact ⟨[], by simp, List.Sublist.slnil⟩
  | cons a L ih =>
    intro st
    rw [List.foldl_cons]
    obtain ⟨G, hG, hs⟩ := ih (triage T put st a)
    rcases triage_fired_step T put st a with h | h
    · rw [h] at hG; exact ⟨G, hG, hs.cons a⟩
    · rw [h, List.append_assoc] at hG; exact ⟨a :: G, hG, hs.cons_cons a⟩

/-- under the invariant, an id in the slot `d+1` ahead fires at `tick + d + 1` -/
theorem wheel_fireAt {s : TW} (h : Inv s) {d x : Nat} {e : Entry} (hd : d < 512)
    (hx : x ∈ s.wheel ((s.slot + (d + 1)) % 512)) (he : s.entries x = some e) :
    e.fireAt = s.tick + d + 1 := by
  obtain ⟨h1, h2, h3⟩ := (h.wheel_ok _ x hx).2 e he
  have := h.slot_lt
  omega

theorem wheelIds_sorted {s : TW} (h : Inv s) : (wheelIds s).Pairwise (FireLe s.entries) := by
  unfold wheelIds
  rw [List.pairwise_flatMap]
  refine ⟨fun d hd => List.pairwise_of_forall_mem_list fun x hx y hy ex ey hex hey => ?_, ?_⟩
  · have := List.mem_range.1 hd
    rw [wheel_fireAt h this hx hex, wheel_fireAt h this hy hey]; exact Nat.le_refl _
  · refine List.Pairwise.imp_of_mem ?_ List.pairwise_lt_range
    intro d1 d2 hd1 hd2 hlt x hx y hy ex ey hex hey
    rw [wheel_fireAt h (List.mem_range.1 hd1) hx hex, wheel_fireAt h (List.mem_range.1 hd2) hy hey]
    omega

/-- **Jump order (flare's documented contract).** The jump reports `W ++ O`:
`W` comes from the wheel, in slot order, sorted by fire time; `O` comes from
the overflow list, in list order. -/
theorem jump_fire_order {s : TW} (h : Inv s) (now : Nat) :
    ∃ W O, (jump s now).2 = W ++ O ∧ W.Sublist (wheelIds s) ∧ O.Sublist s.overflow ∧
      W.Pairwise (FireLe s.entries) := by
  have hj : (jump s now).2 = ((jumpIds s).foldl
      (triage now (fun (later : List Nat) eid (_ : Entry) => later ++ [eid])) ⟨s.entries, [], []⟩).fired := by
    simp only [jump]
  rw [hj, jumpIds_eq, List.foldl_append]
  obtain ⟨GA, hA, sA⟩ := fold_fired_sublist now
    (fun (later : List Nat) eid (_ : Entry) => later ++ [eid]) (wheelIds s) ⟨s.entries, [], []⟩
  obtain ⟨GB, hB, sB⟩ := fold_fired_sublist now
    (fun (later : List Nat) eid (_ : Entry) => later ++ [eid]) s.overflow
    ((wheelIds s).foldl (triage now (fun (later : List Nat) eid (_ : Entry) => later ++ [eid]))
      ⟨s.entries, [], []⟩)
  rw [hB, hA]
  exact ⟨GA, GB, by simp, sA, sB, (wheelIds_sorted h).sublist sA⟩

set_option maxRecDepth 100000 in
/-- The jump order is *not* fire-time order overall. From `init 700`:
schedule id 1 with delay 512 (overflow, due 1212), tick to 1000 (slot 300),
schedule id 2 with delay 400 (wheel, due 1400), then advance to 2000 (a
jump). The jump reports id 2 before id 1, although id 1 was due 188 ms
earlier; ticking would report `[1, 2]`. -/
theorem jump_not_sorted :
    (run (init 700) [.schedule 512 0, .advance 1000, .schedule 400 0]).1.entries 1 =
        some ⟨1212, 0, true⟩ ∧
    (run (init 700) [.schedule 512 0, .advance 1000, .schedule 400 0]).1.entries 2 =
        some ⟨1400, 0, true⟩ ∧
    (run (init 700) [.schedule 512 0, .advance 1000, .schedule 400 0, .advance 2000]).2 = [2, 1] := by
  decide

theorem ticks_add : ∀ (a b : Nat) (s : TW),
    (ticks (a + b) s).2 = (ticks a s).2 ++ (ticks b (ticks a s).1).2 ∧
    (ticks (a + b) s).1 = (ticks b (ticks a s).1).1
  | 0, b, s => by simp [ticks]
  | a + 1, b, s => by
    rw [show a + 1 + b = (a + b) + 1 by omega]
    simp only [ticks]
    obtain ⟨h1, h2⟩ := ticks_add a b (stepTick s).1
    rw [h1, h2, List.append_assoc]; exact ⟨rfl, rfl⟩

theorem eq_singleton_of_nodup {L : List Nat} {a : Nat} (hn : L.Nodup) (hm : ∀ x, x ∈ L ↔ x = a) :
    L = [a] := by
  cases L with
  | nil => exact absurd ((hm a).2 rfl) (by simp)
  | cons b t =>
    have hb : b = a := (hm b).1 List.mem_cons_self
    subst hb
    cases t with
    | nil => rfl
    | cons c t' =>
      have hc : c = b := (hm c).1 (List.mem_cons_of_mem _ List.mem_cons_self)
      subst hc
      exact absurd (List.mem_cons_self) (List.nodup_cons.1 hn).1

/-- the state before the last `advance` of `jump_not_sorted` -/
def S0 : TW := (run (init 700) [.schedule 512 0, .advance 1000, .schedule 400 0]).1

set_option maxRecDepth 100000 in
theorem S0_facts : S0.tick = 1000 ∧ S0.nextId = 2 ∧ S0.entries 0 = none ∧
    S0.entries 1 = some ⟨1212, 0, true⟩ ∧ S0.entries 2 = some ⟨1400, 0, true⟩ := by
  decide

theorem S0_inv : Inv S0 := inv_run _ (inv_init 700)

theorem S0_act (x : Nat) (e : Entry) :
    Act S0 x e ↔ (x = 1 ∧ e = ⟨1212, 0, true⟩) ∨ (x = 2 ∧ e = ⟨1400, 0, true⟩) := by
  obtain ⟨_, hn, h0, h1, h2⟩ := S0_facts
  unfold Act
  constructor
  · rintro ⟨he, ha⟩
    rcases Nat.lt_or_ge 2 x with hx | hx
    · rw [S0_inv.fresh x (by omega)] at he; cases he
    · have : x = 0 ∨ x = 1 ∨ x = 2 := by omega
      rcases this with rfl | rfl | rfl
      · rw [h0] at he; cases he
      · rw [h1] at he; cases he; exact Or.inl ⟨rfl, rfl⟩
      · rw [h2] at he; cases he; exact Or.inr ⟨rfl, rfl⟩
  · rintro (⟨rfl, rfl⟩ | ⟨rfl, rfl⟩)
    · exact ⟨h1, rfl⟩
    · exact ⟨h2, rfl⟩

/-- **Tick order differs**: ticking the same state over the same gap reports
`[1, 2]` (fire-time order), where the jump reports `[2, 1]`. -/
theorem ticks_order_example : (ticks 1000 S0).2 = [1, 2] := by
  obtain ⟨ht, _⟩ := S0_facts
  obtain ⟨hsplit, hst⟩ := ticks_add 212 788 S0
  rw [show (1000 : Nat) = 212 + 788 from rfl, hsplit]
  obtain ⟨A, hAt⟩ := ticks_spec 212 S0_inv
  obtain ⟨B, _⟩ := ticks_spec 788 A.inv
  have hA : (ticks 212 S0).2 = [1] := by
    refine eq_singleton_of_nodup A.nodup fun x => ?_
    rw [A.fired]
    constructor
    · rintro ⟨e, he, hle⟩
      rcases (S0_act x e).1 he with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
      · rfl
      · rw [ht] at hle; simp at hle
    · rintro rfl; exact ⟨_, (S0_act 1 _).2 (Or.inl ⟨rfl, rfl⟩), by rw [ht]; decide⟩
  have hB : (ticks 788 (ticks 212 S0).1).2 = [2] := by
    refine eq_singleton_of_nodup B.nodup fun x => ?_
    rw [B.fired, hAt, ht]
    constructor
    · rintro ⟨e, he, hle⟩
      obtain ⟨he', hlt⟩ := (A.left x e).1 he
      rcases (S0_act x e).1 he' with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
      · rw [ht] at hlt; simp at hlt
      · rfl
    · rintro rfl
      exact ⟨_, (A.left 2 _).2 ⟨(S0_act 2 _).2 (Or.inr ⟨rfl, rfl⟩), by rw [ht]; decide⟩, by decide⟩
  rw [hA, hB]; rfl

/-! ## `UInt64` time -/

/-- the Mojo `UInt64(n)` of a stored time -/
abbrev u (n : Nat) : UInt64 := UInt64.ofNat n

theorem u_toNat {n : Nat} (h : n < 2 ^ 64) : (u n).toNat = n := by
  simp [UInt64.toNat_ofNat', Nat.mod_eq_of_lt h]

theorem u_add {a b : Nat} (h : a + b < 2 ^ 64) : (u a + u b).toNat = a + b := by
  rw [UInt64.toNat_add, u_toNat (by omega), u_toNat (by omega), Nat.mod_eq_of_lt h]

theorem u_le {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64) : u a ≤ u b ↔ a ≤ b := by
  rw [UInt64.le_iff_toNat_le, u_toNat ha, u_toNat hb]

theorem u_lt {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64) : u a < u b ↔ a < b := by
  rw [UInt64.lt_iff_toNat_lt, u_toNat ha, u_toNat hb]

theorem u_sub {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64) (hab : b ≤ a) :
    (u a - u b).toNat = a - b := by
  rw [UInt64.toNat_sub_of_le _ _ ((u_le hb ha).2 hab), u_toNat ha, u_toNat hb]

/-- `fire_at = self._current_tick_ms + UInt64(delay)` in `UInt64`.
mirrors flare/runtime/timer_wheel.mojo:119-144 @59bda50 -/
def schedule64 (s : TW) (after : Int) (token : Nat) : TW × Nat :=
  let id := s.nextId + 1
  let delay := delayOf after
  let fireAt := (u s.tick + u delay).toNat
  let entries := upd s.entries id (some ⟨fireAt, token, true⟩)
  if delay < 512 then
    let j := (s.slot + delay) % 512
    ({ s with nextId := id, entries := entries, wheel := upd s.wheel j (s.wheel j ++ [id]) }, id)
  else
    ({ s with nextId := id, entries := entries, overflow := s.overflow ++ [id] }, id)

/-- `triage` with the `UInt64` comparison `entry.fire_at_ms <= T`.
mirrors flare/runtime/timer_wheel.mojo:238-255 and :274-285 @59bda50 -/
def triage64 {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (st : TState σ) (eid : Nat) :
    TState σ :=
  match st.entries eid with
  | none => st
  | some e =>
    if e.active = false then { st with entries := upd st.entries eid none }
    else if u e.fireAt ≤ u T then
      { st with entries := upd st.entries eid none, fired := st.fired ++ [eid] }
    else { st with rest := put st.rest eid e }

/-- `putB` with `dt = fire_at - T` computed in `UInt64`.
mirrors flare/runtime/timer_wheel.mojo:248-255 and :287-293 @59bda50 -/
def putB64 (T slot : Nat) (r : (Nat → List Nat) × List Nat) (eid : Nat) (e : Entry) :
    (Nat → List Nat) × List Nat :=
  if (u e.fireAt - u T).toNat < 512 then
    let target := (slot + (u e.fireAt - u T).toNat) % 512
    (upd r.1 target (r.1 target ++ [eid]), r.2)
  else (r.1, r.2 ++ [eid])

/-- mirrors flare/runtime/timer_wheel.mojo:208-256 @59bda50 -/
def stepTick64 (s : TW) : TW × List Nat :=
  let tick := (u s.tick + u 1).toNat
  let slot := (s.slot + 1) % 512
  let ids := s.wheel slot
  let wheel := upd s.wheel slot []
  let d := ids.foldl drainOne (s.entries, [])
  if slot = 0 ∧ s.overflow ≠ [] then
    let p := s.overflow.foldl (triage64 tick (putB64 tick slot)) ⟨d.1, d.2, (wheel, [])⟩
    ({ s with tick := tick, slot := slot, wheel := p.rest.1, entries := p.entries,
              overflow := p.rest.2 }, p.fired)
  else
    ({ s with tick := tick, slot := slot, wheel := wheel, entries := d.1 }, d.2)

def ticks64 : Nat → TW → TW × List Nat
  | 0, s => (s, [])
  | n + 1, s =>
    let r1 := stepTick64 s
    let r2 := ticks64 n r1.1
    (r2.1, r1.2 ++ r2.2)

def rebucketOne64 (now slot : Nat) (E : Nat → Option Entry)
    (st : (Nat → List Nat) × List Nat) (eid : Nat) : (Nat → List Nat) × List Nat :=
  match E eid with
  | none => st
  | some e => putB64 now slot st eid e

/-- mirrors flare/runtime/timer_wheel.mojo:258-293 @59bda50 -/
def jump64 (s : TW) (now : Nat) : TW × List Nat :=
  let c := (jumpIds s).foldl (triage64 now (fun (later : List Nat) eid _ => later ++ [eid]))
    ⟨s.entries, [], []⟩
  let r := c.rest.foldl (rebucketOne64 now s.slot c.entries) (fun _ => [], [])
  ({ s with tick := now, wheel := r.1, overflow := r.2, entries := c.entries }, c.fired)

/-- `advance(now_ms: UInt64)`: the jump test and the `while tick < now`
loop in `UInt64`.
mirrors flare/runtime/timer_wheel.mojo:169-256 @59bda50 -/
def advance64 (s : TW) (now : UInt64) : TW × List Nat :=
  if now > u s.tick ∧ now - u s.tick > 512 then jump64 s now.toNat
  else ticks64 (if u s.tick < now then (now - u s.tick).toNat else 0) s

/-- mirrors flare/runtime/timer_wheel.mojo:310-333 @59bda50 -/
def nextFire64 (s : TW) : UInt64 :=
  match scan s 512 1 with
  | some d => u s.tick + u d
  | none => if s.overflow ≠ [] then u s.tick + 512 else u s.tick + 0xFFFFFFFF

/-- every stored time is a `UInt64` value -/
def Bnd (s : TW) : Prop := s.tick < 2 ^ 64 ∧ ∀ x e, s.entries x = some e → e.fireAt < 2 ^ 64

def BndE (E : Nat → Option Entry) : Prop := ∀ x e, E x = some e → e.fireAt < 2 ^ 64

theorem triage64_eq {σ : Type} (T : Nat) (put put64 : σ → Nat → Entry → σ) (st : TState σ) (a : Nat)
    (hT : T < 2 ^ 64) (hb : BndE st.entries)
    (hput : ∀ r a e, T < e.fireAt → e.fireAt < 2 ^ 64 → put64 r a e = put r a e) :
    triage64 T put64 st a = triage T put st a := by
  unfold triage64 triage
  cases he : st.entries a with
  | none => rfl
  | some e =>
    dsimp only
    have hf := hb a e he
    by_cases hA : e.active = false
    · rw [if_pos hA, if_pos hA]
    · rw [if_neg hA, if_neg hA]
      by_cases hle : e.fireAt ≤ T
      · rw [if_pos ((u_le hf hT).2 hle), if_pos hle]
      · rw [if_neg (fun h => hle ((u_le hf hT).1 h)), if_neg hle, hput _ _ _ (by omega) hf]

theorem triage_bnd {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (st : TState σ) (a : Nat)
    (hb : BndE st.entries) : BndE (triage T put st a).entries :=
  fun x e he => hb x e ((triage_entries T put st a x e).1 he).1

theorem triage64_fold_eq {σ : Type} (T : Nat) (put put64 : σ → Nat → Entry → σ) (hT : T < 2 ^ 64)
    (hput : ∀ r a e, T < e.fireAt → e.fireAt < 2 ^ 64 → put64 r a e = put r a e) :
    ∀ (L : List Nat) (st : TState σ), BndE st.entries →
      L.foldl (triage64 T put64) st = L.foldl (triage T put) st := by
  intro L
  induction L with
  | nil => intro st _; rfl
  | cons a L ih =>
    intro st hb
    rw [List.foldl_cons, List.foldl_cons, triage64_eq T put put64 st a hT hb hput]
    exact ih _ (triage_bnd T put st a hb)

theorem putB64_eq (T slot : Nat) (r : (Nat → List Nat) × List Nat) (eid : Nat) (e : Entry)
    (hT : T < e.fireAt) (hf : e.fireAt < 2 ^ 64) : putB64 T slot r eid e = putB T slot r eid e := by
  unfold putB64 putB
  rw [u_sub hf (by omega) (by omega)]

theorem drain_bnd (L : List Nat) (E : Nat → Option Entry) (hb : BndE E) :
    BndE (L.foldl drainOne (E, [])).1 := by
  intro x e he
  rw [(drain_fold L E []).1] at he
  by_cases hx : x ∈ L
  · simp [hx] at he
  · simp only [hx, if_false] at he; exact hb x e he

theorem stepTick64_eq (s : TW) (hb : Bnd s) (ht : s.tick + 1 < 2 ^ 64) : stepTick64 s = stepTick s := by
  unfold stepTick64 stepTick
  rw [show (u s.tick + u 1).toNat = s.tick + 1 from u_add ht]
  dsimp only
  split
  · rw [triage64_fold_eq (s.tick + 1) (putB (s.tick + 1) ((s.slot + 1) % 512))
      (putB64 (s.tick + 1) ((s.slot + 1) % 512)) ht
      (fun r a e h1 h2 => putB64_eq _ _ r a e h1 h2) s.overflow _
      (drain_bnd _ s.entries hb.2)]
  · rfl

theorem stepTick_entries_sub (s : TW) (x : Nat) (e : Entry)
    (h : (stepTick s).1.entries x = some e) : s.entries x = some e := by
  unfold stepTick at h
  dsimp only at h
  have hd : ∀ y f, (List.foldl drainOne (s.entries, []) (s.wheel ((s.slot + 1) % 512))).1 y = some f →
      s.entries y = some f := by
    intro y f hy
    rw [(drain_fold _ s.entries []).1] at hy
    by_cases hx : y ∈ s.wheel ((s.slot + 1) % 512)
    · simp [hx] at hy
    · simp only [hx, if_false] at hy; exact hy
  split at h
  · have := ((triage_fold (s.tick + 1) (putB (s.tick + 1) ((s.slot + 1) % 512)) s.overflow _).1 x e).1 h
    exact hd x e this.1
  · exact hd x e h

theorem stepTick_tick (s : TW) : (stepTick s).1.tick = s.tick + 1 := by
  unfold stepTick; dsimp only; split <;> rfl

theorem ticks_bnd_tick : ∀ (n : Nat) (s : TW),
    (ticks n s).1.tick = s.tick + n ∧ ∀ x e, (ticks n s).1.entries x = some e → s.entries x = some e
  | 0, s => ⟨rfl, fun _ _ h => h⟩
  | n + 1, s => by
    obtain ⟨h1, h2⟩ := ticks_bnd_tick n (stepTick s).1
    refine ⟨?_, fun x e h => stepTick_entries_sub s x e (h2 x e h)⟩
    show (ticks n (stepTick s).1).1.tick = _
    rw [h1, stepTick_tick]; omega

theorem ticks64_eq : ∀ (n : Nat) (s : TW), Bnd s → s.tick + n < 2 ^ 64 → ticks64 n s = ticks n s
  | 0, _, _, _ => rfl
  | n + 1, s, hb, hn => by
    simp only [ticks64, ticks]
    rw [stepTick64_eq s hb (by omega),
      ticks64_eq n (stepTick s).1
        ⟨by rw [stepTick_tick]; omega, fun x e h => hb.2 x e (stepTick_entries_sub s x e h)⟩
        (by rw [stepTick_tick]; omega)]

theorem foldl_eq_of_mem {α β : Type} (f g : β → α → β) :
    ∀ (L : List α) (b : β), (∀ r a, a ∈ L → f r a = g r a) → L.foldl f b = L.foldl g b
  | [], _, _ => rfl
  | a :: L, b, h => by
    rw [List.foldl_cons, List.foldl_cons, h b a List.mem_cons_self]
    exact foldl_eq_of_mem f g L _ fun r x hx => h r x (List.mem_cons_of_mem _ hx)

theorem jump64_eq (s : TW) (now : Nat) (hb : Bnd s) (hn : now < 2 ^ 64) : jump64 s now = jump s now := by
  have key := triage64_fold_eq now (fun (later : List Nat) eid (_ : Entry) => later ++ [eid])
    (fun (later : List Nat) eid (_ : Entry) => later ++ [eid]) hn (fun _ _ _ _ _ => rfl)
    (jumpIds s) ⟨s.entries, [], []⟩ hb.2
  unfold jump64 jump
  dsimp only
  rw [key]
  obtain ⟨c1, _, c3, _⟩ := triage_fold now (fun (later : List Nat) eid (_ : Entry) => later ++ [eid])
    (jumpIds s) ⟨s.entries, [], []⟩
  dsimp only at c1 c3
  rw [keep_map_fst, List.nil_append] at c3
  generalize List.foldl (triage now fun later eid _ => later ++ [eid]) ⟨s.entries, [], []⟩ (jumpIds s)
    = C at c1 c3 ⊢
  rw [foldl_eq_of_mem (rebucketOne64 now s.slot C.entries) (rebucketOne now s.slot C.entries) C.rest
    _ (fun r a ha => ?_)]
  rw [c3, List.mem_map] at ha
  obtain ⟨⟨x, e⟩, hp, rfl⟩ := ha
  obtain ⟨_, hEx, _, hlt⟩ := (mem_keep s.entries now (jumpIds s) x e).1 hp
  unfold rebucketOne64 rebucketOne
  cases hC : C.entries x with
  | none => rfl
  | some e' =>
    dsimp only
    have := ((c1 x e').1 hC).1
    rw [hEx] at this; cases this
    exact putB64_eq now s.slot r x e hlt (hb.2 x e hEx)

theorem u512_lt (x : UInt64) : (512 : UInt64) < x ↔ 512 < x.toNat := by
  rw [UInt64.lt_iff_toNat_lt]; rfl

/-- **`advance` agrees** for every `UInt64` clock reading, as long as the
stored times are `UInt64` values. -/
theorem advance64_eq (s : TW) (now : UInt64) (hb : Bnd s) :
    advance64 s now = advance s now.toNat := by
  have hn := UInt64.toNat_lt now
  have ht := hb.1
  have hnow : u now.toNat = now := UInt64.ofNat_toNat
  unfold advance64 advance
  rw [← hnow]
  simp only [gt_iff_lt]
  rw [u_toNat hn]
  by_cases hlt : s.tick < now.toNat
  · have hs := u_sub hn ht (Nat.le_of_lt hlt)
    have hl : u s.tick < u now.toNat := (u_lt ht hn).2 hlt
    by_cases hj : 512 < now.toNat - s.tick
    · rw [if_pos (show u s.tick < u now.toNat ∧ 512 < u now.toNat - u s.tick from
          ⟨hl, by rw [u512_lt, hs]; exact hj⟩),
        if_pos (show s.tick < now.toNat ∧ 512 < now.toNat - s.tick from ⟨hlt, hj⟩),
        jump64_eq s _ hb hn]
    · rw [if_neg (show ¬ (u s.tick < u now.toNat ∧ 512 < u now.toNat - u s.tick) from
          fun h => hj (by have := (u512_lt _).1 h.2; rwa [hs] at this)),
        if_neg (show ¬ (s.tick < now.toNat ∧ 512 < now.toNat - s.tick) from fun h => hj h.2),
        if_pos hl, hs, ticks64_eq _ s hb (by omega)]
  · rw [if_neg (show ¬ (u s.tick < u now.toNat ∧ 512 < u now.toNat - u s.tick) from
        fun h => hlt ((u_lt ht hn).1 h.1)),
      if_neg (show ¬ (s.tick < now.toNat ∧ 512 < now.toNat - s.tick) from fun h => hlt h.1),
      if_neg (show ¬ (u s.tick < u now.toNat) from fun h => hlt ((u_lt ht hn).1 h)),
      show now.toNat - s.tick = 0 by omega]
    rfl

/-- `schedule` agrees when `tick + delay` fits in `UInt64`. -/
theorem schedule64_eq (s : TW) (after : Int) (token : Nat) (h : s.tick + delayOf after < 2 ^ 64) :
    schedule64 s after token = schedule s after token := by
  unfold schedule64 schedule
  dsimp only
  rw [u_add h]

theorem scan_empty (s : TW) (h : ∀ j, s.wheel j = []) : ∀ n d, scan s n d = none
  | 0, _ => rfl
  | n + 1, d => by simp only [scan, h, ne_eq, not_true_eq_false, if_false]; exact scan_empty s h n (d + 1)

/-- `next_fire_ms` agrees when `tick + 0xFFFFFFFF` fits in `UInt64`. -/
theorem nextFire64_eq (s : TW) (h : s.tick + 0xFFFFFFFF < 2 ^ 64) :
    (nextFire64 s).toNat = nextFire s := by
  unfold nextFire64 nextFire
  cases hs : scan s 512 1 with
  | some d =>
    dsimp only
    have := (scan_some s 512 1 d hs).2.1
    exact u_add (by omega)
  | none =>
    dsimp only
    split
    · exact (u_add (a := s.tick) (b := 512) (by omega) : _)
    · exact (u_add (a := s.tick) (b := 0xFFFFFFFF) (by omega) : _)

/-- Without a bound the models part: near `2^64` the "no timer" hint wraps
to a time before `now` (the reactor would then poll with a zero timeout). -/
theorem nextFire64_wraps :
    (nextFire64 (init (2 ^ 64 - 1))).toNat = 0xFFFFFFFE ∧
      nextFire (init (2 ^ 64 - 1)) = 2 ^ 64 - 1 + 0xFFFFFFFF := by
  have he := scan_empty (init (2 ^ 64 - 1)) (fun _ => rfl) 512 1
  unfold nextFire64 nextFire
  rw [he]
  exact ⟨by decide, rfl⟩

/-! ### Traces -/

inductive Op64 where
  | schedule (after : Int) (token : Nat)
  | cancel (id : Nat)
  | advance (now : UInt64)

def Op64.toOp : Op64 → Op
  | .schedule a t => .schedule a t
  | .cancel id => .cancel id
  | .advance now => .advance now.toNat

def exec64 (s : TW) : Op64 → TW × List Nat
  | .schedule a t => ((schedule64 s a t).1, [])
  | .cancel id => ((cancel s id).1, [])
  | .advance now => advance64 s now

def run64 : TW → List Op64 → TW × List Nat
  | s, [] => (s, [])
  | s, o :: os =>
    let r := exec64 s o
    let r' := run64 r.1 os
    (r'.1, r.2 ++ r'.2)

/-- **Environment hypothesis** (not an axiom): every clock reading passed to
`advance` is below `2^63` ms, and every `after_ms` is a Mojo `Int`, hence
below `2^63`. -/
def ClockBound : List Op64 → Prop
  | [] => True
  | .schedule a _ :: os => a < 2 ^ 63 ∧ ClockBound os
  | .cancel _ :: os => ClockBound os
  | .advance now :: os => now.toNat < 2 ^ 63 ∧ ClockBound os

def Bnd63 (s : TW) : Prop := s.tick < 2 ^ 63 ∧ BndE s.entries

theorem delayOf_lt (a : Int) (h : a < 2 ^ 63) : delayOf a < 2 ^ 63 := by
  unfold delayOf; split <;> omega

theorem schedule_bnd (s : TW) (a : Int) (t : Nat) (hs : Bnd63 s) (ha : a < 2 ^ 63) :
    Bnd63 (schedule s a t).1 := by
  have hd := delayOf_lt a ha
  have hsch : (schedule s a t).1.tick = s.tick ∧
      (schedule s a t).1.entries = upd s.entries (s.nextId + 1)
        (some ⟨s.tick + delayOf a, t, true⟩) := by
    unfold schedule; dsimp only; split <;> exact ⟨rfl, rfl⟩
  rw [Bnd63, hsch.1, hsch.2]
  refine ⟨hs.1, fun x e he => ?_⟩
  rw [upd_apply] at he
  split at he
  · cases he; dsimp only; have := hs.1; omega
  · exact hs.2 x e he

theorem cancel_bnd (s : TW) (id : Nat) (hs : Bnd63 s) : Bnd63 (cancel s id).1 := by
  unfold cancel
  cases he : s.entries id with
  | none => exact hs
  | some e0 =>
    dsimp only
    split
    · refine ⟨hs.1, fun x e hx => ?_⟩
      dsimp only at hx
      rw [upd_apply] at hx
      split at hx
      · cases hx; exact hs.2 id e0 he
      · exact hs.2 x e hx
    · exact hs

theorem advance_bnd (s : TW) (now : Nat) (hs : Bnd63 s) (hn : now < 2 ^ 63) :
    Bnd63 (advance s now).1 := by
  unfold advance
  split
  · refine ⟨hn, fun x e hx => ?_⟩
    unfold jump at hx; dsimp only at hx
    exact hs.2 x e (((triage_fold now _ (jumpIds s) ⟨s.entries, [], []⟩).1 x e).1 hx).1
  · obtain ⟨h1, h2⟩ := ticks_bnd_tick (now - s.tick) s
    refine ⟨by rw [h1]; have := hs.1; omega, fun x e hx => hs.2 x e (h2 x e hx)⟩

/-- **`UInt64` and `Nat` machines agree on every trace** satisfying
`ClockBound`, from any state whose clock is below `2^63`. -/
theorem run64_eq : ∀ (os : List Op64) (s : TW), Bnd63 s → ClockBound os →
    run64 s os = run s (os.map Op64.toOp)
  | [], _, _, _ => rfl
  | .schedule a t :: os, s, hs, ⟨ha, hos⟩ => by
    have hd := delayOf_lt a ha
    simp only [run64, run, exec64, exec, List.map_cons, Op64.toOp]
    rw [schedule64_eq s a t (by have := hs.1; omega),
      run64_eq os _ (schedule_bnd s a t hs ha) hos]
  | .cancel id :: os, s, hs, hos => by
    simp only [run64, run, exec64, exec, List.map_cons, Op64.toOp]
    rw [run64_eq os _ (cancel_bnd s id hs) hos]
  | .advance now :: os, s, hs, ⟨hn, hos⟩ => by
    simp only [run64, run, exec64, exec, List.map_cons, Op64.toOp]
    rw [advance64_eq s now ⟨by have := hs.1; omega, hs.2⟩,
      run64_eq os _ (advance_bnd s now.toNat hs hn) hos]

/-- from a fresh wheel anchored below `2^63` -/
theorem run64_init (now : Nat) (h : now < 2 ^ 63) (os : List Op64) (hos : ClockBound os) :
    run64 (init now) os = run (init now) (os.map Op64.toOp) :=
  run64_eq os _ ⟨h, fun _ _ he => by simp [init] at he⟩ hos

end Flare.L2.TimerWheel
