import Flare.Core

/-!
# `BufReader`

flare/io/buf_reader.mojo. The buffer is `cap` bytes; `_pos` is the next
unread byte and `_len` the number of unread bytes. `_fill` resets both and
reads one chunk from the underlying `Readable`.

The `Readable` is modelled as the list of chunks its successive `read`
calls deliver (an empty chunk is a 0 return, i.e. EOF). The trait
contract (`0 ≤ n ≤ cap`; errors raise) is the hypothesis that every chunk
has length `≤ cap`. All in-tree implementors (`TcpStream`, `TlsStream`,
`_H2Transport`) return `0..size` or raise.
-/
namespace Flare.L2.BufReader

structure St where
  pos : Nat
  len : Nat
  buf : List UInt8
  src : List (List UInt8)
  deriving DecidableEq, Repr

/-- The bytes still to be delivered: unread buffer bytes, then the stream. -/
def view (s : St) : List UInt8 := (s.buf.drop s.pos).take s.len ++ s.src.flatten

/-- `_consume_byte`, with `_fill` inlined.
mirrors flare/io/buf_reader.mojo:139-178 @59bda50 -/
def consume (s : St) : Option UInt8 × St :=
  if s.len = 0 then
    match s.src with
    | [] => (none, { s with pos := 0, len := 0 })
    | c :: cs =>
      if c.length = 0 then (none, { s with pos := 0, len := 0, src := cs })
      else
        let buf' := c ++ s.buf.drop c.length
        (some (buf'.getD 0 0), { pos := 1, len := c.length - 1, buf := buf', src := cs })
  else (some (s.buf.getD s.pos 0), { s with pos := s.pos + 1, len := s.len - 1 })

/-- Buffer invariant under the Readable contract. -/
def Inv (cap : Nat) (s : St) : Prop :=
  s.buf.length = cap ∧ s.pos + s.len ≤ cap ∧ ∀ c ∈ s.src, c.length ≤ cap

theorem consume_inv (cap : Nat) (s : St) (h : Inv cap s) : Inv cap (consume s).2 := by
  obtain ⟨hb, hp, hs⟩ := h
  unfold consume
  split
  · split
    · exact ⟨hb, by simp, hs⟩
    · rename_i c cs heq
      have hc := hs c (by simp [heq])
      have hcs : ∀ x ∈ cs, x.length ≤ cap := fun x hx => hs x (by simp [heq, hx])
      split
      · exact ⟨hb, by simp, hcs⟩
      · refine ⟨?_, ?_, hcs⟩
        · simp [hb]; omega
        · simp only; omega
  · exact ⟨hb, by simp only; omega, hs⟩

theorem getD_eq_head (l : List UInt8) (b : UInt8) (t : List UInt8) (h : l = b :: t) :
    l.getD 0 0 = b := by subst h; rfl

/-- Refinement: no byte is lost or duplicated. A returned byte is the head
of the remaining view; a `None` (EOF) leaves the view unchanged. -/
theorem consume_view (cap : Nat) (s : St) (h : Inv cap s) :
    (∀ b, (consume s).1 = some b → b :: view (consume s).2 = view s) ∧
    ((consume s).1 = none → view (consume s).2 = view s) := by
  obtain ⟨hb, hp, hs⟩ := h
  unfold consume
  split
  · rename_i hl
    split
    · simp [view, hl]
    · rename_i c cs heq
      have hc := hs c (by simp [heq])
      split
      · rename_i h0
        have : c = [] := List.length_eq_zero_iff.mp h0
        simp [view, hl, heq, this]
      · rename_i h0
        obtain ⟨x, t, hxt⟩ : ∃ x t, c = x :: t := by
          cases c with
          | nil => simp at h0
          | cons x t => exact ⟨x, t, rfl⟩
        subst hxt
        refine ⟨fun b hb' => ?_, fun h => by simp at h⟩
        simp only [Option.some.injEq] at hb'
        subst hb'
        simp [view, hl, heq, List.getD]
  · rename_i hl
    refine ⟨fun b hb' => ?_, fun h => by simp at h⟩
    simp only [Option.some.injEq] at hb'
    subst hb'
    simp only [view]
    have hlt : s.pos < s.buf.length := by omega
    obtain ⟨n, hn⟩ : ∃ n, s.len = n + 1 := ⟨s.len - 1, by omega⟩
    rw [hn]
    have hd : s.buf.drop s.pos = s.buf[s.pos] :: s.buf.drop (s.pos + 1) :=
      List.drop_eq_getElem_cons hlt
    have hg : s.buf.getD s.pos 0 = s.buf[s.pos] := by
      simp [List.getD, List.getElem?_eq_getElem hlt]
    rw [hd, List.take_succ_cons, List.cons_append, hg, Nat.add_sub_cancel]

/-- `read_exact(n)`: `n` calls to `_consume_byte`, raising (here `none`) on EOF.
mirrors flare/io/buf_reader.mojo:241-266 @59bda50 -/
def readExact : Nat → St → Option (List UInt8 × St)
  | 0, s => some ([], s)
  | n + 1, s =>
    match consume s with
    | (none, _) => none
    | (some b, s') =>
      match readExact n s' with
      | none => none
      | some (bs, s'') => some (b :: bs, s'')

/-- `read_exact` returns exactly `n` bytes, and they are the next `n` bytes
of the stream, and the invariant is kept. -/
theorem readExact_correct (cap : Nat) :
    ∀ n s bs s', Inv cap s → readExact n s = some (bs, s') →
      bs.length = n ∧ bs ++ view s' = view s ∧ Inv cap s' := by
  intro n
  induction n with
  | zero => intro s bs s' hi h; simp [readExact] at h; obtain ⟨rfl, rfl⟩ := h; simp [hi]
  | succ n ih =>
    intro s bs s' hi h
    simp only [readExact] at h
    have hv := consume_view cap s hi
    have hi' := consume_inv cap s hi
    rcases hcs : consume s with ⟨o, s1⟩
    rw [hcs] at h hv hi'
    cases o with
    | none => simp at h
    | some b =>
      simp only at h
      cases heq : readExact n s1 with
      | none => simp [heq] at h
      | some p =>
        obtain ⟨bs1, s2⟩ := p
        simp only [heq, Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨l1, l2, l3⟩ := ih s1 bs1 s2 hi' heq
        refine ⟨by simp [l1], ?_, l3⟩
        rw [List.cons_append, l2]; exact hv.1 b rfl

/-! ## Outside the contract (Int model of `_pos`/`_len`) -/

/-- `_fill` + bookkeeping on Mojo `Int`s: a read returning `n` sets
`_pos = 0, _len = n`; `_consume_byte` without a refill does
`_pos += 1, _len -= 1` and refills only when `_len == 0`.
mirrors flare/io/buf_reader.mojo:117-178 @59bda50 -/
def fillInt (n : Int) : Int × Int := (0, n)
def stepInt (p : Int × Int) : Int × Int := (p.1 + 1, p.2 - 1)

def stepsInt : Nat → Int × Int → Int × Int
  | 0, p => p
  | k + 1, p => stepsInt k (stepInt p)

theorem stepsInt_eq (k : Nat) (p : Int × Int) : stepsInt k p = (p.1 + k, p.2 - k) := by
  induction k generalizing p with
  | zero => simp [stepsInt]
  | succ k ih => simp only [stepsInt, ih, stepInt]; ext <;> simp <;> omega

/-- A Readable returning `n > cap` breaks `pos + len ≤ cap` immediately. -/
theorem overlong_read_breaks_inv (cap : Nat) (n : Int) (h : (cap : Int) < n) :
    ¬ ((fillInt n).1 + (fillInt n).2 ≤ cap) := by simp [fillInt]; omega

/-- A Readable returning `n < 0`: `_len` is never 0 again, so no refill
ever happens and `_pos` runs past any buffer (`_buf[_pos]` out of bounds
after `cap` steps). -/
theorem negative_read_runs_away (n : Int) (h : n < 0) (k : Nat) :
    (stepsInt k (fillInt n)).2 ≠ 0 ∧ (stepsInt k (fillInt n)).1 = k := by
  rw [stepsInt_eq]; simp [fillInt]; omega

end Flare.L2.BufReader
