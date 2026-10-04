import Flare.Core.Bytes
/-!
# QUIC wire reading: cursor monad, varints, byte ranges

flare's QUIC parsers walk a `Span[UInt8]` with an `Int` cursor. We model
the buffer as `Bytes` and the cursor as the state of `StateT Nat`. Every
byte access goes through `rd`, which fails with the distinguished error
`Err.oob` when the index is out of range. Mojo raises (`Err.raise`) are a
different constructor, so "the parser never reads past its input" is the
statement "the parser never returns `Err.oob`".

Mojo `Int` cursors are 64-bit; positions here are `Nat`. Every cursor is
proved `≤ buf.length`, and `buf.length < 2^62` for any UDP datagram, so the
Mojo additions `pos + n` (with `n < 2^62` a decoded varint) never wrap.

The QUIC varint decoder below is re-modelled locally (the L1 agent owns the
round-trip proof); here we only need its bounds behaviour.
-/
namespace Flare.L3.Quic.Wire

inductive Err where
  | raise (msg : String)
  | oob
  deriving DecidableEq, Repr, Inhabited

/-- Cursor parser over a fixed buffer. -/
abbrev Parser (α : Type) := StateT Nat (Except Err) α

/-- Bounds-checked byte read at an absolute index. -/
def rd (b : Bytes) (i : Nat) : Except Err UInt8 :=
  if h : i < b.length then .ok b[i] else .error .oob

def fail {α : Type} (msg : String) : Parser α := fun _ => .error (.raise msg)

/-- Read big-endian continuation bytes `b[pos+1 .. pos+k]` onto `acc`. -/
def rdTail (b : Bytes) (pos : Nat) : Nat → UInt64 → Except Err UInt64
  | 0, acc => .ok acc
  | k + 1, acc => do
      let x ← rd b (pos + 1)
      rdTail b (pos + 1) k ((acc <<< 8) ||| x.toUInt64)

/-- mirrors flare/quic/varint.mojo:104-138 @59bda50 (applied to `buf[pos:]`;
the empty-slice raise covers `pos = len`). -/
def varint (b : Bytes) : Parser UInt64 := fun pos =>
  if pos > b.length then .error .oob
  else if pos = b.length then .error (.raise "quic varint: empty buffer")
  else do
    let first ← rd b pos
    let tag := (first >>> 6).toNat &&& 3
    let length := if tag = 0 then 1 else if tag = 1 then 2 else if tag = 2 then 4 else 8
    if b.length - pos < length then .error (.raise "quic varint: truncated")
    else do
      let v ← rdTail b pos (length - 1) (first.toUInt64 &&& 0x3F)
      .ok (v, pos + length)

/-- mirrors flare/quic/frame.mojo:701-714 @59bda50 (`_read_bytes`: the
`pos + n > len(buf)` check precedes the copy loop). -/
def bytes (b : Bytes) (n : Nat) : Parser Bytes := fun pos =>
  if pos + n > b.length then .error (.raise "quic frame: truncated payload")
  else
    let rec go : Nat → Nat → Except Err Bytes
      | 0, _ => .ok []
      | k + 1, i => do
          let x ← rd b i
          let xs ← go k (i + 1)
          .ok (x :: xs)
    match go n pos with
    | .ok xs => .ok (xs, pos + n)
    | .error e => .error e

/-- Read one byte at the cursor after an explicit `pos >= len` check
(the NEW_CONNECTION_ID length byte, frame.mojo:869-872). -/
def byte (b : Bytes) (msg : String) : Parser UInt8 := fun pos =>
  if pos ≥ b.length then .error (.raise msg)
  else match rd b pos with
    | .ok x => .ok (x, pos + 1)
    | .error e => .error e

/-! ## The `Good` predicate: no out-of-bounds read, cursor stays in range -/

/-- A parser is `Good` on `b` if, started anywhere in `0..len`, it never
fails with `oob` and on success leaves the cursor in `pos..len`. -/
def Good {α : Type} (b : Bytes) (p : Parser α) : Prop :=
  ∀ pos, pos ≤ b.length →
    p pos ≠ .error .oob ∧ ∀ a pos', p pos = .ok (a, pos') → pos ≤ pos' ∧ pos' ≤ b.length

theorem good_pure {α : Type} (b : Bytes) (a : α) : Good b (pure a) := by
  intro pos hp
  refine ⟨by simp [pure, StateT.pure, Except.pure], ?_⟩
  intro a' pos' h
  simp [pure, StateT.pure, Except.pure] at h
  omega

theorem good_fail {α : Type} (b : Bytes) (m : String) : Good b (fail (α := α) m) := by
  intro pos _
  exact ⟨by simp [fail], by intro a p h; simp [fail] at h⟩

theorem good_bind {α β : Type} (b : Bytes) (p : Parser α) (f : α → Parser β)
    (hp : Good b p) (hf : ∀ a, Good b (f a)) : Good b (p >>= f) := by
  intro pos hpos
  have ⟨h1, h2⟩ := hp pos hpos
  simp only [bind, StateT.bind]
  cases hq : p pos with
  | error e =>
    simp only [Except.bind]
    refine ⟨?_, by intro a p' h; cases h⟩
    intro he; cases he; exact h1 hq
  | ok r =>
    obtain ⟨a, p1⟩ := r
    have ⟨l1, l2⟩ := h2 a p1 hq
    have ⟨k1, k2⟩ := hf a p1 l2
    simp only [Except.bind]
    exact ⟨k1, fun c p' h => by have := k2 c p' h; omega⟩

theorem good_ite {α : Type} (b : Bytes) (c : Prop) [Decidable c] (p q : Parser α)
    (hp : Good b p) (hq : Good b q) : Good b (if c then p else q) := by
  split <;> assumption

theorem rd_ok_of_lt (b : Bytes) (i : Nat) (h : i < b.length) : ∃ x, rd b i = .ok x := by
  exact ⟨b[i], by simp [rd, h]⟩

theorem rdTail_no_oob (b : Bytes) (pos k : Nat) (acc : UInt64)
    (h : pos + k < b.length) : rdTail b pos k acc ≠ .error .oob := by
  induction k generalizing pos acc with
  | zero => simp [rdTail]
  | succ k ih =>
    simp only [rdTail]
    obtain ⟨x, hx⟩ := rd_ok_of_lt b (pos + 1) (by omega)
    rw [hx]
    exact ih (pos + 1) _ (by omega)

theorem good_varint (b : Bytes) : Good b (varint b) := by
  intro pos hpos
  simp only [varint]
  rw [if_neg (by omega)]
  by_cases he : pos = b.length
  · rw [if_pos he]; exact ⟨by simp, by intro a p h; cases h⟩
  · rw [if_neg he]
    obtain ⟨x, hx⟩ := rd_ok_of_lt b pos (by omega)
    simp only [hx, bind, Except.bind]
    generalize hlen : (if (x >>> 6).toNat &&& 3 = 0 then 1 else if (x >>> 6).toNat &&& 3 = 1 then 2
      else if (x >>> 6).toNat &&& 3 = 2 then 4 else 8) = L
    have hL : 1 ≤ L := by
      subst hlen; split <;> (try split) <;> (try split) <;> omega
    by_cases ht : b.length - pos < L
    · rw [if_pos ht]; exact ⟨by simp, by intro a p h; cases h⟩
    · rw [if_neg ht]
      have hno := rdTail_no_oob b pos (L - 1) (x.toUInt64 &&& 0x3F) (by omega)
      cases hr : rdTail b pos (L - 1) (x.toUInt64 &&& 0x3F) with
      | error e => exact ⟨by intro h; cases h; exact hno hr, by intro a p h; cases h⟩
      | ok v =>
        refine ⟨by simp, ?_⟩
        intro a p h
        simp only [pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at h
        omega

theorem bytes_go_no_oob (b : Bytes) : ∀ n i, i + n ≤ b.length → bytes.go b n i ≠ .error .oob := by
  intro n
  induction n with
  | zero => intro i _; simp [bytes.go]
  | succ k ih =>
    intro i hi
    simp only [bytes.go]
    obtain ⟨x, hx⟩ := rd_ok_of_lt b i (by omega)
    simp only [hx, bind, Except.bind]
    have := ih (i + 1) (by omega)
    cases hg : bytes.go b k (i + 1) with
    | error e => intro h; cases h; exact this hg
    | ok xs => simp [pure, Except.pure]

theorem good_bytes (b : Bytes) (n : Nat) : Good b (bytes b n) := by
  intro pos hpos
  simp only [bytes]
  by_cases h : pos + n > b.length
  · rw [if_pos h]; exact ⟨by simp, by intro a p h; cases h⟩
  · rw [if_neg h]
    have := bytes_go_no_oob b n pos (by omega)
    cases hg : bytes.go b n pos with
    | error e => exact ⟨by intro h'; cases h'; exact this hg, by intro a p h; simp at h⟩
    | ok xs =>
      refine ⟨by simp, ?_⟩
      intro a p h'
      simp only [Except.ok.injEq, Prod.mk.injEq] at h'
      omega

theorem good_byte (b : Bytes) (m : String) : Good b (byte b m) := by
  intro pos hpos
  simp only [byte]
  by_cases h : pos ≥ b.length
  · rw [if_pos h]; exact ⟨by simp, by intro a p h; cases h⟩
  · rw [if_neg h]
    obtain ⟨x, hx⟩ := rd_ok_of_lt b pos (by omega)
    rw [hx]
    refine ⟨by simp, ?_⟩
    intro a p h'
    simp only [Except.ok.injEq, Prod.mk.injEq] at h'
    omega

/-- The varint parser always makes progress when it succeeds. -/
theorem varint_progress (b : Bytes) (pos pos' : Nat) (v : UInt64)
    (h : varint b pos = .ok (v, pos')) : pos < pos' := by
  simp only [varint] at h
  split at h; · cases h
  split at h; · cases h
  cases hx : rd b pos with
  | error e => simp [hx, bind, Except.bind] at h
  | ok x =>
    simp only [hx, bind, Except.bind] at h
    generalize hlen : (if (x >>> 6).toNat &&& 3 = 0 then 1 else if (x >>> 6).toNat &&& 3 = 1 then 2
      else if (x >>> 6).toNat &&& 3 = 2 then 4 else 8) = L at h
    have hL : 1 ≤ L := by
      subst hlen; split <;> (try split) <;> (try split) <;> omega
    split at h; · cases h
    cases hr : rdTail b pos (L - 1) (x.toUInt64 &&& 0x3F) with
    | error e => rw [hr] at h; cases h
    | ok w =>
      rw [hr] at h
      simp only [pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at h
      omega

end Flare.L3.Quic.Wire
