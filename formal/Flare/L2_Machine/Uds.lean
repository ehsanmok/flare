import Flare.Core

/-!
# Unix-domain sockets: the `sockaddr_un` path codec

`flare/uds/_libc.mojo:55-134`. `fill_sockaddr_un` writes a 2-byte family
prefix, the path's UTF-8 bytes and a NUL; `read_path_from_sockaddr_un`
reads bytes from offset 2 up to the first NUL (at most
`min(used_len - 2, SUN_PATH_MAX)` bytes) and appends `chr(b)` for each byte
`b`, i.e. it decodes Latin-1 and re-encodes every byte `≥ 0x80` as a
2-byte UTF-8 sequence.

A Mojo `String` is modelled by its UTF-8 bytes (`Bytes`); `out += chr(b)`
appends the UTF-8 encoding of code point `b`. The family-prefix bytes are
left abstract (`h0`, `h1`); they are never read back.
-/
namespace Flare.L2.Uds

/-- `SUN_PATH_MAX`: 108 on Linux, 104 on macOS (`uds/_libc.mojo:48`). -/
def sunPathMax (linux : Bool) : Nat := if linux then 108 else 104

/-- `SOCKADDR_UN_SIZE = 2 + SUN_PATH_MAX` (`uds/_libc.mojo:43-47`). -/
def sockaddrUnSize (linux : Bool) : Nat := 2 + sunPathMax linux

/-- `fill_sockaddr_un`: `none` = raises (too long / embedded NUL); otherwise
the bytes written and the returned `addrlen`.
mirrors flare/uds/_libc.mojo:55-107 @59bda50 -/
def fill (linux : Bool) (h0 h1 : UInt8) (path : Bytes) : Option (Bytes × Nat) :=
  if path.length ≥ sunPathMax linux then none
  else if (0 : UInt8) ∈ path then none
  else some ([h0, h1] ++ path ++ [0], 2 + path.length + 1)

/-- UTF-8 encoding of the code point `b` (`chr(Int(b))`, `b < 256`). -/
def chrUtf8 (b : UInt8) : Bytes :=
  if b < 0x80 then [b] else [(0xC0 : UInt8) ||| (b >>> (6 : UInt8)), (0x80 : UInt8) ||| (b &&& (0x3F : UInt8))]

def latin1ToUtf8 : Bytes → Bytes
  | [] => []
  | b :: bs => chrUtf8 b ++ latin1ToUtf8 bs

/-- the raw path bytes the decoder loop visits -/
def rawPath (linux : Bool) (buf : Bytes) (usedLen : Nat) : Bytes :=
  ((buf.drop 2).take (min (usedLen - 2) (sunPathMax linux))).takeWhile (· != 0)

/-- mirrors flare/uds/_libc.mojo:110-133 @59bda50 -/
def readPath (linux : Bool) (buf : Bytes) (usedLen : Nat) : Bytes :=
  latin1ToUtf8 (rawPath linux buf usedLen)

/-- The minimal fix: build the `String` from the collected bytes as UTF-8
(`String(unsafe_from_utf8=...)`), as `fill_sockaddr_un` encoded them. -/
def readPathFixed (linux : Bool) (buf : Bytes) (usedLen : Nat) : Bytes :=
  rawPath linux buf usedLen

/-- the used length `fill` returns fits the buffer -/
theorem fill_len_le (linux : Bool) (h0 h1 : UInt8) (p b : Bytes) (n : Nat)
    (h : fill linux h0 h1 p = some (b, n)) : n ≤ sockaddrUnSize linux ∧ b.length = n := by
  unfold fill at h
  split at h
  · cases h
  · split at h
    · cases h
    · cases h; unfold sockaddrUnSize; simp; omega

theorem takeWhile_take_path (p rest : Bytes) (hp : ∀ b ∈ p, b ≠ 0) :
    ∀ k, p.length < k → ((p ++ 0 :: rest).take k).takeWhile (· != 0) = p := by
  induction p with
  | nil => intro k hk; cases k with
    | zero => omega
    | succ k => simp
  | cons x xs ih =>
    intro k hk
    cases k with
    | zero => simp at hk
    | succ k =>
      have hx : x ≠ 0 := hp x (by simp)
      simp only [List.cons_append, List.take_succ_cons, List.takeWhile_cons]
      rw [if_pos (by simpa using hx)]
      rw [ih (fun b hb => hp b (by simp [hb])) k (by simp at hk; omega)]

/-- **Fix meets spec**: whatever `used_len` the kernel reports (at least the
filled length) and whatever follows the NUL, the fixed decoder returns the
bound path. -/
theorem readPathFixed_fill (linux : Bool) (h0 h1 : UInt8) (p b rest : Bytes) (n usedLen : Nat)
    (h : fill linux h0 h1 p = some (b, n)) (hu : n ≤ usedLen) :
    readPathFixed linux (b ++ rest) usedLen = p := by
  unfold fill at h
  split at h
  · cases h
  · rename_i hlen
    split at h
    · cases h
    · rename_i hnul
      cases h
      unfold readPathFixed rawPath
      simp only [List.append_assoc, List.cons_append, List.nil_append, List.drop_succ_cons,
        List.drop_zero]
      exact takeWhile_take_path p rest (fun b hb hb0 => hnul (hb0 ▸ hb)) _
        (by cases linux <;> simp only [sunPathMax] at hlen ⊢ <;> simp at hlen ⊢ <;> omega)

theorem latin1ToUtf8_length (p : Bytes) :
    (latin1ToUtf8 p).length = p.length + (p.filter (fun b => decide (0x80 ≤ b))).length := by
  induction p with
  | nil => rfl
  | cons b bs ih =>
    simp only [latin1ToUtf8, List.length_append, ih, List.filter_cons, List.length_cons]
    unfold chrUtf8
    by_cases hb : b < 0x80
    · have hb' : ¬ (0x80 ≤ b) := fun h => UInt8.not_lt.2 h hb
      rw [if_pos hb, if_neg (by simpa using hb')]
      simp only [List.length_singleton]; omega
    · have hb' : 0x80 ≤ b := UInt8.not_lt.1 hb
      rw [if_neg hb, if_pos (by simpa using hb')]
      simp only [List.length_cons, List.length_nil]; omega

theorem latin1ToUtf8_ascii (p : Bytes) (h : ∀ b ∈ p, b < 0x80) : latin1ToUtf8 p = p := by
  induction p with
  | nil => rfl
  | cons b bs ih =>
    simp only [latin1ToUtf8, chrUtf8]
    rw [if_pos (h b (by simp)), ih (fun x hx => h x (by simp [hx]))]; rfl

/-- **Characterisation of the defect**: flare's decoder returns the bound
path exactly when every byte of it is ASCII; any non-ASCII path comes back
longer (each byte `≥ 0x80` becomes two). -/
theorem readPath_fill_iff_ascii (linux : Bool) (h0 h1 : UInt8) (p b rest : Bytes) (n usedLen : Nat)
    (h : fill linux h0 h1 p = some (b, n)) (hu : n ≤ usedLen) :
    readPath linux (b ++ rest) usedLen = p ↔ ∀ x ∈ p, x < 0x80 := by
  have hr : rawPath linux (b ++ rest) usedLen = p := readPathFixed_fill linux h0 h1 p b rest n usedLen h hu
  unfold readPath; rw [hr]
  constructor
  · intro he x hx
    have hl := congrArg List.length he
    rw [latin1ToUtf8_length] at hl
    have h0' : (p.filter (fun b => decide (0x80 ≤ b))).length = 0 := by omega
    rw [List.length_eq_zero_iff, List.filter_eq_nil_iff] at h0'
    have := h0' x hx
    simp only [decide_eq_true_eq] at this
    exact UInt8.not_le.1 this
  · exact latin1ToUtf8_ascii p

end Flare.L2.Uds
