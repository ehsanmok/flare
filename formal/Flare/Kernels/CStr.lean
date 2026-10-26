import Flare.Core

/-!
# NUL-terminated strings across the FFI boundary (net/cstr.mojo, issue #42)

flare hands C a `char*` for TLS paths, server names and certificate hosts,
`getaddrinfo` hosts, `inet_pton` addresses and `unlink` paths. C reads such
a pointer up to its first NUL, so the Mojo string and the C string can
differ in two ways:

* a string holding a NUL is read cut short (`localhost\0.evil` resolves as
  `localhost`, a certificate host or SNI names a different host);
* an empty string must arrive as `""` or as NULL, whichever the C
  parameter gives meaning to (NULL is "use the default" for a CA path, `""`
  is the default-certificate key), or be refused. Issue #42 was an empty CA
  bundle path that reached OpenSSL as a pointer into unrelated static data.

`c_str_verdict` decides, for each such string and the call site's `empty`
mode, whether it is passed, passed as NULL, or refused. `c_str_addr` applies
the verdict and, for a pass, hands C the string's buffer with one NUL
appended (`as_c_string_span`; an empty string is first replaced by a fresh
one). That last step is the stdlib's, so the difftest target `cstr.cross`
and `fuzz/fuzz_cstr.mojo` check it against real libc, including on the
string of issue #42.

Theorems:
* `cRead_append_nul`: C reads exactly `s` from `s ++ [0]` iff `s` holds no
  NUL.
* `verdict_ok`: every verdict meets `CrossOK`. A pass is read by C as
  exactly the Mojo string, NULL is sent only for an empty string where the
  parameter reads NULL as a default, and every string C would read
  faithfully (and whose emptiness the parameter accepts) is passed.
* `cRead_prefix`: C never reads past the buffer it is given.
-/
namespace Flare.Kernels.CStr

/-- [spec] What C reads from a `char*` buffer: the bytes before the first
NUL (C11 §7.1.1: a string is terminated by the first null character). -/
def cRead (b : Bytes) : Bytes := b.takeWhile (· != 0)

inductive Verdict where
  | pass | null | reject
  deriving DecidableEq, Repr

/-- [spec] A verdict for the Mojo string `s` is right when it passes exactly
the strings C reads back unchanged from `s` plus a terminator, and that are
nonempty unless the parameter gives `""` a meaning (`empty = 2`); and when it
sends NULL exactly for an empty string where the parameter reads NULL as a
default (`empty = 1`). Everything else (`empty = 0` or any other mode) is
refused. -/
def CrossOK (empty : Nat) (s : Bytes) (v : Verdict) : Prop :=
  (v = .pass ↔ cRead (s ++ [0]) = s ∧ (s ≠ [] ∨ empty = 2)) ∧
  (v = .null ↔ s = [] ∧ empty = 1)

/-- mirrors flare/net/cstr.mojo#c_str_verdict+CSTR_PASS+CSTR_NULL+CSTR_REJECT+EMPTY_REJECT+EMPTY_NULL+EMPTY_PASS sha=bde04a8a2fe0 at=6cf4db1f -/
def verdict (s : Bytes) (empty : Nat) : Nat :=
  if s.length = 0 then (if empty = 1 then 1 else if empty = 2 then 0 else 2)
  else if s.any (· == 0) then 2 else 0

/-- `CSTR_PASS = 0`, `CSTR_NULL = 1`, `CSTR_REJECT = 2`. -/
def ofCode : Nat → Verdict
  | 0 => .pass
  | 1 => .null
  | _ => .reject

theorem cRead_append_nul : ∀ s : Bytes, cRead (s ++ [0]) = s ↔ (0 : UInt8) ∉ s
  | [] => by simp [cRead]
  | x :: xs => by
    have ih := cRead_append_nul xs
    by_cases hx : x = 0
    · subst hx; simp [cRead]
    · have : (x != 0) = true := by simpa using hx
      simp only [cRead, List.cons_append, List.takeWhile_cons, this, if_true, List.cons.injEq,
        true_and, List.mem_cons, not_or] at ih ⊢
      exact ⟨fun h => ⟨fun e => hx e.symm, ih.mp h⟩, fun h => ih.mpr h.2⟩

theorem cRead_prefix (b : Bytes) : cRead b <+: b := List.takeWhile_prefix _

theorem any_nul_iff (s : Bytes) : s.any (· == 0) = true ↔ (0 : UInt8) ∈ s := by
  simp

/-- **The verdict is right** for every string and every `empty` mode. -/
theorem verdict_ok (s : Bytes) (empty : Nat) : CrossOK empty s (ofCode (verdict s empty)) := by
  unfold CrossOK verdict
  by_cases h0 : s = []
  · subst h0
    by_cases h1 : empty = 1
    · subst h1; simp [ofCode, cRead]
    · by_cases h2 : empty = 2
      · subst h2; simp [ofCode, cRead]
      · simp [ofCode, h1, h2]
  · have hl : s.length ≠ 0 := by simpa using h0
    have hr := cRead_append_nul s
    rw [if_neg hl]
    by_cases hn : (0 : UInt8) ∈ s
    · rw [if_pos ((any_nul_iff s).mpr hn)]
      simp only [ofCode, reduceCtorEq, false_iff, not_and, h0, false_and]
      exact ⟨fun e => absurd hn (hr.mp e), trivial⟩
    · rw [if_neg (fun e => hn ((any_nul_iff s).mp e))]
      simp only [ofCode, true_iff, reduceCtorEq, h0, false_and]
      exact ⟨⟨hr.mpr hn, .inl h0⟩, trivial⟩

/-- A passed string reaches C exactly. -/
theorem pass_exact (s : Bytes) (empty : Nat) (h : ofCode (verdict s empty) = .pass) :
    cRead (s ++ [0]) = s :=
  ((verdict_ok s empty).1.mp h).1

/-- Every NUL-free string is passed, an empty one where `""` has a meaning. -/
theorem pass_complete (s : Bytes) (empty : Nat) (hn : (0 : UInt8) ∉ s) (he : s ≠ [] ∨ empty = 2) :
    ofCode (verdict s empty) = .pass :=
  (verdict_ok s empty).1.mpr ⟨(cRead_append_nul s).mpr hn, he⟩

end Flare.Kernels.CStr
