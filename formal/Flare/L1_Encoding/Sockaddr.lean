import Flare.Core
import Flare.L1_Encoding.Bits
/-!
# `sockaddr_in` / `sockaddr_in6` codecs

flare fills socket addresses byte by byte into a caller buffer and reads
port/family back out of kernel-filled buffers. The layouts differ:

* BSD/macOS: `[sin_len : u8][sin_family : u8][port : be16]...`
* Linux:     `[sin_family : le16 (host order)][port : be16]...`

The model writes into an arbitrary initial buffer `b0` (so we can state
exactly which bytes the caller must pre-zero) with `List.set`, mirroring the
`unsafe_write` sequence. Spec side: `kFamily`/`kPort`/`kLen`/`kByte` are the
kernel's view of the struct, written from the platform ABI headers
(`<netinet/in.h>`, `<sys/socket.h>`), independent of flare.
-/
namespace Flare.L1.Sockaddr

open Flare.Bytes (getD)

inductive Platform | macos | linux
  deriving DecidableEq, Repr

/-- `AF_INET6` per platform (flare/net/_libc.mojo:50). -/
def afInet6 : Platform → Nat
  | .macos => 30
  | .linux => 10
def afInet : Nat := 2

/-! ## Impl (transliteration) -/

/-- mirrors flare/net/_libc.mojo:209-247 @59bda50 -/
def fillIn (pl : Platform) (b0 : Bytes) (port : UInt16) (ip : Bytes) : Bytes :=
  let b := match pl with
    | .macos => (b0.set 0 16).set 1 2
    | .linux => (b0.set 0 2).set 1 0
  let b := (b.set 2 (port >>> 8).toUInt8).set 3 (port &&& 0xFF).toUInt8
  (((b.set 4 (getD ip 0)).set 5 (getD ip 1)).set 6 (getD ip 2)).set 7 (getD ip 3)

/-- mirrors flare/net/_libc.mojo:250-297 @59bda50 (the three `for` loops are
`List.set` folds over the same index ranges). -/
def fillIn6 (pl : Platform) (b0 : Bytes) (port : UInt16) (ip : Bytes) : Bytes :=
  let af6 := afInet6 pl
  let b := match pl with
    | .macos => (b0.set 0 28).set 1 (UInt8.ofNat af6)
    | .linux => (b0.set 0 (UInt8.ofNat (af6 % 256))).set 1 (UInt8.ofNat (af6 / 256 % 256))
  let b := (b.set 2 (port >>> 8).toUInt8).set 3 (port &&& 0xFF).toUInt8
  let b := (List.range' 4 4).foldl (fun b i => b.set i 0) b
  let b := (List.range 16).foldl (fun b i => b.set (8 + i) (getD ip i)) b
  (List.range' 24 4).foldl (fun b i => b.set i 0) b

/-- mirrors flare/net/_libc.mojo:300-321 @59bda50 -/
def readPort (b : Bytes) : UInt16 :=
  ((getD b 2).toUInt16 <<< 8) ||| (getD b 3).toUInt16

/-- mirrors flare/net/_libc.mojo:395-411 @59bda50 -/
def getFamily (pl : Platform) (b : Bytes) : Nat :=
  match pl with
  | .macos => (getD b 1).toNat
  | .linux => (getD b 0).toNat ||| ((getD b 1).toNat <<< 8)

/-! ## Spec: the kernel's view of the struct (platform ABI) -/

/-- `sa_family`: BSD byte 1; Linux little-endian u16 at 0. -/
def kFamily (pl : Platform) (b : Bytes) : Nat :=
  match pl with
  | .macos => (getD b 1).toNat
  | .linux => Bytes.leNat [getD b 0, getD b 1]
/-- `sin_port`/`sin6_port`: big-endian u16 at offset 2 on both platforms. -/
def kPort (b : Bytes) : Nat := Bytes.beNat [getD b 2, getD b 3]
/-- BSD `sin_len`. -/
def kLen (b : Bytes) : Nat := (getD b 0).toNat

/-! ## Theorems -/

theorem getD_set_ne (l : Bytes) (i j : Nat) (v : UInt8) (h : i ≠ j) :
    getD (l.set i v) j = getD l j := by
  simp [getD, List.getElem?_set, h]

theorem getD_set_eq (l : Bytes) (i : Nat) (v : UInt8) (h : i < l.length) :
    getD (l.set i v) i = v := by
  simp [getD, List.getElem?_set, h]

theorem getD_set_of_lt (l : Bytes) (i j : Nat) (v : UInt8) (h : j < l.length) :
    getD (l.set i v) j = if i = j then v else getD l j := by
  by_cases e : i = j
  · subst e; simp [getD_set_eq _ _ _ h]
  · simp [getD_set_ne _ _ _ _ e, e]

/-- Simp set for evaluating a chain of `List.set`s at a concrete index. -/
macro "set_simp" : tactic => `(tactic|
  simp (disch := ((try simp only [List.length_set]); omega))
    [fillIn, fillIn6, getD_set_ne, getD_set_eq, getD_set_of_lt, getFamily, kLen, afInet, afInet6])

theorem fillIn_length (pl : Platform) (b0 : Bytes) (p : UInt16) (ip : Bytes) :
    (fillIn pl b0 p ip).length = b0.length := by
  cases pl <;> simp [fillIn]

theorem fillIn6_length (pl : Platform) (b0 : Bytes) (p : UInt16) (ip : Bytes) :
    (fillIn6 pl b0 p ip).length = b0.length := by
  cases pl <;> simp [fillIn6, List.range', List.range, List.range.loop]

/-- The two port bytes reassemble to the port (word level). -/
theorem port_bytes (p : UInt16) :
    (((p >>> 8).toUInt8.toUInt16 <<< 8) ||| (p &&& 0xFF).toUInt8.toUInt16) = p := by
  bit_blast

/-- The two port bytes are the big-endian encoding of the port. -/
theorem port_beNat (p : UInt16) :
    Bytes.beNat [(p >>> 8).toUInt8, (p &&& 0xFF).toUInt8] = p.toNat := by
  have := p.toNat_lt
  simp [Bytes.beNat, UInt16.toNat_toUInt8, UInt16.toNat_shiftRight, UInt16.toNat_and]
  rw [Nat.and_two_pow_sub_one_eq_mod (n := 8)]
  omega

/-- flare's family reader agrees with the kernel's view on *every* buffer. -/
theorem getFamily_eq_kFamily (pl : Platform) (b : Bytes) :
    getFamily pl b = kFamily pl b := by
  cases pl
  · rfl
  · simp only [getFamily, kFamily, Bytes.leNat]
    have h0 := (getD b 0).toNat_lt
    rw [Nat.or_comm, ← Nat.shiftLeft_add_eq_or_of_lt h0, Nat.shiftLeft_eq]
    omega

section v4
variable (pl : Platform) (b0 : Bytes) (p : UInt16) (ip : Bytes) (hb : 16 ≤ b0.length)
include hb

theorem fillIn_family : getFamily pl (fillIn pl b0 p ip) = afInet := by
  cases pl <;> set_simp

theorem fillIn_kFamily : kFamily pl (fillIn pl b0 p ip) = afInet := by
  rw [← getFamily_eq_kFamily]; exact fillIn_family pl b0 p ip hb

theorem fillIn_len_macos : kLen (fillIn .macos b0 p ip) = 16 := by
  set_simp

/-- `read_port ∘ fill = id`. -/
theorem readPort_fillIn : readPort (fillIn pl b0 p ip) = p := by
  have : getD (fillIn pl b0 p ip) 2 = (p >>> 8).toUInt8 ∧
      getD (fillIn pl b0 p ip) 3 = (p &&& 0xFF).toUInt8 := by
    cases pl <;> set_simp
  simp only [readPort, this.1, this.2]; exact port_bytes p

theorem kPort_fillIn : kPort (fillIn pl b0 p ip) = p.toNat := by
  have : getD (fillIn pl b0 p ip) 2 = (p >>> 8).toUInt8 ∧
      getD (fillIn pl b0 p ip) 3 = (p &&& 0xFF).toUInt8 := by
    cases pl <;> set_simp
  simp only [kPort, this.1, this.2]; exact port_beNat p

/-- `sin_addr` (bytes 4..7) is the 4 address bytes from `inet_pton`. -/
theorem addr_fillIn : ∀ i, i < 4 → getD (fillIn pl b0 p ip) (4 + i) = getD ip i := by
  simp only [Flare.L1.forall_lt_succ', Flare.L1.forall_lt_zero', true_and]
  cases pl <;> set_simp

/-- `sin_zero` (bytes 8..15) is left untouched: the caller must pre-zero it. -/
theorem zero_fillIn : ∀ i, 8 ≤ i → getD (fillIn pl b0 p ip) i = getD b0 i := by
  intro i hi
  cases pl <;> set_simp
end v4

section v6
variable (pl : Platform) (b0 : Bytes) (p : UInt16) (ip : Bytes) (hb : 28 ≤ b0.length)
include hb


macro "set_simp6" : tactic => `(tactic|
  simp (disch := ((try simp only [List.length_set]); omega))
    [fillIn6, List.range', List.range_succ, List.foldl_append, List.range_zero,
     getD_set_ne, getD_set_eq, getD_set_of_lt, getFamily, kLen, afInet6])

theorem fillIn6_family : getFamily pl (fillIn6 pl b0 p ip) = afInet6 pl := by
  cases pl <;> set_simp6

theorem fillIn6_kFamily : kFamily pl (fillIn6 pl b0 p ip) = afInet6 pl := by
  rw [← getFamily_eq_kFamily]; exact fillIn6_family pl b0 p ip hb

theorem fillIn6_len_macos : kLen (fillIn6 .macos b0 p ip) = 28 := by
  set_simp6

theorem readPort_fillIn6 : readPort (fillIn6 pl b0 p ip) = p := by
  have : getD (fillIn6 pl b0 p ip) 2 = (p >>> 8).toUInt8 ∧
      getD (fillIn6 pl b0 p ip) 3 = (p &&& 0xFF).toUInt8 := by
    cases pl <;> set_simp6
  simp only [readPort, this.1, this.2]; exact port_bytes p

theorem kPort_fillIn6 : kPort (fillIn6 pl b0 p ip) = p.toNat := by
  have : getD (fillIn6 pl b0 p ip) 2 = (p >>> 8).toUInt8 ∧
      getD (fillIn6 pl b0 p ip) 3 = (p &&& 0xFF).toUInt8 := by
    cases pl <;> set_simp6
  simp only [kPort, this.1, this.2]; exact port_beNat p

/-- `sin6_flowinfo` (4..7) and `sin6_scope_id` (24..27) are zeroed. -/
theorem flow_scope_fillIn6 : ∀ i, i < 4 →
    getD (fillIn6 pl b0 p ip) (4 + i) = 0 ∧ getD (fillIn6 pl b0 p ip) (24 + i) = 0 := by
  simp only [Flare.L1.forall_lt_succ', Flare.L1.forall_lt_zero', true_and]
  cases pl <;> set_simp6

/-- `sin6_addr` (8..23) holds the 16 address bytes. -/
theorem addr_fillIn6 : ∀ i, i < 16 → getD (fillIn6 pl b0 p ip) (8 + i) = getD ip i := by
  simp only [Flare.L1.forall_lt_succ', Flare.L1.forall_lt_zero', true_and]
  cases pl <;> set_simp6

/-- Nothing past byte 27 is written. -/
theorem tail_fillIn6 : ∀ i, 28 ≤ i → getD (fillIn6 pl b0 p ip) i = getD b0 i := by
  intro i hi
  cases pl <;> set_simp6

end v6

end Flare.L1.Sockaddr
