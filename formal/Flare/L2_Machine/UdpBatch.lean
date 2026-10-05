import Flare.Core

/-!
# Batched UDP: wire layouts, the GSO control message, receiver buffers

Model of `flare/udp/batch.mojo` (Linux only: `recvmmsg`, `sendmmsg`,
`sendmsg` + `UDP_SEGMENT`).

* **Layouts** (batch.mojo:66-92). A C struct layout calculator (natural
  alignment, LP64: pointers and `size_t` 8 bytes, `int`/`socklen_t`/
  `unsigned` 4) applied to `iovec`, `msghdr`, `mmsghdr` and `cmsghdr`
  reproduces every comptime offset and size flare hard-codes
  (`layout_constants`). `CMSG_LEN(2) = 18`, `CMSG_SPACE(2) = 24`,
  `CMSG_DATA` at 16 (`cmsg_constants`).
* **GSO control message** (batch.mojo:411-426). flare sets
  `msg_controllen = CMSG_LEN(2) = 18`, not `CMSG_SPACE(2) = 24`. A model of
  the kernel's `for_each_cmsghdr` / `CMSG_OK` walk
  (include/linux/socket.h `__CMSG_FIRSTHDR`, `__cmsg_nxthdr`, `CMSG_OK`;
  net/ipv4/udp.c `__udp_cmsg_send`) shows both lengths parse to the same
  single header `(SOL_UDP, UDP_SEGMENT)` and the same segment size
  (`gso_walk_18`, `gso_walk_24`, `gso_seg`): not a bug on Linux.
* **Receiver buffers** (batch.mojo:176-218). Slot `i` of the data region is
  `[i*max_payload, (i+1)*max_payload)`; with exact arithmetic every slot
  lies inside the `capacity*max_payload` allocation and slots are disjoint
  (`slot_in_bounds`, `slots_disjoint`). The size is a 64-bit `Int` product.
  Before the fix (NET-11) only `> 0` was asserted, so the product could wrap
  to a tiny allocation while each iovec still announced `max_payload` bytes
  (`acceptsOld`, `allocSize_wraps`); the shipped constructor refuses
  arguments whose product overflows (`accepts`), which makes the size exact
  (`allocSize_fixed`) and covering (`covers_fixed`).
-/
namespace Flare.L2.UdpBatch

/-! ## C struct layout -/

def alignUp (n a : Nat) : Nat := (n + a - 1) / a * a

/-- offsets of fields `(size, align)` laid out in order -/
def offsets : List (Nat × Nat) → Nat → List Nat
  | [], _ => []
  | (sz, al) :: fs, cur => alignUp cur al :: offsets fs (alignUp cur al + sz)

def endOf : List (Nat × Nat) → Nat → Nat
  | [], cur => cur
  | (sz, al) :: fs, cur => endOf fs (alignUp cur al + sz)

def maxAlign (fs : List (Nat × Nat)) : Nat := fs.foldl (fun m f => max m f.2) 1

def sizeOf (fs : List (Nat × Nat)) : Nat := alignUp (endOf fs 0) (maxAlign fs)

/-- `struct iovec { void *base; size_t len; }` -/
def iovecF : List (Nat × Nat) := [(8, 8), (8, 8)]
/-- `struct msghdr` (glibc LP64: `socklen_t namelen`, `size_t iovlen`,
`size_t controllen`, `int flags`) -/
def msghdrF : List (Nat × Nat) := [(8, 8), (4, 4), (8, 8), (8, 8), (8, 8), (8, 8), (4, 4)]
/-- `struct mmsghdr { struct msghdr hdr; unsigned int len; }` -/
def mmsghdrF : List (Nat × Nat) := [(sizeOf msghdrF, 8), (4, 4)]
/-- `struct cmsghdr { size_t len; int level; int type; }` -/
def cmsghdrF : List (Nat × Nat) := [(8, 8), (4, 4), (4, 4)]

/-- flare's comptime constants.
mirrors flare/udp/batch.mojo:67-92 @59bda50 -/
def IOVEC := 16
def MSGHDR := 56
def MMSGHDR := 64
def NAME := 28
def OFF_MSG : List Nat := [0, 8, 16, 24, 32, 40, 48]
def OFF_MSGLEN := 56
def CMSG_HDR := 16
def CMSG_DATA_OFF := 16
def CMSG_LEN_GSO := 18
def CMSG_SPACE_GSO := 24

/-- **Layouts**: every hard-coded size and offset is the C layout. -/
theorem layout_constants :
    sizeOf iovecF = IOVEC ∧ sizeOf msghdrF = MSGHDR ∧ offsets msghdrF 0 = OFF_MSG ∧
    sizeOf mmsghdrF = MMSGHDR ∧ offsets mmsghdrF 0 = [0, OFF_MSGLEN] ∧
    sizeOf cmsghdrF = CMSG_HDR := by decide

/-- `CMSG_ALIGN` (align to `sizeof(size_t)`) -/
def cmsgAlign (n : Nat) : Nat := alignUp n 8
def cmsgLen (n : Nat) : Nat := cmsgAlign (sizeOf cmsghdrF) + n
def cmsgSpace (n : Nat) : Nat := cmsgAlign (sizeOf cmsghdrF) + cmsgAlign n

/-- **CMSG macros**: `CMSG_LEN(2) = 18`, `CMSG_SPACE(2) = 24`, data at 16,
and the 28-byte name slot holds a `sockaddr_in6` (28) or `sockaddr_in` (16). -/
theorem cmsg_constants :
    cmsgLen 2 = CMSG_LEN_GSO ∧ cmsgSpace 2 = CMSG_SPACE_GSO ∧
    cmsgAlign (sizeOf cmsghdrF) = CMSG_DATA_OFF ∧ 28 ≤ NAME ∧ 16 ≤ NAME := by decide

/-! ## The GSO control buffer and the kernel's cmsg walk -/

def rd (buf : Bytes) (off k : Nat) : Nat := Flare.Bytes.leNat ((buf.drop off).take k)

/-- the 24 zeroed bytes after `_poke_u64(ctrl, 0, 18)`,
`_poke_u32(ctrl, 8, 17)`, `_poke_u32(ctrl, 12, 103)`,
`_poke_u16(ctrl, 16, seg)`.
mirrors flare/udp/batch.mojo:412-420 -/
def gsoCtrl (seg : Nat) : Bytes :=
  [18, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 103, 0, 0, 0,
   UInt8.ofNat (seg % 256), UInt8.ofNat (seg / 256 % 256), 0, 0, 0, 0, 0, 0]

/-- Linux `for_each_cmsghdr` with the `CMSG_OK` check of `__udp_cmsg_send`:
`none` = `-EINVAL`, otherwise the headers seen as
`(offset, cmsg_len, level, type)`. `fuel` bounds the walk (each step
advances at least 16 bytes). -/
def walk (buf : Bytes) (ctl : Nat) : Nat → Nat → Option (List (Nat × Nat × Nat × Nat))
  | 0, _ => some []
  | fuel + 1, off =>
    let len := rd buf off 8
    if 16 ≤ len ∧ len ≤ ctl - off then
      let next := off + cmsgAlign len
      let rest := if next + 16 > ctl then some [] else walk buf ctl fuel next
      rest.map ((off, len, rd buf (off + 8) 4, rd buf (off + 12) 4) :: ·)
    else none

/-- `CMSG_FIRSTHDR`: no header if `msg_controllen < sizeof(cmsghdr)` -/
def cmsgs (buf : Bytes) (ctl : Nat) : Option (List (Nat × Nat × Nat × Nat)) :=
  if ctl < 16 then some [] else walk buf ctl ctl 0

/-- **flare's `msg_controllen = 18`**: the kernel sees exactly one header,
`SOL_UDP (17) / UDP_SEGMENT (103)` with `cmsg_len = CMSG_LEN(2)` (the length
`__udp_cmsg_send` requires). -/
theorem gso_walk_18 (seg : Nat) : cmsgs (gsoCtrl seg) CMSG_LEN_GSO = some [(0, 18, 17, 103)] := by
  simp [cmsgs, walk, rd, gsoCtrl, cmsgAlign, alignUp, Flare.Bytes.leNat, CMSG_LEN_GSO]

/-- the textbook `CMSG_SPACE(2) = 24` gives the same walk -/
theorem gso_walk_24 (seg : Nat) : cmsgs (gsoCtrl seg) CMSG_SPACE_GSO = some [(0, 18, 17, 103)] := by
  simp [cmsgs, walk, rd, gsoCtrl, cmsgAlign, alignUp, Flare.Bytes.leNat, CMSG_SPACE_GSO]

/-- the `__u16` at `CMSG_DATA` is the requested segment size -/
theorem gso_seg (seg : Nat) (h : seg < 65536) : rd (gsoCtrl seg) 16 2 = seg := by
  simp only [rd, gsoCtrl, List.drop, List.take, Flare.Bytes.leNat, UInt8.toNat_ofNat']
  omega

/-! ## Receiver buffers -/

/-- Exact arithmetic: slot `i < capacity` lies inside the data region. -/
theorem slot_in_bounds (cap mp i : Nat) (hi : i < cap) : i * mp + mp ≤ cap * mp := by
  have : (i + 1) * mp ≤ cap * mp := Nat.mul_le_mul_right _ hi
  rw [Nat.add_mul, Nat.one_mul] at this; exact this

/-- Exact arithmetic: distinct slots do not overlap. -/
theorem slots_disjoint (mp i j : Nat) (hij : i < j) : i * mp + mp ≤ j * mp := by
  have : (i + 1) * mp ≤ j * mp := Nat.mul_le_mul_right _ hij
  rw [Nat.add_mul, Nat.one_mul] at this; exact this

/-- the byte count passed to `_alloc_zeroed` for the data region: the Mojo
`Int` (64-bit) product `capacity * max_payload`.
mirrors flare/udp/batch.mojo:207 (fixed, NET-11) -/
def allocSize (cap mp : Int) : Int := (Int64.ofInt cap * Int64.ofInt mp).toInt

/-- what flare checked before allocating, before the fix
(flare/udp/batch.mojo:185-195 @59bda50) -/
def acceptsOld (cap mp : Int) : Prop := 0 < cap ∧ 0 < mp

/-- Spec: the region covers every slot `[i*mp, (i+1)*mp)`, `i < cap`. -/
def Covers (cap mp : Int) : Prop := ∀ i : Int, 0 ≤ i → i < cap → (i + 1) * mp ≤ allocSize cap mp

/-- **Overflow** (pre-fix check): `capacity = 16`, `max_payload = 2^60`
passed `acceptsOld`, but the product wraps to 0. -/
theorem allocSize_wraps : acceptsOld 16 (2 ^ 60) ∧ allocSize 16 (2 ^ 60) = 0 := by
  refine ⟨⟨by decide, by decide⟩, by decide⟩

def I64MAX : Int := 2 ^ 63 - 1

/-- the shipped constructor checks: both arguments positive,
`capacity <= Int.MAX // max_payload` and `capacity <= Int.MAX // 64`
(`_MMSGHDR`, the largest per-slot array).
mirrors flare/udp/batch.mojo:189-200 (fixed, NET-11) -/
def accepts (cap mp : Int) : Prop :=
  0 < cap ∧ 0 < mp ∧ cap ≤ I64MAX / mp ∧ cap ≤ I64MAX / 64

/-- the wrapping argument is refused by the shipped checks -/
theorem accepts_refuses_wrap : ¬ accepts 16 (2 ^ 60) := by
  unfold accepts I64MAX
  decide

theorem toInt_ofInt_small (n : Int) (h0 : 0 ≤ n) (h1 : n ≤ I64MAX) : (Int64.ofInt n).toInt = n := by
  rw [Int64.toInt_ofInt]
  apply Int.bmod_eq_of_le
  · have : (Int64.size : Int) = 2 ^ 64 := rfl
    rw [this]; omega
  · have : (Int64.size : Int) = 2 ^ 64 := rfl
    rw [this]; unfold I64MAX at h1; omega

/-- **Fix meets spec**: with the extra check the product is exact. -/
theorem allocSize_fixed (cap mp : Int) (h : accepts cap mp) : allocSize cap mp = cap * mp := by
  obtain ⟨hc, hm, hle, _⟩ := h
  have hprod : cap * mp ≤ I64MAX := by
    have := Int.mul_le_mul_of_nonneg_right hle (Int.le_of_lt hm)
    exact Int.le_trans this (Int.ediv_mul_le _ (Int.ne_of_gt hm))
  have hmp : mp ≤ I64MAX := by
    have : 1 * mp ≤ cap * mp := Int.mul_le_mul_of_nonneg_right (by omega) (Int.le_of_lt hm)
    omega
  have hcap : cap ≤ I64MAX := by
    have : cap * 1 ≤ cap * mp := Int.mul_le_mul_of_nonneg_left (by omega) (Int.le_of_lt hc)
    omega
  unfold allocSize
  rw [Int64.toInt_mul, toInt_ofInt_small cap (by omega) hcap, toInt_ofInt_small mp (by omega) hmp]
  apply Int.bmod_eq_of_le
  · have : 0 ≤ cap * mp := Int.mul_nonneg (by omega) (by omega)
    omega
  · unfold I64MAX at hprod; omega

theorem covers_fixed (cap mp : Int) (h : accepts cap mp) : Covers cap mp := by
  intro i hi0 hi
  rw [allocSize_fixed cap mp h]
  exact Int.mul_le_mul_of_nonneg_right (by omega) (Int.le_of_lt h.2.1)

end Flare.L2.UdpBatch
