import Flare.L2_Machine.Uds

/-!
# NET-06: `queried_local_path()` garbles non-ASCII Unix socket paths

Status: resolved. `read_path_from_sockaddr_un` now collects the bytes and
builds the `String` from them as UTF-8; `Flare.L2.Uds.readPath` mirrors the
shipped code and the counterexample below is about the pre-fix
`readPathOld`.

Pre-fix code: flare/uds/_libc.mojo:55-134 @59bda50.

Spec: decoding the `sockaddr_un` written by `fill_sockaddr_un(path)` gives
back `path` (the round trip `read_path_from_sockaddr_un ∘
fill_sockaddr_un = id` that `queried_local_path()` relies on).

What goes wrong: `fill_sockaddr_un` copies the path's UTF-8 bytes, but
`read_path_from_sockaddr_un` appends `chr(Int(b))` per byte, i.e. decodes
the bytes as Latin-1 and re-encodes each byte `≥ 0x80` as two UTF-8 bytes.
The round trip holds exactly for ASCII paths.

Repro: formal/repro/NET-06_uds_queried_path_latin1.mojo.
-/
namespace Flare.Bugs.NET_06
open Flare.L2.Uds

/-- "é" in UTF-8 -/
def eAcute : Flare.Bytes := [0xC3, 0xA9]

/-- **Counterexample**: binding "é" reads back "Ã©" (`C3 83 C2 A9`). -/
theorem decode_encode_not_id :
    fill true 1 0 eAcute = some ([1, 0, 0xC3, 0xA9, 0], 5) ∧
      readPathOld true [1, 0, 0xC3, 0xA9, 0] 5 = [0xC3, 0x83, 0xC2, 0xA9] ∧
      readPathOld true [1, 0, 0xC3, 0xA9, 0] 5 ≠ eAcute := by
  native_decide

/-- The pre-fix round trip holds iff the path is ASCII. -/
theorem roundtrip_iff_ascii (linux : Bool) (h0 h1 : UInt8) (p b rest : Flare.Bytes) (n usedLen : Nat)
    (h : fill linux h0 h1 p = some (b, n)) (hu : n ≤ usedLen) :
    readPathOld linux (b ++ rest) usedLen = p ↔ ∀ x ∈ p, x < 0x80 :=
  readPathOld_fill_iff_ascii linux h0 h1 p b rest n usedLen h hu

/-- **Fix meets spec**: the shipped decoder (collected bytes as UTF-8) returns the
bound path for every path `fill` accepts, whatever follows the used
length in the buffer. -/
theorem decodeFixed_encode (linux : Bool) (h0 h1 : UInt8) (p b rest : Flare.Bytes) (n usedLen : Nat)
    (h : fill linux h0 h1 p = some (b, n)) (hu : n ≤ usedLen) :
    readPath linux (b ++ rest) usedLen = p :=
  readPath_fill linux h0 h1 p b rest n usedLen h hu

end Flare.Bugs.NET_06
