import Flare.Core
/-!
# Oracle wire format

One case per line, `target<TAB>hex-input`. The oracle answers with
`impl<TAB>spec`, where each side is `OK:<payload>`, `ERR`, or `-` when the
target has no executable spec (or the input is too long for it). The Mojo
drivers under formal/difftest/drivers/ print the same `OK:`/`ERR` strings,
so the runner compares lines as text.
-/
namespace Oracle

open Flare

def hexChar (d : Nat) : Char :=
  if d < 10 then Char.ofNat (48 + d) else Char.ofNat (87 + d)

def toHex (b : Bytes) : String :=
  String.ofList (b.flatMap fun x => [hexChar (x.toNat / 16), hexChar (x.toNat % 16)])

def nibble? (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - 48)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 87)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 55)
  else none

def ofHexList : List Char → Option Bytes
  | [] => some []
  | a :: b :: rest => do
    let hi ← nibble? a
    let lo ← nibble? b
    let tl ← ofHexList rest
    pure (UInt8.ofNat (hi * 16 + lo) :: tl)
  | [_] => none

def ofHex? (s : String) : Option Bytes := ofHexList s.toList

/-- Big-endian value of a byte string (at most the first `n` bytes). -/
def beTake (n : Nat) (b : Bytes) : Nat := (b.take n).foldl (fun a x => a * 256 + x.toNat) 0

def okHex (b : Bytes) : String := "OK:" ++ toHex b

def errOr {ε : Type} (r : Bytes × Option ε) : String :=
  match r with
  | (out, none) => okHex out
  | (_, some _) => "ERR"

end Oracle
