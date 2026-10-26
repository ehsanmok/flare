import Oracle.Codec
import Flare.L1_Encoding.HpackInt
import Flare.L1_Encoding.QuicVarint
import Flare.L1_Encoding.Utf8
import Flare.L1_Encoding.Huffman
import Flare.Kernels.BufLedger
import Flare.Kernels.CStr
import Flare.L3_Protocol.H1.Chunked
import Oracle.H2
import Oracle.Ws
/-!
# Oracle targets

Each target runs a Lean `impl` model (the transliteration of the Mojo code)
and, where the model has one, an executable `spec`, on the raw input bytes.
How a target reads its input bytes is fixed here and repeated verbatim in
its Mojo driver. The mapping from target to the anchored Mojo symbols, the
driver and the input generator lives in formal/difftest/targets.py.

To add a target: add an entry to `targets`, a branch to the family's Mojo
driver, and a row to targets.py. The runner refuses to run if the target
lists here and in targets.py disagree.
-/
namespace Oracle

open Flare
open Flare.L1

structure Target where
  name : String
  impl : Bytes → String
  spec : Option (Bytes → String) := none
  /-- Inputs longer than this skip the spec (it may be slow by design). -/
  specMax : Nat := 1 <<< 20

/-- byte 0 picks the prefix width `N = byte0 % 8 + 1`; the rest is the buffer. -/
def hpackIntDecode : Bytes → String
  | [] => "ERR"
  | n :: buf =>
    match HpackInt.decode buf 0 (n.toNat % 8 + 1) with
    | some (v, off) => s!"OK:{v},{off}"
    | none => "ERR"

/-- byte 0 picks `N`, byte 1 is the flag byte, bytes 2..5 are the value
(big-endian). -/
def hpackIntEncode : Bytes → String
  | n :: flags :: v => okHex (HpackInt.encode (beTake 4 v) (n.toNat % 8 + 1) flags)
  | _ => "ERR"

def quicDecode (b : Bytes) : String :=
  match QuicVarint.decode b with
  | some (v, n) => s!"OK:{v.toNat},{n}"
  | none => "ERR"

/-- bytes 0..7 are the value (big-endian). -/
def quicEncode (b : Bytes) : String :=
  match QuicVarint.encode (UInt64.ofNat (beTake 8 b)) with
  | some e => okHex e
  | none => "ERR"

def utf8Valid (b : Bytes) : String := if Utf8.isValidUtf8 b then "OK:1" else "OK:0"

def utf8Lossy (b : Bytes) : String := okHex (Utf8.lossy b)

/-- `max_body` for the chunked targets, picked by `byte0 % 8`. -/
def chunkMaxBody (sel : UInt8) : Nat :=
  [0, 1, 10, 255, 4096, 65536, 1 <<< 30, 1 <<< 40].getD (sel.toNat % 8) 0

/-- byte 0 picks `max_body` (`chunkMaxBody`), byte 1 the start cursor
(`byte1 % 8`, at most the buffer length); the rest is the buffer.
`scan_chunked_resume` from that cursor with `decoded_total = 0`:
`OK:<verdict>,<cursor>,<decoded_total>`, verdict -1 / -2 / end offset. -/
def chunkedResume : Bytes → String
  | sel :: cur :: buf =>
    let c := min (cur.toNat % 8) buf.length
    let (v, c', t) := Flare.L3.H1.Chunked.scanResume buf c 0 (chunkMaxBody sel)
    s!"OK:{v.toInt},{c'},{t}"
  | _ => "ERR"

section Ledger
open Flare.Kernels.BufLedger

/-- One trace byte as an event. Low two bits 0: the kernel fills a receive.
Otherwise the loop processes a completion: bit 2 = connection live, bits 3-4
pick the result (0, -105 = -ENOBUFS, 1, 8192), bit 5 = carries a buffer,
honoured only while a completion holds one. -/
def ledgerEvent (s : Ledger) (b : UInt8) : Event :=
  if b % 4 = 0 then .fill
  else
    let res : Int := match ((b >>> 3) &&& 3).toNat with
      | 0 => 0 | 1 => -105 | 2 => 1 | _ => 8192
    .complete ((b >>> 2) &&& 1 == 1) res ((b >>> 5) &&& 1 == 1 && 0 < s.inCq)

def actionTok : Action → String
  | .stage => "S" | .drop => "D" | .close => "C"

/-- Ledger, output so far, and whether every step met `RecvOk` and `Conserved`. -/
def ledgerStep (st : Ledger × String × Bool) (b : UInt8) : Ledger × String × Bool :=
  let (s, out, ok) := st
  match ledgerEvent s b with
  | .fill =>
    let (s', got) := s.onFill
    (s', out ++ (if got then "F" else "N"), ok && decide (Conserved s'))
  | .complete l r h =>
    let (s', d) := s.onComplete l r h
    (s', out ++ actionTok d.action ++ (if d.returnBuf then "r" else ""),
      ok && decide (RecvOk l r h d) && decide (Conserved s'))

/-- byte 0 picks the ring size `byte0 % 8 + 1`; each later byte is one event
(`ledgerEvent`). Output: one token per event (`F` fill, `N` -ENOBUFS,
`S`/`D`/`C` stage/drop/close, `r` when the buffer goes back), then
`;inRing,inCq,enobufs`. With `check`, any step that breaks the spec turns the
answer into `VIOLATION`. -/
def ledgerTrace (check : Bool) : Bytes → String
  | [] => "ERR"
  | n :: evs =>
    let (s, out, ok) := evs.foldl ledgerStep (Ledger.init (n.toNat % 8 + 1), "", true)
    if check && !ok then "VIOLATION"
    else s!"OK:{out};{s.inRing},{s.inCq},{s.enobufs}"

end Ledger

/-- byte 0: bits 0-1 pick what an empty value means, `% 3` (refused, NULL,
`""`); bits 2-3 only change how the Mojo driver builds the string. The rest
is the string. Output: what C reads (`PASS:<hex>`), `NULL`, or `REJECT`. The
spec answers from `cRead` alone: pass exactly what C reads back unchanged. -/
def cstrCross (spec : Bool) : Bytes → String
  | [] => "ERR"
  | f :: s =>
    let empty := (f.toNat % 4) % 3
    if spec then
      if Kernels.CStr.cRead (s ++ [0]) == s && (!s.isEmpty || empty == 2) then
        "PASS:" ++ toHex s
      else if s.isEmpty && empty == 1 then "NULL" else "REJECT"
    else
      match Kernels.CStr.ofCode (Kernels.CStr.verdict s empty) with
      | .pass => "PASS:" ++ toHex (Kernels.CStr.cRead (s ++ [0]))
      | .null => "NULL"
      | .reject => "REJECT"

def targets : List Target := [
  { name := "hpack_int.decode", impl := hpackIntDecode },
  { name := "hpack_int.encode", impl := hpackIntEncode },
  { name := "quic_varint.decode", impl := quicDecode },
  { name := "quic_varint.encode", impl := quicEncode },
  { name := "utf8.valid", impl := utf8Valid },
  { name := "utf8.lossy", impl := utf8Lossy },
  { name := "huffman.decode", impl := fun b => errOr (Huffman.decodeImpl b),
    spec := some fun b => errOr (Huffman.decodeFull b), specMax := 24 },
  { name := "huffman.decode_simd", impl := fun b => errOr (Huffman.decodeSimdImpl b),
    spec := some fun b => errOr (Huffman.decodeFull b), specMax := 24 },
  { name := "huffman.encode", impl := fun b => okHex (Huffman.encodeImpl b),
    spec := some fun b => okHex (Huffman.encode b), specMax := 24 },
  { name := "huffman.length", impl := fun b => s!"OK:{Huffman.encodedLengthImpl b}",
    spec := some fun b => s!"OK:{(Huffman.encode b).length}", specMax := 24 },
  { name := "bufring_ledger.trace", impl := ledgerTrace false, spec := some (ledgerTrace true) },
  { name := "cstr.cross", impl := cstrCross false, spec := some (cstrCross true) },
  { name := "h1_chunked.resume", impl := chunkedResume },
  { name := "h2_conn.frames", impl := Oracle.H2.frames },
  { name := "ws_protocol.trace", impl := Oracle.Ws.trace }
]

def find? (name : String) : Option Target := targets.find? (·.name == name)

def run (t : Target) (b : Bytes) : String :=
  let spec := match t.spec with
    | some f => if b.length ≤ t.specMax then f b else "-"
    | none => "-"
  t.impl b ++ "\t" ++ spec

end Oracle
