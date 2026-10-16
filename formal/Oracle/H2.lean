import Oracle.Codec
import Flare.L3_Protocol.H2.Conn
import Flare.L3_Protocol.H2.HpackCodec
/-!
# Oracle target: the HTTP/2 connection state machine

`h2_conn.frames` drives a server-role `Conn` with `handleW`
(`Connection.handle_frame`, including the connection-window accounting) over a trace of
raw frames, as `formal/difftest/drivers/dt_h2.mojo` does with the real
`Connection()`.

Two adapters stand in for what the model leaves abstract:

* `frOf` builds the model's `Fr` from a frame's type, flags, stream id and
  payload, the way `handle_frame` reads them (pad octet, first 32-bit word,
  SETTINGS pairs, the fragment `_strip_pad_and_priority` leaves).
* The HPACK oracle `Dec` is the stateful decoder model (`Hpack.decode` on
  `Hpack.real`, Huffman allowed, budget `_header_block_ceiling`), with its
  dynamic table threaded across header blocks.

The trace stops at the first raise or GOAWAY: after a decode error the Mojo
decoder's table is out of step by design, and the server driver applies
nothing after a GOAWAY.
-/
namespace Oracle.H2

open Flare
open Flare.L3.H2.Conn
open Flare.L3.H2.Hpack (Table decode real)

def be32At (p : Bytes) (off : Nat) : Nat :=
  if p.length ≥ off + 4 then beTake 4 (p.drop off) else 0

def settingsOf : Bytes → List (Nat × Nat)
  | a :: b :: c :: d :: e :: f :: rest => (a.toNat * 256 + b.toNat, beTake 4 [c, d, e, f]) :: settingsOf rest
  | _ => []

/-- The payload left by `_strip_pad_and_priority`, or `[]` where it raises
(the model never reads the fragment then). -/
def stripped (padded prio : Bool) (p : Bytes) : Bytes :=
  let (st, en) : Nat × Nat :=
    if padded then (match p with | b0 :: _ => (1, p.length - b0.toNat) | [] => (0, 0)) else (0, p.length)
  let st := if prio then st + 5 else st
  if padded && (p.isEmpty || (p.headD 0).toNat > p.length - 1) then []
  else if st > en then [] else (p.take en).drop st

def frOf (ty flags sid : Nat) (p : Bytes) : Fr :=
  let padded := flags &&& 8 != 0
  let prio := flags &&& 0x20 != 0
  { ty := ty, sid := sid, f1 := flags &&& 1 != 0, eh := flags &&& 4 != 0, padded, prio,
    plen := p.length, b0 := (p.headD 0).toNat,
    word := be32At p (if ty = tHEADERS && padded then 1 else 0),
    settings := if ty = tSETTINGS then settingsOf p else [],
    frag := if ty = tHEADERS then stripped padded prio p
      else if ty = tDATA then stripped padded false p
      else p }

def decWith (t : Table) (budget : Nat) (blk : Bytes) : DecRes :=
  match decode real true t blk budget with
  | .ok (_, hs) => .ok hs
  | .error .budget => .budget
  | .error _ => .fail

def outTok : Out → String
  | .goaway l code => s!"G{l},{code}"
  | .rst k code => s!"R{k},{code}"
  | .wu k n => s!"W{k},{n}"
  | .settingsAck => "S"
  | .pingAck => "P"
  | .data k n => s!"D{k},{n}"
  | .drained k _ => s!"B{k}"

def stTok : St → String
  | .idle => "i" | .open_ => "o" | .hcl => "l" | .hcr => "r" | .closed => "c"

def isGoaway : Out → Bool
  | .goaway .. => true
  | _ => false

/-- Frames as `[type, flags, sid, len, payload...]` records. -/
def records : Bytes → List (Nat × Nat × Nat × Bytes)
  | ty :: fl :: sid :: n :: rest =>
    if rest.length < n.toNat then []
    else (ty.toNat, fl.toNat, sid.toNat, rest.take n.toNat) :: records (rest.drop n.toNat)
  | _ => []
termination_by b => b.length
decreasing_by simp only [List.length_cons, List.length_drop]; omega

/-- Run the records; the outputs of each frame, and the final connection. -/
def go (c : Conn) (t : Table) : List (Nat × Nat × Nat × Bytes) → List String → List String × Conn
  | [], acc => (acc.reverse, c)
  | (ty, fl, sid, p) :: rs, acc =>
    let f := frOf ty fl sid p
    match handleW (decWith t (ceiling c)) c f with
    | .error _ => (("X" :: acc).reverse, c)
    | .ok (c', o) =>
      let t' := if c'.decLog.length > c.decLog.length then
          match c'.decLog.getLast? with
          | some blk => (match decode real true t blk (ceiling c) with | .ok (t', _) => t' | .error _ => t)
          | none => t
        else t
      let tok := " ".intercalate (o.map outTok)
      if o.any isGoaway then ((tok :: acc).reverse, c')
      else go c' t' rs (tok :: acc)

/-- Output: each frame's queued frames (`|`-separated), then `;` and, for
every nonzero stream id in the trace (ascending), `sid=<state>/<sendW>/<recvW>`
(`-` if not in the table), then the connection windows. -/
def frames (b : Bytes) : String :=
  let rs := records b
  let (toks, c) := go {} Table.init rs []
  let sids := (rs.map (·.2.2.1)).filter (· ≠ 0) |>.eraseDups |>.mergeSort (· ≤ ·)
  let st := sids.map fun k => match get c k with
    | some s => s!"{k}={stTok s.state}/{s.sendW}/{s.recvW}"
    | none => s!"{k}=-"
  s!"OK:{"|".intercalate toks};{" ".intercalate st};{c.sendW}/{c.recvW}"

end Oracle.H2
