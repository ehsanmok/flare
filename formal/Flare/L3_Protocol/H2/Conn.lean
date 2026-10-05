import Flare.L3_Protocol.H2.Validate

/-!
# HTTP/2 connection state machine (impl)

An executable transliteration of `Connection.handle_frame`
(`flare/http2/state.mojo:1005-1547`) and the code it calls:
`_commit_header_block` (781-1003), `_ensure_stream` / pruning (538-566),
`_rst_stream_frame` (587-605), `_conn_error` (676-688),
`_strip_pad_and_priority` (690-716), `_declared_content_length` (748-765),
`_active_stream_count` (767-779), `release_request_credit` (619-633),
plus the server driver's frame loop (`flare/http2/server.mojo:398-438`)
and the local actions that change stream or window state
(`emit_response` 603-681, `queue_stream_data` 870-921, client
`send_request` 788-798 and `take_response` 1021).

## Abstractions

* A frame (`Fr`) carries its type, flag bits, stream id, payload length
  and the payload fields the code reads: the pad-length octet, the first
  32-bit word (WINDOW_UPDATE increment, PRIORITY / HEADERS dependency,
  RST_STREAM code), the SETTINGS pairs and the header-block fragment.
  The model assumes the usual consistency (`settings.length = plen / 6`,
  `frag` is the stripped fragment); the frame codec itself is `Frame.lean`.
* HPACK decoding of a completed header block is an oracle `Dec` supplied
  with each step, so every theorem holds for whatever the stateful
  decoder (`Hpack.lean`) returns. Decoded headers are the `Entry` octets.
* Stream bodies are represented by their length (`dataLen`) plus a ghost
  copy of the accepted octets (`buf`, drained by the client's streaming
  reader), header lists by their RFC 9113 §6.5.2 size. The client's
  streaming mode (`defer_body_credit`, `drain_body`) is modelled.
* In client role inbound frames go through the client driver
  (`client.mojo:400-512`), in server role through the server driver
  (`server.mojo:398-438`).
* Mojo `Int` is modelled as `Int`/`Nat`; `WinInv` (in `ConnSpec`) bounds
  every send window, so the 64-bit values never wrap. The one place the
  Mojo code does wrap, `_declared_content_length`, uses `Int64`.
* The header-list cap check in `_commit_header_block` (826-838) leaves the
  RFC size of the whole list in `header_list_bytes`, where Mojo leaves the
  prefix sum at which it stopped; the stream is closed either way.

`Fix` selects the fix for each issue. `Fix.none` is the code as it was
before any fix (flare @59bda50), kept so every counterexample stays
checkable; every fix is a guarded extra branch, so `step Fix.none` is
exactly that transliteration. `Fix.shipped` is the set of fixes that have
landed in `flare/http2`: it grows by one flag per resolved finding, and
`step Fix.shipped` mirrors the Mojo as it stands.
-/
namespace Flare.L3.H2.Conn
open Flare.L3.H2.Names
open Flare.L3.H2.Validate (Header validate validateOld isConnSpecific)

/-! ## Constants (`state.mojo:57-173`, `frame.mojo`) -/

def MAX_WINDOW : Int := 2147483647
def CONT_CAP : Nat := 64
def RST_FLOOD : Nat := 500
def RESET_REMEMBERED : Nat := 1024
def MAX_BUFFERED : Nat := 64 * 1024 * 1024
def HARD_HEADER_CAP : Nat := 1048576
def I64MAX : Nat := 9223372036854775807

def eNO : Nat := 0
def ePROTOCOL : Nat := 1
def eFLOW : Nat := 3
def eSTREAM_CLOSED : Nat := 5
def eFRAME_SIZE : Nat := 6
def eREFUSED : Nat := 7
def eCOMPRESSION : Nat := 9
def eCALM : Nat := 11

def tDATA : Nat := 0
def tHEADERS : Nat := 1
def tPRIORITY : Nat := 2
def tRST : Nat := 3
def tSETTINGS : Nat := 4
def tPUSH : Nat := 5
def tPING : Nat := 6
def tGOAWAY : Nat := 7
def tWU : Nat := 8
def tCONT : Nat := 9

/-! ## Frames, streams, connection -/

/-- An inbound frame. `f1` is flag bit 0x1 (END_STREAM, or ACK on
SETTINGS / PING), `eh` 0x4 END_HEADERS, `padded` 0x8, `prio` 0x20. -/
structure Fr where
  ty : Nat
  sid : Nat := 0
  f1 : Bool := false
  eh : Bool := false
  padded : Bool := false
  prio : Bool := false
  plen : Nat := 0
  b0 : Nat := 0
  word : Nat := 0
  settings : List (Nat × Nat) := []
  frag : Bytes := []
  deriving Repr

/-- `StreamState` (`state.mojo:199-228`); RESERVED is absent (push off). -/
inductive St | idle | open_ | hcl | hcr | closed
  deriving DecidableEq, Repr

/-- mirrors flare/http2/state.mojo:234-298 @59bda50 -/
structure Stream where
  state : St := .idle
  sendW : Int := 65535
  recvW : Int := 65535
  headersComplete : Bool := false
  dataComplete : Bool := false
  dataLen : Nat := 0
  received : Nat := 0
  contentLength : Int := -1
  headerListBytes : Nat := 0
  bodyAllowed : Bool := true
  /-- `defer_body_credit` (client streaming reader, `client.mojo:1189-1197`) -/
  deferCredit : Bool := false
  /-- `pending_body_credit`: body octets not yet credited back -/
  pendingCredit : Nat := 0
  /-- `data`: the accepted body octets not yet drained (content ghost:
  the model takes a DATA frame's stripped body to be `frag`) -/
  buf : Bytes := []
  deriving DecidableEq, Repr

/-- mirrors flare/http2/state.mojo:304-466 @59bda50
(`maxLocalSid` is `max_local_stream_id`, added by the H2-03 fix;
`peerSettingsSeen` and `decLog` are ghosts: the code before the fixes
never reads them, and the H2-08 fix reads the first). -/
structure Conn where
  isClient : Bool := false
  streams : List (Nat × Stream) := []
  maxConcurrent : Nat := 100
  maxBody : Nat := 10485760
  initW : Int := 65535
  peerInitW : Int := 65535
  maxHeaderList : Nat := 0
  sendW : Int := 65535
  recvW : Int := 65535
  goawayReceived : Bool := false
  settingsAcked : Bool := false
  enableConnect : Bool := false
  peerMaxFrame : Nat := 16384
  peerHeaderTable : Nat := 4096
  peerConnect : Bool := false
  rstCount : Nat := 0
  goawaySent : Bool := false
  lastPeer : Nat := 0
  localMaxFrame : Nat := 16384
  continuing : Nat := 0
  block : Bytes := []
  blockES : Bool := false
  blockRefuse : Nat := 0
  blockConts : Nat := 0
  resetByUs : List Nat := []
  buffered : Nat := 0
  withheld : Nat := 0
  peerSettingsSeen : Bool := false
  maxLocalSid : Nat := 0
  /-- Ghost: every complete header block handed to the HPACK decoder, in
  order (`_commit_header_block`, state.mojo:781-800). -/
  decLog : List Bytes := []
  deriving Repr

/-- Outbound frames the step queues. -/
inductive Out
  | goaway (last code : Nat)
  | rst (sid code : Nat)
  | wu (sid credit : Nat)
  | settingsAck
  | pingAck
  | data (sid n : Nat)
  /-- body octets handed to the application by `drain_body` -/
  | drained (sid : Nat) (b : Bytes)
  deriving DecidableEq, Repr

/-- HPACK decode outcome (`hpack.mojo:356-441`): fields, budget error, or
any other decode error. -/
inductive DecRes
  | ok (hs : List Header)
  | budget
  | fail

abbrev Dec := Bytes → DecRes

/-- Minimal fixes, one flag per issue. -/
structure Fix where
  h2_01 : Bool := false
  h2_02 : Bool := false
  h2_03 : Bool := false
  h2_04 : Bool := false
  h2_05 : Bool := false
  h2_06 : Bool := false
  h2_07 : Bool := false
  h2_08 : Bool := false
  h2_09 : Bool := false
  h2_10 : Bool := false
  h2_11 : Bool := false
  h2_12 : Bool := false
  h2_13 : Bool := false
  h2_14 : Bool := false
  h2_15 : Bool := false
  h2_16 : Bool := false
  h2_17 : Bool := false
  h2_18 : Bool := false
  h2_19 : Bool := false
  h2_20 : Bool := false

/-- The code before any fix (flare @59bda50). -/
def Fix.none : Fix := {}

/-- The fixes that have landed in `flare/http2` (one flag per resolved
finding): H2-01, H2-02, H2-03, H2-04, H2-05, H2-06, H2-07, H2-08, H2-09, H2-10, H2-11, H2-12, H2-13, H2-14, H2-15, H2-17. -/
def Fix.shipped : Fix :=
  { h2_01 := true, h2_02 := true, h2_03 := true, h2_04 := true, h2_05 := true, h2_06 := true,
    h2_07 := true, h2_08 := true, h2_09 := true, h2_10 := true, h2_11 := true, h2_12 := true,
    h2_13 := true, h2_14 := true, h2_15 := true, h2_17 := true }

def Fix.all : Fix :=
  { h2_01 := true, h2_02 := true, h2_03 := true, h2_04 := true, h2_05 := true,
    h2_06 := true, h2_07 := true, h2_08 := true, h2_09 := true, h2_10 := true, h2_11 := true, h2_12 := true,
    h2_13 := true, h2_14 := true, h2_15 := true, h2_16 := true, h2_17 := true, h2_18 := true, h2_19 := true, h2_20 := true }

/-- A step's result: `.error` is a Mojo `raise`. -/
abbrev Res := Except String (Conn × List Out)

/-! ## Stream table (`StreamSlab`, `stream_slab.mojo`) -/

def get (c : Conn) (k : Nat) : Option Stream := (c.streams.find? (·.1 == k)).map (·.2)

def mem (c : Conn) (k : Nat) : Bool := (get c k).isSome

def putL : List (Nat × Stream) → Nat → Stream → List (Nat × Stream)
  | [], k, s => [(k, s)]
  | p :: t, k, s => if p.1 = k then (k, s) :: t else p :: putL t k s

def put (c : Conn) (k : Nat) (s : Stream) : Conn := { c with streams := putL c.streams k s }

def erase (c : Conn) (k : Nat) : Conn := { c with streams := c.streams.filter (·.1 != k) }

/-- mirrors flare/http2/state.mojo:556-558 @59bda50 -/
def pruneThreshold (c : Conn) : Nat :=
  if c.maxConcurrent * 2 > 256 then c.maxConcurrent * 2 else 256

/-- mirrors flare/http2/state.mojo:538-554 @59bda50 -/
def ensure (c : Conn) (k : Nat) : Conn × Stream :=
  match get c k with
  | some s => (c, s)
  | none =>
    let c := if c.streams.length ≥ pruneThreshold c then
      { c with streams := c.streams.filter (fun p => p.2.state != .closed) } else c
    (c, { state := .idle, sendW := c.peerInitW, recvW := c.initW })

/-- mirrors flare/http2/state.mojo:767-779 @59bda50 -/
def isActive (s : Stream) : Bool := s.state == .open_ || s.state == .hcl || s.state == .hcr

def activeCount (c : Conn) : Nat := c.streams.countP (fun p => isActive p.2)

/-- mirrors flare/http2/state.mojo:571-585 @59bda50 -/
def headerListCap (c : Conn) : Nat := if c.maxHeaderList > 0 then c.maxHeaderList else HARD_HEADER_CAP

def ceiling (c : Conn) : Nat := if headerListCap c * 4 > 262144 then headerListCap c * 4 else 262144

/-! ## Reply frames -/

/-- The bookkeeping half of `_rst_stream_frame`: remember `k` in the
bounded `reset_by_us` list (the frame itself is `Out.rst k code`).
mirrors flare/http2/state.mojo:587-605 @59bda50 -/
def rstC (c : Conn) (k : Nat) : Conn :=
  let l := c.resetByUs ++ [k]
  { c with resetByUs := if l.length > RESET_REMEMBERED then l.tail else l }

/-- mirrors flare/http2/state.mojo:676-688 @59bda50 -/
def connErr (c : Conn) (code : Nat) : Conn × List Out :=
  if c.goawaySent then (c, []) else ({ c with goawaySent := true }, [.goaway c.lastPeer code])

/-- mirrors flare/http2/state.mojo:635-642 @59bda50 -/
def closeIfKnown (c : Conn) (k : Nat) : Conn :=
  match get c k with
  | some s => put c k { s with state := .closed }
  | none => c

/-- RST_STREAM, then put `s` back closed (the recurring stream-error tail).
mirrors flare/http2/state.mojo:1376-1383 @59bda50 -/
def rstCloseX (c : Conn) (k code : Nat) (s : Stream) (extra : List Out) : Conn × List Out :=
  (put (rstC c k) k { s with state := .closed }, .rst k code :: extra)

def rstClose (c : Conn) (k code : Nat) (s : Stream) : Conn × List Out := rstCloseX c k code s []

/-- Sum of the connection-level WINDOW_UPDATE credit in a reply. -/
def wu0 : List Out → Nat
  | [] => 0
  | .wu 0 n :: t => n + wu0 t
  | _ :: t => wu0 t

/-- `WINDOW_UPDATE(0, n)` when `n > 0` (the `if len(f.payload) > 0` guards). -/
def wu0If (n : Nat) : List Out := if n > 0 then [.wu 0 n] else []

/-! ## Payload helpers -/

/-- Length of the payload left by `_strip_pad_and_priority`; `none` is the
raise. mirrors flare/http2/state.mojo:690-716 @59bda50 -/
def stripLen (f : Fr) (prioField : Bool) : Option Nat :=
  let r : Option (Nat × Nat) :=
    if f.padded then
      if f.plen < 1 then none
      else if f.b0 > f.plen - 1 then none
      else some (1, f.plen - f.b0)
    else some (0, f.plen)
  match r with
  | none => none
  | some (st, en) =>
    if prioField && f.prio then
      if en - st < 5 then none else some (en - (st + 5))
    else some (en - st)

/-- Pre-fix (flare @59bda50): digits of a content-length value folded in
Mojo `Int` (wrapping); `none` on a non-digit.
mirrors flare/http2/state.mojo:756-763 @59bda50 -/
def clDigits : Bytes → Int64 → Option Int64
  | [], acc => some acc
  | b :: t, acc => if b < 48 || b > 57 then none else clDigits t (acc * 10 + Int64.ofNat (b.toNat - 48))

/-- Pre-fix `_declared_content_length` (first field only, wrapping).
mirrors flare/http2/state.mojo:748-765 @59bda50 -/
def declaredCLOld (hs : List Header) : Int :=
  match hs.find? (·.name == kContentLength) with
  | none => -1
  | some h =>
    if h.value = [] then -1
    else match clDigits h.value 0 with
      | none => -1
      | some a => a.toInt

/-- The shipped parser: `1*DIGIT` with an overflow guard (`acc > (Int.MAX -
d) // 10`), every content-length field checked, disagreeing values
rejected. `-1` absent, `-2` malformed.
mirrors flare/http2/state.mojo:789-818 (fixed, H2-05) -/
def clParseFixed : Bytes → Nat → Option Nat
  | [], acc => some acc
  | b :: t, acc =>
    if b < 48 || b > 57 then none
    else if acc > (I64MAX - (b.toNat - 48)) / 10 then none
    else clParseFixed t (acc * 10 + (b.toNat - 48))

/-- mirrors flare/http2/state.mojo:789-818 (fixed, H2-05) -/
def declaredCLFixedGo : List Header → Int → Int
  | [], d => d
  | h :: t, d =>
    if h.name = kContentLength then
      if h.value = [] then -2
      else match clParseFixed h.value 0 with
        | none => -2
        | some n => if (0 : Int) ≤ d && d ≠ (n : Int) then -2 else declaredCLFixedGo t n
    else declaredCLFixedGo t d

/-- `_declared_content_length`. mirrors flare/http2/state.mojo:789-818 (fixed, H2-05) -/
def declaredCLFixed (hs : List Header) : Int := declaredCLFixedGo hs (-1)

/-! ## Client response checks (`state.mojo:851-956`) -/

def lowerB (b : UInt8) : UInt8 := if 65 ≤ b && b ≤ 90 then b + 32 else b

def isDigitB (b : UInt8) : Bool := 48 ≤ b && b ≤ 57

def digitsVal (v : Bytes) : Nat := v.foldl (fun a b => a * 10 + (b.toNat - 48)) 0

/-- Loop state: `(bad, status, regular)`.
mirrors flare/http2/state.mojo:866-902 @59bda50 -/
def cliLoop1 (isTr : Bool) : List Header → Nat → Bool → Bool × Nat
  | [], st, _ => (false, st)
  | h :: t, st, reg =>
    if h.name = [] || h.name != h.name.map lowerB || isConnSpecific h.name then (true, st)
    else if h.name = kStatus then
      if isTr || st != 0 || reg || h.value.length != 3 then (true, st)
      else if !(h.value.all isDigitB) then (true, st)
      else cliLoop1 isTr t (digitsVal h.value) reg
    else if h.name.head? == some 58 then (true, st)
    else if isTr && h.name = kContentLength then (true, st)
    else cliLoop1 isTr t st true

/-- The client's own content-length scan (904-928): `true` = bad.
mirrors flare/http2/state.mojo:903-928 @59bda50 -/
def cliCLBad : List Header → Int → Bool
  | [], _ => false
  | h :: t, d =>
    if h.name = kContentLength then
      if h.value = [] then true
      else match clParseFixed h.value 0 with
        | none => true
        | some n => if d ≥ 0 && (n : Int) ≠ d then true else cliCLBad t n
    else cliCLBad t d

inductive CRes | bad | info | ok (bodyAllowed : Bool)

/-- mirrors flare/http2/state.mojo:851-956 @59bda50 (lowercase test on
ASCII letters only; Mojo's `String.lower` also folds non-ASCII letters). -/
def clientCheck (hs : List Header) (isTr es bodyAllowed : Bool) : CRes :=
  let (bad, st) := cliLoop1 isTr hs 0 false
  if bad || cliCLBad hs (-1) then .bad
  else if !isTr then
    if st < 100 || st > 599 || st == 101 then .bad
    else if st < 200 then (if es then .bad else .info)
    else if st == 204 || st == 304 then .ok false
    else .ok bodyAllowed
  else if !es then .bad
  else .ok bodyAllowed

/-! ## `_commit_header_block` -/

/-- `validate_request_fields`: the H2-10 fix tightens the field-name
check (`validate`); without it the pre-fix `validateOld` runs. -/
def validateFx (fx : Fix) (hs : List Header) (isTr allowExt : Bool) : Bool :=
  if fx.h2_10 then validate hs isTr allowExt else validateOld hs isTr allowExt

def hlSize (hs : List Header) : Nat := (hs.map (fun h => h.name.length + h.value.length + 32)).sum

/-- The tail of `_commit_header_block` after validation (958-1003). The
H2-05 fix answers a malformed content-length (-2) with RST_STREAM
(PROTOCOL_ERROR) and closes the stream.
mirrors flare/http2/state.mojo:1021-1080 (fixed, H2-05) -/
def commitTail (fx : Fix) (c : Conn) (k : Nat) (s : Stream) (isTr es : Bool) (hdrs : List Header) :
    Conn × List Out :=
  let cl := if isTr then s.contentLength
    else if c.isClient && !s.bodyAllowed then -1
    else if fx.h2_05 then declaredCLFixed hdrs else declaredCLOld hdrs
  let s := { s with contentLength := cl, headersComplete := true }
  if fx.h2_05 && cl = -2 then rstClose c k ePROTOCOL s
  else if es then
    if (0 : Int) ≤ s.contentLength && (s.received : Int) ≠ s.contentLength then rstClose c k ePROTOCOL s
    else
      let st := if c.isClient && s.state == .hcl then .closed else .hcr
      (put c k { s with dataComplete := true, state := st }, [])
  else
    let st := if c.isClient && s.state == .hcl then s.state else .open_
    (put c k { s with state := st }, [])

/-- mirrors flare/http2/state.mojo:781-1003 @59bda50 -/
def commit (fx : Fix) (dec : Dec) (c : Conn) (k : Nat) : Conn × List Out :=
  let block := c.block
  let es := c.blockES
  let c := { c with block := [], blockES := false, decLog := c.decLog ++ [block] }
  match dec block with
  | .budget => connErr c eCALM
  | .fail => connErr c eCOMPRESSION
  | .ok hdrs =>
    let refuse := c.blockRefuse
    let c := { c with blockRefuse := 0 }
    if refuse ≠ 0 then (closeIfKnown (rstC c k) k, [.rst k refuse])
    else
      let s0 := (ensure c k).2
      let c := (ensure c k).1
      let isTr := s0.headersComplete
      let s := { s0 with headerListBytes := s0.headerListBytes + hlSize hdrs }
      if s.headerListBytes > headerListCap c then rstClose c k eCALM s
      else if !c.isClient then
        if !validateFx fx hdrs isTr c.enableConnect then rstClose c k ePROTOCOL s
        else commitTail fx c k s isTr es hdrs
      else
        match clientCheck hdrs isTr es s.bodyAllowed with
        | .bad => rstClose c k ePROTOCOL { s with dataLen := 0 }
        | .info => (put c k s, [])
        | .ok ba => commitTail fx c k { s with bodyAllowed := ba } isTr es hdrs

/-! ## `handle_frame` -/

/-- Whether an id absent from the table names an idle (never opened)
stream: above the peer's high-water mark (`state.mojo:1099,1238,1351`), or,
with the H2-03 fix in client role, even or above our own highest id, and
with the H2-15 fix in server role, even (server-initiated, never opened).
mirrors flare/http2/state.mojo:571-583 (`_idle_id`; fixed, H2-03; the
server-role even-id rule is H2-15, fixed) -/
def isIdleId (fx : Fix) (c : Conn) (k : Nat) : Bool :=
  if fx.h2_03 && c.isClient then decide (k > c.maxLocalSid) || k % 2 == 0
  else if fx.h2_15 && !c.isClient then decide (k > c.lastPeer) || k % 2 == 0
  else decide (k > c.lastPeer)

/-- CONTINUATION while a block is open. mirrors flare/http2/state.mojo:1021-1052 @59bda50 -/
def contBranch (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : Conn × List Out :=
  if f.ty ≠ tCONT || f.sid ≠ c.continuing then connErr c ePROTOCOL
  else
    let c := { c with blockConts := c.blockConts + 1 }
    if c.blockConts > CONT_CAP then connErr { c with continuing := 0, block := [] } eCALM
    else if f.plen > c.localMaxFrame then connErr { c with continuing := 0, block := [] } eFRAME_SIZE
    else if c.block.length + f.plen > ceiling c then connErr { c with continuing := 0, block := [] } eCALM
    else
      let c := { c with block := c.block ++ f.frag }
      if !f.eh then (c, [])
      else commit fx dec { c with continuing := 0 } f.sid

/-- Frame-shape validation; `some r` returns early.
mirrors flare/http2/state.mojo:1054-1111 @59bda50 -/
def shapeCheck (fx : Fix) (c : Conn) (f : Fr) : Option (Conn × List Out) :=
  if f.ty = tPING then
    if f.sid ≠ 0 then some (connErr c ePROTOCOL)
    else if f.plen ≠ 8 then some (connErr c eFRAME_SIZE) else none
  else if f.ty = tGOAWAY then
    if f.sid ≠ 0 then some (connErr c ePROTOCOL)
    else if fx.h2_07 && f.plen < 8 then some (connErr c eFRAME_SIZE) else none
  else if f.ty = tSETTINGS then
    if f.sid ≠ 0 then some (connErr c ePROTOCOL)
    else if f.f1 && f.plen ≠ 0 then some (connErr c eFRAME_SIZE)
    else if f.plen % 6 ≠ 0 then some (connErr c eFRAME_SIZE) else none
  else if f.ty = tPRIORITY then
    if f.sid = 0 then some (connErr c ePROTOCOL)
    else if f.plen ≠ 5 then some (connErr c eFRAME_SIZE)
    else if f.word % 2147483648 = f.sid then
      if fx.h2_16 && !mem c f.sid && isIdleId fx c f.sid then some (connErr c ePROTOCOL)
      else some (closeIfKnown (rstC c f.sid) f.sid, [.rst f.sid ePROTOCOL])
    else none
  else if f.ty = tRST then
    if f.sid = 0 then some (connErr c ePROTOCOL)
    else if f.plen ≠ 4 then some (connErr c eFRAME_SIZE)
    else if !mem c f.sid && isIdleId fx c f.sid then some (connErr c ePROTOCOL) else none
  else if f.ty = tWU then
    if f.plen ≠ 4 then some (connErr c eFRAME_SIZE) else none
  else if f.ty = tDATA then
    if f.sid = 0 then some (connErr c ePROTOCOL) else none
  else if f.ty = tPUSH then some (connErr c ePROTOCOL)
  else none

/-- Server-side stream-id monotonicity (`state.mojo:1117-1126`);
`.inl` returns early.
mirrors flare/http2/state.mojo:1117-1126 @59bda50; with `h2_02`: `last_peer_stream_id > 0 and
sid <= last_peer_stream_id` (state.mojo, H2-02 fix) -/
def idCheck (fx : Fix) (c : Conn) (f : Fr) : (Conn × List Out) ⊕ Conn :=
  if f.ty = tHEADERS && !c.isClient then
    if f.sid ≠ 0 && f.sid % 2 = 0 then .inl (connErr c ePROTOCOL)
    else if (if fx.h2_02 then decide (f.sid ≤ c.lastPeer) && decide (0 < c.lastPeer)
              else decide (f.sid < c.lastPeer)) && !mem c f.sid then
      .inl (connErr c ePROTOCOL)
    else .inr (if f.sid > c.lastPeer then { c with lastPeer := f.sid } else c)
  else .inr c

/-- `h2_setting_error`. mirrors flare/http2/state.mojo:87-98 @59bda50 -/
def settingError (id v : Nat) : Nat :=
  if id = 2 && v ≠ 0 && v ≠ 1 then ePROTOCOL
  else if id = 4 && v > 2147483647 then eFLOW
  else if id = 5 && (v < 16384 || v > 16777215) then ePROTOCOL
  else 0

/-- The INITIAL_WINDOW_SIZE delta over the stream table (1158-1174);
`false` = a stream would pass `_MAX_WINDOW` (the streams before it are
already updated, as in Mojo).
mirrors flare/http2/state.mojo:1156-1174 @59bda50 -/
def applyDelta (delta : Int) : List (Nat × Stream) → List (Nat × Stream) × Bool
  | [] => ([], true)
  | p :: t =>
    if p.2.state = .closed then
      let r := applyDelta delta t
      (p :: r.1, r.2)
    else if p.2.sendW + delta > MAX_WINDOW then (p :: t, false)
    else
      let r := applyDelta delta t
      ((p.1, { p.2 with sendW := p.2.sendW + delta }) :: r.1, r.2)

/-- One SETTINGS pair. mirrors flare/http2/state.mojo:1136-1190 @59bda50 -/
def applySetting (c : Conn) (id v : Nat) : Conn ⊕ (Conn × List Out) :=
  let bad := settingError id v
  if bad ≠ 0 then .inr (connErr c bad)
  else if id = 4 then
    let delta : Int := (v : Int) - c.peerInitW
    let c := { c with peerInitW := v }
    if delta ≠ 0 then
      let r := applyDelta delta c.streams
      if r.2 then .inl { c with streams := r.1 }
      else .inr (connErr { c with streams := r.1 } eFLOW)
    else .inl c
  else if id = 5 then .inl { c with peerMaxFrame := v }
  else if id = 1 then .inl { c with peerHeaderTable := v }
  else if id = 8 then .inl { c with peerConnect := v ≠ 0 }
  else .inl c

/-- mirrors flare/http2/state.mojo:1135-1191 @59bda50 -/
def applySettings (c : Conn) : List (Nat × Nat) → Conn ⊕ (Conn × List Out)
  | [] => .inl c
  | (id, v) :: t =>
    match applySetting c id v with
    | .inl c => applySettings c t
    | .inr r => .inr r

/-- mirrors flare/http2/state.mojo:1128-1192 @59bda50 -/
def settingsH (c : Conn) (f : Fr) : Conn × List Out :=
  if f.f1 then ({ c with settingsAcked := true }, [])
  else match applySettings c f.settings with
    | .inl c => (c, [.settingsAck])
    | .inr r => r

/-- mirrors flare/http2/state.mojo:1205-1255 @59bda50 -/
def wuH (fx : Fix) (c : Conn) (f : Fr) : Conn × List Out :=
  let inc := f.word % 2147483648
  if inc = 0 then
    if f.sid = 0 then connErr c ePROTOCOL
    else if fx.h2_16 && !mem c f.sid && isIdleId fx c f.sid then connErr c ePROTOCOL
    else (closeIfKnown (rstC c f.sid) f.sid, [.rst f.sid ePROTOCOL])
  else if f.sid = 0 then
    if c.sendW + inc > MAX_WINDOW then connErr c eFLOW
    else ({ c with sendW := c.sendW + inc }, [])
  else match get c f.sid with
    | none => if isIdleId fx c f.sid then connErr c ePROTOCOL else (c, [])
    | some s =>
      if s.sendW + inc > MAX_WINDOW then rstClose c f.sid eFLOW s
      else (put c f.sid { s with sendW := s.sendW + inc }, [])

/-- Checks against an existing stream (1268-1288): `.inl` is a
connection error, `.inr code` the refusal code so far (0 = none).
mirrors flare/http2/state.mojo:1268-1288 @59bda50 -/
def headersPre (fx : Fix) (c : Conn) (f : Fr) : (Conn × List Out) ⊕ Nat :=
  match get c f.sid with
  | some p =>
    if p.state = .closed then .inl (connErr c eSTREAM_CLOSED)
    else if (!c.isClient || fx.h2_14) && p.state = .hcr then .inl (connErr c eSTREAM_CLOSED)
    else if !c.isClient && p.headersComplete && !f.f1 then .inr ePROTOCOL
    else .inr 0
  | none => .inr 0

/-- The concurrency refusal (1289-1298).
mirrors flare/http2/state.mojo:1289-1298 @59bda50 -/
def headersRefuse (fx : Fix) (c : Conn) (f : Fr) (refuse0 : Nat) : Nat :=
  if refuse0 = 0 && !c.isClient && !mem c f.sid &&
      (fx.h2_11 || decide (c.maxConcurrent > 0)) && activeCount c ≥ c.maxConcurrent
  then eREFUSED else refuse0

/-- Start the header block (1313-1333).
mirrors flare/http2/state.mojo:1313-1333 @59bda50 -/
def headersOpen (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (refuse : Nat) : Conn × List Out :=
  let c := { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 }
  let c := if refuse = 0 then put (ensure c f.sid).1 f.sid (ensure c f.sid).2 else c
  if !f.eh then ({ c with continuing := f.sid }, [])
  else commit fx dec c f.sid

/-- mirrors flare/http2/state.mojo:1257-1333 @59bda50; `h2_04` is the client-role
unopened-stream check at the top of the HEADERS branch -/
def headersH (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if f.sid = 0 then
    if fx.h2_06 then .ok (connErr c ePROTOCOL) else .error "h2: HEADERS on stream 0"
  else if fx.h2_04 && c.isClient && !mem c f.sid then .ok (connErr c ePROTOCOL)
  else match headersPre fx c f with
    | .inl r => .ok r
    | .inr refuse0 =>
      if f.prio && f.plen ≥ (if f.padded then 1 else 0) + 4 && f.word % 2147483648 = f.sid then
        .ok (connErr c ePROTOCOL)
      else match stripLen f true with
        | none => .ok (connErr c ePROTOCOL)
        | some _ => .ok (headersOpen fx dec c f (headersRefuse fx c f refuse0))

/-- Sum of `dataLen` over non-closed streams.
mirrors flare/http2/state.mojo:607-617 @59bda50 -/
def recount (c : Conn) : Nat :=
  (c.streams.filter (fun p => p.2.state != .closed)).foldl (fun a p => a + p.2.dataLen) 0

/-- The connection-credit tail of the DATA branch (1492-1511).
mirrors flare/http2/state.mojo:1492-1511 @59bda50 -/
def dataCredit (c : Conn) (f : Fr) (credit : Nat) : Conn × List Out :=
  if f.plen > 0 then
    let o1 : List Out := if credit > 0 then [.wu f.sid credit] else []
    if !c.isClient && c.buffered > MAX_BUFFERED && recount c > MAX_BUFFERED then
      ({ c with buffered := recount c, withheld := c.withheld + f.plen }, o1)
    else
      let c := if !c.isClient && c.buffered > MAX_BUFFERED then { c with buffered := recount c } else c
      ({ c with withheld := 0 }, o1 ++ [.wu 0 (f.plen + c.withheld)])
  else (c, [])

/-- The END_STREAM and credit tail of the DATA branch (1457-1511); `c` already
counts the body in `buffered`, `s` has the stream credit restored. The
H2-09 fix returns the frame's connection credit when the content-length
mismatch resets the stream; the H2-19 fix sends no stream WINDOW_UPDATE
on a stream this frame closes.
mirrors flare/http2/state.mojo:1540-1600 (H2-09 fixed; H2-19 @59bda50) -/
def dataFinish (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (cr : Nat) : Conn × List Out :=
  if f.f1 && (0 : Int) ≤ s.contentLength && (s.received : Int) ≠ s.contentLength then
    rstCloseX c f.sid ePROTOCOL s (if fx.h2_09 then wu0If f.plen else [])
  else
    dataCredit (put c f.sid (if f.f1 then
      { s with dataComplete := true,
               state := if c.isClient && s.state == .hcl then .closed else .hcr }
      else s)) f (if fx.h2_19 && f.f1 && c.isClient && s.state == .hcl then 0 else cr)

/-- Body octets whose stream credit is deferred to `drain_body`
(state.mojo:1450-1455). -/
def deferOf (s : Stream) (body : Nat) : Nat := if s.deferCredit then body else 0

/-- The accepted-body part of the DATA branch (1428-1456); `s` already
counts the body in `dataLen` and `received`.
mirrors flare/http2/state.mojo:1428-1456 @59bda50 -/
def dataAccept (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (body : Nat) : Conn × List Out :=
  if !c.isClient && (0 : Int) ≤ s.contentLength && (s.received : Int) > s.contentLength then
    rstCloseX c f.sid ePROTOCOL { s with dataLen := 0, buf := [] } (wu0If f.plen)
  else
    dataFinish fx (if !c.isClient then { c with buffered := c.buffered + body } else c) f
      { s with recvW := s.recvW + (f.plen - deferOf s body),
               pendingCredit := s.pendingCredit + deferOf s body } (f.plen - deferOf s body)

/-- The per-stream checks of the DATA branch (1374-1427); `s` already has
`recvW` debited by the frame length. The H2-09 fix returns the
connection credit when the stream window is overrun.
mirrors flare/http2/state.mojo:1453-1520 (H2-09 fixed) -/
def dataBody (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (body : Nat) : Conn × List Out :=
  if s.recvW < 0 then
    rstCloseX c f.sid eFLOW s (if fx.h2_09 then wu0If f.plen else [])
  else if c.isClient && !s.bodyAllowed && body > 0 then
    rstCloseX c f.sid ePROTOCOL { s with dataLen := 0, buf := [] } (wu0If f.plen)
  else if !c.isClient && (body : Int) > (c.maxBody : Int) - s.dataLen then
    rstCloseX c f.sid eCALM { s with dataLen := 0, buf := [] } (wu0If f.plen)
  else dataAccept fx c f { s with dataLen := s.dataLen + body, received := s.received + body,
                                   buf := s.buf ++ f.frag } body

/-- The H2-20 fix tests for a closed / half-closed (remote) stream before
the client's headers-complete test.
mirrors flare/http2/state.mojo:1340-1512 @59bda50 -/
def dataH (fx : Fix) (c : Conn) (f : Fr) : Conn × List Out :=
  if f.sid ∈ c.resetByUs then (c, wu0If f.plen)
  else match get c f.sid with
  | none => if isIdleId fx c f.sid then connErr c ePROTOCOL else connErr c eSTREAM_CLOSED
  | some s =>
    if fx.h2_20 && (s.state == .closed || s.state == .hcr) then connErr c eSTREAM_CLOSED
    else if c.isClient && !s.headersComplete then connErr c ePROTOCOL
    else if s.state = .closed || s.state = .hcr then connErr c eSTREAM_CLOSED
    else match stripLen f false with
    | none => connErr c ePROTOCOL
    | some body => dataBody fx c f { s with recvW := s.recvW - f.plen } body

/-- The flood check of the RST_STREAM branch (1529-1540).
mirrors flare/http2/state.mojo:1529-1540 @59bda50 -/
def rstFlood (c : Conn) (f : Fr) : Conn × List Out :=
  if c.rstCount > RST_FLOOD && !c.goawaySent then
    ({ c with goawaySent := true }, [.goaway f.sid eCALM])
  else (c, [])

/-- mirrors flare/http2/state.mojo:1518-1540 @59bda50 -/
def rstH (c : Conn) (f : Fr) : Conn × List Out :=
  rstFlood { closeIfKnown c f.sid with rstCount := (closeIfKnown c f.sid).rstCount + 1 } f

/-- Per-type dispatch after the common checks (1128-1547).
mirrors flare/http2/state.mojo:1128-1547 @59bda50 -/
def dispatch (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if f.ty = tSETTINGS then .ok (settingsH c f)
  else if f.ty = tPING then .ok (if f.f1 then (c, []) else (c, [.pingAck]))
  else if f.ty = tWU then .ok (wuH fx c f)
  else if f.ty = tHEADERS then headersH fx dec c f
  else if f.ty = tCONT then .ok (connErr c ePROTOCOL)
  else if f.ty = tDATA then .ok (dataH fx c f)
  else if f.ty = tGOAWAY then .ok ({ c with goawayReceived := true }, [])
  else if f.ty = tRST then .ok (rstH c f)
  else .ok (c, [])

/-- mirrors flare/http2/state.mojo:1005-1547 @59bda50 -/
def handle (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if c.continuing ≠ 0 then .ok (contBranch fx dec c f)
  else match shapeCheck fx c f with
  | some r => .ok r
  | none =>
    if f.plen > c.localMaxFrame then .ok (connErr c eFRAME_SIZE)
    else match idCheck fx c f with
    | .inl r => .ok r
    | .inr c => dispatch fx dec c f

/-- Whether `handle` reaches the DATA branch (line 1340) for `f`. -/
def reachesData (c : Conn) (f : Fr) : Bool :=
  c.continuing == 0 && f.ty == tDATA && f.sid != 0 && decide (f.plen ≤ c.localMaxFrame)

/-! ## Driver and local actions -/

/-- Inputs: an inbound frame or a local action that touches stream or
window state. -/
inductive Ev
  /-- an inbound frame (`Http2Connection.feed`, server.mojo:398-438) -/
  | frame (f : Fr)
  /-- `release_request_credit(n)` (state.mojo:619-633) -/
  | release (n : Nat)
  /-- one-shot `emit_response` with an `n`-byte body that fits the
  windows (server.mojo:603-681) -/
  | respond (sid n : Nat)
  /-- `queue_stream_data` of `n` bytes (server.mojo:870-921) -/
  | send (sid n : Nat)
  /-- client `send_request` opening `sid` (client.mojo:788-798) -/
  | openLocal (sid : Nat) (endStream : Bool)
  /-- client `take_response` / `discard_stream` (client.mojo:1021) -/
  | pop (sid : Nat)
  /-- local END_STREAM: client `send_data(sid, body, end_stream=True)`;
  `empty` selects the empty-DATA half-close path (client.mojo:885-901),
  otherwise the last chunk of `_emit_body_span` (client.mojo:560-584) -/
  | endLocal (sid : Nat) (empty : Bool)
  /-- client `enable_response_streaming` (client.mojo:1189-1197) -/
  | stream (sid : Nat)
  /-- client `drain_body` (client.mojo:1160-1187) -/
  | drain (sid : Nat)
  deriving Repr

/-- The H2-01 fix layered on `handle`: account every DATA payload against
`recvW`, refuse a frame that overruns it, and add back every
connection-level WINDOW_UPDATE that is emitted.
mirrors flare/http2/state.mojo:1356-1366 and `_conn_window_update`
(639-648) (fixed, H2-01) -/
def handleW (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if fx.h2_01 && reachesData c f && decide ((f.plen : Int) > c.recvW) then .ok (connErr c eFLOW)
  else match handle fx dec c f with
    | .ok (c', o) =>
      .ok ({ c' with recvW :=
        if fx.h2_01 then c.recvW - (if reachesData c f then (f.plen : Int) else 0) + wu0 o
        else c'.recvW }, o)
    | .error e => .error e

/-- The connection preface rule (RFC 9113 §3.4) and its ghost:
`peerSettingsSeen` records that a SETTINGS (non-ACK) frame was received.
The code before the H2-08 fix never read it; the fix (`peer_settings_seen`
on `Http2Connection`, in `feed`) refuses any other first frame.
mirrors flare/http2/server.mojo:398-438 @59bda50; the H2-08 fix is the
`peer_settings_seen` test before `handle_frame` in `feed` -/
def prefaceGate (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if !c.peerSettingsSeen then
    if f.ty = tSETTINGS && !f.f1 then handleW fx dec { c with peerSettingsSeen := true } f
    else if fx.h2_08 then .ok (connErr c ePROTOCOL)
    else handleW fx dec c f
  else handleW fx dec c f

/-- One inbound frame through the server driver (server.mojo:398-438):
nothing is applied after a GOAWAY was queued, and a frame declaring more
than `local_max_frame_size` is refused from its header. The H2-08 fix
adds the first-frame check.
mirrors flare/http2/server.mojo:398-438 @59bda50 -/
def driveFrame (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if c.goawaySent then .ok (c, [])
  else if f.plen > c.localMaxFrame then .ok (connErr c eFRAME_SIZE)
  else prefaceGate fx dec c f

/-- The client driver's frame loop (`Http2ClientConnection.feed`,
client.mojo:400-512): a frame declaring more than the advertised maximum
raises (the H2-18 fix answers GOAWAY(FRAME_SIZE_ERROR)); PUSH_PROMISE
used to be answered with RST_STREAM on the promised id and never reached
`handle_frame` (pre-fix; the H2-17 fix hands it over, and it draws
GOAWAY(PROTOCOL_ERROR)); frames are applied after a GOAWAY was queued as
well (`handle_frame` itself then emits nothing for a further connection
error).
mirrors flare/http2/client.mojo:400-512 (H2-17 fixed at 426-433; H2-18 @59bda50) -/
def driveClient (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if f.plen > c.localMaxFrame then
    if fx.h2_18 then .ok (connErr c eFRAME_SIZE)
    else .error "h2 client: frame exceeds advertised maximum size"
  else if !fx.h2_17 && f.ty = tPUSH then
    .ok (c, if f.plen ≥ 4 then [.rst (f.word % 2147483648) ePROTOCOL] else [])
  else prefaceGate fx dec c f

/-- mirrors flare/http2/state.mojo:623-637 (fixed, H2-01) -/
def release (fx : Fix) (c : Conn) (n : Nat) : Conn × List Out :=
  let c := { c with buffered := c.buffered - n }
  if c.withheld > 0 && c.buffered ≤ MAX_BUFFERED then
    ({ c with withheld := 0, recvW := if fx.h2_01 then c.recvW + c.withheld else c.recvW },
     [.wu 0 c.withheld])
  else (c, [])

/-- mirrors flare/http2/server.mojo:884-888 @59bda50 -/
def budget (c : Conn) (s : Stream) : Int := if c.sendW < s.sendW then c.sendW else s.sendW

/-- mirrors flare/http2/server.mojo:870-921 @59bda50 -/
def send (c : Conn) (k n : Nat) : Conn × List Out :=
  match get c k with
  | none => (c, [])
  | some s =>
    let b := budget c s
    if b ≤ 0 then (c, [])
    else
      let sent : Nat := if (n : Int) < b then n else b.toNat
      (put { c with sendW := c.sendW - sent } k { s with sendW := s.sendW - sent },
       if sent > 0 then [.data k sent] else [])

/-- One-shot response: only when the body fits both windows, otherwise
flare takes the `queue_stream_data` path (modelled by `send`).
mirrors flare/http2/server.mojo:603-681 @59bda50 -/
def respond (c : Conn) (k n : Nat) : Conn × List Out :=
  match get c k with
  | none => (c, [])
  | some s =>
    if n > 0 && ((n : Int) > budget c s || n > c.peerMaxFrame) then (c, [])
    else (put { c with sendW := c.sendW - n } k { s with state := .closed, sendW := s.sendW - n },
          if n > 0 then [.data k n] else [])

/-- mirrors flare/http2/client.mojo:800,870,1145 and `note_local_stream`
(state.mojo:566-569) (fixed, H2-03) -/
def openLocal (c : Conn) (k : Nat) (es : Bool) : Conn :=
  let c := { c with maxLocalSid := if k > c.maxLocalSid then k else c.maxLocalSid }
  put c k { state := if es then .hcl else .open_, sendW := c.peerInitW, recvW := c.initW }

/-- Local END_STREAM. The H2-12 fix applies the empty path's state rule
to the last body chunk too; the H2-13 fix (the closed-stream guard at the top of `send_data`) leaves a closed stream alone
(and sends nothing).
mirrors flare/http2/client.mojo:560-584,885-901 @59bda50; the H2-12 fix is the CLOSED-if-HALF_CLOSED_REMOTE rule in `_emit_body_span` -/
def endLocal (fx : Fix) (c : Conn) (k : Nat) (empty : Bool) : Conn :=
  match get c k with
  | none => c
  | some s =>
    if fx.h2_13 && s.state == .closed then c
    else put c k { s with state :=
      if (empty || fx.h2_12) && s.state == .hcr then .closed else .hcl }

/-- mirrors flare/http2/client.mojo:1189-1197 @59bda50 -/
def enableStream (c : Conn) (k : Nat) : Conn :=
  match get c k with
  | none => c
  | some s => put c k { s with deferCredit := true }

/-- Stream 0 is never a key of the table (HEADERS on stream 0 never opens
one), so the guard only spares the proofs that invariant.
mirrors flare/http2/client.mojo:1160-1187 @59bda50 -/
def drain (c : Conn) (k : Nat) : Conn × List Out :=
  if k = 0 then (c, []) else
  match get c k with
  | none => (c, [])
  | some s =>
    (put c k { s with buf := [], pendingCredit := 0, recvW := s.recvW + s.pendingCredit },
     .drained k s.buf ::
       (if s.pendingCredit > 0 && !s.dataComplete && s.state != .closed
        then [.wu k s.pendingCredit] else []))

/-- One step of the whole connection. -/
def step (fx : Fix) (dec : Dec) (c : Conn) : Ev → Res
  | .frame f => if c.isClient then driveClient fx dec c f else driveFrame fx dec c f
  | .release n => .ok (release fx c n)
  | .respond k n => .ok (respond c k n)
  | .send k n => .ok (send c k n)
  | .openLocal k es => .ok (openLocal c k es, [])
  | .pop k => .ok (erase c k, [])
  | .endLocal k e => .ok (endLocal fx c k e, [])
  | .stream k => .ok (enableStream c k, [])
  | .drain k => .ok (drain c k)

/-- Run a trace with one decoder; collects each step's input and reply.
`none` if a step raises. -/
def run (fx : Fix) (dec : Dec) : Conn → List Ev → Option (Conn × List (Ev × List Out))
  | c, [] => some (c, [])
  | c, e :: es =>
    match step fx dec c e with
    | .error _ => none
    | .ok (c', o) =>
      match run fx dec c' es with
      | none => none
      | some (c'', tr) => some (c'', (e, o) :: tr)

/-- The connection as an LTS; each label carries the HPACK outcome
function in force for that step (so stateful decoding is covered). -/
def lts (fx : Fix) (init : Conn → Prop) : LTS Conn (Dec × Ev) where
  init := init
  step c l c' := ∃ o, step fx l.1 c l.2 = .ok (c', o)

end Flare.L3.H2.Conn
