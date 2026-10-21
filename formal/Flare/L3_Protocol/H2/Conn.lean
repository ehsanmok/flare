import Flare.L3_Protocol.H2.Validate

/-!
# HTTP/2 connection state machine (impl)

An executable transliteration of `Connection.handle_frame`
(`flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=fda30c33`) and the code it calls:
`_commit_header_block` (781-1003), `_ensure_stream` / pruning (538-566),
`_rst_stream_frame` (587-605), `_conn_error` (676-688),
`_strip_pad_and_priority` (690-716), `_declared_content_length` (748-765),
`_active_stream_count` (767-779), `release_request_credit` (619-633),
plus the server driver's frame loop (`flare/http2/server.mojo#Http2Connection.feed sha=13eaa955fac8 at=fda30c33`)
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
  every send window, so the 64-bit values never wrap. `_declared_content_length`
  guards its accumulator against `2^63-1` (`I64MAX`), and the model keeps that
  guard exactly.
* The header-list cap check in `_commit_header_block` (826-838) leaves the
  RFC size of the whole list in `header_list_bytes`, where Mojo leaves the
  prefix sum at which it stopped; the stream is closed either way.

The difftest target `h2_conn.frames` (`formal/Oracle/H2.lean`) checks
`handleW` against the real server-role `Connection.handle_frame` on frame
traces.
-/
namespace Flare.L3.H2.Conn
open Flare.L3.H2.Names
open Flare.L3.H2.Validate (Header validate isConnSpecific)

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

/-- mirrors flare/http2/state.mojo#Stream+Stream.__init__ sha=ab318179c863 at=df9ed82b -/
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

/-- mirrors flare/http2/state.mojo#Connection+Connection.__init__ sha=38e143bf2275 at=ea1b9282
(`maxLocalSid` is `max_local_stream_id`; `peerSettingsSeen` is the
client's first-frame SETTINGS check (`prefaceGate`); `decLog` is a ghost
log of the header blocks handed to the decoder; `reset_streams`, the peer
resets queued for the application, is not modelled). -/
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

/-- mirrors flare/http2/state.mojo#Connection._prune_threshold sha=93ad4ed58e83 at=59bda50f -/
def pruneThreshold (c : Conn) : Nat :=
  if c.maxConcurrent * 2 > 256 then c.maxConcurrent * 2 else 256

/-- mirrors flare/http2/state.mojo#Connection._ensure_stream sha=3ec708a692c0 at=59bda50f -/
def ensure (c : Conn) (k : Nat) : Conn × Stream :=
  match get c k with
  | some s => (c, s)
  | none =>
    let c := if c.streams.length ≥ pruneThreshold c then
      { c with streams := c.streams.filter (fun p => p.2.state != .closed) } else c
    (c, { state := .idle, sendW := c.peerInitW, recvW := c.initW })

/-- mirrors flare/http2/state.mojo#Connection._active_stream_count sha=0d9b36adaf9c at=df9ed82b -/
def isActive (s : Stream) : Bool := s.state == .open_ || s.state == .hcl || s.state == .hcr

def activeCount (c : Conn) : Nat := c.streams.countP (fun p => isActive p.2)

/-- mirrors flare/http2/state.mojo#Connection._header_list_cap+Connection._header_block_ceiling sha=b4b5a77020df at=59bda50f -/
def headerListCap (c : Conn) : Nat := if c.maxHeaderList > 0 then c.maxHeaderList else HARD_HEADER_CAP

def ceiling (c : Conn) : Nat := if headerListCap c * 4 > 262144 then headerListCap c * 4 else 262144

/-! ## Reply frames -/

/-- The bookkeeping half of `_rst_stream_frame`: remember `k` in the
bounded `reset_by_us` list (the frame itself is `Out.rst k code`).
mirrors flare/http2/state.mojo#Connection._rst_stream_frame sha=28f4983941a8 at=59bda50f -/
def rstC (c : Conn) (k : Nat) : Conn :=
  let l := c.resetByUs ++ [k]
  { c with resetByUs := if l.length > RESET_REMEMBERED then l.tail else l }

/-- mirrors flare/http2/state.mojo#Connection._conn_error sha=19899b15915b at=59bda50f -/
def connErr (c : Conn) (code : Nat) : Conn × List Out :=
  if c.goawaySent then (c, []) else ({ c with goawaySent := true }, [.goaway c.lastPeer code])

/-- mirrors flare/http2/state.mojo#Connection._close_if_known sha=888f2ba7a492 at=59bda50f -/
def closeIfKnown (c : Conn) (k : Nat) : Conn :=
  match get c k with
  | some s => put c k { s with state := .closed }
  | none => c

/-- RST_STREAM, then put `s` back closed (the recurring stream-error tail).
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
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
raise. mirrors flare/http2/state.mojo#Connection._strip_pad_and_priority sha=66bb060d6b9c at=24f7670c -/
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

/-- The shipped parser: `1*DIGIT` with an overflow guard (`acc > (Int.MAX -
d) // 10`), every content-length field checked, disagreeing values
rejected. `-1` absent, `-2` malformed.
mirrors flare/http2/state.mojo#Connection._declared_content_length sha=29c8cdca2d57 at=6c062bde (fixed, H2-05) -/
def clParse : Bytes → Nat → Option Nat
  | [], acc => some acc
  | b :: t, acc =>
    if b < 48 || b > 57 then none
    else if acc > (I64MAX - (b.toNat - 48)) / 10 then none
    else clParse t (acc * 10 + (b.toNat - 48))

/-- mirrors flare/http2/state.mojo#Connection._declared_content_length sha=29c8cdca2d57 at=6c062bde (fixed, H2-05) -/
def declaredCLGo : List Header → Int → Int
  | [], d => d
  | h :: t, d =>
    if h.name = kContentLength then
      if h.value = [] then -2
      else match clParse h.value 0 with
        | none => -2
        | some n => if (0 : Int) ≤ d && d ≠ (n : Int) then -2 else declaredCLGo t n
    else declaredCLGo t d

/-- `_declared_content_length`. mirrors flare/http2/state.mojo#Connection._declared_content_length sha=29c8cdca2d57 at=6c062bde (fixed, H2-05) -/
def declaredCL (hs : List Header) : Int := declaredCLGo hs (-1)

/-! ## Client response checks (`state.mojo:851-956`) -/

def lowerB (b : UInt8) : UInt8 := if 65 ≤ b && b ≤ 90 then b + 32 else b

def isDigitB (b : UInt8) : Bool := 48 ≤ b && b ≤ 57

def digitsVal (v : Bytes) : Nat := v.foldl (fun a b => a * 10 + (b.toNat - 48)) 0

/-- Loop state: `(bad, status, regular)`.
mirrors flare/http2/state.mojo#Connection._commit_header_block sha=df796e7762c8 at=7ae5abc2 -/
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
mirrors flare/http2/state.mojo#Connection._commit_header_block sha=df796e7762c8 at=7ae5abc2 -/
def cliCLBad : List Header → Int → Bool
  | [], _ => false
  | h :: t, d =>
    if h.name = kContentLength then
      if h.value = [] then true
      else match clParse h.value 0 with
        | none => true
        | some n => if d ≥ 0 && (n : Int) ≠ d then true else cliCLBad t n
    else cliCLBad t d

inductive CRes | bad | info | ok (bodyAllowed : Bool)

/-- mirrors flare/http2/state.mojo#Connection._commit_header_block sha=df796e7762c8 at=7ae5abc2 (lowercase test on
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

def hlSize (hs : List Header) : Nat := (hs.map (fun h => h.name.length + h.value.length + 32)).sum

/-- The tail of `_commit_header_block` after validation (958-1003). A
malformed content-length (-2) is answered with RST_STREAM
(PROTOCOL_ERROR) and closes the stream.
mirrors flare/http2/state.mojo#Connection._commit_header_block+Connection.handle_frame sha=a8cbd317463b at=7ae5abc2 -/
def commitTail (c : Conn) (k : Nat) (s : Stream) (isTr es : Bool) (hdrs : List Header) :
    Conn × List Out :=
  let cl := if isTr then s.contentLength
    else if c.isClient && !s.bodyAllowed then -1
    else declaredCL hdrs
  let s := { s with contentLength := cl, headersComplete := true }
  if cl = -2 then rstClose c k ePROTOCOL s
  else if es then
    if (0 : Int) ≤ s.contentLength && (s.received : Int) ≠ s.contentLength then rstClose c k ePROTOCOL s
    else
      let st := if c.isClient && s.state == .hcl then .closed else .hcr
      (put c k { s with dataComplete := true, state := st }, [])
  else
    let st := if c.isClient && s.state == .hcl then s.state else .open_
    (put c k { s with state := st }, [])

/-- mirrors flare/http2/state.mojo#Connection._commit_header_block sha=df796e7762c8 at=7ae5abc2 -/
def commit (dec : Dec) (c : Conn) (k : Nat) : Conn × List Out :=
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
        if !validate hdrs isTr c.enableConnect then rstClose c k ePROTOCOL s
        else commitTail c k s isTr es hdrs
      else
        match clientCheck hdrs isTr es s.bodyAllowed with
        | .bad => rstClose c k ePROTOCOL { s with dataLen := 0 }
        | .info => (put c k s, [])
        | .ok ba => commitTail c k { s with bodyAllowed := ba } isTr es hdrs

/-! ## `handle_frame` -/

/-- Whether an id absent from the table names an idle (never opened)
stream: in client role, even or above our own highest id; in server role,
even (server-initiated, never opened) or above the peer's high-water mark.
mirrors flare/http2/state.mojo#Connection._idle_id sha=3d37fea92735 at=ea1b9282 -/
def isIdleId (c : Conn) (k : Nat) : Bool :=
  if c.isClient then decide (k > c.maxLocalSid) || k % 2 == 0
  else decide (k > c.lastPeer) || k % 2 == 0

/-- CONTINUATION while a block is open. mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def contBranch (dec : Dec) (c : Conn) (f : Fr) : Conn × List Out :=
  if f.ty ≠ tCONT || f.sid ≠ c.continuing then connErr c ePROTOCOL
  else
    let c := { c with blockConts := c.blockConts + 1 }
    if c.blockConts > CONT_CAP then connErr { c with continuing := 0, block := [] } eCALM
    else if f.plen > c.localMaxFrame then connErr { c with continuing := 0, block := [] } eFRAME_SIZE
    else if c.block.length + f.plen > ceiling c then connErr { c with continuing := 0, block := [] } eCALM
    else
      let c := { c with block := c.block ++ f.frag }
      if !f.eh then (c, [])
      else commit dec { c with continuing := 0 } f.sid

/-- Frame-shape validation; `some r` returns early.
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def shapeCheck (c : Conn) (f : Fr) : Option (Conn × List Out) :=
  if f.ty = tPING then
    if f.sid ≠ 0 then some (connErr c ePROTOCOL)
    else if f.plen ≠ 8 then some (connErr c eFRAME_SIZE) else none
  else if f.ty = tGOAWAY then
    if f.sid ≠ 0 then some (connErr c ePROTOCOL)
    else if f.plen < 8 then some (connErr c eFRAME_SIZE) else none
  else if f.ty = tSETTINGS then
    if f.sid ≠ 0 then some (connErr c ePROTOCOL)
    else if f.f1 && f.plen ≠ 0 then some (connErr c eFRAME_SIZE)
    else if f.plen % 6 ≠ 0 then some (connErr c eFRAME_SIZE) else none
  else if f.ty = tPRIORITY then
    if f.sid = 0 then some (connErr c ePROTOCOL)
    else if f.plen ≠ 5 then some (connErr c eFRAME_SIZE)
    else if f.word % 2147483648 = f.sid then
      if !mem c f.sid && isIdleId c f.sid then some (connErr c ePROTOCOL)
      else some (closeIfKnown (rstC c f.sid) f.sid, [.rst f.sid ePROTOCOL])
    else none
  else if f.ty = tRST then
    if f.sid = 0 then some (connErr c ePROTOCOL)
    else if f.plen ≠ 4 then some (connErr c eFRAME_SIZE)
    else if !mem c f.sid && isIdleId c f.sid then some (connErr c ePROTOCOL) else none
  else if f.ty = tWU then
    if f.plen ≠ 4 then some (connErr c eFRAME_SIZE) else none
  else if f.ty = tDATA then
    if f.sid = 0 then some (connErr c ePROTOCOL) else none
  else if f.ty = tPUSH then some (connErr c ePROTOCOL)
  else none

/-- Server-side stream-id monotonicity (`state.mojo:1117-1126`):
`last_peer_stream_id > 0 and sid <= last_peer_stream_id`; `.inl` returns early.
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def idCheck (c : Conn) (f : Fr) : (Conn × List Out) ⊕ Conn :=
  if f.ty = tHEADERS && !c.isClient then
    if f.sid ≠ 0 && f.sid % 2 = 0 then .inl (connErr c ePROTOCOL)
    else if (decide (f.sid ≤ c.lastPeer) && decide (0 < c.lastPeer)) && !mem c f.sid then
      .inl (connErr c ePROTOCOL)
    else .inr (if f.sid > c.lastPeer then { c with lastPeer := f.sid } else c)
  else .inr c

/-- `h2_setting_error`. mirrors flare/http2/state.mojo#h2_setting_error sha=8b9f982f935d at=59bda50f -/
def settingError (id v : Nat) : Nat :=
  if id = 2 && v ≠ 0 && v ≠ 1 then ePROTOCOL
  else if id = 4 && v > 2147483647 then eFLOW
  else if id = 5 && (v < 16384 || v > 16777215) then ePROTOCOL
  else 0

/-- The INITIAL_WINDOW_SIZE delta over the stream table (1158-1174);
`false` = a stream would pass `_MAX_WINDOW` (the streams before it are
already updated, as in Mojo).
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
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

/-- One SETTINGS pair. mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
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

/-- mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def applySettings (c : Conn) : List (Nat × Nat) → Conn ⊕ (Conn × List Out)
  | [] => .inl c
  | (id, v) :: t =>
    match applySetting c id v with
    | .inl c => applySettings c t
    | .inr r => .inr r

/-- mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def settingsH (c : Conn) (f : Fr) : Conn × List Out :=
  if f.f1 then ({ c with settingsAcked := true }, [])
  else match applySettings c f.settings with
    | .inl c => (c, [.settingsAck])
    | .inr r => r

/-- mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def wuH (c : Conn) (f : Fr) : Conn × List Out :=
  let inc := f.word % 2147483648
  if inc = 0 then
    if f.sid = 0 then connErr c ePROTOCOL
    else if !mem c f.sid && isIdleId c f.sid then connErr c ePROTOCOL
    else (closeIfKnown (rstC c f.sid) f.sid, [.rst f.sid ePROTOCOL])
  else if f.sid = 0 then
    if c.sendW + inc > MAX_WINDOW then connErr c eFLOW
    else ({ c with sendW := c.sendW + inc }, [])
  else match get c f.sid with
    | none => if isIdleId c f.sid then connErr c ePROTOCOL else (c, [])
    | some s =>
      if s.sendW + inc > MAX_WINDOW then rstClose c f.sid eFLOW s
      else (put c f.sid { s with sendW := s.sendW + inc }, [])

/-- Checks against an existing stream (1268-1288): `.inl` is a
connection error, `.inr code` the refusal code so far (0 = none).
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def headersPre (c : Conn) (f : Fr) : (Conn × List Out) ⊕ Nat :=
  match get c f.sid with
  | some p =>
    if p.state = .closed then .inl (connErr c eSTREAM_CLOSED)
    else if p.state = .hcr then .inl (connErr c eSTREAM_CLOSED)
    else if !c.isClient && p.headersComplete && !f.f1 then .inr ePROTOCOL
    else .inr 0
  | none => .inr 0

/-- The concurrency refusal (1289-1298).
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def headersRefuse (c : Conn) (f : Fr) (refuse0 : Nat) : Nat :=
  if refuse0 = 0 && !c.isClient && !mem c f.sid && activeCount c ≥ c.maxConcurrent
  then eREFUSED else refuse0

/-- Start the header block (1313-1333).
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def headersOpen (dec : Dec) (c : Conn) (f : Fr) (refuse : Nat) : Conn × List Out :=
  let c := { c with block := f.frag, blockES := f.f1, blockRefuse := refuse, blockConts := 0 }
  let c := if refuse = 0 then put (ensure c f.sid).1 f.sid (ensure c f.sid).2 else c
  if !f.eh then ({ c with continuing := f.sid }, [])
  else commit dec c f.sid

/-- In client role an id not in the stream table is a connection error at
the top of the HEADERS branch.
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def headersH (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if f.sid = 0 then .ok (connErr c ePROTOCOL)
  else if c.isClient && !mem c f.sid then .ok (connErr c ePROTOCOL)
  else match headersPre c f with
    | .inl r => .ok r
    | .inr refuse0 =>
      if f.prio && f.plen ≥ (if f.padded then 1 else 0) + 4 && f.word % 2147483648 = f.sid then
        .ok (connErr c ePROTOCOL)
      else match stripLen f true with
        | none => .ok (connErr c ePROTOCOL)
        | some _ => .ok (headersOpen dec c f (headersRefuse c f refuse0))

/-- Sum of `dataLen` over non-closed streams.
mirrors flare/http2/state.mojo#Connection._recount_buffered_request_bytes sha=d280a5a47046 at=59bda50f -/
def recount (c : Conn) : Nat :=
  (c.streams.filter (fun p => p.2.state != .closed)).foldl (fun a p => a + p.2.dataLen) 0

/-- The connection-credit tail of the DATA branch (1492-1511).
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
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
content-length mismatch reset returns the frame's connection credit; no
stream WINDOW_UPDATE goes out on a stream this frame closes.
mirrors flare/http2/state.mojo#Connection.handle_frame+Connection.make_response+Connection.make_response_with_trailers sha=1f63214e4ebe at=c64f0e0b -/
def dataFinish (c : Conn) (f : Fr) (s : Stream) (cr : Nat) : Conn × List Out :=
  if f.f1 && (0 : Int) ≤ s.contentLength && (s.received : Int) ≠ s.contentLength then
    rstCloseX c f.sid ePROTOCOL s (wu0If f.plen)
  else
    dataCredit (put c f.sid (if f.f1 then
      { s with dataComplete := true,
               state := if c.isClient && s.state == .hcl then .closed else .hcr }
      else s)) f (if f.f1 && c.isClient && s.state == .hcl then 0 else cr)

/-- Body octets whose stream credit is deferred to `drain_body`
(state.mojo:1450-1455). -/
def deferOf (s : Stream) (body : Nat) : Nat := if s.deferCredit then body else 0

/-- The accepted-body part of the DATA branch (1428-1456); `s` already
counts the body in `dataLen` and `received`.
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def dataAccept (c : Conn) (f : Fr) (s : Stream) (body : Nat) : Conn × List Out :=
  if !c.isClient && (0 : Int) ≤ s.contentLength && (s.received : Int) > s.contentLength then
    rstCloseX c f.sid ePROTOCOL { s with dataLen := 0, buf := [] } (wu0If f.plen)
  else
    dataFinish (if !c.isClient then { c with buffered := c.buffered + body } else c) f
      { s with recvW := s.recvW + (f.plen - deferOf s body),
               pendingCredit := s.pendingCredit + deferOf s body } (f.plen - deferOf s body)

/-- The per-stream checks of the DATA branch (1374-1427); `s` already has
`recvW` debited by the frame length. A stream-window overrun returns the
connection credit.
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def dataBody (c : Conn) (f : Fr) (s : Stream) (body : Nat) : Conn × List Out :=
  if s.recvW < 0 then
    rstCloseX c f.sid eFLOW s (wu0If f.plen)
  else if c.isClient && !s.bodyAllowed && body > 0 then
    rstCloseX c f.sid ePROTOCOL { s with dataLen := 0, buf := [] } (wu0If f.plen)
  else if !c.isClient && (body : Int) > (c.maxBody : Int) - s.dataLen then
    rstCloseX c f.sid eCALM { s with dataLen := 0, buf := [] } (wu0If f.plen)
  else dataAccept c f { s with dataLen := s.dataLen + body, received := s.received + body,
                                buf := s.buf ++ f.frag } body

/-- A closed / half-closed (remote) stream is tested before the client's
headers-complete test; DATA before the response HEADERS is a stream error.
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def dataH (c : Conn) (f : Fr) : Conn × List Out :=
  if f.sid ∈ c.resetByUs then (c, wu0If f.plen)
  else match get c f.sid with
  | none => if isIdleId c f.sid then connErr c ePROTOCOL else connErr c eSTREAM_CLOSED
  | some s =>
    if s.state == .closed || s.state == .hcr then connErr c eSTREAM_CLOSED
    else if c.isClient && !s.headersComplete then
      rstCloseX c f.sid ePROTOCOL { s with dataLen := 0, buf := [] } (wu0If f.plen)
    else match stripLen f false with
    | none => connErr c ePROTOCOL
    | some body => dataBody c f { s with recvW := s.recvW - f.plen } body

/-- The flood check of the RST_STREAM branch (1529-1540).
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def rstFlood (c : Conn) (f : Fr) : Conn × List Out :=
  if c.rstCount > RST_FLOOD && !c.goawaySent then
    ({ c with goawaySent := true }, [.goaway f.sid eCALM])
  else (c, [])

/-- mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def rstH (c : Conn) (f : Fr) : Conn × List Out :=
  rstFlood { closeIfKnown c f.sid with rstCount := (closeIfKnown c f.sid).rstCount + 1 } f

/-- Per-type dispatch after the common checks (1128-1547).
mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def dispatch (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if f.ty = tSETTINGS then .ok (settingsH c f)
  else if f.ty = tPING then .ok (if f.f1 then (c, []) else (c, [.pingAck]))
  else if f.ty = tWU then .ok (wuH c f)
  else if f.ty = tHEADERS then headersH dec c f
  else if f.ty = tCONT then .ok (connErr c ePROTOCOL)
  else if f.ty = tDATA then .ok (dataH c f)
  else if f.ty = tGOAWAY then .ok ({ c with goawayReceived := true }, [])
  else if f.ty = tRST then .ok (rstH c f)
  else .ok (c, [])

/-- mirrors flare/http2/state.mojo#Connection.handle_frame sha=75ac9ea2cd82 at=268ccb85 -/
def handle (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if c.continuing ≠ 0 then .ok (contBranch dec c f)
  else match shapeCheck c f with
  | some r => .ok r
  | none =>
    if f.plen > c.localMaxFrame then .ok (connErr c eFRAME_SIZE)
    else match idCheck c f with
    | .inl r => .ok r
    | .inr c => dispatch dec c f

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
  /-- local END_STREAM: client `send_data(sid, body, end_stream=True)`,
  either the empty-DATA half-close path (client.mojo:885-901) or the last
  chunk of `_emit_body_span` (client.mojo:560-584); both apply the same
  state rule -/
  | endLocal (sid : Nat)
  /-- client `enable_response_streaming` (client.mojo:1189-1197) -/
  | stream (sid : Nat)
  /-- client `drain_body` (client.mojo:1160-1187) -/
  | drain (sid : Nat)
  deriving Repr

/-- Connection flow control layered on `handle`: account every DATA payload
against `recvW`, refuse a frame that overruns it, and add back every
connection-level WINDOW_UPDATE that is emitted.
mirrors flare/http2/state.mojo#Connection.handle_frame+Connection._conn_window_update sha=6ba0292a6e6e at=268ccb85 -/
def handleW (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if reachesData c f && decide ((f.plen : Int) > c.recvW) then .ok (connErr c eFLOW)
  else match handle dec c f with
    | .ok (c', o) =>
      .ok ({ c' with recvW := c.recvW - (if reachesData c f then (f.plen : Int) else 0) + wu0 o }, o)
    | .error e => .error e

/-- The connection preface rule (RFC 9113 §3.4): until a SETTINGS (non-ACK)
frame was received (`peer_settings_seen`), any other frame is refused.
mirrors flare/http2/server.mojo#Http2Connection.feed sha=13eaa955fac8 at=fda30c33 -/
def prefaceGate (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if !c.peerSettingsSeen then
    if f.ty = tSETTINGS && !f.f1 then handleW dec { c with peerSettingsSeen := true } f
    else .ok (connErr c ePROTOCOL)
  else handleW dec c f

/-- One inbound frame through the server driver (server.mojo:398-438):
nothing is applied after a GOAWAY was queued, a frame declaring more
than `local_max_frame_size` is refused from its header, and the first
frame must be SETTINGS.
mirrors flare/http2/server.mojo#Http2Connection.feed sha=13eaa955fac8 at=fda30c33 -/
def driveFrame (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if c.goawaySent then .ok (c, [])
  else if f.plen > c.localMaxFrame then .ok (connErr c eFRAME_SIZE)
  else prefaceGate dec c f

/-- The client driver's frame loop (`Http2ClientConnection.feed`,
client.mojo:400-512): a frame declaring more than the advertised maximum
is GOAWAY(FRAME_SIZE_ERROR); PUSH_PROMISE goes to `handle_frame`, which
answers GOAWAY(PROTOCOL_ERROR); frames are applied after a GOAWAY was
queued as well (`handle_frame` itself then emits nothing for a further
connection error).
mirrors flare/http2/client.mojo#Http2ClientConnection.feed sha=a349cf805ea2 at=ea1b9282 -/
def driveClient (dec : Dec) (c : Conn) (f : Fr) : Res :=
  if f.plen > c.localMaxFrame then .ok (connErr c eFRAME_SIZE)
  else prefaceGate dec c f

/-- mirrors flare/http2/state.mojo#Connection.release_request_credit sha=3575eab6d8b4 at=0a8720b8 -/
def release (c : Conn) (n : Nat) : Conn × List Out :=
  let c := { c with buffered := c.buffered - n }
  if c.withheld > 0 && c.buffered ≤ MAX_BUFFERED then
    ({ c with withheld := 0, recvW := c.recvW + c.withheld }, [.wu 0 c.withheld])
  else (c, [])

/-- mirrors flare/http2/server.mojo#Http2Connection.queue_stream_data sha=7bdf64108236 at=c64f0e0b -/
def budget (c : Conn) (s : Stream) : Int := if c.sendW < s.sendW then c.sendW else s.sendW

/-- mirrors flare/http2/server.mojo#Http2Connection.queue_stream_data sha=7bdf64108236 at=c64f0e0b -/
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
mirrors flare/http2/server.mojo#Http2Connection.emit_response sha=1c9c08a9782d at=c64f0e0b -/
def respond (c : Conn) (k n : Nat) : Conn × List Out :=
  match get c k with
  | none => (c, [])
  | some s =>
    if n > 0 && ((n : Int) > budget c s || n > c.peerMaxFrame) then (c, [])
    else (put { c with sendW := c.sendW - n } k { s with state := .closed, sendW := s.sendW - n },
          if n > 0 then [.data k n] else [])

/-- mirrors flare/http2/client.mojo#Http2ClientConnection.send_request+Http2ClientConnection.send_extended_connect+Http2ClientConnection.send_request_open sha=9368911d9ef4 at=30c98ba7
and flare/http2/state.mojo#Connection.note_local_stream sha=7504d960f0e3 at=30c98ba7 -/
def openLocal (c : Conn) (k : Nat) (es : Bool) : Conn :=
  let c := { c with maxLocalSid := if k > c.maxLocalSid then k else c.maxLocalSid }
  put c k { state := if es then .hcl else .open_, sendW := c.peerInitW, recvW := c.initW }

/-- Local END_STREAM: a closed stream is left alone (the guard at the top
of `send_data`, nothing is sent); otherwise half-closed (remote) becomes
closed and anything else half-closed (local).
mirrors flare/http2/client.mojo#Http2ClientConnection._emit_body_span+Http2ClientConnection.send_data sha=1fecb7971c3a at=ea1b9282 -/
def endLocal (c : Conn) (k : Nat) : Conn :=
  match get c k with
  | none => c
  | some s =>
    if s.state == .closed then c
    else put c k { s with state := if s.state == .hcr then .closed else .hcl }

/-- mirrors flare/http2/client.mojo#Http2ClientConnection.enable_response_streaming sha=1c211a19530b at=59bda50f -/
def enableStream (c : Conn) (k : Nat) : Conn :=
  match get c k with
  | none => c
  | some s => put c k { s with deferCredit := true }

/-- Stream 0 is never a key of the table (HEADERS on stream 0 never opens
one), so the guard only spares the proofs that invariant.
mirrors flare/http2/client.mojo#Http2ClientConnection.stream_ended+Http2ClientConnection.drain_body sha=c6ad1acf831a at=59bda50f -/
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
def step (dec : Dec) (c : Conn) : Ev → Res
  | .frame f => if c.isClient then driveClient dec c f else driveFrame dec c f
  | .release n => .ok (release c n)
  | .respond k n => .ok (respond c k n)
  | .send k n => .ok (send c k n)
  | .openLocal k es => .ok (openLocal c k es, [])
  | .pop k => .ok (erase c k, [])
  | .endLocal k => .ok (endLocal c k, [])
  | .stream k => .ok (enableStream c k, [])
  | .drain k => .ok (drain c k)

/-- Run a trace with one decoder; collects each step's input and reply.
`none` if a step raises. -/
def run (dec : Dec) : Conn → List Ev → Option (Conn × List (Ev × List Out))
  | c, [] => some (c, [])
  | c, e :: es =>
    match step dec c e with
    | .error _ => none
    | .ok (c', o) =>
      match run dec c' es with
      | none => none
      | some (c'', tr) => some (c'', (e, o) :: tr)

/-- The connection as an LTS; each label carries the HPACK outcome
function in force for that step (so stateful decoding is covered). -/
def lts (init : Conn → Prop) : LTS Conn (Dec × Ev) where
  init := init
  step c l c' := ∃ o, step l.1 c l.2 = .ok (c', o)

end Flare.L3.H2.Conn
