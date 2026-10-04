import Flare.Core.LTS

/-!
# RFC 9113 §5.1 stream states (spec)

The stream life-cycle of RFC 9113 §5.1 (Figure 2), written from the
point of view of one endpoint (the one whose behaviour is checked), as a
labelled transition system over the map from stream id to state.
Nothing here refers to flare.

## States

`idle`, `resL` / `resR` (reserved local / remote), `open_`, `hcl` / `hcr`
(half-closed local / remote), `closed`.

## Inbound frames (`RK`)

A header block counts as one HEADERS frame for state transitions (§5.1:
"CONTINUATION frames [...] are treated as part of the preceding HEADERS
or PUSH_PROMISE frame"), so a block that spans frames is split into
`hdrBegin` (HEADERS without END_HEADERS), `contMid` and `hdrEnd es`
(the CONTINUATION carrying END_HEADERS); `hdr es` is a single-frame
block. `other` is an unknown frame type (§5.5: ignored).

## Verdicts (`V`)

The endpoint either accepts the frame (`ok`), answers with a stream
error (`strm code`: RST_STREAM, the stream becomes closed, §5.4.2), or
ends the connection (`conn code`: GOAWAY, §5.4.1).

`recvOK peerId room s k v s'` is the §5.1 rule for receiving `k` in state
`s` with verdict `v` and resulting state `s'`:

* frames §5.1 forbids in a state draw the error class it prescribes:
  - idle: anything but HEADERS / PRIORITY is a connection error
    PROTOCOL_ERROR (§5.1 idle); HEADERS on an id the peer may not
    open is one too (§5.1.1);
  - half-closed (remote): DATA / HEADERS / CONTINUATION is a stream
    error STREAM_CLOSED (§5.1);
  - closed: DATA / HEADERS is STREAM_CLOSED (§5.1 closed), HEADERS on a
    used id may also be PROTOCOL_ERROR (§5.1.1); WINDOW_UPDATE /
    RST_STREAM / PRIORITY "MUST [be] ignore[d]" (§5.1 closed), so a
    connection error there is wrong;
  - PUSH_PROMISE with push disabled is PROTOCOL_ERROR (§6.6, §8.4);
  - CONTINUATION outside a block is PROTOCOL_ERROR (§6.10);
* a stream error closes the stream; it is never allowed on an idle
  stream (RST_STREAM "MUST NOT be sent for a stream in the idle state",
  §6.4) unless the frame opened it (HEADERS);
* an accepted frame moves the stream along Figure 2; HEADERS on an idle
  stream needs `room` under the advertised concurrency limit (§5.1.2);
* connection errors FRAME_SIZE_ERROR, COMPRESSION_ERROR and
  ENHANCE_YOUR_CALM are allowed everywhere (malformed frames §4.2, HPACK
  state loss §4.3, resource protection §10.5). On a frame §5.1 permits,
  any connection error is allowed (message-level and flow-control errors
  are other sections' business), except on a closed stream as above.

Over-approximation: on a closed stream, accepting (ignoring) DATA is
allowed (it is required after we sent RST_STREAM, and the model does not
track which closes were ours); WINDOW_UPDATE / RST_STREAM arriving long
after a close may be treated as a connection error by the RFC, which this
spec, having no clock, does not allow.

## Our sends (`SK`)

`sendPost s k` is the state after we send `k` in `s`, or `none` if §5.1
forbids it: no frame but PRIORITY on a closed stream; on half-closed
(local) only WINDOW_UPDATE, PRIORITY and RST_STREAM; on idle only
HEADERS (and PUSH_PROMISE); `forget` is dropping the local record of a
stream the peer can no longer send DATA / HEADERS on (half-closed remote
or closed), which §5.1 treats as closed.
-/
namespace Flare.L3.H2.StreamSpec

inductive SS | idle | resL | resR | open_ | hcl | hcr | closed
  deriving DecidableEq, Repr

inductive RK
  | hdr (es : Bool)
  | hdrBegin
  | contMid
  | hdrEnd (es : Bool)
  | data (es : Bool)
  | rst | wu | prio | push | cont | other
  deriving DecidableEq, Repr

inductive V | ok | strm (code : Nat) | conn (code : Nat)
  deriving DecidableEq, Repr

/-- FRAME_SIZE_ERROR, COMPRESSION_ERROR, ENHANCE_YOUR_CALM. -/
def connAny (code : Nat) : Bool := code == 6 || code == 9 || code == 11

/-- Connection-error codes §5.1 allows for `k` in `s`. -/
def connCodes (peerId : Bool) (s : SS) (k : RK) (code : Nat) : Bool :=
  match k with
  | .cont | .push => code == 1
  | .contMid | .other => true
  | .hdr _ | .hdrBegin =>
    match s with
    | .idle => peerId || code == 1
    | .hcr => code == 5
    | .closed => code == 5 || code == 1
    | .resL => code == 1
    | _ => true
  | .hdrEnd _ =>
    match s with
    | .hcr => code == 5
    | .closed => code == 5 || code == 1
    | _ => true
  | .data _ =>
    match s with
    | .idle | .resL | .resR => code == 1
    | .hcr | .closed => code == 5
    | _ => true
  | .rst =>
    match s with
    | .idle => code == 1
    | .closed => false
    | _ => true
  | .wu =>
    match s with
    | .idle | .resR => code == 1
    | .closed => false
    | _ => true
  | .prio =>
    match s with
    | .closed => false
    | _ => true

/-- Whether a stream error (RST_STREAM, then closed) is allowed. -/
def strmOK (s : SS) (k : RK) : Bool :=
  match k with
  | .hdrBegin | .contMid | .cont | .push | .other => false
  | .hdr _ | .hdrEnd _ => s != .resL
  | _ => s != .idle

def esTo (es : Bool) (a b : SS) : SS := if es then b else a

/-- Whether accepting `k` in `s` may lead to `s'`. -/
def okPost (peerId room : Bool) (s : SS) (k : RK) (s' : SS) : Bool :=
  match k, s with
  | .other, _ | .contMid, _ => s' == s
  | .cont, _ | .push, _ => false
  | .hdr es, .idle => peerId && room && s' == esTo es .open_ .hcr
  | .hdrBegin, .idle => peerId && ((room && s' == .idle) || s' == .closed)
  | .hdrEnd es, .idle => s' == esTo es .open_ .hcr
  | .prio, .idle => s' == .idle
  | .hdr es, .resR | .hdrEnd es, .resR => s' == esTo es .hcl .closed
  | .hdrBegin, .resR => s' == .resR
  | .prio, .resR | .prio, .resL | .wu, .resL => s' == s
  | .rst, .resR | .rst, .resL => s' == .closed
  | .hdr es, .open_ | .hdrEnd es, .open_ | .data es, .open_ => s' == esTo es .open_ .hcr
  | .hdrBegin, .open_ => s' == .open_
  | .hdr es, .hcl | .hdrEnd es, .hcl | .data es, .hcl => s' == esTo es .hcl .closed
  | .hdrBegin, .hcl => s' == .hcl
  | .rst, .open_ | .rst, .hcl | .rst, .hcr | .rst, .closed => s' == .closed
  | .wu, .open_ | .wu, .hcl | .wu, .hcr | .wu, .closed => s' == s
  | .prio, .open_ | .prio, .hcl | .prio, .hcr | .prio, .closed => s' == s
  | .data _, .closed => s' == .closed
  | _, _ => false

/-- The §5.1 rule for receiving `k` in state `s`. -/
def recvOK (peerId room : Bool) (s : SS) (k : RK) (v : V) (s' : SS) : Bool :=
  match v with
  | .conn code => connAny code || connCodes peerId s k code
  | .strm _ => strmOK s k && s' == .closed
  | .ok => okPost peerId room s k s'

inductive SK | hdr (es : Bool) | data (es : Bool) | wu | prio | rst | forget
  deriving DecidableEq, Repr

/-- The state after we send `k` in `s`; `none` if §5.1 forbids it. -/
def sendPost : SS → SK → Option SS
  | s, .prio => some s
  | .idle, .hdr es => some (esTo es .open_ .hcl)
  | .resL, .hdr es => some (esTo es .hcr .closed)
  | .open_, .hdr es | .open_, .data es => some (esTo es .open_ .hcl)
  | .hcr, .hdr es | .hcr, .data es => some (esTo es .hcr .closed)
  | .open_, .wu => some .open_
  | .hcl, .wu => some .hcl
  | .hcr, .wu => some .hcr
  | .resR, .wu => some .resR
  | .idle, .rst => none
  | _, .rst => some .closed
  | .hcr, .forget | .closed, .forget => some .closed
  | _, _ => none

/-- Whether we may send WINDOW_UPDATE on a stream in state `s`. -/
def wuOK (s : SS) : Bool := (sendPost s .wu).isSome

/-- Streams other than `k` keep their state, except that idle streams with
a lower id may become closed (§5.1.1: "The first use of a new stream
identifier implicitly closes all streams in the idle state [...] with a
lower-valued stream identifier"). -/
def Others (M M' : Nat → SS) (k : Nat) : Prop :=
  ∀ j, j ≠ k → M' j = M j ∨ (M j = .idle ∧ M' j = .closed ∧ j < k)

/-- Spec labels. `recv k rk v room`: an inbound frame on stream `k`, with
the endpoint's verdict and whether the concurrency limit has room;
`send k sk`: our frame on stream `k`; `conn`: a frame on stream 0 that
leaves every stream alone. -/
inductive Lab
  | recv (k : Nat) (rk : RK) (v : V) (room : Bool)
  | send (k : Nat) (sk : SK)
  | conn
  deriving Repr

/-- Which ids the peer may open: with push disabled, a client's peer
opens none, a server's peer opens the odd ids (§5.1.1). -/
def peerId (client : Bool) (k : Nat) : Bool := !client && k % 2 == 1

/-- One spec step; `none` is the state after a connection error. -/
def specStep (client : Bool) (M : Nat → SS) : Lab → Option (Nat → SS) → Prop
  | .recv k rk (.conn code) room, s' =>
    recvOK (peerId client k) room (M k) rk (.conn code) .closed = true ∧ s' = none
  | .recv k rk v room, some M' =>
    recvOK (peerId client k) room (M k) rk v (M' k) = true ∧ Others M M' k
  | .send k sk, some M' => sendPost (M k) sk = some (M' k) ∧ Others M M' k
  | .conn, some M' => M' = M
  | _, none => False

/-- The §5.1 LTS: every stream starts idle; nothing happens after a
connection error. -/
def lts (client : Bool) : LTS (Option (Nat → SS)) Lab where
  init s := s = some (fun _ => .idle)
  step s l s' := ∃ M, s = some M ∧ specStep client M l s'

/-! ## Sanity: the figure's edges -/

theorem idle_headers_open : okPost true true .idle (.hdr false) .open_ = true := rfl
theorem idle_headers_es : okPost true true .idle (.hdr true) .hcr = true := rfl
theorem open_es : okPost true true .open_ (.data true) .hcr = true := rfl
theorem hcl_es : okPost true true .hcl (.data true) .closed = true := rfl
theorem hcr_data_err : recvOK true true .hcr (.data false) (.conn 1) .closed = false := rfl
theorem closed_wu_ignore : recvOK true true .closed .wu .ok .closed = true := rfl
theorem closed_wu_no_conn : recvOK true true .closed .wu (.conn 1) .closed = false := rfl
theorem idle_rst_conn : recvOK true true .idle .rst (.conn 1) .closed = true := rfl
theorem idle_no_strm : recvOK true true .idle .prio (.strm 1) .closed = false := rfl
theorem closed_no_send_wu : wuOK .closed = false := rfl
theorem send_es_hcr : sendPost .hcr (.data true) = some .closed := rfl

end Flare.L3.H2.StreamSpec
